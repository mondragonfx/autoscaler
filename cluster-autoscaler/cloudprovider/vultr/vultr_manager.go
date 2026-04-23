/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vultr

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"k8s.io/autoscaler/cluster-autoscaler/cloudprovider/vultr/govultr"
	"k8s.io/klog/v2"
)

type vultrClient interface {
	ListNodePools(ctx context.Context, vkeID string, options *govultr.ListOptions) ([]govultr.NodePool, *govultr.Meta, error)
	UpdateNodePool(ctx context.Context, vkeID, nodePoolID string, updateReq *govultr.NodePoolReqUpdate) (*govultr.NodePool, error)
	DeleteNodePoolInstance(ctx context.Context, vkeID, nodePoolID, nodeID string) error
}

type manager struct {
	clusterID  string
	client     vultrClient
	nodeGroups []*NodeGroup

	useIRSA     bool
	stsExchange *stsTokenExchange
}

// Config is the configuration of the Vultr cloud provider
type Config struct {
	ClusterID string `json:"cluster_id"`
	Token     string `json:"token"`
}

func newManager(config io.Reader) (*manager, error) {
	cfg := &Config{}

	if config != nil {
		body, err := io.ReadAll(config)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(body, cfg); err != nil {
			return nil, err
		}
	}

	if cfg.ClusterID == "" {
		return nil, errors.New("cluster ID is required")
	}

	useIRSA := os.Getenv("AWS_ROLE_ARN") != ""

	var oauth2Client *http.Client
	var stsExchange *stsTokenExchange

	if useIRSA {
		klog.V(1).Info("Vultr IRSA mode enabled: authenticating via AssumeRoleWithWebIdentity")

		stsExchange = newSTSTokenExchange()
		tokenSource := &stsTokenSource{exchange: stsExchange}
		oauth2Client = &http.Client{
			Timeout: 60 * time.Second,
			Transport: &oauth2.Transport{
				Source: tokenSource,
			},
		}
	} else {
		if cfg.Token == "" {
			return nil, errors.New("token is required")
		}

		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.Token})
		oauth2Client = &http.Client{
			Timeout: 60 * time.Second,
			Transport: &oauth2.Transport{
				Source: tokenSource,
			},
		}
	}

	m := &manager{
		client:      govultr.NewClient(oauth2Client),
		nodeGroups:  make([]*NodeGroup, 0),
		clusterID:   cfg.ClusterID,
		useIRSA:     useIRSA,
		stsExchange: stsExchange,
	}

	return m, nil
}


// stsTokenExchange exchanges a Kubernetes ServiceAccount token for
// temporary credentials via AssumeRoleWithWebIdentity
type stsTokenExchange struct {
	mu         sync.RWMutex
	token      string
	expiryTime time.Time
}

func newSTSTokenExchange() *stsTokenExchange {
	return &stsTokenExchange{}
}

// GetToken returns a valid Vultr API token, refreshing via STS if needed.
func (e *stsTokenExchange) GetToken(ctx context.Context) (string, error) {
	e.mu.RLock()
	if e.token != "" && time.Until(e.expiryTime) > 5*time.Minute {
		token := e.token
		e.mu.RUnlock()
		return token, nil
	}
	e.mu.RUnlock()

	return e.refreshToken(ctx)
}

func (e *stsTokenExchange) refreshToken(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check after acquiring write lock
	if e.token != "" && time.Until(e.expiryTime) > 5*time.Minute {
		return e.token, nil
	}

	// Read the ServiceAccount token injected by the IRSA webhook
	tokenPath := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	if tokenPath == "" {
		tokenPath = "/var/run/secrets/vultr.com/serviceaccount/token"
	}

	saToken, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token from %s: %v", tokenPath, err)
	}

	stsEndpoint := os.Getenv("AWS_ENDPOINT_URL_STS")
	if stsEndpoint == "" {
		stsEndpoint = "https://api.vultr.com/v2/assumed-roles/compatibility/aws/sts"
	}

	roleArn := os.Getenv("AWS_ROLE_ARN")
	if roleArn == "" {
		return "", errors.New("AWS_ROLE_ARN environment variable is required for IRSA")
	}

	// AssumeRoleWithWebIdentity request parameters
	data := url.Values{}
	data.Set("Action", "AssumeRoleWithWebIdentity")
	data.Set("RoleArn", roleArn)
	data.Set("RoleSessionName", "cluster-autoscaler")
	data.Set("WebIdentityToken", strings.TrimSpace(string(saToken)))
	data.Set("DurationSeconds", "3600")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stsEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create STS request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("STS request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read STS response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("STS request returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse XML response
	var stsResp STSAssumeRoleResponse
	if err := xml.Unmarshal(respBody, &stsResp); err != nil {
		return "", fmt.Errorf("failed to decode STS response: %v", err)
	}

	sessionToken := stsResp.Result.Credentials.SessionToken
	if sessionToken == "" {
		return "", errors.New("STS response missing SessionToken")
	}

	expiration := stsResp.Result.Credentials.Expiration
	e.token = sessionToken
	if expiration != "" {
		e.expiryTime, err = time.Parse(time.RFC3339, expiration)
		if err != nil {
			klog.Warningf("Failed to parse STS credential expiration %q, defaulting to 50m: %v", expiration, err)
			e.expiryTime = time.Now().Add(50 * time.Minute)
		}
	} else {
		e.expiryTime = time.Now().Add(50 * time.Minute)
	}

	klog.V(2).Infof("Successfully refreshed Vultr IRSA token, expires at %s", e.expiryTime)
	return e.token, nil
}

// STSAssumeRoleResponse represents the XML response from AssumeRoleWithWebIdentity
type STSAssumeRoleResponse struct {
	XMLName xml.Name `xml:"AssumeRoleWithWebIdentityResponse"`
	Result  struct {
		AssumedRoleUser struct {
			Arn           string `xml:"Arn"`
			AssumedRoleId string `xml:"AssumedRoleId"`
		} `xml:"AssumedRoleUser"`
		Credentials struct {
			AccessKeyId     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
		SubjectFromWebIdentityToken string `xml:"SubjectFromWebIdentityToken"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

// stsTokenSource implements oauth2.TokenSource by fetching tokens via STS exchange.
type stsTokenSource struct {
	exchange *stsTokenExchange
}

func (s *stsTokenSource) Token() (*oauth2.Token, error) {
	token, err := s.exchange.GetToken(context.Background())
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{AccessToken: token}, nil
}

func (m *manager) Refresh() error {
	ctx := context.Background()

	//todo do we want to set the paging options here?
	nodePools, _, err := m.client.ListNodePools(ctx, m.clusterID, nil)
	if err != nil {
		return err
	}

	var group []*NodeGroup
	for _, nodePool := range nodePools {

		if !nodePool.AutoScaler {
			continue
		}

		klog.V(3).Infof("adding node pool: %q name with min nodes %d and max nodes %d", nodePool.Label, nodePool.MinNodes, nodePool.MaxNodes)

		np := nodePool
		group = append(group, &NodeGroup{
			id:        nodePool.ID,
			clusterID: m.clusterID,
			client:    m.client,
			nodePool:  &np, // we had to set this as a pointer because we don't return the [] as []*
			minSize:   nodePool.MinNodes,
			maxSize:   nodePool.MaxNodes,
		})
	}

	m.nodeGroups = group
	return nil
}

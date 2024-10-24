package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go/aws"
	txn "github.com/bigchaindb/go-bigchaindb-driver/pkg/transaction"
	"github.com/go-interledger/cryptoconditions"
	"github.com/kalaspuffar/base64url"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

var nodeUrls []string = []string{
	"https://hns-t-vsc-helm-test-prometheus-1.dev.platform-services.dev1.poweredbyvia.com/",
	"https://hns-t-vsc-helm-test-prometheus-2.dev.platform-services.dev1.poweredbyvia.com/",
	"https://hns-t-vsc-helm-test-prometheus-3.dev.platform-services.dev1.poweredbyvia.com/",
	"https://hns-t-vsc-helm-test-prometheus-4.dev.platform-services.dev1.poweredbyvia.com/",
	"https://hns-t-vsc-helm-test-prometheus-5.dev.platform-services.dev1.poweredbyvia.com/",
}

var mode string
var jsonBody string
var requestsPerSecond int

const (
	BaseUmUrl = "keycloak.um-dev.dev.poweredbyvia.com"
	Realm     = "tac-dev"
	Region    = "ca-central-1"
	SecretArn = "arn:aws:secretsmanager:ca-central-1:977445517197:secret:keycloak_dev_user_credentials-CFTeIU"
)

func init() {
	flag.StringVar(&mode, "mode", "commit", "mode for each transaction submission")
	flag.StringVar(&jsonBody, "json-body", "{}", "json body sent to each of the nodes")
	flag.IntVar(&requestsPerSecond, "requests-per-sec", 10, "number of requests per second to be fired off per node")
}

func main() {
	flag.Parse()

	if mode != "commit" && mode != "sync" && mode != "async" && mode != "adtm" {
		log.Fatalf("%s is not a valid mode. choose from `commit`, `sync`, `async` or `adtm`.\n", mode)
	}

	appCtx, cancelFunc := context.WithCancel(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		<-sig
		cancelFunc()
	}()

	for i, url := range nodeUrls {
		var endpoint string
		// Check if mode is one of commit, sync, or async
		if mode == "commit" || mode == "sync" || mode == "async" {
			endpoint = fmt.Sprintf("%svsc/api/v1/transactions/?mode=%s", url, mode)
		} else if mode == "adtm" {
			// Use /arb-data-tm/ for mode adtm
			endpoint = fmt.Sprintf("%sarb-data-tm/", url)
		}
		go getEm(endpoint, i+1, appCtx)
	}

	<-appCtx.Done()
}

// Struct for secret
type KeycloakCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Function to retrieve secret from AWS Secrets Manager
func getKeycloakUserSecret(appCtx context.Context) (KeycloakCredentials, error) {
	//secretName := "keycloak_dev_user_credentials-CFTeIU"
	region := "ca-central-1"

	config, err := config.LoadDefaultConfig(appCtx, config.WithRegion(region), config.WithSharedConfigProfile("vianeer"))
	if err != nil {
		log.Fatal(err)
	}

	// Create Secrets Manager client
	svc := secretsmanager.NewFromConfig(config)

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(SecretArn),
	}

	result, err := svc.GetSecretValue(appCtx, input)
	if err != nil {
		// For a list of exceptions thrown, see
		// https://<<{{DocsDomain}}>>/secretsmanager/latest/apireference/API_GetSecretValue.html
		log.Fatalf("GetSecretValue error: %s\n", err)
		log.Fatal(err.Error())
	}

	// Decrypts secret using the associated KMS key.
	var secretString string = *result.SecretString

	// Unmarshal the secret string into KeycloakCredentials struct
	var credentials KeycloakCredentials
	err = json.Unmarshal([]byte(secretString), &credentials)
	if err != nil {
		log.Fatalf("failed to unmarshal secret: %v", err)
	}

	return credentials, err
}

// Function to retrieve Keycloak token (without retries)
func getKeycloakToken(appCtx context.Context) (string, error) {
	// Construct URL and headers
	umUrl := fmt.Sprintf("https://%s/auth/realms/%s/protocol/openid-connect/token", BaseUmUrl, Realm)
	secret, err := getKeycloakUserSecret(appCtx)
	if err != nil {
		return "", fmt.Errorf("error fetching Keycloak credentials: %v", err)
	}

	// Prepare POST request data
	data := fmt.Sprintf("username=%s&password=%s&grant_type=password&client_id=admin-cli",
		secret.Username, secret.Password)
	req, err := http.NewRequest("POST", umUrl, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 response: %v", resp.StatusCode)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse the JSON response
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %v", err)
	}

	// Extract the access token
	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access token not found in response")
	}

	return token, nil
}

// Function to get Authorization headers with Bearer token
func getKeycloakTokenHeader(appCtx context.Context) (map[string]string, error) {
	token, err := getKeycloakToken(appCtx)
	if err != nil {
		return nil, err
	}

	return map[string]string{"Authorization": fmt.Sprintf("Bearer %s", token)}, nil
}

func getEm(url string, nodeNumber int, ctx context.Context) {

	// Fetch the Keycloak token header
	headers, err := getKeycloakTokenHeader(ctx)
	if err != nil {
		log.Fatalf("failed to get Keycloak token: %v", err)
	}

	ticker := time.NewTicker(time.Second / time.Duration(requestsPerSecond))
outer:
	for {
		select {
		case <-ctx.Done():
			break outer
		case <-ticker.C:
			go func() {

				tx := createTransaction()
				// Convert transaction object to JSON
				txJSON, err := json.Marshal(tx)
				if err != nil {
					fmt.Println("Error marshalling transaction:", err)
					return
				}

				// Print the JSON representation of the transaction
				//fmt.Println("*** SIGNED TXN:")
				//fmt.Println(string(txJSON))

				req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(txJSON))
				if err != nil {
					wrapped := fmt.Errorf("unable to create request due to the following error: %w", err)
					log.Fatalln(wrapped.Error())
				}
				for key, value := range headers {
					req.Header.Add(key, value)
				}
				req.Header.Add("Content-Type", "application/json")

				client := &http.Client{}

				now := time.Now()
				res, err := client.Do(req)
				if err != nil {
					wrapped := fmt.Errorf("request failed due to the following error: %w", err)
					log.Fatalln(wrapped.Error())
				}
				resTime := time.Since(now)
				slog.Info(fmt.Sprintf("Node %d", nodeNumber), "code", res.StatusCode, "response-time", resTime)
			}()
		}
	}
}

func createTransaction() *txn.Transaction {
	var keyPairs []*txn.KeyPair

	keyPair, _ := txn.NewKeyPair()

	keyPairs = append(keyPairs, keyPair)

	var outputs []txn.Output
	var issuers []ed25519.PublicKey

	for _, keyPair := range keyPairs {
		// Create conditions
		condition := txn.NewEd25519Condition(keyPair.PublicKey)

		// Create output
		output, _ := txn.NewOutput(*condition, "1")

		outputs = append(outputs, output)

		// Create issuers
		issuers = append(issuers, keyPair.PublicKey)
	}

	data := make(map[string]interface{})
	data["assetID"] = "testID1"
	asset := txn.Asset{
		Data: data,
	}
	metadata := make(map[string]interface{})
	metadata["planet"] = "earth"

	// New create transaction
	txn, _ := txn.NewCreateTransaction(asset, metadata, outputs, issuers)

	txn, _ = Sign(keyPairs, txn)

	return txn
}

func Sign(keyPairs []*txn.KeyPair, t *txn.Transaction) (*txn.Transaction, error) {
	// Set transaction ID to nil value
	t.ID = nil
	signedTx := *t
	// Compute signatures of inputs
	for idx, input := range signedTx.Inputs {
		var serializedTxn strings.Builder
		s, err := t.String()
		if err != nil {
			return nil, err
		}
		serializedTxn.WriteString(s)
		keyPair := keyPairs[idx]
		// If fulfills is not empty, add to make unique serialization Txn
		if input.Fulfills != nil {
			serializedTxn.WriteString(input.Fulfills.TransactionID)
			serializedTxn.WriteString(string(input.Fulfills.OutputIndex))
		}

		bytes_to_sign := []byte(serializedTxn.String())

		h3_256 := sha3.New256()
		h3_256.Write(bytes_to_sign)
		h3_256Hash := h3_256.Sum(nil)

		// rand reader is ignored within Sign method; crypto.Hash(0) is sanity check to
		// make sure bytes_to_sign is not hashed already - ed25519.PrivateKey cannot sign hashed msg
		signature, _ := keyPair.PrivateKey.Sign(rand.Reader, h3_256Hash, crypto.Hash(0))

		// https://tools.ietf.org/html/draft-thomas-crypto-conditions-03#section-8.5
		ed25519Fulfillment, err := cryptoconditions.NewEd25519Sha256(keyPair.PublicKey, signature)
		if err != nil {
			return nil, errors.Wrap(err, "Could not create fulfillment")
		}
		// TODO - Not sure whether this should be ed25519Fulfillment.Encode()
		// TODO - or ed25519Fulfillment.Condition().Encode()
		ff, err := ed25519Fulfillment.Encode()
		if err != nil {
			return nil, err
		}
		ffSt := base64url.Encode(ff)
		signedTx.Inputs[idx].Fulfillment = &ffSt
	}
	// Create ID of transaction (hash of body)
	id, err := createID(&signedTx)
	if err != nil {
		return nil, errors.Wrap(err, "Could not create ID")
	}
	signedTx.ID = &id

	// Return the signed transaction
	return &signedTx, nil
}

func createID(t *txn.Transaction) (string, error) {

	// Strip ID of txn
	tn := &txn.Transaction{
		ID:        nil,
		Version:   t.Version,
		Inputs:    t.Inputs,
		Outputs:   t.Outputs,
		Operation: t.Operation,
		Asset:     t.Asset,
		Metadata:  t.Metadata,
	}
	// Serialize transaction - encoding/json follows RFC7159 and BDB marshalling
	dbytes, err := tn.JSON()
	if err != nil {
		return "", err
	}

	// Return hash of serialized txn object
	h := sha3.Sum256(dbytes)
	return hex.EncodeToString(h[:]), nil
}

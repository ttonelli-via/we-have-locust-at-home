package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var nodeUrls []string = []string{
	"https://hns-t-vsc-helm-test-prometheus-1.dev.platform-services.dev1.poweredbyvia.com/",
	"https://hns-t-vsc-helm-test-prometheus-2.dev.platform-services.dev1.poweredbyvia.com/",
	"https://hns-t-vsc-helm-test-prometheus-3.dev.platform-services.dev1.poweredbyvia.com/",
	"https://hns-t-vsc-helm-test-prometheus-4.dev.platform-services.dev1.poweredbyvia.com/",
	"https://hns-t-vsc-helm-test-prometheus-5.dev.platform-services.dev1.poweredbyvia.com/",
}

var keycloakToken string
var mode string
var jsonBody string
var requestsPerSecond int

func init() {
	flag.StringVar(&keycloakToken, "keycloak-token", "", "keycloak token to be included in headers")
	flag.StringVar(&mode, "mode", "commit", "mode for each transaction submission")
	flag.StringVar(&jsonBody, "json-body", "{}", "json body sent to each of the nodes")
	flag.IntVar(&requestsPerSecond, "requests-per-sec", 10, "number of requests per second to be fired off per node")
}

func main() {
	flag.Parse()

	if keycloakToken == "" {
		log.Fatal("no keycloak secret provided\n")
	}

	if mode != "commit" && mode != "sync" && mode != "async" {
		log.Fatalf("%s is not a valid mode. choose from `commit`, `sync` or `async`.\n", mode)
	}

	appCtx, cancelFunc := context.WithCancel(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		<-sig
		cancelFunc()
	}()

	for i, url := range nodeUrls {
		go getEm(url, i+1, appCtx)
	}

	<-appCtx.Done()
}

func getEm(url string, nodeNumber int, ctx context.Context) {
	ticker := time.NewTicker(time.Second / time.Duration(requestsPerSecond))
	for {
		select {
		case <-ctx.Done():
			break
		case <-ticker.C:
			go func() {
				reqBody := []byte(jsonBody)
				req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
				if err != nil {
					wrapped := fmt.Errorf("unable to create request due to the following error: %w", err)
					log.Fatalln(wrapped.Error())
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", keycloakToken))
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

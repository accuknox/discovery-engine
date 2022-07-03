package cluster

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// WatchK8sPods Function
func WatchK8sPods() *http.Response {

	var host, port, token string

	if IsInCluster() { // kube-apiserver

		host, port, token = GetK8sClientConfig()

		watchClient := &http.Client{
			// #nosec
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}

		URL := "https://" + host + ":" + port + "/api/v1/pods?watch=true"

		req, err := http.NewRequest("GET", URL, nil)
		if err != nil {
			return nil
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

		resp, err := watchClient.Do(req)
		if err != nil {
			return nil
		}

		return resp
	}

	// kube-proxy (local)
	URL := "http://" + host + ":" + port + "/api/v1/pods?watch=true"

	// #nosec
	if resp, err := http.Get(URL); err == nil {
		return resp
	}

	return nil
}

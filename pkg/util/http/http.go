package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

func Request(ctx context.Context, method, url string, headers map[string]string, body interface{}) (*http.Response, error) {
	var err error

	bodyStr := []byte{}
	if body != nil {
		bodyStr, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(bodyStr))
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return http.DefaultClient.Do(req)
}

package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {

	tests := []struct {
		name           string
		headers        map[string]string
		expectedErrMsg string
		expectedToken  string
	}{
		{
			name:           "no headers",
			headers:        nil,
			expectedErrMsg: "no authorization header included",
		},
		{
			name:           "no auth header",
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedErrMsg: "no authorization header included",
		},
		{
			name:           "malformed header",
			headers:        map[string]string{"Content-Type": "application/json", "Authorization": "Foo XYZ"},
			expectedErrMsg: "malformed authorization header",
		},
		{
			name:           "case insensitive header value prefix fails",
			headers:        map[string]string{"Content-Type": "application/json", "authorization": "ApIkEy XYZ"},
			expectedErrMsg: "malformed authorization header",
		},
		{
			name:           "no token",
			headers:        map[string]string{"Content-Type": "application/json", "authorization": "ApiKey"},
			expectedErrMsg: "malformed authorization header",
		},
		{
			name:           "no token, bad value prefix",
			headers:        map[string]string{"Content-Type": "application/json", "authorization": "Foo"},
			expectedErrMsg: "malformed authorization header",
		},

		{
			name:          "case insensitive header key success",
			headers:       map[string]string{"Content-Type": "application/json", "authorization": "ApiKey XYZ"},
			expectedToken: "XYZ",
		},
		{
			name:          "case insensitive header key success",
			headers:       map[string]string{"Content-Type": "application/json", "Authorization": "ApiKey XYZ"},
			expectedToken: "XYZ",
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.headers != nil {
				for k, v := range tt.headers {
					headers.Add(k, v)
				}
			}

			token, err := GetAPIKey(headers)
			if tt.expectedErrMsg != "" {
				if err == nil || token != "" {
					t.Fatalf("expected empty string token and error message '%v'; got '%s' and '%v'", tt.expectedErrMsg, token, err)
					return
				}

				if tt.expectedErrMsg != err.Error() {
					t.Fatalf("expected error message '%v'; got '%v'", tt.expectedErrMsg, err)
					return
				}
			}

			if tt.expectedToken != token {
				t.Fatalf("expected token '%s'; got '%s'", tt.expectedToken, token)
				return
			}
		})
	}
}

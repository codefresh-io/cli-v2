package config

import (
	"bytes"
	"context"
	"testing"

	"github.com/codefresh-io/go-sdk/pkg/codefresh"
	"github.com/codefresh-io/go-sdk/pkg/codefresh/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestConfig_Write(t *testing.T) {
	tests := map[string]struct {
		ctx      context.Context
		config   Config
		prepFn   func(t *testing.T, usersMock *mocks.UsersAPI)
		assertFn func(t *testing.T, usersMock *mocks.UsersAPI, out string, err error)
	}{
		"Basic": {
			ctx: context.Background(),
			config: Config{
				Contexts: map[string]AuthContext{
					"foo": {
						Type:  "APIKey",
						Name:  "foo",
						Token: "123qwe",
						URL:   "https://g.codefresh.io",
					},
				},
				CurrentContext: "foo",
			},
			prepFn: func(t *testing.T, usersMock *mocks.UsersAPI) {
				usersMock.On("GetCurrent", mock.Anything).Return(&codefresh.User{
					Name: "foo",
					Accounts: []codefresh.Account{
						{
							Name: "bar",
						},
					},
					ActiveAccountName: "bar",
				}, nil)
			},
			assertFn: func(t *testing.T, usersMock *mocks.UsersAPI, out string, err error) {
				usersMock.AssertCalled(t, "GetCurrent", mock.Anything)
				assert.Contains(t, out, "foo")
				assert.Contains(t, out, "VALID")
				assert.Contains(t, out, "bar")
				assert.Contains(t, out, "*")
			},
		},
	}

	orgCf := newCodefresh
	defer func() { newCodefresh = orgCf }()

	for tname, tt := range tests {
		t.Run(tname, func(t *testing.T) {
			usersMock := &mocks.UsersAPI{}
			cfMock := &mocks.Codefresh{}
			cfMock.On("Users").Return(usersMock)
			newCodefresh = func(opts *codefresh.ClientOptions) codefresh.Codefresh { return cfMock }

			tt.prepFn(t, usersMock)
			w := &bytes.Buffer{}
			err := tt.config.Write(tt.ctx, w)

			tt.assertFn(t, usersMock, w.String(), err)
		})
	}
}

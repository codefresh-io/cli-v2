// // Copyright 2023 The Codefresh Authors.
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //     http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.

package config

// import (
// 	"bytes"
// 	"context"
// 	"testing"

// 	"github.com/codefresh-io/go-sdk/pkg/codefresh"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/mock"
// )

// func TestConfig_Write(t *testing.T) {
// 	tests := map[string]struct {
// 		config   ConfigImpl
// 		beforeFn func(usersMock *mocks.UsersAPI)
// 		assertFn func(t *testing.T, usersMock *mocks.UsersAPI, out string, err error)
// 	}{
// 		"Basic": {
// 			config: ConfigImpl{
// 				Contexts: map[string]*AuthContext{
// 					"foo": {
// 						Type:  "APIKey",
// 						Name:  "foo",
// 						Token: "123qwe",
// 						URL:   "https://g.codefresh.io",
// 					},
// 				},
// 				CurrentContext: "foo",
// 			},
// 			beforeFn: func(usersMock *mocks.UsersAPI) {
// 				usersMock.On("GetCurrent", mock.Anything).Return(&codefresh.User{
// 					Name: "foo",
// 					Accounts: []codefresh.Account{
// 						{
// 							Name: "bar",
// 						},
// 					},
// 					ActiveAccountName: "bar",
// 				}, nil)
// 			},
// 			assertFn: func(t *testing.T, usersMock *mocks.UsersAPI, out string, _ error) {
// 				usersMock.AssertCalled(t, "GetCurrent", mock.Anything)
// 				assert.Contains(t, out, "foo")
// 				assert.Contains(t, out, "VALID")
// 				assert.Contains(t, out, "bar")
// 				assert.Contains(t, out, "*")
// 			},
// 		},
// 	}

// 	orgCf := NewCodefresh
// 	defer func() { NewCodefresh = orgCf }()

// 	for tname, tt := range tests {
// 		t.Run(tname, func(t *testing.T) {
// 			usersMock := &mocks.UsersAPI{}
// 			cfMock := &mocks.Codefresh{}
// 			cfMock.On("Users").Return(usersMock)
// 			NewCodefresh = func(opts *codefresh.ClientOptions) codefresh.Codefresh { return cfMock }

// 			tt.beforeFn(usersMock)
// 			w := &bytes.Buffer{}
// 			err := tt.config.Write(context.Background(), w)

// 			tt.assertFn(t, usersMock, w.String(), err)
// 		})
// 	}
// }

// func TestConfig_GetUser(t *testing.T) {
// 	tests := map[string]struct {
// 		config   ConfigImpl
// 		beforeFn func(usersMock *mocks.UsersAPI)
// 		assertFn func(t *testing.T, user *codefresh.User, usersMock *mocks.UsersAPI, err error)
// 	}{
// 		"Basic": {
// 			config: ConfigImpl{
// 				Contexts: map[string]*AuthContext{
// 					"foo": {
// 						Type:  "APIKey",
// 						Name:  "foo",
// 						Token: "123qwe",
// 						URL:   "https://g.codefresh.io",
// 					},
// 				},
// 				CurrentContext: "foo",
// 			},
// 			beforeFn: func(usersMock *mocks.UsersAPI) {
// 				usersMock.On("GetCurrent", mock.Anything).Return(&codefresh.User{
// 					Name: "foo",
// 					Accounts: []codefresh.Account{
// 						{
// 							Name: "bar",
// 							ID:   "1234",
// 						},
// 					},
// 					ActiveAccountName: "bar",
// 				}, nil)
// 			},
// 			assertFn: func(t *testing.T, user *codefresh.User, usersMock *mocks.UsersAPI, _ error) {
// 				usersMock.AssertCalled(t, "GetCurrent", mock.Anything)
// 				assert.Equal(t, "bar", user.GetActiveAccount().Name)
// 				assert.Equal(t, "1234", user.GetActiveAccount().ID)
// 			},
// 		},
// 	}

// 	orgCf := NewCodefresh
// 	defer func() { NewCodefresh = orgCf }()

// 	for tname, tt := range tests {
// 		t.Run(tname, func(t *testing.T) {
// 			usersMock := &mocks.UsersAPI{}
// 			cfMock := &mocks.Codefresh{}
// 			cfMock.On("Users").Return(usersMock)
// 			NewCodefresh = func(opts *codefresh.ClientOptions) codefresh.Codefresh { return cfMock }

// 			tt.beforeFn(usersMock)
// 			user, err := tt.config.GetUser(context.Background())

// 			tt.assertFn(t, user, usersMock, err)
// 		})
// 	}
// }

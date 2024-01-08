// Copyright 2024 The Codefresh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by MockGen. DO NOT EDIT.
// Source: ./config.go

// Package config is a generated GoMock package.
package config

import (
	context "context"
	io "io"
	reflect "reflect"

	config "github.com/codefresh-io/cli-v2/pkg/config"
	codefresh "github.com/codefresh-io/go-sdk/pkg/codefresh"
	rest "github.com/codefresh-io/go-sdk/pkg/rest"
	gomock "github.com/golang/mock/gomock"
	cobra "github.com/spf13/cobra"
)

// MockConfig is a mock of Config interface.
type MockConfig struct {
	ctrl     *gomock.Controller
	recorder *MockConfigMockRecorder
}

// MockConfigMockRecorder is the mock recorder for MockConfig.
type MockConfigMockRecorder struct {
	mock *MockConfig
}

// NewMockConfig creates a new mock instance.
func NewMockConfig(ctrl *gomock.Controller) *MockConfig {
	mock := &MockConfig{ctrl: ctrl}
	mock.recorder = &MockConfigMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConfig) EXPECT() *MockConfigMockRecorder {
	return m.recorder
}

// CreateContext mocks base method.
func (m *MockConfig) CreateContext(ctx context.Context, name, token, url, caCert string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateContext", ctx, name, token, url, caCert)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateContext indicates an expected call of CreateContext.
func (mr *MockConfigMockRecorder) CreateContext(ctx, name, token, url, caCert interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateContext", reflect.TypeOf((*MockConfig)(nil).CreateContext), ctx, name, token, url, caCert)
}

// DeleteContext mocks base method.
func (m *MockConfig) DeleteContext(name string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteContext", name)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteContext indicates an expected call of DeleteContext.
func (mr *MockConfigMockRecorder) DeleteContext(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteContext", reflect.TypeOf((*MockConfig)(nil).DeleteContext), name)
}

// GetAccountId mocks base method.
func (m *MockConfig) GetAccountId(ctx context.Context) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccountId", ctx)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccountId indicates an expected call of GetAccountId.
func (mr *MockConfigMockRecorder) GetAccountId(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccountId", reflect.TypeOf((*MockConfig)(nil).GetAccountId), ctx)
}

// GetCurrentContext mocks base method.
func (m *MockConfig) GetCurrentContext() *config.AuthContext {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCurrentContext")
	ret0, _ := ret[0].(*config.AuthContext)
	return ret0
}

// GetCurrentContext indicates an expected call of GetCurrentContext.
func (mr *MockConfigMockRecorder) GetCurrentContext() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCurrentContext", reflect.TypeOf((*MockConfig)(nil).GetCurrentContext))
}

// GetUser mocks base method.
func (m *MockConfig) GetUser(ctx context.Context) (*rest.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUser", ctx)
	ret0, _ := ret[0].(*rest.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUser indicates an expected call of GetUser.
func (mr *MockConfigMockRecorder) GetUser(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUser", reflect.TypeOf((*MockConfig)(nil).GetUser), ctx)
}

// Load mocks base method.
func (m *MockConfig) Load(cmd *cobra.Command, args []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Load", cmd, args)
	ret0, _ := ret[0].(error)
	return ret0
}

// Load indicates an expected call of Load.
func (mr *MockConfigMockRecorder) Load(cmd, args interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Load", reflect.TypeOf((*MockConfig)(nil).Load), cmd, args)
}

// NewAdHocClient mocks base method.
func (m *MockConfig) NewAdHocClient(ctx context.Context, url, token, caCert string) (codefresh.Codefresh, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewAdHocClient", ctx, url, token, caCert)
	ret0, _ := ret[0].(codefresh.Codefresh)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewAdHocClient indicates an expected call of NewAdHocClient.
func (mr *MockConfigMockRecorder) NewAdHocClient(ctx, url, token, caCert interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewAdHocClient", reflect.TypeOf((*MockConfig)(nil).NewAdHocClient), ctx, url, token, caCert)
}

// NewClient mocks base method.
func (m *MockConfig) NewClient() codefresh.Codefresh {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewClient")
	ret0, _ := ret[0].(codefresh.Codefresh)
	return ret0
}

// NewClient indicates an expected call of NewClient.
func (mr *MockConfigMockRecorder) NewClient() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewClient", reflect.TypeOf((*MockConfig)(nil).NewClient))
}

// RequireAuthentication mocks base method.
func (m *MockConfig) RequireAuthentication(cmd *cobra.Command, args []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequireAuthentication", cmd, args)
	ret0, _ := ret[0].(error)
	return ret0
}

// RequireAuthentication indicates an expected call of RequireAuthentication.
func (mr *MockConfigMockRecorder) RequireAuthentication(cmd, args interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequireAuthentication", reflect.TypeOf((*MockConfig)(nil).RequireAuthentication), cmd, args)
}

// Save mocks base method.
func (m *MockConfig) Save() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Save")
	ret0, _ := ret[0].(error)
	return ret0
}

// Save indicates an expected call of Save.
func (mr *MockConfigMockRecorder) Save() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Save", reflect.TypeOf((*MockConfig)(nil).Save))
}

// UseContext mocks base method.
func (m *MockConfig) UseContext(ctx context.Context, name string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UseContext", ctx, name)
	ret0, _ := ret[0].(error)
	return ret0
}

// UseContext indicates an expected call of UseContext.
func (mr *MockConfigMockRecorder) UseContext(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UseContext", reflect.TypeOf((*MockConfig)(nil).UseContext), ctx, name)
}

// Write mocks base method.
func (m *MockConfig) Write(ctx context.Context, w io.Writer) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Write", ctx, w)
	ret0, _ := ret[0].(error)
	return ret0
}

// Write indicates an expected call of Write.
func (mr *MockConfigMockRecorder) Write(ctx, w interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*MockConfig)(nil).Write), ctx, w)
}

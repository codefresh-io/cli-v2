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

package fs

import (
	"os"
	"reflect"
	"testing"

	"github.com/codefresh-io/cli-v2/internal/util"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	billyUtils "github.com/go-git/go-billy/v5/util"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type (
	SampleJson struct {
		Name string `json:"name"`
	}
)

func TestCreate(t *testing.T) {
	tests := map[string]struct {
		bfs      billy.Filesystem
		beforeFn func(fs billy.Filesystem) FS
	}{
		"should create FS": {
			bfs: memfs.New(),
			beforeFn: func(bfs billy.Filesystem) FS {
				return &fsimpl{bfs}
			},
		},
	}
	for tname, tt := range tests {
		t.Run(tname, func(t *testing.T) {
			want := tt.beforeFn(tt.bfs)
			if got := Create(tt.bfs); !reflect.DeepEqual(got, want) {
				t.Errorf("Create() = %v, want %v", got, want)
			}
		})
	}
}

func Test_fsimpl_ReadFile(t *testing.T) {
	tests := map[string]struct {
		filename string
		want     []byte
		wantErr  string
		beforeFn func() FS
	}{
		"Should read file data": {
			filename: "file",
			want:     []byte("some data"),
			beforeFn: func() FS {
				memfs := memfs.New()
				_ = billyUtils.WriteFile(memfs, "file", []byte("some data"), 0666)
				return Create(memfs)
			},
		},
		"Should fail if file does not exist": {
			filename: "file",
			wantErr:  os.ErrNotExist.Error(),
			beforeFn: func() FS {
				memfs := memfs.New()
				return Create(memfs)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			fs := tt.beforeFn()
			got, err := readFile(fs, tt.filename)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fsimpl_ReadYamls(t *testing.T) {
	tests := map[string]struct {
		o        []interface{}
		wantErr  string
		beforeFn func() FS
		assertFn func(*testing.T, ...interface{})
	}{
		"Should read a simple yaml file": {
			o: []interface{}{
				&corev1.Namespace{},
			},
			beforeFn: func() FS {
				ns := &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "Namespace",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "namespace",
					},
				}
				y, _ := yaml.Marshal(ns)
				memfs := memfs.New()
				_ = billyUtils.WriteFile(memfs, "filename", y, 0666)
				return Create(memfs)
			},
			assertFn: func(t *testing.T, o ...interface{}) {
				ns := o[0].(*corev1.Namespace)
				assert.Equal(t, "namespace", ns.Name)
			},
		},
		"Should return two manifests when requested": {
			o: []interface{}{
				&corev1.Namespace{},
				&corev1.Namespace{},
			},
			beforeFn: func() FS {
				ns1 := &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "Namespace",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "namespace1",
					},
				}
				ns2 := &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "Namespace",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "namespace2",
					},
				}
				y1, _ := yaml.Marshal(ns1)
				y2, _ := yaml.Marshal(ns2)
				data := util.JoinManifests(y1, y2)
				memfs := memfs.New()
				_ = billyUtils.WriteFile(memfs, "filename", data, 0666)
				return Create(memfs)
			},
			assertFn: func(t *testing.T, o ...interface{}) {
				ns1 := o[0].(*corev1.Namespace)
				ns2 := o[1].(*corev1.Namespace)
				assert.Equal(t, "namespace1", ns1.Name)
				assert.Equal(t, "namespace2", ns2.Name)
			},
		},
		"Should return only the 2nd manifest when requested": {
			o: []interface{}{
				nil,
				&corev1.Namespace{},
			},
			beforeFn: func() FS {
				ns1 := &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "Namespace",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "namespace1",
					},
				}
				ns2 := &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "Namespace",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "namespace2",
					},
				}
				y1, _ := yaml.Marshal(ns1)
				y2, _ := yaml.Marshal(ns2)
				data := util.JoinManifests(y1, y2)
				memfs := memfs.New()
				_ = billyUtils.WriteFile(memfs, "filename", data, 0666)
				return Create(memfs)
			},
			assertFn: func(t *testing.T, o ...interface{}) {
				assert.Nil(t, o[0])
				ns2 := o[1].(*corev1.Namespace)
				assert.Equal(t, "namespace2", ns2.Name)
			},
		},
		"Should fail if file does not exist": {
			o: []interface{}{
				&corev1.Namespace{},
			},
			wantErr: os.ErrNotExist.Error(),
			beforeFn: func() FS {
				memfs := memfs.New()
				return Create(memfs)
			},
		},
		"Should fail if file contains less manifests than expected": {
			o: []interface{}{
				&corev1.Namespace{},
				&corev1.Namespace{},
			},
			wantErr: "expected at least 2 manifests when reading 'filename'",
			beforeFn: func() FS {
				ns := &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "Namespace",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "namespace",
					},
				}
				memfs := memfs.New()
				y, _ := yaml.Marshal(ns)
				_ = billyUtils.WriteFile(memfs, "filename", y, 0666)
				return Create(memfs)
			},
		},
		"Should fail if second manifest is corrupted": {
			o: []interface{}{
				&corev1.Namespace{},
				&corev1.Namespace{},
			},
			wantErr: "error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type v1.Namespace",
			beforeFn: func() FS {
				ns := &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "Namespace",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "namespace",
					},
				}
				y, _ := yaml.Marshal(ns)
				memfs := memfs.New()
				data := util.JoinManifests(y, []byte("some data"))
				_ = billyUtils.WriteFile(memfs, "filename", data, 0666)
				return Create(memfs)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			fs := tt.beforeFn()
			if err := fs.ReadYamls("filename", tt.o...); err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			if tt.assertFn != nil {
				tt.assertFn(t, tt.o...)
			}
		})
	}
}

// Copyright 2022 The Codefresh Authors.
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

// Copyright 2021 The Codefresh Authors.
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

package assets

import "github.com/gobuffalo/packr"

// You can use the "packr clean" command to clean up this,
// and any other packr generated files.
func init() {
	_ = packr.PackJSONBytes("../../assets", "README.md", "\"dGhpcyBpcyBoZXJlIGp1c3QgdG8gZml4IHRoaXMgaXNzdWU6IGh0dHBzOi8vZ2l0aHViLmNvbS9hcmdvcHJvai9hcmdvLWNkL2lzc3Vlcy8yOTA3\"")
	_ = packr.PackJSONBytes("../../assets", "badge.svg", "\"bW9jaw==\"")
	_ = packr.PackJSONBytes("../../assets", "builtin-policy.csv", "\"bW9jaw==\"")
	_ = packr.PackJSONBytes("../../assets", "model.conf", "\"bW9jaw==\"")
	_ = packr.PackJSONBytes("../../assets", "swagger.json", "\"Im1vY2si\"")
}

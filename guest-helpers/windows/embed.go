/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package windowshelpers embeds the Windows guest helper scripts so the operator
// can distribute them via ConfigMap without requiring a git checkout.
package windowshelpers

import "embed"

// Scripts contains setup.bat and filerestore.bat from this directory.
//
//go:embed setup.bat filerestore.bat
var Scripts embed.FS

const (
	SetupScriptName       = "setup.bat"
	FileRestoreScriptName = "filerestore.bat"
)

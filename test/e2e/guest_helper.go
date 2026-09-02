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

package e2e

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"time"
)

// installGuestHelper extracts setup.sh and filerestore.sh from linuxHelperTar,
// stages each file on the VM via a single-quoted heredoc (avoids base64 overhead
// and SSH exec-request size limits), then runs setup.sh with the operator's public key.
func installGuestHelper(vmiName, namespace, operatorPubKey string, linuxHelperTar []byte, identityFile string) error {
	scripts, err := extractTar(linuxHelperTar)
	if err != nil {
		return fmt.Errorf("extract linux-helpers.tar: %w", err)
	}

	helperScript, ok := scripts["filerestore.sh"]
	if !ok {
		return fmt.Errorf("filerestore.sh not found in linux-helpers.tar")
	}
	setupScript, ok := scripts["setup.sh"]
	if !ok {
		return fmt.Errorf("setup.sh not found in linux-helpers.tar")
	}

	stageDir := fmt.Sprintf("/root/filerestore-helper-%d", time.Now().UnixNano())
	defer func() {
		_, _ = runSSHCommand(vmiName, namespace, fmt.Sprintf("rm -rf %s", stageDir), identityFile)
	}()

	// Stage both files individually to stay well under the SSH exec-request packet limit.
	// Single-quoted heredoc (<<'STAGE_EOF') passes content literally without variable expansion.
	for name, content := range map[string]string{"filerestore.sh": helperScript, "setup.sh": setupScript} {
		path := stageDir + "/" + name
		cmd := fmt.Sprintf(
			"mkdir -m 0700 -p %s && cat <<'STAGE_EOF' > %s && chown root:root %s && chmod 0644 %s\n%s\nSTAGE_EOF",
			stageDir, path, path, path, content,
		)
		if _, err := runSSHCommand(vmiName, namespace, cmd, identityFile); err != nil {
			return fmt.Errorf("stage %s on VM: %w", name, err)
		}
	}

	// Verify staged files are in place before running setup.
	if lsOut, err := runSSHCommand(vmiName, namespace, fmt.Sprintf("ls -la %s/", stageDir), identityFile); err != nil {
		return fmt.Errorf("staged files missing in %s: %w\n%s", stageDir, err, lsOut)
	}

	setupCmd := fmt.Sprintf("bash %s/setup.sh %s", stageDir, shellEscape(operatorPubKey))
	if out, err := runSSHCommand(vmiName, namespace, setupCmd, identityFile); err != nil {
		return fmt.Errorf("run guest setup.sh: %w\noutput:\n%s", err, out)
	}
	return nil
}

// extractTar reads an uncompressed tar archive and returns a map of filename -> content.
func extractTar(data []byte) (map[string]string, error) {
	files := make(map[string]string)
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		files[hdr.Name] = string(content)
	}
	return files, nil
}

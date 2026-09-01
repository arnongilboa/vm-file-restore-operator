//nolint:goconst // Test constants are acceptable
package controller

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	linuxhelpers "kubevirt.io/vm-file-restore-operator/guest-helpers/linux"
	windowshelpers "kubevirt.io/vm-file-restore-operator/guest-helpers/windows"
)

func TestEnsureOperatorResources_CreatesKeypair(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	require.NoError(t, EnsureOperatorResources(context.Background(), c, "test-ns"))

	secret := &corev1.Secret{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: OperatorResourceName, Namespace: "test-ns"}, secret))
	assert.Equal(t, corev1.SecretTypeSSHAuth, secret.Type)
	privKeyBytes, ok := secret.Data[corev1.SSHAuthPrivateKey]
	require.True(t, ok, "%s not found in Secret", corev1.SSHAuthPrivateKey)
	_, err := ssh.ParsePrivateKey(privKeyBytes)
	require.NoError(t, err, "private key is not valid")

	cm := &corev1.ConfigMap{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: OperatorResourceName, Namespace: "test-ns"}, cm))
	pubKey := cm.Data["ssh-publickey"]
	require.NotEmpty(t, pubKey)
	assert.InDelta(t, 100, len(pubKey), 50, "unexpected public key length")
	_, _, _, _, err = ssh.ParseAuthorizedKey([]byte(pubKey))
	require.NoError(t, err, "public key is not valid")

	assert.NotEmpty(t, cm.BinaryData[cmKeyLinuxHelpers], "%s missing from binaryData", cmKeyLinuxHelpers)
	assert.NotEmpty(t, cm.BinaryData[cmKeyWindowsHelpers], "%s missing from binaryData", cmKeyWindowsHelpers)
}

func TestEnsureOperatorResources_SkipsIfBothExistWithCurrentTars(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	linuxTar, err := buildTar(linuxhelpers.Scripts, "setup.sh", "filerestore.sh")
	require.NoError(t, err)
	windowsTar, err := buildTar(windowshelpers.Scripts, "setup.bat", "filerestore.bat")
	require.NoError(t, err)

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorResourceName, Namespace: "test-ns"},
		Type:       corev1.SecretTypeSSHAuth,
		Data:       map[string][]byte{corev1.SSHAuthPrivateKey: []byte("existing-key")},
	}
	existingConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorResourceName, Namespace: "test-ns"},
		Data:       map[string]string{"ssh-publickey": "existing-pubkey"},
		BinaryData: map[string][]byte{cmKeyLinuxHelpers: linuxTar, cmKeyWindowsHelpers: windowsTar},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingSecret, existingConfigMap).Build()
	require.NoError(t, EnsureOperatorResources(context.Background(), c, "test-ns"))

	secret := &corev1.Secret{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: OperatorResourceName, Namespace: "test-ns"}, secret))
	assert.Equal(t, "existing-key", string(secret.Data[corev1.SSHAuthPrivateKey]), "Secret modified when both resources existed with current tars")

	cm := &corev1.ConfigMap{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: OperatorResourceName, Namespace: "test-ns"}, cm))
	assert.Equal(t, "existing-pubkey", cm.Data["ssh-publickey"], "ConfigMap public key modified when tars were already current")
}

func TestEnsureOperatorResources_UpgradesConfigMapWithHelperTars(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorResourceName, Namespace: "test-ns"},
		Type:       corev1.SecretTypeSSHAuth,
		Data:       map[string][]byte{corev1.SSHAuthPrivateKey: []byte("existing-key")},
	}
	existingConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorResourceName, Namespace: "test-ns"},
		Data:       map[string]string{"ssh-publickey": "existing-pubkey"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingSecret, existingConfigMap).Build()
	require.NoError(t, EnsureOperatorResources(context.Background(), c, "test-ns"))

	cm := &corev1.ConfigMap{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: OperatorResourceName, Namespace: "test-ns"}, cm))
	assert.Equal(t, "existing-pubkey", cm.Data["ssh-publickey"], "ssh-publickey overwritten during upgrade")
	assert.NotEmpty(t, cm.BinaryData[cmKeyLinuxHelpers], "%s not populated after upgrade", cmKeyLinuxHelpers)
	assert.NotEmpty(t, cm.BinaryData[cmKeyWindowsHelpers], "%s not populated after upgrade", cmKeyWindowsHelpers)

	secret := &corev1.Secret{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: OperatorResourceName, Namespace: "test-ns"}, secret))
	assert.Equal(t, "existing-key", string(secret.Data[corev1.SSHAuthPrivateKey]), "Secret modified during ConfigMap upgrade")
}

func TestEnsureOperatorResources_RecoversMissingConfigMap(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	// Use a real keypair — the recovery path parses the private key to derive the public key.
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privKeyBytes, err := ssh.MarshalPrivateKey(privateKey, "")
	require.NoError(t, err)
	privKeyPEM := pem.EncodeToMemory(privKeyBytes)

	orphanedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorResourceName, Namespace: "test-ns"},
		Type:       corev1.SecretTypeSSHAuth,
		Data:       map[string][]byte{corev1.SSHAuthPrivateKey: privKeyPEM},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(orphanedSecret).Build()
	require.NoError(t, EnsureOperatorResources(context.Background(), c, "test-ns"))

	// Secret must be PRESERVED — deleting it would revoke access on all configured VMs.
	secret := &corev1.Secret{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: OperatorResourceName, Namespace: "test-ns"}, secret))
	assert.Equal(t, privKeyPEM, secret.Data[corev1.SSHAuthPrivateKey], "Secret should be preserved when ConfigMap is missing")

	// ConfigMap must be created with a parseable public key.
	cm := &corev1.ConfigMap{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: OperatorResourceName, Namespace: "test-ns"}, cm))
	require.NotEmpty(t, cm.Data[cmKeyPublicKey])
	_, _, _, _, err = ssh.ParseAuthorizedKey([]byte(cm.Data[cmKeyPublicKey]))
	require.NoError(t, err, "recovered ConfigMap public key must be parseable")
	assert.NotEmpty(t, cm.BinaryData[cmKeyLinuxHelpers])
}

func TestEnsureOperatorResources_ReplacesStaleHelperTars(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	// Simulate a post-upgrade state where BinaryData is non-nil but contains stale content.
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorResourceName, Namespace: "test-ns"},
		Type:       corev1.SecretTypeSSHAuth,
		Data:       map[string][]byte{corev1.SSHAuthPrivateKey: []byte("existing-key")},
	}
	existingConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorResourceName, Namespace: "test-ns"},
		Data:       map[string]string{"ssh-publickey": "existing-pubkey"},
		BinaryData: map[string][]byte{
			cmKeyLinuxHelpers:   []byte("stale-linux-tar"),
			cmKeyWindowsHelpers: []byte("stale-windows-tar"),
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingSecret, existingConfigMap).Build()
	require.NoError(t, EnsureOperatorResources(context.Background(), c, "test-ns"))

	cm := &corev1.ConfigMap{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: OperatorResourceName, Namespace: "test-ns"}, cm))

	// Verify tars were replaced with the real embedded content.
	wantLinux, err := buildTar(linuxhelpers.Scripts, linuxhelpers.SetupScriptName, linuxhelpers.FileRestoreScriptName)
	require.NoError(t, err)
	wantWindows, err := buildTar(windowshelpers.Scripts, windowshelpers.SetupScriptName, windowshelpers.FileRestoreScriptName)
	require.NoError(t, err)

	assert.Equal(t, wantLinux, cm.BinaryData[cmKeyLinuxHelpers], "stale linux tar was not replaced")
	assert.Equal(t, wantWindows, cm.BinaryData[cmKeyWindowsHelpers], "stale windows tar was not replaced")
	assert.Equal(t, "existing-pubkey", cm.Data["ssh-publickey"], "public key should not be touched")
}

func TestEnsureOperatorResources_CleansUpOrphanedConfigMap(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	orphanedConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorResourceName, Namespace: "test-ns"},
		Data:       map[string]string{"ssh-publickey": "orphaned-pubkey"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(orphanedConfigMap).Build()
	require.NoError(t, EnsureOperatorResources(context.Background(), c, "test-ns"))

	// Verify new Secret was created with a real key.
	secret := &corev1.Secret{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: OperatorResourceName, Namespace: "test-ns"}, secret))
	assert.NotEmpty(t, secret.Data[corev1.SSHAuthPrivateKey])

	// Verify ConfigMap was recreated (orphaned pubkey replaced).
	cm := &corev1.ConfigMap{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: OperatorResourceName, Namespace: "test-ns"}, cm))
	assert.NotEqual(t, "orphaned-pubkey", cm.Data["ssh-publickey"], "orphaned ConfigMap pubkey was not replaced")
}

func TestEnsureOperatorResources_SecretGetAPIError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	boom := errors.New("apiserver unavailable")
	c := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(_ context.Context, _ crclient.WithWatch, _ crclient.ObjectKey, obj crclient.Object, _ ...crclient.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				return boom
			}
			return apierrors.NewNotFound(corev1.Resource("configmaps"), OperatorResourceName)
		},
	}).Build()

	err := EnsureOperatorResources(context.Background(), c, "test-ns")
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "failed to check for existing Secret")
}

func TestEnsureOperatorResources_ConfigMapGetAPIError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	boom := errors.New("apiserver unavailable")
	c := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(_ context.Context, _ crclient.WithWatch, _ crclient.ObjectKey, obj crclient.Object, _ ...crclient.GetOption) error {
			if _, ok := obj.(*corev1.ConfigMap); ok {
				return boom
			}
			return apierrors.NewNotFound(corev1.Resource("secrets"), OperatorResourceName)
		},
	}).Build()

	err := EnsureOperatorResources(context.Background(), c, "test-ns")
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "failed to check for existing ConfigMap")
}

func TestEnsureOperatorResources_EnsureHelperTarsUpdateError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	// Both exist but binaryData is stale (empty), so ensureHelperTars will call Update.
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorResourceName, Namespace: "test-ns"},
		Type:       corev1.SecretTypeSSHAuth,
		Data:       map[string][]byte{corev1.SSHAuthPrivateKey: []byte("key")},
	}
	existingConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorResourceName, Namespace: "test-ns"},
		Data:       map[string]string{"ssh-publickey": "pubkey"},
	}

	boom := errors.New("update conflict")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingSecret, existingConfigMap).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(_ context.Context, _ crclient.WithWatch, _ crclient.Object, _ ...crclient.UpdateOption) error {
				return boom
			},
		}).Build()

	err := EnsureOperatorResources(context.Background(), c, "test-ns")
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "failed to update ConfigMap with helper tars")
}

func TestBuildTar_Structure(t *testing.T) {
	tarBytes, err := buildTar(linuxhelpers.Scripts, "setup.sh", "filerestore.sh")
	require.NoError(t, err)

	tr := tar.NewReader(bytes.NewReader(tarBytes))
	found := map[string]int64{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		found[hdr.Name] = hdr.Mode
	}

	require.Contains(t, found, "setup.sh")
	require.Contains(t, found, "filerestore.sh")
	assert.Equal(t, int64(0755), found["setup.sh"], "setup.sh must be executable (0755)")
	assert.Equal(t, int64(0755), found["filerestore.sh"], "filerestore.sh must be executable (0755)")
}

const testOperatorNamespace = "test-operator-ns"

func sshSecret(data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      OperatorResourceName,
			Namespace: testOperatorNamespace,
		},
		Type: corev1.SecretTypeSSHAuth,
		Data: data,
	}
}

// getSSHPrivateKey must read the keypair Secret through the uncached APIReader,
// so these tests wire the fake client only into APIReader (never Client) to prove
// the read never falls back to the cached client.
func TestGetSSHPrivateKey_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	reader := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(sshSecret(map[string][]byte{corev1.SSHAuthPrivateKey: []byte("PRIVATE-KEY")})).
		Build()

	r := &VirtualMachineFileRestoreReconciler{
		APIReader:         reader,
		OperatorNamespace: testOperatorNamespace,
	}

	key, err := r.getSSHPrivateKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []byte("PRIVATE-KEY"), key)
}

func TestGetSSHPrivateKey_SecretNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	reader := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := &VirtualMachineFileRestoreReconciler{
		APIReader:         reader,
		OperatorNamespace: testOperatorNamespace,
	}

	key, err := r.getSSHPrivateKey(context.Background())
	require.Error(t, err)
	assert.Nil(t, key)
	assert.True(t, apierrors.IsNotFound(err), "expected NotFound, got %v", err)
}

func TestGetSSHPrivateKey_MissingPrivateKeyData(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	// Secret exists but has no SSHAuthPrivateKey entry.
	reader := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(sshSecret(map[string][]byte{"some-other-key": []byte("x")})).
		Build()

	r := &VirtualMachineFileRestoreReconciler{
		APIReader:         reader,
		OperatorNamespace: testOperatorNamespace,
	}

	key, err := r.getSSHPrivateKey(context.Background())
	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "not found in secret")
}

func TestGetSSHPrivateKey_APIError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	boom := errors.New("apiserver unavailable")
	reader := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ crclient.WithWatch, _ crclient.ObjectKey, _ crclient.Object, _ ...crclient.GetOption) error {
				return boom
			},
		}).Build()

	r := &VirtualMachineFileRestoreReconciler{
		APIReader:         reader,
		OperatorNamespace: testOperatorNamespace,
	}

	key, err := r.getSSHPrivateKey(context.Background())
	require.Error(t, err)
	assert.Nil(t, key)
	assert.ErrorIs(t, err, boom)
}

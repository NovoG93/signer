#!/bin/bash

set -e

KO_VERSION="0.18.0"
KIND_VERSION="0.30.0"
KUBECTL_VERSION="1.35.0"
HELM_VERSION="3.20.0"
ARCH="$(uname -m)"
TMP_DIR=$(mktemp -d)

echo "Configurations:"
echo "  KO Version: $KO_VERSION"
echo "  kind Version: $KIND_VERSION"
echo "  kubectl Version: $KUBECTL_VERSION"
echo "  helm Version: $HELM_VERSION"
echo "  Architecture: $ARCH"

echo "Starting end-to-end tests for signer with local provider..."

# Install kind
echo "Installing kind..."
if [ -x "$(command -v kind)" ]; then
  echo "kind is already installed"
else
  echo "kind not found, installing..."
  curl -Lo ./kind https://kind.sigs.k8s.io/dl/v${KIND_VERSION}/kind-linux-${ARCH}
  chmod +x ./kind
  sudo mv ./kind /usr/local/bin/kind
fi

# Creating temporary directory for kind config
KIND_CONFIG_DIR="$TMP_DIR/kind-config"
mkdir -p "$KIND_CONFIG_DIR"
cat <<EOF > "$KIND_CONFIG_DIR/kind-config.yaml"
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
featureGates:
  PodCertificateRequest: true
runtimeConfig:
  "certificates.k8s.io/v1beta1/podcertificaterequests": "true"
EOF


# Create kind cluster
kind delete cluster || true
echo "Creating kind cluster..."
kind create cluster --image kindest/node:v${KUBECTL_VERSION} --config "$KIND_CONFIG_DIR/kind-config.yaml"

# Install kubectl
if [ -x "$(command -v kubectl)" ]; then
  echo "kubectl is already installed"
else
  echo "Installing kubectl..."
  curl -LO "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl"
  chmod +x kubectl
  sudo mv kubectl /usr/local/bin/kubectl
fi

kubectl api-resources --api-group certificates.k8s.io | grep podcertificaterequests >/dev/null 2>&1 || { echo >&2 "PodCertificateRequest API not found in the cluster. Aborting."; exit 1; }

# Install ko
if [ -x "$(command -v ko)" ]; then
  echo "ko is already installed"
else
  echo "Installing ko..."
  curl -sSfL "https://github.com/ko-build/ko/releases/download/v${KO_VERSION}/ko_${KO_VERSION}_linux_${ARCH}.tar.gz" > ko.tar.gz
  tar xzf ko.tar.gz ko
  chmod +x ./ko
  sudo mv ko /usr/local/bin/ko
fi

# Installing helm
if [ -x "$(command -v helm)" ]; then
  echo "helm is already installed"
else
  echo "Installing helm..."
  curl -LO https://get.helm.sh/helm-v${HELM_VERSION}-linux-${ARCH}.tar.gz
  tar -zxvf helm-v${HELM_VERSION}-linux-${ARCH}.tar.gz
  sudo mv linux-${ARCH}/helm /usr/local/bin/helm
  rm -rf linux-${ARCH} helm-v${HELM_VERSION}-linux-${ARCH}.tar.gz
fi

# Build signer
echo "Building signer..."
# Use ko with --local to save the image to Docker daemon
pushd ./src >/dev/null 2>&1
SIGNER_IMAGE_FULL=$(KO_DOCKER_REPO=ko.local VERSION=$(git describe --tags --always --dirty) \
    ko build --tags "$(git describe --tags --always --dirty)" --bare --sbom none \
    --platform=linux/${ARCH} --local .)
echo "Built image: $SIGNER_IMAGE_FULL"
popd >/dev/null 2>&1

# Extract image name and tag (strip the @sha256 digest for kind load and kustomize)
SIGNER_IMAGE="${SIGNER_IMAGE_FULL%%@*}"
SIGNER_TAG="${SIGNER_IMAGE##*:}"
echo "Using image reference: $SIGNER_IMAGE"


# Load all images into kind cluster
echo "Loading Docker images into kind cluster..."
kind load docker-image "$SIGNER_IMAGE"

# Deploy signer to the cluster
echo "Deploying signer with custom arguments..."

# Create temporary directory for kustomization
TEMP_KUSTOMIZE_DIR="$TMP_DIR/kustomize"
TEMP_CHART_DIR="$TMP_DIR/charts/signer"
mkdir -p "$TEMP_KUSTOMIZE_DIR"
mkdir -p "$TEMP_CHART_DIR"
echo "Using temporary kustomize directory: $TEMP_KUSTOMIZE_DIR"
cp -r kustomize/* "$TEMP_KUSTOMIZE_DIR/"
cp -r charts/signer/ "$TEMP_CHART_DIR/"

# Create values.yaml file on the fly
cat <<EOF > "$TEMP_KUSTOMIZE_DIR/values.yaml"
image:
  pullPolicy: IfNotPresent
  repository: ko.local
replicaCount: 1
env:
  signerName: "novog93.ghcr/signer"
  logLevel: "debug"
  leaderElection: "true"
  leaderElectionID: "signer-controller"
  leaderElectionNamespace: ""
  maxConcurrentReconciles: 1
  podNamespace: ""
  metricsBindAddress: ":8080"
  healthProbeBindAddress: ":8081"
  certValidity: "1h"
  certRefreshBefore: "5m"
  caSecretNamespace: ""
  caCertKey: "ca.crt"
  caKeyKey: "ca.key"
ca:
  commonName: "Lab Signer CA"
  validity: 3650
EOF

# Create netshoot pod yaml
cat <<EOF > "$TEMP_KUSTOMIZE_DIR/netshoot-pod.yaml"
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: netshoot
  name: netshoot
spec:
  containers:
  - command:
    - sleep
    - infinity
    image: nicolaka/netshoot:latest
    name: netshoot
    volumeMounts:
        - name: tls-certs
          mountPath: /var/run/secrets/tls
          readOnly: true
  volumes:
  - name: tls-certs
    projected:
      sources:
      - podCertificate:
          signerName: novog93.ghcr/signer
          keyType: RSA3072
          credentialBundlePath: tls.crt
EOF

# Extend kustomization.yaml to set the image
cat <<EOF >> "$TEMP_KUSTOMIZE_DIR/kustomization.yaml"

images:
  - name: ko.local
    newTag: $SIGNER_TAG
EOF

cat "$TEMP_KUSTOMIZE_DIR/kustomization.yaml"

# Apply the kustomization
kubectl kustomize "$TEMP_KUSTOMIZE_DIR" --enable-helm  | kubectl apply -f -

# add a wait for the deployment to be available
kubectl wait --for=condition=available --timeout=60s deployment/signer || true

kubectl describe pods -l app=signer
kubectl describe deployment signer
kubectl logs -l app=signer

# Start netshoot pod with PodCertificate volume
echo "Starting netshoot pod with PodCertificate volume..."
kubectl apply -f "$TEMP_KUSTOMIZE_DIR/netshoot-pod.yaml"

# Cleanup temporary directory
rm -rf "$TEMP_KUSTOMIZE_DIR"

# Wait for convergence
echo "Waiting for netshoot pod to be ready (implies certificate issued)..."
if kubectl wait --for=condition=ready pod/netshoot --timeout=120s; then
    echo "Netshoot Pod started successfully! Certificate was issued."
else
    echo "Netshoot Pod failed to start. Debugging..."
    kubectl describe pod netshoot
    kubectl logs -l app=signer
    exit 1
fi

# Check that the records are present
echo "Checking services again..."
kubectl get podcertificaterequests -A
kubectl describe pod netshoot
kubectl logs -l app=signer


echo "End-to-end test completed!"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    if [ ! -z "$EXTERNAL_DNS_PID" ]; then
        kill $EXTERNAL_DNS_PID 2>/dev/null || true
    fi
    kind delete cluster 2>/dev/null || true
}

# Set trap to cleanup on script exit
trap cleanup EXIT
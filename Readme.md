# Signer: Kubernetes PodCertificateRequest Controller

A Kubernetes controller that implements a **Signer** for `PodCertificateRequest` (PCR) resources. It automatically generates and manages X.509 certificates for pods using a self-signed Certificate Authority (CA).

---
DISCLAIMER: This project is only a toy implementation for my education and experimentation purposes. Do NOT use in production environments.
If you are looking for a production-ready solution, consider using [cert-manager](https://cert-manager.io/docs/usage/kube-csr/) or other established tools.
---

## Features

* **Automated Signing**: Watches for `PodCertificateRequest` resources and issues certificates automatically.
* **Flexible CA Management**:
  * **In-Memory**: Generates a self-signed CA on startup (ephemeral).
  * **Persistent**: Can load an existing CA from a Kubernetes Secret.
* **Key Support**: Supports both **RSA** and **ECDSA** key pairs.
* **High Availability**: Built-in leader election for multi-replica deployments.
* **Observability**: Exposes Prometheus metrics (`signer_certificates_issued_total`, `signer_certificates_failed_total`) and health probes (`/healthz`, `/readyz`).
* **Configurable Validity**: Customize certificate validity duration and refresh windows.

## Installation

### Prerequisites

* Kubernetes cluster (v1.35+)
* Helm v3+ (optional, for Chart installation)

#### Enabling the API

The controller relies on the `certificates.k8s.io/v1beta1` API, this needs to be enabled in your cluster. 

On a kubeadm cluster this can be done in the following way:
* Add `--feature-gates=PodCertificateRequest=true` and `--runtime-config=certificates.k8s.io/v1beta1/podcertificaterequests=true` to kube-apiserver.yaml on Control Plane nodes.
* Verify with `kubectl get podcertificaterequests -A` -> no API error (`error: the server doesn't have a resource type "podcertificaterequests"`) should be returned.


### Using Helm

The project includes a Helm chart for easy deployment.

1. **Package the chart** (optional if installing from source):
```bash
helm pull oci://ghcr.io/novog93/signer --version <version>
```


2. **Install the chart**:
```bash
helm install signer oci://ghcr.io/novog93/charts/signer --version <version> --namespace signer --create-namespace
```



### Using Kustomize

You can deploy the controller using Kustomize directly from the repository.

```bash
kubectl create namespace signer
cat values.yaml << EOF > values.yaml
replicas: 3
podDisruptionBudget:
  enabled: true
  minAvailable: 2
EOF

cat <<EOF | kubectl apply -f -
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: signer

helmCharts:
  - name: signer
    releaseName: signer
    valuesFile: values.yaml
EOF
```

## Configuration

### Environment Variables

The controller is configured via environment variables. These can be set via the values.yaml.

| Variable | Description | Default |
| --- | --- | --- |
| `SIGNER_NAME` | The signer name to listen for in PCRs. | `novog93.ghcr/signer` |
| `LOG_LEVEL` | Logging verbosity (`info` or `debug`). | `info` |
| `LEADER_ELECTION` | Enable leader election for HA. | `true` |
| `CERT_VALIDITY` | Duration for which issued certs are valid. | `1h` |
| `CERT_REFRESH_BEFORE` | Time window before expiration to trigger refresh. | `30m` |
| `CA_SECRET_NAME` | Name of Secret to load CA from. If empty, generates new CA. | `""` |
| `CA_SECRET_NAMESPACE` | Namespace of the CA Secret. | `""` |

## Usage

To request a certificate for a pod, create a pod containing a `podCertificate` volume source.

**Example `PodCertificateRequest`:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: netshoot
spec:
  containers:
  - command:
    - sleep
    - inf
    image: nicolaka/netshoot
    name: netshoot
  volumes:
  - name: tls-certs
    projected:
      sources:
      - podCertificate:
          signerName: novog93.ghcr/signer
          keyType: RSA3072
          credentialBundlePath: tls.crt
```

Once applied, the Signer controller will validate the request and populate the `.status.certificateChain` field with the PEM-encoded certificate.



## Architecture

1. **Controller**: The main loop runs a `SignerReconciler` using the `controller-runtime` framework.
2. **CA Helper**: Handles cryptographic operations. It can initialize a new Self-Signed CA or load one from a Secret (`tls.crt`, `tls.key`).
3. **Metrics**: Prometheus metrics are exposed on port `8080` (default) to track issued and failed certificates.


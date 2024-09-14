# k8s-tpm-kms-plugin

# Usage

```
Usage of k8s-tpm-kms-plugin:
  -additional-secret string
        ADDITIONAL_SECRET
  -data-dir string
        DATA_DIR Full path to data directory (default "/var/lib/k8s-tpm-kms-plugin/")
  -export string
        Domain Key export path
  -healthz-path string
        Path at which to publish healthz (default "healthz")
  -healthz-port int
        Port on which to publish healthz (default 8081)
  -healthz-timeout duration
        timeout in seconds for communicating with the unix socket (default 5s)
  -import string
        Domain Key import path
  -kms string
        Kubernetes Service API version. Possible values: v1, v2. Default value is v2. (default "v2")
  -metrics-path string
        Path at which to publish metrics (default "metrics")
  -metrics-port int
        Port on which to publish metrics (default 8082)
  -password string
        import/export password
  -provision
        create Domain Key
  -tpm-device string
        TPM_DEVICE Path to tpm device or tpm resource manager. (default "/dev/tpmrm0")
  -tpm-pcrs string
        TPM_PCRS PCRs to measure.
  -unix-socket string
        Full path to Unix socket that is used for communicating with KubeAPI Server, or Linux socket namespace object - must start with @ (default "/var/run/k8s-tpm-kms-plugin.sock")
```

## Provision

**In First Control Plan Node:**

```bash
$ k8s-tpm-kms-plugin --provision \
  --additional-secret="additional_secret_for_domain_key" # optional. must be shared between all nodes. 
  --data-dir=/var/lib/k8s-tpm-kms-plugin/                # default

$ k8s-tpm-kms-plugin --export exported.bin \ 
  --data-dir=/var/lib/k8s-tpm-kms-plugin/                # default
Enter password: **********
Confirm: **********
```

**In Other Control Plan Nodes:**

```bash
$ k8s-tpm-kms-plugin --import exported.bin \ 
  --data-dir=/var/lib/k8s-tpm-kms-plugin/                # default
Enter password: **********
```

## Installation for Kubernetes

```bash
$ sudo wget -O /opt/k8s-tpm-kms-plugin https://github.com/jc-lab/k8s-tpm-kms-plugin/releases/download/v0.0.4/k8s-tpm-kms-plugin-linux_x86_64
$ sudo chmod +x /opt/k8s-tpm-kms-plugin
$ sudo mkdir -p mkdir -p /var/run/kmsplugin/ /var/lib/k8s-tpm-kms-plugin/
(WAIT! You must provision.)
$ cat <<EOF | sudo tee /etc/systemd/system/k8s-tpm-kms-plugin.service
[Unit]
Description=Kubernetes TPM KMS Plugin

[Service]
ExecStart=/opt/k8s-tpm-kms-plugin --kms=v2 --healthz-addr=127.0.0.1 --healthz-port=51201 --metrics-addr=127.0.0.1 --metrics-port=51202 --additional-secret YOUR_ADDITIONAL_SECRET
Restart=on-failure
Type=simple

[Install]
WantedBy=multi-user.target
EOF

$ sudo systemctl daemon-reload && sudo systemctl start k8s-tpm-kms-plugin.service

$ cat <<EOF | sudo tee /etc/kubernetes/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - testsecrets
    providers:
      - kms:
          apiVersion: v2
          name: k8sTpmKmsPlugin
          endpoint: unix:///var/run/kmsplugin/k8s-tpm-kms-plugin.sock
          timeout: 3s
      - identity: {}
EOF

(Modify your kubelet config: --encryption-provider-config=/etc/kubernetes/encryption-config.yaml)
```

# License

[Apache License 2.0](./LICENSE)

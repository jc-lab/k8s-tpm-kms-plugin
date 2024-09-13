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

# License

[Apache License 2.0](./LICENSE)

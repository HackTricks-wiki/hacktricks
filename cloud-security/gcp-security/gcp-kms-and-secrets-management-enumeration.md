# GCP - KMS & Secrets Management Enumeration

## Crypto Keys

[Cloud Key Management Service](https://cloud.google.com/kms/docs/) is a repository for storing cryptographic keys, such as those used to **encrypt and decrypt sensitive files**. Individual keys are stored in key rings, and granular permissions can be applied at either level.

Having **permissions to list the keys** this is how you can access them:

```bash
# List the global keyrings available
gcloud kms keyrings list --location global

# List the keys inside a keyring
gcloud kms keys list --keyring [KEYRING NAME] --location global

# Decrypt a file using one of your keys
gcloud kms decrypt --ciphertext-file=[INFILE] \
    --plaintext-file=[OUTFILE] \
    --key [KEY] \
    --keyring [KEYRING] \
    --location global
```

## Secrets Management

Google [Secrets Management](https://cloud.google.com/solutions/secrets-management/) is a vault-like solution for storing passwords, API keys, certificates, and other sensitive data. As of this writing, it is currently in beta.

```bash
# First, list the entries
gcloud beta secrets list

# Then, pull the clear-text of any secret
gcloud beta secrets versions access 1 --secret="[SECRET NAME]"
```

Note that changing a secret entry will create a new version, so it's worth changing the `1` in the command above to a `2` and so on.

## References

* [https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/#reviewing-stackdriver-logging](https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/#reviewing-stackdriver-logging)

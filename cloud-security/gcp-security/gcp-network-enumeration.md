# GCP - Network Enumeration

## Network Enumeration

### Compute

```bash
# List networks
gcloud compute networks list
gcloud compute networks describe <network>

# List subnetworks
gcloud compute networks subnets list
gcloud compute networks subnets get-iam-policy <name> --region <region>
gcloud compute networks subnets describe <name> --region <region>

# List FW rules in networks
gcloud compute firewall-rules list
```

You easily find compute instances with open firewall rules with [https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp\_firewall\_enum](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp\_firewall\_enum)

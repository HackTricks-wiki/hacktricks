# Unauthenticated Memory Disclosure

{{#include ../banners/hacktricks-training.md}}

## Overview

Unauthenticated memory disclosure vulnerabilities allow attackers to retrieve arbitrary portions of a target's memory without providing any credentials. Leaked data can include session tokens, credentials, and other sensitive information, leading to session hijacking and further compromise.

## CitrixBleed 2: CVE-2025-5777

- **Vulnerability**: Critical unauthenticated memory disclosure in Citrix NetScaler Gateway and AAA virtual servers.
- **CVE**: CVE-2025-5777
- **Affected**: Any externally exposed Gateway or AAA virtual server endpoint. Unlike CVE-2023-4966, this issue is not limited to the management interface.

### Exploitation

1. Identify an exposed Citrix NetScaler Gateway/AAA endpoint.
2. Send a crafted HTTP request to the appliance. The response will include a raw dump of server memory.

   Example (generic):
   ```bash
   curl -k https://<target>/
   ```

3. Inspect the memory dump for sensitive data such as session tokens (ICA/PCoIP), credentials, and configuration details.

### Discovery (Shodan)

- Favicon hash query:
  ```
  http.favicon.hash:-1292923998,-1166125415
  ```
- Organization and product query:
  ```
  org:YourOrg ssl:YourOrg html:Citrix
  ```

### Impact

- Leak of session tokens enables replay attacks to hijack Citrix sessions, bypassing MFA.
- Exposure of credentials or other in-memory secrets.

### Mitigation

- **Patch** all Citrix NetScaler appliances according to advisory CTX693420:
  https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420

- **Post-patch session cleanup** (terminate all active ICA and PCoIP sessions):
  ```bash
  kill icaconnection -all
  kill pcoipConnection -all
  ```

## References

- Blog: CitrixBleed 2: Electric Boogaloo — CVE-2025-5777
  https://doublepulsar.com/citrixbleed-2-electric-boogaloo-cve-2025-5777-c7f5e349d206
- Citrix Advisory CTX693420: https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420
- NVD CVE-2025-5777: https://nvd.nist.gov/vuln/detail/CVE-2025-5777

{{#include ../banners/hacktricks-training.md}}

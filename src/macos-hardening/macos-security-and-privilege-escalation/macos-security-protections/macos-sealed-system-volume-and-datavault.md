# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basic Information

Kuanzia na **macOS Big Sur (11.0)**, system volume imefungwa kwa njia ya kriptografia kwa kutumia **APFS snapshot hash tree**. Hii inaitwa **Sealed System Volume (SSV)**. System partition imewekwa **read-only** na mabadiliko yoyote yanavunja muhuri, ambao unathibitishwa wakati wa boot.

The SSV provides:
- **Tamper detection** — mabadiliko yoyote kwenye system binaries/frameworks yanaweza kugunduliwa kupitia kuvunjwa kwa muhuri wa kriptografia
- **Rollback protection** — mchakato wa boot unathibitisha uadilifu wa snapshot ya mfumo
- **Rootkit prevention** — hata root hawezi kubadilisha kwa kudumu faili kwenye system volume (bila kuvunja muhuri)

### Checking SSV Status
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
### Idhini za Mwandishi wa SSV

Binaries fulani za mfumo wa Apple zina idhini zinazowawezesha kurekebisha au kusimamia volumu iliyofungwa ya mfumo (Sealed System Volume):

| Entitlement | Madhumuni |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Rudisha volumu ya mfumo kwa snapshot ya awali |
| `com.apple.private.apfs.create-sealed-snapshot` | Unda snapshot mpya iliyofungwa baada ya masasisho ya mfumo |
| `com.apple.rootless.install.heritable` | Andika kwenye njia zilizo na ulinzi za SIP (zinazorithiwa na michakato ya mtoto) |
| `com.apple.rootless.install` | Andika kwenye njia zilizo na ulinzi za SIP |

### Kutafuta Waandishi wa SSV
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
### Senario za Shambulio

#### Snapshot Rollback Attack

Ikiwa mshambuliaji anapata udhibiti wa binary yenye `com.apple.private.apfs.revert-to-snapshot`, anaweza **kurudisha volume ya mfumo katika hali ya kabla ya sasisho**, akirejesha udhaifu uliotambuliwa:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Kurudisha snapshot kwa ufanisi **hurejesha sasisho za usalama**, ikirejesha udhaifu wa kernel na mfumo uliotengenezwa hapo awali. Hii ni moja ya shughuli hatari zaidi zinazowezekana kwenye macOS za kisasa.

#### Ubadilishaji wa Binary ya Mfumo

Kwa SIP bypass + uwezo wa kuandika SSV, mshambuliaji anaweza:

1. Ku-mount volume ya mfumo kwa kusomeka-na-kuandika
2. Kubadilisha daemon ya mfumo au maktaba ya framework na toleo lenye trojan
3. Kure-seal snapshot (au kukubali seal iliyovunjika ikiwa SIP tayari imeharibika)
4. Rootkit hubaki kuhifadhiwa baada ya kuanzisha upya na haonekani kwa zana za utambuzi za userland

### CVE za Dunia Halisi

| CVE | Maelezo |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass inayoruhusu urekebishaji wa SSV kupitia `system_installd` |
| CVE-2022-22583 | SSV bypass kupitia usimamizi wa snapshot wa PackageKit |
| CVE-2022-46689 | Race condition inayoruhusu uandishi kwa faili zilizolindwa na SIP |

---

## DataVault

### Taarifa za Msingi

**DataVault** ni safu ya ulinzi ya Apple kwa hifadhidata za mfumo zinazohitaji ulinzi. Hata **root hawezi kufikia faili zilizolindwa na DataVault** — ni mchakato tu wenye entitlements maalum wanaoweza kusoma au kuhariri. Hifadhidata zilizolindwa ni pamoja na:

| Hifadhidata Iliolindwa | Njia | Yaliyomo |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Maamuzi ya faragha ya TCC kwa kiwango cha mfumo |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Maamuzi ya faragha ya TCC kwa kila mtumiaji |
| Keychain (system) | `/Library/Keychains/System.keychain` | Keychain ya mfumo |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Keychain ya mtumiaji |

Ulinzi wa DataVault unatekelezwa katika **ngazi ya filesystem** kwa kutumia extended attributes na volume protection flags, ukathibitishwa na kernel.

### Entitlements za DataVault Controller
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Kugundua DataVault Controllers
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
### Mifano ya Mashambulizi

#### Marekebisho ya Moja kwa Moja ya TCC Database

Ikiwa mshambuliaji atapata udhibiti wa DataVault controller binary (kwa mfano, kwa njia ya code injection katika process yenye `com.apple.private.tcc.manager`), anaweza **kubadilisha moja kwa moja TCC database** ili kumpa application yoyote ruhusa yoyote ya TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Marekebisho ya database ya TCC ni **bypass ya faragha ya mwisho** — yanatoa ruhusa yoyote kimya, bila ombi la mtumiaji au dalili inayoonekana. Kihistoria, minyororo mingi ya privilege escalation kwenye macOS imeisha kwa maandishi kwenye database ya TCC kama payload ya mwisho.

#### Ufikiaji wa Hifadhidata za Keychain

DataVault pia inalinda faili za kuhifadhi za keychain. Kontrola ya DataVault iliyodhulikazwa inaweza:

1. Kusoma faili ghafi za database za keychain
2. Kutoa vitu vya keychain vilivyosenywa
3. Ku jaribu decryption offline kwa kutumia nenosiri la mtumiaji au funguo zilizopatikana

### CVE za Maisha Halisi Zinazohusiana na DataVault/TCC Bypass

| CVE | Description |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink to DataVault-protected file |
| CVE-2023-32364 | Sandbox bypass leading to TCC database modification |
| CVE-2021-30713 | TCC bypass via XCSSET malware modifying TCC.db |
| CVE-2020-9934 | TCC bypass via environment variable manipulation |
| CVE-2020-29621 | Music app TCC bypass reaching DataVault |

## References

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}

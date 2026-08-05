# Sealed System Volume & DataVault ya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Maelezo ya Msingi

Kuanzia **macOS Big Sur (11.0)**, system volume hufungwa kwa cryptography kwa kutumia **APFS snapshot hash tree**. Hii huitwa **Sealed System Volume (SSV)**. System partition huwekwa kama **read-only**, na marekebisho yoyote huvunja seal, ambayo huthibitishwa wakati wa boot.

SSV hutoa:
- **Utambuzi wa Tamper** — marekebisho yoyote kwenye system binaries/frameworks yanaweza kutambuliwa kupitia seal ya cryptography iliyovunjika
- **Ulinzi dhidi ya Rollback** — mchakato wa boot huthibitisha uadilifu wa system snapshot
- **Kuzuia Rootkit** — hata root haiwezi kufanya marekebisho ya kudumu kwenye files za system volume (bila kuvunja seal)

### Kukagua Hali ya SSV
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
### Entitlements za SSV Writer

Apple system binaries fulani zina entitlements zinazoruhusu kubadilisha au kudhibiti sealed system volume:

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Kurudisha system volume kwenye snapshot ya awali |
| `com.apple.private.apfs.create-sealed-snapshot` | Kuunda sealed snapshot mpya baada ya system updates |
| `com.apple.rootless.install.heritable` | Kuandika kwenye SIP-protected paths (hurithiwa na child processes) |
| `com.apple.rootless.install` | Kuandika kwenye SIP-protected paths |

### Kupata SSV Writers
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
### Matukio ya Mashambulizi

#### Snapshot Rollback Attack

Ikiwa mshambuliaji ata-compromise binary yenye `com.apple.private.apfs.revert-to-snapshot`, anaweza **kurudisha system volume kwenye hali ya kabla ya update**, na hivyo kurejesha vulnerabilities zinazojulikana:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback kwa ufanisi **hubatilisha security updates**, na kurejesha kernel na system vulnerabilities zilizokuwa zimeshapatiwa marekebisho. Hii ni mojawapo ya operations hatari zaidi zinazowezekana kwenye macOS za kisasa.

#### System Binary Replacement

Kwa SIP bypass + SSV write capability, attacker anaweza:

1. Ku-mount system volume ikiwa read-write
2. Kubadilisha system daemon au framework library kwa toleo lenye trojan
3. Ku-seal tena snapshot (au kukubali seal iliyoharibika ikiwa SIP tayari imedhoofishwa)
4. Rootkit itaendelea kuwepo baada ya reboots na haitaonekana na userland detection tools

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass inayotumia vibaya entitlement ya `system_installd` ya `com.apple.rootless.install.heritable` kuendesha arbitrary post-install scripts ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd` iliweka post-install script katika SIP-protected folder chini ya `/tmp`, lakini `/tmp` yenyewe hailindwi na SIP, hivyo folder hiyo ingeweza kubadilishwa kwa ku-mount image juu yake ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — copy-on-write race katika XNU inayoruhusu writes kwenye read-only root-owned files ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Basic Information

**DataVault** ni protection layer ya Apple kwa system databases nyeti. Hata **root hawezi kufikia files zinazolindwa na DataVault** — ni processes zilizo na entitlements maalum pekee zinazoweza kuzisoma au kuzirekebisha.<sup>[1]</sup> Protected stores ni pamoja na:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Maamuzi ya faragha ya TCC ya system nzima |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Maamuzi ya faragha ya TCC kwa kila user |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

Ulinzi wa DataVault unatekelezwa katika **filesystem level** kwa kutumia extended attributes na volume protection flags, ambazo huthibitishwa na kernel.

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Kutafuta DataVault Controllers
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
### Matukio ya Attack

#### Direct TCC Database Modification

Iwapo mshambuliaji ataathiri controller binary ya DataVault (kwa mfano, kupitia code injection kwenye process yenye `com.apple.private.tcc.manager`), anaweza **kubadilisha moja kwa moja TCC database** ili kuipa application yoyote TCC permission yoyote:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Urekebishaji wa database ya TCC ni **privacy bypass ya mwisho** — hutoa ruhusa yoyote kimya kimya, bila prompt yoyote ya mtumiaji au kiashirio kinachoonekana. Kihistoria, minyororo mingi ya macOS privilege escalation imeishia kwa kuandika kwenye database ya TCC kama payload ya mwisho.

#### Keychain Database Access

DataVault pia hulinda faili za msingi za keychain. Controller ya DataVault iliyoathiriwa inaweza:

1. Kusoma faili ghafi za database ya keychain
2. Kutoa vipengee vilivyosimbwa vya keychain
3. Kujaribu decryption ya offline kwa kutumia password ya mtumiaji au keys zilizorejeshwa

### Real-World CVEs Involving DataVault/TCC Bypass

| CVE | Description |
|---|---|
| CVE-2024-44131 | FileProvider symlink race inayomwezesha helper mwenye privileged kufikia data iliyolindwa na TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Kama root, **kuunda user mpya ambaye `NFSHomeDirectory` inaelekeza kwenye `TCC.db` inayodhibitiwa na attacker**; wakati wa login `tccd` huitumia, na grants hutumika, hivyo kufikia data ya users wengine ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": kubadilisha home dir ya mtumiaji ili kupandikiza TCC.db inayodhibitiwa na attacker ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Hitilafu ya bundle-conclusion inayowezesha app **kurithi TCC grants za donor bundle** bila prompt; ilitumiwa porini na **XCSSET** kupiga screenshot ya desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` iliunda DB path kutoka kwa `$HOME`, hivyo `launchctl setenv HOME` iliielekeza kwenye `TCC.db` inayodhibitiwa na attacker ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` ilikuwa na `com.apple.private.tcc.manager` **na** ilikuwa imezima library validation, hivyo HAL plug-in iliyowekwa katika `/Library/Audio/Plug-Ins/HAL` ingeweza kutoa TCC rights kiholela ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## References

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}

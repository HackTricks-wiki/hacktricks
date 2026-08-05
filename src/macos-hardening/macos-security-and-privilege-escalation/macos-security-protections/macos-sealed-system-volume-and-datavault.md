# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Taarifa za Msingi

Kuanzia **macOS Big Sur (11.0)**, volume ya mfumo hufungwa kwa njia ya cryptographic kwa kutumia **APFS snapshot hash tree**. Hii huitwa **Sealed System Volume (SSV)**. Partition ya mfumo huwekwa **read-only**, na marekebisho yoyote huvunja seal, jambo linalothibitishwa wakati wa boot.

SSV hutoa:
- **Utambuzi wa tampering** — marekebisho yoyote kwenye system binaries/frameworks yanaweza kutambuliwa kupitia cryptographic seal iliyovunjika
- **Ulinzi dhidi ya rollback** — mchakato wa boot huthibitisha integrity ya system snapshot
- **Kuzuia rootkit** — hata root haiwezi kufanya marekebisho ya kudumu kwenye files zilizo kwenye system volume (bila kuvunja seal)

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
### Waandishi wa SSV wenye Entitlements

Binaries fulani za mfumo wa Apple zina entitlements zinazoziruhusu kurekebisha au kudhibiti sealed system volume:

| Entitlement | Madhumuni |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Kurudisha system volume kwenye snapshot ya awali |
| `com.apple.private.apfs.create-sealed-snapshot` | Kuunda snapshot mpya iliyotiwa muhuri baada ya system updates |
| `com.apple.rootless.install.heritable` | Kuandika kwenye paths zinazolindwa na SIP (hurithishwa na child processes) |
| `com.apple.rootless.install` | Kuandika kwenye paths zinazolindwa na SIP |

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
### Matukio ya Mashambulizi

#### Snapshot Rollback Attack

Ikiwa mshambuliaji ataathiri binary yenye `com.apple.private.apfs.revert-to-snapshot`, anaweza **kurudisha system volume kwenye hali ya kabla ya update**, na kurejesha vulnerabilities zinazojulikana:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Urejeshaji wa snapshot (**Snapshot rollback**) kwa ufanisi **hubatilisha security updates**, na kurejesha udhaifu wa kernel na mfumo uliokuwa umesharekebishwa. Hii ni mojawapo ya operesheni hatari zaidi zinazowezekana kwenye macOS ya kisasa.

#### Ubadilishaji wa System Binary

Kwa SIP bypass + uwezo wa kuandika kwenye SSV, mshambuliaji anaweza:

1. Ku-mount system volume kwa read-write
2. Kubadilisha system daemon au framework library kwa toleo lenye trojan
3. Kuweka muhuri upya snapshot (**re-seal**) (au kukubali seal iliyoharibika ikiwa SIP tayari imedhoofishwa)
4. Rootkit hubaki baada ya kuwasha upya na haionekani kwa userland detection tools

### CVEs za Ulimwengu Halisi

| CVE | Maelezo |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass inayotumia entitlement ya `system_installd` ya `com.apple.rootless.install.heritable` kuendesha post-install scripts kiholela ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd` iliweka post-install script katika SIP-protected folder ndani ya `/tmp`, lakini `/tmp` yenyewe haijalindwa na SIP, hivyo folder ingeweza kubadilishwa kwa ku-mount image juu yake ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — copy-on-write race katika XNU inayowezesha kuandika kwenye read-only files zinazomilikiwa na root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Taarifa za Msingi

**DataVault** ni protection layer ya Apple kwa system databases nyeti. Hata **root hawezi kufikia files zinazolindwa na DataVault** — ni processes zenye entitlements maalum pekee zinazoweza kuzisoma au kuzirekebisha. Protected stores zinajumuisha:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Maamuzi ya faragha ya TCC kwa mfumo mzima |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Maamuzi ya faragha ya TCC kwa kila user |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

Ulinzi wa DataVault unatekelezwa katika **filesystem level** kwa kutumia extended attributes na volume protection flags, ambazo zinathibitishwa na kernel.

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Kupata DataVault Controllers
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
### Matukio ya Mashambulizi

#### Direct TCC Database Modification

Ikiwa attacker atavuruga binary ya DataVault controller (kwa mfano, kupitia code injection kwenye process yenye `com.apple.private.tcc.manager`), anaweza **kurekebisha moja kwa moja TCC database** ili kuipa application yoyote ruhusa yoyote ya TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Marekebisho ya database ya TCC ni **njia kuu kabisa ya kukwepa ulinzi wa faragha** — hutoa ruhusa yoyote kimya kimya, bila prompt yoyote ya mtumiaji au kiashiria kinachoonekana. Kihistoria, minyororo kadhaa ya macOS privilege escalation imeishia kwenye uandishi wa database ya TCC kama payload ya mwisho.

#### Keychain Database Access

DataVault pia hulinda mafaili ya msingi ya keychain. Controller ya DataVault iliyoathiriwa inaweza:

1. Kusoma mafaili ghafi ya database ya keychain
2. Kutoa vipengee vya keychain vilivyosimbwa
3. Kujaribu kuvifungua offline kwa kutumia password ya mtumiaji au keys zilizorejeshwa

### Real-World CVEs Involving DataVault/TCC Bypass

| CVE | Description |
|---|---|
| CVE-2024-44131 | FileProvider symlink race inayomwezesha privileged helper kufikia data inayolindwa na TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Kama root, **kuunda mtumiaji mpya ambaye `NFSHomeDirectory` yake inaelekeza kwenye `TCC.db` inayodhibitiwa na attacker**; wakati wa login `tccd` huitumia na grants hutumika, hivyo kufikia data ya watumiaji wengine ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": kubadilisha home dir ya mtumiaji ili kupandikiza TCC.db inayodhibitiwa na attacker ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Hitilafu ya bundle-conclusion inayowezesha app **kurithi TCC grants za donor bundle** bila prompt; ilitumiwa porini na **XCSSET** kupiga screenshot ya desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` iliunda DB path kutoka kwa `$HOME`, hivyo `launchctl setenv HOME` iliielekeza kwenye `TCC.db` inayodhibitiwa na attacker ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` ilikuwa na `com.apple.private.tcc.manager` **na** ilikuwa imezima library validation, hivyo HAL plug-in iliyowekwa kwenye `/Library/Audio/Plug-Ins/HAL` ingeweza kutoa TCC rights kiholela ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Marejeo

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}

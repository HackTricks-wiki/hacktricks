# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Taarifa za Msingi

Kuanzia **macOS Big Sur (11.0)**, system volume hutiwa muhuri wa cryptographic kwa kutumia **APFS snapshot hash tree**. Hii huitwa **Sealed System Volume (SSV)**. System partition huwekwa **read-only**, na marekebisho yoyote huvunja muhuri, ambao huthibitishwa wakati wa boot.<sup>[[11]](#references)</sup>

SSV hutoa:
- **Ugunduzi wa Tampering** — marekebisho yoyote kwenye system binaries/frameworks yanaweza kugunduliwa kupitia muhuri wa cryptographic uliovunjika
- **Ulinzi dhidi ya Rollback** — mchakato wa boot huthibitisha integrity ya system snapshot
- **Kuzuia Rootkit** — hata root hawezi kurekebisha files kwenye system volume kwa kudumu (bila kuvunja muhuri)

### Kuangalia Hali ya SSV
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

Baadhi ya Apple system binaries zina entitlements zinazoziruhusu kurekebisha au kudhibiti sealed system volume:

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Kurejesha system volume kwenye snapshot ya awali |
| `com.apple.private.apfs.create-sealed-snapshot` | Kuunda sealed snapshot mpya baada ya system updates |
| `com.apple.rootless.install.heritable` | Kuandika kwenye SIP-protected paths (hurithiwa na child processes) |
| `com.apple.rootless.install` | Kuandika kwenye SIP-protected paths |

### Finding SSV Writers
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

Ikiwa mshambuliaji ataathiri binary yenye `com.apple.private.apfs.revert-to-snapshot`, anaweza **kurudisha system volume kwenye hali ya kabla ya update**, na hivyo kurejesha vulnerabilities zinazojulikana:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback kwa ufanisi **hubatilisha security updates**, na kurejesha kernel na system vulnerabilities zilizokuwa zimerekebishwa hapo awali. Hii ni mojawapo ya operations hatari zaidi zinazowezekana kwenye macOS za kisasa.

#### Ubadilishaji wa System Binary

Kwa SIP bypass + SSV write capability, attacker anaweza:

1. Kuweka system volume katika hali ya read-write
2. Kubadilisha system daemon au framework library kwa toleo lenye trojan
3. Kuweka muhuri upya snapshot (au kukubali seal iliyoharibika ikiwa SIP tayari imedhoofishwa)
4. Rootkit kuendelea kuwepo baada ya reboots na kutokuonekana kwa userland detection tools

### CVEs za Ulimwengu Halisi

| CVE | Maelezo |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass inayotumia entitlement ya `system_installd` ya `com.apple.rootless.install.heritable` kuendesha arbitrary post-install scripts ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` iliweka post-install script kwenye SIP-protected folder chini ya `/tmp`, lakini `/tmp` yenyewe haijalindwa na SIP, hivyo folder ingeweza kubadilishwa kwa ku-mount image juu yake ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — copy-on-write race katika XNU inayoruhusu writes kwenye read-only root-owned files ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Taarifa za Msingi

**DataVault** ni protection layer ya Apple kwa system databases nyeti. Hata **root hawezi kufikia DataVault-protected files** — ni processes zilizo na entitlements maalum pekee zinazoweza kuzisoma au kuzirekebisha.<sup>[[4]](#references)</sup> Protected stores zinajumuisha:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Maamuzi ya faragha ya TCC ya mfumo mzima |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Maamuzi ya faragha ya TCC kwa kila user |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

Ulinzi wa DataVault unatekelezwa katika **filesystem level** kwa kutumia extended attributes na volume protection flags, na kuthibitishwa na kernel.

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
### Matukio ya Mashambulizi

#### Marekebisho ya Moja kwa Moja ya Database ya TCC

Ikiwa mshambulizi ataathiri binary ya DataVault controller (kwa mfano, kupitia code injection kwenye process yenye `com.apple.private.tcc.manager`), anaweza **kurekebisha moja kwa moja database ya TCC** ili kuipa application yoyote ruhusa yoyote ya TCC:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Marekebisho ya database ya TCC ni **njia kuu ya kukwepa ulinzi wa faragha** — hutoa ruhusa yoyote kimya kimya, bila prompt yoyote ya mtumiaji au kiashiria kinachoonekana. Kihistoria, minyororo kadhaa ya macOS privilege escalation imeishia kwa kuandika kwenye database ya TCC kama payload ya mwisho.

#### Ufikiaji wa Keychain Database

DataVault pia hulinda faili za msingi za keychain. DataVault controller iliyoathiriwa inaweza:

1. Kusoma faili ghafi za keychain database
2. Kutoa keychain items zilizotiwa encryption
3. Kujaribu offline decryption kwa kutumia password ya mtumiaji au keys zilizopatikana

### CVEs za Kivitendo Zinazohusisha DataVault/TCC Bypass

| CVE | Maelezo |
|---|---|
| CVE-2024-44131 | FileProvider symlink race inayomwezesha privileged helper kufikia data inayolindwa na TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Kama root, **unda mtumiaji mpya ambaye `NFSHomeDirectory` inaelekeza kwenye `TCC.db` inayodhibitiwa na mshambuliaji**; wakati wa login `tccd` huitumia na grants hutumika, hivyo kufikia data ya watumiaji wengine ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": kubadilisha home dir ya mtumiaji ili kuweka TCC.db inayodhibitiwa na mshambuliaji ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Hitilafu ya bundle-conclusion inayowezesha app **kurithi TCC grants za donor bundle** bila prompt; ilitumiwa porini na **XCSSET** kupiga screenshot ya desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` ilijenga njia ya DB kutoka `$HOME`, kwa hiyo `launchctl setenv HOME` iliielekeza kwenye `TCC.db` inayodhibitiwa na mshambuliaji ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` ilikuwa na `com.apple.private.tcc.manager` **na** library validation ilikuwa imezimwa, kwa hiyo HAL plug-in iliyowekwa kwenye `/Library/Audio/Plug-Ins/HAL` ingeweza kutoa haki za TCC kiholela ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

## Marejeleo

- [1] [Microsoft yagundua udhaifu mpya wa macOS, Shrootless, unaoweza kukwepa System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technical Analysis: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass huiba data kutoka iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Kugundua macOS Malware: Kukwepa TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Udhaifu mpya wa macOS, "powerdir," unaweza kusababisha ufikiaji wa data ya mtumiaji bila ruhusa](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass imegunduliwa katika XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Kukwepa macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Cheza muziki na ukwepe TCC, yaani CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}

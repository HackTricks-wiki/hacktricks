# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basic Information

**macOS Big Sur (11.0)** sürümünden itibaren system volume, bir **APFS snapshot hash tree** kullanılarak kriptografik olarak mühürlenir. Buna **Sealed System Volume (SSV)** adı verilir. System partition **salt okunur** olarak mount edilir ve herhangi bir değişiklik mührü bozar; bu durum boot sırasında doğrulanır.<sup>[[11]](#references)</sup>

SSV şunları sağlar:
- **Tamper detection** — system binary'lerinde/framework'lerinde yapılan herhangi bir değişiklik Merkle-tree root'unu değiştirir ve Apple tarafından imzalanmış mührü geçersiz kılar
- **Boot-time authentication** — boot chain, root filesystem haline gelmeden önce seçilen system snapshot'ını doğrular
- **Rootkit resistance** — root kullanıcısı bile authenticated root'u devre dışı bırakmadan veya yetkilendirilmiş bir update path'i ele geçirmeden, doğrulanmış system snapshot'ındaki dosyaları kalıcı olarak değiştiremez

SSV, yazılabilir **Data** volume ile eşleştirilmiş **System** volume'ünü değil, yalnızca **System** volume'ünü korur. Firmlink'ler her iki volume'ü `/` altında görünen namespace'e birleştirir; bu nedenle yazılabilir görünen bir path, temel nesnenin mühürlenmiş snapshot'a ait olduğunu kanıtlamaz. FileVault ve Data Protection, bekleyen verilerin gizliliğini kapsar; bunlar SSV integrity'sinden ayrıdır.<sup>[[11]](#references)</sup>

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
### Etkin sistem görünümü: SSV + Cryptex graft'leri

Güncel macOS sürümlerinde, `/System` altında görünen her executable, boot edilmiş SSV snapshot'ından gelmeyebilir. **Cryptexes**, içerikleri seçili dizinler üzerine graft edilen ve ayrı ayrı doğrulanan APFS disk image'larıdır; bu nedenle Rapid Security Responses, temel SSV'yi yeniden oluşturmadan security-sensitive bileşenleri değiştirebilir. Persistence incelemesi veya sistem kodunu diff ederken yalnızca temel snapshot'ı hash'lemek yerine live mount'ları ve Preboot Cryptex store'u envantere alın:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
Boot-chain ve Rapid Security Response ayrıntıları [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses) bölümünde ele alınmaktadır; bu bölüm SSV sınırının kendisine odaklanır.

### SSV Writer Entitlements

Bazı Apple system binary'leri, sealed system volume'u değiştirmelerine veya yönetmelerine olanak tanıyan entitlement'lara sahiptir:

| Entitlement | Amaç |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | System volume'u önceki bir snapshot'a geri döndürmek |
| `com.apple.private.apfs.create-sealed-snapshot` | System updates sonrasında yeni bir sealed snapshot oluşturmak |
| `com.apple.rootless.install.heritable` | SIP-korumalı path'lere yazmak (child process'ler tarafından devralınır) |
| `com.apple.rootless.install` | SIP-korumalı path'lere yazmak |

### SSV Writer'larını Bulma
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
### Snapshot Rollback Attack

Bir saldırgan `com.apple.private.apfs.revert-to-snapshot` ile bir binary'yi ele geçirirse, **system volume'u güncelleme öncesi bir duruma geri alabilir** ve bilinen güvenlik açıklarını yeniden etkinleştirebilir:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback, **security updates'i geri alarak** daha önce yamalanmış kernel ve sistem açıklarını geri yükler. Bu, modern macOS'ta gerçekleştirilebilecek en tehlikeli işlemlerden biridir.

#### System Binary Replacement

SIP bypass + SSV write capability ile bir attacker şunları yapabilir:

1. System volume'ü read-write olarak mount etmek
2. Bir system daemon'u veya framework library'yi trojanlı bir sürümle değiştirmek
3. Snapshot'ı yeniden seal etmek (veya SIP zaten zayıflatılmışsa bozuk seal'i kabul etmek)
4. Rootkit reboot'lar arasında kalıcılığını sürdürür ve userland detection tools tarafından görünmez

### Real-World CVEs

| CVE | Açıklama |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd`'ın arbitrary post-install scripts çalıştırmasını sağlayan `com.apple.rootless.install.heritable` entitlement'ını kötüye kullanan SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd`, post-install script'i `/tmp` altındaki SIP-protected bir folder'a stage etti; ancak `/tmp` SIP-protected değildir, bu nedenle folder üzerine bir image mount edilerek değiştirilebilirdi ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — XNU'da read-only root-owned files üzerine write yapılmasına olanak sağlayan copy-on-write race ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basic Information

**DataVault**, sensitive files ve directories için entitlement-gated bir filesystem protection'dır. BSD flag'i `UF_DATAVAULT` (`0x00000080`), bir object'in hem okunması hem de yazılması için entitlement gerektiğini belirtir; normal DAC'in aksine, yalnızca **root** olmak veya Full Disk Access almak, protection enforced durumdayken bu kontrolü karşılamaz.<sup>[[4]](#references)[[13]](#references)</sup>

Her protected database için “DataVault” ifadesini synonym olarak kullanmayın. TCC databases, TCC/FDA ve SIP-specific policy tarafından yönetilir (bkz. [macOS TCC](macos-tcc/README.md)); keychain item access ise ayrıca Keychain ACLs ve cryptographic protection'a bağlıdır (bkz. [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Gerçek DataVault örnekleri genellikle `/private/var/folders/.../0/` altındaki service-owned stores olarak görülür; örneğin Screen Time store. Parent üzerinde stat alınabildiğinde flag, BSD file flags içinde `datavault` olarak görünür.

### DataVault Controller Entitlements

| Entitlement | Sınır |
|---|---|
| `com.apple.rootless.datavault.controller` | `UF_DATAVAULT` objects'e erişme/yönetme<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | TCC decisions'ı yönetme; bu, ilişkili ancak ayrı bir privacy boundary'dir |
| `com.apple.private.tcc.allow` | Entitlement value içinde belirtilen seçili TCC services'larını bypass etme |
| `com.apple.rootless.storage.TCC` | SIP-protected TCC store'a write yapma |

DataVault-controller entitlement'ını FDA, backup, indexing veya IPC functionality ile birleştiren bir process özellikle ilgi çekicidir: vault'u doğrudan açmaya çalışmak yerine protected object'i ordinary path'e kopyalayan bir confused-deputy primitive arayın.<sup>[[14]](#references)</sup>

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
### Saldırı Senaryoları

#### Doğrudan TCC Veritabanı Değişikliği (ayrı TCC sınırı)

Bir saldırgan bir TCC manager process'ini (örneğin `com.apple.private.tcc.manager` taşıyan bir process'e code injection yoluyla) ele geçirirse, herhangi bir uygulamaya herhangi bir TCC izni vermek için **TCC veritabanını doğrudan değiştirebilir**:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database modification, **nihai gizlilik bypass'ıdır** — herhangi bir izni sessizce verir; herhangi bir kullanıcı istemi veya görünür gösterge oluşturmaz. Tarihsel olarak, birden fazla macOS privilege escalation zinciri, son payload olarak TCC database write işlemleriyle sonuçlanmıştır.

#### Keychain Veritabanına Erişim

Bir keychain backing database'ine raw erişim, plaintext secret erişimine eşdeğer değildir. Başka bir privilege boundary, saldırganın database'i kopyalamasına izin verse bile key material ve item ACL'leri hâlâ attack edilmelidir; bir DataVault-controller entitlement'ının yeterli olduğunu varsaymak yerine özel [macOS Keychain](../../macos-red-teaming/macos-keychain.md) sayfasına bakın.

#### Yedek kopya sınırı: Time Machine

2026 tarihli bir analysis, yararlı bir genel pattern ortaya koydu: `backupd`, korumalı store'ları kopyalayabilmek için hem `com.apple.rootless.datavault.controller` hem de Full Disk Access taşır. Test edilen configuration'da `/private/var/folders`, Time Machine'e dahil edilmişti ve mount edilen backup copy, live DataVault boundary'sini enforce etmiyordu. Researcher bunu Screen Time SQLite store'unu bulmak ve live vault'u açmadan plaintext restrictions PIN'ini okumak için kullandı. Bunu bir **copy-boundary attack** olarak değerlendirin: vault data'yı daha zayıf bir mount veya path altında materialize edebilen backup, export, migration, indexing ve diagnostic deputy'lerini enumerate edin.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
Bu davranış sürüme ve yedekleme düzenine bağlıdır. Hedef build üzerinde doğrulayın ve şifrelenmiş bir Time Machine hedefinin kopyayı yalnızca kilitliyken koruduğunu unutmayın; hedef bağlandığında erişim denetimleri attack surface'ın bir parçası hâline gelir.

### DataVault/TCC Bypass İçeren Gerçek Dünya CVE'leri

| CVE | Açıklama |
|---|---|
| CVE-2024-44131 | Ayrıcalıklı bir helper'ın TCC tarafından korunan verilere ulaşmasını sağlayan FileProvider symlink race ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Root olarak, **`NFSHomeDirectory` değeri saldırganın kontrolündeki bir `TCC.db` dosyasını gösteren yeni bir kullanıcı oluşturma**; giriş sırasında `tccd` bu dosyayı kullanır ve grant'ler uygulanarak diğer kullanıcıların verilerine erişilir ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": saldırganın kontrolündeki bir TCC.db dosyasını yerleştirmek için kullanıcının home dir'ini değiştirme ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bir uygulamanın herhangi bir prompt olmadan **donör bundle'ın TCC grant'lerini devralmasını** sağlayan bundle-conclusion açığı; masaüstünün screenshot'ını almak için gerçek dünyada **XCSSET** tarafından exploit edildi ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd`, DB path'ini `$HOME` üzerinden oluşturuyordu; bu nedenle `launchctl setenv HOME`, path'i saldırganın kontrolündeki bir `TCC.db` dosyasına yönlendirdi ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod`, `com.apple.private.tcc.manager` yetkisine sahipti **ve** library validation'ı devre dışı bırakıyordu; bu nedenle `/Library/Audio/Plug-Ins/HAL` içine bırakılan bir HAL plug-in'i keyfi TCC hakları verebiliyordu ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft, System Integrity Protection'ı bypass edebilen yeni macOS açığı Shrootless'ı buldu](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Teknik Analiz: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Kötü Yapmaya Değer](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass iCloud'dan veri çalıyor](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - macOS Malware'ını Ortaya Çıkarmak: TCC Bypass](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Yeni macOS açığı "powerdir", yetkisiz kullanıcı verisi erişimine yol açabilir](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [XCSSET malware'ında Zero-Day TCC bypass keşfedildi](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework'ünü Bypass Etme](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Müziği çal ve TCC bypass yap; diğer adıyla CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Apple OTA Updates'ın Kabusu (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Kendi Screen Time parolanızı nasıl bypass edersiniz — kaynak kodu ve Time Machine/DataVault analizi](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}

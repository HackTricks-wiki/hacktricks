# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Temel Bilgiler

**macOS Big Sur (11.0)** ile birlikte sistem volume'ü, **APFS snapshot hash tree** kullanılarak kriptografik olarak mühürlenir. Buna **Sealed System Volume (SSV)** adı verilir. Sistem partition'ı **salt okunur** olarak mount edilir ve herhangi bir değişiklik mührü bozar; bu durum boot sırasında doğrulanır.

SSV şunları sağlar:
- **Kurcalama tespiti** — sistem binary'leri/framework'leri üzerinde yapılan tüm değişiklikler, bozulan kriptografik mühür aracılığıyla tespit edilebilir
- **Rollback koruması** — boot süreci sistem snapshot'ının bütünlüğünü doğrular
- **Rootkit önleme** — root bile sistem volume'ündeki dosyaları kalıcı olarak değiştiremez (mühür bozulmadan)

### SSV Durumunu Kontrol Etmek
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

Bazı Apple system binary'leri, sealed system volume'u değiştirmelerine veya yönetmelerine olanak tanıyan entitlement'lara sahiptir:

| Entitlement | Amaç |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | System volume'u önceki bir snapshot'a geri döndürmek |
| `com.apple.private.apfs.create-sealed-snapshot` | System update'lerinden sonra yeni bir sealed snapshot oluşturmak |
| `com.apple.rootless.install.heritable` | SIP tarafından korunan path'lere yazmak (child process'ler tarafından devralınır) |
| `com.apple.rootless.install` | SIP tarafından korunan path'lere yazmak |

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
### Attack Scenarios

#### Snapshot Rollback Attack

Bir saldırgan `com.apple.private.apfs.revert-to-snapshot` yetkisine sahip bir binary'yi ele geçirirse, **system volume'u güncelleme öncesi bir duruma geri döndürebilir** ve bilinen güvenlik açıklarını yeniden etkinleştirebilir:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback işlemi **security updates'leri geri alarak**, daha önce yamalanmış kernel ve system vulnerability'lerini yeniden etkinleştirir. Bu, modern macOS'ta gerçekleştirilebilecek en tehlikeli işlemlerden biridir.

#### System Binary Replacement

SIP bypass + SSV write capability ile bir attacker:

1. System volume'ü read-write olarak mount eder
2. Bir system daemon'u veya framework library'yi trojan edilmiş bir sürümle değiştirir
3. Snapshot'ı yeniden seal eder (veya SIP zaten degraded durumdaysa bozuk seal'i kabul eder)
4. Rootkit reboot'lar arasında kalıcılığını korur ve userland detection tools tarafından görünmez

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — arbitrary post-install scripts çalıştırmak için `system_installd`'in `com.apple.rootless.install.heritable` entitlement'ını abuse eden SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd`, post-install script'i `/tmp` altındaki SIP-protected bir folder'a stage etti; ancak `/tmp`'nin kendisi SIP-protected değildir, bu nedenle folder üzerine bir image mount edilerek folder değiştirilebilirdi ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — XNU'da read-only root-owned files'lara write yapılmasına olanak sağlayan copy-on-write race ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Basic Information

**DataVault**, sensitive system databases için Apple'ın protection layer'ıdır. Belirli entitlement'lara sahip process'ler dışında **root bile DataVault-protected files'lara erişemez** — bu process'ler dosyaları okuyabilir veya değiştirebilir. Protected stores şunları içerir:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user TCC privacy decisions |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

DataVault protection, kernel tarafından doğrulanan extended attributes ve volume protection flags kullanılarak **filesystem level**'da uygulanır.

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### DataVault Controller'larını Bulma
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

Bir saldırgan, bir DataVault controller binary'sini (ör. `com.apple.private.tcc.manager` özelliğine sahip bir process'e code injection yoluyla) ele geçirirse, herhangi bir uygulamaya herhangi bir TCC izni vermek için **TCC veritabanını doğrudan değiştirebilir**:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database modification, herhangi bir izni sessizce verir — hiçbir kullanıcı istemi veya görünür gösterge olmadan — **nihai gizlilik bypass'ıdır**. Geçmişte birden fazla macOS privilege escalation zinciri, son payload olarak TCC database yazma işlemiyle sonuçlanmıştır.

#### Keychain Database Access

DataVault, keychain backing dosyalarını da korur. Ele geçirilmiş bir DataVault controller şunları yapabilir:

1. Ham keychain database dosyalarını okuma
2. Şifrelenmiş keychain öğelerini çıkarma
3. Kullanıcının password'ünü veya kurtarılmış key'leri kullanarak offline decryption denemesi

### DataVault/TCC Bypass İçeren Gerçek Dünya CVE'leri

| CVE | Açıklama |
|---|---|
| CVE-2024-44131 | Ayrıcalıklı bir helper'ın TCC tarafından korunan verilere ulaşmasını sağlayan FileProvider symlink race ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Root olarak, `NFSHomeDirectory` değeri attacker-controlled bir `TCC.db` dosyasını gösteren **yeni bir user oluşturma**; login sırasında `tccd` bu dosyayı kullanır ve grant'ler uygulanarak diğer user'ların verilerine ulaşılır ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | Attacker-controlled bir TCC.db yerleştirmek için user'ın home dir'ini değiştirme: "powerdir" ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Bir app'in herhangi bir prompt olmadan **donor bundle'ın TCC grant'lerini miras almasını** sağlayan bundle-conclusion flaw; masaüstünün screenshot'ını almak için gerçek dünyada **XCSSET** tarafından exploit edildi ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd`, DB path'ini `$HOME` üzerinden oluşturuyordu; bu nedenle `launchctl setenv HOME`, path'i attacker-controlled bir `TCC.db` dosyasına yönlendiriyordu ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod`, `com.apple.private.tcc.manager` yetkisine sahipti ve library validation'ı devre dışı bırakıyordu; bu nedenle `/Library/Audio/Plug-Ins/HAL` konumuna yerleştirilen bir HAL plug-in'i rastgele TCC hakları verebiliyordu ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Referanslar

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [Apple OTA Updates Kabusu (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}

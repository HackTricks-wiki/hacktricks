# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Temel Bilgiler

**macOS Big Sur (11.0)** sürümünden itibaren sistem volume'u, bir **APFS snapshot hash tree** kullanılarak kriptografik olarak mühürlenir. Buna **Sealed System Volume (SSV)** adı verilir. Sistem partition'ı **salt okunur** olarak mount edilir ve herhangi bir değişiklik mührü bozar; bu durum boot sırasında doğrulanır.

SSV şunları sağlar:
- **Kurcalama tespiti** — sistem binary'lerinde/framework'lerinde yapılan herhangi bir değişiklik, bozulan kriptografik mühür üzerinden tespit edilebilir
- **Rollback koruması** — boot süreci, sistem snapshot'ının bütünlüğünü doğrular
- **Rootkit önleme** — root kullanıcısı bile sistem volume'undaki dosyaları mührü bozmadan kalıcı olarak değiştiremez

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
### SSV Writer Entitlements

Bazı Apple system binary'leri, sealed system volume'u değiştirmelerine veya yönetmelerine olanak tanıyan entitlement'lara sahiptir:

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | System volume'u önceki bir snapshot'a geri döndürür |
| `com.apple.private.apfs.create-sealed-snapshot` | System update'lerinden sonra yeni bir sealed snapshot oluşturur |
| `com.apple.rootless.install.heritable` | SIP-protected path'lere yazma (child process'ler tarafından devralınır) |
| `com.apple.rootless.install` | SIP-protected path'lere yazma |

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

Bir saldırgan `com.apple.private.apfs.revert-to-snapshot` ile bir binary'yi ele geçirirse, **system volume'ü güncelleme öncesi bir duruma geri alabilir** ve bilinen zafiyetleri yeniden etkinleştirebilir:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback, daha önce yamalanmış kernel ve sistem güvenlik açıklarını geri getirerek **güvenlik güncellemelerini etkili biçimde geri alır**. Bu, modern macOS'ta gerçekleştirilebilecek en tehlikeli işlemlerden biridir.

#### System Binary Replacement

SIP bypass + SSV write capability ile bir saldırgan şunları yapabilir:

1. System volume'ü read-write olarak mount etmek
2. Bir system daemon'ını veya framework library'sini trojaned bir sürümle değiştirmek
3. Snapshot'ı yeniden seal etmek (veya SIP zaten zayıflatılmışsa bozuk seal'i kabul etmek)
4. Rootkit reboot'lar boyunca kalıcı olur ve userland detection tools tarafından görünmez

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd`'ın `com.apple.rootless.install.heritable` entitlement'ını kötüye kullanarak arbitrary post-install scripts çalıştıran SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd`, post-install script'i `/tmp` altında SIP-protected bir folder'a yerleştirdi; ancak `/tmp`'nin kendisi SIP-protected değildir, bu nedenle folder üzerine bir image mount edilerek değiştirilebilirdi ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — read-only root-owned files üzerine yazmaya olanak tanıyan XNU içindeki copy-on-write race ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Basic Information

**DataVault**, hassas system database'leri için Apple'ın protection layer'ıdır. **root bile DataVault-protected files'lara erişemez** — bunları yalnızca belirli entitlements'a sahip process'ler okuyabilir veya değiştirebilir.<sup>[1]</sup> Protected stores şunları içerir:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user TCC privacy decisions |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

DataVault protection, kernel tarafından doğrulanan extended attributes ve volume protection flags kullanılarak **filesystem seviyesinde** uygulanır.

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

Bir saldırgan, bir DataVault controller binary'sini (ör. `com.apple.private.tcc.manager` içeren bir sürece code injection yoluyla) ele geçirirse, herhangi bir uygulamaya herhangi bir TCC izni vermek için **TCC veritabanını doğrudan değiştirebilir**:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database modification, **nihai privacy bypass** yöntemidir — herhangi bir izni sessizce verir; hiçbir kullanıcı istemi veya görünür gösterge görüntülenmez. Geçmişte, birden fazla macOS privilege escalation zinciri, son payload olarak TCC database write işlemleriyle sonuçlanmıştır.

#### Keychain Database Access

DataVault, keychain backing file'larını da korur. Ele geçirilmiş bir DataVault controller şunları yapabilir:

1. Ham keychain database file'larını okuma
2. Şifrelenmiş keychain öğelerini çıkarma
3. Kullanıcının parolasını veya kurtarılmış anahtarları kullanarak offline decryption denemesi

### DataVault/TCC Bypass İçeren Gerçek Dünya CVE'leri

| CVE | Açıklama |
|---|---|
| CVE-2024-44131 | Privileged helper'ın TCC-protected verilere erişmesini sağlayan FileProvider symlink race ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Root olarak, `NFSHomeDirectory` değeri attacker-controlled bir `TCC.db` dosyasını gösteren **yeni bir kullanıcı oluşturma**; login sırasında `tccd` bu dosyayı kullanır ve grant'ler uygulanarak diğer kullanıcıların verilerine erişilir ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | Kullanıcının home directory'sini değiştirerek attacker-controlled bir TCC.db yerleştirme: "powerdir" ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Bir uygulamanın prompt olmadan **donor bundle'ın TCC grant'lerini devralmasına** olanak tanıyan bundle-conclusion flaw; masaüstünün screenshot'ını almak için **XCSSET** tarafından in the wild exploit edildi ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd`, DB path'ini `$HOME` üzerinden oluşturuyordu; bu nedenle `launchctl setenv HOME`, path'i attacker-controlled bir `TCC.db` dosyasına yönlendiriyordu ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod`, `com.apple.private.tcc.manager` yetkisine sahipti ve library validation'ı devre dışı bırakıyordu; bu nedenle `/Library/Audio/Plug-Ins/HAL` içine bırakılan bir HAL plug-in'i arbitrary TCC rights verebiliyordu ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## References

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}

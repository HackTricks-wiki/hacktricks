# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Mühürlü Sistem Birimi (SSV)

### Temel Bilgiler

**macOS Big Sur (11.0)** sürümünden itibaren sistem birimi, bir **APFS snapshot hash tree** kullanılarak kriptografik olarak mühürlenir. Buna **Sealed System Volume (SSV)** adı verilir. Sistem bölümü **salt okunur** olarak bağlanır ve herhangi bir değişiklik mührü bozar; bu durum önyükleme sırasında doğrulanır.<sup>[[11]](#references)</sup>

SSV şunları sağlar:
- **Kurcalama algılama** — sistem binary'leri/framework'leri üzerindeki herhangi bir değişiklik, bozulan kriptografik mühür üzerinden algılanabilir
- **Rollback koruması** — önyükleme işlemi, sistem snapshot'ının bütünlüğünü doğrular
- **Rootkit önleme** — root bile sistem birimindeki dosyaları mührü bozmadan kalıcı olarak değiştiremez

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
### SSV Writer Yetkilendirmeleri

Bazı Apple sistem binary'leri, sealed system volume'u değiştirmelerine veya yönetmelerine olanak tanıyan yetkilendirmelere sahiptir:

| Yetkilendirme | Amaç |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | System volume'u önceki bir snapshot'a geri döndürmek |
| `com.apple.private.apfs.create-sealed-snapshot` | Sistem güncellemelerinden sonra yeni bir sealed snapshot oluşturmak |
| `com.apple.rootless.install.heritable` | SIP tarafından korunan path'lere yazmak (child process'ler tarafından devralınır) |
| `com.apple.rootless.install` | SIP tarafından korunan path'lere yazmak |

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

#### Snapshot Geri Alma Saldırısı

Bir saldırgan `com.apple.private.apfs.revert-to-snapshot` yetkisine sahip bir binary'yi ele geçirirse, **system volume'u güncelleme öncesi bir duruma geri alarak** bilinen güvenlik açıklarını yeniden etkinleştirebilir:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback, güvenlik güncellemelerini etkili bir şekilde **geri alır** ve daha önce yamalanmış kernel ve sistem zafiyetlerini geri yükler. Bu, modern macOS'ta gerçekleştirilebilecek en tehlikeli işlemlerden biridir.

#### System Binary Replacement

SIP bypass + SSV write capability ile bir attacker şunları yapabilir:

1. System volume'ü read-write olarak mount etmek
2. Bir system daemon veya framework library'yi trojaned bir sürümle değiştirmek
3. Snapshot'u yeniden seal etmek (veya SIP zaten degraded durumdaysa bozuk seal'i kabul etmek)
4. Rootkit reboot'lar boyunca kalıcı olur ve userland detection tools tarafından görünmez

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — arbitrary post-install scripts çalıştırmak için `system_installd`'ın `com.apple.rootless.install.heritable` entitlement'ını abuse eden SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd`, post-install script'i `/tmp` altındaki SIP-protected bir folder'a stage etti; ancak `/tmp` kendisi SIP-protected değildir, bu nedenle folder üzerine bir image mount edilerek değiştirilebilirdi ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — XNU'da read-only root-owned file'lara write yapılmasına olanak tanıyan copy-on-write race ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basic Information

**DataVault**, hassas system database'leri için Apple'ın protection layer'ıdır. **root bile DataVault-protected file'lara erişemez** — bunları yalnızca belirli entitlement'lara sahip process'ler okuyabilir veya değiştirebilir.<sup>[[4]](#references)</sup> Protected store'lar şunları içerir:

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

Bir attacker, bir DataVault controller binary'sini (örneğin `com.apple.private.tcc.manager` özelliğine sahip bir process'e code injection yoluyla) ele geçirirse, herhangi bir application'a herhangi bir TCC permission vermek için **TCC database'i doğrudan değiştirebilir**:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database modification is the **ultimate privacy bypass** — herhangi bir izni sessizce verir; kullanıcıya hiçbir istem veya görünür gösterge sunmaz. Geçmişte, birçok macOS privilege escalation zinciri son payload olarak TCC database yazma işlemiyle tamamlanmıştır.

#### Keychain Database Access

DataVault, keychain backing file'larını da korur. Ele geçirilmiş bir DataVault controller şunları yapabilir:

1. Ham keychain database file'larını okuma
2. Şifrelenmiş keychain item'larını çıkarma
3. Kullanıcının password'ünü veya kurtarılmış key'leri kullanarak offline decryption deneme

### Real-World CVEs Involving DataVault/TCC Bypass

| CVE | Açıklama |
|---|---|
| CVE-2024-44131 | Privileged helper'ın TCC-protected data'ya erişmesini sağlayan FileProvider symlink race ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Root olarak, `NFSHomeDirectory` değeri attacker-controlled bir `TCC.db`'yi gösteren **yeni bir user oluşturma**; login sırasında `tccd` bunu tüketir ve grant'ler uygulanarak diğer user'ların data'sına erişilir ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | Kullanıcının home dir'ini değiştirerek attacker-controlled bir TCC.db yerleştirme: "powerdir" ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bir app'in, prompt olmadan **donor bundle'ın TCC grant'lerini devralmasını** sağlayan bundle-conclusion flaw; desktop'un screenshot'ını almak için **XCSSET** tarafından in the wild exploit edildi ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd`, DB path'ini `$HOME` üzerinden oluşturuyordu; bu nedenle `launchctl setenv HOME`, path'i attacker-controlled bir `TCC.db`'ye yönlendirdi ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod`, `com.apple.private.tcc.manager` yetkisini taşıyor ve library validation'ı devre dışı bırakıyordu; bu nedenle `/Library/Audio/Plug-Ins/HAL` içine bırakılan bir HAL plug-in'i arbitrary TCC rights verebiliyordu ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

## References

- [1] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technical Analysis: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Uncovering macOS Malware: Bypassing TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}

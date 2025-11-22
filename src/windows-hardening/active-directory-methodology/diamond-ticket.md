# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, un diamond ticket es un TGT que puede usarse para **acceder a cualquier servicio como cualquier usuario**. Un golden ticket se forja completamente offline, se cifra con el hash krbtgt de ese dominio y luego se inyecta en una sesión de logon para su uso. Como los domain controllers no rastrean los TGTs que han emitido legítimamente, aceptarán sin problema TGTs que estén cifrados con su propio hash krbtgt.

Hay dos técnicas comunes para detectar el uso de golden tickets:

- Buscar TGS-REQs que no tengan un AS-REQ correspondiente.
- Buscar TGTs con valores absurdos, como la validez por defecto de 10 años de Mimikatz.

Un **diamond ticket** se crea **modificando los campos de un TGT legítimo emitido por un DC**. Esto se consigue **solicitando** un **TGT**, **descifrándolo** con el hash krbtgt del dominio, **modificando** los campos deseados del ticket y luego **re-cifrándolo**. Esto **supera las dos limitaciones mencionadas** de un golden ticket porque:

- Las TGS-REQs tendrán un AS-REQ precedente.
- El TGT fue emitido por un DC, lo que significa que tendrá todos los detalles correctos según la política Kerberos del dominio. Aunque estos también pueden forjarse con precisión en un golden ticket, es más complejo y propenso a errores.

### Requirements & workflow

- **Cryptographic material**: la clave krbtgt AES256 (preferida) o el hash NTLM para descifrar y volver a firmar el TGT.
- **Legitimate TGT blob**: obtenido con `/tgtdeleg`, `asktgt`, `s4u`, o exportando tickets desde memoria.
- **Context data**: el RID del usuario objetivo, RIDs/SIDs de grupos y atributos PAC derivados de LDAP (opcionalmente).
- **Service keys** (only if you plan to re-cut service tickets): clave AES del SPN de servicio que será suplantado.

1. Obtén un TGT para cualquier usuario controlado vía AS-REQ (Rubeus `/tgtdeleg` es conveniente porque obliga al cliente a realizar el baile Kerberos GSS-API sin credenciales).
2. Descifra el TGT devuelto con la clave krbtgt, parchea atributos PAC (user, groups, logon info, SIDs, device claims, etc.).
3. Vuelve a cifrar/firma el ticket con la misma clave krbtgt e inyéctalo en la sesión de logon actual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repite el proceso sobre un service ticket proporcionando un blob TGT válido más la clave del servicio objetivo para mantener el sigilo en la red.

### Updated Rubeus tradecraft (2024+)

Trabajo reciente de Huntress modernizó la acción `diamond` dentro de Rubeus al portar las mejoras `/ldap` y `/opsec` que antes existían solo para golden/silver tickets. `/ldap` ahora rellena automáticamente atributos PAC precisos directamente desde AD (user profile, logon hours, sidHistory, domain policies), mientras que `/opsec` hace que el flujo AS-REQ/AS-REP sea indistinguible del de un cliente Windows al realizar la secuencia de pre-auth en dos pasos y forzar criptografía solo AES. Esto reduce drásticamente indicadores obvios como IDs de dispositivo vacíos o ventanas de validez poco realistas.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) consulta AD y SYSVOL para replicar los datos de la política PAC del usuario objetivo.
- `/opsec` fuerza un reintento AS-REQ al estilo Windows, poniendo a cero flags ruidosos y manteniéndose en AES256.
- `/tgtdeleg` evita tocar la contraseña en claro o la clave NTLM/AES de la víctima mientras devuelve un TGT descifrable.

### Service-ticket recutting

La misma actualización de Rubeus añadió la capacidad de aplicar la técnica diamond a blobs TGS. Alimentando a `diamond` con un **TGT codificado en base64** (desde `asktgt`, `/tgtdeleg`, o un TGT forjado previamente), el **service SPN**, y la **service AES key**, puedes generar service tickets realistas sin tocar el KDC — efectivamente un silver ticket más sigiloso.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Este flujo de trabajo es ideal cuando ya controlas la clave de una cuenta de servicio (p. ej., volcada con `lsadump::lsa /inject` o `secretsdump.py`) y quieres crear un TGS puntual que coincida perfectamente con la política de AD, los plazos y los datos del PAC sin emitir tráfico AS/TGS nuevo.

### Notas de OPSEC y detección

- Las heurísticas tradicionales de detección (TGS without AS, duraciones de décadas) siguen aplicando a golden tickets, pero diamond tickets salen a la superficie principalmente cuando el **contenido del PAC o el mapeo de grupos parece imposible**. Rellena todos los campos del PAC (horarios de inicio de sesión, rutas de perfil de usuario, IDs de dispositivo) para que las comparaciones automatizadas no señalen inmediatamente la falsificación.
- **No sobresuscribas grupos/RIDs**. Si solo necesitas `512` (Domain Admins) y `519` (Enterprise Admins), párate ahí y asegúrate de que la cuenta objetivo pertenezca de forma plausible a esos grupos en otra parte de AD. Un exceso de `ExtraSids` delata la manipulación.
- El proyecto Security Content de Splunk distribuye telemetría de attack-range para diamond tickets además de detecciones como *Windows Domain Admin Impersonation Indicator*, que correlaciona secuencias inusuales de Event ID 4768/4769/4624 y cambios en los grupos del PAC. Reproducir ese conjunto de datos (o generar el tuyo propio con los comandos anteriores) ayuda a validar la cobertura del SOC para T1558.001 y te proporciona lógica de alertas concreta para evadir.

## Referencias

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}

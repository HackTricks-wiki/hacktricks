# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Al igual que un golden ticket**, un diamond ticket es un TGT que puede usarse para **acceder a cualquier servicio como cualquier usuario**. Un golden ticket se forja completamente offline, se cifra con el hash krbtgt de ese dominio y luego se inyecta en una sesión de inicio de sesión para su uso. Debido a que los controladores de dominio no rastrean los TGTs que hayan emitido legítimamente, aceptarán sin problema TGTs cifrados con su propio hash krbtgt.

Hay dos técnicas comunes para detectar el uso de golden tickets:

- Buscar TGS-REQs que no tengan AS-REQ correspondiente.
- Buscar TGTs con valores absurdos, como la validez por defecto de 10 años de Mimikatz.

Un diamond ticket se crea modificando los campos de un TGT legítimo emitido por un DC. Esto se consigue solicitando un TGT, descifrándolo con el hash krbtgt del dominio, modificando los campos deseados del ticket y luego re-cifrándolo. Esto supera las dos limitaciones mencionadas anteriormente de un golden ticket porque:

- Los TGS-REQs tendrán un AS-REQ previo.
- El TGT fue emitido por un DC, lo que significa que tendrá todos los detalles correctos según la política Kerberos del dominio. Aunque estos pueden forjarse con precisión en un golden ticket, es más complejo y propenso a errores.

### Requisitos y flujo de trabajo

- **Material criptográfico**: la clave krbtgt AES256 (preferible) o el hash NTLM para descifrar y volver a firmar el TGT.
- **Blob de TGT legítimo**: obtenido con `/tgtdeleg`, `asktgt`, `s4u`, o exportando tickets desde memoria.
- **Datos de contexto**: el RID del usuario objetivo, los RIDs/SIDs de grupo y (opcionalmente) atributos PAC derivados de LDAP.
- **Claves de servicio** (solo si planeas re-cut service tickets): clave AES del SPN del servicio a suplantar.

1. Obtén un TGT para cualquier usuario controlado mediante AS-REQ (Rubeus `/tgtdeleg` es conveniente porque obliga al cliente a realizar el intercambio GSS-API de Kerberos sin credenciales).
2. Descifra el TGT devuelto con la clave krbtgt, parchea los atributos PAC (usuario, grupos, información de inicio de sesión, SIDs, device claims, etc.).
3. Vuelve a cifrar/firmar el ticket con la misma clave krbtgt e inyéctalo en la sesión de inicio actual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repite el proceso sobre un service ticket proporcionando un blob TGT válido más la clave del servicio objetivo para mantener sigilo en la red.

### Updated Rubeus tradecraft (2024+)

Trabajo reciente de Huntress modernizó la acción `diamond` dentro de Rubeus al portar las mejoras `/ldap` y `/opsec` que previamente existían solo para golden/silver tickets. `/ldap` ahora autocompleta atributos PAC precisos directamente desde AD (perfil de usuario, logon hours, sidHistory, políticas del dominio), mientras que `/opsec` hace que el flujo AS-REQ/AS-REP sea indistinguible de un cliente Windows al ejecutar la secuencia de pre-auth en dos pasos y forzar criptografía exclusivamente AES. Esto reduce drásticamente indicadores obvios como device IDs vacíos o ventanas de validez poco realistas.
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
- `/opsec` fuerza un reintento AS-REQ al estilo Windows, pone a cero flags ruidosas y se ciñe a AES256.
- `/tgtdeleg` evita tocar la contraseña en cleartext o la clave NTLM/AES de la víctima mientras sigue devolviendo un TGT descifrable.

### Recorte de service-ticket

La misma actualización de Rubeus añadió la capacidad de aplicar la diamond technique a TGS blobs. Al alimentar a `diamond` un **base64-encoded TGT** (desde `asktgt`, `/tgtdeleg`, o un TGT forjado previamente), el **service SPN**, y la **service AES key**, puedes crear service tickets realistas sin tocar el KDC—efectivamente un silver ticket más sigiloso.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Este flujo de trabajo es ideal cuando ya controlas la clave de una cuenta de servicio (por ejemplo, volcada con `lsadump::lsa /inject` o `secretsdump.py`) y quieres generar un TGS puntual que coincida perfectamente con la política de AD, los plazos y los datos del PAC sin emitir tráfico nuevo de AS/TGS.

### OPSEC y notas de detección

- Las heurísticas tradicionales de detección (TGS without AS, decade-long lifetimes) siguen aplicándose a los golden tickets, pero los diamond tickets suelen aparecer cuando el **contenido del PAC o el mapeo de grupos parece imposible**. Rellena todos los campos del PAC (logon hours, user profile paths, device IDs) para que las comparaciones automatizadas no marquen inmediatamente la falsificación.
- **No asignes demasiados grupos/RIDs**. Si solo necesitas `512` (Domain Admins) y `519` (Enterprise Admins), detente ahí y asegúrate de que la cuenta objetivo pertenezca de manera plausible a esos grupos en otra parte de AD. Un exceso de `ExtraSids` es una pista evidente.
- El proyecto Splunk's Security Content distribuye telemetría de attack-range para diamond tickets, así como detecciones como *Windows Domain Admin Impersonation Indicator*, que correlaciona secuencias inusuales de Event ID 4768/4769/4624 y cambios de grupo en el PAC. Reproducir ese conjunto de datos (o generar el propio con los comandos anteriores) ayuda a validar la cobertura del SOC para T1558.001, además de proporcionarte una lógica de alertas concreta para evadirla.

## Referencias

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}

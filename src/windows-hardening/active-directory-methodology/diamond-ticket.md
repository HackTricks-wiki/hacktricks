# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Al igual que un golden ticket**, un diamond ticket es un TGT que se puede usar para **acceder a cualquier servicio como cualquier usuario**. Un golden ticket se falsifica completamente offline, se cifra con el hash de krbtgt de ese dominio y luego se introduce en una sesión de inicio de sesión para usarlo. Como los controladores de dominio no registran qué TGT han emitido legítimamente, aceptarán sin problemas los TGT cifrados con su propio hash de krbtgt.<sup>[[1]](#references)</sup>

Hay dos técnicas habituales para detectar el uso de golden tickets:

- Buscar TGS-REQ que no tengan un AS-REQ correspondiente.
- Buscar TGT con valores absurdos, como la duración predeterminada de 10 años de Mimikatz.

Un **diamond ticket** se crea **modificando los campos de un TGT legítimo emitido por un DC**. Esto se consigue **solicitando** un **TGT**, **descifrándolo** con el hash de krbtgt del dominio, **modificando** los campos deseados del ticket y luego **volviéndolo a cifrar**. Esto **supera las dos deficiencias mencionadas anteriormente** de un golden ticket porque:<sup>[[1]](#references)</sup>

- Los TGS-REQ tendrán un AS-REQ previo.
- El TGT fue emitido por un DC, por lo que tendrá todos los detalles correctos según la política Kerberos del dominio. Aunque estos se pueden falsificar con precisión en un golden ticket, es más complejo y propenso a errores.

### Requisitos y flujo de trabajo

- **Material criptográfico**: la clave AES256 de krbtgt (preferida) o el hash NTLM para descifrar y volver a firmar el TGT.
- **Blob de TGT legítimo**: obtenido con `/tgtdeleg`, `asktgt`, `s4u` o exportando tickets de la memoria.
- **Datos de contexto**: el RID del usuario objetivo, los RID/SID de los grupos y, opcionalmente, atributos PAC derivados de LDAP.
- **Claves de servicio** (solo si planeas volver a generar tickets de servicio): clave AES del SPN del servicio que se va a suplantar.

1. Obtén un TGT para cualquier usuario controlado mediante AS-REQ (`/tgtdeleg` de Rubeus es práctico porque fuerza al cliente a realizar el intercambio Kerberos GSS-API sin credenciales).
2. Descifra el TGT devuelto con la clave de krbtgt y modifica los atributos PAC (usuario, grupos, información de inicio de sesión, SID, declaraciones del dispositivo, etc.).
3. Vuelve a cifrar y firmar el ticket con la misma clave de krbtgt e inyéctalo en la sesión de inicio de sesión actual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repite el proceso con un ticket de servicio proporcionando un blob de TGT válido y la clave del servicio objetivo para mantener el sigilo en el tráfico de red.

### Tradecraft actualizado de Rubeus (2024+)

El trabajo reciente de Huntress modernizó la acción `diamond` de Rubeus incorporando las mejoras `/ldap` y `/opsec`, que antes solo estaban disponibles para golden/silver tickets. Ahora, `/ldap` obtiene contexto PAC real consultando LDAP **y** montando SYSVOL para extraer atributos de cuentas y grupos, además de la política Kerberos/contraseñas (por ejemplo, `GptTmpl.inf`); por su parte, `/opsec` hace que el flujo AS-REQ/AS-REP coincida con el de Windows mediante el intercambio de preautenticación de dos pasos y el uso exclusivo de AES y KDCOptions realistas. Esto reduce drásticamente los indicadores evidentes, como campos PAC ausentes o duraciones que no coinciden con la política.<sup>[[3]](#references)</sup>

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
- `/opsec` fuerza un reintento de AS-REQ similar al de Windows, poniendo a cero los flags que generan ruido y usando únicamente AES256.
- `/tgtdeleg` evita que tengas que acceder a la contraseña en texto claro o a la clave NTLM/AES de la víctima, y aun así devuelve un TGT que se puede descifrar.

### Reacuñación de tickets de servicio

La misma actualización de Rubeus añadió la capacidad de aplicar la técnica diamond a blobs TGS. Al proporcionar a `diamond` un **TGT codificado en base64** (de `asktgt`, `/tgtdeleg` o un TGT falsificado anteriormente), el **SPN del servicio** y la **clave AES del servicio**, puedes acuñar tickets de servicio realistas sin contactar con el KDC; en la práctica, un silver ticket más sigiloso.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Este workflow es ideal cuando ya controlas una clave de cuenta de servicio (p. ej., obtenida con `lsadump::lsa /inject` o `secretsdump.py`) y quieres generar un TGS puntual que coincida perfectamente con la política, las fechas y los datos PAC de AD sin generar tráfico AS/TGS nuevo.<sup>[[3]](#references)</sup>

### Intercambios de PAC al estilo Sapphire (2025)

Una variante más reciente, a veces llamada **sapphire ticket**, combina la base de «TGT real» de Diamond con **S4U2self+U2U** para robar un PAC privilegiado e insertarlo en tu propio TGT. En lugar de inventar SIDs adicionales, solicitas un ticket S4U2self U2U para un usuario con privilegios elevados, donde `sname` apunta al solicitante con pocos privilegios; el KRB_TGS_REQ incluye el TGT del solicitante en `additional-tickets` y establece `ENC-TKT-IN-SKEY`, lo que permite descifrar el ticket de servicio con la clave de ese usuario. Luego extraes el PAC privilegiado y lo insertas en tu TGT legítimo antes de volver a firmarlo con la clave de krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

`ticketer.py` de Impacket ahora incluye soporte para sapphire mediante `-impersonate` + `-request` (intercambio en vivo con el KDC):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` acepta un nombre de usuario o SID; `-request` requiere credenciales activas de usuario y material de clave krbtgt (AES/NTLM) para descifrar/modificar tickets.

Indicadores clave de OPSEC al usar esta variante:<sup>[[5]](#references)</sup>

- TGS-REQ incluirá `ENC-TKT-IN-SKEY` y `additional-tickets` (el TGT de la víctima), algo poco frecuente en el tráfico normal.
- `sname` suele ser igual al usuario que realiza la solicitud (acceso de autoservicio), y el Event ID 4769 muestra al solicitante y al objetivo como el mismo SPN/usuario.
- Se esperan entradas emparejadas 4768/4769 con el mismo equipo cliente, pero con distintos CNAMES (solicitante con pocos privilegios frente al propietario privilegiado del PAC).

### OPSEC y notas de detección

- Las heurísticas tradicionales de detección (TGS sin AS, vidas útiles de décadas) siguen aplicándose a los golden tickets, pero los diamond tickets suelen detectarse cuando el **contenido del PAC o la asignación de grupos parecen imposibles**. Completa todos los campos del PAC (horas de inicio de sesión, rutas de perfil de usuario, ID de dispositivos) para que las comparaciones automatizadas no detecten inmediatamente la falsificación.<sup>[[3]](#references)</sup>
- **No asignes grupos/RID en exceso**. Si solo necesitas `512` (Domain Admins) y `519` (Enterprise Admins), limítate a esos y asegúrate de que la cuenta objetivo pertenezca plausiblemente a esos grupos en otras partes de AD. Un exceso de `ExtraSids` delata la falsificación.
- Los intercambios al estilo Sapphire dejan rastros de U2U: `ENC-TKT-IN-SKEY` + `additional-tickets`, además de un `sname` que apunta a un usuario (a menudo el solicitante) en 4769, y un inicio de sesión 4624 posterior procedente del ticket falsificado. Correlaciona esos campos en vez de buscar únicamente brechas sin AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft comenzó a retirar gradualmente la **emisión de tickets de servicio RC4** debido a CVE-2026-20833; aplicar tipos de cifrado solo AES en el KDC refuerza el dominio y es compatible con las herramientas diamond/sapphire (/opsec ya fuerza AES). El uso de RC4 en PAC falsificados destacará cada vez más.<sup>[[6]](#references)</sup>
- El proyecto Security Content de Splunk distribuye telemetría de attack-range para diamond tickets, además de detecciones como *Indicador de suplantación de Domain Admin de Windows*, que correlacionan secuencias inusuales de Event ID 4768/4769/4624 y cambios en grupos del PAC. Reproducir ese conjunto de datos (o generar uno propio con los comandos anteriores) ayuda a validar la cobertura del SOC para T1558.001 y proporciona lógica de alertas concreta que puedes evadir.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Piedras preciosas: la nueva generación de ataques Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: nos encanta jugar con tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Replanteamiento del Diamond Ticket de Kerberos (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Datos y detecciones de ataques Diamond Ticket (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – El lado oscuro de las gemas: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Aplicación de RC4 para tickets de servicio en CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}

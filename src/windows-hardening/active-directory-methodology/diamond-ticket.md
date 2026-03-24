# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Como un golden ticket**, un diamond ticket es un TGT que puede usarse para **acceder a cualquier servicio como cualquier usuario**. Un golden ticket se forja completamente offline, se cifra con el hash krbtgt de ese dominio y luego se inyecta en una sesión de inicio de sesión para su uso. Como los controladores de dominio no rastrean los TGTs que hayan emitido legítimamente, aceptarán sin problema TGTs que estén cifrados con su propio hash krbtgt.

Hay dos técnicas comunes para detectar el uso de golden tickets:

- Buscar TGS-REQs que no tengan una AS-REQ correspondiente.
- Buscar TGTs que tengan valores absurdos, como la duración por defecto de 10 años de Mimikatz.

Un **diamond ticket** se crea **modificando los campos de un TGT legítimo emitido por un DC**. Esto se logra **solicitando** un **TGT**, **descifrándolo** con el hash krbtgt del dominio, **modificando** los campos deseados del ticket y luego **re-encriptándolo**. Esto **supera las dos limitaciones mencionadas** de un golden ticket porque:

- Los TGS-REQs tendrán una AS-REQ previa.
- El TGT fue emitido por un DC, por lo que tendrá todos los detalles correctos según la política Kerberos del dominio. Aunque estos se pueden forjar con precisión en un golden ticket, es más complejo y propenso a errores.

### Requisitos y flujo de trabajo

- **Cryptographic material**: la clave krbtgt AES256 (preferida) o el hash NTLM para poder descifrar y volver a firmar el TGT.
- **Legitimate TGT blob**: obtenido con `/tgtdeleg`, `asktgt`, `s4u`, o exportando tickets desde memoria.
- **Context data**: el RID del usuario objetivo, RIDs/SIDs de grupos, y (opcionalmente) atributos PAC derivados de LDAP.
- **Service keys** (solo si planeas volver a generar service tickets): clave AES del SPN de servicio a suplantar.

1. Obtén un TGT para cualquier usuario controlado vía AS-REQ (Rubeus `/tgtdeleg` es conveniente porque fuerza al cliente a realizar el Kerberos GSS-API dance sin credenciales).
2. Descifra el TGT devuelto con la key krbtgt, parchea los atributos PAC (usuario, grupos, información de logon, SIDs, claims de dispositivo, etc.).
3. Re-encripta/firma el ticket con la misma key krbtgt e inyectalo en la sesión de inicio actual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repite el proceso sobre un service ticket suministrando un blob TGT válido más la clave del servicio objetivo para mantener sigilo en la red.

### Rubeus tradecraft actualizado (2024+)

Trabajo reciente de Huntress modernizó la acción `diamond` dentro de Rubeus porteando las mejoras `/ldap` y `/opsec` que antes solo existían para golden/silver tickets. `/ldap` ahora extrae contexto PAC real consultando LDAP **y** montando SYSVOL para obtener atributos de cuenta/grupo además de la política Kerberos/password (p. ej., `GptTmpl.inf`), mientras que `/opsec` hace que el flujo AS-REQ/AS-REP coincida con Windows realizando el intercambio de preauth en dos pasos y aplicando AES-only + KDCOptions realistas. Esto reduce drásticamente indicadores obvios como campos PAC faltantes o duraciones que no coinciden con la política.
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
- `/ldap` (con opcionales `/ldapuser` y `/ldappassword`) consulta AD y SYSVOL para reflejar los datos de la política PAC del usuario objetivo.
- `/opsec` fuerza un reintento AS-REQ al estilo Windows, pone a cero flags ruidosos y se ciñe a AES256.
- `/tgtdeleg` evita tocar la cleartext password o la NTLM/AES key de la víctima mientras sigue devolviendo un TGT descifrable.

### Recorte de service-ticket

La misma actualización de Rubeus añadió la capacidad de aplicar la técnica diamond a los TGS blobs. Alimentando a `diamond` un **TGT codificado en base64** (desde `asktgt`, `/tgtdeleg` o un TGT previamente forjado), el **service SPN**, y la **service AES key**, puedes generar service tickets realistas sin tocar el KDC—efectivamente un silver ticket más sigiloso.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Este flujo de trabajo es ideal cuando ya controlas la clave de una cuenta de servicio (por ejemplo, extraída con `lsadump::lsa /inject` o `secretsdump.py`) y quieres emitir un TGS único que coincida perfectamente con la política de AD, las ventanas temporales y los datos del PAC sin generar tráfico AS/TGS nuevo.

### Sapphire-style PAC swaps (2025)

A newer twist sometimes called a **sapphire ticket** combines Diamond's "real TGT" base with **S4U2self+U2U** to steal a privileged PAC and drop it into your own TGT. Instead of inventing extra SIDs, you request a U2U S4U2self ticket for a high-privilege user where the `sname` targets the low-priv requester; the KRB_TGS_REQ carries the requester's TGT in `additional-tickets` and sets `ENC-TKT-IN-SKEY`, allowing the service ticket to be decrypted with that user's key. You then extract the privileged PAC and splice it into your legitimate TGT before re-signing with the krbtgt key.

Impacket's `ticketer.py` now ships sapphire support via `-impersonate` + `-request` (live KDC exchange):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` acepta un nombre de usuario o SID; `-request` requiere credenciales de usuario en vivo más material de clave krbtgt (AES/NTLM) para descifrar/parchear tickets.

Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — rare in normal traffic.
- `sname` often equals the requesting user (self-service access) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (low-priv requester vs. privileged PAC owner).

### Notas de OPSEC y detección

- Las heurísticas tradicionales de los hunters (TGS without AS, lifetimes de décadas) siguen aplicándose a golden tickets, pero diamond tickets suelen aflorar cuando el contenido del **PAC o el mapeo de grupos parece imposible**. Rellena todos los campos del PAC (logon hours, user profile paths, device IDs) para que las comparaciones automáticas no señalen inmediatamente la falsificación.
- **No sobreasignes grupos/RIDs**. Si solo necesitas `512` (Domain Admins) y `519` (Enterprise Admins), quédate ahí y asegúrate de que la cuenta objetivo pertenezca plausiblemente a esos grupos en otra parte de AD. `ExtraSids` excesivos delatan la maniobra.
- Los intercambios al estilo Sapphire dejan huellas U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` más un `sname` que apunta a un usuario (a menudo el solicitante) en 4769, y un inicio de sesión 4624 posterior originado por el ticket falsificado. Correlaciona esos campos en lugar de fijarte solo en las brechas de no-AS-REQ.
- Microsoft empezó a retirar progresivamente la emisión de **RC4 service ticket** debido a CVE-2026-20833; forzar etypes solo AES en el KDC tanto fortalece el dominio como se alinea con las herramientas diamond/sapphire (/opsec ya fuerza AES). Mezclar RC4 en PACs falsificados cada vez resultará más llamativo.
- El proyecto Security Content de Splunk distribuye telemetría de attack-range para diamond tickets además de detecciones como *Windows Domain Admin Impersonation Indicator*, que correlaciona secuencias inusuales de Event ID 4768/4769/4624 y cambios de grupos en el PAC. Reproducir ese dataset (o generar el propio con los comandos anteriores) ayuda a validar la cobertura del SOC para T1558.001 y te proporciona lógica de alertas concreta para evadir.

## Referencias

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}

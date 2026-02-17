# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket es un TGT que puede usarse para **acceder a cualquier servicio como cualquier usuario**. Un golden ticket se forja completamente offline, está cifrado con el hash krbtgt de ese dominio y luego se inyecta en una sesión de inicio de sesión para su uso. Como los controladores de dominio no rastrean los TGTs que ellos (o éste) han emitido legítimamente, aceptarán sin problema TGTs que estén cifrados con su propio hash krbtgt.

Existen dos técnicas comunes para detectar el uso de golden tickets:

- Buscar TGS-REQs que no tengan una AS-REQ correspondiente.
- Buscar TGTs con valores extraños, como la duración por defecto de 10 años que usa Mimikatz.

Un **diamond ticket** se crea **modificando los campos de un TGT legítimo emitido por un DC**. Esto se consigue solicitando un TGT, desencriptándolo con el hash krbtgt del dominio, modificando los campos deseados del ticket y luego volviéndolo a encriptar. Esto **supera las dos limitaciones mencionadas** de un golden ticket porque:

- Las TGS-REQ tendrán una AS-REQ previa.
- El TGT fue emitido por un DC, lo que significa que tendrá todos los detalles correctos de la política Kerberos del dominio. Aunque en un golden ticket se pueden forjar con precisión estos campos, es más complejo y propenso a errores.

### Requisitos y flujo de trabajo

- Material criptográfico: la clave krbtgt AES256 (preferida) o el hash NTLM para poder desencriptar y volver a firmar el TGT.
- Blob legítimo de TGT: obtenido con `/tgtdeleg`, `asktgt`, `s4u`, o exportando tickets desde memoria.
- Datos de contexto: el RID del usuario objetivo, los RIDs/SIDs de grupo y (opcionalmente) atributos PAC derivados de LDAP.
- Service keys (solo si planeas volver a emitir service tickets): clave AES del SPN de servicio que se va a suplantar.

1. Obtener un TGT para cualquier usuario controlado mediante AS-REQ (Rubeus `/tgtdeleg` es conveniente porque obliga al cliente a realizar el Kerberos GSS-API dance sin credenciales).
2. Desencriptar el TGT obtenido con la clave krbtgt, parchear los atributos PAC (usuario, grupos, información de inicio de sesión, SIDs, claims del dispositivo, etc.).
3. Re-encriptar/firma el ticket con la misma clave krbtgt e inyectarlo en la sesión de inicio actual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repetir el proceso sobre un service ticket suministrando un blob de TGT válido más la clave del servicio objetivo para mantenerse sigiloso en la red.

### Actualización del tradecraft de Rubeus (2024+)

Trabajo reciente de Huntress modernizó la acción `diamond` dentro de Rubeus al portar las mejoras de `/ldap` y `/opsec` que previamente existían solo para golden/silver tickets. `/ldap` ahora auto-puebla atributos PAC precisos directamente desde AD (perfil de usuario, logon hours, sidHistory, políticas de dominio), mientras que `/opsec` hace que el flujo AS-REQ/AS-REP sea indistinguible del de un cliente Windows al realizar la secuencia de pre-auth en dos pasos y forzar crypto solo AES. Esto reduce drásticamente indicadores obvios como device IDs en blanco o ventanas de validez poco realistas.
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
- `/ldap` (con opcional `/ldapuser` y `/ldappassword`) consulta AD y SYSVOL para replicar los datos de la política PAC del usuario objetivo.
- `/opsec` fuerza un reintento AS-REQ al estilo Windows, poniendo a cero flags ruidosos y limitándose a AES256.
- `/tgtdeleg` mantiene tus manos fuera de la contraseña en texto claro o de la clave NTLM/AES de la víctima mientras sigue devolviendo un TGT descifrable.

### Recorte de tickets de servicio

La misma actualización de Rubeus añadió la capacidad de aplicar la técnica diamond a los blobs TGS. Al alimentar a `diamond` con un **TGT codificado en base64** (desde `asktgt`, `/tgtdeleg`, o un TGT forjado previamente), el **service SPN**, y la **service AES key**, puedes crear tickets de servicio realistas sin tocar el KDC—efectivamente un silver ticket más sigiloso.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Este flujo de trabajo es ideal cuando ya controlas una clave de cuenta de servicio (p. ej., volcada con `lsadump::lsa /inject` o `secretsdump.py`) y quieres forjar un TGS único que coincida perfectamente con la política de AD, los plazos y los datos del PAC sin emitir tráfico AS/TGS adicional.

### Sapphire-style PAC swaps (2025)

Una variante más reciente, a veces llamada **sapphire ticket**, combina la base "real TGT" de Diamond con **S4U2self+U2U** para robar un PAC privilegiado y colocarlo en tu propio TGT. En lugar de inventar SIDs adicionales, solicitas un ticket U2U S4U2self para un usuario de alto privilegio, extraes ese PAC y lo empalmas en tu TGT legítimo antes de volver a firmarlo con la clave krbtgt. Como U2U establece `ENC-TKT-IN-SKEY`, el flujo en la red resultante parece un intercambio legítimo de usuario a usuario.

Reproducción mínima en Linux con `ticketer.py` parcheado de Impacket (añade soporte para sapphire):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Key OPSEC tells when using this variant:

- TGS-REQ llevará `ENC-TKT-IN-SKEY` y `additional-tickets` (el TGT de la víctima) — raro en el tráfico normal.
- `sname` a menudo es igual al usuario que solicita (acceso de autoservicio) y Event ID 4769 muestra al llamante y al objetivo como el mismo SPN/usuario.
- Espere entradas emparejadas 4768/4769 con el mismo equipo cliente pero diferentes CNAMES (solicitante de bajo privilegio vs. propietario de PAC privilegiado).

### OPSEC & detection notes

- Las heurísticas tradicionales de hunter (TGS sin AS, tiempos de vida de décadas) siguen aplicando a los golden tickets, pero los diamond tickets suelen aflorar cuando el **contenido del PAC o el mapeo de grupos parece imposible**. Rellene todos los campos del PAC (logon hours, user profile paths, device IDs) para que las comparaciones automatizadas no marquen inmediatamente la falsificación.
- **No asigne en exceso grupos/RIDs**. Si solo necesita `512` (Domain Admins) y `519` (Enterprise Admins), deténgase ahí y asegúrese de que la cuenta objetivo pertenezca de forma plausible a esos grupos en otra parte del AD. Excessive `ExtraSids` es una pista evidente.
- Los swaps estilo Sapphire dejan huellas U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` en 4769, y un inicio de sesión 4624 posterior originado desde el ticket forjado. Correlacione esos campos en lugar de solo buscar brechas de no-AS-REQ.
- Microsoft empezó a eliminar gradualmente la emisión de **RC4 service ticket** por CVE-2026-20833; imponer etypes solo AES en el KDC tanto endurece el dominio como se alinea con las herramientas diamond/sapphire (/opsec ya fuerza AES). Mezclar RC4 en PACs forjados cada vez destacará más.
- El proyecto Security Content de Splunk distribuye telemetría de attack-range para diamond tickets además de detecciones como *Windows Domain Admin Impersonation Indicator*, que correlaciona secuencias inusuales de Event ID 4768/4769/4624 y cambios de grupos en el PAC. Reproducir ese dataset (o generar el propio con los comandos anteriores) ayuda a validar la cobertura del SOC para T1558.001 a la vez que proporciona lógica de alertas concreta para evadir.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}

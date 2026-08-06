# Enumeración de Active Directory Web Services (ADWS) y recopilación sigilosa

{{#include ../../banners/hacktricks-training.md}}

## ¿Qué es ADWS?

Active Directory Web Services (ADWS) está **habilitado de forma predeterminada en todos los Domain Controllers desde Windows Server 2008 R2** y escucha en el puerto TCP **9389**. A pesar del nombre, **no interviene HTTP**. En su lugar, el servicio expone datos de estilo LDAP mediante una pila de protocolos de framing .NET propietarios:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Debido a que el tráfico está encapsulado dentro de estos frames SOAP binarios y viaja por un puerto poco común, **es mucho menos probable que la enumeración mediante ADWS sea inspeccionada, filtrada o detectada mediante firmas que el tráfico LDAP/389 y 636 clásico**. Para los operadores, esto significa:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon más sigiloso: los equipos Blue suelen concentrarse en las consultas LDAP.
* Libertad para recopilar datos desde **hosts que no son Windows (Linux, macOS)** mediante un túnel de 9389/TCP a través de un proxy SOCKS.
* Los mismos datos que obtendrías mediante LDAP (usuarios, grupos, ACLs, schema, etc.) y la capacidad de realizar **writes** (por ejemplo, `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

Las interacciones con ADWS se implementan mediante WS-Enumeration: cada consulta comienza con un mensaje `Enumerate` que define el filtro/atributos LDAP y devuelve un GUID `EnumerationContext`, seguido de uno o más mensajes `Pull` que transmiten resultados hasta el límite de resultados definido por el servidor.<sup>[[7]](#references)</sup> Los contextos caducan después de unos 30 minutos, por lo que las herramientas deben paginar los resultados o dividir los filtros (consultas por prefijo para cada CN) para evitar perder el estado.<sup>[[8]](#references)</sup> Al solicitar security descriptors, especifica el control `LDAP_SERVER_SD_FLAGS_OID` para omitir las SACLs; de lo contrario, ADWS simplemente elimina el atributo `nTSecurityDescriptor` de su respuesta SOAP.

> NOTA: ADWS también es utilizado por muchas herramientas RSAT GUI/PowerShell, por lo que el tráfico puede mezclarse con actividad legítima de administración.

## SoaPy – Cliente nativo de Python

[SoaPy](https://github.com/logangoins/soapy) es una **reimplementación completa de la pila de protocolos ADWS en Python puro**. Construye los frames NBFX/NBFSE/NNS/NMF byte a byte, lo que permite recopilar datos desde sistemas tipo Unix sin utilizar el runtime de .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Características principales

* Admite **proxying mediante SOCKS** (útil desde implantes C2).
* Filtros de búsqueda detallados idénticos a LDAP: `-q '(objectClass=user)'`.
* Operaciones opcionales de **write** (`--set` / `--delete`).
* **Modo de salida BOFHound** para la ingesta directa en BloodHound.
* Flag `--parse` para hacer más legibles las marcas de tiempo / `userAccountControl` cuando se necesita legibilidad humana.<sup>[[2]](#references)</sup>

### Flags de recopilación dirigida y operaciones de write

SoaPy incluye switches seleccionados que replican las tareas más comunes de LDAP hunting mediante ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, además de las opciones `--query` / `--filter` sin formato para pulls personalizados. Combínalos con primitives de write como `--rbcd <source>` (establece `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (preparación de SPNs para Kerberoasting dirigido) y `--asrep` (activa `DONT_REQ_PREAUTH` en `userAccountControl`).<sup>[[2]](#references)</sup>

Ejemplo de SPN hunting dirigido que solo devuelve `samAccountName` y `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa el mismo host/credenciales para weaponise inmediatamente los findings: extrae los objetos capaces de RBCD con `--rbcds` y, después, aplica `--rbcd 'WEBSRV01$' --account 'FILE01$'` para preparar una cadena de Resource-Based Constrained Delegation (consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para conocer el proceso completo de abuso).

### Instalación (host del operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump sobre ADWS (Linux/Windows)

* Fork de `ldapdomaindump` que sustituye las consultas LDAP por llamadas ADWS en TCP/9389 para reducir las detecciones de firmas LDAP.
* Realiza una comprobación inicial de accesibilidad al puerto 9389, a menos que se pase `--force` (omite la sonda si los escaneos de puertos generan demasiado ruido o están filtrados).
* Probado con Microsoft Defender for Endpoint y CrowdStrike Falcon, con un bypass exitoso en el README.<sup>[[4]](#references)</sup>

### Instalación
```bash
pipx install .
```
### Uso
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
La salida típica registra la comprobación de accesibilidad del puerto 9389, el bind de ADWS y el inicio/finalización del dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Un cliente práctico para ADWS en Golang

Al igual que soapy, [sopa](https://github.com/Macmod/sopa) implementa el protocol stack de ADWS (MS-NNS + MC-NMF + SOAP) en Golang y expone flags de línea de comandos para realizar llamadas ADWS como:<sup>[[5]](#references)</sup>

* **Búsqueda y recuperación de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` y `delete`
* **Edición de atributos** - `attr [add|replace|delete]`
* **Gestión de cuentas** - `set-password` / `change-password`
* y otros como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Aspectos destacados del mapeo de protocolos

* Las búsquedas de estilo LDAP se realizan mediante **WS-Enumeration** (`Enumerate` + `Pull`), con proyección de atributos, control del scope (Base/OneLevel/Subtree) y paginación.
* La obtención de un único objeto utiliza **WS-Transfer** `Get`; los cambios de atributos usan `Put`; las eliminaciones usan `Delete`.
* La creación de objetos integrada utiliza **WS-Transfer ResourceFactory**; los objetos custom utilizan una **IMDA AddRequest** basada en templates YAML.
* Las operaciones de contraseña son acciones **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Descubrimiento de metadatos sin autenticación (mex)

ADWS expone WS-MetadataExchange sin credenciales, lo que permite validar rápidamente la exposición antes de autenticarse:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Notas sobre el descubrimiento de DNS/DC y la selección de objetivos de Kerberos

Sopa puede resolver DCs mediante SRV si se omite `--dc` y se proporciona `--domain`. Consulta en este orden y utiliza el objetivo con mayor prioridad:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operativamente, es preferible usar un resolver controlado por un DC para evitar fallos en entornos segmentados:

* Usa `--dns <DC-IP>` para que **todas** las búsquedas SRV/PTR/forward pasen por el DNS del DC.
* Usa `--dns-tcp` cuando UDP esté bloqueado o las respuestas SRV sean grandes.
* Si Kerberos está habilitado y `--dc` es una IP, sopa realiza un **reverse PTR** para obtener un FQDN y dirigir correctamente el SPN/KDC. Si no se usa Kerberos, no se realiza ninguna búsqueda PTR.

Ejemplo (IP + Kerberos, DNS forzado mediante el DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opciones de material de autenticación

Además de las contraseñas en texto plano, sopa admite **NT hashes**, **Kerberos AES keys**, **ccache** y **PKINIT certificates** (PFX o PEM) para la autenticación ADWS. Kerberos se da por hecho al usar `--aes-key`, `-c` (ccache) u opciones basadas en certificados.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Creación de objetos personalizados mediante plantillas

Para clases de objetos arbitrarias, el comando `create custom` consume una plantilla YAML que se asigna a una `AddRequest` de IMDA:<sup>[[5]](#references)</sup>

* `parentDN` y `rdn` definen el contenedor y el DN relativo.
* `attributes[].name` admite `cn` o `addata:cn` con namespace.
* `attributes[].type` acepta `string|int|bool|base64|hex` o un `xsd:*` explícito.
* **No** incluyas `ad:relativeDistinguishedName` ni `ad:container-hierarchy-parent`; sopa los inyecta.
* Los valores `hex` se convierten a `xsd:base64Binary`; usa `value: ""` para establecer cadenas vacías.

## SOAPHound – Recopilación de ADWS de alto volumen (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) es un collector de .NET que mantiene todas las interacciones LDAP dentro de ADWS y genera JSON compatible con BloodHound v4. Construye una cache completa de `objectSid`, `objectGUID`, `distinguishedName` y `objectClass` una vez (`--buildcache`), y después la reutiliza para las pasadas de alto volumen `--bhdump`, `--certdump` (ADCS) o `--dnsdump` (DNS integrado en AD), de modo que solo unos ~35 atributos críticos salen del DC. AutoSplit (`--autosplit --threshold <N>`) divide automáticamente las queries por prefijo CN para mantenerse por debajo del timeout de 30 minutos de EnumerationContext en forests grandes.<sup>[[8]](#references)</sup>

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
Exporta slots JSON directamente a los workflows de SharpHound/BloodHound; consulta [BloodHound methodology](bloodhound.md) para obtener ideas sobre el graficado posterior. AutoSplit hace que SOAPHound sea resistente en forests con millones de objetos, manteniendo el número de consultas por debajo del de los snapshots de estilo ADExplorer.

## Stealth AD Collection Workflow

El siguiente workflow muestra cómo enumerar **objetos de dominio y ADCS** mediante ADWS, convertirlos a JSON de BloodHound y buscar attack paths basados en certificados, todo desde Linux:

1. **Tuneliza 9389/TCP** desde la red objetivo hasta tu equipo (por ejemplo, mediante Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` o usa `--proxyHost/--proxyPort` de SoaPy.

2. **Recopila el objeto del dominio raíz:**
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
5. **Carga el ZIP** en la GUI de BloodHound y ejecuta consultas cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar rutas de escalación de certificados (ESC1, ESC8, etc.).

### Escritura de `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combínalo con `s4u2proxy`/`Rubeus /getticket` para crear una cadena completa de **Resource-Based Constrained Delegation** (consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumen de herramientas

| Propósito | Herramienta | Notas |
|---------|------|-------|
| Enumeración de ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lectura/escritura |
| Volcado de ADWS de gran volumen | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modos BH/ADCS/DNS |
| Ingesta en BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convierte logs de SoaPy/ldapsearch |
| Compromiso de certificados | [Certipy](https://github.com/ly4k/Certipy) | Se puede usar mediante el mismo SOCKS |
| Enumeración de ADWS y cambios de objetos | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interactuar con endpoints de ADWS conocidos; permite la enumeración, la creación de objetos, la modificación de atributos y los cambios de contraseña |

## Referencias

- [1] [SpecterOps – Asegúrate de usar SOAP(y) – Guía del operador para la recopilación sigilosa de AD mediante ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy en GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound en GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump en GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa en GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – especificaciones MC-NBFX, MC-NBFSE, MS-NNS y MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Enumeración sigilosa de entornos de Active Directory mediante ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Herramienta SOAPHound para recopilar datos de Active Directory mediante ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ¿Qué es ADWS?

Active Directory Web Services (ADWS) está **habilitado por defecto en cada Domain Controller desde Windows Server 2008 R2** y escucha en TCP **9389**. A pesar del nombre, **no se usa HTTP**. En su lugar, el servicio expone datos estilo LDAP a través de una pila de protocolos propietarios .NET de enmarcado binario:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Debido a que el tráfico está encapsulado dentro de estos marcos SOAP binarios y viaja por un puerto poco común, **la enumeración a través de ADWS es mucho menos probable que sea inspeccionada, filtrada o detectada por firmas que el tráfico clásico LDAP/389 & 636**. Para los operadores esto significa:

* Recon sigiloso: los Blue teams a menudo se concentran en consultas LDAP.
* Libertad para recolectar desde **hosts no Windows (Linux, macOS)** tunnelizando 9389/TCP a través de un proxy SOCKS.
* Los mismos datos que obtendrías vía LDAP (usuarios, grupos, ACLs, schema, etc.) y la capacidad de realizar **writes** (p. ej. `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

Las interacciones con ADWS se implementan sobre WS-Enumeration: cada consulta comienza con un mensaje `Enumerate` que define el filtro/atributos LDAP y devuelve un `EnumerationContext` GUID, seguido de uno o más mensajes `Pull` que transmiten hasta la ventana de resultados definida por el servidor. Los contextos caducan tras ~30 minutos, por lo que las herramientas necesitan paginar resultados o dividir filtros (consultas por prefijo en CN) para evitar perder estado. Cuando se solicitan descriptores de seguridad, especifica el control `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs, de lo contrario ADWS simplemente elimina el atributo `nTSecurityDescriptor` de su respuesta SOAP.

> NOTA: ADWS también es usado por muchas herramientas RSAT GUI/PowerShell, por lo que el tráfico puede mezclarse con actividad administrativa legítima.

## SoaPy – Cliente nativo en Python

[SoaPy](https://github.com/logangoins/soapy) es una **implementación completa de la pila de protocolos ADWS en puro Python**. Fabrica los frames NBFX/NBFSE/NNS/NMF byte a byte, permitiendo la recolección desde sistemas tipo Unix sin tocar el runtime .NET.

### Características clave

* Soporta **proxying through SOCKS** (útil desde implantes C2).
* Filtros de búsqueda fino idénticos a LDAP `-q '(objectClass=user)'`.
* Operaciones opcionales de **write** ( `--set` / `--delete` ).
* Modo de salida **BOFHound** para ingestión directa en BloodHound.
* Flag `--parse` para embellecer timestamps / `userAccountControl` cuando se requiere legibilidad humana.

### Flags de recolección dirigidos & operaciones de escritura

SoaPy incluye switches curados que replican las tareas de hunting LDAP más comunes sobre ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, además de knobs crudos `--query` / `--filter` para pulls personalizados. Combínalos con primitivas de escritura como `--rbcd <source>` (setea `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (staging de SPN para Kerberoasting dirigido) y `--asrep` (voltea `DONT_REQ_PREAUTH` en `userAccountControl`).

Ejemplo de búsqueda dirigida de SPN que solo devuelve `samAccountName` y `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa el mismo host/credenciales para explotar inmediatamente los hallazgos: vuelca objetos RBCD-capable con `--rbcds`, y luego aplica `--rbcd 'WEBSRV01$' --account 'FILE01$'` para montar una cadena Resource-Based Constrained Delegation (ver [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para la ruta completa de abuso).

### Instalación (host del operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump sobre ADWS (Linux/Windows)

* Fork de `ldapdomaindump` que reemplaza las consultas LDAP por llamadas ADWS en TCP/9389 para reducir las detecciones por firmas LDAP.
* Realiza una comprobación inicial de accesibilidad al puerto 9389 a menos que se indique `--force` (omite la prueba si los escaneos de puertos son ruidosos/filtrados).
* Probado contra Microsoft Defender for Endpoint y CrowdStrike Falcon con un bypass exitoso documentado en el README.

### Instalación
```bash
pipx install .
```
### Uso
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
La salida típica registra la comprobación de accesibilidad del puerto 9389, el ADWS bind y el inicio/fin del dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Un cliente práctico para ADWS en Golang

De manera similar a soapy, [sopa](https://github.com/Macmod/sopa) implementa la pila de protocolos ADWS (MS-NNS + MC-NMF + SOAP) en Golang, exponiendo banderas de línea de comandos para emitir llamadas ADWS como:

* **Búsqueda y recuperación de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Edición de atributos** - `attr [add|replace|delete]`
* **Gestión de cuentas** - `set-password` / `change-password`
* y otros como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Aspectos destacados del mapeo del protocolo

* Las búsquedas estilo LDAP se ejecutan vía **WS-Enumeration** (`Enumerate` + `Pull`) con proyección de atributos, control de alcance (Base/OneLevel/Subtree) y paginación.
* La recuperación de un único objeto usa **WS-Transfer** `Get`; los cambios de atributos usan `Put`; las eliminaciones usan `Delete`.
* La creación de objetos integrada usa **WS-Transfer ResourceFactory**; los objetos personalizados usan un **IMDA AddRequest** impulsado por plantillas YAML.
* Las operaciones de contraseña son acciones de **MS-ADCAP** (`SetPassword`, `ChangePassword`).

### Unauthenticated metadata discovery (mex)

ADWS expone WS-MetadataExchange sin credenciales, lo que es una forma rápida de validar la exposición antes de autenticarse:
```bash
sopa mex --dc <DC>
```
### Notas sobre DNS/DC discovery y Kerberos targeting

Sopa puede resolver DCs mediante registros SRV si `--dc` se omite y se proporciona `--domain`. Consulta en este orden y utiliza el objetivo de mayor prioridad:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operativamente, prefiera un resolver controlado por el DC para evitar fallos en entornos segmentados:

* Use `--dns <DC-IP>` para que **todas** las búsquedas SRV/PTR/forward pasen por el DNS del DC.
* Use `--dns-tcp` cuando UDP esté bloqueado o las respuestas SRV sean grandes.
* Si Kerberos está habilitado y `--dc` es una IP, sopa realiza un **reverse PTR** para obtener un FQDN para el correcto direccionamiento a SPN/KDC. Si no se usa Kerberos, no se realiza ninguna búsqueda PTR.

Ejemplo (IP + Kerberos, DNS forzado vía el DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opciones de material de autenticación

Además de contraseñas en texto plano, sopa admite **NT hashes**, **Kerberos AES keys**, **ccache**, y **PKINIT certificates** (PFX o PEM) para la autenticación ADWS. Se asume Kerberos al usar `--aes-key`, `-c` (ccache) u opciones basadas en certificados.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Creación de objetos personalizados mediante plantillas

Para clases de objeto arbitrarias, el comando `create custom` consume una plantilla YAML que mapea a una `AddRequest` de IMDA:

* `parentDN` y `rdn` definen el contenedor y el DN relativo.
* `attributes[].name` admite `cn` o `addata:cn` con espacio de nombres.
* `attributes[].type` acepta `string|int|bool|base64|hex` o `xsd:*` explícito.
* **No** incluya `ad:relativeDistinguishedName` ni `ad:container-hierarchy-parent`; sopa los inyecta.
* Los valores `hex` se convierten a `xsd:base64Binary`; utilice `value: ""` para establecer cadenas vacías.

## SOAPHound – Colección ADWS de alto volumen (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) es un colector .NET que mantiene todas las interacciones LDAP dentro de ADWS y emite JSON compatible con BloodHound v4. Construye una caché completa de `objectSid`, `objectGUID`, `distinguishedName` y `objectClass` una vez (`--buildcache`), luego la reutiliza para pases de alto volumen `--bhdump`, `--certdump` (ADCS), o `--dnsdump` (AD-integrated DNS) de modo que solo ~35 atributos críticos salen del DC. AutoSplit (`--autosplit --threshold <N>`) divide automáticamente las consultas por prefijo CN para mantenerse por debajo del tiempo de espera de 30 minutos de EnumerationContext en bosques grandes.

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
Los JSON exportados se integraron directamente en los workflows de SharpHound/BloodHound — ver [BloodHound methodology](bloodhound.md) para ideas de graficado downstream. AutoSplit hace que SOAPHound sea resistente en bosques con millones de objetos mientras mantiene el número de consultas más bajo que los snapshots al estilo ADExplorer.

## Flujo de trabajo de recolección AD sigiloso

El siguiente flujo de trabajo muestra cómo enumerar **domain & ADCS objects** sobre ADWS, convertirlos a BloodHound JSON y buscar rutas de ataque basadas en certificados — todo desde Linux:

1. **Tunnel 9389/TCP** desde la red objetivo a tu equipo (p. ej. vía Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` o usa SoaPy’s `--proxyHost/--proxyPort`.

2. **Recopila el objeto raíz del dominio:**
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
5. **Sube el ZIP** en la GUI de BloodHound y ejecuta consultas cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar rutas de escalada de certificados (ESC1, ESC8, etc.).

### Escribiendo `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combínalo con `s4u2proxy`/`Rubeus /getticket` para una cadena completa de **Resource-Based Constrained Delegation** (ver [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumen de herramientas

| Propósito | Herramienta | Notas |
|---------|------|-------|
| Enumeración ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lectura/escritura |
| Volcado masivo de ADWS | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| Ingesta para BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convierte logs de SoaPy/ldapsearch |
| Compromiso de certificados | [Certipy](https://github.com/ly4k/Certipy) | Se puede enrutar a través del mismo SOCKS |
| Enumeración ADWS y cambios de objetos | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interactuar con endpoints ADWS conocidos - permite enumeración, creación de objetos, modificación de atributos y cambios de contraseñas |

## Referencias

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

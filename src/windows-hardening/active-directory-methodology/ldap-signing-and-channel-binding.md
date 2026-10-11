# Endurecimiento de LDAP Signing y Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Por qué importa

Los ataques de LDAP relay/MITM reenvían la autenticación a un controlador de dominio para obtener un contexto LDAP autenticado. Dos controles relacionados reducen estas vías:

- **LDAP channel binding (CBT)** vincula la autenticación aplicable al certificado/canal TLS del servidor usado por LDAPS, dificultando el relay entre canales.
- **LDAP signing** requiere protección de integridad para los enlaces LDAP SASL. No añade confidencialidad; usa TLS cuando también sea necesario cifrar el contenido LDAP.<sup>[[2]](#references)</sup>

**Comprobación rápida del estado**: herramientas como `netexec ldap <dc> -u user -p pass` informan de las políticas observadas de signing y channel binding. `(signing:None)` y `(channel binding:Never)` indican que faltan controles, pero que un relay tenga éxito sigue dependiendo del tipo de autenticación capturada, el comportamiento de EPA, los privilegios de la cuenta, el protocolo de destino y las protecciones contra relay. Cuando la entidad autenticada reenviada tiene los permisos necesarios, herramientas como KrbRelayUp pueden escribir `msDS-AllowedToActOnBehalfOfOtherIdentity`, configurar la delegación restringida basada en recursos (RBCD) y usar la ruta de delegación resultante para suplantar a una entidad privilegiada.<sup>[[4]](#references)</sup>

**Los DC con Server 2025** introducen una nueva GPO (**LDAP server signing requirements Enforcement**) cuyo valor predeterminado es **Require Signing** si se deja en **Not Configured**. Para evitar la aplicación obligatoria, debes establecer explícitamente esa política en **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (solo LDAPS)

- **Requisitos**:
  - El parche CVE-2017-8563 (2017) añade compatibilidad con Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) añade telemetría de LDAPS CBT en modo “what-if”.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (valor predeterminado, sin CBT)
  - `When Supported` (aplicación parcial: los clientes compatibles con CBT deben proporcionar un token válido; los clientes sin compatibilidad con CBT aún pueden establecer el enlace, y se generan eventos de auditoría)
  - `Always` (aplicación obligatoria: rechaza los enlaces LDAPS sin un CBT válido)<sup>[[1]](#references)</sup>
- **Auditoría**: establece **When Supported** para detectar:
  - **3074** – El enlace LDAPS habría fallado la validación de CBT si la política se hubiera aplicado.
  - **3075** – El enlace LDAPS omitió los datos de CBT y se habría rechazado si la política se hubiera aplicado.
  - (El evento **3039** sigue indicando fallos de CBT en compilaciones anteriores.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Aplicación obligatoria**: establece **Always** cuando los clientes LDAPS envíen CBT; solo tiene efecto en **LDAPS** (no en LDAP sin TLS por el puerto 389).<sup>[[1]](#references)</sup>

`When Supported` no es solo de auditoría: valida el CBT de los clientes compatibles y permite la conexión de los clientes sin compatibilidad con CBT. La [referencia de políticas de Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) describe los valores predeterminados según la versión. LDAP signing se aplica a los enlaces correspondientes por LDAP/389; channel binding se aplica a la autenticación LDAP protegida por TLS.


## LDAP Signing

- **GPO de cliente**: `Network security: LDAP client signing requirements` = `Require signing` (en lugar del valor predeterminado `Negotiate signing` en las versiones modernas de Windows).<sup>[[1]](#references)</sup>
- **GPO del DC**:
  - Heredada: `Domain controller: LDAP server signing requirements` = `Require signing` (el valor predeterminado es `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: deja la política heredada en `None` y establece `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` aplica la política de forma predeterminada; establece `Disabled` para evitarlo).<sup>[[1]](#references)</sup>
- **Compatibilidad**: inventaría los dispositivos y aplicaciones que no sean Windows y que usen enlaces simples o enlaces SASL sin firma. Microsoft documenta la compatibilidad en versiones de Windows con soporte vigente; las afirmaciones de compatibilidad con clientes heredados deben verificarse con la pila real del cliente, en lugar de reducirse a un umbral de versión de XP.<sup>[[2]](#references)</sup>

## Despliegue con auditoría primero (se recomiendan ~30 días)

1. Habilita los diagnósticos de la interfaz LDAP en cada DC para registrar los enlaces sin firma (evento **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Establece `LDAP server channel binding token requirements` en la GPO del DC como **When Supported** para aplicar CBT parcialmente y recopilar telemetría; valida primero la compatibilidad con clientes heredados.<sup>[[1]](#references)</sup>
3. Supervisa los eventos de Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – vinculaciones sin firma o permitidas sin firma (no cumplen los requisitos de firma).
   - **3074/3075** – vinculaciones LDAPS que fallarían o no incluirían CBT (requiere KB4520412 en 2019/2022 y el paso 2 anterior).
4. Aplica en cambios separados:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clientes).
   - `LDAP server signing requirements` = **Require signing** (DCs) **o** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - Vinculación de canal LDAP y firma LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Requisitos de vinculación de canal LDAP y firma LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Actualización para mitigar LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (firma LDAP deshabilitada → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}

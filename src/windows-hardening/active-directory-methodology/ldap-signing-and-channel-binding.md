# Hardening de LDAP Signing y Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Por qué importa

LDAP relay/MITM permite a los atacantes reenviar binds a Domain Controllers para obtener contextos autenticados. Dos controles del servidor mitigan estas vías:

- **LDAP Channel Binding (CBT)** vincula un bind LDAPS al túnel TLS específico, impidiendo relays/replays entre canales diferentes.
- **LDAP Signing** fuerza el uso de mensajes LDAP protegidos mediante integridad, evitando la manipulación y la mayoría de los relays sin firma.

**Comprobación ofensiva rápida**: herramientas como `netexec ldap <dc> -u user -p pass` muestran la configuración del servidor. Si aparece `(signing:None)` y `(channel binding:Never)`, los **relays de Kerberos/NTLM a LDAP** son viables (por ejemplo, usando KrbRelayUp para escribir `msDS-AllowedToActOnBehalfOfOtherIdentity` para RBCD e impersonar a administradores).<sup>[[4]](#references)</sup>

Los **DC de Server 2025** introducen una nueva GPO (**LDAP server signing requirements Enforcement**) que, si se deja en **Not Configured**, usa **Require Signing** de forma predeterminada. Para evitar la aplicación de esta configuración, debes establecer explícitamente esa política en **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (solo LDAPS)

- **Requisitos**:
- El parche CVE-2017-8563 (2017) añade compatibilidad con Extended Protection for Authentication.<sup>[[3]](#references)</sup>
- **KB4520412** (Server 2019/2022) añade telemetría “what-if” de CBT para LDAPS.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (valor predeterminado, sin CBT)
- `When Supported` (auditoría: genera errores, pero no bloquea)
- `Always` (aplicación: rechaza binds LDAPS sin un CBT válido)<sup>[[1]](#references)</sup>
- **Auditoría**: establece **When Supported** para detectar:
- **3074** – El bind LDAPS habría fallado la validación de CBT si se hubiera aplicado la política.
- **3075** – El bind LDAPS no incluyó datos CBT y habría sido rechazado si se hubiera aplicado la política.
- (El evento **3039** también indica fallos de CBT en compilaciones anteriores.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Aplicación**: establece **Always** cuando los clientes LDAPS envíen CBT; solo es efectivo en **LDAPS** (no en el puerto 389 sin TLS).<sup>[[1]](#references)</sup>


## LDAP Signing

- **GPO de cliente**: `Network security: LDAP client signing requirements` = `Require signing` (frente al valor predeterminado `Negotiate signing` en las versiones modernas de Windows).<sup>[[1]](#references)</sup>
- **GPO del DC**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (el valor predeterminado es `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: deja la política legacy en `None` y establece `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` = aplicado de forma predeterminada; establece `Disabled` para evitarlo).<sup>[[1]](#references)</sup>
- **Compatibilidad**: solo Windows **XP SP3+** admite LDAP signing; los sistemas más antiguos dejarán de funcionar cuando se active la aplicación.

## Despliegue basado primero en auditoría (recomendado: ~30 días)

1. Activa los diagnósticos de la interfaz LDAP en cada DC para registrar binds sin firma (evento **2889**):<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Establece la GPO del DC `LDAP server channel binding token requirements` = **When Supported** para iniciar la telemetría de CBT.<sup>[[1]](#references)</sup>
3. Monitoriza los eventos de Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – binds sin firma/permitidos sin firma (no cumplen los requisitos de signing).
- **3074/3075** – binds LDAPS que fallarían u omitirían CBT (requiere KB4520412 en 2019/2022 y el paso 2 anterior).
4. Aplica las siguientes medidas en cambios separados:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **o** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Referencias

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Requisitos de LDAP channel binding y signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Actualización para mitigar LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing deshabilitado → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}

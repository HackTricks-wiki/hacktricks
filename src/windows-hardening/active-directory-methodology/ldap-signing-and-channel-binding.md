# Endurecimiento de LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Por qué importa

LDAP relay/MITM permite a los atacantes reenviar binds a controladores de dominio para obtener contextos autenticados. Dos controles del lado del servidor bloquean estas vías:

- **LDAP Channel Binding (CBT)** vincula un bind LDAPS al túnel TLS específico, impidiendo relays/replays a través de canales diferentes.
- **LDAP Signing** obliga a que los mensajes LDAP tengan integridad protegida, evitando manipulaciones y la mayoría de los relays no firmados.

**Comprobación ofensiva rápida**: herramientas como `netexec ldap <dc> -u user -p pass` muestran la postura del servidor. Si ves `(signing:None)` y `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** son viables (por ejemplo, usando KrbRelayUp para escribir `msDS-AllowedToActOnBehalfOfOtherIdentity` para RBCD e impersonar administradores).

**Server 2025 DCs** introduce una nueva GPO (**LDAP server signing requirements Enforcement**) que por defecto queda en **Require Signing** cuando se deja **Not Configured**. Para evitar la aplicación debes configurar explícitamente esa política en **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Requisitos**:
- CVE-2017-8563 patch (2017) agrega soporte para Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) agrega telemetría “what-if” de LDAPS CBT.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (por defecto, sin CBT)
- `When Supported` (auditoría: emite fallos, no bloquea)
- `Always` (aplica: rechaza LDAPS binds sin CBT válido)
- **Auditoría**: establece **When Supported** para detectar:
- **3074** – LDAPS bind habría fallado la validación CBT si se hubiera aplicado.
- **3075** – LDAPS bind omitió datos CBT y habría sido rechazado si se hubiera aplicado.
- (El evento **3039** aún señala fallos de CBT en compilaciones antiguas.)
- **Aplicación**: establece **Always** una vez que los clientes LDAPS envíen CBTs; solo efectivo en **LDAPS** (no en el puerto 389 sin TLS).

## LDAP Signing

- **GPO del cliente**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` por defecto en Windows modernos).
- **GPO de DC**:
- Legado: `Domain controller: LDAP server signing requirements` = `Require signing` (el valor por defecto es `None`).
- **Server 2025**: deja la política heredada en `None` y configura `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = aplicado por defecto; establece `Disabled` para evitarlo).
- **Compatibilidad**: solo Windows **XP SP3+** soporta LDAP signing; los sistemas más antiguos dejarán de funcionar cuando la aplicación esté habilitada.

## Implementación en modo auditoría (recomendada ~30 días)

1. Habilita la diagnosticación de la interfaz LDAP en cada DC para registrar binds no firmados (Evento **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Establecer la GPO del DC `LDAP server channel binding token requirements` = **When Supported** para iniciar la telemetría de CBT.
3. Supervisar eventos de Directory Service:
- **2889** – unsigned/unsigned-allow binds (firma no conforme).
- **3074/3075** – LDAPS binds que fallarían u omitirían CBT (requiere KB4520412 en 2019/2022 y el paso 2 anterior).
4. Hacer cumplir mediante cambios separados:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Referencias

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}

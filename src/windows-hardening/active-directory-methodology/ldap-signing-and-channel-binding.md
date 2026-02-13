# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Por qué importa

LDAP relay/MITM permite a los atacantes reenviar binds a controladores de dominio para obtener contextos autenticados. Dos controles en el servidor bloquean estas vías:

- **LDAP Channel Binding (CBT)** vincula un bind LDAPS con el túnel TLS específico, rompiendo relays/replays entre canales distintos.
- **LDAP Signing** obliga a que los mensajes LDAP tengan integridad protegida, evitando manipulaciones y la mayoría de los relays no firmados.

**Server 2025 DCs** introducen una nueva GPO (**LDAP server signing requirements Enforcement**) que por defecto queda en **Require Signing** cuando está **Not Configured**. Para evitar la aplicación debes establecer explícitamente esa política en **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Requisitos**:
- CVE-2017-8563 patch (2017) añade soporte para Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) añade telemetría LDAPS CBT “what-if”.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (por defecto, sin CBT)
- `When Supported` (audit: emite fallos, no bloquea)
- `Always` (enforce: rechaza binds LDAPS sin CBT válido)
- **Auditoría**: configura **When Supported** para detectar:
- **3074** – El bind LDAPS habría fallado la validación CBT si se hubiese aplicado.
- **3075** – El bind LDAPS omitió datos CBT y habría sido rechazado si se hubiese aplicado.
- (El evento **3039** aún señala fallos CBT en builds más antiguos.)
- **Enforcement**: establece **Always** una vez que los clientes LDAPS envíen CBTs; efectivo sólo en **LDAPS** (no en el puerto 389 sin TLS).

## LDAP Signing

- **GPO del cliente**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` por defecto en Windows modernos).
- **GPO del DC**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (el valor por defecto es `None`).
- **Server 2025**: deja la política legacy en `None` y establece `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = aplicado por defecto; pon `Disabled` para evitarlo).
- **Compatibilidad**: sólo Windows **XP SP3+** soporta LDAP signing; los sistemas más antiguos dejarán de funcionar cuando se habilite la aplicación.

## Despliegue empezando por auditoría (recomendado ~30 días)

1. Habilita diagnostics de la interfaz LDAP en cada DC para registrar binds no firmados (Evento **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Establezca la GPO del DC `LDAP server channel binding token requirements` = **When Supported** para iniciar la telemetría de CBT.
3. Supervisar eventos de Directory Service:
- **2889** – unsigned/unsigned-allow binds (firma no conforme).
- **3074/3075** – LDAPS binds que fallarían u omitirían CBT (requiere KB4520412 en 2019/2022 y el paso 2 anterior).
4. Aplicar en cambios separados:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}

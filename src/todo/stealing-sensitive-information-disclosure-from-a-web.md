# Robar información sensible de una página web

{{#include ../banners/hacktricks-training.md}}

Si una **página web muestra información sensible basándose en la sesión actual**—como cookies, datos de la cuenta o detalles de tarjetas de crédito—un atacante puede intentar exfiltrarla. Las principales técnicas incluyen:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Una configuración incorrecta de CORS puede permitir que un origen malicioso lea respuestas sensibles mediante solicitudes cross-origin.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Una vulnerabilidad XSS en el origen objetivo puede permitir que JavaScript inyectado lea y exfiltre la información.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Cuando la inyección de scripts no está disponible, los elementos HTML inyectados aún pueden capturar contenido sensible.
- [**Clickjacking**](../pentesting-web/clickjacking.md): Si faltan protecciones contra el framing, un atacante puede engañar a un usuario para que interactúe con la página sensible. El caso práctico enlazado demuestra esta técnica.<sup>[[1]](#references)</sup>

## References

- [1] [El servlet de ejemplo de Apache provoca una divulgación de información](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}

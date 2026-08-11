# Otros trucos web

{{#include ../banners/hacktricks-training.md}}

## Host header

A veces los back ends confían en el campo HTTP `Host` al construir enlaces absolutos. Si un correo de restablecimiento de contraseña utiliza un host proporcionado por el atacante, solicitar un restablecimiento para una víctima puede enviar un enlace que contiene un token a través de un dominio controlado por el atacante. Prueba también los campos forwarded-host, el manejo de varios valores Host y los destinos de solicitud en formato absoluto en cada salto del proxy.<sup>[[1]](#references)</sup>

> [!WARNING]
> Puede que no sea necesario que el usuario haga clic: **los escáneres de seguridad de correo, los servicios de vista previa u otros intermediarios pueden solicitar automáticamente el enlace controlado por el atacante**, divulgando el token de restablecimiento.

## Booleanos de sesión

Algunas aplicaciones registran una verificación completada como un booleano en la sesión y después permiten que otro endpoint dependa de ese indicador. Después de superar legítimamente la comprobación para un recurso, prueba si el mismo indicador autoriza incorrectamente a otro usuario, objeto o flujo de trabajo. Esto es una falla de autorización/reutilización del estado de segundo orden, no simplemente un IDOR.<sup>[[2]](#references)</sup>

## Funcionalidad de registro

Intenta registrarte como un usuario que ya existe. Prueba también usando caracteres equivalentes (puntos, muchos espacios y Unicode).

## Confusión del estado del cambio de correo electrónico

Registra una dirección de correo electrónico y cámbiala antes de confirmarla. Comprueba si la confirmación de la nueva dirección se envía a la dirección antigua o si confirmar el token antiguo activa la nueva dirección. Los tokens de confirmación deben estar vinculados a la cuenta exacta, la dirección pendiente, el propósito y el estado actual.

## Service desks de Atlassian expuestos


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## Método TRACE

El método HTTP `TRACE` solicita un reflejo de la solicitud recibida con fines de diagnóstico. RFC 9110 exige que los destinatarios omitan del contenido reflejado los campos sensibles, como las credenciales y las cookies, pero las implementaciones inseguras o las cabeceras añadidas por intermediarios aún pueden divulgar transformaciones internas de la solicitud. Los navegadores impiden que los scripts generen solicitudes TRACE, por lo que el histórico cross-site tracing attack también depende de una forma independiente de inyectar campos protegidos.<sup>[[3]](#references)</sup>![Imagen que muestra una respuesta TRACE](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Imagen de la publicación](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Cómo pude tomar el control de la cuenta de cualquier usuario mediante Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Un vector de ataque menos conocido: ataques IDOR de segundo orden](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, sección 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}

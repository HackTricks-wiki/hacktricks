# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Tipos de payload de Intruder

Burp Intruder incluye los siguientes generadores y transformaciones de payload integrados:<sup>[[1]](#references)</sup>

- **Simple list:** Usa una lista configurada de cadenas como payloads.
- **Runtime file:** Lee un payload por línea durante la ejecución. Esto resulta útil para listas grandes porque Burp no carga el archivo entero en memoria.
- **Case modification:** Genera el valor sin modificar, en minúsculas y en mayúsculas, en formato `Propername` (primera letra en mayúscula y el resto en minúsculas) o `ProperName` (primera letra en mayúscula y los caracteres restantes sin modificar). Burp descarta los resultados duplicados.
- **Numbers:** Genera números secuenciales o aleatorios dentro de un rango configurado.
- **Brute forcer:** Genera todas las permutaciones para un conjunto de caracteres y una longitud mínima y máxima elegidos.

## Extensiones y herramientas complementarias

- **Collabfiltrator** genera payloads que ejecutan comandos y exfiltran su salida mediante consultas DNS a Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exporta los hallazgos de Burp para usarlos en otros flujos de trabajo de informes.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** convierte solicitudes HTTP en scripts en varios lenguajes.<sup>[[4]](#references)</sup>

## Pruebas de autorización con varias sesiones mediante Session Switcher

[Session Switcher](https://github.com/doyensec/burp-session-switcher) es una extensión Java para Burp Suite `2025.5+` que almacena cookies y encabezados poco comunes como perfiles de credenciales con nombre. Al seleccionar un perfil en un editor de solicitudes editable, como Repeater o una solicitud de Proxy interceptada, se reemplaza el material de autenticación de la solicitud. Esto facilita la repetición de solicitudes, **no es un bypass de autorización**: úsalo para enviar la misma solicitud con distintas cuentas al comprobar el acceso horizontal, los límites entre roles verticales, el aislamiento entre tenants y [IDOR/BOLA](../pentesting-web/idor.md) como parte de la [metodología de pruebas web](../pentesting-web/web-vulnerabilities-methodology.md).<sup>[[5]](#references)[[8]](#references)</sup>

### Flujo de trabajo repetible para comparar identidades

El siguiente flujo de trabajo mantiene el recurso/acción y la identidad que actúa como variables de prueba separadas, lo que reduce los falsos resultados causados por tokens obsoletos o por usar la sesión de navegador equivocada.<sup>[[5]](#references)[[8]](#references)</sup>

1. Autentica cuentas de prueba que representen a cada usuario, rol y tenant relevante en perfiles de navegador o contenedores separados.
2. Abre una solicitud que lleve las cookies y los encabezados de una identidad, selecciona **Sessions > New** y asigna al perfil un nombre inequívoco, como `tenant-a-user` o `tenant-b-admin`. Repite el proceso con cada identidad de prueba.
3. Envía una solicitud candidata a Repeater y repítela sin cambiar el método, el endpoint, los parámetros ni el identificador del objeto; cambia únicamente la sesión seleccionada. Compara los datos de la respuesta y los cambios de estado observables, no solo los códigos de estado.
4. Para comprobaciones a nivel de objeto, repite una solicitud de un objeto que se sepa que pertenece a la cuenta A mientras seleccionas el perfil de la cuenta B. Para comprobaciones a nivel de función, repite la misma acción privilegiada con perfiles de menor privilegio.
5. Después de volver a autenticarte o rotar el token, usa **Update** en una solicitud actual del navegador o configura una regla de Auto Update antes de repetir la comparación.

### Semántica de captura e inyección

Revisa los modos de actualización/inyección antes de probar, porque una solicitud híbrida que contenga credenciales de dos identidades puede invalidar la comparación. La configuración predeterminada actual copia todas las cookies de la solicitud a un perfil, actualiza solo los encabezados poco comunes ya almacenados, copia las cookies del perfil seleccionado a la solicitud de destino (eliminando las cookies existentes) y añade los encabezados del perfil. El selector puede limitarse a un subdominio exacto, al dominio de nivel superior de la aplicación (predeterminado) o a todos los perfiles guardados.<sup>[[7]](#references)</sup>

- **Mirror** resulta útil cuando el conjunto completo de cookies define una identidad y es necesario eliminar las cookies obsoletas de destino.
- **Update existing** sigue los valores rotativos sin incorporar cookies ni encabezados no relacionados del tráfico del navegador.
- **Add all** conserva los valores adicionales ya almacenados en el perfil o la solicitud; comprueba que no queden datos de identidad de la sesión anterior.
- **Do nothing** excluye las cookies o los encabezados de las actualizaciones del perfil cuando esa clase de credencial no es relevante.

### Sincronización de sesiones basada en Proxy

Las reglas de Auto Update asocian el tráfico de Proxy con un perfil guardado y actualizan sus cookies/encabezados. Prioriza un discriminador estable, como un encabezado de solicitud dedicado, un marcador `User-Agent` específico del perfil, una cookie identificadora, `X-PwnFox-Color` o una claim de JWT; combínalo con condiciones de ámbito/dominio/ruta para impedir que aplicaciones no relacionadas actualicen el perfil. Todas las condiciones de una regla se evalúan en orden mediante un `AND` lógico, así que coloca primero las comprobaciones más restrictivas; implementa `OR` creando varias reglas que apunten al mismo perfil. También se admite la coincidencia negativa.<sup>[[6]](#references)</sup>

Para cada regla coincidente, elige **Mirror request**, **Add all**, **Update existing** o **Do nothing** de forma independiente para las cookies y los encabezados. Las reglas que solo evalúan solicitudes se ejecutan cuando Proxy recibe la solicitud; añadir una condición de estado, encabezado o cuerpo de respuesta aplaza la evaluación hasta que llega la respuesta. Se puede asignar un color de resaltado al tráfico coincidente, lo que ayuda a verificar que cada identidad de navegador actualice solo el perfil previsto.<sup>[[6]](#references)</sup>

Los perfiles guardados residen en el proyecto de Burp, y las exportaciones de datos del proyecto en JSON incluyen las sesiones y, por tanto, sus cookies y encabezados. Trata ambos archivos como material de credenciales activo, restringe el acceso a ellos y elimina los datos almacenados de la extensión después del engagement.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [Documentación de PortSwigger - tipos de payload de Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Exporter de Burp Suite](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - documentación sobre el código fuente y el uso de Session Switcher](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - reglas de Auto Update de Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - configuración de Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: simplificación de las pruebas de autorización con varias sesiones en Burp Suite](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}

# Hacking de sistemas de control industrial

{{#include ../banners/hacktricks-training.md}}

## Acerca de esta sección

Esta sección presenta los componentes, las arquitecturas, los protocolos y los métodos de evaluación de seguridad de los sistemas de control industrial (ICS). ICS forma parte del ámbito más amplio de la tecnología operacional (OT): sistemas y dispositivos programables que supervisan o provocan cambios en procesos físicos. Entre los ejemplos habituales se incluyen los sistemas de supervisión, control y adquisición de datos (SCADA), los sistemas de control distribuido (DCS) y los controladores lógicos programables (PLC).<sup>[[1]](#references)</sup>

El trabajo de seguridad en estos entornos debe tener en cuenta requisitos distintos de los de la IT convencional, como la seguridad de los procesos, la fiabilidad, la disponibilidad, el funcionamiento determinista y los ciclos de vida de los equipos. Un control de seguridad técnicamente válido puede no ser adecuado si interrumpe el proceso físico; por eso, las pruebas y las medidas correctivas deben coordinarse con el propietario del sistema y el personal de operaciones.<sup>[[1]](#references)</sup>

Un compromiso o una interrupción accidental pueden detener la producción, dañar equipos, liberar materiales peligrosos, perjudicar el medioambiente o provocar lesiones y pérdidas de vidas. Este posible impacto físico es la razón por la que comprender el proceso controlado y sus límites de operación segura debe ser prioritario antes de realizar pruebas activas.<sup>[[1]](#references)</sup>

Muchas implementaciones de OT conservan sistemas operativos, aplicaciones y protocolos heredados porque los equipos tienen una vida útil prolongada y los cambios requieren pruebas operativas y de seguridad. Algunos protocolos se diseñaron sin autenticación ni cifrado modernos, y la aplicación de parches puede estar limitada por el soporte del proveedor o por las ventanas de mantenimiento; cuando no sea viable actualizar directamente, compénselo con segmentación, control de acceso y monitorización.<sup>[[1]](#references)</sup>

## Prioridades de evaluación

Empiece por comprender el proceso controlado, los límites del sistema, la topología de red, los activos, los flujos de datos, las relaciones de confianza y las conexiones externas. Dispositivos similares pueden cumplir funciones distintas en diferentes instalaciones, así que no dé por hecho que la arquitectura o el modelo de impacto de una implementación se aplica a otra.<sup>[[1]](#references)</sup>

Siempre que sea posible, prefiera el descubrimiento pasivo y la documentación de ingeniería existente. Cualquier análisis activo o explotación debe seguir un plan de pruebas aprobado que defina las restricciones de seguridad, las ventanas de mantenimiento, los procedimientos de recuperación y las condiciones para detener las pruebas. Los hallazgos deben evaluarse tanto por su impacto en la ciberseguridad como por sus posibles efectos en el proceso físico.<sup>[[1]](#references)</sup>

El mismo conocimiento de la arquitectura también permite actividades defensivas como el inventario de activos, la segmentación de red, la monitorización, la respuesta a incidentes y la gestión de vulnerabilidades basada en riesgos.<sup>[[1]](#references)</sup>

## Abuso del controlador de refrigeración supervisado

Un administrador de sistemas de refrigeración coordina los controladores de compresores y vitrinas, pero no enfría las vitrinas por sí mismo. Por tanto, el acceso a su interfaz de gestión puede dar control sobre muchos dispositivos subordinados mediante la distribución normal de la configuración. Esto es distinto de cambiar un termostato o accionar directamente un compresor.<sup>[[3]](#references)[[4]](#references)</sup>

### Inicio de sesión con código de mantenimiento derivado de la fecha

En los administradores de sistemas Danfoss afectados, un inicio de sesión XML alternativo acepta un código derivado de la fecha del controlador en lugar de la contraseña de una cuenta.<sup>[[2]](#references)[[3]](#references)</sup> En los SM800 y SC255, Synacktiv rastreó los atributos `eds_only` y `quantum_only` a través de `xml_load_file` y `check_authorize` hasta `check_code_of_day`. Su aviso también muestra que `read_date_time` en `xml.cgi` revela la fecha del controlador sin autenticación.<sup>[[2]](#references)</sup> Claroty encontró una ruta `getauth` correspondiente en el AK-SM 800A, pero ocultó sus atributos activadores; no debe suponerse que los nombres de atributos de los modelos anteriores funcionen en esa plataforma.<sup>[[3]](#references)</sup>

Synacktiv documenta la consulta de fecha sin autenticación de la siguiente manera:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

El código no contiene ningún secreto específico del dispositivo: recuperar el algoritmo del [firmware](../hardware-physical-access/firmware-analysis/) puede permitir obtener una credencial válida según la fecha para dispositivos con la misma implementación afectada.<sup>[[2]](#references)[[3]](#references)</sup> Confirma primero el modelo y el firmware. Una respuesta basada únicamente en la fecha no demuestra que exista el inicio de sesión alternativo ni que se haya obtenido una sesión.

### Abuso de la configuración masiva y del calentador de descongelación

Tras obtener acceso administrativo, identifica los controladores de vitrinas asignados al gestor del sistema y comprueba si su función de distribución de configuración puede actualizarlos todos a la vez. Un cambio en la consigna de una vitrina normalmente solo la calienta hasta alcanzar la temperatura ambiente. Para calentarla por encima de la temperatura ambiente, el control pertinente es el calentador eléctrico de descongelación del evaporador del controlador: la descongelación detiene la refrigeración y activa el calentador hasta que un sensor o temporizador finaliza el ciclo. En su lugar, cambiar el método de descongelación, la programación, la temperatura de finalización y el límite de tiempo puede mantener activo el calentador. El gestor puede distribuir esos cambios a muchas vitrinas y suprimir las alarmas asociadas, convirtiendo el compromiso de un único sistema de supervisión en un cambio de proceso en toda la tienda.<sup>[[4]](#references)</sup>

Esto supone un peligro para el proceso físico; no es una prueba de concepto segura para realizar en un sistema operativo. Si existen, los termostatos de seguridad pueden limitar el funcionamiento del calentador, pero el funcionamiento continuo aún puede sobrecalentar una conexión eléctrica débil preexistente. Valida la configuración y el impacto únicamente en un laboratorio autorizado o siguiendo el plan de seguridad del proceso del operador.<sup>[[4]](#references)</sup>

## Puntos de entrada de protocolos

- [Pruebas de Modbus](../network-services-pentesting/pentesting-modbus.md) cubre Modbus TCP, variantes seriales, códigos de función y acceso a registros.
- [Pruebas de OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) cubre el servicio industrial de intercambio de datos.
- [Pruebas de BACnet](../network-services-pentesting/47808-udp-bacnet.md) cubre las redes de control de automatización de edificios.

## References

- [1] [NIST SP 800-82 Rev. 3 - Guía de seguridad de la tecnología operativa (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Bypass de autenticación en Danfoss System-Managers SM800 y SC255](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Congela el controlador, descongela los alimentos](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - No necesitas un Estado-nación para calentar un refrigerador](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}

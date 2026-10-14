# Hacking de sistemas de control industrial

{{#include ../banners/hacktricks-training.md}}

## Acerca de esta sección

Esta sección presenta los componentes, las arquitecturas, los protocolos y los métodos de evaluación de seguridad de los sistemas de control industrial (ICS). ICS forma parte del ámbito más amplio de la tecnología operativa (OT): sistemas y dispositivos programables que supervisan o provocan cambios en procesos físicos. Algunos ejemplos comunes son los sistemas de supervisión, control y adquisición de datos (SCADA), los sistemas de control distribuido (DCS) y los controladores lógicos programables (PLC).<sup>[[1]](#references)</sup>

El trabajo de seguridad en estos entornos debe tener en cuenta requisitos distintos de los de la TI convencional, como la seguridad de los procesos, la fiabilidad, la disponibilidad, el funcionamiento determinista y el ciclo de vida de los equipos. Un control de seguridad técnicamente válido puede ser inadecuado si interrumpe el proceso físico, por lo que las pruebas y la corrección deben coordinarse con el propietario del sistema y el personal de operaciones.<sup>[[1]](#references)</sup>

Un compromiso o una interrupción accidental pueden detener la producción, dañar equipos, liberar materiales peligrosos, perjudicar el medio ambiente o causar lesiones y pérdidas de vidas. Este posible impacto físico es la razón por la que comprender el proceso controlado y sus límites de operación segura debe ser prioritario antes de realizar pruebas activas.<sup>[[1]](#references)</sup>

Muchas implementaciones de OT conservan sistemas operativos, aplicaciones y protocolos heredados porque los equipos tienen una vida útil prolongada y los cambios requieren pruebas operativas y de seguridad. Algunos protocolos se diseñaron sin mecanismos modernos de autenticación o cifrado, y la aplicación de parches puede verse limitada por el soporte del proveedor o las ventanas de mantenimiento; cuando no sea viable realizar actualizaciones directas, compénselo con segmentación, control de acceso y monitoreo.<sup>[[1]](#references)</sup>

## Prioridades de evaluación

Comience por comprender el proceso controlado, los límites del sistema, la topología de red, los activos, los flujos de datos, las relaciones de confianza y las conexiones externas. Dispositivos similares pueden desempeñar funciones distintas en diferentes instalaciones, así que no dé por sentado que la arquitectura o el modelo de impacto de una implementación se aplica a otra.<sup>[[1]](#references)</sup>

Siempre que sea posible, prefiera el descubrimiento pasivo y la documentación de ingeniería existente. Cualquier análisis activo o explotación debe seguir un plan de pruebas aprobado que defina las restricciones de seguridad, las ventanas de mantenimiento, los procedimientos de recuperación y las condiciones para detener las pruebas. Los hallazgos deben evaluarse tanto por su impacto en la ciberseguridad como por sus posibles efectos en el proceso físico.<sup>[[1]](#references)</sup>

El mismo conocimiento arquitectónico sirve de apoyo a actividades defensivas como el inventario de activos, la segmentación de red, el monitoreo, la respuesta a incidentes y la gestión de vulnerabilidades basada en el riesgo.<sup>[[1]](#references)</sup>

## Puntos de entrada de protocolos

- [Pruebas de Modbus](../network-services-pentesting/pentesting-modbus.md) abarca Modbus TCP, las variantes seriales, los códigos de función y el acceso a registros.
- [Pruebas de OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) abarca el servicio de intercambio de datos industriales.
- [Pruebas de BACnet](../network-services-pentesting/47808-udp-bacnet.md) abarca las redes de control de automatización de edificios.

## References

- [1] [NIST SP 800-82 Rev. 3 - Guía de seguridad de la tecnología operativa (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../banners/hacktricks-training.md}}

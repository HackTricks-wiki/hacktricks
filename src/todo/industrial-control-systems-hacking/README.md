# Hacking de sistemas de control industrial

{{#include ../../banners/hacktricks-training.md}}

## Acerca de esta sección

Esta sección presenta los componentes, las arquitecturas, los protocolos y los métodos de evaluación de seguridad de los sistemas de control industrial (ICS). ICS forma parte del dominio más amplio de la tecnología operativa (OT): sistemas y dispositivos programables que supervisan o provocan cambios en procesos físicos. Entre los ejemplos habituales se incluyen los sistemas de control supervisorio y adquisición de datos (SCADA), los sistemas de control distribuido (DCS) y los controladores lógicos programables (PLC).<sup>[[1]](#references)</sup>

El trabajo de seguridad en estos entornos debe tener en cuenta requisitos que difieren de los de la TI convencional, incluidos la seguridad del proceso, la fiabilidad, la disponibilidad, el funcionamiento determinista y los ciclos de vida de los equipos. Un control de seguridad técnicamente válido puede seguir siendo inadecuado si interrumpe el proceso físico, por lo que las pruebas y la remediación deben coordinarse con el propietario del sistema y el personal de operaciones.<sup>[[1]](#references)</sup>

## Prioridades de la evaluación

Comienza por comprender el proceso controlado, los límites del sistema, la topología de red, los activos, los flujos de datos, las relaciones de confianza y las conexiones externas. Los tipos de dispositivos similares pueden cumplir funciones diferentes en distintos sitios, por lo que se debe evitar asumir que la arquitectura o el modelo de impacto de una implementación se aplica a otra.<sup>[[1]](#references)</sup>

Da prioridad al descubrimiento pasivo y a la documentación de ingeniería existente siempre que sea posible. Cualquier escaneo activo o explotación debe seguir un plan de pruebas aprobado que defina las restricciones de seguridad, las ventanas de mantenimiento, los procedimientos de recuperación y las condiciones de detención. Los hallazgos deben evaluarse tanto por su impacto en la ciberseguridad como por sus posibles efectos en el proceso físico.<sup>[[1]](#references)</sup>

El mismo conocimiento arquitectónico respalda actividades defensivas como el inventario de activos, la segmentación de red, la monitorización, la respuesta ante incidentes y la gestión de vulnerabilidades basada en riesgos.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Guía sobre seguridad de la tecnología operativa (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}

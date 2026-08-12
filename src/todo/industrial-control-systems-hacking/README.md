# Hacking de sistemas de control industrial

{{#include ../../banners/hacktricks-training.md}}

## Acerca de esta sección

Esta sección presenta los componentes, las arquitecturas, los protocolos y los métodos de evaluación de seguridad de los sistemas de control industrial (ICS). ICS forma parte del ámbito más amplio de la tecnología operativa (OT): sistemas y dispositivos programables que supervisan o provocan cambios en procesos físicos. Entre los ejemplos comunes se incluyen los sistemas de supervisión, control y adquisición de datos (SCADA), los sistemas de control distribuido (DCS) y los controladores lógicos programables (PLC).<sup>[[1]](#references)</sup>

El trabajo de seguridad en estos entornos debe tener en cuenta requisitos diferentes de los de la IT convencional, incluidos la seguridad del proceso, la fiabilidad, la disponibilidad, el funcionamiento determinista y los ciclos de vida de los equipos. Un control de seguridad técnicamente válido puede seguir siendo inadecuado si interrumpe el proceso físico, por lo que las pruebas y la remediación deben coordinarse con el propietario del sistema y el personal de operaciones.<sup>[[1]](#references)</sup>

Un compromiso o una interrupción accidental pueden detener la producción, dañar los equipos, liberar material peligroso, perjudicar el medioambiente o causar lesiones y pérdida de vidas. Este posible impacto físico explica por qué comprender el proceso controlado y sus límites operativos seguros debe preceder a las pruebas activas.<sup>[[1]](#references)</sup>

Muchas implementaciones de OT conservan sistemas operativos, aplicaciones y protocolos heredados porque los equipos tienen una larga vida útil y los cambios requieren pruebas operativas y de seguridad. Algunos protocolos se diseñaron sin autenticación ni cifrado modernos, y la aplicación de parches puede verse limitada por el soporte del proveedor o por las ventanas de mantenimiento; cuando las actualizaciones directas no sean viables, compénselo mediante segmentación, control de acceso y monitorización.<sup>[[1]](#references)</sup>

## Prioridades de la evaluación

Comience por comprender el proceso controlado, los límites del sistema, la topología de red, los activos, los flujos de datos, las relaciones de confianza y las conexiones externas. Los mismos tipos de dispositivos pueden desempeñar funciones diferentes en distintos sitios, por lo que debe evitar asumir que la arquitectura o el modelo de impacto de una implementación se aplica a otra.<sup>[[1]](#references)</sup>

Prefiera el descubrimiento pasivo y la documentación de ingeniería existente siempre que sea posible. Cualquier escaneo activo o explotación debe seguir un plan de pruebas aprobado que defina las restricciones de seguridad, las ventanas de mantenimiento, los procedimientos de recuperación y las condiciones de detención. Los hallazgos deben evaluarse tanto por su impacto en la ciberseguridad como por sus posibles efectos en el proceso físico.<sup>[[1]](#references)</sup>

El mismo conocimiento de la arquitectura permite actividades defensivas como el inventario de activos, la segmentación de red, la monitorización, la respuesta a incidentes y la gestión de vulnerabilidades basada en el riesgo.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Guía de seguridad de la tecnología operativa (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}

# El protocolo Modbus

{{#include ../../banners/hacktricks-training.md}}

## Introducción a Modbus

Modbus es un protocolo de capa de aplicación abierto implementado ampliamente por PLC, sensores, actuadores y otros dispositivos industriales. Su modelo de solicitud/respuesta expone bobinas y registros mediante códigos de función. Por tanto, las pruebas de seguridad se centran en lecturas/escrituras no autorizadas, observación del tráfico, replay y comportamiento inseguro del dispositivo, no únicamente en encontrar el puerto TCP 502.<sup>[[1]](#references)</sup>

Muchas implementaciones conservan equipos serie heredados porque las actualizaciones requieren tiempo de inactividad, recertificación o sustitución de dispositivos de campo. El Modbus tradicional no proporciona confidencialidad ni autenticación entre pares; Modbus Security es un perfil independiente basado en TLS que utiliza certificados X.509 y el puerto TCP 802. Debido a que la especificación es pública y puede implementarse de forma independiente, el comportamiento de los proveedores y la compatibilidad con funciones opcionales varían, por lo que deben identificarse mediante fingerprinting en lugar de darse por supuestos.<sup>[[1]](#references)[[2]](#references)</sup>

## La arquitectura cliente-servidor

En la terminología actual, un **cliente** inicia una transacción y un **servidor** devuelve una respuesta. La documentación antigua utiliza **master/slave**. No se debe confundir esta relación de aplicación con SPI o I2C: son protocolos de bus diferentes.<sup>[[1]](#references)</sup>

## Transportes serie y Ethernet

Los mismos datos de aplicación de Modbus pueden transportarse mediante variantes serie (encuadre RTU o ASCII) y mediante Modbus TCP. Modbus TCP añade una cabecera MBAP y normalmente utiliza el puerto TCP 502; el RTU serie utiliza un encuadre binario compacto y un CRC, mientras que el ASCII serie representa los bytes como caracteres hexadecimales y utiliza un LRC.<sup>[[1]](#references)[[3]](#references)</sup>

## Representación de datos

El modelo de datos consta de bobinas/entradas discretas de un solo bit y registros de entrada/retención de 16 bits. Los valores que ocupan varios registros, el orden de los bytes, el escalado y el significado semántico dependen del dispositivo y deben confirmarse mediante el mapa de registros del proveedor.<sup>[[1]](#references)</sup>

## Códigos de función

Los códigos de función seleccionan operaciones como leer bobinas (`0x01`), leer registros de retención (`0x03`), escribir una única bobina/registro (`0x05`/`0x06`) y escribir múltiples bobinas/registros (`0x0F`/`0x10`). Una solicitud de escritura capturada puede ser susceptible de replay cuando la implementación no cuenta con autenticación compensatoria ni comprobaciones del estado del proceso. Con acceso físico autorizado a tendidos serie largos, un evaluador también puede capturar o inyectar tramas directamente en el cableado después de identificar la interfaz eléctrica, la terminación y el método de conexión seguro. Cualquiera de estas acciones puede afectar al proceso físico, por lo que debe utilizarse un laboratorio o contar con una autorización operativa explícita.<sup>[[1]](#references)[[3]](#references)</sup>

## Direccionamiento

Los dispositivos serie utilizan una dirección de unidad. Modbus TCP utiliza el direccionamiento IP más un identificador de unidad en la cabecera MBAP, lo que resulta especialmente relevante cuando una gateway de TCP a serie enruta solicitudes a unidades posteriores. Las referencias de registros mostradas en la documentación del producto pueden ser de base uno (`40001`), mientras que las direcciones del protocolo son de base cero, una fuente habitual de errores de desplazamiento de uno.<sup>[[1]](#references)[[3]](#references)</sup>

El encuadre serie incluye comprobaciones de errores de transmisión (CRC para RTU y LRC para ASCII), y TCP proporciona su suma de comprobación de transporte normal. Estas comprobaciones detectan corrupción accidental; no constituyen integridad criptográfica ni autenticación del origen.<sup>[[3]](#references)</sup>

Durante una evaluación autorizada, compruebe la exposición, los códigos de función permitidos, los rangos de direcciones de escritura, el manejo de excepciones, los límites de velocidad y si la segmentación de red o un firewall con conocimiento de Modbus restringe a los clientes. Entre las amenazas relevantes se incluyen la divulgación pasiva, la inyección de comandos no autorizada, el replay, la falsificación de datos y la denegación de servicio. Coordine todas las pruebas activas con los responsables del proceso, ya que cambios aparentemente pequeños en los registros pueden alterar un proceso físico.

## References

- [1] [Organización Modbus — Especificación del protocolo de aplicación Modbus V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Organización Modbus — Protocolo de seguridad Modbus y guías de implementación](https://www.modbus.org/modbus-specifications)
- [3] [Organización Modbus — Especificación y guía de implementación de Modbus sobre línea serie V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}

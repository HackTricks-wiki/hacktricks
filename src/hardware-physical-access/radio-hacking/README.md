# Hacking de radio

{{#include ../../banners/hacktricks-training.md}}

Las pruebas de seguridad de radio examinan cómo un dispositivo transmite, recibe e interpreta señales inalámbricas. Una radio definida por software (SDR) puede ayudar a localizar una señal, grabar muestras en fase/cuadratura (I/Q) y probar la demodulación y decodificación sin depender de hardware específico de un protocolo.<sup>[[1]](#references)</sup>

Un flujo de trabajo práctico consiste en identificar la banda de frecuencia y el ancho de canal, capturar varias acciones conocidas del dispositivo, comparar las señales resultantes y, luego, determinar la modulación y la estructura de los paquetes. Prueba la reproducción o transmisión solo en un entorno aislado y en frecuencias y equipos para los que tengas autorización. Las páginas de esta sección abarcan RFID, NFC, radio sub-GHz, infrarrojos, BLE y herramientas relacionadas.<sup>[[1]](#references)</sup>

## Encuentra la interfaz pertinente

- Para una credencial de acceso o una llave de contacto, empieza con [tipos y ataques a etiquetas RFID/NFC](pentesting-rfid.md), [flujos de trabajo de Proxmark3](proxmark-3.md) o [llaves iButton y 1-Wire](ibutton.md). La [guía de Flipper Zero](flipper-zero/README.md) enlaza a las acciones específicas de su interfaz.
- Para una señal de control remoto, usa [RF sub-GHz y códigos variables](sub-ghz-rf.md) o [protocolos y ataques infrarrojos](infrared.md).
- Para dispositivos y sensores cercanos, usa [pruebas de publicidad BLE, GATT y malla](pentesting-ble-bluetooth-low-energy.md) o [seguridad de LPWAN/LoRaWAN](low-power-wide-area-network.md).
- Para señales de RF capturadas o desconocidas, usa el [análisis de señales con SigDigger](../hardware-hacking/radio.md#sigdigger) o el [framework FISSURE](fissure-the-rf-framework.md).
- Para enlaces descendentes de terminales satelitales, consulta [inyección de señales en el enlace de ida VSAT](vsat-forward-link-injection.md).



## References

- [1] [Great Scott Gadgets - Radio definida por software con HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}

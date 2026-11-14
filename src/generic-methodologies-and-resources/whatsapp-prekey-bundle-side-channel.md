# Agotamiento de bundles de prekeys de WhatsApp y canal lateral de recarga

{{#include ../banners/hacktricks-training.md}}

WhatsApp almacena una clave de identidad, una prekey firmada y una reserva de prekeys de un solo uso para cada dispositivo. Obtener el bundle de un dispositivo consume una prekey de un solo uso almacenada en el servidor, aunque quien la solicite no envíe ningún mensaje. Esto proporciona a un atacante con una cuenta de WhatsApp y el número de teléfono de la víctima una sonda **del lado del servidor**, distinta del [timing de los recibos de entrega del cliente](side-channel-attacks-on-messaging-protocols.md). La ausencia de una prekey de un solo uso también debilita el secreto hacia adelante de los *mensajes iniciales* de una sesión recién establecida; no expone el texto sin cifrar por sí sola.<sup>[[1]](#references)[[2]](#references)</sup>

## Inspeccionar los bundles de dispositivos de una víctima

El artefacto [Prekey Pogo](https://github.com/sbaresearch/prekey-pogo) se empareja como una sesión complementaria de WhatsApp y admite consultas **manuales** de dispositivos y prekeys. Emparéjalo con una cuenta de prueba y, después, usa sus comandos interactivos `target`, `devices`, `prekey` (dispositivo principal) y `combine` (todos los dispositivos). El artefacto publicado omite deliberadamente las funciones automatizadas de agotamiento y saturación del servidor.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

Para cada respuesta, registra el JID del dispositivo, la marca de tiempo del bundle `t`, el ID de la signed-prekey `skey.id` y si está presente `key.id` de un solo uso. El ID de dispositivo `0` corresponde al teléfono; los IDs distintos de cero, a los dispositivos complementarios. En las implementaciones probadas en el artículo, el ID inicial de la signed-prekey también permite distinguir algunos clientes: Android empieza en `0`, iOS y macOS usan un valor aleatorio, y WhatsApp Web y Windows Desktop empiezan en `1`. Trátalo como una huella de implementación, no como una regla inmutable del protocolo.<sup>[[1]](#references)</sup>

## Convierte las recargas en un oracle del estado en línea

Primero, calibra con un dispositivo que controles: solicita su bundle repetidamente hasta que el servidor deje de devolver una `key` de un solo uso y anota la última marca de tiempo y los IDs de las keys. Para un dispositivo objetivo, repite el agotamiento y vuelve a consultar después de un intervalo controlado: una nueva key de un solo uso y una marca de tiempo del bundle más reciente indican que el dispositivo subió un nuevo lote. En las pruebas de WhatsApp descritas, el servidor solicitó una recarga cuando quedaban menos de 11 keys y los clientes subieron 812 keys nuevas. Aplica el procedimiento a cada JID de dispositivo para distinguir un teléfono de los dispositivos complementarios. Una recarga tardía solo **sugiere** que un dispositivo está desconectado: la planificación en segundo plano, la pérdida de red y la latencia de recarga específica de cada cliente pueden producir la misma observación. A diferencia de un RTT de recibo, esta prueba no requiere un ciphertext entregado ni un acuse de recibo del lado de la víctima.<sup>[[1]](#references)[[2]](#references)</sup>

Cada consulta consume una key de un solo uso, así que un oracle sostenido requiere un cliente personalizado capaz de recuperar prekeys repetidamente; el artefacto público solo demuestra consultas manuales. Mantener agotada la reserva puede hacer que otros usuarios establezcan sesiones nuevas sin una prekey de un solo uso. Eso reduce la forward secrecy de los mensajes iniciales hasta que se produzca un nuevo paso de ratchet, pero explotar el ciphertext grabado también requiere acceder al ciphertext E2EE y comprometer posteriormente las claves privadas pertinentes de largo y medio plazo. Las sesiones ya establecidas no se degradan automáticamente.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: Investigating Security and Privacy Issues in WhatsApp's Handshake Mechanism](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [3] [Prekey Pogo artifacts](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}

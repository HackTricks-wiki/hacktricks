# Integridad del firmware

{{#include ../../banners/hacktricks-training.md}}

El **firmware personalizado y/o los binarios compilados se pueden cargar para explotar fallos de integridad o de verificación de firmas**. Se pueden seguir los siguientes pasos para compilar un bind shell de backdoor:

1. El firmware se puede extraer mediante firmware-mod-kit (FMK).
2. Se deben identificar la arquitectura y el endianness del firmware objetivo.
3. Se puede crear un cross compiler mediante Buildroot u otros métodos adecuados para el entorno.
4. El backdoor se puede compilar mediante el cross compiler.
5. El backdoor se puede copiar al directorio /usr/bin del firmware extraído.
6. El binario QEMU apropiado se puede copiar al rootfs del firmware extraído.
7. El backdoor se puede emular mediante chroot y QEMU.
8. Se puede acceder al backdoor mediante netcat.
9. El binario QEMU se debe eliminar del rootfs del firmware extraído.
10. El firmware modificado se puede volver a empaquetar mediante FMK.
11. El firmware con backdoor se puede probar emulándolo con firmware analysis toolkit (FAT) y conectándose a la IP y al puerto del backdoor objetivo mediante netcat.

Si ya se ha obtenido un root shell mediante análisis dinámico, manipulación del bootloader o pruebas de seguridad del hardware, se pueden ejecutar binarios maliciosos precompilados, como implants o reverse shells. Se pueden utilizar herramientas automatizadas de payloads/implants, como el framework Metasploit y 'msfvenom', siguiendo estos pasos:

1. Se deben identificar la arquitectura y el endianness del firmware objetivo.
2. Msfvenom se puede utilizar para especificar el payload objetivo, la dirección IP del host del atacante, el número de puerto de escucha, el tipo de archivo, la arquitectura, la plataforma y el archivo de salida.
3. El payload se puede transferir al dispositivo comprometido y se debe comprobar que tenga permisos de ejecución.
4. Metasploit se puede preparar para gestionar las solicitudes entrantes iniciando msfconsole y configurando los ajustes de acuerdo con el payload.
5. El reverse shell de meterpreter se puede ejecutar en el dispositivo comprometido.

## Puentes de transporte no autenticados hacia protocolos de actualización privilegiados

Un error común de diseño en sistemas embebidos consiste en exponer el **mismo protocolo de comandos interno a través de varios transportes**, pero aplicar autenticación únicamente en uno de ellos. Por ejemplo, USB puede requerir challenge-response, mientras que BLE simplemente reenvía **GATT writes** no autenticados al mismo handler privilegiado de actualización del firmware.<sup>[[1]](#references)</sup>

Flujo de trabajo ofensivo típico:

1. Enumerar la base de datos GATT de BLE e identificar las características escribibles utilizadas por la aplicación móvil oficial.
2. Capturar el tráfico de la aplicación y buscar **magic bytes / opcodes** que coincidan con el protocolo cableado.
3. Reproducir comandos privilegiados mediante BLE **sin pairing** y verificar si las operaciones sensibles siguen funcionando.
4. Si se puede acceder a opcodes de actualización del firmware, escritura de configuración, debug o pruebas de fábrica, tratar BLE como un **puerto de administración accesible por radio**.

Comprobaciones rápidas:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Aspectos que verificar durante el reversing:

- ¿BLE requiere **pairing/bonding** o solo una conexión normal?
- ¿Todos los transportes se enrutan a la misma tabla interna de dispatch?
- ¿Los opcodes privilegiados se filtran de forma diferente en USB / BLE / UART / Wi-Fi?
- ¿La app móvil puede activar remotamente handlers de actualización de firmware, recovery o diagnóstico?

## Los contenedores de firmware protegidos únicamente con checksum siguen estando bajo el control del atacante

Un contenedor de firmware protegido únicamente mediante un **checksum no basado en clave** (CRC32, SHA-256, MD5, etc.) proporciona detección de corrupción, **no autenticidad**. Si el atacante puede alcanzar la rutina de actualización, puede modificar la imagen, recalcular el checksum y flashear código arbitrario.<sup>[[1]](#references)</sup>

Señales de alerta durante el RE:

- El código de actualización solo valida un blob de checksum final, como `CHK2`, `CRC` o `SHA256`.
- No existe verificación de firmas ni una raíz de confianza de secure boot.
- No se utiliza MAC / HMAC vinculado al dispositivo ni authenticated encryption.
- El recovery mode acepta el mismo formato de imagen no autenticado.

Flujo práctico de validación:

1. Extrae el contenedor de firmware e identifica el bootloader, el firmware principal y los metadatos de integridad.
2. Modifica una cadena o banner inofensivo en la imagen.
3. Recalcula el checksum exactamente como espera el updater.
4. Vuelve a flashear la imagen mediante la ruta de actualización normal.
5. Confirma el cambio durante el arranque para demostrar el reemplazo arbitrario del firmware.

Si esto funciona a través de un transporte accesible remotamente, como BLE/Wi-Fi, el bug es, en la práctica, un **reemplazo de firmware OTA no autenticado**.

## Convertir un periférico USB de confianza en BadUSB mediante reflashing del firmware

Cuando el dispositivo objetivo ya es de confianza para el host mediante USB, el firmware malicioso quizá no necesite implementar un stack USB completamente nuevo. A menudo, un pivot mucho más sencillo consiste en **reutilizar el soporte HID existente**.<sup>[[1]](#references)</sup>

Patrón útil:

1. Comprueba si el dispositivo ya se enumera como una interfaz **HID Consumer Control** / multimedia / vendor HID.
2. Localiza el **descriptor de reportes HID** existente en el firmware.
3. Añade o sustituye entradas del descriptor para que el dispositivo también anuncie capacidad de **teclado**.
4. Reutiliza las rutinas de firmware existentes que ya envían reportes HID en lugar de escribir una implementación de transporte nueva.
5. Inyecta reportes de pulsación + liberación de teclas para escribir comandos en el host.

Esto convierte el compromiso del firmware en un **compromiso del host**, porque el PC confiará en el periférico reflasheado como un teclado legítimo.

### Checklist mínimo de evaluación

- ¿`dmesg`, Device Manager o los descriptores USB muestran una interfaz HID existente?
- ¿Hay espacio libre cerca del descriptor de reportes o una tabla de descriptores relocatable?
- ¿Se pueden reutilizar las rutinas existentes de envío de controles multimedia para los reportes de teclado?
- ¿El host acepta automáticamente la nueva interfaz de teclado después del reflashing?

## Ejecución fiable de payloads dentro del firmware de un RTOS

En lugar de insertar trampolines frágiles en rutas de código aleatorias, busca **tareas existentes del RTOS** que no se utilicen o tengan poco impacto durante el funcionamiento normal.<sup>[[1]](#references)</sup>

Por qué resulta útil:

- El scheduler inicia el payload de forma natural durante el arranque.
- Evitas corromper el flujo de control crítico.
- Los payloads diferidos tienen menos probabilidades de activar resets del watchdog que cuando se ejecutan dentro de un handler de USB/red sensible a la latencia.

Los objetivos adecuados son tareas de diagnóstico, factory-test, telemetría o servicios de coprocesador que parezcan inactivas durante el uso normal.

## Iteración rápida de exploits: reutilizar handlers de protocolo benignos

Una vez que es posible parchear el firmware, una forma compacta de acelerar el RE consiste en sobrescribir un handler de comandos inofensivo (por ejemplo, un **opcode de echo/debug**) con primitivas personalizadas de **lectura / escritura / ejecución de memoria**. Esto evita reflashear completamente el dispositivo para cada experimento y resulta especialmente útil cuando el dispositivo admite el handler modificado a través de un transporte cableado rápido.<sup>[[1]](#references)</sup>

Úsalo para:

- Verificar mapas de memoria scatter-loaded
- Inspeccionar en vivo el estado del heap/task
- Probar payloads pequeños antes de grabarlos en flash
- Recuperar punteros a funciones, cadenas y tablas de descriptores de forma segura

## Referencias

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}

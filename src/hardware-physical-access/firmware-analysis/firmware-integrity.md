# Integridad del firmware

{{#include ../../banners/hacktricks-training.md}}

Cuando una evaluación autorizada detecta una verificación débil o inexistente de la firma del firmware, una imagen de firmware modificada puede demostrar el impacto sobre la integridad. El siguiente flujo de trabajo de laboratorio añade un bind shell mientras conserva los pasos originales de extracción, emulación y repaquetado.<sup>[[2]](#references)[[3]](#references)</sup>

1. El firmware se puede extraer usando firmware-mod-kit (FMK).
2. Se deben identificar la arquitectura y el endianness del firmware objetivo.
3. Se puede compilar un cross compiler usando Buildroot u otros métodos adecuados para el entorno.
4. El backdoor se puede compilar usando el cross compiler.
5. El backdoor se puede copiar al directorio /usr/bin del firmware extraído.
6. El binario QEMU apropiado se puede copiar al rootfs del firmware extraído.
7. El backdoor se puede emular usando chroot y QEMU.
8. Se puede acceder al backdoor mediante netcat.
9. Se debe eliminar el binario QEMU del rootfs del firmware extraído.
10. El firmware modificado se puede repaquetar usando FMK.
11. El firmware con backdoor se puede probar emulándolo con firmware analysis toolkit (FAT) y conectándose a la IP y el puerto del backdoor objetivo mediante netcat.

Si ya se ha obtenido un root shell mediante análisis dinámico, manipulación del bootloader o pruebas de seguridad del hardware, se pueden ejecutar binarios de prueba precompilados, como implants o reverse shells. `msfvenom` de Metasploit puede generar un payload específico para la arquitectura para este flujo de validación:<sup>[[4]](#references)</sup>

1. Se deben identificar la arquitectura y el endianness del firmware objetivo.
2. Msfvenom se puede usar para especificar el payload objetivo, la IP del host del atacante, el número de puerto de escucha, el filetype, la arquitectura, la plataforma y el archivo de salida.
3. El payload se puede transferir al dispositivo comprometido y se debe comprobar que tenga permisos de ejecución.
4. Metasploit se puede preparar para gestionar las solicitudes entrantes iniciando msfconsole y configurando los ajustes de acuerdo con el payload.
5. El reverse shell de meterpreter se puede ejecutar en el dispositivo comprometido.

## Puentes de transporte no autenticados hacia protocolos de actualización privilegiados

Un error común de diseño en dispositivos embebidos consiste en exponer el **mismo protocolo de comandos interno a través de varios transportes**, pero aplicar autenticación únicamente en uno de ellos. Por ejemplo, USB puede requerir challenge-response, mientras que BLE simplemente reenvía **GATT writes** no autenticados al mismo handler privilegiado de actualización del firmware.<sup>[[1]](#references)</sup>

Flujo de trabajo ofensivo habitual:

1. Enumerar la base de datos GATT de BLE e identificar las characteristics modificables utilizadas por la aplicación móvil oficial.
2. Capturar el tráfico de la aplicación y buscar **magic bytes / opcodes** que coincidan con el protocolo cableado.
3. Repetir comandos privilegiados mediante BLE **sin pairing** y verificar si las operaciones sensibles siguen funcionando.
4. Si los opcodes de actualización del firmware, escritura de configuración, debug o pruebas de fábrica son accesibles, tratar BLE como un **puerto de administración accesible por radio**.

Comprobaciones rápidas:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Cosas que verificar durante el reversing:

- ¿BLE requiere **pairing/bonding** o solo una conexión simple?
- ¿Todos los transportes se enrutan a la misma tabla interna de dispatcher?
- ¿Los opcodes privilegiados se filtran de forma diferente en USB / BLE / UART / Wi-Fi?
- ¿La aplicación móvil puede activar remotamente handlers de actualización de firmware, recuperación o diagnóstico?

## Los contenedores de firmware protegidos únicamente por checksum siguen estando bajo el control del atacante

Un contenedor de firmware protegido únicamente por un **checksum sin clave** (CRC32, SHA-256, MD5, etc.) proporciona detección de corrupción, **no autenticidad**. Si el atacante puede acceder a la rutina de actualización, puede modificar la imagen, recalcular el checksum y flashear código arbitrario.<sup>[[1]](#references)</sup>

Señales de alerta durante RE:

- El código de actualización solo valida un blob de checksum final como `CHK2`, `CRC` o `SHA256`.
- No hay verificación de firma ni root of trust de secure-boot.
- No se utiliza MAC / HMAC vinculada al dispositivo ni cifrado autenticado.
- El modo de recuperación acepta el mismo formato de imagen no autenticado.

Flujo práctico de validación:

1. Extrae el contenedor de firmware e identifica el bootloader, el firmware principal y los metadatos de integridad.
2. Modifica una cadena o banner inofensivo en la imagen.
3. Recalcula el checksum exactamente como espera el actualizador.
4. Reflashea la imagen mediante la ruta de actualización normal.
5. Confirma el cambio durante el arranque para demostrar el reemplazo arbitrario del firmware.

Si esto funciona a través de un transporte accesible remotamente, como BLE/Wi-Fi, el fallo es, en la práctica, un **reemplazo no autenticado de firmware OTA**.

## Convertir un periférico USB confiable en BadUSB mediante reflasheo del firmware

Cuando el dispositivo objetivo ya es confiable para el host mediante USB, el firmware malicioso quizá no necesite implementar un stack USB nuevo completo. A menudo, un pivot mucho más sencillo consiste en **reutilizar el soporte HID existente**.<sup>[[1]](#references)</sup>

Patrón útil:

1. Comprueba si el dispositivo ya se enumera como una interfaz **HID Consumer Control** / multimedia / HID de vendor.
2. Localiza el **descriptor de reportes HID** existente en el firmware.
3. Añade o reemplaza entradas del descriptor para que el dispositivo también anuncie capacidad de **teclado**.
4. Reutiliza las rutinas de firmware existentes que ya envían reportes HID, en lugar de escribir una implementación de transporte nueva.
5. Inyecta reportes de pulsación + liberación de teclas para escribir comandos en el host.

Esto convierte el compromiso del firmware en un **compromiso del host**, porque el PC confiará en el periférico reflasheado como si fuera un teclado legítimo.

### Lista de comprobación mínima de evaluación

- ¿`dmesg`, el Device Manager o los descriptores USB muestran una interfaz HID existente?
- ¿Hay espacio libre cerca del descriptor de reportes o una tabla de descriptores relocalizable?
- ¿Se pueden reutilizar las rutinas existentes de envío de controles multimedia para los reportes de teclado?
- ¿El host acepta automáticamente la nueva interfaz de teclado después del reflasheo?

## Ejecución fiable de payloads dentro del firmware de un RTOS

En lugar de insertar trampolines frágiles en rutas de código aleatorias, busca **tareas existentes del RTOS** que no se utilicen o que tengan poco impacto durante el funcionamiento normal.<sup>[[1]](#references)</sup>

Por qué resulta útil:

- El scheduler inicia tu payload de forma natural durante el arranque.
- Evitas corromper el flujo de control crítico.
- Es menos probable que los payloads retardados provoquen reinicios del watchdog que cuando se ejecutan dentro de un handler USB/de red sensible a la latencia.

Los objetivos adecuados son tareas de diagnóstico, pruebas de fábrica, telemetría o servicios de coprocesador que parezcan inactivas durante el uso normal.

## Iteración rápida de exploits: reutilizar handlers benignos de protocolo

Una vez que sea posible parchear el firmware, una forma compacta de acelerar el RE consiste en sobrescribir un handler de comandos inofensivo (por ejemplo, un **opcode de echo/debug**) con primitivas personalizadas de **lectura / escritura / ejecución de memoria**. Esto evita reflashear por completo el dispositivo en cada experimento y resulta especialmente útil cuando el dispositivo admite el handler modificado a través de un transporte cableado rápido.<sup>[[1]](#references)</sup>

Úsalo para:

- Verificar mapas de memoria cargados de forma dispersa
- Inspeccionar en vivo el estado del heap/task
- Probar payloads pequeños antes de grabarlos en flash
- Recuperar de forma segura punteros a funciones, cadenas y tablas de descriptores

## References

- [1] [Pwnd Blaster: Hackear tu PC usando tu altavoz sin tocarlo](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Cómo usar `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}

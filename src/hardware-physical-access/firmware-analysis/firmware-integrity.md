# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

El **firmware personalizado y/o los binarios compilados pueden ser subidos para explotar fallos de integridad o de verificación de firmas**. Los siguientes pasos pueden seguirse para la compilación de un backdoor bind shell:

1. El firmware puede extraerse usando firmware-mod-kit (FMK).
2. Se debe identificar la arquitectura y el endianness del firmware objetivo.
3. Se puede construir un cross compiler usando Buildroot u otros métodos adecuados para el entorno.
4. El backdoor puede compilarse usando el cross compiler.
5. El backdoor puede copiarse al directorio /usr/bin del firmware extraído.
6. El binario QEMU adecuado puede copiarse al rootfs del firmware extraído.
7. El backdoor puede emularse usando chroot y QEMU.
8. Se puede acceder al backdoor mediante netcat.
9. El binario QEMU debe eliminarse del rootfs del firmware extraído.
10. El firmware modificado puede volver a empaquetarse usando FMK.
11. El firmware con backdoor puede probarse emulándolo con firmware analysis toolkit (FAT) y conectándose a la IP y puerto del backdoor objetivo usando netcat.

Si ya se ha obtenido una root shell mediante dynamic analysis, manipulación del bootloader o hardware security testing, se pueden ejecutar binarios maliciosos precompilados como implants o reverse shells. Se pueden aprovechar herramientas automatizadas de payload/implant como el framework Metasploit y 'msfvenom' usando los siguientes pasos:

1. Se debe identificar la arquitectura y el endianness del firmware objetivo.
2. Se puede usar Msfvenom para especificar el payload objetivo, la IP del host atacante, el número de puerto de escucha, el tipo de archivo, la arquitectura, la plataforma y el archivo de salida.
3. El payload puede transferirse al dispositivo comprometido y asegurarse de que tenga permisos de ejecución.
4. Metasploit puede prepararse para manejar las solicitudes entrantes iniciando msfconsole y configurando los ajustes de acuerdo con el payload.
5. El meterpreter reverse shell puede ejecutarse en el dispositivo comprometido.

## Unauthenticated transport bridges to privileged update protocols

Un error común de diseño embebido es exponer el **mismo protocolo de comandos interno sobre varios transportes** pero aplicar autenticación solo en uno de ellos. Por ejemplo, USB puede requerir challenge-response mientras BLE simplemente reenvía **GATT writes** no autenticados al mismo manejador privilegiado de actualización de firmware.

Flujo ofensivo típico:

1. Enumerar la base de datos GATT de BLE e identificar las características escribibles usadas por la app móvil oficial.
2. Sniff app traffic y buscar **magic bytes / opcodes** que coincidan con el protocolo cableado.
3. Repetir comandos privilegiados sobre BLE **sin pairing** y verificar si las operaciones sensibles siguen funcionando.
4. Si los opcodes de upgrade de firmware, escritura de configuración, debug o factory-test son accesibles, tratar BLE como un **radio-reachable admin port**.

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Cosas que verificar al hacer reversing:

- ¿BLE requiere **pairing/bonding** o solo una conexión simple?
- ¿Todos los transports se enrutan a la misma tabla interna de dispatcher?
- ¿Los privileged opcodes se filtran de forma distinta en USB / BLE / UART / Wi-Fi?
- ¿La mobile app puede activar firmware update, recovery o diagnostic handlers de forma remota?

## Los contenedores de firmware con solo checksum siguen siendo firmware controlado por el atacante

Un contenedor de firmware protegido solo por un **unkeyed checksum** (CRC32, SHA-256, MD5, etc.) proporciona detección de corrupción, **no autenticidad**. Si el atacante puede الوصول a la rutina de actualización, puede parchear la imagen, recalcular el checksum y flashear código arbitrario.

Señales de alerta durante RE:

- El código de actualización valida solo un blob de checksum al final, como `CHK2`, `CRC` o `SHA256`.
- No hay verificación de firma ni root of trust de secure-boot.
- No se usa MAC / HMAC ligado al dispositivo ni authenticated encryption.
- El modo recovery acepta el mismo formato de imagen no autenticada.

Flujo práctico de validación:

1. Extrae el contenedor de firmware e identifica bootloader, main firmware y metadata de integridad.
2. Modifica una cadena inocua o un banner en la imagen.
3. Recalcula el checksum exactamente como espera el updater.
4. Vuelve a flashear la imagen por la ruta normal de actualización.
5. Confirma el cambio al arrancar para demostrar reemplazo arbitrario de firmware.

Si esto funciona sobre un transport accesible remotamente como BLE/Wi-Fi, el bug es efectivamente **una sustitución de firmware OTA no autenticada**.

## Convertir un periférico USB confiable en BadUSB mediante reflasheo de firmware

Cuando el dispositivo objetivo ya es confiable para el host por USB, el firmware malicioso puede no necesitar implementar un stack USB nuevo completo. Un pivot mucho más fácil suele ser **reutilizar el soporte HID existente**.

Patrón útil:

1. Comprueba si el dispositivo ya se enumera como una interfaz **HID Consumer Control** / media / vendor HID.
2. Localiza el **HID report descriptor** existente en el firmware.
3. Añade o reemplaza entradas del descriptor para que el dispositivo también anuncie capacidad de **keyboard**.
4. Reutiliza rutinas de firmware existentes que ya envían HID reports en lugar de escribir una nueva implementación de transport.
5. Inyecta reports de key press + key release para escribir comandos en el host.

Esto convierte el compromiso del firmware en **compromiso del host** porque el PC confiará en el periférico reflasheado como un keyboard legítimo.

### Lista mínima de verificación

- ¿`dmesg`, Device Manager o los USB descriptors muestran una interfaz HID existente?
- ¿Hay espacio libre cerca del report descriptor o una tabla de descriptors relocatable?
- ¿Se pueden reutilizar rutinas existentes de media-control para reports de keyboard?
- ¿El host acepta automáticamente la nueva interfaz de keyboard después de reflashear?

## Ejecución fiable de payload dentro de firmware RTOS

En lugar de insertar trampolines frágiles en rutas de código aleatorias, busca **tareas RTOS existentes** que estén sin usar o tengan bajo impacto en operación normal.

Por qué esto es útil:

- El scheduler inicia tu payload de forma natural durante el boot.
- Evitas corromper el flujo de control crítico.
- Los payloads retrasados tienen menos probabilidades de disparar watchdog resets que cuando se ejecutan dentro de un handler USB/network sensible a la latencia.

Buenos objetivos son tareas de diagnóstico, factory-test, telemetry o servicio de coprocesador que parezcan inactivas en uso normal.

## Iteración rápida de exploits: reutiliza benign protocol handlers

Una vez que es posible parchear firmware, una forma compacta de acelerar RE es sobrescribir un handler de comando inocuo (por ejemplo un opcode de **echo/debug**) con primitivas personalizadas de **memory read / write / execute**. Esto evita reflashear por completo en cada experimento y es especialmente útil cuando el dispositivo soporta el handler modificado sobre un transport cableado rápido.

Úsalo para:

- Verificar scatter-loaded memory maps
- Inspeccionar heap/task state en vivo
- Probar payloads pequeños antes de grabarlos en flash
- Recuperar function pointers, strings y descriptor tables de forma segura

## Referencias

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}

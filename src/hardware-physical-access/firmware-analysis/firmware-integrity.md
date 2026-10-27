# Integridad del firmware

{{#include ../../banners/hacktricks-training.md}}

Cuando una evaluación autorizada detecta una verificación débil o inexistente de las firmas del firmware, una imagen de firmware modificada puede demostrar el impacto sobre la integridad. El siguiente flujo de trabajo de laboratorio añade un bind shell y conserva los pasos originales de extracción, emulación y reempaquetado.<sup>[[2]](#references)[[3]](#references)</sup>

1. El firmware se puede extraer con firmware-mod-kit (FMK).
2. Se deben identificar la arquitectura y el endianness del firmware objetivo.
3. Se puede crear un cross compiler con Buildroot u otros métodos adecuados para el entorno.
4. Se puede compilar el backdoor con el cross compiler.
5. Se puede copiar el backdoor al directorio /usr/bin del firmware extraído.
6. Se puede copiar el binario QEMU adecuado a la rootfs del firmware extraído.
7. Se puede emular el backdoor con chroot y QEMU.
8. Se puede acceder al backdoor mediante netcat.
9. Se debe eliminar el binario QEMU de la rootfs del firmware extraído.
10. Se puede reempaquetar el firmware modificado con FMK.
11. Se puede probar el firmware con backdoor emulándolo con firmware analysis toolkit (FAT) y conectándose a la IP y al puerto del backdoor objetivo mediante netcat.

Si ya se obtuvo un shell de root mediante análisis dinámico, manipulación del bootloader o pruebas de seguridad de hardware, se pueden ejecutar binarios de prueba precompilados, como implants o reverse shells. `msfvenom` de Metasploit puede generar un payload específico para la arquitectura para este flujo de validación:<sup>[[4]](#references)</sup>

1. Se deben identificar la arquitectura y el endianness del firmware objetivo.
2. Se puede usar Msfvenom para especificar el payload objetivo, la IP del host atacante, el número del puerto de escucha, el tipo de archivo, la arquitectura, la plataforma y el archivo de salida.
3. Se puede transferir el payload al dispositivo comprometido y comprobar que tenga permisos de ejecución.
4. Se puede preparar Metasploit para gestionar las solicitudes entrantes iniciando msfconsole y configurando los ajustes según el payload.
5. Se puede ejecutar el reverse shell de meterpreter en el dispositivo comprometido.

## Puentes de transporte no autenticados hacia protocolos de actualización privilegiados

Un error común en el diseño de dispositivos integrados es exponer el **mismo protocolo de comandos interno a través de varios transportes**, pero aplicar la autenticación en solo uno de ellos. Por ejemplo, USB puede requerir un challenge-response mientras que BLE simplemente reenvía **escrituras GATT** no autenticadas al mismo controlador privilegiado de actualización de firmware.<sup>[[1]](#references)</sup>

Flujo de trabajo ofensivo típico:

1. Enumerar la base de datos GATT de BLE e identificar las características escribibles que usa la aplicación móvil oficial.
2. Capturar el tráfico de la aplicación y buscar **bytes mágicos / opcodes** que coincidan con el protocolo por cable.
3. Reproducir comandos privilegiados por BLE **sin emparejamiento** y comprobar si las operaciones sensibles siguen funcionando.
4. Si se puede acceder a los opcodes de actualización del firmware, escritura de configuración, depuración o pruebas de fábrica, tratar BLE como un **puerto de administración accesible por radio**.

Comprobaciones rápidas:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

Cosas que verificar durante el análisis inverso:

- ¿BLE requiere **emparejamiento/vinculación** o solo una conexión normal?
- ¿Todos los transportes se enrutan a la misma tabla interna de despacho?
- ¿Los códigos de operación privilegiados se filtran de forma distinta en USB / BLE / UART / Wi-Fi?
- ¿La aplicación móvil puede activar handlers de actualización de firmware, recuperación o diagnóstico de forma remota?

## Los contenedores de firmware protegidos solo por checksum siguen estando bajo el control del atacante

Un contenedor de firmware protegido únicamente por un **checksum sin clave** (CRC32, SHA-256, MD5, etc.) detecta daños, pero **no proporciona autenticidad**. Si el atacante puede acceder a la rutina de actualización, puede modificar la imagen, volver a calcular el checksum e instalar código arbitrario.<sup>[[1]](#references)</sup>

Señales de alerta durante el análisis inverso:

- El código de actualización solo valida un bloque de checksum final, como `CHK2`, `CRC` o `SHA256`.
- No hay verificación de firmas ni una raíz de confianza de secure boot.
- No se usa MAC / HMAC vinculada al dispositivo ni cifrado autenticado.
- El modo de recuperación acepta el mismo formato de imagen no autenticado.

Flujo práctico de validación:

1. Extrae el contenedor de firmware e identifica el bootloader, el firmware principal y los metadatos de integridad.
2. Modifica una cadena o un banner inofensivo de la imagen.
3. Vuelve a calcular el checksum exactamente como lo espera el actualizador.
4. Vuelve a instalar la imagen mediante el proceso de actualización normal.
5. Confirma el cambio durante el arranque para demostrar que es posible reemplazar el firmware por uno arbitrario.

Si esto funciona a través de un transporte accesible de forma remota, como BLE/Wi-Fi, el fallo equivale en la práctica a un **reemplazo de firmware OTA no autenticado**.

## Estado de actualización fragmentado y metadatos de integridad modificables

Un actualizador puede verificar un encabezado de firmware firmado durante la instalación y, aun así, arrancar imágenes usando solo un hash de integridad almacenado. En el Cypherock X1, el Bootloader invocaba tareas independientes de Firewall para verificar el encabezado y guardar la versión/tamaño en RAM, almacenar la firma del firmware en RAM, verificar la imagen escrita y, por último, guardar el hash de la imagen en los datos persistentes del Primary Bootloader. La firma no se guardaba de forma persistente. Estas tareas podían invocarse por separado, en vez de imponer una única transacción de actualización autenticada.<sup>[[5]](#references)</sup>

Con ejecución de código en el MCU y acceso de escritura a Flash, el ataque descrito reescribía la imagen de la aplicación, cambiaba los valores de versión/tamaño en la RAM del Bootloader compartida con Firewall y, después, llamaba a la tarea final de metadatos para guardar el hash de la imagen maliciosa y restaurar el estado de arranque normal. La comprobación de integridad habitual durante el arranque aceptaba ese hash sin volver a verificar una firma. Al analizar un actualizador similar, rastrea **qué componente puede invocar cada tarea**, dónde se almacenan los valores verificados y si la decisión de arranque autentica la *misma imagen* cuyo hash se guarda. Este caso es más específico que un formato de imagen protegido solo por checksum: había verificación de firmas, pero la transición de estado no estaba vinculada a ella.<sup>[[5]](#references)</sup>

## Firmas del secure element sobre mediciones de firmware no confiables

Un secure element no certifica el código en ejecución por el mero hecho de firmar un hash que ese código le proporciona. En el mismo wallet, el secure element firmaba el número de serie del dispositivo y, después, el XOR de un nonce de la nube y un hash de firmware proporcionado a través del MCU. El firmware comprometido podía proporcionar el hash esperado para que se firmara mientras ejecutaba bytes distintos. El cliente complementario también enviaba la versión del firmware a la nube, por lo que la comparación del hash esperado por parte del verificador seguía dependiendo de una medición originada en el MCU, y no de una lectura independiente de Flash.<sup>[[5]](#references)</sup>

El resultado del lado del dispositivo constituía un límite de confianza separado: la nube comprobaba el dispositivo, pero el dispositivo no autenticaba el veredicto de la nube. Un cliente modificado podía informar de un éxito local a un dispositivo manipulado. Comprueba por separado la procedencia de la medición y la autenticación de la respuesta; una firma válida del secure element y una pantalla de éxito no demuestran, por sí solas, que la aplicación instalada sea auténtica.<sup>[[5]](#references)</sup>

Para consultar la divulgación del código protegido que permitió analizar este actualizador, ve [Adquisición de firmware mediante una tarea de copia de Firewall](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Convertir un periférico USB confiable en BadUSB mediante la regrabación del firmware

Cuando el host ya confía en el dispositivo de destino a través de USB, quizá el firmware malicioso no necesite implementar una pila USB completamente nueva. A menudo, una alternativa mucho más sencilla es **reutilizar la compatibilidad HID existente**.<sup>[[1]](#references)</sup>

Patrón útil:

1. Comprueba si el dispositivo ya se enumera como una interfaz **HID Consumer Control** / multimedia / HID del fabricante.
2. Localiza el **descriptor de informes HID** existente en el firmware.
3. Añade o reemplaza entradas del descriptor para que el dispositivo también anuncie capacidad de **teclado**.
4. Reutiliza las rutinas de firmware existentes que ya envían informes HID, en lugar de escribir una implementación de transporte nueva.
5. Inyecta informes de pulsación + liberación de teclas para escribir comandos en el host.

Esto convierte el compromiso del firmware en **compromiso del host**, porque el PC confiará en el periférico regrabado como si fuera un teclado legítimo.

### Lista de comprobación mínima para la evaluación

- ¿`dmesg`, el Administrador de dispositivos o los descriptores USB muestran una interfaz HID existente?
- ¿Hay espacio libre cerca del descriptor de informes o una tabla de descriptores reubicable?
- ¿Se pueden reutilizar las rutinas existentes de envío de controles multimedia para los informes de teclado?
- ¿El host acepta automáticamente la nueva interfaz de teclado después de regrabar el firmware?

## Ejecución fiable de payloads dentro del firmware RTOS

En lugar de insertar trampolines frágiles en rutas de código aleatorias, busca **tareas RTOS existentes** que no se usen o tengan poco impacto durante el funcionamiento normal.<sup>[[1]](#references)</sup>

Por qué resulta útil:

- El planificador inicia el payload de forma natural durante el arranque.
- Evitas corromper el flujo de control crítico.
- Es menos probable que los payloads con retardo provoquen reinicios del watchdog que si se ejecutan dentro de un handler de USB/red sensible a la latencia.

Entre los buenos objetivos están las tareas de diagnóstico, pruebas de fábrica, telemetría o servicios de coprocesador que parecen inactivas durante el uso normal.

## Iteración rápida de exploits: reutilizar handlers de protocolo inofensivos

Una vez que sea posible parchear el firmware, una forma compacta de acelerar el análisis inverso consiste en sobrescribir un handler de comandos inofensivo (por ejemplo, un **opcode de echo/debug**) con primitivas personalizadas de **lectura / escritura / ejecución de memoria**. Así se evita regrabar el firmware para cada experimento, y resulta especialmente útil si el dispositivo admite el handler modificado a través de un transporte cableado rápido.<sup>[[1]](#references)</sup>

Úsalo para:

- Verificar mapas de memoria cargados de forma dispersa
- Inspeccionar en vivo el estado del heap y las tareas
- Probar payloads pequeños antes de grabarlos en flash
- Recuperar de forma segura punteros a funciones, cadenas y tablas de descriptores

## References

- [1] [Pwnd Blaster: Hackear tu PC usando el altavoz sin tocarlo nunca](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [kit de modificación de firmware](https://github.com/rampageX/firmware-mod-kit)
- [3] [Kit de herramientas de análisis de firmware](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit: cómo usar `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [Cómo y por qué hackeamos el wallet de hardware Cypherock: la historia completa](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}

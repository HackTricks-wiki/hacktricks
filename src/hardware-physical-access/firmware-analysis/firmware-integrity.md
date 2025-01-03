{{#include ../../banners/hacktricks-training.md}}

## Integridad del Firmware

El **firmware personalizado y/o binarios compilados pueden ser subidos para explotar fallos de integridad o verificación de firma**. Se pueden seguir los siguientes pasos para la compilación de un shell de puerta trasera:

1. El firmware puede ser extraído usando firmware-mod-kit (FMK).
2. Se debe identificar la arquitectura del firmware objetivo y el endianness.
3. Se puede construir un compilador cruzado usando Buildroot u otros métodos adecuados para el entorno.
4. La puerta trasera puede ser construida usando el compilador cruzado.
5. La puerta trasera puede ser copiada al directorio /usr/bin del firmware extraído.
6. El binario QEMU apropiado puede ser copiado al rootfs del firmware extraído.
7. La puerta trasera puede ser emulada usando chroot y QEMU.
8. La puerta trasera puede ser accedida a través de netcat.
9. El binario QEMU debe ser eliminado del rootfs del firmware extraído.
10. El firmware modificado puede ser reempaquetado usando FMK.
11. El firmware con puerta trasera puede ser probado emulándolo con el kit de herramientas de análisis de firmware (FAT) y conectándose a la IP y puerto de la puerta trasera objetivo usando netcat.

Si ya se ha obtenido un shell root a través de análisis dinámico, manipulación del bootloader o pruebas de seguridad de hardware, se pueden ejecutar binarios maliciosos precompilados como implantes o shells reversos. Herramientas automatizadas de carga útil/implante como el marco Metasploit y 'msfvenom' pueden ser aprovechadas usando los siguientes pasos:

1. Se debe identificar la arquitectura del firmware objetivo y el endianness.
2. Msfvenom puede ser utilizado para especificar la carga útil objetivo, la IP del host atacante, el número de puerto de escucha, el tipo de archivo, la arquitectura, la plataforma y el archivo de salida.
3. La carga útil puede ser transferida al dispositivo comprometido y asegurarse de que tenga permisos de ejecución.
4. Metasploit puede ser preparado para manejar solicitudes entrantes iniciando msfconsole y configurando los ajustes de acuerdo con la carga útil.
5. El shell reverso meterpreter puede ser ejecutado en el dispositivo comprometido.

{{#include ../../banners/hacktricks-training.md}}

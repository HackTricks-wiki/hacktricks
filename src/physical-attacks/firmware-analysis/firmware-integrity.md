{{#include ../../banners/hacktricks-training.md}}

## Integridad del Firmware

El **firmware personalizado y/o binarios compilados pueden ser subidos para explotar fallos de verificación de integridad o firma**. Se pueden seguir los siguientes pasos para la compilación de un shell de puerta trasera:

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
11. El firmware con puerta trasera puede ser probado emulándolo con un toolkit de análisis de firmware (FAT) y conectándose a la IP y puerto de la puerta trasera objetivo usando netcat.

Si ya se ha obtenido un shell root a través de análisis dinámico, manipulación del bootloader o pruebas de seguridad de hardware, se pueden ejecutar binarios maliciosos precompilados como implantes o shells reversos. Herramientas automatizadas de carga útil/implante como el framework Metasploit y 'msfvenom' pueden ser aprovechadas usando los siguientes pasos:

1. Se debe identificar la arquitectura del firmware objetivo y el endianness.
2. Msfvenom puede ser utilizado para especificar la carga útil objetivo, la IP del host atacante, el número de puerto de escucha, el tipo de archivo, la arquitectura, la plataforma y el archivo de salida.
3. La carga útil puede ser transferida al dispositivo comprometido y asegurarse de que tenga permisos de ejecución.
4. Metasploit puede ser preparado para manejar solicitudes entrantes iniciando msfconsole y configurando los ajustes de acuerdo con la carga útil.
5. El shell reverso de meterpreter puede ser ejecutado en el dispositivo comprometido.
6. Las sesiones de meterpreter pueden ser monitoreadas a medida que se abren.
7. Se pueden realizar actividades post-explotación.

Si es posible, se pueden explotar vulnerabilidades dentro de los scripts de inicio para obtener acceso persistente a un dispositivo a través de reinicios. Estas vulnerabilidades surgen cuando los scripts de inicio hacen referencia, [enlazan simbólicamente](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), o dependen de código ubicado en ubicaciones montadas no confiables, como tarjetas SD y volúmenes flash utilizados para almacenar datos fuera de los sistemas de archivos raíz.

## Referencias

- Para más información, consulta [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}

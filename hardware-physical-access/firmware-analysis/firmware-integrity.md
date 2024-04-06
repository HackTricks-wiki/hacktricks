<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Integridad del Firmware

Los **firmwares personalizados y/o binarios compilados pueden ser cargados para explotar fallos de integridad o verificación de firmas**. Los siguientes pasos pueden seguirse para compilar un backdoor bind shell:

1. El firmware puede ser extraído usando firmware-mod-kit (FMK).
2. Debe identificarse la arquitectura y el endianness del firmware objetivo.
3. Se puede construir un compilador cruzado usando Buildroot u otros métodos adecuados para el entorno.
4. El backdoor puede ser construido usando el compilador cruzado.
5. El backdoor puede ser copiado al directorio /usr/bin del firmware extraído.
6. El binario QEMU apropiado puede ser copiado al rootfs del firmware extraído.
7. El backdoor puede ser emulado usando chroot y QEMU.
8. El backdoor puede ser accedido a través de netcat.
9. El binario QEMU debe ser eliminado del rootfs del firmware extraído.
10. El firmware modificado puede ser empaquetado de nuevo usando FMK.
11. El firmware con backdoor puede ser probado emulándolo con la herramienta de análisis de firmware (FAT) y conectándose a la IP y puerto del backdoor objetivo usando netcat.

Si ya se ha obtenido un shell de root a través de análisis dinámico, manipulación del cargador de arranque o pruebas de seguridad de hardware, se pueden ejecutar binarios maliciosos precompilados como implantes o reverse shells. Herramientas automatizadas de carga/implante como el framework Metasploit y 'msfvenom' pueden ser aprovechadas siguiendo los siguientes pasos:

1. Debe identificarse la arquitectura y el endianness del firmware objetivo.
2. Msfvenom puede ser utilizado para especificar el payload objetivo, la IP del host atacante, el número de puerto de escucha, el tipo de archivo, la arquitectura, la plataforma y el archivo de salida.
3. El payload puede ser transferido al dispositivo comprometido y asegurarse de que tenga permisos de ejecución.
4. Metasploit puede ser preparado para manejar las solicitudes entrantes iniciando msfconsole y configurando los ajustes según el payload.
5. El reverse shell de meterpreter puede ser ejecutado en el dispositivo comprometido.
6. Las sesiones de meterpreter pueden ser monitoreadas a medida que se abren.
7. Se pueden realizar actividades de post-explotación.

Si es posible, las vulnerabilidades dentro de los scripts de inicio pueden ser explotadas para obtener acceso persistente a un dispositivo a través de reinicios. Estas vulnerabilidades surgen cuando los scripts de inicio hacen referencia, [enlazan simbólicamente](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), o dependen de código ubicado en ubicaciones montadas no confiables como tarjetas SD y volúmenes flash utilizados para almacenar datos fuera de los sistemas de archivos raíz.

## Referencias
* Para más información consulta [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>

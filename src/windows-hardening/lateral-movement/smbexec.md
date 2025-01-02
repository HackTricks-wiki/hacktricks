# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtén la perspectiva de un hacker sobre tus aplicaciones web, red y nube**

**Encuentra e informa sobre vulnerabilidades críticas y explotables con un impacto real en el negocio.** Utiliza nuestras más de 20 herramientas personalizadas para mapear la superficie de ataque, encontrar problemas de seguridad que te permitan escalar privilegios y usar exploits automatizados para recopilar evidencia esencial, convirtiendo tu arduo trabajo en informes persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Cómo Funciona

**Smbexec** es una herramienta utilizada para la ejecución remota de comandos en sistemas Windows, similar a **Psexec**, pero evita colocar archivos maliciosos en el sistema objetivo.

### Puntos Clave sobre **SMBExec**

- Opera creando un servicio temporal (por ejemplo, "BTOBTO") en la máquina objetivo para ejecutar comandos a través de cmd.exe (%COMSPEC%), sin dejar caer ningún binario.
- A pesar de su enfoque sigiloso, genera registros de eventos para cada comando ejecutado, ofreciendo una forma de "shell" no interactiva.
- El comando para conectarse usando **Smbexec** se ve así:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Ejecutando Comandos Sin Binarios

- **Smbexec** permite la ejecución directa de comandos a través de binPaths de servicio, eliminando la necesidad de binarios físicos en el objetivo.
- Este método es útil para ejecutar comandos únicos en un objetivo Windows. Por ejemplo, emparejarlo con el módulo `web_delivery` de Metasploit permite la ejecución de una carga útil de Meterpreter inversa dirigida a PowerShell.
- Al crear un servicio remoto en la máquina del atacante con binPath configurado para ejecutar el comando proporcionado a través de cmd.exe, es posible ejecutar la carga útil con éxito, logrando la devolución de llamada y la ejecución de la carga útil con el listener de Metasploit, incluso si ocurren errores de respuesta del servicio.

### Ejemplo de Comandos

Crear e iniciar el servicio se puede lograr con los siguientes comandos:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Para más detalles, consulta [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Referencias

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtén la perspectiva de un hacker sobre tus aplicaciones web, red y nube**

**Encuentra e informa sobre vulnerabilidades críticas y explotables con un impacto real en el negocio.** Utiliza nuestras más de 20 herramientas personalizadas para mapear la superficie de ataque, encontrar problemas de seguridad que te permitan escalar privilegios y usar exploits automatizados para recopilar evidencia esencial, convirtiendo tu arduo trabajo en informes persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}

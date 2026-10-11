# Adquisición y montaje

{{#include ../../banners/hacktricks-training.md}}

## Adquisición

> Adquiere siempre en modo **de solo lectura** y **calcula el hash mientras copias**. Mantén el dispositivo original **protegido contra escritura** y trabaja únicamente con copias verificadas.

Registra la marca, el modelo, el número de serie y el tamaño del dispositivo de origen, la herramienta y su versión, las marcas de tiempo, el operador, el destino, los errores y los hashes de adquisición/verificación. Conserva una imagen de archivo y examina una copia de trabajo separada.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` añade hashing en tiempo real, verificación de salida, registro de errores y salida segmentada al flujo de trabajo de `dd`. `hof=` selecciona una salida verificada mediante hash; `hash=`, `hlog=`, `log=` y `bufsz=` son operandos independientes.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager es una herramienta gráfica de Linux, con soporte para múltiples subprocesos, para crear imágenes en formato raw/dd, EWF y AFF heredado. **AFF y AFF4 son formatos diferentes**; Guymager no anuncia compatibilidad con la salida AFF4. Activa SHA-256 y la verificación del destino en el cuadro de diálogo de adquisición; luego, inícialo con `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

La especificación AFF4 v1.0 define un contenedor forense con almacenamiento virtualizado, metadatos arbitrarios, compresión y hashing extensibles, y funcionamiento de alto rendimiento.<sup>[[1]](#references)</sup>

La implementación canónica en C/C++ usa `-i` para la fuente y `-o` para el volumen AFF4. Crea y conserva un hash externo del contenedor como referencia para la adquisición.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

La documentación actual de FTK Imager anuncia salida raw/DD, E01 y AFF con verificación de hash. No etiquetes su salida AFF como AFF4.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### Herramientas EWF (libewf)

Para la adquisición desatendida, el destino se indica con `-t`, los metadatos del caso con `-C/-D/-E/-e`, `-d sha256` añade SHA-256 y `-l` registra los errores de adquisición y los resúmenes criptográficos. Verifica el conjunto completo de segmentos antes del análisis.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Creación de imágenes de discos en la nube

Una instantánea del proveedor es una fuente de adquisición en un momento determinado, no una imagen forense coherente con la aplicación de forma automática. Una instantánea de EBS excluye los datos que aún están en la caché del sistema invitado; pausa las escrituras, detén la aplicación de forma ordenada, desmonta el volumen de datos o detén la instancia cuyo volumen raíz se está capturando cuando el plan de respuesta lo permita.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

No describas las snapshots de EBS como archivos que se pueden copiar simplemente a S3. Para reconstruir la imagen de bloques sin crear un volumen, enumera los bloques asignados con `ListSnapshotBlocks`, obtén cada bloque de 512 KiB con `GetSnapshotBlock`, valida el checksum devuelto y rellena con ceros los índices de bloques ausentes de la snapshot dispersa.<sup>[[14]](#references)</sup>

En Azure, crea la snapshot, emite un SAS de corta duración de **solo lectura**, descarga el VHD, revoca el acceso y calcula el hash del resultado. Crea una snapshot de cada disco por separado, a menos que el mecanismo de recopilación proporcione coherencia coordinada.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Montaje

### Trata las imágenes como entradas hostiles

Un sistema de archivos malicioso puede atacar los analizadores de particiones y sistemas de archivos del kernel del host. QEMU advierte explícitamente que no se conecte una imagen de guest no confiable al NBD del host para montarla, y libguestfs recomienda no montar nunca directamente un sistema de archivos de guest no confiable con loop o `kpartx`.<sup>[[2]](#references)[[16]](#references)</sup>

Para una imagen desconocida o controlada por un atacante, prefiere `guestmount`. Analiza y monta el guest dentro de un appliance pequeño y luego expone los archivos mediante FUSE. Fuerza el formato conocido en lugar de usar la detección automática y mantén el lado del appliance en modo de solo lectura.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

Si la inspección no permite inferir el sistema operativo, sustituye `-i` por un dispositivo explícito del sistema invitado, como `-m /dev/sda2`. Se pueden proporcionar volúmenes LUKS cifrados mediante selectores `--key`; evita introducir una clave directamente en el historial del shell.<sup>[[17]](#references)</sup>

### Elegir un montaje directo en el host

Usa un montaje directo en el host solo con imágenes de confianza o en una VM de análisis desechable:

1. Monta el **disco completo** cuando necesites su tabla de particiones original.
2. Monta una **imagen de una sola partición** cuando solo necesites un volumen.
3. Configura la conexión como de solo lectura y fuerza el formato de la imagen. Monta también el sistema de archivos en modo de solo lectura. `ro` por sí solo no impide la reproducción del journal de ext3/ext4, así que usa `ro,noload` con sistemas de archivos ext que estén marcados como sucios.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` es útil cuando el tamaño del sector no es de 512 bytes o los metadatos de la partición están dañados; `-b` especifica el tamaño real del sector del dispositivo. Continúa aquí el análisis de particiones y sistemas de archivos:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Imágenes raw (dd, extraídas de AFF4)

```bash
# Identify partitions without attaching the image
mmls -b 512 disk.img

# Attach a known raw image read-only and force its format
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 --read-only --format=raw disk.img
lsblk /dev/nbd0 -o NAME,SIZE,RO,TYPE,FSTYPE,LABEL,UUID

# Example ext4 partition: prevent journal replay
sudo mount -o ro,noload /dev/nbd0p2 /mnt/evidence
```

Desmonta cuando termines:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

Para qcow2, VMDK o VHD/VHDX, determina el formato a partir de una procedencia confiable o inspecciónalo dentro de la VM de análisis desechable; luego, reemplaza `--format=raw` por el formato explícito. Nunca confíes en la detección automática del formato en el host para entradas no confiables.<sup>[[2]](#references)</sup>

### EWF (E01/EWFX)

```bash
# Verify, then expose the embedded raw media stream
mkdir -p /mnt/ewf /mnt/evidence
ewfverify evidence.E01
ewfmount evidence.E01 /mnt/ewf

# ewf1 is raw media data; attach it explicitly as raw and read-only
sudo qemu-nbd --connect=/dev/nbd1 --read-only --format=raw /mnt/ewf/ewf1
# Example XFS partition
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```

Para los montajes específicos del sistema de archivos que no reproducen el journal, ext3/ext4 usan `noload`, mientras que XFS usa `norecovery` y requiere el modo de solo lectura.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` puede exponer una vista virtual raw, pero esa vista sigue conteniendo la tabla de particiones original. Pásala al mismo flujo de trabajo con `mmls`, `guestmount` aislado o NBD de solo lectura, en lugar de montar el archivo de disco completo como si fuera un sistema de archivos.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### Volúmenes de BitLocker

Usa el modo de solo lectura en ambas capas. `-u` sin valor solicita la contraseña, lo que evita que aparezca en los argumentos del proceso o en el historial del shell.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

Para LUKS o LVM, es preferible usar `guestmount -i --ro`; su appliance puede inspeccionar diseños comunes cifrados y de volúmenes lógicos sin activar un grupo de volúmenes ajeno en el host.<sup>[[17]](#references)</sup>

### Ayudantes de kpartx

`kpartx` crea nodos device-mapper en el host y, por lo tanto, no es apropiado para imágenes hostiles. Cuando se justifique el mapeo directo, añade `-r` para que los mapeos de particiones sean de solo lectura y elimina los mapeos pasando la misma ruta de imagen que usaste para crearlos.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Errores comunes de montaje y soluciones

| Error | Causa habitual | Siguiente paso seguro |
|-------|---------------|-----------------------|
| `cannot mount ... read-only` | Sistema de archivos con journaling no limpio | usa la opción específica del sistema de archivos para no reproducir el journal, como `ro,noload` en ext4 |
| `bad superblock ...` | Partición/offset de sector incorrecto o sistema de archivos dañado | confirma el tamaño y el offset de sector con `mmls`; ejecuta `fsck -n` solo en una copia verificada |
| `unknown filesystem type 'LVM2_member'` | La partición seleccionada es un volumen físico de LVM | deja que libguestfs lo inspeccione o aísla la activación manual de LVM en una VM desechable |

### Limpieza

Desmonta los sistemas de archivos antes de desconectar sus dispositivos subyacentes. Elimina también la capa FUSE de EWF/xmount y cualquier mapeo de crypt o device-mapper que hayas creado:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [Especificación del estándar AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Documentación de QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Página del manual de mount(8) para Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [El sistema de archivos SGI XFS (documentación del kernel de Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [SWGDE: mejores prácticas para la recopilación de evidencia digital](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [SWGDE: mejores prácticas para adquisiciones forenses de computadoras](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [Página del manual de dc3dd(1)](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Página principal de Guymager y documentación de configuración](https://guymager.sourceforge.io/)
- [9] [Documentación de c-aff4](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Formatos y verificación de Exterro FTK Imager](https://www.exterro.com/digital-forensics-software)
- [11] [Manual de libewf ewfacquire(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [Manual de libewf ewfverify(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Crear snapshots de Amazon EBS](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Leer snapshots de Amazon EBS con las EBS direct APIs](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Referencia de snapshots de Azure CLI](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [Seguridad de libguestfs](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}

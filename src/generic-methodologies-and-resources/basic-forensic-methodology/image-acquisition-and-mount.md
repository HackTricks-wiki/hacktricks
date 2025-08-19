# Aquisição de Imagem & Montagem

{{#include ../../banners/hacktricks-training.md}}


## Aquisição

> Sempre adquira **somente leitura** e **hash enquanto copia**. Mantenha o dispositivo original **bloqueado para gravação** e trabalhe apenas em cópias verificadas.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` é o fork ativamente mantido do dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Imager gráfico e multithread que suporta **raw (dd)**, **EWF (E01/EWFX)** e **AFF4** com verificação paralela. Disponível na maioria dos repositórios do Linux (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Formato Avançado de Análise 4)

AFF4 é o formato de imagem moderno do Google projetado para evidências *muito* grandes (esparsas, retomáveis, nativas da nuvem).
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Você pode [baixar o FTK Imager](https://accessdata.com/product-download) e criar imagens **raw, E01 ou AFF4**:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### Ferramentas EWF (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Imaging Cloud Disks

*AWS* – crie um **snapshot forense** sem desligar a instância:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – use `az snapshot create` e exporte para uma URL SAS.

## Montar

### Escolhendo a abordagem certa

1. Monte o **disco inteiro** quando você quiser a tabela de partição original (MBR/GPT).
2. Monte um **arquivo de partição única** quando você precisar apenas de um volume.
3. Sempre monte **somente leitura** (`-o ro,norecovery`) e trabalhe em **cópias**.

### Imagens brutas (dd, extraídas do AFF4)
```bash
# Identify partitions
fdisk -l disk.img

# Attach the image to a network block device (does not modify the file)
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 --read-only disk.img

# Inspect partitions
lsblk /dev/nbd0 -o NAME,SIZE,TYPE,FSTYPE,LABEL,UUID

# Mount a partition (e.g. /dev/nbd0p2)
sudo mount -o ro,uid=$(id -u) /dev/nbd0p2 /mnt
```
Desconecte-se quando terminar:
```bash
sudo umount /mnt && sudo qemu-nbd --disconnect /dev/nbd0
```
### EWF (E01/EWFX)
```bash
# 1. Mount the EWF container
mkdir /mnt/ewf
ewfmount evidence.E01 /mnt/ewf

# 2. Attach the exposed raw file via qemu-nbd (safer than loop)
sudo qemu-nbd --connect=/dev/nbd1 --read-only /mnt/ewf/ewf1

# 3. Mount the desired partition
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```
Alternativamente, converta em tempo real com **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumes

Após anexar o dispositivo de bloco (loop ou nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx helpers

`kpartx` mapeia partições de uma imagem para `/dev/mapper/` automaticamente:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Erros comuns de montagem e correções

| Erro | Causa Típica | Correção |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | FS com journal (ext4) não desmontado corretamente | use `-o ro,norecovery` |
| `bad superblock …` | Offset errado ou FS danificado | calcule o offset (`sector*size`) ou execute `fsck -n` em uma cópia |
| `mount: unknown filesystem type 'LVM2_member'` | Contêiner LVM | ative o grupo de volumes com `vgchange -ay` |

### Limpeza

Lembre-se de **umount** e **desconectar** dispositivos loop/nbd para evitar deixar mapeamentos pendentes que podem corromper trabalhos futuros:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## Referências

- Anúncio e especificação da ferramenta de imagem AFF4: https://github.com/aff4/aff4
- Página do manual do qemu-nbd (montando imagens de disco com segurança): https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html

{{#include ../../banners/hacktricks-training.md}}

# Aquisição e Montagem de Imagens

{{#include ../../banners/hacktricks-training.md}}


## Aquisição

> Sempre adquira em modo **somente leitura** e **calcule o hash enquanto copia**. Mantenha o dispositivo original **bloqueado contra escrita** e trabalhe apenas com cópias verificadas.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` é o fork mantido ativamente do dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Imager gráfico e multithread que oferece suporte a saída **raw (dd)**, **EWF (E01/EWFX)** e **AFF4**, com verificação paralela. Disponível na maioria dos repositórios Linux (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4 é o formato moderno de imagem forense do Google, projetado para evidências *muito* grandes (esparsas, retomáveis, cloud-native).<sup>[[1]](#references)</sup>
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
### Criação de Imagens de Discos na Cloud

*AWS* – crie um **snapshot forense** sem desligar a instância:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – use `az snapshot create` and export to a SAS URL.


## Montagem

### Escolhendo a abordagem correta

1. Monte o **disco inteiro** quando quiser a tabela de partições original (MBR/GPT).
2. Monte um **arquivo de partição individual** quando precisar apenas de um volume.
3. Sempre monte como **somente leitura** (`-o ro,norecovery`) e trabalhe em **cópias**.<sup>[[2]](#references)</sup>

### Imagens raw (extraídas com dd, AFF4)
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
Nenhum conteúdo foi fornecido para tradução.
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
Como alternativa, converta em tempo real com **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### Volumes LVM / BitLocker / VeraCrypt

Após anexar o dispositivo de bloco (loop ou nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### Auxiliares do kpartx

`kpartx` mapeia automaticamente as partições de uma imagem para `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Erros comuns de montagem e correções

| Erro | Causa típica | Correção |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | FS com journal (ext4) não foi desmontado corretamente | use `-o ro,norecovery` |
| `bad superblock …` | Offset incorreto ou FS danificado | calcule o offset (`sector*size`) ou execute `fsck -n` em uma cópia |
| `mount: unknown filesystem type 'LVM2_member'` | Container LVM | ative o grupo de volumes com `vgchange -ay` |

### Limpeza

Lembre-se de executar **umount** e **disconnect** nos dispositivos loop/nbd para evitar deixar mapeamentos pendentes que possam corromper trabalhos futuros:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## Referências

- [1] [Especificação do Padrão AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [página de manual do qemu-nbd (montagem segura de imagens de disco)](https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html)

{{#include ../../banners/hacktricks-training.md}}

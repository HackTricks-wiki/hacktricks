# Aquisição e Montagem de Imagem

{{#include ../../banners/hacktricks-training.md}}

## Aquisição

> Sempre adquira em modo **somente leitura** e **calcule o hash enquanto copia**. Mantenha o dispositivo original **bloqueado contra gravação** e trabalhe apenas com cópias verificadas.

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
Imager gráfico e multithread que oferece suporte a saídas **raw (dd)**, **EWF (E01/EWFX)** e **AFF4**, com verificação paralela. Disponível na maioria dos repositórios Linux (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

A especificação AFF4 v1.0, criada por Bradley L. Schatz e Michael I. Cohen, define um contêiner forense com armazenamento virtualizado, metadados arbitrários, compressão e hashing extensíveis e operação de alto desempenho.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows e Linux)

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

*AWS* – crie um **forensic snapshot** sem desligar a instância:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – use `az snapshot create` and export to a SAS URL.


## Montagem

### Escolhendo a abordagem correta

1. Monte o **disco inteiro** quando quiser a tabela de partições original (MBR/GPT).
2. Monte um **arquivo de partição único** quando precisar apenas de um volume.
3. Mantenha os anexos de imagem somente para leitura (por exemplo, `--read-only` do qemu-nbd).<sup>[[2]](#references)</sup> Monte os sistemas de arquivos somente para leitura (`-o ro`).<sup>[[3]](#references)</sup> Trabalhe em **cópias**.

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
Desmonte quando terminar:
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

# 3. Mount the desired partition (XFS example; use the filesystem-specific option)
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```
Para montagens sem replay específicas do sistema de arquivos, ext3/ext4 usam `noload`, enquanto XFS usa `norecovery` e exige o modo somente leitura.<sup>[[3]](#references)[[4]](#references)</sup>

Como alternativa, converta em tempo real com **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumes

Após anexar o block device (loop ou nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx helpers

`kpartx` mapeia automaticamente as partições de uma imagem para `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Erros comuns de montagem e correções

Para um filesystem ext3/ext4 com alterações pendentes, use `ro,noload` quando a reprodução do journal precisar ser impedida.<sup>[[3]](#references)</sup>

| Erro | Causa típica | Correção |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | FS com journal (ext4) não desmontado corretamente | use `-o ro,noload` |
| `bad superblock …` | Offset incorreto ou FS danificado | calcule o offset (`sector*size`) ou execute `fsck -n` em uma cópia |
| `mount: unknown filesystem type 'LVM2_member'` | Container LVM | ative o volume group com `vgchange -ay` |

### Limpeza

Lembre-se de executar **umount** e **disconnect** nos dispositivos loop/nbd para evitar deixar mapeamentos pendentes que possam corromper trabalhos posteriores:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [Especificação do padrão AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Documentação do QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Página do manual Linux mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [O sistema de arquivos XFS da SGI (documentação do kernel Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}

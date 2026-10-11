# Aquisição de Imagem e Montagem

{{#include ../../banners/hacktricks-training.md}}

## Aquisição

> Sempre adquira em **somente leitura** e calcule o **hash durante a cópia**. Mantenha o dispositivo original **bloqueado contra gravação** e trabalhe apenas com cópias verificadas.

Registre a marca, o modelo, o número de série e o tamanho da origem, a ferramenta e a versão, os timestamps, o operador, o destino, os erros e os hashes de aquisição/verificação. Preserve uma imagem de arquivo e examine uma cópia de trabalho separada.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` adiciona hashing em tempo real, verificação da saída, registro de erros e divisão da saída ao fluxo de trabalho do `dd`. `hof=` seleciona uma saída verificada por hash; `hash=`, `hlog=`, `log=` e `bufsz=` são operandos separados.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager é um imager gráfico e multithread para Linux, que gera arquivos raw/dd, EWF e AFF legado. **AFF e AFF4 são formatos diferentes**; o Guymager não anuncia suporte à geração de AFF4. Ative SHA-256 e a verificação do destino na caixa de diálogo de aquisição e, em seguida, inicie-o com `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

A especificação AFF4 v1.0 define um contêiner forense com armazenamento virtualizado, metadados arbitrários, compressão e hashing extensíveis e operação de alto desempenho.<sup>[[1]](#references)</sup>

A implementação canônica em C/C++ usa `-i` para a origem e `-o` para o volume AFF4. Crie e mantenha um hash externo do contêiner como referência de aquisição.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

A documentação atual do FTK Imager anuncia saída raw/DD, E01 e AFF com verificação de hash. Não rotule sua saída AFF como AFF4.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### Ferramentas EWF (libewf)

Para aquisição não supervisionada, o destino é `-t`, os metadados do caso usam `-C/-D/-E/-e`, `-d sha256` adiciona SHA-256, e `-l` registra erros e hashes da aquisição. Verifique o conjunto de segmentos concluído antes da análise.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Imaging de discos na nuvem

Um snapshot do provedor é uma fonte de coleta em um momento específico, não uma imagem forense automaticamente consistente com a aplicação. Um snapshot do EBS não inclui dados que ainda estejam em cache no sistema convidado; pause as gravações, coloque a aplicação em estado consistente, desmonte o volume de dados ou pare a instância cujo volume raiz está sendo capturado, quando o plano de resposta permitir.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Não descreva snapshots do EBS como arquivos que podem simplesmente ser copiados para o S3. Para reconstruir a imagem de blocos sem criar um volume, enumere os blocos alocados com `ListSnapshotBlocks`, obtenha cada bloco de 512 KiB com `GetSnapshotBlock`, valide o checksum retornado e preencha com zeros os índices de blocos ausentes do snapshot esparso.<sup>[[14]](#references)</sup>

No Azure, crie o snapshot, emita uma SAS **somente leitura** de curta duração, baixe o VHD, revogue o acesso e calcule o hash do resultado. Crie um snapshot de cada disco separadamente, a menos que o mecanismo de coleta forneça consistência coordenada.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Montagem

### Trate imagens como entrada hostil

Um sistema de arquivos malicioso pode atacar os analisadores de partições e sistemas de arquivos do kernel do host. O QEMU alerta explicitamente para não conectar uma imagem de máquina virtual não confiável ao NBD do host para montá-la, e o libguestfs recomenda nunca montar diretamente um sistema de arquivos de máquina virtual não confiável usando loop ou `kpartx`.<sup>[[2]](#references)[[16]](#references)</sup>

Prefira `guestmount` para uma imagem desconhecida ou controlada por um invasor. Ele analisa e monta o sistema de arquivos da máquina virtual dentro de um appliance pequeno e, em seguida, expõe os arquivos por meio do FUSE. Especifique o formato conhecido em vez de usar a detecção automática e mantenha o appliance em modo somente leitura.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

Se a inspeção não conseguir inferir o SO, substitua `-i` por um dispositivo explícito do sistema convidado, como `-m /dev/sda2`. Volumes LUKS criptografados podem ser fornecidos com seletores `--key`; evite colocar uma chave diretamente no histórico do shell.<sup>[[17]](#references)</sup>

### Escolher uma montagem direta no host

Use uma montagem direta no host apenas para imagens confiáveis ou em uma VM de análise descartável:

1. Monte o **disco inteiro** quando precisar da tabela de partições original.
2. Monte uma **imagem de partição única** quando precisar apenas de um volume.
3. Torne o anexo somente leitura e force o formato da imagem. Monte também o sistema de arquivos como somente leitura. `ro` sozinho não impede a reprodução do journal de ext3/ext4; portanto, use `ro,noload` para sistemas de arquivos ext com journal pendente.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` é útil quando o tamanho do setor não é de 512 bytes ou os metadados da partição estão danificados; `-b` especifica o tamanho real do setor do dispositivo. Continue a análise de partições e sistemas de arquivos aqui:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Imagens raw (dd, extraídas de AFF4)

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

Desmonte ao terminar:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

Para qcow2, VMDK ou VHD/VHDX, determine o formato com base em uma procedência confiável ou inspecione-o dentro da VM de análise descartável e, em seguida, substitua `--format=raw` pelo formato explícito. Nunca confie na detecção automática de formato pelo host para entradas não confiáveis.<sup>[[2]](#references)</sup>

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

Para mounts sem replay específicos do sistema de arquivos, ext3/ext4 usam `noload`, enquanto XFS usa `norecovery` e exige modo somente leitura.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` pode expor uma visualização raw virtual, mas ela ainda contém a tabela de partições original. Encaminhe-a para o mesmo fluxo de trabalho com `mmls`, `guestmount` isolado ou NBD somente leitura, em vez de montar o arquivo de disco inteiro como um sistema de arquivos.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### Volumes BitLocker

Use o modo somente leitura nas duas camadas. `-u` sem um valor solicita a senha, evitando que ela apareça nos argumentos do processo ou no histórico do shell.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

Para LUKS ou LVM, prefira `guestmount -i --ro`; seu appliance pode inspecionar layouts comuns criptografados e de volumes lógicos sem ativar um grupo de volumes externo no host.<sup>[[17]](#references)</sup>

### Auxiliares do `kpartx`

`kpartx` cria nós de device-mapper no host e, portanto, não é apropriado para imagens hostis. Quando o mapeamento direto for justificável, adicione `-r` para que os mapeamentos das partições sejam somente leitura e remova os mapeamentos passando o mesmo caminho da imagem usado para criá-los.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Erros comuns de montagem e correções

| Erro | Causa típica | Próxima etapa segura |
|-------|---------------|----------------------|
| `cannot mount ... read-only` | Sistema de arquivos com journal inconsistente | use a opção específica do sistema de arquivos para não reproduzir o journal, como `ro,noload` no ext4 |
| `bad superblock ...` | Partição/offset de setor incorreto ou sistema de arquivos danificado | confirme o tamanho e o offset do setor com `mmls`; execute `fsck -n` somente em uma cópia verificada |
| `unknown filesystem type 'LVM2_member'` | A partição selecionada é um volume físico LVM | deixe o libguestfs inspecioná-la ou isole a ativação manual do LVM em uma VM descartável |

### Limpeza

Desmonte os sistemas de arquivos antes de desconectar os dispositivos subjacentes. Remova também a camada FUSE do EWF/xmount e quaisquer mapeamentos crypt ou device-mapper criados:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [Especificação padrão AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Documentação do QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Página de manual do mount(8) para Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [O sistema de arquivos SGI XFS (documentação do kernel Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [Melhores práticas do SWGDE para coleta de evidências digitais](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [Melhores práticas do SWGDE para aquisições forenses de computadores](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [Página de manual do dc3dd(1)](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Página inicial e documentação de configuração do Guymager](https://guymager.sourceforge.io/)
- [9] [Documentação do c-aff4](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Formatos e verificação do Exterro FTK Imager](https://www.exterro.com/digital-forensics-software)
- [11] [Manual do libewf ewfacquire(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [Manual do libewf ewfverify(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Criar snapshots do Amazon EBS](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Ler snapshots do Amazon EBS com as APIs diretas do EBS](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Referência de snapshots da Azure CLI](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [Segurança do libguestfs](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}

# Aquisição de Imagem e Montagem

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Aquisição

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

O `dcfldd` é uma ferramenta de linha de comando que é uma versão aprimorada do `dd`. Ele tem recursos adicionais, como hash de verificação de integridade, capacidade de exibir o progresso da cópia e a capacidade de copiar dados em paralelo. 

Para criar uma imagem de um dispositivo usando o `dcfldd`, use o seguinte comando:

```
dcfldd if=/dev/sda of=image.dd
```

Isso criará uma imagem do dispositivo `/dev/sda` e a salvará em um arquivo chamado `image.dd`. 

Para montar a imagem criada, use o seguinte comando:

```
sudo mount -o loop,ro image.dd /mnt/image
```

Isso montará a imagem somente leitura no diretório `/mnt/image`.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

Você pode [**baixar o FTK Imager aqui**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

Você pode gerar uma imagem de disco usando as [**ferramentas ewf**](https://github.com/libyal/libewf).
```bash
ewfacquire /dev/sdb
#Name: evidence
#Case number: 1
#Description: A description for the case
#Evidence number: 1
#Examiner Name: Your name
#Media type: fixed
#Media characteristics: physical
#File format: encase6
#Compression method: deflate
#Compression level: fast

#Then use default values
#It will generate the disk image in the current directory
```
## Montagem

### Vários tipos

No **Windows**, você pode tentar usar a versão gratuita do Arsenal Image Mounter ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)) para **montar a imagem forense**.

### Raw
```bash
#Get file type
file evidence.img 
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

O formato EWF (Expert Witness Compression Format) é um formato de imagem de disco que permite a compressão de imagens de disco forense. Ele é amplamente utilizado em investigações forenses, pois permite a criação de imagens de disco compactas e eficientes em termos de espaço. O EWF também suporta a criação de imagens segmentadas, o que significa que uma imagem grande pode ser dividida em várias partes menores para facilitar o armazenamento e a transferência.

Para criar uma imagem EWF, você pode usar ferramentas como o `ewfacquire` ou o `dcfldd`. O `ewfacquire` é uma ferramenta de linha de comando que permite a criação de imagens EWF segmentadas. O `dcfldd` é uma ferramenta semelhante que suporta a criação de imagens EWF e outras imagens de disco forense.

Para montar uma imagem EWF, você pode usar ferramentas como o `ewfmount` ou o `mount_ewf.py`. O `ewfmount` é uma ferramenta de linha de comando que permite a montagem de imagens EWF em sistemas Linux. O `mount_ewf.py` é uma ferramenta Python que suporta a montagem de imagens EWF em sistemas Windows e Linux.

Ao trabalhar com imagens EWF, é importante lembrar que elas são apenas uma cópia do disco original e não devem ser modificadas. Qualquer modificação na imagem pode comprometer a integridade dos dados e invalidar a imagem como evidência forense.
```bash
#Get file type
file evidence.E01 
evidence.E01: EWF/Expert Witness/EnCase image file format

#Transform to raw
mkdir output
ewfmount evidence.E01 output/
file output/ewf1 
output/ewf1: Linux rev 1.0 ext4 filesystem data, UUID=05acca66-d042-4ab2-9e9c-be813be09b24 (needs journal recovery) (extents) (64bit) (large files) (huge files)

#Mount
mount output/ewf1 -o ro,norecovery /mnt
```
### ArsenalImageMounter

É um aplicativo do Windows para montar volumes. Você pode baixá-lo aqui [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Erros

* **`cannot mount /dev/loop0 read-only`** neste caso, você precisa usar as flags **`-o ro,norecovery`**
* **`wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.`** neste caso, a montagem falhou devido ao deslocamento do sistema de arquivos ser diferente do da imagem do disco. Você precisa encontrar o tamanho do setor e o setor de início:
```bash
fdisk -l disk.img 
Disk disk.img: 102 MiB, 106954648 bytes, 208896 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00495395

Device        Boot Start    End Sectors  Size Id Type
disk.img1       2048 208895  206848  101M  1 FAT12
```
Observe que o tamanho do setor é **512** e o início é **2048**. Em seguida, monte a imagem da seguinte maneira:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

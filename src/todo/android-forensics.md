# Perícia Forense em Android

{{#include ../banners/hacktricks-training.md}}

## Dispositivo Bloqueado

Para começar a extrair dados de um dispositivo Android, ele precisa estar desbloqueado. Se estiver bloqueado, você pode:

- Verificar se a depuração via USB está ativada no dispositivo.
- Verificar a possibilidade de um [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>
- Tentar usar [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>

## Aquisição de Dados

Crie um [backup do Android usando adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) e extraia-o usando o [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Se houver acesso root ou conexão física à interface JTAG

- `cat /proc/partitions` (procure o caminho para a memória flash; geralmente, a primeira entrada é _mmcblk0_ e corresponde à memória flash inteira).
- `df /data` (descubra o tamanho do bloco do sistema).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (execute-o usando as informações obtidas sobre o tamanho do bloco).

### Memória

Use o Linux Memory Extractor (LiME) para extrair as informações da RAM. Trata-se de uma extensão do kernel que deve ser carregada via adb.

## Referências

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}

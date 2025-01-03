# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Dispositivo Bloqueado

Para começar a extrair dados de um dispositivo Android, ele deve estar desbloqueado. Se estiver bloqueado, você pode:

- Verificar se o dispositivo tem depuração via USB ativada.
- Verificar um possível [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- Tentar com [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Aquisição de Dados

Crie um [backup android usando adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) e extraia-o usando [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Se acesso root ou conexão física à interface JTAG

- `cat /proc/partitions` (procure o caminho para a memória flash, geralmente a primeira entrada é _mmcblk0_ e corresponde à memória flash inteira).
- `df /data` (Descubra o tamanho do bloco do sistema).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (execute com as informações coletadas do tamanho do bloco).

### Memória

Use o Linux Memory Extractor (LiME) para extrair as informações da RAM. É uma extensão do kernel que deve ser carregada via adb.

{{#include ../banners/hacktricks-training.md}}

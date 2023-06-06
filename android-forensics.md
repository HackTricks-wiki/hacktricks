# Forense Android

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Dispositivo Bloqueado

Para começar a extrair dados de um dispositivo Android, ele deve estar desbloqueado. Se estiver bloqueado, você pode:

* Verificar se o dispositivo tem depuração via USB ativada.
* Verificar se há um possível [ataque de impressão digital](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)
* Tentar com [força bruta](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Aquisição de Dados

Crie um backup do Android usando adb e extraia-o usando o [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Se houver acesso root ou conexão física com a interface JTAG

* `cat /proc/partitions` (procure o caminho para a memória flash, geralmente a primeira entrada é _mmcblk0_ e corresponde a toda a memória flash).
* `df /data` (descubra o tamanho do bloco do sistema).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (execute-o com as informações coletadas do tamanho do bloco).

### Memória

Use o Linux Memory Extractor (LiME) para extrair as informações da RAM. É uma extensão do kernel que deve ser carregada via adb.

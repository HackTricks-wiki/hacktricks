# Abusando do Socket do Docker para Escalonamento de Privilégios

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Há algumas ocasiões em que você tem **acesso ao socket do Docker** e deseja usá-lo para **escalar privilégios**. Algumas ações podem ser muito suspeitas e você pode querer evitá-las, então aqui você pode encontrar diferentes flags que podem ser úteis para escalar privilégios:

### Através de mount

Você pode **montar** diferentes partes do **sistema de arquivos** em um contêiner em execução como root e **acessá-las**.\
Você também pode **abusar de um mount para escalar privilégios** dentro do contêiner.

* **`-v /:/host`** -> Monta o sistema de arquivos do host no contêiner para que você possa **ler o sistema de arquivos do host.**
  * Se você quiser **sentir como se estivesse no host** mas estiver no contêiner, você pode desabilitar outros mecanismos de defesa usando flags como:
    * `--privileged`
    * `--cap-add=ALL`
    * `--security-opt apparmor=unconfined`
    * `--security-opt seccomp=unconfined`
    * `-security-opt label:disable`
    * `--pid=host`
    * `--userns=host`
    * `--uts=host`
    * `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Isso é semelhante ao método anterior, mas aqui estamos **montando o disco do dispositivo**. Em seguida, dentro do contêiner, execute `mount /dev/sda1 /mnt` e você pode **acessar** o **sistema de arquivos do host** em `/mnt`
  * Execute `fdisk -l` no host para encontrar o dispositivo `</dev/sda1>` para montar
* **`-v /tmp:/host`** -> Se por algum motivo você puder **apenas montar algum diretório** do host e tiver acesso dentro do host. Monte-o e crie um **`/bin/bash`** com **suid** no diretório montado para que você possa **executá-lo no host e escalar para root**.

{% hint style="info" %}
Observe que talvez você não possa montar a pasta `/tmp`, mas pode montar uma **pasta gravável diferente**. Você pode encontrar diretórios graváveis usando: `find / -writable -type d 2>/dev/null`

**Observe que nem todos os diretórios em uma máquina Linux suportarão o bit suid!** Para verificar quais diretórios suportam o bit suid, execute `mount | grep -v "nosuid"`. Por exemplo, geralmente `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` e `/var/lib/lxcfs` não suportam o bit suid.

Observe também que se você puder **montar `/etc`** ou qualquer outra pasta **que contenha arquivos de configuração**, poderá alterá-los do contêiner Docker como root para **abusá-los no host** e escalar privilégios (talvez modificando `/etc/shadow`)
{% endhint %}

### Escapando do contêiner

* **`--privileged`** -> Com essa flag, você [remove todo o isolamento do contêiner](docker-privileged.md#what-affects). Verifique as técnicas para [escapar de contêineres privilegiados como root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Para [escalar abusando de capacidades](../linux-capabilities.md), **conceda essa capacidade ao contêiner** e desative outros métodos de proteção que possam impedir que o exploit funcione.

### Curl

Nesta página, discutimos maneiras de escalar privilégios usando flags do Docker, você pode encontrar **maneiras de abusar desses métodos usando o comando curl** na página:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks

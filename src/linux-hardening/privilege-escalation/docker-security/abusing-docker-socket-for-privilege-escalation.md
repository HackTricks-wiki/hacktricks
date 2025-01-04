# Abusando do Socket Docker para Escalação de Privilégios

{{#include ../../../banners/hacktricks-training.md}}

Existem algumas ocasiões em que você tem **acesso ao socket docker** e deseja usá-lo para **escalar privilégios**. Algumas ações podem ser muito suspeitas e você pode querer evitá-las, então aqui você pode encontrar diferentes flags que podem ser úteis para escalar privilégios:

### Via mount

Você pode **montar** diferentes partes do **sistema de arquivos** em um contêiner executando como root e **acessá-las**.\
Você também pode **abusar de um mount para escalar privilégios** dentro do contêiner.

- **`-v /:/host`** -> Monte o sistema de arquivos do host no contêiner para que você possa **ler o sistema de arquivos do host.**
- Se você quiser **sentir que está no host** mas estando no contêiner, você pode desativar outros mecanismos de defesa usando flags como:
- `--privileged`
- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `-security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Isso é semelhante ao método anterior, mas aqui estamos **montando o disco do dispositivo**. Então, dentro do contêiner, execute `mount /dev/sda1 /mnt` e você pode **acessar** o **sistema de arquivos do host** em `/mnt`
- Execute `fdisk -l` no host para encontrar o dispositivo `</dev/sda1>` para montar
- **`-v /tmp:/host`** -> Se por algum motivo você pode **apenas montar algum diretório** do host e você tem acesso dentro do host. Monte-o e crie um **`/bin/bash`** com **suid** no diretório montado para que você possa **executá-lo a partir do host e escalar para root**.

> [!NOTE]
> Note que talvez você não consiga montar a pasta `/tmp`, mas pode montar uma **pasta gravável diferente**. Você pode encontrar diretórios graváveis usando: `find / -writable -type d 2>/dev/null`
>
> **Note que nem todos os diretórios em uma máquina linux suportarão o bit suid!** Para verificar quais diretórios suportam o bit suid, execute `mount | grep -v "nosuid"` Por exemplo, geralmente `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` e `/var/lib/lxcfs` não suportam o bit suid.
>
> Note também que se você puder **montar `/etc`** ou qualquer outra pasta **contendo arquivos de configuração**, você pode alterá-los a partir do contêiner docker como root para **abusar deles no host** e escalar privilégios (talvez modificando `/etc/shadow`)

### Escapando do contêiner

- **`--privileged`** -> Com esta flag você [remove toda a isolação do contêiner](docker-privileged.md#what-affects). Verifique técnicas para [escapar de contêineres privilegiados como root](docker-breakout-privilege-escalation/index.html#automatic-enumeration-and-escape).
- **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Para [escalar abusando de capacidades](../linux-capabilities.md), **conceda essa capacidade ao contêiner** e desative outros métodos de proteção que podem impedir a exploração de funcionar.

### Curl

Nesta página discutimos maneiras de escalar privilégios usando flags do docker, você pode encontrar **maneiras de abusar desses métodos usando o comando curl** na página:

{{#include ../../../banners/hacktricks-training.md}}

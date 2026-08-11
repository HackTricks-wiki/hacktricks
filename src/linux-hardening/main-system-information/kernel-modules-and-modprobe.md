# Abuso de Kernel Modules e modprobe

{{#include ../../banners/hacktricks-training.md}}

## Misconfigurações de Kernel modules e carregamento de modules

O suporte a Kernel modules é uma área de alto impacto durante a revisão de privilege escalation no Linux. Não trate toda mensagem sobre módulos unsigned como explorável por si só, mas use-a para responder a perguntas práticas.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- O usuário atual pode carregar modules por meio de `sudo`, capabilities ou de um helper path gravável?
- O carregamento de modules ainda está habilitado?
- A imposição de assinaturas de modules está desabilitada?
- Os diretórios de modules ou os arquivos de modules são graváveis?
- Os logs do Kernel podem ser lidos para confirmar o que aconteceu?

A triagem rápida começa com as seguintes verificações de status de modules, assinaturas, logging e da árvore de modules.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretação:

- `modules_disabled=1` significa que os módulos não podem ser carregados nem descarregados, e o valor não pode ser redefinido para `0` até a reinicialização.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` na linha de comando do kernel ou `CONFIG_MODULE_SIG_FORCE=y` exige módulos assinados validamente; caso contrário, módulos não assinados podem ser carregados e contaminar o kernel.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` não impõe nenhuma restrição ao `dmesg`; quando é `1`, o acesso exige `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Caminhos graváveis sob `/lib/modules/$(uname -r)/` são perigosos porque o `modprobe` pesquisa essa árvore e seus dados de dependências ao carregar módulos.<sup>[[8]](#references)</sup>

### Carregando um módulo e lendo a saída do kernel

Se você tiver permissão legítima para carregar um módulo local, `insmod` insere o arquivo `.ko` exato que você fornecer. A função de inicialização do módulo é executada como parte do carregamento, e as mensagens escritas com `printk()` vão para o buffer de logs do kernel, que normalmente é lido com `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Um workflow mínimo de revisão usa `modinfo` para inspecionar metadados, `insmod` e `rmmod` para carregar e remover um módulo, `lsmod` para confirmar o estado de carregamento e `dmesg` para inspecionar os logs do kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Se `sudo -l` permitir `insmod`, `modprobe` ou um wrapper em torno deles, trate isso como crítico: `sudo -l` lista os privilégios do usuário que o invoca, e carregar um módulo do kernel requer `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` permitido pelo Sudo

Uma regra do sudo que permite a um usuário executar `insmod` não é comparável a permitir um helper administrativo comum. O código de inicialização do módulo é executado como parte da inserção, portanto, a questão prática da revisão é saber se esse usuário pode escolher ou modificar o módulo que está sendo carregado.<sup>[[3]](#references)</sup>

O fluxo genérico de revisão a seguir repete essas verificações de inspeção, carregamento, estado, logs e remoção para um módulo candidato.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Se o usuário puder fornecer um `.ko` arbitrário, a regra deverá ser tratada como comprometimento total do sistema em uma avaliação autorizada. Um padrão operacional mais seguro é evitar delegar o carregamento de módulos por meio do sudo; se isso for inevitável, restrinja o caminho exato, a propriedade, as permissões, a política de assinatura e o fluxo de remoção.<sup>[[3]](#references)[[10]](#references)</sup>

Para um padrão inofensivo de compilação de módulo em um laboratório controlado, um código-fonte mínimo e um Makefile são mostrados abaixo; a forma `make -C /lib/modules/$(uname -r)/build M=$PWD` segue o fluxo de trabalho kbuild documentado pelo kernel para módulos externos.<sup>[[5]](#references)[[7]](#references)</sup>
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

`kernel.modprobe` identifica o helper userspace que o kernel executa para solicitações de autoload de módulos; esse sysctl afeta o autoloading, não a inserção explícita de módulos. Se um atacante puder alterá-lo para o caminho de um executável gravável e disparar uma solicitação de módulo, esse helper se tornará um caminho privilegiado para execução de código.<sup>[[1]](#references)</sup>

Verifique o caminho atual do helper por meio da interface sysctl do kernel e inspecione a propriedade e o modo do alvo.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Verifique se o sysctl, as regras de sudo delegadas ou as file capabilities podem ser influenciados.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
O padrão a seguir, exclusivo para laboratórios, altera o caminho do helper e aciona uma solicitação documentada de autoload de módulo; use-o somente em um sistema isolado e autorizado.<sup>[[1]](#references)</sup>

Nos kernels Linux atuais, não use um executável desconhecido como trigger genérico: o autoload legado de módulos por formatos binários personalizados foi removido no Linux 6.14, enquanto a documentação do kernel identifica um tipo de filesystem desconhecido como um caminho de solicitação de autoload de módulo.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Em sistemas reforçados, isso deve falhar quando as permissões impedirem gravações não privilegiadas em `kernel.modprobe`, o caminho do helper não for gravável ou o carregamento automático de módulos estiver desabilitado.<sup>[[1]](#references)</sup>

### Revisão de `/lib/modules` gravável

Diretórios de módulos graváveis podem permitir a substituição de módulos, o plantio de módulos maliciosos ou o abuso do carregamento automático, dependendo de como `modprobe` for invocado posteriormente; `modprobe` pesquisa `/lib/modules/$(uname -r)` e usa seus dados de dependência ao resolver módulos.<sup>[[8]](#references)</sup>

Revise os arquivos de módulos graváveis e os metadados de dependências/aliases na árvore de módulos da versão ativa do kernel.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Se encontrar conteúdo de módulo gravável, analise como `modprobe` resolve dependências e como `modinfo` relata os metadados do módulo.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Notas defensivas:

- Mantenha `/lib/modules` pertencente a `root:root` e sem permissão de escrita para usuários.<sup>[[8]](#references)</sup>
- Defina `kernel.modules_disabled=1` após a inicialização, quando for operacionalmente possível.<sup>[[1]](#references)</sup>
- Enforce module signing em sistemas que exigem módulos carregáveis.<sup>[[2]](#references)</sup>
- Monitore escritas em `/proc/sys/kernel/modprobe`, `/lib/modules` e a execução inesperada de `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [Documentação para /proc/sys/kernel/ — A documentação do Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Recurso de assinatura de módulos do kernel — A documentação do Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Página de manual do Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Página de manual do Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Fundamentos de drivers — A documentação do Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Registro de mensagens com printk — A documentação do Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Compilação de módulos externos — A documentação do Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Página de manual do Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Página de manual do Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Página de manual do Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Mesclar a tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Página de manual do Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Página de manual do Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Página de manual do Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Página de manual do Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}

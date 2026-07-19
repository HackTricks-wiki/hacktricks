# Caminhos mascarados

{{#include ../../../../banners/hacktricks-training.md}}

Caminhos mascarados são proteções de runtime que ocultam do container locais do sistema de arquivos especialmente sensíveis e voltados ao kernel, montando um bind mount sobre eles ou tornando-os inacessíveis de outra forma. O objetivo é impedir que uma workload interaja diretamente com interfaces das quais aplicações comuns não precisam, especialmente dentro do procfs.

Isso é importante porque muitos escapes de container e truques que afetam o host começam pela leitura ou escrita de arquivos especiais em `/proc` ou `/sys`. Se esses locais estiverem mascarados, o atacante perde o acesso direto a uma parte útil da superfície de controle do kernel, mesmo após obter execução de código dentro do container.

## Operação

Runtimes geralmente mascaram caminhos selecionados, como:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

A lista exata depende do runtime e da configuração do host. A propriedade importante é que o caminho se torna inacessível ou é substituído do ponto de vista do container, mesmo continuando a existir no host.

## Laboratório

Inspecione a configuração de caminhos mascarados exposta pelo Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspecione o comportamento real de montagem dentro do workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impacto na segurança

O mascaramento não cria o principal limite de isolamento, mas remove vários alvos de alto valor de post-exploitation. Sem o mascaramento, um container comprometido pode conseguir inspecionar o estado do kernel, ler informações sensíveis de processos ou de keying, ou interagir com objetos procfs/sysfs que nunca deveriam estar visíveis para a aplicação.

## Misconfigurations

O principal erro é remover o mascaramento de classes amplas de paths por conveniência ou para debugging. No Podman, isso pode aparecer como `--security-opt unmask=ALL` ou como a remoção direcionada do mascaramento. No Kubernetes, uma exposição excessivamente ampla do proc pode aparecer por meio de `procMount: Unmasked`. Outro problema grave é expor o `/proc` ou `/sys` do host por meio de um bind mount, ignorando completamente a ideia de uma visão reduzida do container.

## Abuse

Se o mascaramento for fraco ou estiver ausente, comece identificando quais paths sensíveis de procfs/sysfs podem ser acessados diretamente:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Se um caminho supostamente mascarado estiver acessível, inspecione-o cuidadosamente:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
O que estes comandos podem revelar:

- `/proc/timer_list` pode expor dados de timers e do scheduler do host. Isso é principalmente um recurso de reconhecimento, mas confirma que o container pode ler informações voltadas ao kernel que normalmente ficam ocultas.
- `/proc/keys` é muito mais sensível. Dependendo da configuração do host, pode revelar entradas do keyring, descrições de chaves e relações entre serviços do host que usam o subsistema de keyring do kernel.
- `/sys/firmware` ajuda a identificar o modo de boot, interfaces de firmware e detalhes da plataforma úteis para fingerprinting do host e para entender se o workload está acessando estado no nível do host.
- `/proc/config.gz` pode revelar a configuração do kernel em execução, o que é útil para verificar os pré-requisitos de exploits públicos do kernel ou entender por que um recurso específico está acessível.
- `/proc/sched_debug` expõe o estado do scheduler e frequentemente contraria a expectativa intuitiva de que o namespace de PID deveria ocultar completamente informações sobre processos não relacionados.

Resultados interessantes incluem leituras diretas desses arquivos, evidências de que os dados pertencem ao host em vez de uma visão restrita do container, ou acesso a outros locais de procfs/sysfs que normalmente são mascarados por padrão.

## Verificações

O objetivo destas verificações é determinar quais paths o runtime ocultou intencionalmente e se o workload atual ainda enxerga um filesystem voltado ao kernel de forma reduzida.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
O que é interessante aqui:

- Uma lista longa de masked paths é normal em runtimes hardened.
- A ausência de masking em entradas sensíveis do procfs merece uma inspeção mais detalhada.
- Se um path sensível estiver acessível e o container também tiver capabilities fortes ou mounts amplos, a exposição será mais relevante.

## Defaults do Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por padrão | O Docker define uma lista padrão de masked paths | exposição de mounts host proc/sys, `--privileged` |
| Podman | Habilitado por padrão | O Podman aplica masked paths padrão, a menos que sejam manualmente desmascarados | `--security-opt unmask=ALL`, desmascaramento direcionado, `--privileged` |
| Kubernetes | Herda os defaults do runtime | Usa o comportamento de masking do runtime subjacente, a menos que as configurações do Pod enfraqueçam a exposição do proc | `procMount: Unmasked`, padrões de workloads privilegiados, mounts host amplos |
| containerd / CRI-O sob Kubernetes | Default do runtime | Normalmente aplica masked paths do OCI/runtime, a menos que seja sobrescrito | alterações diretas na configuração do runtime, os mesmos caminhos de enfraquecimento do Kubernetes |

Masked paths geralmente estão presentes por padrão. O principal problema operacional não é a ausência deles no runtime, mas o unmasking deliberado ou os bind mounts do host que anulam a proteção.
{{#include ../../../../banners/hacktricks-training.md}}

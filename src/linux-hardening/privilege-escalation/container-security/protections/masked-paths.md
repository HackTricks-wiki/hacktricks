# Caminhos Mascarados

{{#include ../../../../banners/hacktricks-training.md}}

Caminhos mascarados são proteções do runtime que ocultam locais do sistema de arquivos especialmente sensíveis e voltados para o kernel do container, fazendo bind-mounting sobre eles ou, de outra forma, tornando-os inacessíveis. O objetivo é impedir que uma workload interaja diretamente com interfaces que aplicações comuns não precisam, especialmente dentro de procfs.

Isso importa porque muitos container escapes e truques que impactam o host começam lendo ou escrevendo arquivos especiais em `/proc` ou `/sys`. Se esses locais estiverem mascarados, o atacante perde o acesso direto a uma parte útil da superfície de controle do kernel mesmo após obter execução de código dentro do container.

## Operação

Runtimes comumente mascaram caminhos selecionados, tais como:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

A lista exata depende do runtime e da configuração do host. A propriedade importante é que, do ponto de vista do container, o caminho se torna inacessível ou substituído mesmo que ele ainda exista no host.

## Lab

Inspecione a configuração masked-path exposta pelo Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspecione o comportamento real de montagem dentro do workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impacto de Segurança

O mascaramento não cria a principal fronteira de isolamento, mas remove vários alvos pós-exploração de alto valor. Sem mascaramento, um container comprometido pode conseguir inspecionar o estado do kernel, ler informações sensíveis de processos ou material de chave, ou interagir com objetos procfs/sysfs que nunca deveriam ter sido visíveis para a aplicação.

## Configurações incorretas

O erro principal é desmascarar classes amplas de caminhos por conveniência ou depuração. No Podman isso pode aparecer como `--security-opt unmask=ALL` ou desmascaramento direcionado. No Kubernetes, exposição excessiva de proc pode aparecer através de `procMount: Unmasked`. Outro problema sério é expor o host `/proc` ou `/sys` através de um bind mount, o que contorna completamente a ideia de uma visão reduzida do container.

## Abuso

Se o mascaramento for fraco ou estiver ausente, comece identificando quais caminhos sensíveis de procfs/sysfs são diretamente alcançáveis:
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
O que esses comandos podem revelar:

- `/proc/timer_list` pode expor dados de timer e scheduler do host. Isso é principalmente uma primitiva de reconhecimento, mas confirma que o container pode ler informações do kernel que normalmente ficam ocultas.
- `/proc/keys` é muito mais sensível. Dependendo da configuração do host, pode revelar entradas de keyring, descrições de chaves e relações entre serviços do host que usam o subsistema de keyring do kernel.
- `/sys/firmware` ajuda a identificar o modo de inicialização, interfaces de firmware e detalhes da plataforma que são úteis para identificação do host e para entender se a workload está vendo estado a nível de host.
- `/proc/config.gz` pode revelar a configuração do kernel em execução, o que é valioso para corresponder pré-requisitos de exploits públicos do kernel ou entender por que uma funcionalidade específica é alcançável.
- `/proc/sched_debug` expõe o estado do scheduler e frequentemente contorna a expectativa intuitiva de que o PID namespace deveria ocultar completamente informações de processos não relacionados.

Resultados interessantes incluem leituras diretas desses arquivos, evidências de que os dados pertencem ao host em vez de a uma visão de container restrita, ou acesso a outros locais do procfs/sysfs que normalmente são mascarados por padrão.

## Verificações

O objetivo dessas verificações é determinar quais caminhos o runtime ocultou intencionalmente e se a workload atual ainda vê um sistema de arquivos voltado ao kernel reduzido.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
O que é interessante aqui:

- Uma longa lista de caminhos mascarados é normal em runtimes endurecidos.
- A ausência de mascaramento em entradas sensíveis do procfs merece uma inspeção mais detalhada.
- Se um caminho sensível estiver acessível e o container também tiver capabilities elevadas ou mounts amplos, a exposição passa a ser mais relevante.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker defines a default masked path list | exposing host proc/sys mounts, `--privileged` |
| Podman | Enabled by default | Podman applies default masked paths unless unmasked manually | `--security-opt unmask=ALL`, desmascaramento direcionado, `--privileged` |
| Kubernetes | Inherits runtime defaults | Uses the underlying runtime's masking behavior unless Pod settings weaken proc exposure | `procMount: Unmasked`, padrões de workloads privilegiados, mounts amplos do host |
| containerd / CRI-O under Kubernetes | Runtime default | Usually applies OCI/runtime masked paths unless overridden | alterações diretas na configuração do runtime, mesmos caminhos de enfraquecimento do Kubernetes |

Caminhos mascarados geralmente estão presentes por padrão. O principal problema operacional não é a ausência no runtime, mas o desmascaramento deliberado ou bind mounts do host que anulam a proteção.
{{#include ../../../../banners/hacktricks-training.md}}

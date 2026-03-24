# Caminhos mascarados

{{#include ../../../../banners/hacktricks-training.md}}

Caminhos mascarados são proteções em tempo de execução que ocultam locais do sistema de arquivos voltados ao kernel especialmente sensíveis ao container, seja por bind-mounting sobre eles ou tornando-os inacessíveis de outra forma. O objetivo é impedir que uma carga de trabalho interaja diretamente com interfaces que aplicações comuns não precisam, especialmente dentro de procfs.

Isso importa porque muitos container escapes e truques que afetam o host começam lendo ou escrevendo arquivos especiais em `/proc` ou `/sys`. Se esses locais estiverem mascarados, o atacante perde o acesso direto a uma parte útil da superfície de controle do kernel mesmo após obter execução de código dentro do container.

## Operação

Runtimes comumente mascaram caminhos selecionados, tais como:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

A lista exata depende do runtime e da configuração do host. A propriedade importante é que o caminho se torna inacessível ou substituído do ponto de vista do container, mesmo que ainda exista no host.

## Laboratório

Inspecione a configuração masked-path exposta pelo Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspecione o comportamento real do mount dentro do workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impacto na Segurança

O mascaramento não cria a principal barreira de isolamento, mas remove vários alvos de alto valor para post-exploitation. Sem mascaramento, um container comprometido pode ser capaz de inspecionar o estado do kernel, ler informações sensíveis de processos ou informações de chave, ou interagir com objetos procfs/sysfs que nunca deveriam ter sido visíveis para a aplicação.

## Misconfigurações

O erro principal é desmascarar classes amplas de caminhos por conveniência ou depuração. No Podman isso pode aparecer como `--security-opt unmask=ALL` ou desmascaramento direcionado. No Kubernetes, uma exposição excessivamente ampla do proc pode aparecer através de `procMount: Unmasked`. Outro problema sério é expor o `/proc` ou `/sys` do host através de um bind mount, o que contorna completamente a ideia de uma visão reduzida do container.

## Abuso

Se o mascaramento for fraco ou ausente, comece identificando quais caminhos sensíveis de procfs/sysfs são diretamente acessíveis:
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

- `/proc/timer_list` pode expor dados de timers e do scheduler do host. Isso é, em sua maioria, uma primitiva de reconhecimento, mas confirma que o container pode ler informação voltada ao kernel que normalmente está oculta.
- `/proc/keys` é muito mais sensível. Dependendo da configuração do host, pode revelar entradas do keyring, descrições de chaves e relações entre serviços do host que usam o subsistema de keyring do kernel.
- `/sys/firmware` ajuda a identificar o modo de boot, interfaces de firmware e detalhes da plataforma que são úteis para a identificação (fingerprinting) do host e para entender se a carga de trabalho está vendo o estado a nível de host.
- `/proc/config.gz` pode revelar a configuração do kernel em execução, o que é valioso para casar pré-requisitos de exploits públicos do kernel ou para entender por que uma funcionalidade específica é acessível.
- `/proc/sched_debug` expõe o estado do scheduler e frequentemente contorna a expectativa intuitiva de que o namespace de PID deve ocultar completamente informações de processos não relacionados.

Resultados interessantes incluem leituras diretas desses arquivos, evidência de que os dados pertencem ao host em vez de a uma visão restrita do container, ou acesso a outras localizações em procfs/sysfs que costumam ser mascaradas por padrão.

## Checks

O objetivo dessas verificações é determinar quais caminhos o runtime intencionalmente ocultou e se a carga de trabalho atual ainda enxerga um sistema de arquivos voltado ao kernel reduzido.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
O que é interessante aqui:

- Uma longa lista de masked-path é normal em runtimes hardened.
- Falta de masking em entradas sensíveis do procfs merece inspeção mais detalhada.
- Se um path sensível é acessível e o container também possui strong capabilities ou montagens amplas, a exposição importa mais.

## Padrões do Runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por padrão | Docker defines a default masked path list | expondo montagens do host em proc/sys, `--privileged` |
| Podman | Habilitado por padrão | Podman applies default masked paths unless unmasked manually | `--security-opt unmask=ALL`, desmascaramento direcionado, `--privileged` |
| Kubernetes | Herda os padrões do runtime | Usa o comportamento de masking do runtime subjacente, salvo se as configurações do Pod enfraqueçam a exposição de proc | `procMount: Unmasked`, padrões de workloads privilegiadas, montagens amplas do host |
| containerd / CRI-O under Kubernetes | Padrão do runtime | Normalmente aplica OCI/runtime masked paths a menos que seja sobrescrito | alterações diretas na configuração do runtime, mesmas formas de enfraquecimento via Kubernetes |

Masked paths geralmente estão presentes por padrão. O principal problema operacional não é a ausência no runtime, mas o desmascaramento deliberado ou bind mounts do host que anulam a proteção.
{{#include ../../../../banners/hacktricks-training.md}}

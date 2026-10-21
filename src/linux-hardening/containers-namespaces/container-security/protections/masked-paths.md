# Caminhos mascarados

{{#include ../../../../banners/hacktricks-training.md}}

Caminhos mascarados são proteções de runtime que ocultam do contêiner locais especialmente sensíveis do sistema de arquivos voltados ao kernel, montando outros sistemas de arquivos sobre eles ou tornando-os inacessíveis de outra forma. A especificação de runtime da OCI define `maskedPaths` como caminhos absolutos que não podem ser lidos dentro do contêiner.

<sup>[[1]](#references)</sup>

Isso é importante porque muitas técnicas de escape de contêiner e de impacto no host começam pela leitura ou gravação de arquivos especiais em `/proc` ou `/sys`. Se esses locais estiverem mascarados, o atacante perde acesso direto a uma parte útil da superfície de controle do kernel, mesmo depois de obter execução de código dentro do contêiner.

## Operação

Os runtimes costumam mascarar caminhos selecionados, como:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

A lista exata depende do runtime e da configuração do host. O importante é que, do ponto de vista do contêiner, o caminho se torne inacessível ou seja substituído, embora continue existindo no host.

## Laboratório

Inspecione a configuração de caminhos mascarados exposta pelo Docker:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Inspecione o comportamento real da montagem dentro do workload:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

Um caminho listado não é necessariamente legível: o runc pode mascarar um arquivo com um bind mount de `/dev/null` e um diretório com um tmpfs vazio somente leitura. Verifique o ponto de montagem exato, não apenas se `ls` funciona. <sup>[[4]](#references)</sup>

## Security Impact

O mascaramento não cria o principal limite de isolamento, mas remove vários alvos de alto valor para post-exploitation. Sem mascaramento, um container comprometido pode conseguir inspecionar o estado do kernel, ler informações sensíveis de processos ou de chaves, ou interagir com objetos de procfs/sysfs que nunca deveriam estar visíveis para a aplicação.

## Misconfigurations

O principal erro é desmascarar classes amplas de caminhos por conveniência ou para depuração. No Podman, isso pode aparecer como `--security-opt unmask=ALL` ou desmascaramento direcionado. <sup>[[2]](#references)</sup> No Kubernetes, uma exposição excessivamente ampla de proc pode ocorrer por meio de `procMount: Unmasked`; nas versões atuais do Kubernetes, `spec.hostUsers: false` (um user namespace) é obrigatório para essa configuração, enquanto as versões 1.12–1.29 não aplicavam esse requisito. <sup>[[3]](#references)</sup> Outro problema grave é expor `/proc` ou `/sys` do host por meio de um bind mount, o que contorna completamente a ideia de uma visão reduzida do container.

## Abuse

Se o mascaramento for fraco ou inexistente, comece identificando quais caminhos sensíveis de procfs/sysfs estão diretamente acessíveis:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Se um caminho supostamente mascarado estiver acessível, inspecione-o cuidadosamente:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

O que estes comandos podem revelar:

- `/proc/timer_list` pode expor dados do host sobre temporizadores e o scheduler. É principalmente uma primitiva de reconhecimento, mas confirma que o container pode ler informações voltadas ao kernel que normalmente ficam ocultas.
- `/proc/keys` lista metadados apenas das chaves para as quais o leitor tem permissão de **view**, sujeito às verificações do LSM. Pode revelar tipos e descrições de chaves, mas não despeja os payloads das chaves. <sup>[[6]](#references)</sup>
- `/sys/firmware` ajuda a identificar o modo de boot, as interfaces de firmware e detalhes da plataforma úteis para fingerprinting do host e para entender se a workload está vendo o estado do host.
- `/proc/config.gz` pode revelar a configuração do kernel em execução, o que é valioso para verificar os pré-requisitos de exploits públicos de kernel ou entender por que um recurso específico pode ser acessado.
- `/proc/sched_debug` expõe o estado do scheduler e muitas vezes contraria a expectativa intuitiva de que o namespace de PID deve ocultar completamente informações de processos não relacionados.

Resultados interessantes incluem leituras diretas desses arquivos, evidências de que os dados pertencem ao host e não a uma visão restrita do container, ou acesso a outros locais de procfs/sysfs que normalmente são mascarados por padrão.

### Race na origem do mascaramento durante a inicialização do container

Em implementações vulneráveis do runc, os mascaramentos de arquivos dependem do inode de `/dev/null` do container. Um atacante capaz de iniciar containers simultâneos com mounts compartilhados, incluindo etapas paralelas do BuildKit, pode explorar uma race na inicialização e remover `/dev/null` antes que o runc o monte sobre os arquivos de procfs mascarados. O runtime então trata a ausência da **origem** como se o destino do mascaramento estivesse ausente e, sem avisar, ignora esses mascaramentos de arquivos. A falha depende de uma race durante a configuração do runtime; remover `/dev/null` após a inicialização não desfaz um mascaramento já aplicado. <sup>[[4]](#references)</sup>

Após um teste controlado, compare a lista de mascaramentos solicitados com os pontos de montagem exatos dentro do novo container. <sup>[[4]](#references)</sup> `findmnt -M` verifica o ponto de montagem indicado, sem recorrer a um mount pai; se `findmnt` não estiver disponível, inspecione `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> O sucesso de `ls` ou um `cat` sem saída não prova que o mascaramento está ausente. <sup>[[4]](#references)</sup>

Use as [verificações abaixo](#checks) para comparar os mascaramentos solicitados com os mounts exatos no novo container.

Um mascaramento de arquivo ignorado pode expor dados de procfs se as permissões normais e a política do LSM permitirem. Isso, por si só, **não** torna `/proc/sys` gravável: esse é um controle separado de [caminho somente leitura](read-only-paths.md). A substituição distinta do link simbólico `/dev/null`, que pode redirecionar um bind mount para um destino gravável de procfs, é abordada em [race de runtime no namespace de PID](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Checks

O objetivo destas verificações é determinar quais caminhos o runtime ocultou intencionalmente e se a workload atual ainda vê um sistema de arquivos voltado ao kernel com acesso reduzido.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Use uma verificação de montagem exata, pois um arquivo mascarado ainda pode existir e uma leitura pode retornar um resultado vazio de `/dev/null`. A ausência de um ponto de montagem é algo a investigar, não uma prova de que dados do host podem ser lidos. <sup>[[4]](#references)[[5]](#references)</sup>

O que é interessante aqui:

- Uma lista longa de caminhos mascarados é normal em runtimes reforçados.
- A ausência de mascaramento em entradas sensíveis do procfs merece uma análise mais detalhada.
- Se um caminho sensível estiver acessível e o contêiner também tiver capacidades fortes ou montagens amplas, a exposição é mais relevante.

## Padrões do runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Ativado por padrão | O Docker define uma lista padrão de caminhos mascarados | exposição de montagens host de proc/sys, `--privileged` |
| Podman | Ativado por padrão | O Podman aplica caminhos mascarados padrão, a menos que sejam desmascarados manualmente | `--security-opt unmask=ALL`, desmascaramento direcionado, `--privileged` |
| Kubernetes | Herda os padrões do runtime | Usa o comportamento de mascaramento do runtime subjacente, a menos que as configurações do Pod enfraqueçam a exposição do proc | `procMount: Unmasked` (requer `hostUsers: false` nas versões atuais), padrões de cargas de trabalho privilegiadas, montagens host amplas |
| containerd / CRI-O no Kubernetes | Padrão do runtime | Geralmente aplica caminhos mascarados do OCI/runtime, a menos que sejam substituídos | alterações diretas na configuração do runtime, mesmos caminhos de enfraquecimento do Kubernetes |

Os caminhos mascarados geralmente estão presentes por padrão. O principal problema operacional não é a ausência deles no runtime, mas o desmascaramento deliberado ou as montagens bind do host que anulam a proteção.

## References

- [1] [Iniciativa Open Container - Configuração de contêineres Linux: Caminhos mascarados](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Documentação do Podman - opções de segurança de `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Documentação do Kubernetes - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [Aviso do runc: corrida na origem de montagem de caminhos mascarados](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [Manual do findmnt(8)](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [Manual do keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}

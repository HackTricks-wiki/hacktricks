# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

**seccomp** é o mecanismo que permite ao kernel aplicar um filtro às syscalls que um processo pode invocar. Em ambientes containerizados, o seccomp normalmente é usado no modo de filtro, para que o processo não seja simplesmente marcado como "restrito" de forma vaga, mas esteja sujeito a uma política concreta de syscalls. Isso é importante porque muitos container breakouts exigem alcançar interfaces muito específicas do kernel. Se o processo não puder invocar com sucesso as syscalls relevantes, uma grande classe de ataques desaparece antes que qualquer nuance de namespace ou capability se torne relevante.

O modelo mental principal é simples: namespaces definem **o que o processo pode ver**, capabilities definem **quais ações privilegiadas o processo tem nominalmente permissão para tentar**, e o seccomp decide **se o kernel sequer aceitará o ponto de entrada da syscall para a ação tentada**. É por isso que o seccomp frequentemente impede ataques que, de outra forma, pareceriam possíveis com base apenas nas capabilities.

## Impacto na Segurança

Grande parte da superfície perigosa do kernel só pode ser alcançada por meio de um conjunto relativamente pequeno de syscalls. Exemplos que são repetidamente relevantes no hardening de containers incluem `mount`, `unshare`, `clone` ou `clone3` com flags específicas, `bpf`, `ptrace`, `keyctl` e `perf_event_open`. Um atacante que consiga alcançar essas syscalls pode ser capaz de criar novos namespaces, manipular subsistemas do kernel ou interagir com uma superfície de ataque que um container de aplicação normal não precisa usar.

É por isso que os perfis padrão de seccomp dos runtimes são tão importantes. Eles não são apenas uma "defesa adicional". Em muitos ambientes, são a diferença entre um container que pode exercer uma ampla parte da funcionalidade do kernel e outro que está limitado a uma superfície de syscalls mais próxima do que a aplicação realmente precisa.

## Modos e Construção de Filtros

Historicamente, o seccomp tinha um modo estrito no qual apenas um conjunto mínimo de syscalls permanecia disponível, mas o modo relevante para os container runtimes modernos é o modo de filtro do seccomp, frequentemente chamado de **seccomp-bpf**. Nesse modelo, o kernel avalia um programa de filtro que decide se uma syscall deve ser permitida, negada com um errno, interceptada, registrada em log ou usada para encerrar o processo. Os container runtimes usam esse mecanismo porque ele é expressivo o suficiente para bloquear classes amplas de syscalls perigosas e, ao mesmo tempo, permitir o comportamento normal das aplicações.

Dois exemplos de baixo nível são úteis porque tornam o mecanismo concreto, em vez de mágico. O modo estrito demonstra o antigo modelo de que "apenas um conjunto mínimo de syscalls sobrevive":
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
O `open` final faz com que o processo seja encerrado, pois não faz parte do conjunto mínimo do strict mode.

Um exemplo de filtro do libseccomp mostra mais claramente o modelo moderno de políticas:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Esse é o estilo de política que a maioria dos leitores deve imaginar quando pensa em profiles de seccomp em runtime.

## Laboratório

Uma maneira simples de confirmar que o seccomp está ativo em um container é:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Você também pode tentar uma operação que os perfis padrão geralmente restringem:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Se o container estiver sendo executado sob um perfil seccomp padrão normal, as operações no estilo de `unshare` geralmente serão bloqueadas. Esta é uma demonstração útil porque mostra que, mesmo que a ferramenta de userspace exista dentro da imagem, o caminho do kernel de que ela precisa ainda pode estar indisponível.
Se o container estiver sendo executado sob um perfil seccomp padrão normal, as operações no estilo de `unshare` geralmente serão bloqueadas, mesmo quando a ferramenta de userspace existe dentro da imagem.

Para inspecionar o status do processo de forma mais geral, execute:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Uso em Runtime

Docker oferece suporte a perfis seccomp padrão e personalizados e permite que os administradores os desabilitem com `--security-opt seccomp=unconfined`. Podman oferece suporte semelhante e frequentemente combina seccomp com execução rootless em uma postura padrão bastante sensata. Kubernetes expõe seccomp por meio da configuração da workload, onde `RuntimeDefault` geralmente é uma baseline sensata, enquanto `Unconfined` deve ser tratado como uma exceção que exige justificativa, e não como uma opção de conveniência.

Em ambientes baseados em containerd e CRI-O, o caminho exato é mais complexo, mas o princípio é o mesmo: o engine ou orquestrador de nível superior decide o que deve acontecer, e o runtime finalmente instala a política seccomp resultante para o processo do container. O resultado ainda depende da configuração final do runtime que chega ao kernel.

### Exemplo de Política Personalizada

Docker e engines semelhantes podem carregar um perfil seccomp personalizado a partir de JSON. Um exemplo mínimo que nega `chmod` enquanto permite todo o restante é:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Aplicado com:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
O comando falha com `Operation not permitted`, demonstrando que a restrição vem da política de syscall, e não apenas das permissões comuns de arquivos. Em hardening real, allowlists geralmente são mais fortes do que padrões permissivos com uma pequena blacklist.

## Misconfigurações

O erro mais direto é definir o seccomp como **unconfined** porque uma aplicação falhou sob a política padrão. Isso é comum durante a resolução de problemas e muito perigoso como correção permanente. Quando o filtro desaparece, muitos primitivos de breakout baseados em syscall tornam-se acessíveis novamente, especialmente quando capabilities poderosas ou o compartilhamento de namespaces do host também estão presentes.

Outro problema frequente é o uso de um **custom permissive profile** copiado de algum blog ou workaround interno sem uma revisão cuidadosa. Às vezes, as equipes mantêm quase todas as syscalls perigosas simplesmente porque o profile foi criado com o objetivo de "impedir que a aplicação falhe", em vez de "conceder apenas o que a aplicação realmente precisa". Outro equívoco é presumir que o seccomp é menos importante para containers non-root. Na realidade, uma grande parte da superfície de ataque do kernel continua relevante mesmo quando o processo não é UID 0.

## Abuso

Se o seccomp estiver ausente ou severamente enfraquecido, um atacante poderá conseguir invocar syscalls de criação de namespaces, expandir a superfície de ataque acessível do kernel por meio de `bpf` ou `perf_event_open`, abusar de `keyctl` ou combinar esses caminhos de syscall com capabilities perigosas, como `CAP_SYS_ADMIN`. Em muitos ataques reais, o seccomp não é o único controle ausente, mas sua ausência reduz drasticamente o caminho de exploração, pois remove uma das poucas defesas capazes de bloquear uma syscall arriscada antes mesmo que o restante do modelo de privilégios entre em ação.

O teste prático mais útil é tentar exatamente as famílias de syscall que os profiles padrão normalmente bloqueiam. Se elas funcionarem de repente, a postura de segurança do container mudou significativamente:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Se `CAP_SYS_ADMIN` ou outra capability poderosa estiver presente, teste se o seccomp é a única barreira ausente antes de um abuso baseado em mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Em alguns alvos, o objetivo imediato não é obter um escape completo, mas coletar informações e ampliar a superfície de ataque do kernel. Estes comandos ajudam a determinar se caminhos de syscall especialmente sensíveis estão acessíveis:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Se o seccomp estiver ausente e o container também tiver privilégios de outras formas, é nesse momento que faz sentido migrar para as técnicas mais específicas de breakout já documentadas nas páginas legadas de container-escape.

### Exemplo completo: seccomp era a única coisa bloqueando `unshare`

Em muitos alvos, o efeito prático de remover o seccomp é que syscalls de criação de namespace ou de mount começam a funcionar repentinamente. Se o container também tiver `CAP_SYS_ADMIN`, a sequência a seguir poderá ser possível:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
Por si só, isso ainda não é um escape do host, mas demonstra que o seccomp era a barreira que impedia a exploração relacionada a mount.

### Exemplo completo: seccomp desabilitado + `release_agent` do cgroup v1

Se o seccomp estiver desabilitado e o container puder montar hierarquias do cgroup v1, a técnica `release_agent` da seção sobre cgroups se torna acessível:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Este não é um exploit exclusivo do seccomp. O ponto é que, quando o seccomp fica sem restrições, cadeias de breakout com uso intenso de syscalls que antes eram bloqueadas podem começar a funcionar exatamente como foram escritas.

## Verificações

O objetivo destas verificações é determinar se o seccomp está ativo, se `no_new_privs` o acompanha e se a configuração do runtime mostra que o seccomp foi desabilitado explicitamente.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
O que é interessante aqui:

- Um valor não zero de `Seccomp` significa que a filtragem está ativa; `0` geralmente significa que não há proteção seccomp.
- Se as opções de segurança do runtime incluírem `seccomp=unconfined`, o workload perdeu uma de suas defesas mais úteis no nível de syscall.
- `NoNewPrivs` não é o próprio seccomp, mas a presença de ambos geralmente indica uma postura de hardening mais cuidadosa do que a ausência dos dois.

Se um container já tiver mounts suspeitos, capabilities amplas ou namespaces do host compartilhados, e o seccomp também estiver unconfined, essa combinação deve ser tratada como um importante sinal de escalation. O container pode ainda não ser trivialmente explorável, mas o número de pontos de entrada no kernel disponíveis para o atacante aumentou drasticamente.

## Padrões do Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Geralmente habilitado por padrão | Usa o perfil seccomp padrão integrado do Docker, a menos que seja substituído | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Geralmente habilitado por padrão | Aplica o perfil seccomp padrão do runtime, a menos que seja substituído | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Não garantido por padrão** | Se `securityContext.seccompProfile` não estiver definido, o padrão será `Unconfined`, a menos que o kubelet habilite `--seccomp-default`; `RuntimeDefault` ou `Localhost` devem ser definidos explicitamente caso contrário | `securityContext.seccompProfile.type: Unconfined`, deixar o seccomp indefinido em clusters sem `seccompDefault`, `privileged: true` |
| containerd / CRI-O no Kubernetes | Segue as configurações do node e do Pod no Kubernetes | O perfil do runtime é usado quando o Kubernetes solicita `RuntimeDefault` ou quando o default de seccomp do kubelet está habilitado | Igual à linha do Kubernetes; a configuração direta de CRI/OCI também pode omitir completamente o seccomp |

O comportamento do Kubernetes é o que mais costuma surpreender os operadores. Em muitos clusters, o seccomp ainda está ausente, a menos que o Pod o solicite ou que o kubelet esteja configurado para usar `RuntimeDefault` por padrão.
{{#include ../../../../banners/hacktricks-training.md}}

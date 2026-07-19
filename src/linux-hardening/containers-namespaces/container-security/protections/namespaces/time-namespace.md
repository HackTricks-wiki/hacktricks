# Namespace de tempo

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de tempo virtualiza relógios selecionados no estilo monotônico, em vez do relógio de parede do host. Na prática, isso significa offsets privados para **`CLOCK_MONOTONIC`** e **`CLOCK_BOOTTIME`**, além das visualizações intimamente relacionadas **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** e **`CLOCK_BOOTTIME_ALARM`**. Ele não virtualiza **`CLOCK_REALTIME`**, portanto `date` e a lógica de expiração de certificados continuam observando o relógio de parede do host, a menos que algum outro mecanismo interfira.

O objetivo principal é permitir que um processo observe offsets controlados de tempo decorrido sem alterar a visualização global de tempo do host. Isso é útil para workflows de checkpoint/restore, testes determinísticos e comportamentos avançados de runtime. Normalmente, ele não é um controle de isolamento de destaque da mesma forma que os namespaces de mount ou user, mas ainda contribui para tornar o ambiente do processo mais autocontido.

Do ponto de vista ofensivo, esse namespace geralmente é mais relevante para **reconnaissance, timer skew e entendimento do runtime** do que para um breakout direto. Ainda assim, ele é importante porque mais container runtimes e workflows de checkpoint/restore agora conseguem solicitá-lo explicitamente.

## Lab

Se o kernel do host e o userspace oferecerem suporte, você poderá inspecionar o namespace com:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
O suporte varia conforme as versões do kernel e das ferramentas, portanto esta página trata mais da compreensão do mecanismo do que da expectativa de que ele esteja visível em todos os ambientes de laboratório. A observação importante é que `date` ainda deve refletir o relógio de parede do host, enquanto os valores baseados em monotonic/boottime são os que mudam quando offsets diferentes de zero são configurados.

### Particularidade da Criação

Os time namespaces são um pouco incomuns em comparação com mount, PID ou network namespaces:

- `unshare(CLONE_NEWTIME)` cria um novo time namespace para **filhos futuros**.
- A task que chama permanece em seu time namespace atual.
- Portanto, `/proc/<pid>/ns/time_for_children` costuma ser mais interessante que `/proc/<pid>/ns/time` ao depurar a configuração do runtime.

A janela de escrita também é especial. Os offsets em `/proc/<pid>/timens_offsets` devem ser escritos antes que o novo time namespace seja totalmente populado com tasks em execução; na prática, os runtimes fazem isso durante a estreita janela de configuração entre a criação do namespace e o início do payload final. Quando uma task já está em execução nesse namespace, escritas posteriores falham com `EACCES`. É por isso que runtimes de baixo nível tratam a configuração do time namespace como uma etapa inicial de bootstrap, em vez de tentar aplicar patches nos offsets a partir de dentro de um processo de container já iniciado.

### Deslocamentos de Tempo

Os time namespaces do Linux expõem os offsets por namespace através de `/proc/<pid>/timens_offsets`. O formato consiste em um conjunto de nomes ou IDs de clocks, além de deltas de segundos/nanosegundos relativos ao time namespace inicial.

Na prática, o workflow mais confiável para o usuário é deixar que `unshare` escreva esses offsets por você:
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
O ponto importante não é a sintaxe exata do comando, mas o comportamento: um container pode observar uma visão semelhante à de uptime diferente sem alterar o relógio de parede do host.

### Flags auxiliares do `unshare`

Versões recentes do `util-linux` fornecem flags de conveniência que gravam os offsets automaticamente durante a criação do namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Essas flags são principalmente uma melhoria de usabilidade, mas também facilitam o reconhecimento do recurso em documentação, test harnesses e wrappers de runtime.

## Uso em Runtime

Time namespaces são mais recentes e menos testados universalmente do que mount ou PID namespaces. A OCI Runtime Specification v1.1 adicionou suporte explícito ao namespace `time` e ao campo `linux.timeOffsets`, e runtimes modernos podem mapear esses dados para o fluxo de bootstrap do kernel. Um fragmento mínimo de OCI é semelhante a:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Isso é importante porque transforma o time namespacing de uma primitiva de kernel de uso específico em algo que os runtimes podem solicitar de forma portável. Isso também explica por que os componentes internos do runtime precisam de uma etapa explícita de sincronização: o offset deve ser escrito em `/proc/<pid>/timens_offsets` antes que o payload do container entre completamente no novo namespace.

Stacks de checkpoint/restore, como o CRIU, são uma das principais razões práticas para a existência desse recurso. Sem time namespaces, restaurar uma workload pausada faria com que os clocks monotônicos e de tempo de boot avançassem pelo período em que a workload permaneceu suspensa.

## Impacto na Segurança

Há menos casos clássicos de breakout centrados no time namespace do que em outros tipos de namespace. O risco geralmente não é que o time namespace habilite diretamente um escape, mas que os leitores o ignorem completamente e, consequentemente, não percebam como runtimes avançados podem moldar o comportamento dos processos.

Em ambientes especializados, visões alteradas de tempo monotônico ou de boot podem afetar:

- comportamento de timeout e retry
- watchdogs e lógica de lease
- comportamento de `timerfd`, `nanosleep` e `clock_nanosleep`
- forensics de checkpoint/restore
- telemetria de tempo decorrido e heurísticas baseadas em uptime

Portanto, embora este raramente seja o primeiro namespace que você abuse, ele pode explicar perfeitamente comportamentos de timing "impossíveis" durante um assessment.

## Abuso

Geralmente não há uma primitiva direta de breakout aqui, mas o comportamento alterado dos clocks ainda pode ser útil para entender o ambiente de execução, identificar recursos avançados do runtime e encontrar lógicas baseadas em timers que são medidas em relação a clocks monotônicos, em vez do tempo de parede:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Se você estiver comparando dois processos, as diferenças aqui podem ajudar a explicar comportamentos estranhos de timing, artefatos de checkpoint/restore ou divergências de logging específicas do ambiente.

Ângulos relevantes para atacantes:

- confundir a lógica de backoff, sleep ou watchdog implementada com monotonic clocks
- explicar por que `/proc/uptime` e o comportamento orientado por timers discordam das expectativas de wall-clock no host
- reconhecer workflows de CRIU/checkpoint-restore e outros recursos avançados de runtime
- identificar ambientes nos quais ingressar no time namespace de um alvo com `nsenter -T -t <pid> -- ...` pode reproduzir o comportamento de timers local ao container para debugging ou post-exploitation

Impacto:

- quase sempre relacionado a reconnaissance ou à compreensão do ambiente
- útil para explicar anomalias de logging, uptime ou checkpoint/restore
- útil para analisar sleeps, retries e timers baseados em monotonic time
- normalmente não é, por si só, um mecanismo direto de container-escape

A nuance importante de abuse é que time namespaces não virtualizam `CLOCK_REALTIME`; portanto, por si só, não permitem que um atacante falsifique o wall clock do host nem quebre diretamente as verificações de expiração de certificados em todo o sistema. Seu valor está principalmente em confundir lógica baseada em monotonic time, reproduzir bugs específicos do ambiente ou compreender comportamentos avançados de runtime.

## Checks

Esses checks são principalmente para confirmar se o runtime está usando um time namespace privado e se ele realmente definiu offsets diferentes de zero.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
O que é interessante aqui:

- Em muitos ambientes, esses valores não levarão a uma finding de segurança imediata, mas informam se um recurso especializado do runtime está em uso.
- Se `time_for_children` for diferente de `time`, o chamador pode ter preparado um namespace de tempo exclusivo para filhos, no qual ele próprio não entrou.
- Se `date` corresponder ao host, mas os valores baseados em monotonic/boottime não corresponderem, provavelmente você está observando namespacing de tempo, e não adulteração do relógio de parede.
- Se você estiver comparando dois processos, as diferenças aqui podem explicar comportamentos confusos de timing ou de checkpoint/restore.

Para a maioria dos escapes de container, o namespace de tempo não é o primeiro controle que você investigará. Ainda assim, uma seção completa sobre container-security deve mencioná-lo, pois ele faz parte do modelo moderno do kernel e ocasionalmente é relevante em cenários avançados de runtime.

## Referências

- [Página de manual `time_namespaces(7)` do Linux](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}

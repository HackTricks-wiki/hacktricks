# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

O time namespace virtualiza clocks monotonic-style selecionados em vez do host wall clock. Na prática, isso significa offsets privados para **`CLOCK_MONOTONIC`** e **`CLOCK_BOOTTIME`**, além das views intimamente relacionadas **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** e **`CLOCK_BOOTTIME_ALARM`**. Ele **não** virtualiza **`CLOCK_REALTIME`**, então `date` e a lógica de certificate-expiry ainda observam o host wall clock, a menos que algum outro mecanismo interfira.

O objetivo principal é permitir que um processo observe offsets controlados de elapsed-time sem alterar a visão global de tempo do host. Isso é útil para workflows de checkpoint/restore, testes determinísticos e comportamento avançado de runtime. Normalmente, não é um controle de isolamento de destaque como mount ou user namespaces, mas ainda contribui para tornar o ambiente do processo mais autônomo.

Do ponto de vista ofensivo, esse namespace costuma ser mais relevante para **reconnaissance, timer skew e runtime understanding** do que para um breakout direto. Ainda assim, ele importa porque mais container runtimes e workflows de checkpoint/restore agora podem solicitá-lo explicitamente.

## Lab

Se o host kernel e o userspace suportarem isso, você pode inspecionar o namespace com:
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
O suporte varia conforme as versões do kernel e da ferramenta, então esta página é mais sobre entender o mecanismo do que esperar que ele fique visível em todo ambiente de laboratório. A observação importante é que `date` ainda deve refletir o clock wall do host, enquanto os valores baseados em monotonic/boottime são os que mudam quando offsets diferentes de zero são configurados.

### Creation Nuance

Time namespaces são um pouco incomuns em comparação com mount, PID ou network namespaces:

- `unshare(CLONE_NEWTIME)` cria um novo time namespace para **future children**.
- A task que chama permanece no seu time namespace atual.
- `/proc/<pid>/ns/time_for_children` é, portanto, muitas vezes mais interessante do que `/proc/<pid>/ns/time` ao depurar o runtime setup.

A janela de escrita também é especial. Os offsets em `/proc/<pid>/timens_offsets` devem ser escritos antes que o novo time namespace esteja totalmente populado com tasks em execução; na prática, runtimes fazem isso durante a janela estreita de setup entre a criação do namespace e o início do payload final. Uma vez que uma task já esteja em execução ali, escritas posteriores falham com `EACCES`. É por isso que runtimes de baixo nível tratam o setup de time-namespace como uma etapa inicial de bootstrap, em vez de tentar aplicar patches nos offsets a partir de dentro de um processo de container já iniciado.

### Time Offsets

Linux time namespaces expõem os offsets por namespace através de `/proc/<pid>/timens_offsets`. O formato é um conjunto de nomes ou IDs de clock, mais deltas de segundo/nanosecond relativos ao time namespace inicial.

Na prática, o fluxo mais confiável voltado ao usuário é deixar o `unshare` escrever esses offsets para você:
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
O ponto importante não é a sintaxe exata do comando, mas o comportamento: um container pode observar uma visão parecida com uptime diferente sem alterar o relógio do host.

### `unshare` Helper Flags

Versões recentes do `util-linux` fornecem flags de conveniência que escrevem os offsets automaticamente durante a criação do namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Esses flags são principalmente uma melhoria de usabilidade, mas também facilitam reconhecer o recurso em documentação, test harnesses e runtime wrappers.

## Runtime Usage

Time namespaces são mais novos e menos universalmente exercitados do que mount ou PID namespaces. OCI Runtime Specification v1.1 adicionou suporte explícito ao namespace `time` e ao campo `linux.timeOffsets`, e runtimes modernos podem mapear esses dados para o fluxo de bootstrap do kernel. Um fragmento OCI mínimo é assim:
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
Isso importa porque transforma o namespacing de tempo de um primitive de kernel de nicho em algo que runtimes podem solicitar de forma portátil. Também explica por que os internals do runtime precisam de uma etapa explícita de sincronização: o offset deve ser gravado em `/proc/<pid>/timens_offsets` antes que o payload do container entre totalmente no novo namespace.

Stacks de checkpoint/restore como CRIU são uma das principais razões do mundo real para isso existir. Sem time namespaces, restaurar um workload pausado faria os clocks monotonic e boot-time saltarem pela quantidade de tempo que o workload ficou suspenso.

## Security Impact

Há menos histórias clássicas de breakout centradas no time namespace do que em outros tipos de namespace. O risco aqui geralmente não é que o time namespace permita escape diretamente, mas que os leitores o ignorem completamente e, assim, deixem passar como runtimes avançados podem estar moldando o comportamento dos processos.

Em ambientes especializados, visões alteradas de monotonic ou boottime podem afetar:

- timeout e retry behavior
- watchdogs and lease logic
- `timerfd`, `nanosleep`, e `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry e heurísticas baseadas em uptime

Então, embora este raramente seja o primeiro namespace que você abusa, ele pode בהחלט explicar comportamento de timing "impossível" durante uma assessment.

## Abuse

Normalmente não há um primitive de breakout direto aqui, mas o comportamento alterado do clock ainda pode ser útil para entender o ambiente de execução, identificar advanced runtime features e detectar lógica baseada em timer que é medida contra clocks monotonic em vez de wall clock time:
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
Se você estiver comparando dois processos, diferenças aqui podem ajudar a explicar comportamento estranho de timing, artefatos de checkpoint/restore ou inconsistências de logging específicas do ambiente.

Ângulos práticos relevantes para o atacante:

- confundir lógica de backoff, sleep ou watchdog implementada com monotonic clocks
- explicar por que `/proc/uptime` e o comportamento guiado por timer discordam das expectativas de wall-clock do host
- reconhecer workflows de CRIU/checkpoint-restore e outros recursos avançados do runtime
- identificar ambientes onde juntar um target time namespace com `nsenter -T -t <pid> -- ...` pode reproduzir o comportamento de timer local do container para debugging ou post-exploitation

Impacto:

- quase sempre reconnaissance ou entendimento do ambiente
- útil para explicar anomalias de logging, uptime ou checkpoint/restore
- útil para analisar sleeps, retries e timers baseados em monotonic-time
- normalmente não é, por si só, um mecanismo direto de container-escape

A nuance importante de abuso é que time namespaces não virtualizam `CLOCK_REALTIME`, então eles não permitem, por si só, que um atacante falsifique o wall clock do host ou quebre diretamente verificações de expiração de certificado em todo o sistema. Seu valor está principalmente em confundir lógica baseada em monotonic-time, reproduzir bugs específicos do ambiente ou entender comportamento avançado do runtime.

## Checks

Esses checks servem principalmente para confirmar se o runtime está usando um private time namespace e se ele realmente definiu offsets não zero.
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

- Em muitos ambientes, esses valores não levarão a uma descoberta de segurança imediata, mas indicam se um recurso de runtime especializado está em uso.
- Se `time_for_children` for diferente de `time`, o caller pode ter preparado um time namespace apenas para filhos que ele próprio não entrou.
- Se `date` совпidir com o host, mas os valores baseados em monotonic/boottime não, você provavelmente está olhando para time namespacing em vez de adulteração do wall-clock.
- Se você estiver comparando dois processes, diferenças aqui podem explicar timing confuso ou comportamento de checkpoint/restore.

Para a maioria dos container breakouts, o time namespace não é o primeiro controle que você investigará. Ainda assim, uma seção completa de container-security deve mencioná-lo porque ele faz parte do modelo moderno do kernel e, ocasionalmente, importa em cenários avançados de runtime.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}

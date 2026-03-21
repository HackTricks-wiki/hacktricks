# Namespace de Tempo

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de tempo virtualiza relógios selecionados, especialmente **`CLOCK_MONOTONIC`** e **`CLOCK_BOOTTIME`**. É um namespace mais recente e mais especializado do que mount, PID, network, ou user namespaces, e raramente é a primeira coisa em que um operador pensa ao discutir hardening de containers. Ainda assim, faz parte da família moderna de namespaces e vale a pena entender conceptualmente.

O objetivo principal é permitir que um processo observe deslocamentos controlados para certos relógios sem alterar a visão de tempo global do host. Isso é útil para workflows de checkpoint/restore, testes determinísticos e algum comportamento avançado em runtime. Geralmente não é um controle de isolamento de destaque da mesma forma que os mount ou user namespaces, mas ainda contribui para tornar o ambiente do processo mais autocontido.

## Laboratório

Se o kernel do host e o userspace oferecerem suporte, você pode inspecionar o namespace com:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
O suporte varia conforme a versão do kernel e das ferramentas, então esta página trata mais de entender o mecanismo do que de esperar que ele esteja visível em todo ambiente de laboratório.

### Deslocamentos de tempo

Namespaces de tempo do Linux virtualizam deslocamentos para `CLOCK_MONOTONIC` e `CLOCK_BOOTTIME`. Os deslocamentos atuais por namespace são expostos em `/proc/<pid>/timens_offsets`, que em kernels com suporte também podem ser modificados por um processo que possua `CAP_SYS_TIME` dentro do namespace relevante:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
O arquivo contém deltas em nanossegundos. Ajustar `monotonic` em dois dias altera observações do tipo 'uptime' dentro desse namespace sem alterar o relógio de parede do host.

### `unshare` Flags auxiliares

Versões recentes do `util-linux` fornecem flags convenientes que escrevem os offsets automaticamente:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Essas flags são, na maior parte, uma melhoria de usabilidade, mas também facilitam reconhecer o recurso na documentação e nos testes.

## Uso em tempo de execução

Os namespaces `time` são mais recentes e menos amplamente exercitados do que os namespaces `mount` ou `PID`. OCI Runtime Specification v1.1 adicionou suporte explícito para o namespace `time` e o campo `linux.timeOffsets`, e versões mais recentes do `runc` implementam essa parte do modelo. Um fragmento OCI mínimo fica assim:
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
Isso importa porque transforma time namespacing de uma primitiva de kernel de nicho em algo que os runtimes podem solicitar de forma portátil.

## Impacto de Segurança

Existem menos relatos clássicos de breakout centrados no time namespace do que em outros tipos de namespace. O risco aqui normalmente não é que o time namespace permita diretamente um escape, mas sim que os leitores o ignorem completamente e, portanto, deixem de perceber como runtimes avançados podem estar moldando o comportamento dos processos. Em ambientes especializados, visões de relógio alteradas podem afetar checkpoint/restore, observability ou suposições forenses.

## Abuso

Normalmente não há uma breakout primitive direta aqui, mas comportamento de relógio alterado ainda pode ser útil para entender o execution environment e identificar recursos avançados do runtime:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Se você estiver comparando dois processos, diferenças aqui podem ajudar a explicar comportamentos estranhos de temporização, artefatos de checkpoint/restore ou incompatibilidades de logging específicas do ambiente.

Impacto:

- quase sempre reconhecimento ou compreensão do ambiente
- útil para explicar anomalias em logs, tempo de atividade (uptime) ou em checkpoint/restore
- normalmente não é, por si só, um mecanismo direto de container-escape

A nuance importante de abuso é que os namespaces de tempo não virtualizam `CLOCK_REALTIME`, portanto não permitem, por si só, que um atacante falsifique o relógio do host (wall clock) ou quebre diretamente verificações de expiração de certificados em todo o sistema. Seu valor está principalmente em confundir lógica baseada em tempo monotônico, reproduzir bugs específicos do ambiente ou entender comportamento avançado do runtime.

## Verificações

Essas verificações tratam principalmente de confirmar se o runtime está usando um namespace de tempo privado.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
O que é interessante aqui:

- Em muitos ambientes, esses valores não levarão a um achado de segurança imediato, mas informam se um recurso de runtime especializado está em uso.
- Se você estiver comparando dois processos, diferenças aqui podem explicar comportamentos confusos de timing ou de checkpoint/restore.

Para a maioria dos container breakouts, o time namespace não é o primeiro controle que você investigará. Ainda assim, uma seção completa de container-security deve mencioná-lo porque ele faz parte do modelo moderno do kernel e ocasionalmente é relevante em cenários avançados de runtime.

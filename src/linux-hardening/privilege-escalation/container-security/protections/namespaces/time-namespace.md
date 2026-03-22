# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O time namespace virtualiza relógios selecionados, especialmente **`CLOCK_MONOTONIC`** e **`CLOCK_BOOTTIME`**. É um namespace mais recente e mais especializado do que os namespaces mount, PID, network ou user, e raramente é a primeira coisa em que um operador pensa ao discutir hardening de containers. Ainda assim, faz parte da família moderna de namespaces e vale a pena compreendê-lo conceitualmente.

O principal objetivo é permitir que um processo observe offsets controlados para certos relógios sem alterar a visão de tempo global do host. Isso é útil para fluxos de trabalho de checkpoint/restore, testes determinísticos e alguns comportamentos avançados de runtime. Geralmente não é um controle de isolamento de destaque do mesmo modo que os namespaces mount ou user, mas ainda contribui para tornar o ambiente do processo mais autocontido.

## Laboratório

Se o kernel e o userspace do host suportarem, você pode inspecionar o namespace com:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Support varies by kernel and tool versions, so this page is more about understanding the mechanism than expecting it to be visible in every lab environment.

### Deslocamentos de tempo

Os namespaces de tempo do Linux virtualizam os deslocamentos para `CLOCK_MONOTONIC` e `CLOCK_BOOTTIME`. Os deslocamentos atuais por namespace são expostos através de `/proc/<pid>/timens_offsets`, os quais em kernels com suporte também podem ser modificados por um processo que detenha `CAP_SYS_TIME` dentro do namespace relevante:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
O arquivo contém deltas em nanossegundos. Ajustar `monotonic` em dois dias altera observações do tipo uptime dentro desse namespace sem alterar o wall clock do host.

### Flags auxiliares do `unshare`

Versões recentes do `util-linux` fornecem flags de conveniência que escrevem os offsets automaticamente:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Essas flags são principalmente uma melhoria de usabilidade, mas também tornam mais fácil reconhecer o recurso na documentação e nos testes.

## Runtime Usage

Time namespaces são mais recentes e menos amplamente utilizadas do que mount ou PID namespaces. OCI Runtime Specification v1.1 adicionou suporte explícito para o `time` namespace e o campo `linux.timeOffsets`, e versões mais recentes do `runc` implementam essa parte do modelo. Um fragmento OCI mínimo fica assim:
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
Isto importa porque transforma o time namespacing de uma primitiva do kernel de nicho em algo que runtimes podem solicitar de forma portátil.

## Security Impact

Existem menos casos clássicos de breakout centrados no time namespace do que em outros tipos de namespace. O risco aqui geralmente não é que o time namespace habilite diretamente um escape, mas que leitores o ignorem completamente e, portanto, deixem de perceber como runtimes avançados podem estar moldando o comportamento dos processos. Em ambientes especializados, visões de relógio alteradas podem afetar checkpoint/restore, observabilidade ou suposições forenses.

## Abuse

Normalmente não existe um breakout primitive direto aqui, mas o comportamento de relógio alterado ainda pode ser útil para entender o ambiente de execução e identificar recursos avançados do runtime:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Se você estiver comparando dois processos, diferenças aqui podem ajudar a explicar comportamento estranho de temporização, artefatos de checkpoint/restore ou discrepâncias de logging específicas do ambiente.

Impacto:

- quase sempre reconnaissance ou entendimento do ambiente
- útil para explicar logging, uptime ou anomalias de checkpoint/restore
- normalmente não é um mecanismo direto de container-escape por si só

A nuance importante de abuso é que namespaces de tempo não virtualizam `CLOCK_REALTIME`, então eles por si só não permitem que um atacante falsifique o relógio do host nem quebrem diretamente verificações de expiração de certificados em todo o sistema. Seu valor está principalmente em confundir lógica baseada em tempo monotônico, reproduzir bugs específicos do ambiente ou entender comportamento avançado do runtime.

## Verificações

Estas verificações tratam principalmente de confirmar se o runtime está usando de fato um namespace de tempo privado.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
O que é interessante aqui:

- Em muitos ambientes, esses valores não levarão a uma descoberta de segurança imediata, mas indicam se um recurso de runtime especializado está em uso.
- Se você estiver comparando dois processos, diferenças aqui podem explicar comportamento confuso de timing ou de checkpoint/restore.

Para a maioria dos container breakouts, o time namespace não é o primeiro controle que você investigará. Ainda assim, uma seção completa de container-security deve mencioná-lo porque ele faz parte do modelo moderno do kernel e ocasionalmente é relevante em cenários avançados de runtime.
{{#include ../../../../../banners/hacktricks-training.md}}

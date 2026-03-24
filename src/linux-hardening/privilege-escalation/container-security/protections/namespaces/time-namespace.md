# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão Geral

O time namespace virtualiza relógios selecionados, especialmente **`CLOCK_MONOTONIC`** e **`CLOCK_BOOTTIME`**. É um namespace mais novo e mais especializado do que os namespaces mount, PID, network ou user, e raramente é a primeira coisa em que um operador pensa ao discutir hardening de containers. Ainda assim, faz parte da família moderna de namespaces e vale a pena entendê-lo conceitualmente.

## Lab

Se o kernel do host e o userspace o suportarem, você pode inspecionar o namespace com:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
O suporte varia conforme as versões do kernel e das ferramentas, então esta página trata mais de entender o mecanismo do que de esperar que ele esteja visível em todos os ambientes de laboratório.

### Deslocamentos de tempo

Os namespaces de tempo do Linux virtualizam deslocamentos para `CLOCK_MONOTONIC` e `CLOCK_BOOTTIME`. Os deslocamentos atuais por namespace são expostos através de `/proc/<pid>/timens_offsets`, que em kernels com suporte também pode ser modificado por um processo que detenha `CAP_SYS_TIME` dentro do namespace relevante:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
O arquivo contém deltas em nanosegundos. Ajustar `monotonic` em dois dias altera observações semelhantes ao uptime dentro desse namespace sem alterar o relógio do host.

### Flags auxiliares do `unshare`

Versões recentes do `util-linux` fornecem flags de conveniência que escrevem os offsets automaticamente:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Essas flags são principalmente uma melhoria de usabilidade, mas também tornam mais fácil reconhecer o recurso na documentação e nos testes.

## Uso em tempo de execução

Time namespaces são mais recentes e menos amplamente utilizados do que os namespaces mount ou PID. OCI Runtime Specification v1.1 adicionou suporte explícito para o `time` namespace e o campo `linux.timeOffsets`, e versões mais recentes do `runc` implementam essa parte do modelo. Um fragmento OCI mínimo fica assim:
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
Isto importa porque transforma o time namespacing de um primitivo de kernel de nicho em algo que runtimes podem solicitar de forma portátil.

## Impacto de Segurança

Existem menos histórias clássicas de breakout centradas no time namespace do que em outros tipos de namespace. O risco aqui geralmente não é que o time namespace permita diretamente um escape, mas que os leitores o ignorem completamente e, portanto, deixem de notar como runtimes avançados podem estar moldando o comportamento dos processos. Em ambientes especializados, visões de relógio alteradas podem afetar checkpoint/restore, observability ou suposições forenses.

## Abuso

Normalmente não existe um primitivo de breakout direto aqui, mas o comportamento de relógio alterado ainda pode ser útil para entender o ambiente de execução e identificar funcionalidades avançadas do runtime:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Se você estiver comparando dois processos, diferenças aqui podem ajudar a explicar comportamentos de temporização estranhos, artefatos de checkpoint/restore, ou incompatibilidades de logging específicas do ambiente.

Impact:

- quase sempre reconnaissance ou compreensão do ambiente
- útil para explicar logs, uptime ou anomalias de checkpoint/restore
- normalmente não é um mecanismo direto de container-escape por si só

A nuance importante de abuso é que time namespaces não virtualizam `CLOCK_REALTIME`, então eles por si só não permitem que um atacante falsifique o relógio do host ou quebre diretamente verificações de expiração de certificados em todo o sistema. Seu valor está principalmente em confundir lógica baseada em monotonic-time, reproduzir bugs específicos do ambiente ou entender comportamento avançado do runtime.

## Checks

Essas verificações tratam principalmente de confirmar se o runtime está usando um time namespace privado.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
- Em muitos ambientes, esses valores não resultarão em um achado de segurança imediato, mas indicam se um recurso especializado de runtime está em uso.
- Se você estiver comparando dois processos, diferenças aqui podem explicar timing confuso ou comportamento de checkpoint/restore.

Para a maioria dos container breakouts, o time namespace não é o primeiro controle que você investigará. Ainda assim, uma seção completa de container-security deve mencioná-lo porque ele faz parte do modelo moderno do kernel e ocasionalmente é relevante em cenários avançados de runtime.
{{#include ../../../../../banners/hacktricks-training.md}}

# Thread Injection via Task port no macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Inicialmente, a função `task_threads()` é invocada na task port para obter uma lista de threads da task remota. Um thread é selecionado para hijacking. Essa abordagem diverge dos métodos convencionais de code injection, pois a criação de um novo thread remoto é proibida devido à mitigation que bloqueia `thread_create_running()`.<sup>[[1]](#references)</sup>

Para controlar o thread, `thread_suspend()` é chamado, interrompendo sua execução.<sup>[[1]](#references)</sup>

As únicas operações permitidas no thread remoto envolvem **pará-lo** e **iniciá-lo**, além de **obter**/**modificar** os valores de seus registradores. Chamadas de funções remotas são iniciadas definindo os registradores `x0` a `x7` como os **argumentos**, configurando `pc` para apontar para a função desejada e retomando o thread. Garantir que o thread não sofra um crash após o retorno exige a detecção desse retorno.<sup>[[1]](#references)</sup>

Uma estratégia envolve registrar um **exception handler** para o thread remoto usando `thread_set_exception_ports()`, definindo o registrador `lr` como um endereço inválido antes da chamada da função. Isso aciona uma exception após a execução da função, enviando uma mensagem para a exception port e permitindo a inspeção do estado do thread para recuperar o valor de retorno. Como alternativa, conforme adotado do exploit *triple_fetch* de Ian Beer, `lr` é definido para executar um loop infinito; os registradores do thread são então monitorados continuamente até que `pc` aponte para essa instrução.<sup>[[1]](#references)</sup>

## 2. Mach ports para comunicação

A fase seguinte envolve o estabelecimento de Mach ports para facilitar a comunicação com o thread remoto. Essas ports são fundamentais para transferir send/receive rights arbitrários entre tasks.<sup>[[1]](#references)</sup>

Para comunicação bidirecional, dois Mach receive rights são criados: um na task local e outro na task remota. Em seguida, um send right para cada port é transferido para a task correspondente, permitindo a troca de mensagens.<sup>[[1]](#references)</sup>

Focando na port local, o receive right é mantido pela task local. A port é criada com `mach_port_allocate()`. O desafio está em transferir um send right para essa port para dentro da task remota.<sup>[[1]](#references)</sup>

Uma estratégia envolve aproveitar `thread_set_special_port()` para colocar um send right para a port local na `THREAD_KERNEL_PORT` do thread remoto. Em seguida, o thread remoto é instruído a chamar `mach_thread_self()` para obter o send right.<sup>[[1]](#references)</sup>

Para a port remota, o processo é essencialmente revertido. O thread remoto é direcionado a gerar uma Mach port por meio de `mach_reply_port()` (pois `mach_port_allocate()` não é adequado devido ao seu mecanismo de retorno). Após a criação da port, `mach_port_insert_right()` é invocado no thread remoto para estabelecer um send right. Esse right é então armazenado no kernel usando `thread_set_special_port()`. De volta à task local, `thread_get_special_port()` é usado no thread remoto para obter um send right para a Mach port recém-alocada na task remota.<sup>[[1]](#references)</sup>

A conclusão dessas etapas resulta no estabelecimento das Mach ports, preparando a base para a comunicação bidirecional.<sup>[[1]](#references)</sup>

## 3. Primitivas básicas de Memory Read/Write

Nesta seção, o foco está na utilização da execute primitive para estabelecer primitivas básicas de memory read/write. Essas etapas iniciais são cruciais para obter mais controle sobre o processo remoto, embora as primitives nesta fase não tenham muitas utilidades. Em breve, elas serão atualizadas para versões mais avançadas.<sup>[[1]](#references)</sup>

### Leitura e escrita de memória usando a execute primitive

O objetivo é realizar leitura e escrita de memória usando funções específicas. Para **ler a memória**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Envie o texto que deseja traduzir.
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Estas funções correspondem ao seguinte assembly:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identificando funções adequadas

Uma análise de bibliotecas comuns revelou candidatos apropriados para essas operações:<sup>[[1]](#references)</sup>

1. **Leitura de memória — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Escrita na memória — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Para realizar uma escrita de 64 bits em um endereço arbitrário:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Com essas primitivas estabelecidas, o cenário está pronto para a criação de memória compartilhada, representando um avanço significativo no controle do processo remoto.<sup>[[1]](#references)</sup>

## 4. Configuração da memória compartilhada

O objetivo é estabelecer memória compartilhada entre as tasks local e remota, simplificando a transferência de dados e facilitando a chamada de funções com múltiplos argumentos. A abordagem utiliza `libxpc` e seu tipo de objeto `OS_xpc_shmem`, construído sobre Mach memory entries.<sup>[[1]](#references)</sup>

### Visão geral do processo

1. **Alocação de memória**
* Aloque memória para compartilhamento usando `mach_vm_allocate()`.
* Use `xpc_shmem_create()` para criar um objeto `OS_xpc_shmem` para a região alocada.
2. **Criação da memória compartilhada no processo remoto**
* Aloque memória para o objeto `OS_xpc_shmem` no processo remoto (`remote_malloc`).
* Copie o objeto template local; ainda é necessário corrigir o Mach send right incorporado no offset `0x18`.
3. **Correção da Mach memory entry**
* Insira um send right com `thread_set_special_port()` e sobrescreva o campo `0x18` com o nome da entry remota.
4. **Finalização**
* Valide o objeto remoto e mapeie-o com uma chamada remota para `xpc_shmem_remote()`.

## 5. Obtendo controle total

Quando a execução arbitrária e um shared-memory back-channel estão disponíveis, você efetivamente assume o controle do processo-alvo:<sup>[[1]](#references)</sup>

* **Leitura/gravação arbitrária de memória** — use `memcpy()` entre regiões locais e compartilhadas.
* **Chamadas de funções com > 8 args** — coloque os argumentos adicionais na stack seguindo a convenção de chamada arm64.
* **Transferência de Mach ports** — passe rights em mensagens Mach por meio das ports estabelecidas.
* **Transferência de file descriptors** — utilize fileports (consulte *triple_fetch*).

Tudo isso está encapsulado na library [`threadexec`](https://github.com/bazad/threadexec) para facilitar a reutilização.

---

## 6. Particularidades do Apple Silicon (arm64e)

Em dispositivos Apple Silicon (arm64e), os **Pointer Authentication Codes (PAC)** protegem todos os endereços de retorno e muitos function pointers. Técnicas de thread-hijacking que *reutilizam código existente* continuam funcionando porque os valores originais em `lr`/`pc` já contêm assinaturas PAC válidas. Os problemas surgem quando você tenta saltar para uma memória controlada pelo atacante:

1. Aloque memória executável dentro do alvo (`mach_vm_allocate` remoto + `mprotect(PROT_EXEC)`).
2. Copie seu payload.
3. Dentro do processo *remoto*, assine o pointer:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Defina `pc = ptr` no estado da thread sequestrada.

Como alternativa, mantenha a conformidade com PAC encadeando gadgets/funções existentes (ROP tradicional).

## 7. Detecção e Hardening com EndpointSecurity

O framework **EndpointSecurity (ES)** expõe eventos do kernel que permitem aos defensores observar ou bloquear tentativas de thread injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – acionado quando um processo solicita a port de outra task (por exemplo, `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – emitido sempre que uma thread é criada em uma *task* diferente.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (adicionado no macOS 14 Sonoma) – indica a manipulação dos registradores de uma thread existente.

Cliente Swift mínimo que imprime eventos de remote thread:
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
Consultando com **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Considerações sobre hardened runtime

Distribuir sua aplicação **sem** o entitlement `com.apple.security.get-task-allow` impede que attackers não-root obtenham seu task-port. O System Integrity Protection (SIP) ainda bloqueia o acesso a muitos binários da Apple, mas softwares de terceiros precisam optar por não participar explicitamente.

## 8. Ferramentas públicas recentes (2023-2025)

| Tool | Ano | Observações |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | PoC compacto que demonstra thread hijacking compatível com PAC no Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | Helper do EndpointSecurity usado por vários fornecedores de EDR para expor eventos `REMOTE_THREAD_CREATE` |

> Ler o código-fonte desses projetos é útil para entender as mudanças de API introduzidas no macOS 13/14 e manter a compatibilidade entre Intel ↔ Apple Silicon.

## References

- [1] [Contornando restrições de binários da plataforma com task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Documentação do Apple Developer](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
{{#include ../../../../banners/hacktricks-training.md}}

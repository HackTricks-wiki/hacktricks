# Thread Injection no macOS via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Código

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Inicialmente, a função `task_threads()` é invocada na task port para obter uma lista de threads da task remota. Uma thread é selecionada para o hijacking. Essa abordagem diverge dos métodos convencionais de code injection, pois a criação de uma nova thread remota é proibida devido à mitigation que bloqueia `thread_create_running()`.<sup>[[1]](#references)</sup>

Para controlar a thread, `thread_suspend()` é chamada, interrompendo sua execução.<sup>[[1]](#references)</sup>

As únicas operações permitidas na thread remota envolvem **pará-la** e **iniciá-la**, além de **obter**/**modificar** seus valores de registradores. Chamadas de funções remotas são iniciadas definindo os registradores `x0` a `x7` como os **argumentos**, configurando `pc` para apontar para a função desejada e retomando a execução da thread. Para garantir que a thread não sofra um crash após o retorno, é necessário detectar esse retorno.<sup>[[1]](#references)</sup>

Uma estratégia consiste em registrar um **exception handler** para a thread remota usando `thread_set_exception_ports()`, definindo o registrador `lr` como um endereço inválido antes da chamada da função. Isso dispara uma exception após a execução da função, enviando uma mensagem para a exception port e permitindo inspecionar o estado da thread para recuperar o valor de retorno. Alternativamente, conforme adotado do exploit *triple_fetch* de Ian Beer, `lr` é configurado para entrar em um loop infinito; os registradores da thread são então monitorados continuamente até que `pc` aponte para essa instrução.<sup>[[1]](#references)</sup>

## 2. Mach ports para comunicação

A fase seguinte envolve o estabelecimento de Mach ports para facilitar a comunicação com a thread remota. Essas ports são utilizadas para transferir arbitrary send/receive rights entre tasks.<sup>[[1]](#references)</sup>

Para a comunicação bidirecional, são criados dois Mach receive rights: um na task local e outro na task remota. Em seguida, um send right de cada port é transferido para a task correspondente, permitindo a troca de mensagens.<sup>[[1]](#references)</sup>

Considerando a port local, o receive right é mantido pela task local. A port é criada com `mach_port_allocate()`. O desafio está em transferir um send right dessa port para a task remota.<sup>[[1]](#references)</sup>

Uma estratégia consiste em utilizar `thread_set_special_port()` para colocar um send right da port local na `THREAD_KERNEL_PORT` da thread remota. Em seguida, a thread remota recebe instruções para chamar `mach_thread_self()` e obter o send right.<sup>[[1]](#references)</sup>

Para a port remota, o processo é essencialmente invertido. A thread remota é instruída a gerar uma Mach port por meio de `mach_reply_port()` (pois `mach_port_allocate()` é inadequada devido ao seu mecanismo de retorno). Após a criação da port, `mach_port_insert_right()` é invocada na thread remota para estabelecer um send right. Esse right é então armazenado no kernel usando `thread_set_special_port()`. De volta à task local, `thread_get_special_port()` é usado na thread remota para adquirir um send right para a Mach port recém-alocada na task remota.<sup>[[1]](#references)</sup>

A conclusão dessas etapas resulta no estabelecimento das Mach ports, preparando a base para a comunicação bidirecional.<sup>[[1]](#references)</sup>

## 3. Primitives básicas de Memory Read/Write

Nesta seção, o foco está na utilização da execute primitive para estabelecer primitives básicas de memory read/write. Essas etapas iniciais são cruciais para obter mais controle sobre o processo remoto, embora as primitives neste estágio não tenham muitas utilidades. Em breve, elas serão atualizadas para versões mais avançadas.<sup>[[1]](#references)</sup>

### Leitura e escrita de memória usando a execute primitive

O objetivo é realizar leitura e escrita de memória usando funções específicas. Para **ler memória**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Para **writing memory**:
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
Para realizar uma gravação de 64 bits em um endereço arbitrário:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Com esses primitives estabelecidos, o cenário está pronto para a criação de memória compartilhada, representando um avanço significativo no controle do processo remoto.<sup>[[1]](#references)</sup>

## 4. Configuração da memória compartilhada

O objetivo é estabelecer memória compartilhada entre as tasks local e remota, simplificando a transferência de dados e facilitando a chamada de funções com múltiplos argumentos. A abordagem utiliza `libxpc` e seu tipo de objeto `OS_xpc_shmem`, baseado em Mach memory entries.<sup>[[1]](#references)</sup>

### Visão geral do processo

1. **Alocação de memória**
* Alocar memória para compartilhamento usando `mach_vm_allocate()`.
* Usar `xpc_shmem_create()` para criar um objeto `OS_xpc_shmem` para a região alocada.
2. **Criação da memória compartilhada no processo remoto**
* Alocar memória para o objeto `OS_xpc_shmem` no processo remoto (`remote_malloc`).
* Copiar o objeto template local; ainda é necessário corrigir o Mach send right incorporado no offset `0x18`.
3. **Correção da Mach memory entry**
* Inserir um send right com `thread_set_special_port()` e sobrescrever o campo `0x18` com o nome da entry remota.
4. **Finalização**
* Validar o objeto remoto e mapeá-lo com uma chamada remota para `xpc_shmem_remote()`.

## 5. Obtendo controle total

Assim que a execução arbitrária e um back-channel de memória compartilhada estiverem disponíveis, você efetivamente controla o processo-alvo:<sup>[[1]](#references)</sup>

* **Leitura/escrita arbitrária de memória** — usar `memcpy()` entre regiões locais e compartilhadas.
* **Chamadas de função com > 8 argumentos** — colocar os argumentos adicionais na stack seguindo a convenção de chamada arm64.
* **Transferência de Mach port** — passar rights em Mach messages por meio das ports estabelecidas.
* **Transferência de descritores de arquivo** — utilizar fileports (consulte *triple_fetch*).

Tudo isso é encapsulado na biblioteca [`threadexec`](https://github.com/bazad/threadexec) para facilitar a reutilização.

---

## 6. Particularidades do Apple Silicon (arm64e)

Em dispositivos Apple Silicon (arm64e), **Pointer Authentication Codes (PAC)** protegem todos os endereços de retorno e muitos function pointers. Técnicas de thread-hijacking que *reutilizam código existente* continuam funcionando porque os valores originais em `lr`/`pc` já contêm assinaturas PAC válidas. Os problemas surgem quando você tenta saltar para memória controlada pelo atacante:

1. Alocar memória executável dentro do alvo (`mach_vm_allocate` remoto + `mprotect(PROT_EXEC)`).
2. Copiar seu payload.
3. Dentro do processo *remoto*, assinar o ponteiro:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Defina `pc = ptr` no estado da thread sequestrada.

Como alternativa, permaneça compatível com PAC encadeando gadgets/funções existentes (ROP tradicional).

## 7. Detecção e Hardening com EndpointSecurity

O framework **EndpointSecurity (ES)** expõe eventos do kernel que permitem aos defensores observar ou bloquear tentativas de thread injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – acionado quando um processo solicita a porta da task de outro processo (por exemplo, `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – emitido sempre que uma thread é criada em uma *task* diferente.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (adicionado no macOS 14 Sonoma) – indica a manipulação de registradores de uma thread existente.

Cliente Swift mínimo que exibe eventos de remote-thread:
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

Distribuir sua aplicação **sem** o entitlement `com.apple.security.get-task-allow` impede que atacantes não-root obtenham seu task-port. O System Integrity Protection (SIP) ainda bloqueia o acesso a muitos binários da Apple, mas softwares de terceiros precisam optar por não participar explicitamente.

## 8. Ferramentas públicas recentes (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | PoC compacto que demonstra thread hijacking com reconhecimento de PAC no Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | Helper do EndpointSecurity usado por vários fornecedores de EDR para expor eventos `REMOTE_THREAD_CREATE` |

> Ler o código-fonte desses projetos é útil para entender as mudanças de API introduzidas no macOS 13/14 e manter a compatibilidade entre Intel ↔ Apple Silicon.

## Referências

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}

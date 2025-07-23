# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Código

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Sequestro de Thread

Inicialmente, a função `task_threads()` é invocada na porta da tarefa para obter uma lista de threads da tarefa remota. Uma thread é selecionada para sequestro. Essa abordagem diverge dos métodos convencionais de injeção de código, pois criar uma nova thread remota é proibido devido à mitigação que bloqueia `thread_create_running()`.

Para controlar a thread, `thread_suspend()` é chamada, interrompendo sua execução.

As únicas operações permitidas na thread remota envolvem **parar** e **iniciar** e **recuperar**/**modificar** seus valores de registradores. Chamadas de função remotas são iniciadas configurando os registradores `x0` a `x7` para os **argumentos**, configurando `pc` para direcionar à função desejada e retomando a thread. Garantir que a thread não falhe após o retorno requer a detecção do retorno.

Uma estratégia envolve registrar um **manipulador de exceção** para a thread remota usando `thread_set_exception_ports()`, definindo o registrador `lr` para um endereço inválido antes da chamada da função. Isso aciona uma exceção após a execução da função, enviando uma mensagem para a porta de exceção, permitindo a inspeção do estado da thread para recuperar o valor de retorno. Alternativamente, como adotado do exploit *triple_fetch* de Ian Beer, `lr` é configurado para loop infinito; os registradores da thread são então monitorados continuamente até que `pc` aponte para essa instrução.

## 2. Portas Mach para comunicação

A fase subsequente envolve estabelecer portas Mach para facilitar a comunicação com a thread remota. Essas portas são instrumentais na transferência de direitos de envio/recebimento arbitrários entre tarefas.

Para comunicação bidirecional, dois direitos de recebimento Mach são criados: um na tarefa local e o outro na tarefa remota. Subsequentemente, um direito de envio para cada porta é transferido para a tarefa correspondente, permitindo a troca de mensagens.

Focando na porta local, o direito de recebimento é mantido pela tarefa local. A porta é criada com `mach_port_allocate()`. O desafio reside em transferir um direito de envio para esta porta na tarefa remota.

Uma estratégia envolve aproveitar `thread_set_special_port()` para colocar um direito de envio na porta local na `THREAD_KERNEL_PORT` da thread remota. Em seguida, a thread remota é instruída a chamar `mach_thread_self()` para recuperar o direito de envio.

Para a porta remota, o processo é essencialmente invertido. A thread remota é direcionada a gerar uma porta Mach via `mach_reply_port()` (já que `mach_port_allocate()` não é adequada devido ao seu mecanismo de retorno). Após a criação da porta, `mach_port_insert_right()` é invocado na thread remota para estabelecer um direito de envio. Esse direito é então armazenado no kernel usando `thread_set_special_port()`. De volta à tarefa local, `thread_get_special_port()` é usado na thread remota para adquirir um direito de envio para a nova porta Mach alocada na tarefa remota.

A conclusão desses passos resulta no estabelecimento de portas Mach, preparando o terreno para comunicação bidirecional.

## 3. Primitivas Básicas de Leitura/Escrita de Memória

Nesta seção, o foco está em utilizar a primitiva de execução para estabelecer primitivas básicas de leitura/escrita de memória. Esses passos iniciais são cruciais para obter mais controle sobre o processo remoto, embora as primitivas neste estágio não sirvam para muitos propósitos. Em breve, elas serão atualizadas para versões mais avançadas.

### Leitura e escrita de memória usando a primitiva de execução

O objetivo é realizar leitura e escrita de memória usando funções específicas. Para **ler memória**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Para **escrever na memória**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Essas funções correspondem à seguinte montagem:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identificando funções adequadas

Uma varredura em bibliotecas comuns revelou candidatos apropriados para essas operações:

1. **Lendo memória — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Escrevendo na memória — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Para realizar uma gravação de 64 bits em um endereço arbitrário:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Com essas primitivas estabelecidas, o palco está preparado para criar memória compartilhada, marcando um progresso significativo no controle do processo remoto.

## 4. Configuração de Memória Compartilhada

O objetivo é estabelecer memória compartilhada entre tarefas locais e remotas, simplificando a transferência de dados e facilitando a chamada de funções com múltiplos argumentos. A abordagem utiliza `libxpc` e seu tipo de objeto `OS_xpc_shmem`, que é construído sobre entradas de memória Mach.

### Visão geral do processo

1. **Alocação de memória**
* Alocar memória para compartilhamento usando `mach_vm_allocate()`.
* Usar `xpc_shmem_create()` para criar um objeto `OS_xpc_shmem` para a região alocada.
2. **Criando memória compartilhada no processo remoto**
* Alocar memória para o objeto `OS_xpc_shmem` no processo remoto (`remote_malloc`).
* Copiar o objeto de template local; a correção do direito de envio Mach embutido no deslocamento `0x18` ainda é necessária.
3. **Corrigindo a entrada de memória Mach**
* Inserir um direito de envio com `thread_set_special_port()` e sobrescrever o campo `0x18` com o nome da entrada remota.
4. **Finalizando**
* Validar o objeto remoto e mapeá-lo com uma chamada remota para `xpc_shmem_remote()`.

## 5. Obtendo Controle Total

Uma vez que a execução arbitrária e um canal de retorno de memória compartilhada estão disponíveis, você efetivamente possui o processo alvo:

* **R/W de memória arbitrária** — use `memcpy()` entre regiões locais e compartilhadas.
* **Chamadas de função com > 8 args** — coloque os argumentos extras na pilha seguindo a convenção de chamada arm64.
* **Transferência de porta Mach** — passe direitos em mensagens Mach através das portas estabelecidas.
* **Transferência de descritor de arquivo** — aproveite fileports (veja *triple_fetch*).

Tudo isso está encapsulado na biblioteca [`threadexec`](https://github.com/bazad/threadexec) para fácil reutilização.

---

## 6. Nuances do Apple Silicon (arm64e)

Em dispositivos Apple Silicon (arm64e), **Códigos de Autenticação de Ponteiros (PAC)** protegem todos os endereços de retorno e muitos ponteiros de função. Técnicas de sequestro de thread que *reutilizam código existente* continuam a funcionar porque os valores originais em `lr`/`pc` já possuem assinaturas PAC válidas. Problemas surgem quando você tenta pular para a memória controlada pelo atacante:

1. Alocar memória executável dentro do alvo (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Copiar sua carga útil.
3. Dentro do processo *remoto*, assinar o ponteiro:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Defina `pc = ptr` no estado da thread sequestrada.

Alternativamente, mantenha a conformidade com PAC encadeando gadgets/funções existentes (ROP tradicional).

## 7. Detecção e Fortalecimento com EndpointSecurity

O **EndpointSecurity (ES)** expõe eventos do kernel que permitem que defensores observem ou bloqueiem tentativas de injeção de thread:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – acionado quando um processo solicita a porta de outra tarefa (por exemplo, `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – emitido sempre que uma thread é criada em uma tarefa *diferente*.
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (adicionado no macOS 14 Sonoma) – indica manipulação de registradores de uma thread existente.

Cliente Swift mínimo que imprime eventos de thread remota:
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
### Considerações sobre runtime endurecido

Distribuir seu aplicativo **sem** a concessão `com.apple.security.get-task-allow` impede que atacantes não-root obtenham seu task-port. A Proteção de Integridade do Sistema (SIP) ainda bloqueia o acesso a muitos binários da Apple, mas o software de terceiros deve optar explicitamente por sair.

## 8. Ferramentas Públicas Recentes (2023-2025)

| Ferramenta | Ano | Observações |
|------------|-----|-------------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | PoC compacta que demonstra sequestro de thread ciente de PAC no Ventura/Sonoma |
| `remote_thread_es` | 2024 | Auxiliar de EndpointSecurity usado por vários fornecedores de EDR para exibir eventos `REMOTE_THREAD_CREATE` |

> Ler o código-fonte desses projetos é útil para entender as mudanças na API introduzidas no macOS 13/14 e para manter a compatibilidade entre Intel ↔ Apple Silicon.

## Referências

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}

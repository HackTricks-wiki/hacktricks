# Injeção de processos do Windows via nomes de threads e threads em espera

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) transfere bytes para um processo em execução sem `WriteProcessMemory`; Waiting Thread Hijacking (WTH) executa esses bytes em uma thread existente sem `SetThreadContext` nem criar uma thread remota.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Essas são **primitivas de injeção de processos, não vulnerabilidades de escalonamento de privilégios**: o injetor ainda precisa de acesso ao processo e à thread de destino. As APIs de descrição de thread exigem o Windows 10 versão 1607 ou posterior.<sup>[[1]](#references)[[3]](#references)</sup> Consulte [Antivirus (AV) Bypass](av-bypass.md) para outras abordagens de injeção e evasão.

## Thread Name-Calling: cópia do payload no processo de destino

`NtSetInformationThread(ThreadNameInformation)` copia uma `UNICODE_STRING` fornecida para o armazenamento do nome da thread. Chamar `GetThreadDescription` **dentro do processo de destino** cria então uma cópia do nome no heap em modo de usuário. Isso separa a transferência do payload da cópia final para a memória: o injetor pode ler o **ponteiro** de heap retornado, enquanto um APC que executa `RtlMoveMemory` dentro do processo de destino copia os bytes para o destino.<sup>[[1]](#references)</sup> A técnica original também oferece suporte a APCs especiais de usuário; a implementação do WhisperHijack usa, em vez disso, `NtQueueApcThread` comum em uma thread em espera.<sup>[[1]](#references)[[3]](#references)</sup>

Para cada bloco de até `0xFFFE` bytes, o PoC usa esta ordem. Um evento auto-reset duplicado sinaliza a conclusão somente depois que o processo de destino preencheu o espaço temporário; o injetor aguarda esse sinal antes de ler o ponteiro. O evento confirma o APC do ponteiro de heap, não o APC de cópia subsequente. O PoC alerta a mesma thread após enfileirar a cópia e depende da ordem dos APCs, em vez de usar um segundo sinal de conclusão.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

O endereço scratch precisa permitir gravação no alvo e ser conhecido pelo injector sem que seja necessário gravar nele antes. O PoC original usa `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack também oferece `PEB.PostProcessInitRoutine` e, por padrão, usa `TEB.TlsSlots[63]` (localizado com `NtQueryInformationThread(ThreadBasicInformation)`). Não há garantia de que o slot TLS esteja **sempre livre** no alvo; sobrescrever um slot em uso pode interromper essa thread. Ative exatamente uma opção em `Main.c`. As verificações em tempo de compilação rejeitam seleções PEB/TEB ausentes ou conflitantes.<sup>[[4]](#references)</sup>

Uma chamada normal a `RtlInitUnicodeString` pararia em um nulo wide embutido. Para transportar dados binários, inicialize o comprimento de `UNICODE_STRING` usando um buffer de preenchimento não nulo do mesmo tamanho, substitua os bytes de `Buffer` pelo chunk real e, em seguida, passe-o a `NtSetInformationThread`. Essa transferência baseada no comprimento é diferente de passar o shellcode diretamente para `SetThreadDescription` como uma string terminada.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: retornar de uma espera em fila

Enumere as threads com `NtQuerySystemInformation(SystemProcessInformation)` e procure por `ThreadState == Waiting` com `WaitReason == WrQueue`. Uma thread bloqueada em um wrapper de syscall, como `NtWaitForWorkViaWorkerFactory`, tem um endereço de retorno do chamador salvo em `[Rsp]`. Substituir esse slot da stack redireciona o `ret` do wrapper para um stub sem alterar `Rip` por meio de `SetThreadContext`. O stub precisa salvar flags e registradores, **chamar** um payload que retorne, restaurar o estado e, em seguida, saltar para o endereço de retorno original salvo.<sup>[[2]](#references)[[3]](#references)</sup>

No PoC x64, o stub tem um slot de retorno salvo de 8 bytes em `+0x00`, instruções em `+0x08` e o payload em `+0x45`. O slot da stack recebe `allocation_base + 0x08`, não o endereço do slot de dados. `WrQueue`, por si só, **não prova** que se trata de uma espera de worker factory: a pesquisa original também identifica `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` como um caminho de espera em fila. Verifique a espera real e a call stack, e confirme que `[Rsp]` é o slot de retorno pretendido antes de confiar nesse layout.<sup>[[2]](#references)[[3]](#references)</sup>

## Combinar TNC e WTH sem gravações entre processos

WhisperHijack demonstra o fluxo combinado contra um processo x64 nativo existente. Seu Writer seleciona um processo/thread candidato, enquanto um processo filho Flipper herda os handles necessários para a transferência final. O handle do processo solicita `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **não** `PROCESS_VM_WRITE`; ainda assim, o PoC atual abre a thread com `THREAD_ALL_ACCESS`. As verificações de acesso e as mitigações do processo continuam se aplicando.<sup>[[3]](#references)[[4]](#references)</sup>

O PoC combinado usa esta sequência; as APCs de cópia de memória são executadas no alvo, em vez de usar um handle com direitos de gravação remota.<sup>[[4]](#references)</sup>

1. Reserve blocos livres alinhados a 64 KB no alvo e, em seguida, faça commit de suas páginas de 4 KB como `PAGE_READWRITE`. O PoC testa endereços candidatos fixos com `NtQueryVirtualMemory`; esses endereços são escolhas de implementação, não requisitos de TNC ou WTH.
2. Monte `[stub WTH de 0x45 bytes][payload x64 que retorna][ponteiro de 8 bytes para a entrada do stub]`, em que o ponteiro final é `allocation_base + 0x08`. Entregue esse buffer com o loop de chunks de TNC.
3. No Flipper, obtenha o `Rsp` da thread em espera com `NtGetContextThread(CONTEXT_CONTROL)`. Enfileire uma APC de `RtlMoveMemory` no alvo para copiar o valor original de 8 bytes em `[Rsp]` para o slot de dados do stub.
4. Altere a região preparada para executável com `NtProtectVirtualMemory`. Este PoC escolhe `PAGE_EXECUTE_READWRITE` porque seu payload polimórfico se decodifica sozinho; o WTH não exige, por si só, um payload que modifique a si mesmo.
5. Enfileire outra APC de `RtlMoveMemory` no alvo para copiar o **ponteiro final preparado previamente** para `[Rsp]` e, em seguida, chame `NtAlertThread`. A ordem FIFO das APCs salva o retorno original antes de substituí-lo; o retorno do wrapper entra no stub e, após o retorno do payload, retoma o chamador original.

A ausência de `NtWriteVirtualMemory` **não** significa que não há gravações no alvo: `GetThreadDescription` e `RtlMoveMemory` as realizam dentro do alvo.<sup>[[1]](#references)[[3]](#references)</sup> A entrega de APCs de usuário comuns também depende de a thread selecionada processar sua fila de APCs; um snapshot `WrQueue` e um alerta não garantem a execução imediata de forma geral.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> O exemplo evita a criação de remote threads, a suspensão e a substituição direta do contexto, mas continua observável por meio de suas APCs e da transição de proteção.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – PoC e README do WhisperHijack](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – Implementação Main.c do WhisperHijack](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)

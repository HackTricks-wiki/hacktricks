# Fluxo de controle baseado em exceções do Windows e anti-debugging

{{#include ../banners/hacktricks-training.md}}

Um programa protegido do Windows pode usar uma exceção intencional como desvio: a instrução que causa a falha é apenas a entrada para um handler que seleciona o próximo endereço de código do usuário. Isso oculta arestas da desassemblagem linear e transfere a próxima etapa para o despacho de exceções.<sup>[[1]](#references)</sup>

## O despacho importa

Um debugger conectado ao processo recebe uma exceção de **primeira chance** antes dos handlers da aplicação. Se a repassar como não tratada, o Windows procura os handlers do processo; uma exceção sem handler retorna ao debugger como **última chance**. Portanto, um debugger que consome um evento de breakpoint ou de execução passo a passo pode alterar se o handler do programa será executado.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registra um VEH para todo o processo no início da lista de exceções vetoriais. Ele é executado antes do SEH baseado em frames, mas um registro posterior com prioridade máxima pode colocar outro handler à sua frente. Retornar `EXCEPTION_CONTINUE_SEARCH` deixa a exceção para outros handlers; `EXCEPTION_CONTINUE_EXECUTION` retoma a execução a partir do `CONTEXT` salvo, incluindo quaisquer alterações nos registradores feitas pelo handler.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

O SEH clássico do x86 usa registros encadeados na pilha, que podem ser inspecionados com `!exchain`. O x64 nativo usa entradas `RUNTIME_FUNCTION` em `.pdata`, com dados de unwind em `.xdata`, e não essa cadeia do x86. Não aplique o [fluxo de trabalho de sobrescrita de SEH do x86](../binary-exploitation/stack-overflow/windows-seh-overflow.md) a um processo x64 nativo.<sup>[[5]](#references)[[6]](#references)</sup>

## Transforme uma falha em uma aresta de fluxo de controle

Por exemplo, um divisor zero pode gerar intencionalmente `EXCEPTION_INT_DIVIDE_BY_ZERO`, em vez de representar um bug. O handler precisa reconhecer a exceção e o endereço da falha e, em seguida, definir `ContextRecord->Rip` (ou `Eip` no x86) para um endereço de continuação válido antes de retornar `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

O núcleo do manipulador abaixo presume que `fault_site` e `continuation` são endereços conhecidos no mesmo contexto de fluxo de controle. Uma implementação real deve preservar a pilha e os registradores esperados e não deve retomar a execução na mesma instrução que causou a falha, ou ela falhará novamente.<sup>[[7]](#references)</sup>

```c
if (e->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO &&
    e->ExceptionRecord->ExceptionAddress == fault_site) {
#ifdef _M_X64
    e->ContextRecord->Rip = (DWORD64)continuation;
#else
    e->ContextRecord->Eip = (DWORD)continuation;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}
return EXCEPTION_CONTINUE_SEARCH;
```

O mesmo mecanismo pode consumir um `INT3`/`__debugbreak()` intencional (`EXCEPTION_BREAKPOINT`) e redirecionar a execução. **Não** incremente `Rip` às cegas para “pular o breakpoint”: o endereço salvo e o ajuste necessário dependem da trap, da codificação da instrução e do comportamento do debugger. Compare `ExceptionRecord->ExceptionAddress` com o ponteiro de instrução salvo e desmonte os bytes antes de escolher a continuação.<sup>[[8]](#references)</sup> O [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) é um exemplo separado de hardware-breakpoint que altera o estado de retorno de uma syscall do loader.

## Trap Flag como mecanismo de controle dependente do debugger

O bit `0x100` em `EFLAGS`/`RFLAGS` é a Trap Flag (TF). Ativá-lo faz com que o próximo limite de instrução gere `STATUS_SINGLE_STEP` (`0x80000004`). Um branch de VEH ou SEH pode distinguir um evento de single-step passado para o aplicativo de um consumido por um debugger, mas isso é uma **heurística controlada pela política de exceções do debugger**, não uma prova confiável de que existe um debugger.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Se o handler quiser apenas uma etapa, limpe `0x100` em `EFlags` do contexto retomado antes de continuar. Diferencie também as etapas acionadas por TF dos eventos de breakpoint de hardware verificando o endereço que acionou o evento e o estado de depuração; ambos podem aparecer como `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Para as configurações de primeira/segunda chance de `sxe`, `sxd` e `sxi` do WinDbg, consulte [Automação de exceções do WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Exceções](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Tratamento de exceções do depurador](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Tratamento de exceções vetorizadas](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Tratamento de exceções x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Usando um manipulador de exceções vetorizado](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Instruções de Assembly](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Arquitetura x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)

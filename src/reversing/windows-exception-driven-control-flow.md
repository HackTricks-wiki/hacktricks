# Fluxo de controle do Windows dirigido por exceções e anti-debugging

{{#include ../banners/hacktricks-training.md}}

Um programa protegido do Windows pode usar uma exceção intencional como desvio: a instrução que gera a falha é apenas a entrada para um handler que seleciona o próximo endereço de código do usuário. Isso oculta arestas da desassemblagem linear e transfere a próxima etapa para o despacho de exceções.<sup>[[1]](#references)</sup>

## O despacho importa

Um debugger conectado ao processo recebe uma exceção de **primeira chance** antes dos handlers da aplicação. Se ele passar o evento como não tratado, o Windows procura os handlers do processo; uma exceção sem handler retorna ao debugger como **última chance**. Portanto, um debugger que consome um evento de breakpoint ou de single-step pode alterar se o handler do programa será executado.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registra um VEH de todo o processo no início da lista de handlers vetoriais. Ele é executado antes do SEH baseado em quadros, mas um registro posterior com prioridade máxima pode colocar outro handler à sua frente. Retornar `EXCEPTION_CONTINUE_SEARCH` deixa a exceção para outros handlers; `EXCEPTION_CONTINUE_EXECUTION` retoma a execução a partir do `CONTEXT` salvo, incluindo quaisquer alterações de registradores feitas pelo handler.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

O SEH clássico de x86 usa registros vinculados à pilha, que podem ser inspecionados com `!exchain`. O x64 nativo usa entradas `RUNTIME_FUNCTION` em `.pdata`, com dados de unwind em `.xdata`, e não essa cadeia de x86. Não aplique o [workflow de sobrescrita de SEH em x86](../binary-exploitation/stack-overflow/windows-seh-overflow.md) a um processo x64 nativo.<sup>[[5]](#references)[[6]](#references)</sup>

## Transforme uma falha em uma aresta de fluxo de controle

Por exemplo, um divisor zero pode gerar intencionalmente `EXCEPTION_INT_DIVIDE_BY_ZERO` em vez de representar um bug. O handler deve reconhecer a exceção e o endereço da falha e, em seguida, definir `ContextRecord->Rip` (ou `Eip` em x86) como uma continuação válida antes de retornar `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

O núcleo do handler abaixo assume que `fault_site` e `continuation` são endereços conhecidos no mesmo contexto de fluxo de controle. Uma implementação real deve preservar a pilha e os registradores esperados, e não deve retomar na mesma instrução que causou a falha, ou ela falhará novamente.<sup>[[7]](#references)</sup>

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

O mesmo mecanismo pode consumir um `INT3`/`__debugbreak()` intencional (`EXCEPTION_BREAKPOINT`) e redirecionar a execução. **Não** incremente `Rip` cegamente para "pular o breakpoint": o endereço salvo e o ajuste necessário dependem da exceção, da codificação da instrução e do comportamento do debugger. Compare `ExceptionRecord->ExceptionAddress` com o ponteiro de instrução salvo e desmonte os bytes antes de escolher a continuação.<sup>[[8]](#references)</sup> O [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) é um exemplo separado de hardware breakpoint que altera o estado de retorno de uma syscall do loader.

## Materialização de páginas orientada por falhas

Um VEH pode transformar uma page fault em um **lazy loader**, não apenas em um salto. Reserve um intervalo de imagem privado com páginas ainda não confirmadas, ou páginas mapeadas com proteção guard, quando houver suporte. Antes de executar a imagem, indexe os locais de relocação e os thunks da IAT por página de destino. Em uma falha dentro desse intervalo, o handler confirma a página acessada ou a torna gravável, copia os bytes da seção, aplica as relocations e os imports daquela página, define sua proteção final e retorna `EXCEPTION_CONTINUE_EXECUTION`. A instrução original é repetida; **não** avance `Rip` como em um handler que ignora a falha. As páginas nunca acessadas não precisam conter o payload na memória.<sup>[[11]](#references)</sup>

Em uma violação de acesso, `ExceptionRecord->ExceptionAddress` identifica a **instrução** que causou a falha, enquanto `ExceptionInformation[1]` identifica o endereço acessado.<sup>[[10]](#references)</sup> Verifique o código da exceção, a quantidade de parâmetros e o intervalo do endereço acessado antes de materializar uma página; caso contrário, uma falha não relacionada pode ser confundida com uma solicitação do loader.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` gera `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) no primeiro acesso, e o Windows limpa automaticamente o bit de guard; portanto, rearmá-lo é uma etapa separada, não um hook contínuo.<sup>[[12]](#references)</sup> Mantenha o VEH e quaisquer metadados de que ele precise acessíveis durante o tratamento da exceção.<sup>[[11]](#references)</sup> No x64, os dados de unwind podem precisar estar disponíveis antes da primeira falha; o loader citado materializa páginas antecipadamente antes de invocar `DllMain` para evitar condições de corrida durante a inicialização.<sup>[[11]](#references)</sup> Limpe o cache de instruções depois de gravar o código e antes de executá-lo.<sup>[[13]](#references)</sup>

Para recuperar esse fluxo durante o reversing, interrompa na primeira chance em violações de página guard e violações de acesso, inspecione o registro da exceção e, em seguida, passe o evento ao handler da aplicação com `gn`.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Use `!vprot` no endereço acessado para inspecionar a proteção atual da página.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Depois que o handler materializar a página, despeje seus bytes e compare-os com a imagem do arquivo.<sup>[[11]](#references)</sup> Um `!vprot` executado após a falha não pode provar que a página estava protegida antes, pois o status de guarda é de uso único.<sup>[[11]](#references)[[12]](#references)</sup> Restrinja os filtros de exceção ou os breakpoints do handler assim que o intervalo relevante da imagem for conhecido, para evitar falhas não relacionadas.<sup>[[16]](#references)</sup> Consulte [automação de exceções do WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) para configurar os filtros.<sup>[[16]](#references)</sup>

## Trap Flag como um mecanismo de controle dependente do debugger

O bit `0x100` em `EFLAGS`/`RFLAGS` é o Trap Flag (TF). Defini-lo faz com que o próximo limite entre instruções gere `STATUS_SINGLE_STEP` (`0x80000004`). Um branch de VEH ou SEH pode distinguir um evento de single-step encaminhado à aplicação de um consumido por um debugger, mas isso é uma **heurística controlada pela política de exceções do debugger**, não uma prova confiável de que existe um debugger.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Se o handler quiser apenas um passo, limpe `0x100` em `EFlags` do contexto retomado antes de continuar. Diferencie também os passos acionados por TF dos eventos de hardware breakpoint verificando o endereço que os acionou e o estado de depuração; ambos podem aparecer como `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Para as configurações de primeira/segunda chance de `sxe`, `sxd` e `sxi` do WinDbg, consulte [Automação de exceções do WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Exceções](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Tratamento de exceções do depurador](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Tratamento vetorizado de exceções](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Tratamento de exceções x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Usando um handler vetorizado de exceções](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Instruções de Assembly](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Arquitetura x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Carregamento de imagem orientado a falhas](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Criando páginas de guarda](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (Exibir registro de exceção)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - Filtros de exceção sx](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (Continuar com exceção não tratada)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}

# Depuração do kernel do Windows com KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt é um depurador para Windows x64 usado em laboratórios controlados de reverse engineering. Uma interface WPF no host ou o `KfConsole.exe` envia comandos para o `KfRelay.exe` em uma VM do Windows com assinatura de teste. O relay os traduz em solicitações `DeviceIoControl` para o `KernelFlirt.sys`, que oferece operações de memória, registradores, breakpoints, controle de execução e módulos do kernel. O driver também modifica o caminho de depuração do kernel com um hook inline `KdpStub`/`KdTrap`; portanto, use-o somente em uma VM descartável.<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

O relay é um limite de depuração privilegiado, não um serviço remoto comum. Mantenha o TCP `31337` em uma rede isolada somente de host e nunca exponha o driver assinado para testes nem o relay a uma rede não confiável.<sup>[[1]](#references)</sup>

Técnicas relacionadas de exploração do Windows:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Configuração do laboratório e primeira parada

As compilações exigem Windows 10/11 x64, Visual Studio 2022 com C++, WDK 10.0.26100.0 ou posterior e .NET 9. Carregue o driver e o relay dentro da VM e, em seguida, conecte-se a partir do host. A interface pode abrir um EXE ou SYS remoto, e a visualização **Kernel Modules** permite colocar breakpoints em drivers já carregados.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Use `KfLoader.exe unload` quando o laboratório estiver concluído. O console oferece suporte a um REPL desconectado, acesso direto ao dispositivo local e acesso por relay; somente o modo relay implementa o fluxo de trabalho determinístico `open` descrito abaixo.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

Um fluxo de trabalho mínimo no console é:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

Endereços são expressões. Números sem prefixo são hexadecimais, e as expressões podem usar registradores, operações aritméticas, desreferências como `[rsp]` e símbolos como `ntdll!NtCreateFile`. Breakpoints em símbolos só devem ser adicionados depois que `open` ou `attach` enumerar os módulos e carregar seus PDBs.<sup>[[2]](#references)</sup>

## Interceptação determinística do ponto de entrada com `EB FE`

O `open` do relay cria o processo de destino suspenso, salva os bytes iniciais do ponto de entrada, grava `EB FE`, retoma a thread de entrada e verifica repetidamente até que o ponteiro de instrução chegue a esse endereço. `EB FE` é um salto curto de dois bytes para si mesmo; assim, intercepta a execução sem depender da entrega de uma exceção de depuração em modo de usuário. Em seguida, o relay restaura os bytes originais e mantém o destino parado no ponto de entrada.<sup>[[2]](#references)</sup>

Esse padrão também é útil quando é necessário observar um caminho inicial do loader antes que a configuração normal do debugger seja concluída.<sup>[[2]](#references)</sup>

1. Crie o processo suspenso e resolva seu ponto de entrada real após o mapeamento da imagem.
2. Salve os bytes originais do ponto de entrada e substitua-os pelo loop de dois bytes que salta para si mesmo.
3. Retome a thread de entrada e verifique repetidamente o ponteiro de instrução até que ele chegue ao endereço alterado.
4. Suspenda o destino e restaure exatamente os bytes originais antes de continuar a análise.

A técnica é deliberadamente intrusiva. Se o debugger ou o relay for encerrado antes da restauração, o destino pode continuar em loop. O modo local do KernelFlirt não oferece alteração do ponto de entrada pelo relay; inicie o processo manualmente e use `attach <pid>`.<sup>[[2]](#references)</sup>

## Escolha a primitiva de breakpoint

O KernelFlirt oferece vários mecanismos de breakpoint com diferentes efeitos colaterais. Os comandos a seguir permitem que o analista alterne entre primitivas quando código empacotado se reescreve, páginas executáveis são somente leitura ou bytes de software breakpoint são verificados quanto à integridade.<sup>[[1]](#references)[[2]](#references)</sup>

| Primitiva | Comando | Mecanismo e uso |
| --- | --- | --- |
| Software | `bp <expr>` | `INT3` com suporte de MDL; pode instrumentar páginas RX `.text` |
| Software condicional | `bp <expr> if <condition>` | Avalia a condição em cada ocorrência e retoma silenciosamente quando ela é falsa |
| Execução por hardware | `ba e1 <expr>` | Usa um dos registradores DR0-DR3 sem alterar os bytes do código |
| Dados por hardware | `ba w4 <expr>` / `ba r8 <expr>` | Monitora gravações ou leituras/gravações de 1, 2, 4 ou 8 bytes |
| Página de guarda | `bm <expr> [size]` | Usa `PAGE_GUARD` para criar um breakpoint em um intervalo de memória |
| Temporário | `g <expr>`, `p` ou `o` | Breakpoint auxiliar para executar até um endereço, fazer step-over e fazer step-out |

Use `bl` para distinguir entradas de software, hardware, memória e temporárias, e `bc <address|handle|all>` para removê-las. Os slots de hardware são escassos e dependem do estado dos registradores de depuração, enquanto as páginas de guarda abrangem um intervalo maior, mas são acionadas por acessos não relacionados à mesma página.

## Step em x64 nativo versus WoW64

O single-step em x64 nativo define a trap flag do processador por meio de `IOCTL_KF_SINGLE_STEP`. O Step Over decodifica a instrução atual e coloca breakpoints temporários nos possíveis endereços seguintes. O Step Out lê o endereço de retorno do topo da pilha atual. Em um prólogo de função, essa suposição sobre a pilha pode estar errada; portanto, prefira um breakpoint interno conhecido.<sup>[[2]](#references)</sup>

O hook `KdTrap` não captura exceções de 32 bits da mesma maneira. Para destinos WoW64, o debugger decodifica a instrução com Iced, grava `EB FE` no `EIP` seguinte calculado e verifica os ponteiros de instrução das threads. Por isso, `g <address>` não está disponível para WoW64, e um `g` simples bloqueia o console até que um breakpoint seja atingido. Defina primeiro um breakpoint alcançável e evite uma execução indefinida, pois `Ctrl+C` encerra o console em vez de cancelar a verificação repetida.<sup>[[2]](#references)</sup>

## Análise assistida por memória, registradores e símbolos

O console pode combinar uma parada simbólica com inspeção de memória e um patch controlado. As buscas aceitam curingas para bytes, ASCII ou UTF-16 e são limitadas a 4 MB, com no máximo 256 correspondências relatadas. Os comandos de alocação e proteção correspondem aos IOCTLs de alocação, liberação e proteção do driver.<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

O carregamento de PDB lê o diretório de depuração PE de cada módulo remoto, extrai seu identificador RSDS, encontra o PDB correspondente por meio de DbgHelp/SymSrv e verifica se ele foi carregado como um PDB. Coloque os PDBs privados ao lado do alvo na máquina relay ou adicione o diretório deles a `_NT_SYMBOL_PATH` no host.<sup>[[2]](#references)</sup>

## Alterações no estado anti-debug com suporte do kernel

O acesso ao kernel permite que o debugger remova indicadores que um debugger em modo de usuário não consegue ocultar de forma confiável. Aplique uma alteração por vez, confirme a verificação do alvo e reverta o hook correspondente antes de encerrar a sessão.<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port` limpa `EPROCESS.DebugPort`.
- `clr_thread_hide` remove `HideFromDebugger` das threads de destino.
- `ntqsi on` falsifica a classe `0x23` (`SystemKernelDebuggerInformation`) de `NtQuerySystemInformation`.
- `spoof on` faz com que leituras em modo de usuário de `KUSER_SHARED_DATA.KdDebuggerEnabled` retornem false, mantendo o estado do kernel necessário ao mecanismo de trap.
- `stats` verifica os contadores de hook e os estados registrados de `KiDebugRoutine`, `KdpStub` e `KdTrap`.

Essas operações alteram o estado do processo e do kernel. Uma falha, um inline hook obsoleto, um offset incorreto de estrutura ou a restauração incompleta de um patch podem desestabilizar a VM. Por isso, snapshots e um ambiente isolado com assinatura de teste são obrigatórios.<sup>[[1]](#references)</sup>

## References

- [1] [Repositório KernelFlirt e documentação principal](https://github.com/AkaTorich/KernelFlirt)
- [2] [Referência do console KernelFlirt](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}

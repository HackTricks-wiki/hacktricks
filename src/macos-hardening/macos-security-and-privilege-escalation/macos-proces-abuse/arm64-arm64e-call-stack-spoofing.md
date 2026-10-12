# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Por que o unwinding orientado por metadados pode ser falsificado

Algumas ferramentas de segurança do macOS delegam a coleta de pilhas de threads a `/usr/sbin/spindump` ou, de outra forma, confiam em um unwinder convencional orientado por metadados. Um implante pode explorar esse limite de confiança colocando registros sintéticos compatíveis com a ABI em sua pilha, fazendo com que pareça que uma API sensível foi alcançada por funções escolhidas pelo atacante em dyld e frameworks Apple carregados, em vez de código do implante sem respaldo. Isso é uma fraude de telemetria, não uma alteração do executável ou dos metadados de unwind.<sup>[[1]](#references)</sup>

Consulte [macOS stackshots and `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) para entender o contexto do lado da coleta.

Um unwinder não prova que um prólogo gerado pelo compilador criou um registro. Ele usa repetidamente o `PC` atual para selecionar uma receita Mach-O, aplica essa receita a `SP`, `x29`, `x30`, à memória da pilha e a quaisquer registradores não voláteis declarados, e usa o `PC` do chamador recuperado para selecionar a próxima receita. Se a memória controlada pelo atacante satisfizer todas as receitas selecionadas, a cadeia resultante poderá ser estruturalmente válida e simbolizável, mesmo que essas chamadas nunca tenham ocorrido.<sup>[[1]](#references)</sup>

## Estado do frame ARM64

A [visão geral de assembly ARM64](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) aborda as funções dos registradores e a convenção de chamada. Para um frame convencional criado com `stp x29, x30, [sp, #-16]!` seguido por `mov x29, sp`, o Endereço Canônico do Frame (CFA), que representa o `SP` do chamador ao entrar, é `FP+0x10`:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Os registros de frame formam uma lista encadeada por meio de `[FP]`, mas seguir essa lista cegamente não basta: funções folha podem não ter frame, tail calls podem remover transições lógicas e layouts incomuns usam DWARF CFI. A receita selecionada pelo endereço atual determina se o unwinder lê a cadeia de FP.<sup>[[1]](#references)[[4]](#references)</sup>

## Selecionando uma receita de unwind Mach-O

Imagens finais ligadas armazenam dados compactos de unwind em `__TEXT,__unwind_info`. O cabeçalho da seção aponta para um índice de primeiro nível; cada intervalo do índice aponta para uma página de segundo nível regular (`kind=2`) ou compactada (`kind=3`). Layouts que o compact unwind não consegue descrever usam um FDE e instruções de call frame em `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

Para cada PC de runtime candidato:<sup>[[1]](#references)[[2]](#references)</sup>

1. Remova ou normalize os bits PAC de ARM64e apenas para a busca.
2. Encontre o Mach-O carregado cujo intervalo executável `__TEXT` contém o endereço.
3. Calcule `functionOffset = normalizedPC - loadedImageBase` e rejeite resultados negativos ou valores acima de `UINT32_MAX`.
4. Selecione o intervalo de primeiro nível que satisfaça `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`.
5. Analise a página de segundo nível referenciada, escolha a entrada mais próxima cujo início não exceda o offset e verifique se o endereço está abaixo da próxima entrada ou do fim do intervalo de primeiro nível.
6. Decodifique essa entrada e construa o estado exato que ela descreve.

Quando um endereço veio de um LR salvo, a busca pode usar `PC-1` para que um endereço imediatamente após uma call continue dentro do intervalo coberto pelo caller. Isso altera a seleção da receita, não qualquer offset da stack.<sup>[[1]](#references)</sup>

Um parser deve verificar os limites de cada cabeçalho e array, exigir a versão de seção `1`, considerar o sentinela final de primeiro nível, rejeitar um offset de página de segundo nível igual a zero e distinguir páginas regulares de páginas compactadas. Em uma página regular, `entryPageOffset` é relativo ao início dessa página, enquanto o offset da página de primeiro nível é relativo ao início de `__unwind_info`.<sup>[[1]](#references)[[2]](#references)</sup>

O modo geral é `encoding & 0x0F000000`. As definições atuais do LLVM incluem os seguintes modos; um parser não deve tratar todo valor que não seja DWARF como um frame clássico:<sup>[[1]](#references)[[2]](#references)</sup>

| Modo | Valor | Recuperação do caller |
| --- | --- | --- |
| Sem receita compacta | `0x00000000` | Parar ou usar um fallback independente. |
| Frameless | `0x02000000` | Adicionar o tamanho de stack codificado ao `SP` atual; o PC do caller é o LR ativo. |
| DWARF | `0x03000000` | Executar o FDE/CFI identificado pelos 24 bits inferiores. |
| Frame | `0x04000000` | Ler o registro de frame convencional `x29`. |
| Frame arm64e com intervalo de LR autenticado | `0x05000000` | Tratar `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`; seu campo de offset localiza `pacibsppc` dentro do intervalo coberto. |

No modo frameless, `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. No modo frame, os cinco bits inferiores declaram pares contíguos de GPRs salvos, de `x19/x20` a `x27/x28`; os bits `0x100-0x800` declaram, da mesma forma, pares `d8-d15`. Esses registradores salvos podem não ser necessários para encontrar o próximo PC, mas um estado virtual de caller plausível deve satisfazer todos os campos que o consumidor reconstrói.<sup>[[1]](#references)[[2]](#references)</sup>

## Construindo registros sintéticos em modo frame

O processo de construção inverte o funcionamento do unwinder, em vez de procurar na stack valores que pareçam endereços:<sup>[[1]](#references)</sup>

1. Escolha um PC executável real em uma imagem carregada no momento.
2. Decodifique a receita que cobre esse PC preciso ou endereço de call site.
3. Aloque um registro sintético com o alinhamento necessário e a relação CFA correspondente.
4. Armazene o próximo FP sintético em `[FP]`, o PC salvo do caller daquele frame em `[FP+8]` e todos os salvamentos de GPR/FPR declarados pela codificação abaixo de FP.
5. Encadeie vários registros e coloque o primeiro registro no `x29` ativo.
6. Organize o LR ativo e o caminho de retorno da API para que o unwind entre na cadeia escolhida, permitindo que a execução ainda possa ser restaurada com segurança.

Por exemplo, `0x04000001` significa modo frame mais o par `x19/x20`. A transformação de estado correspondente e a memória necessária são:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

Um endereço com aparência legítima, portanto, não é suficiente. Cada PC recuperado se torna a chave para a próxima consulta, então um único endereço cuja codificação não corresponda ao layout fabricado rompe a cadeia ou faz com que o consumidor reconstrua um estado inconsistente dos registradores.<sup>[[1]](#references)</sup>

## Requisitos de PAC do ARM64e

O PAC armazena um valor de integridade com chave nos bits restantes do ponteiro; ele não criptografa o endereço. O esquema de endereço de retorno arm64e do Clang usa a chave de instrução B e o ponteiro da pilha na entrada da função como discriminador. Em um frame convencional, esse `SP` de entrada é o CFA, então o LR salvo em `[FP+8]` é vinculado a `FP+0x10`.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Cada LR sintético deve ser assinado de forma independente, pois mover um LR já assinado para um frame com um CFA diferente altera o discriminador e faz a autenticação falhar. `ptrauth_strip()` é adequado para normalização de endereços e busca de símbolos, mas **não** comprova autenticidade; qualquer retorno real ou branch indireto autenticado deve usar a chave e o modificador esperados naquela transição exata.<sup>[[1]](#references)[[3]](#references)</sup>

Uma função arm64e típica que não é folha assina o LR antes de armazená-lo e o autentica após restaurar o SP de entrada:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline e restore bridge

Registros sintéticos só precisam satisfazer o unwinder; eles não contêm um contexto de execução completo. Retornar da API sensível diretamente para os callers fabricados normalmente causaria uma falha. Por isso, o design prático coloca um frame de gadget imediatamente abaixo da API: a API retorna para código executável em um framework carregado, e esse gadget desvia, por meio de um registrador callee-saved controlado, para um restore bridge no implant.<sup>[[1]](#references)</sup>

Um gadget útil preserva LR e transfere o controle por meio de um registrador controlado, por exemplo, com uma sequência `br`, `braa` ou `brab` apropriada. O restore bridge precisa recuperar os valores originais de `x19-x30` e `SP` antes de retomar a execução do implant. Em arm64e, cada retorno ou branch autenticado no caminho da API ao gadget, do gadget ao bridge e do bridge ao implant exige um ponteiro assinado para a chave e o discriminador usados por essa instrução.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

O resultado é uma falha importante no limite de confiança para detecções baseadas em stack: uma cadeia pode conter apenas PCs de frameworks da Apple mapeados e simbolizáveis e, ainda assim, não representar o fluxo de controle real. Portanto, a saída do unwind deve ser corroborada por evidências independentes sobre a proveniência da memória executável da thread e as transições reais em torno da API sensível, em vez de ser tratada como um rastreamento de execução.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Internals de stack ARM64 e obfuscação no Apple Silicon](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Definições de codificação compact unwind do Mach-O](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Autenticação de ponteiros](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Padrão de chamada de procedimentos para a arquitetura Arm de 64 bits](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}

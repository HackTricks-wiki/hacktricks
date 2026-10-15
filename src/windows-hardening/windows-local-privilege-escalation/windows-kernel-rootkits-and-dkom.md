# Rootkits de kernel do Windows e DKOM

{{#include ../../banners/hacktricks-training.md}}

## Escopo

Um implante pós-comprometimento pode carregar um driver de kernel assinado como serviço e expor um plano de controle em user mode por meio de `IRP_MJ_DEVICE_CONTROL`. A assinatura do driver apenas estabelece que o Windows aceita a imagem; ela não torna seguros a autorização de IOCTL, as operações de memória, os callbacks ou os hooks. Um rootkit analisado usava três handlers durante a operação normal, mas expunha dezenas de primitivas adicionais de pós-exploração, portanto a engenharia reversa deve abranger o dispatcher completo, e não apenas as solicitações observadas em um rastreamento de malware.<sup>[[1]](#references)</sup>

## Triagem de drivers assinados e IOCTLs

Comece em `DriverEntry`, registre os objetos de dispositivo e os links simbólicos DOS, localize a rotina `MajorFunction[IRP_MJ_DEVICE_CONTROL]` e mapeie cada comparação/entrada de tabela que leva a um handler. Compare os nomes abertos pelo user mode com os nomes realmente criados pelo driver: uma cadeia observada abriu `\\.\msagent`, enquanto o driver criou `\Device\ToolTool` e `\DosDevices\ToolTool`. Essa incompatibilidade pode indicar outra amostra/configuração, lógica de configuração ausente ou uma inconsistência na análise.<sup>[[1]](#references)</sup>

Decodifique cada código de controle antes de reconstruir sua estrutura de entrada.<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

Esses três códigos são decodificados como `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` e `METHOD_BUFFERED`. Isso **não** prova que um chamador sem privilégios possa acessá-los: inspecione também a DACL do dispositivo, o despacho de criação/abertura, as verificações do chamador por solicitação, os comprimentos esperados dos buffers, os ponteiros embutidos, o tratamento do ciclo de vida do PID e se o handler confia em um PID ou flag fornecido pelo chamador.<sup>[[1]](#references)</sup>

Quando o implant usa apenas um subconjunto dos comandos, agrupe os handlers restantes por primitiva em vez de descartá-los como código morto. Um único driver multifuncional expôs todas as seguintes classes:<sup>[[1]](#references)</sup>

- **Controle/configuração:** alternar o estado do rootkit; adicionar, remover, consultar ou limpar caminhos, processos e endereços C2 protegidos.
- **Manipulação de processos:** encerrar um PID, desmapear sua imagem, injetar com `NtCreateThreadEx`, ocultar/restaurar processos ou módulos de usuário e remover a proteção PPL.
- **Manipulação do kernel:** desvincular um driver carregado, enumerar/desativar/restaurar callbacks de notificação, mapear manualmente outro driver e escrever em um endereço arbitrário do kernel.
- **Manipulação de objetos:** excluir/descriptografar arquivos e criar ou modificar valores do registro.

## Mapeamento manual do kernel por meio de um driver assinado vulnerável

Um driver assinado com operações de leitura/escrita na memória do kernel pode fornecer um loader para uma imagem de driver não assinada sem pedir ao Windows que carregue essa imagem como um driver normal.<sup>[[2]](#references)[[7]](#references)</sup> O exemplo LocalStranger abre um dispositivo `\\.\WinNotify` existente; seu código-fonte não mostra que um usuário sem privilégios possa instalar, iniciar ou abrir o driver em qualquer host arbitrário.<sup>[[2]](#references)[[3]](#references)</sup> O mapper recebe um caminho de imagem, consulta a base do kernel carregado e usa os IOCTLs de leitura/escrita de memória virtual do dispositivo.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Para transformar esse acesso de leitura/escrita em uma chamada ao kernel, o mapper lê um valor imediato da base PTE em `MmGetVirtualForPhysical` e percorre as entradas de paginação que cobrem `NtAddAtom`.<sup>[[5]](#references)[[7]](#references)</sup> Seu cálculo de PTE é `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`; o código também verifica se há um PDE de página grande.<sup>[[5]](#references)[[7]](#references)</sup> Ele torna temporariamente gravável a entrada que cobre a página, substitui a entrada de syscall por um salto para a função de kernel desejada, invoca o stub de `NtAddAtom` em modo de usuário e, em seguida, restaura os bytes e a entrada de página originais.<sup>[[6]](#references)</sup>

O mapper usa esse caminho de chamada para `ExAllocatePool`, mapeia seções PE, imports e relocations na imagem, grava-a na alocação e chama seu ponto de entrada.<sup>[[7]](#references)[[8]](#references)</sup> Essa implementação aceita apenas imagens PE x64 relocáveis; a leitura da base PTE também pressupõe um layout fixo de `MmGetVirtualForPhysical + 34`.<sup>[[5]](#references)[[8]](#references)</sup> Considere-a dependente da build, não um bypass independente de KASLR nem uma prova de que HVCI ou PatchGuard permitam o mapeamento.<sup>[[5]](#references)[[8]](#references)</sup> Para um uso de kernel R/W apenas de dados, consulte [SYSTEM token theft](arbitrary-kernel-rw-token-theft.md).

## Isenções para processos confiáveis

Um padrão de design útil é um IOCTL que registra um PID e uma flag **trusted**. A mesma consulta de confiança é usada pelos filtros de arquivo, registro, processo e thread: ferramentas não confiáveis recebem resultados de enumeração filtrados, direitos de handle reduzidos ou `STATUS_ACCESS_DENIED`, enquanto o implant ainda pode atualizar seus próprios objetos ocultos. Trate isso como um limite de autorização e verifique como as entradas são autenticadas, sincronizadas e removidas após o encerramento do processo ou a reutilização do PID.<sup>[[1]](#references)</sup>

Rootkits podem persistir políticas em valores `REG_MULTI_SZ` e compilar listas de arquivos, diretórios, chaves do registro, valores do registro, imagens ignoradas, imagens protegidas e imagens ocultas em árvores AVL. Durante a análise, rastreie todos os leitores e gravadores dessas árvores compartilhadas; isso conecta a configuração do registro, os IOCTLs, os callbacks e a lógica de filtragem, mesmo quando os nomes das funções foram removidos.<sup>[[1]](#references)</sup>

## Ocultação de processos e módulos com DKOM

### `EPROCESS.ActiveProcessLinks`

Os offsets de `ActiveProcessLinks` variam conforme a build do Windows. Um rootkit tolerante a versões pode testar candidatos conhecidos e, em seguida, percorrer `EPROCESS` em busca de um `LIST_ENTRY` autoconsistente, cujos vizinhos apontem de volta para o candidato. Ele mantém o offset descoberto, oculta um processo reconectando os `Flink`/`Blink` de seus vizinhos e preserva o estado para vincular a entrada novamente mais tarde. O processo continua em execução, mas desaparece dos enumeradores que percorrem a lista de processos ativos.<sup>[[1]](#references)</sup>

Isso é **DKOM**, não encerramento. A detecção deve comparar resultados baseados em listas com evidências independentes, como varreduras de pool/objetos, propriedade de threads, tabelas de handles, artefatos do scheduler e inspeção da memória do kernel. Um processo visível em uma varredura, mas ausente da lista canônica, é mais relevante do que qualquer uma das perspectivas isoladamente.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

A primitiva equivalente de ocultação de módulos encontra a entrada de destino em `PsLoadedModuleList` e altera os ponteiros `Flink`/`Blink` adjacentes. O driver continua mapeado e executável, mas consultas de módulos baseadas em listas o omitem. Compare a lista do loader com mapeamentos executáveis do kernel, tags de pool, objetos de dispositivo/driver, chaves de serviço, endereços de callback e ponteiros de dispatch que apontem para fora de uma imagem listada.<sup>[[1]](#references)</sup>

## Proteção e ocultação com callbacks

Um rootkit pode combinar frameworks de callbacks documentados com DKOM e hooks:<sup>[[1]](#references)</sup>

- Handlers de pré-operação de `ObRegisterCallbacks` para `PsProcessType` e `PsThreadType` removem direitos usados para encerramento, acesso à VM, duplicação ou manipulação de threads quando um chamador não confiável abre um alvo protegido. Registre a altitude do callback e resolva cada endereço de callback para o módulo proprietário.
- `PsSetCreateProcessNotifyRoutineEx` e `PsSetLoadImageNotifyRoutine` mantêm o estado de processos protegidos/ignorados/ocultos conforme processos e imagens aparecem; uma varredura única de processos pode preencher objetos que já existiam antes do registro.
- Um minifilter do sistema de arquivos nega acesso aos caminhos configurados. Uma implementação incomum pode criar sua chave `Instances`, escolher uma altitude dinamicamente e incrementá-la/tentar novamente quando `FltRegisterFilter` reportar uma colisão.
- Uma rotina `CmRegisterCallbackEx` pode suprimir nomes protegidos da enumeração e negar operações diretas de abertura, renomeação, definição ou exclusão, enquanto isenta processos confiáveis registrados.

Correlacione os registros de `ObRegisterCallbacks`, as altitudes dos callbacks do registro, a saída de `fltmc filters`, as chaves `Instances` do serviço e os endereços de callback. Se as ferramentas normais estiverem sendo filtradas, inspecione essas estruturas a partir de uma imagem de memória offline ou de outra camada de aquisição confiável.<sup>[[1]](#references)</sup>

## Filtragem de resultados do Nsiproxy

A ocultação de rede pode ter como alvo `\Driver\Nsiproxy`: obtenha o objeto de driver com `ObReferenceObjectByName`, salve um ponteiro de handler, substitua-o por um wrapper e remova os registros IPv4 retornados que correspondam a uma lista C2 gerenciada por IOCTL antes que cheguem ao modo de usuário. Aplicativos que usam os dados filtrados do NSI podem deixar de exibir a conexão, embora o tráfego continue existindo.<sup>[[1]](#references)</sup>

Compare as visualizações de conexões do host com a captura de pacotes, a telemetria WFP/ETW e os objetos de rede da memória do kernel. Inspecione também os ponteiros de dispatch/handler de `Nsiproxy` e confirme que cada um resolve para dentro do módulo assinado esperado; um ponteiro para um mapeamento não listado pode conectar a filtragem de rede ao DKOM de `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Lista de verificação da investigação

O sinal mais forte é a divergência entre camadas, não um nome de arquivo ou hash isolado. Correlacione:<sup>[[1]](#references)</sup>

1. Criação de serviço do kernel e um driver assinado cujo tempo de validade do certificado, publicador ou caminho não seja consistente com o produto instalado.
2. Criação de dispositivo, links DOS e tráfego de IOCTL, incluindo nomes de dispositivo divergentes entre o modo de usuário e o kernel.
3. Uma solicitação de registro de PID seguida por falhas de outros processos ao tentar abrir, enumerar, modificar ou excluir os mesmos objetos.
4. Callbacks de objeto/registro/processo/imagem, instâncias de minifilter e hooks cujos endereços não pertençam a um driver normalmente enumerado.
5. Diferenças entre inventários de processos, módulos, callbacks e redes baseados em listas e em varreduras.

## References

- [1] [Kaspersky Securelist - HoneyMyte aprimora o CoolClient com um rootkit de kernel assinado para Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [README do LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [Inicialização do driver LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [Linha de comando do mapper LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [Resolução de exports do kernel e da base PTE no LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [Trampoline de chamada ao kernel do LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [Alocação do mapper e chamada do ponto de entrada no LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [Mapeamento PE do LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [Contexto do kernel e de syscall do LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [Wrappers de IOCTL de memória virtual do LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}

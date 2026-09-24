# Rootkits de Kernel do Windows e DKOM

{{#include ../../banners/hacktricks-training.md}}

## Escopo

Um implante pós-comprometimento pode carregar um driver de kernel assinado como um serviço e expor um plano de controle em user mode por meio de `IRP_MJ_DEVICE_CONTROL`. A assinatura do driver apenas estabelece que o Windows aceita a imagem; ela não torna seguras a autorização dos IOCTLs, as operações de memória, os callbacks ou os hooks. Um rootkit analisado usava três handlers durante a operação normal, mas expunha dezenas de primitivas adicionais de post-exploitation, portanto a engenharia reversa deve abranger o dispatcher completo, em vez de apenas as solicitações observadas em um trace de malware.<sup>[[1]](#references)</sup>

## Triagem de drivers assinados e IOCTLs

Comece em `DriverEntry`, registre os objetos de dispositivo e os links simbólicos DOS, localize a rotina `MajorFunction[IRP_MJ_DEVICE_CONTROL]` e mapeie cada comparação/entrada de tabela que alcança um handler. Compare os nomes abertos pelo user mode com os nomes realmente criados pelo driver: uma cadeia observada abriu `\\.\msagent`, enquanto o driver criou `\Device\ToolTool` e `\DosDevices\ToolTool`. Essa divergência pode identificar outra amostra/configuração, lógica de configuração ausente ou uma inconsistência na análise.<sup>[[1]](#references)</sup>

Decodifique cada control code antes de reconstruir sua estrutura de entrada.<sup>[[1]](#references)</sup>
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
Esses três códigos são decodificados como `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` e `METHOD_BUFFERED`. Isso **não** prova que um chamador sem privilégios possa alcançá-los: também inspecione a DACL do dispositivo, o dispatch de criação/abertura, as verificações do chamador por requisição, os tamanhos de buffer esperados, os ponteiros incorporados, o tratamento do ciclo de vida do PID e se o handler confia em um PID ou flag fornecido pelo chamador.<sup>[[1]](#references)</sup>

Quando o implant usa apenas um subconjunto dos comandos, agrupe os handlers restantes por primitiva em vez de descartá-los como código morto. Um único driver multifuncional expôs todas as seguintes classes:<sup>[[1]](#references)</sup>

- **Controle/configuração:** alternar o estado do rootkit; adicionar, remover, consultar ou limpar caminhos, processos e endereços de C2 protegidos.
- **Manipulação de processos:** terminar um PID, desmapear sua imagem, injetar com `NtCreateThreadEx`, ocultar/restaurar processos ou módulos de usuário e remover a proteção PPL.
- **Manipulação do kernel:** desvincular um driver carregado, enumerar/desabilitar/restaurar callbacks de notificação, mapear manualmente outro driver e escrever em um endereço arbitrário do kernel.
- **Manipulação de objetos:** excluir/descriptografar arquivos e criar ou modificar valores do registro.

## Exceções de processos confiáveis

Um padrão de design útil é um IOCTL que registra um PID junto com uma flag **confiável**. A mesma consulta de confiança é então usada pelos filtros de arquivos, registro, processos e threads: ferramentas não confiáveis recebem resultados de enumeração filtrados, direitos de handle reduzidos ou `STATUS_ACCESS_DENIED`, enquanto o implant ainda pode atualizar seus próprios objetos ocultos. Trate isso como um limite de autorização e verifique como as entradas são autenticadas, sincronizadas e removidas após a saída do processo ou a reutilização do PID.<sup>[[1]](#references)</sup>

Rootkits podem persistir políticas em valores `REG_MULTI_SZ` e compilar listas de arquivos, diretórios, chaves do registro, valores do registro, imagens ignoradas, imagens protegidas e imagens ocultas em árvores AVL. Durante a análise, rastreie cada leitor e gravador dessas árvores compartilhadas; isso conecta a configuração do registro, IOCTLs, callbacks e lógica de filtragem mesmo quando os nomes das funções são removidos.<sup>[[1]](#references)</sup>

## Ocultação de processos e módulos com DKOM

### `EPROCESS.ActiveProcessLinks`

Os offsets de `ActiveProcessLinks` variam conforme a compilação do Windows. Um rootkit tolerante a versões pode testar candidatos conhecidos e então procurar em `EPROCESS` uma `LIST_ENTRY` autoconsistente cujos vizinhos apontem de volta para o candidato. Ele mantém o offset descoberto, oculta um processo reconectando os `Flink`/`Blink` de seus vizinhos e preserva o estado para vincular a entrada novamente mais tarde. O processo continua em execução, mas desaparece dos enumeradores que percorrem a lista de processos ativos.<sup>[[1]](#references)</sup>

Isso é **DKOM**, não terminação. A detecção deve comparar resultados baseados em listas com evidências independentes, como varreduras de pool/objetos, propriedade de threads, tabelas de handles, artefatos do scheduler e inspeção da memória do kernel. Um processo visível em uma varredura, mas ausente da lista canônica, é mais significativo do que qualquer uma das visualizações isoladamente.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

A primitiva equivalente de ocultação de módulos encontra a entrada-alvo em `PsLoadedModuleList` e corrige os ponteiros `Flink`/`Blink` adjacentes. O driver continua mapeado e executável, mas consultas de módulos baseadas na lista o omitem. Compare a lista do loader com mapeamentos executáveis do kernel, tags de pool, objetos de dispositivo/driver, chaves de serviço, endereços de callbacks e ponteiros de dispatch que apontem para fora de uma imagem listada.<sup>[[1]](#references)</sup>

## Proteção e camuflagem baseadas em callbacks

Um rootkit pode combinar frameworks de callbacks documentados com DKOM e hooks:<sup>[[1]](#references)</sup>

- Os handlers de pré-operação de `ObRegisterCallbacks` para `PsProcessType` e `PsThreadType` removem direitos usados para terminação, acesso à VM, duplicação ou manipulação de threads quando um chamador não confiável abre um alvo protegido. Registre o altitude do callback e resolva cada endereço de callback para o módulo ao qual pertence.
- `PsSetCreateProcessNotifyRoutineEx` e `PsSetLoadImageNotifyRoutine` mantêm o estado de processos protegidos/ignorados/ocultos à medida que processos e imagens aparecem; uma enumeração única de processos pode preencher posteriormente os objetos que existiam antes do registro.
- Um minifilter do sistema de arquivos nega acesso a caminhos configurados. Uma implementação incomum pode criar sua chave `Instances`, escolher um altitude dinamicamente e incrementar/tentar novamente quando `FltRegisterFilter` informar uma colisão.
- Uma rotina `CmRegisterCallbackEx` pode suprimir nomes protegidos da enumeração e negar operações diretas de abertura, renomeação, definição ou exclusão, enquanto isenta processos confiáveis registrados.

Correlacione os registros de `ObRegisterCallbacks`, os altitudes dos callbacks do registro, a saída de `fltmc filters`, as chaves de serviço `Instances` e os endereços dos callbacks. Se ferramentas normais estiverem sendo filtradas, inspecione essas estruturas a partir de uma imagem de memória offline ou de outra camada confiável de aquisição.<sup>[[1]](#references)</sup>

## Filtragem de resultados do Nsiproxy

A ocultação de rede pode ter como alvo `\Driver\Nsiproxy`: obtenha o objeto do driver com `ObReferenceObjectByName`, salve um ponteiro para o handler, substitua-o por um wrapper e remova os registros IPv4 retornados que correspondam a uma lista de C2 gerenciada por IOCTL antes que o user mode os receba. Aplicativos baseados nos dados filtrados do NSI podem deixar de exibir a conexão, mesmo que o tráfego ainda exista.<sup>[[1]](#references)</sup>

Compare as visualizações de conexões do host com captura de pacotes, telemetria WFP/ETW e objetos de rede da memória do kernel. Inspecione também os ponteiros de dispatch/handler do `Nsiproxy` e confirme que cada um é resolvido dentro do módulo assinado esperado; um ponteiro para um mapeamento não listado pode conectar a filtragem de rede ao DKOM de `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Checklist de investigação

O sinal mais forte é a discordância entre camadas, não um único nome de arquivo ou hash. Correlacione:<sup>[[1]](#references)</sup>

1. Criação de serviços do kernel e um driver assinado cujo tempo do certificado, publicador ou caminho seja inconsistente com o produto instalado.
2. Criação de dispositivos, links DOS e tráfego de IOCTL, incluindo nomes de dispositivos do user mode e do kernel que não correspondam.
3. Uma solicitação de registro de PID seguida por falhas de outros processos ao abrir, enumerar, modificar ou excluir os mesmos objetos.
4. Callbacks de objetos/registro/processos/imagens, instâncias de minifilters e hooks cujos endereços não pertençam a um driver normalmente enumerado.
5. Diferenças entre inventários de processos, módulos, callbacks e redes baseados em listas e em varreduras.

## References

- [1] [Kaspersky Securelist - HoneyMyte Enhances CoolClient with a Signed Windows Kernel Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}

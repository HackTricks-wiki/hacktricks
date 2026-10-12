# Double-Fetch de Buffer de Usuário Mapeado por MDL no Windows

{{#include ../../banners/hacktricks-training.md}}

Um driver de kernel do Windows cria uma condição de double-fetch quando valida dados em páginas associadas ao chamador e, depois, passa um ponteiro para essas mesmas páginas a uma API sensível à segurança. Bloquear e mapear as páginas não torna seu conteúdo imutável. A CVE-2025-55680 em `cldflt.sys` ilustra esse padrão: o driver validou o nome relativo de um placeholder do Cloud Files e, em seguida, criou o objeto ainda referenciando o buffer mutável do chamador.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` cria arquivos ou diretórios abaixo de uma raiz de sincronização do Cloud Files registrada. No caminho vulnerável, alterar o nome após a validação poderia redirecionar a criação privilegiada para fora dessa raiz.<sup>[[1]](#references)[[2]](#references)</sup>

## Por que bloquear as páginas não bloqueou os dados

O caminho vulnerável `HsmpOpCreatePlaceholders()` alocava um MDL para o payload do chamador, chamava `ProbeForRead()` e `MmProbeAndLockPages()` e mapeava essas páginas no espaço de endereçamento virtual do kernel. Um MDL descreve e bloqueia as páginas físicas para que permaneçam residentes. Ele **não** cria um snapshot dos bytes. Portanto, o modo de usuário pode modificar a mesma memória física enquanto o driver a lê pelo mapeamento do sistema.<sup>[[1]](#references)[[3]](#references)</sup>

O caminho relevante da requisição e do uso era:<sup>[[1]](#references)</sup>

1. `cldapi.dll` enviava o código de controle do Cloud Files `0x903BC`, com a tag `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) e a operação de criação de placeholder `0xC0000001`.
2. Cada registro do payload continha pares de deslocamento/comprimento de 16 bits para o nome relativo e a identidade do arquivo. A maioria dos campos fixos era copiada para um registro na stack, mas o nome de comprimento variável permanecia nas páginas de usuário mapeadas.
3. O driver examinava o nome UTF-16 e rejeitava uma barra invertida ou dois-pontos.
4. Em seguida, criava uma `UNICODE_STRING` cujo `Buffer` ainda apontava para o payload mapeado e atribuía esse valor a `OBJECT_ATTRIBUTES.ObjectName`.
5. `FltCreateFileEx2()` lia esse ponteiro novamente. Assim, um thread gravador concorrente poderia fazer a validação observar uma string e a criação do arquivo observar outra.

Isso é um **double-fetch**, embora ambas as leituras usem um endereço virtual do kernel: a fronteira de segurança depende do armazenamento subjacente, não do mapeamento virtual que o driver desreferencia.<sup>[[1]](#references)</sup>

## Layout da race do Cloud Files

A estratégia de exploit divulgada usou requisições repetidas, threads mutator e uma junction para transformar o double-fetch em redirecionamento de caminho:<sup>[[1]](#references)</sup>

1. Registre um diretório controlado pelo atacante com `CfRegisterSyncRoot()` e crie `JUSTASTRING` abaixo dele como uma junction para um destino protegido.
2. Prepare um registro de placeholder compartilhado com o nome válido de componente único `JUSTASTRINGDnewfile.dll`.
3. Faça threads mutator alternarem a unidade de código UTF-16 `D` entre `D` e `\`. A segunda representação é `JUSTASTRING\newfile.dll`.
4. Em paralelo, faça threads worker enviarem repetidamente requisições de criação de placeholder que referenciem o mesmo payload, enquanto um monitor verifica o destino protegido.
5. Uma iteração bem-sucedida valida a representação sem separador e, em seguida, segue a junction quando a criação posterior encontra a representação que contém `\`.

A primitiva permite apenas a criação de arquivos ou diretórios protegidos. Transformá-la em execução de código ainda exige controle sobre o conteúdo do arquivo criado e um consumidor privilegiado, como um alvo adequado para DLL side-loading. A análise original usou essa classe final de cadeia, mas não publicou o loader, o payload nem um exploit independente completo.<sup>[[1]](#references)</sup>

Para técnicas complementares que ampliam deliberadamente as races de busca de caminhos do Windows, consulte [Exploração de Race Conditions no Kernel via Caminhos Lentos do Object Manager](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence - Escalação de privilégios TOCTOU no Minifilter Cloud Files do Microsoft Windows](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - Função CfCreatePlaceholders](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - Função MmProbeAndLockPages](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}

# Bypasses de verificação de acesso a arquivos em modo kernel

{{#include ../../banners/hacktricks-training.md}}

## Padrão de driver vulnerável

Um driver não preserva os limites de segurança de um caller apenas por personificá-lo. A abertura de objetos em modo kernel normalmente ignora as verificações de acesso. `OBJ_KERNEL_HANDLE` apenas torna o handle resultante acessível em modo kernel. Quando um driver abre ou manipula um objeto em nome do modo de usuário, também deve usar `OBJ_FORCE_ACCESS_CHECK` para que o Object Manager avalie o acesso solicitado com base no token efetivo.<sup>[[3]](#references)[[4]](#references)</sup>

Audite os IOCTLs que manipulam arquivos e os callbacks de criação em busca desta sequência:<sup>[[3]](#references)[[4]](#references)</sup>

1. O modo de usuário fornece um caminho, um handle de origem, o acesso desejado ou o tipo de operação.
2. O driver personifica o caller, mas chama `IoCreateFileEx`, `ZwCreateFile` ou uma rotina semelhante sem `OBJ_FORCE_ACCESS_CHECK`.
3. Um handle de arquivo ou diretório acessível apenas pelo kernel é salvo em um estado por handle.
4. Uma operação posterior decide se deve personificar com base em um estado influenciado pelo atacante, como a máscara de acesso solicitada durante a primeira abertura.
5. O ramo privilegiado executa uma renomeação ou criação de link usando uma classe de informações `BypassAccessCheck`.

Isso é um **primitivo de arquivo confused-deputy**, não necessariamente corrupção de memória. Uma inversão de estado particularmente perigosa é “solicitou escrita significa personificar; não solicitou escrita significa permanecer privilegiado”. Nesse design, solicitar deliberadamente apenas acesso de leitura pode desbloquear o caminho mais poderoso.<sup>[[3]](#references)</sup>

## Exemplo de vSMB: raiz privilegiada e renomeação privilegiada

`storvsp.sys` implementa o Virtual Server Message Block (vSMB). Quando o recurso **Virtual Machine Platform** está habilitado, o modo de usuário pode acessar `\Device\STORVSP` por meio de `\\.\STORVSP`. Um caminho de sistema de arquivos vSMB tem o formato `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 e CVE-2025-64673 mostraram como duas decisões inconsistentes de controle de acesso poderiam transformar essa interface em uma elevação de privilégio local.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

O mapeamento entre funções e CVEs da fonte vem de engenharia reversa do binário corrigido, e não de código-fonte da Microsoft. Os pesquisadores alertam que os dois identificadores podem corresponder às funções opostas.<sup>[[3]](#references)</sup>

### 1. Criar um compartilhamento somente leitura com raiz em um diretório protegido

O caminho de criação vulnerável registrava os direitos solicitados em flags persistentes, como `HasReadAccess`, `HasWriteAccess` e `HasAppendAccess`. Em seguida, abria o caminho de suporte com `OBJ_KERNEL_HANDLE`, mas sem `OBJ_FORCE_ACCESS_CHECK`. Portanto, a tentativa de personificação não fazia com que a abertura do arquivo respeitasse as permissões NTFS do caller.<sup>[[3]](#references)[[4]](#references)</sup>

Solicite apenas `FILE_READ_DATA`. Isso mantém `HasWriteAccess` desativado, mas ainda obtém um compartilhamento cuja raiz interna é um diretório protegido:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

O artefato importante não é um handle de diretório System32 em user-mode. É um handle de dispositivo vSMB associado a um estado do driver que contém um handle raiz privilegiado do kernel.<sup>[[3]](#references)</sup>

### 2. Transformar a divergência de estado em substituição de arquivo protegido

O IOCTL `0x240330` aceitava um handle de arquivo de origem, uma classe de informação e um buffer de informações de tamanho variável:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

O handler vulnerável aceitava `FileRenameInformation`, `FileLinkInformation` e `FileRenameInformationEx`. Para um caminho de rename normal, ele separava o caminho do diretório pai do componente final e, em seguida, abria o diretório pai relativo ao handle root armazenado. Essa abertura também usava `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` sem `OBJ_FORCE_ACCESS_CHECK`. Um `RootDirectory` não nulo fornecido pelo atacante dentro da estrutura de rename era rejeitado, então o driver fornecia seu próprio handle de diretório privilegiado.<sup>[[3]](#references)</sup>

A branch explorável era selecionada ao **não** solicitar acesso de escrita durante o stage 1:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: impersonar o contexto de segurança root salvo.
- `HasWriteAccess == 0`: ignorar a impersonation e converter `FileRenameInformation` ou `FileRenameInformationEx` em sua variante `BypassAccessCheck`.

O handler duplicava o handle de origem fornecido pelo atacante em `PsInitialSystemProcess`, referenciava-o como um objeto de arquivo, instalava o handle privilegiado do diretório de destino na estrutura de rename e chamava `ZwSetInformationFile`. Com `ReplaceIfExists = TRUE`, um arquivo controlado pelo chamador podia, portanto, substituir um arquivo existente abaixo do root protegido.<sup>[[3]](#references)</sup>

Ao revisar um handler semelhante, acompanhe **a proveniência de ambos os handles e o contexto de segurança** em cada branch. A validação de entrada, as verificações de integer overflow, `IO_STOP_ON_SYMLINK` e a restrição das classes de informação aceitas não compensam a combinação de um handle root privilegiado com uma operação de bypass de verificação de acesso.<sup>[[3]](#references)</sup>

## De uma escrita protegida à execução como SYSTEM

Uma primitiva de substituição de arquivo protegido se torna execução de código quando um processo privilegiado carrega posteriormente o módulo substituído. Na cadeia demonstrada, o destino era `C:\Windows\System32\wuapi.dll`. Ativar a classe COM local-server `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` para a interface `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` e chamar `IWaaSRemediation::LaunchDetectionOnly()` fazia com que um processo SYSTEM carregasse essa DLL.<sup>[[3]](#references)</sup>

Essa chamada COM é um **gatilho de ativação**, não [COM registry hijacking](com-hijacking.md). A primitiva de arquivo fornece o módulo implantado, e o loader privilegiado fornece a execução. Para outras cadeias de escrita protegida, identifique a imagem exata, o caminho da DLL, a política de assinatura, a bitness, as funções exportadas e um gatilho confiável antes de escolher um alvo. Consulte [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) para conhecer o fluxo de trabalho geral de análise do loader.<sup>[[3]](#references)</sup>

### Movendo um token da Session 0 para o desktop interativo

Um payload carregado por um serviço normalmente é executado na Session 0. Para criar um processo interativo, ele pode obter a sessão ativa do console com `WTSGetActiveConsoleSessionId`, habilitar os privilégios de token necessários, duplicar o token SYSTEM atual como um token primário e definir seu `TokenSessionId` como a sessão ativa. Em seguida, `CreateProcessAsUserW` usa esse token com `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` é necessário para definir o ID de sessão de um token neste cenário. A window station interativa e o desktop também devem conceder acesso ao token. Consulte [duplicação de token da Session 0](sedebug-+-seimpersonate-copy-token.md) para conhecer o fluxo mais amplo de cópia de token.<sup>[[3]](#references)[[5]](#references)</sup>

## Orientações para correção e revisão

As atualizações da Microsoft de dezembro de 2025 corrigiram a cadeia demonstrada. A engenharia reversa constatou que o caminho de criação do vSMB corrigido rejeita solicitações de chamadores não confiáveis que solicitam a raiz de um compartilhamento sem `FILE_WRITE_DATA`. As operações relevantes também passaram a aplicar a verificação de acesso forçada. Isso impede a inversão de estado antes que um chamador sem privilégios possa obter a raiz privilegiada.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Para código de driver, aplique estas regras:<sup>[[3]](#references)[[4]](#references)</sup>

- Adicione `OBJ_FORCE_ACCESS_CHECK` sempre que um objeto for aberto em nome de uma solicitação do modo de usuário. Não trate `OBJ_KERNEL_HANDLE` como um controle de autorização.<sup>[[4]](#references)</sup>
- Capture e valide o modo do solicitante e o contexto de segurança efetivo. Não permita que os direitos solicitados selecionem um caminho de execução mais privilegiado.
- Valide os identificadores de usuário com o tipo de objeto, a máscara de acesso e `UserMode` corretos. Duplicar um identificador no processo do sistema não valida a autoridade da operação solicitada.
- Mantenha a resolução do destino relativa a um identificador confiável, mas garanta que o próprio identificador confiável tenha sido aberto com a verificação de acesso obrigatória do solicitante.
- Evite classes `File*BypassAccessCheck` em operações iniciadas pelo usuário. Se o código interno realmente precisar delas, restrinja esse caminho com uma decisão de autorização independente dos sinalizadores de acesso controlados pelo usuário.
- Aplique as correções aos sistemas afetados. A superfície vulnerável é relevante quando o Virtual Machine Platform carrega `storvsp.sys`.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - De compartilhamento virtual a shell físico: explorando o controle de acesso inconsistente do Windows para LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Identificadores de objeto](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - Função CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}

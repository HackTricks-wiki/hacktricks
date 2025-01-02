# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext e amfid

Ele se concentra em impor a integridade do código em execução no sistema, fornecendo a lógica por trás da verificação de assinatura de código do XNU. Também é capaz de verificar direitos e lidar com outras tarefas sensíveis, como permitir depuração ou obter portas de tarefa.

Além disso, para algumas operações, o kext prefere contatar o daemon em espaço de usuário `/usr/libexec/amfid`. Essa relação de confiança foi abusada em vários jailbreaks.

AMFI usa **MACF** políticas e registra seus hooks no momento em que é iniciado. Além disso, impedir seu carregamento ou descarregamento pode desencadear um pânico do kernel. No entanto, existem alguns argumentos de inicialização que permitem debilitar o AMFI:

- `amfi_unrestricted_task_for_pid`: Permitir task_for_pid sem os direitos necessários
- `amfi_allow_any_signature`: Permitir qualquer assinatura de código
- `cs_enforcement_disable`: Argumento de sistema usado para desativar a aplicação da assinatura de código
- `amfi_prevent_old_entitled_platform_binaries`: Anular binários de plataforma com direitos
- `amfi_get_out_of_my_way`: Desativa completamente o amfi

Estas são algumas das políticas MACF que ele registra:

- **`cred_check_label_update_execve:`** A atualização de rótulo será realizada e retornará 1
- **`cred_label_associate`**: Atualiza o slot de rótulo mac do AMFI com o rótulo
- **`cred_label_destroy`**: Remove o slot de rótulo mac do AMFI
- **`cred_label_init`**: Move 0 no slot de rótulo mac do AMFI
- **`cred_label_update_execve`:** Verifica os direitos do processo para ver se deve ser permitido modificar os rótulos.
- **`file_check_mmap`:** Verifica se mmap está adquirindo memória e definindo-a como executável. Nesse caso, verifica se a validação da biblioteca é necessária e, se sim, chama a função de validação da biblioteca.
- **`file_check_library_validation`**: Chama a função de validação da biblioteca que verifica, entre outras coisas, se um binário de plataforma está carregando outro binário de plataforma ou se o processo e o novo arquivo carregado têm o mesmo TeamID. Certos direitos também permitirão carregar qualquer biblioteca.
- **`policy_initbsd`**: Configura chaves NVRAM confiáveis
- **`policy_syscall`**: Verifica políticas DYLD, como se o binário tem segmentos irrestritos, se deve permitir variáveis de ambiente... isso também é chamado quando um processo é iniciado via `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Verifica se, quando um processo executa um novo binário, outros processos com direitos SEND sobre a porta de tarefa do processo devem mantê-los ou não. Binários de plataforma são permitidos, o direito `get-task-allow` permite, os direitos `task_for_pid-allow` são permitidos e binários com o mesmo TeamID.
- **`proc_check_expose_task`**: impõe direitos
- **`amfi_exc_action_check_exception_send`**: Uma mensagem de exceção é enviada ao depurador
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Ciclo de vida do rótulo durante o tratamento de exceções (depuração)
- **`proc_check_get_task`**: Verifica direitos como `get-task-allow`, que permite que outros processos obtenham a porta de tarefas e `task_for_pid-allow`, que permite que o processo obtenha portas de tarefas de outros processos. Se nenhum desses, chama `amfid permitunrestricteddebugging` para verificar se é permitido.
- **`proc_check_mprotect`**: Negar se `mprotect` for chamado com a flag `VM_PROT_TRUSTED`, que indica que a região deve ser tratada como se tivesse uma assinatura de código válida.
- **`vnode_check_exec`**: É chamado quando arquivos executáveis são carregados na memória e define `cs_hard | cs_kill`, que matará o processo se qualquer uma das páginas se tornar inválida
- **`vnode_check_getextattr`**: MacOS: Verifica `com.apple.root.installed` e `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Como get + com.apple.private.allow-bless e direito equivalente de instalador interno
- &#x20;**`vnode_check_signature`**: Código que chama o XNU para verificar a assinatura de código usando direitos, cache de confiança e `amfid`
- &#x20;**`proc_check_run_cs_invalid`**: Intercepta chamadas `ptrace()` (`PT_ATTACH` e `PT_TRACE_ME`). Verifica se algum dos direitos `get-task-allow`, `run-invalid-allow` e `run-unsigned-code` e, se nenhum, verifica se a depuração é permitida.
- **`proc_check_map_anon`**: Se mmap for chamado com a flag **`MAP_JIT`**, o AMFI verificará o direito `dynamic-codesigning`.

`AMFI.kext` também expõe uma API para outras extensões do kernel, e é possível encontrar suas dependências com:
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

Este é o daemon em modo de usuário que `AMFI.kext` usará para verificar assinaturas de código em modo de usuário.\
Para que `AMFI.kext` se comunique com o daemon, ele usa mensagens mach pela porta `HOST_AMFID_PORT`, que é a porta especial `18`.

Note que no macOS não é mais possível que processos root sequestram portas especiais, pois elas são protegidas pelo `SIP` e apenas o launchd pode acessá-las. No iOS, é verificado se o processo que envia a resposta de volta tem o CDHash hardcoded de `amfid`.

É possível ver quando `amfid` é solicitado a verificar um binário e a resposta dele depurando-o e definindo um ponto de interrupção em `mach_msg`.

Uma vez que uma mensagem é recebida pela porta especial, **MIG** é usado para enviar cada função para a função que está chamando. As principais funções foram revertidas e explicadas dentro do livro.

## Provisioning Profiles

Um perfil de provisionamento pode ser usado para assinar código. Existem perfis de **Desenvolvedor** que podem ser usados para assinar código e testá-lo, e perfis **Enterprise** que podem ser usados em todos os dispositivos.

Depois que um aplicativo é enviado para a Apple Store, se aprovado, ele é assinado pela Apple e o perfil de provisionamento não é mais necessário.

Um perfil geralmente usa a extensão `.mobileprovision` ou `.provisionprofile` e pode ser despejado com:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Embora às vezes referidos como certificados, esses perfis de provisionamento têm mais do que um certificado:

- **AppIDName:** O Identificador da Aplicação
- **AppleInternalProfile**: Designa isso como um perfil Interno da Apple
- **ApplicationIdentifierPrefix**: Precedido ao AppIDName (igual ao TeamIdentifier)
- **CreationDate**: Data no formato `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Um array de (geralmente um) certificado(s), codificado como dados Base64
- **Entitlements**: Os direitos permitidos com direitos para este perfil
- **ExpirationDate**: Data de expiração no formato `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: O Nome da Aplicação, o mesmo que AppIDName
- **ProvisionedDevices**: Um array (para certificados de desenvolvedor) de UDIDs para os quais este perfil é válido
- **ProvisionsAllDevices**: Um booleano (verdadeiro para certificados empresariais)
- **TeamIdentifier**: Um array de (geralmente um) string(s) alfanuméricos usados para identificar o desenvolvedor para fins de interação entre aplicativos
- **TeamName**: Um nome legível por humanos usado para identificar o desenvolvedor
- **TimeToLive**: Validade (em dias) do certificado
- **UUID**: Um Identificador Universalmente Único para este perfil
- **Version**: Atualmente definido como 1

Note que a entrada de direitos conterá um conjunto restrito de direitos e o perfil de provisionamento só poderá conceder esses direitos específicos para evitar conceder direitos privados da Apple.

Note que os perfis geralmente estão localizados em `/var/MobileDeviceProvisioningProfiles` e é possível verificá-los com **`security cms -D -i /path/to/profile`**

## **libmis.dyld**

Esta é a biblioteca externa que `amfid` chama para perguntar se deve permitir algo ou não. Isso foi historicamente abusado em jailbreaks ao executar uma versão com backdoor que permitiria tudo.

No macOS, isso está dentro de `MobileDevice.framework`.

## AMFI Trust Caches

O AMFI do iOS mantém uma lista de hashes conhecidos que são assinados ad-hoc, chamada de **Trust Cache** e encontrada na seção `__TEXT.__const` do kext. Note que em operações muito específicas e sensíveis, é possível estender esse Trust Cache com um arquivo externo.

## Referências

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}

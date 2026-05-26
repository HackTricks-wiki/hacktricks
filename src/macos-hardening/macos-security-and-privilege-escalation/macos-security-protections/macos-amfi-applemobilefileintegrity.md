# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Ele foca em impor a integridade do código em execução no sistema, fornecendo a lógica por trás da verificação de assinatura de código do XNU. Também é capaz de verificar entitlements e lidar com outras tarefas sensíveis, como permitir debugging ou obter task ports.

Além disso, para algumas operações, o kext prefere contatar o daemon em user space `/usr/libexec/amfid`. Essa relação de confiança foi abusada em vários jailbreaks.

Em versões recentes do macOS, o AMFI não é mais exposto de forma conveniente como um kext independente no disco, então fazer reversing normalmente significa trabalhar a partir do **kernelcache** ou de um **KDK** em vez de navegar em `/System/Library/Extensions`.

O AMFI usa políticas do **MACF** e registra seus hooks no momento em que é iniciado. Além disso, impedir seu carregamento ou descarregá-lo pode disparar um kernel panic. No entanto, há alguns boot arguments que permitem enfraquecer o AMFI:

- `amfi_unrestricted_task_for_pid`: Permite que task_for_pid seja permitido sem os entitlements necessários
- `amfi_allow_any_signature`: Permite qualquer code signature
- `cs_enforcement_disable`: Argumento global do sistema usado para desativar a aplicação de code signing
- `amfi_prevent_old_entitled_platform_binaries`: Invalida platform binaries com entitlements antigos
- `amfi_get_out_of_my_way`: Desativa o amfi completamente

Estas são algumas das políticas MACF que ele registra:

- **`cred_check_label_update_execve:`** A atualização do label será realizada e retornará 1
- **`cred_label_associate`**: Atualiza o slot do mac label do AMFI com o label
- **`cred_label_destroy`**: Remove o slot do mac label do AMFI
- **`cred_label_init`**: Coloca 0 no slot do mac label do AMFI
- **`cred_label_update_execve`:** Verifica os entitlements do processo para ver se ele deve ter permissão para modificar os labels.
- **`file_check_mmap`:** Verifica se mmap está adquirindo memória e definindo-a como executável. Nesse caso, verifica se a library validation é necessária e, se for, chama a função de library validation.
- **`file_check_library_validation`**: Chama a função de library validation, que verifica, entre outras coisas, se um platform binary está carregando outro platform binary ou se o processo e o novo arquivo carregado têm o mesmo TeamID. Certos entitlements também permitirão carregar qualquer library.
- **`policy_initbsd`**: Configura chaves confiáveis de NVRAM
- **`policy_syscall`**: Verifica políticas do DYLD, como se o binário tem segmentos unrestricted, se deve permitir variáveis de ambiente... isso também é chamado quando um processo é iniciado via `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Verifica se, quando um processo executa um novo binário, outros processos com direitos SEND sobre o task port do processo devem mantê-los ou não. Platform binaries são permitidos, entitlements `get-task-allow` permitem isso, entitlements `task_for_pid-allow` são permitidos e binários com o mesmo TeamID.
- **`proc_check_expose_task`**: impõe entitlements
- **`amfi_exc_action_check_exception_send`**: Uma mensagem de exceção é enviada ao debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Ciclo de vida do label durante o tratamento de exceção (debugging)
- **`proc_check_get_task`**: Verifica entitlements como `get-task-allow`, que permite que outros processos obtenham o task port, e `task_for_pid-allow`, que permite ao processo obter os task ports de outros processos. Se nenhum desses estiver presente, ele consulta o `amfid permitunrestricteddebugging` para verificar se isso é permitido.
- **`proc_check_mprotect`**: Nega se `mprotect` for chamado com a flag `VM_PROT_TRUSTED`, que indica que a região deve ser tratada como se tivesse uma code signature válida
- **`vnode_check_exec`**: É chamado quando arquivos executáveis são carregados na memória e define `cs_hard | cs_kill`, o que encerrará o processo se qualquer página se tornar inválida
- **`vnode_check_getextattr`**: MacOS: Verifica `com.apple.root.installed` e `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Igual a get + `com.apple.private.allow-bless` e o entitlement internal-installer-equivalent
- **`vnode_check_signature`**: Código que chama o XNU para verificar a code signature usando entitlements, trust cache e `amfid`
- **`proc_check_run_cs_invalid`**: Intercepta chamadas `ptrace()` (`PT_ATTACH` e `PT_TRACE_ME`). Verifica qualquer um dos entitlements `get-task-allow`, `run-invalid-allow` e `run-unsigned-code` e, se nenhum existir, verifica se o debugging é permitido.
- **`proc_check_map_anon`**: Se mmap for chamado com a flag **`MAP_JIT`**, o AMFI verificará o entitlement `dynamic-codesigning`.

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

Este é o daemon em modo usuário que `AMFI.kext` usará para verificar assinaturas de código em modo usuário.\
Para `AMFI.kext` se comunicar com o daemon, ele usa mensagens mach sobre a porta `HOST_AMFID_PORT`, que é a porta especial `18`.

Note que no macOS já não é mais possível para processos root sequestrarem portas especiais, pois elas são protegidas por `SIP` e apenas `launchd` pode obtê-las. No iOS, é verificado que o processo que envia a resposta de volta tem o CDHash hardcoded de `amfid`.

É possível ver quando `amfid` é solicitado para verificar um binary e a resposta dele, depurando-o e definindo um breakpoint em `mach_msg`.

Assim que uma mensagem é recebida pela porta especial, **MIG** é usado para enviar cada função para a função que ele está chamando. As funções principais foram reversadas e explicadas dentro do livro.

### DYLD policy and library validation

Versões mais recentes do `dyld` chamam `amfi_check_dyld_policy_self()` bem cedo, a partir de `configureProcessRestrictions()`, para perguntar ao AMFI se o processo pode usar variáveis de caminho `DYLD_*`, interposing, fallback paths, variáveis embutidas, ou tolerar falha na inserção de biblioteca. Portanto, ao triagear uma superfície de injection, não basta inspecionar apenas Mach-O load commands: você também precisa inspecionar os entitlements e flags de runtime que o AMFI vai traduzir em policy do `dyld`.

Um loop prático de triage é:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
No macOS moderno, muitos binários da Apple não carregam mais `com.apple.security.cs.disable-library-validation` diretamente e, em vez disso, vêm com `com.apple.private.security.clear-library-validation`. Nesse caso, a library validation não é desativada no momento do `execve`: o processo deve chamar `csops(..., CS_OPS_CLEAR_LV, ...)` em si mesmo, e o XNU só permite essa operação no processo chamador quando a entitlement está presente. Do ponto de vista ofensivo, isso importa porque um alvo pode se tornar injetável apenas **depois** de chegar ao caminho de código que limpa explicitamente a LV (por exemplo, pouco antes de carregar plugins opcionais).

## Provisioning Profiles

Um provisioning profile pode ser usado para assinar code. Existem perfis **Developer**, que podem ser usados para assinar code e testá-lo, e perfis **Enterprise**, que podem ser usados em todos os devices.

Depois que um App é enviado para a Apple Store, se aprovado, ele é assinado pela Apple e o provisioning profile não é mais necessário.

Um profile normalmente usa a extensão `.mobileprovision` ou `.provisionprofile` e pode ser dumpado com:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Embora às vezes referido como certificated, esses perfis de provisionamento têm mais do que um certificado:

- **AppIDName:** O Identificador da Aplicação
- **AppleInternalProfile**: Designa isto como um perfil Apple Internal
- **ApplicationIdentifierPrefix**: Prefixado a AppIDName (mesmo que TeamIdentifier)
- **CreationDate**: Data no formato `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Um array de certificado(s) (geralmente um), codificados como dados Base64
- **Entitlements**: Os entitlements permitidos com entitlements para este perfil
- **ExpirationDate**: Data de expiração no formato `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: O Nome da Aplicação, o mesmo que AppIDName
- **ProvisionedDevices**: Um array (para developer certificates) de UDIDs para os quais este perfil é válido
- **ProvisionsAllDevices**: Um booleano (true para enterprise certificates)
- **TeamIdentifier**: Um array de string(s) alfanuméricas (geralmente uma) usadas para identificar o developer para fins de interação entre apps
- **TeamName**: Um nome legível para humanos usado para identificar o developer
- **TimeToLive**: Validade (em dias) do certificado
- **UUID**: Um Identificador Único Universal para este perfil
- **Version**: Atualmente definido como 1

Note que a entrada de entitlements conterá um conjunto restrito de entitlements e o provisioning profile só poderá conceder esses entitlements específicos para evitar conceder Apple private entitlements.

Note que os perfis geralmente ficam localizados em `/var/MobileDeviceProvisioningProfiles` e é possível verificá-los com **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Esta é a biblioteca externa que `amfid` chama para perguntar se deve permitir algo ou não. Historicamente, isso foi abusado em jailbreaking ao executar uma versão backdoored dela que permitiria tudo.

No macOS, isso fica dentro de `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches não são apenas um conceito de iOS. No macOS moderno, especialmente em **Apple silicon**, o static trust cache e os loadable trust caches fazem parte da cadeia Secure Boot. Quando o **CodeDirectory hash** de um Mach-O está presente ali, o AMFI pode conceder a ele **platform privilege** sem fazer verificações adicionais de autenticidade no momento da execução. Isso também significa que a Apple pode prender os platform binaries a uma versão específica do sistema operacional e impedir que binaries assinados pela Apple mais antigos sejam reproduzidos em sistemas mais novos.

Em versões recentes do macOS, os metadados de trust-cache também estão vinculados a **launch constraints**, então apps e binaries do sistema copiados e iniciados a partir do parent/location errado podem ser rejeitados pelo AMFI mesmo que ainda estejam assinados pela Apple. O fluxo detalhado de extração e reversing é coberto em:

{{#ref}}
macos-launch-environment-constraints.md
{{endref}}

Em iOS e na pesquisa de jailbreak, você ainda encontrará o modelo tradicional de **loadable trust caches** sendo usado para whitelist de binaries assinados ad-hoc.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}

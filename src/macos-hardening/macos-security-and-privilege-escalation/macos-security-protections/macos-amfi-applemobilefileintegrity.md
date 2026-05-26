# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Ele se concentra em impor a integridade do código em execução no sistema, fornecendo a lógica por trás da verificação de code signature do XNU. Ele também é capaz de verificar entitlements e lidar com outras tarefas sensíveis, como permitir debugging ou obter task ports.

Além disso, para algumas operações, o kext prefere contatar o daemon em user space `/usr/libexec/amfid`. Essa relação de confiança foi abusada em vários jailbreaks.

Em versões recentes do macOS, o AMFI não é mais exposto convenientemente como um kext standalone em disco, então a análise reversa geralmente significa trabalhar a partir do **kernelcache** ou de um **KDK** em vez de navegar por `/System/Library/Extensions`.

AMFI usa políticas **MACF** e registra seus hooks no momento em que é iniciado. Além disso, impedir seu carregamento ou descarregá-lo pode disparar um kernel panic. No entanto, há alguns boot arguments que permitem debilitar o AMFI:

- `amfi_unrestricted_task_for_pid`: Permite que task_for_pid seja permitido sem as entitlements necessárias
- `amfi_allow_any_signature`: Permite qualquer code signature
- `cs_enforcement_disable`: Argumento em todo o sistema usado para desabilitar a aplicação de code signing
- `amfi_prevent_old_entitled_platform_binaries`: Invalida platform binaries com entitlements
- `amfi_get_out_of_my_way`: Desabilita o amfi completamente

Estas são algumas das políticas MACF que ele registra:

- **`cred_check_label_update_execve:`** A atualização do label será realizada e retornará 1
- **`cred_label_associate`**: Atualiza o slot de mac label do AMFI com o label
- **`cred_label_destroy`**: Remove o slot de mac label do AMFI
- **`cred_label_init`**: Move 0 no slot de mac label do AMFI
- **`cred_label_update_execve`:** Ele verifica as entitlements do processo para ver se ele deve ter permissão para modificar os labels.
- **`file_check_mmap`:** Ele verifica se mmap está adquirindo memória e definindo-a como executável. Nesse caso, ele verifica se library validation é necessária e, se for, chama a função de library validation.
- **`file_check_library_validation`**: Chama a função de library validation, que verifica, entre outras coisas, se um platform binary está carregando outro platform binary ou se o processo e o novo arquivo carregado têm o mesmo TeamID. Certas entitlements também permitirão carregar qualquer library.
- **`policy_initbsd`**: Define trusted NVRAM Keys
- **`policy_syscall`**: Ele verifica políticas de DYLD, como se o binary tem segmentos unrestricted, se deve permitir env vars... isso também é chamado quando um processo é iniciado via `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Ele verifica se, quando um processo executa um novo binary, outros processos com direitos SEND sobre o task port do processo devem mantê-los ou não. Platform binaries são permitidos, a entitlement `get-task-allow` permite isso, a entitlement `task_for_pid-allow` permite isso e binaries com o mesmo TeamID.
- **`proc_check_expose_task`**: impõe entitlements
- **`amfi_exc_action_check_exception_send`**: Uma mensagem de exception é enviada ao debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Ciclo de vida do label durante o tratamento de exception (debugging)
- **`proc_check_get_task`**: Verifica entitlements como `get-task-allow`, que permite que outros processos obtenham o task port, e `task_for_pid-allow`, que permite que o processo obtenha os task ports de outros processos. Se nenhuma dessas existir, ele chama `amfid permitunrestricteddebugging` para verificar se isso é permitido.
- **`proc_check_mprotect`**: Nega se `mprotect` for chamado com a flag `VM_PROT_TRUSTED`, que indica que a região deve ser tratada como se tivesse uma code signature válida.
- **`vnode_check_exec`**: É chamado quando arquivos executáveis são carregados na memória e define `cs_hard | cs_kill`, o que matará o processo se qualquer uma das páginas se tornar inválida
- **`vnode_check_getextattr`**: MacOS: Verifica `com.apple.root.installed` e `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Como get + `com.apple.private.allow-bless` e entitlement internal-installer-equivalent
- **`vnode_check_signature`**: Código que chama o XNU para verificar a code signature usando entitlements, trust cache e `amfid`
- **`proc_check_run_cs_invalid`**: Intercepta chamadas `ptrace()` (`PT_ATTACH` e `PT_TRACE_ME`). Verifica qualquer uma das entitlements `get-task-allow`, `run-invalid-allow` e `run-unsigned-code` e, se nenhuma existir, verifica se debugging é permitido.
- **`proc_check_map_anon`**: Se mmap for chamado com a flag **`MAP_JIT`**, o AMFI verificará a entitlement `dynamic-codesigning`.

`AMFI.kext` também expõe uma API para outros kernel extensions, e é possível encontrar suas dependências com:
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

Note que no macOS já não é mais possível para processos root sequestrarem portas especiais, pois elas são protegidas por `SIP` e somente o launchd pode obtê-las. No iOS, é verificado que o processo que envia a resposta de volta tenha o CDHash hardcoded de `amfid`.

É possível ver quando `amfid` é solicitado a verificar um binary e a resposta dele depurando-o e definindo um breakpoint em `mach_msg`.

Uma vez que uma mensagem é recebida pela porta especial, **MIG** é usado para enviar cada function para a function que ela está chamando. As main functions foram revertidas e explicadas dentro do book.

### Política DYLD e library validation

Versões recentes do `dyld` chamam `amfi_check_dyld_policy_self()` muito cedo em `configureProcessRestrictions()` para perguntar ao AMFI se o processo pode usar variáveis de caminho `DYLD_*`, interposing, fallback paths, embedded variables ou tolerar a falha na inserção de library. Portanto, ao fazer triage de uma surface de injection, não basta inspecionar apenas os load commands do Mach-O: você também precisa inspecionar as entitlements e flags de runtime que o AMFI vai traduzir em policy do `dyld`.

Um loop prático de triage é:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
No macOS moderno, muitos binários da Apple já não carregam mais diretamente `com.apple.security.cs.disable-library-validation` e, em vez disso, vêm com `com.apple.private.security.clear-library-validation`. Nesse caso, a library validation não é desativada no momento de `execve`: o processo precisa chamar `csops(..., CS_OPS_CLEAR_LV, ...)` em si mesmo, e o XNU só permite essa operação no processo chamador quando a entitlement está presente. Do ponto de vista ofensivo, isso importa porque um alvo pode se tornar injetável somente **depois** que alcança o caminho de código que limpa explicitamente a LV (por exemplo, pouco antes de carregar plugins opcionais).

## Provisioning Profiles

Um provisioning profile pode ser usado para assinar código. Existem profiles de **Developer** que podem ser usados para assinar código e testá-lo, e profiles **Enterprise** que podem ser usados em todos os dispositivos.

Depois que um App é enviado para a Apple Store, se aprovado, ele é assinado pela Apple e o provisioning profile não é mais necessário.

Um profile normalmente usa a extensão `.mobileprovision` ou `.provisionprofile` e pode ser extraído com:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Embora às vezes sejam chamados de certificated, esses provisioning profiles têm mais do que um certificate:

- **AppIDName:** O Application Identifier
- **AppleInternalProfile**: Designa este como um Apple Internal profile
- **ApplicationIdentifierPrefix**: Prefixado a AppIDName (o mesmo que TeamIdentifier)
- **CreationDate**: Data no formato `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Um array de certificate(s) (normalmente um), codificados como dados Base64
- **Entitlements**: Os entitlements permitidos com entitlements para este profile
- **ExpirationDate**: Data de expiração no formato `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: O Application Name, o mesmo que AppIDName
- **ProvisionedDevices**: Um array (para developer certificates) de UDIDs para os quais este profile é válido
- **ProvisionsAllDevices**: Um booleano (true para enterprise certificates)
- **TeamIdentifier**: Um array de string(s) alfanuméricas (normalmente uma) usadas para identificar o developer para fins de interação entre apps
- **TeamName**: Um nome legível por humanos usado para identificar o developer
- **TimeToLive**: Validade (em dias) do certificate
- **UUID**: Um Universally Unique Identifier para este profile
- **Version**: Atualmente definido como 1

Observe que a entrada de entitlements conterá um conjunto restrito de entitlements e o provisioning profile só poderá conceder esses entitlements específicos para evitar conceder Apple private entitlements.

Observe que os profiles geralmente ficam em `/var/MobileDeviceProvisioningProfiles` e é possível verificá-los com **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Esta é a external library que `amfid` chama para perguntar se deve permitir algo ou não. Isso foi historicamente abusado em jailbreaking executando uma versão backdoored dela que permitiria tudo.

No macOS isso fica dentro de `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches não são apenas um conceito de iOS. No macOS moderno, especialmente em **Apple silicon**, o static trust cache e os loadable trust caches fazem parte da cadeia Secure Boot. Quando o **CodeDirectory hash** de um Mach-O está presente ali, o AMFI pode conceder a ele **platform privilege** sem fazer verificações adicionais de autenticidade no momento da inicialização. Isso também significa que a Apple pode limitar binaries de platform a uma versão específica do OS e impedir que binaries assinados pela Apple mais antigos sejam reutilizados em sistemas mais novos.

Em versões recentes do macOS, os metadados do trust-cache também estão ligados a **launch constraints**, então cópias de system apps e binaries iniciados a partir do parent/location errado podem ser rejeitados pelo AMFI mesmo que ainda estejam assinados pela Apple. O fluxo detalhado de extração e reversing é coberto em:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Em iOS e em pesquisas de jailbreak você ainda encontrará o modelo tradicional de **loadable trust caches** sendo usado para whitelistar binaries assinados ad-hoc.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}

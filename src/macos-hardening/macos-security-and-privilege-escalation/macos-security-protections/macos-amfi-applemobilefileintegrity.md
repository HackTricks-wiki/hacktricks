# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext e amfid

Ele se concentra em impor a integridade do código em execução no sistema, fornecendo a lógica por trás da verificação de assinatura de código do XNU. Ele também é capaz de verificar entitlements e lidar com outras tarefas sensíveis, como permitir debugging ou obter task ports.

Além disso, para algumas operações, o kext prefere entrar em contato com o daemon em user space `/usr/libexec/amfid`. Essa relação de confiança foi abusada em vários jailbreaks.

Nas versões recentes do macOS, o AMFI não é mais convenientemente exposto como um kext independente armazenado no disco, portanto, fazer reversing geralmente significa trabalhar a partir do **kernelcache** ou de um **KDK**, em vez de navegar por `/System/Library/Extensions`.

O AMFI usa políticas **MACF** e registra seus hooks assim que é iniciado. Além disso, impedir seu carregamento ou descarregá-lo pode causar um kernel panic. No entanto, existem alguns boot arguments que permitem debilitar o AMFI:

- `amfi_unrestricted_task_for_pid`: Permite que task_for_pid seja permitido sem os entitlements necessários
- `amfi_allow_any_signature`: Permite qualquer assinatura de código
- `cs_enforcement_disable`: Argumento usado em todo o sistema para desabilitar a imposição de assinatura de código
- `amfi_prevent_old_entitled_platform_binaries`: Invalida platform binaries com entitlements
- `amfi_get_out_of_my_way`: Desabilita completamente o amfi

Estas são algumas das políticas MACF que ele registra:<sup>[1]</sup>

- **`cred_check_label_update_execve:`** A atualização do label será realizada e retornará 1
- **`cred_label_associate`**: Atualiza o slot de mac label do AMFI com o label
- **`cred_label_destroy`**: Remove o slot de mac label do AMFI
- **`cred_label_init`**: Move 0 para o slot de mac label do AMFI
- **`cred_label_update_execve:`**: Verifica os entitlements do processo para verificar se ele deve ter permissão para modificar os labels.
- **`file_check_mmap:`**: Verifica se mmap está adquirindo memória e definindo-a como executável. Nesse caso, verifica se a library validation é necessária e, se for, chama a função de library validation.
- **`file_check_library_validation`**: Chama a função de library validation, que verifica, entre outras coisas, se uma platform binary está carregando outra platform binary ou se o processo e o novo arquivo carregado têm o mesmo TeamID. Certos entitlements também permitirão carregar qualquer library.
- **`policy_initbsd`**: Configura as trusted NVRAM Keys
- **`policy_syscall`**: Verifica políticas DYLD, como se o binário tem segmentos unrestricted, se deve permitir env vars... isso também é chamado quando um processo é iniciado por meio de `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Verifica se, quando um processo executa um novo binário, outros processos com direitos SEND sobre o task port do processo devem mantê-los ou não. Platform binaries têm permissão, o entitlement `get-task-allow` permite isso, entitlements `task_for_pid-allow` têm permissão e binários com o mesmo TeamID também.
- **`proc_check_expose_task`**: Impõe entitlements
- **`amfi_exc_action_check_exception_send`**: Uma mensagem de exception é enviada ao debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Ciclo de vida do label durante o tratamento de exceptions (debugging)
- **`proc_check_get_task`**: Verifica entitlements como `get-task-allow`, que permite que outros processos obtenham o task port do processo, e `task_for_pid-allow`, que permite ao processo obter os task ports de outros processos. Se nenhum deles estiver presente, chama `amfid permitunrestricteddebugging` para verificar se isso é permitido.
- **`proc_check_mprotect`**: Nega se `mprotect` for chamado com a flag `VM_PROT_TRUSTED`, que indica que a região deve ser tratada como se tivesse uma assinatura de código válida.
- **`vnode_check_exec`**: É chamado quando arquivos executáveis são carregados na memória e define `cs_hard | cs_kill`, o que encerrará o processo se alguma das páginas se tornar inválida<sup>[2]</sup>
- **`vnode_check_getextattr`**: MacOS: Verifica `com.apple.root.installed` e `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Assim como get + entitlement `com.apple.private.allow-bless` e `internal-installer-equivalent`
- **`vnode_check_signature`**: Código que chama o XNU para verificar a assinatura de código usando entitlements, trust cache e `amfid`<sup>[3]</sup>
- **`proc_check_run_cs_invalid`**: Intercepta chamadas `ptrace()` (`PT_ATTACH` e `PT_TRACE_ME`). Verifica a presença de qualquer um dos entitlements `get-task-allow`, `run-invalid-allow` e `run-unsigned-code` e, se nenhum estiver presente, verifica se debugging é permitido.
- **`proc_check_map_anon`**: Se mmap for chamado com a flag **`MAP_JIT`**, o AMFI verificará o entitlement `dynamic-codesigning`.

O `AMFI.kext` também expõe uma API para outras kernel extensions, e é possível encontrar suas dependências com:
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

Este é o daemon executado em user mode que `AMFI.kext` usará para verificar code signatures em user mode.\
Para que `AMFI.kext` se comunique com o daemon, ele usa mach messages através da porta `HOST_AMFID_PORT`, que é a porta especial `18`.

Observe que, no macOS, não é mais possível que processos root sequestrem portas especiais, pois elas são protegidas pelo `SIP` e somente o launchd pode obtê-las. No iOS, é verificado se o processo que envia a resposta de volta possui o CDHash de `amfid` hardcoded.

É possível ver quando `amfid` é solicitado a verificar um binary e a resposta enviada por ele fazendo debugging e definindo um breakpoint em `mach_msg`.

Quando uma mensagem é recebida através da porta especial, o **MIG** é usado para encaminhar cada função à função que está sendo chamada. As principais funções foram revertidas e explicadas no livro.

### DYLD policy and library validation

Versões recentes do `dyld` chamam `amfi_check_dyld_policy_self()` muito cedo, a partir de `configureProcessRestrictions()`, para perguntar ao AMFI se o processo pode usar variáveis de caminho `DYLD_*`, interposing, fallback paths, embedded variables ou tolerar falhas na library insertion. Portanto, ao fazer a triagem de uma injection surface, não basta inspecionar apenas os load commands do Mach-O: também é necessário inspecionar os entitlements e runtime flags que o AMFI traduzirá em uma `dyld` policy.

Um loop prático de triagem é:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
No macOS moderno, muitos binários da Apple não carregam mais `com.apple.security.cs.disable-library-validation` diretamente e, em vez disso, são distribuídos com `com.apple.private.security.clear-library-validation`. Nesse caso, a library validation não é desabilitada no momento do `execve`: o processo precisa chamar `csops(..., CS_OPS_CLEAR_LV, ...)` sobre si mesmo, e o XNU só permite essa operação no processo que faz a chamada quando o entitlement está presente. De uma perspectiva ofensiva, isso é importante porque um alvo pode se tornar injetável somente **depois** de alcançar o caminho de código que limpa explicitamente a LV (por exemplo, pouco antes de carregar plugins opcionais).<sup>[4][5]</sup>

## Perfis de Provisionamento

Um provisioning profile pode ser usado para assinar código. Existem perfis **Developer**, que podem ser usados para assinar código e testá-lo, e perfis **Enterprise**, que podem ser usados em todos os dispositivos.

Depois que um App é enviado à Apple Store e aprovado, ele é assinado pela Apple, e o provisioning profile deixa de ser necessário.

Um perfil geralmente usa a extensão `.mobileprovision` ou `.provisionprofile` e pode ser extraído com:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Embora às vezes sejam chamados de certificados, esses provisioning profiles contêm mais do que um certificado:

- **AppIDName:** O identificador da aplicação
- **AppleInternalProfile**: Designa este como um profile interno da Apple
- **ApplicationIdentifierPrefix**: Adicionado como prefixo a AppIDName (igual a TeamIdentifier)
- **CreationDate**: Data no formato `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Um array de certificado(s) (geralmente um), codificado como dados Base64
- **Entitlements**: Os entitlements permitidos para este profile
- **ExpirationDate**: Data de expiração no formato `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: O nome da aplicação, igual a AppIDName
- **ProvisionedDevices**: Um array (para certificados de desenvolvedor) de UDIDs para os quais este profile é válido
- **ProvisionsAllDevices**: Um booleano (true para certificados enterprise)
- **TeamIdentifier**: Um array de string(s) alfanumérica(s) (geralmente uma) usada(s) para identificar o desenvolvedor para fins de interação entre aplicações
- **TeamName**: Um nome legível usado para identificar o desenvolvedor
- **TimeToLive**: Validade (em dias) do certificado
- **UUID**: Um identificador universalmente exclusivo para este profile
- **Version**: Atualmente definido como 1

Observe que a entrada de entitlements conterá um conjunto restrito de entitlements, e o provisioning profile só poderá conceder esses entitlements específicos, impedindo a concessão de entitlements privados da Apple.

Observe que os profiles geralmente estão localizados em `/var/MobileDeviceProvisioningProfiles` e podem ser verificados com **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Esta é a biblioteca externa que `amfid` chama para perguntar se deve permitir algo ou não. Historicamente, ela foi abusada em jailbreaking por meio da execução de uma versão backdoored que permitia qualquer coisa.

No macOS, ela está dentro de `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches não são um conceito exclusivo do iOS. No macOS moderno, especialmente no **Apple silicon**, o static trust cache e os loadable trust caches fazem parte da cadeia do Secure Boot. Quando o **hash do CodeDirectory** de um Mach-O está presente neles, o AMFI pode conceder a ele **platform privilege** sem realizar verificações adicionais de autenticidade no momento da inicialização. Isso também significa que a Apple pode vincular binários da plataforma a uma versão específica do sistema operacional e impedir que binários antigos assinados pela Apple sejam reutilizados em sistemas mais novos.<sup>[6]</sup>

Nas versões recentes do macOS, os metadados do trust cache também estão vinculados a **launch constraints**, portanto, aplicações e binários do sistema copiados e iniciados a partir do parent/localização incorretos podem ser rejeitados pelo AMFI mesmo que ainda estejam assinados pela Apple. O workflow detalhado de extração e reversing é abordado em:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Em pesquisas de iOS e jailbreak, você ainda encontrará o modelo tradicional de **loadable trust caches** sendo usado para permitir binários assinados ad-hoc.

## Referências

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}

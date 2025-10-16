# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

**MACF** significa **Mandatory Access Control Framework**, que é um sistema de segurança integrado ao sistema operacional para ajudar a proteger seu computador. Ele funciona definindo **regras estritas sobre quem ou o que pode acessar certas partes do sistema**, como arquivos, aplicações e recursos do sistema. Ao aplicar essas regras automaticamente, o MACF garante que apenas usuários e processos autorizados possam executar ações específicas, reduzindo o risco de acesso não autorizado ou atividades maliciosas.

Observe que o MACF na verdade não toma decisões, ele apenas **intercepta** ações, deixando as decisões para os **módulos de política** (extensões do kernel) que ele chama, como `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` e `mcxalr.kext`.

- Uma política pode ser de imposição (pode negar — retornar um valor não-zero em alguma operação)
- Uma política pode ser de monitoramento (retornar 0, para não se opor, mas aproveitar o hook para fazer algo)
- Uma política estática do MACF é instalada no boot e NUNCA será removida
- Uma política dinâmica do MACF é instalada por um KEXT (kextload) e pode, hipoteticamente, ser kextunloaded
- No iOS apenas políticas estáticas são permitidas e no macOS políticas estáticas + dinâmicas.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Fluxo

1. O processo realiza uma syscall/mach trap
2. A função relevante é chamada dentro do kernel
3. A função chama o MACF
4. O MACF verifica os módulos de política que requisitaram hook nessa função em sua policy
5. O MACF chama as políticas relevantes
6. As políticas indicam se permitem ou negam a ação

> [!CAUTION]
> A Apple é a única que pode usar o MAC Framework KPI.

Normalmente as funções que verificam permissões com o MACF chamarão a macro `MAC_CHECK`. Como no caso de uma syscall para criar um socket, que chamará a função `mac_socket_check_create` que chama `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Além disso, a macro `MAC_CHECK` é definida em security/mac_internal.h como:
```c
Resolver tambien MAC_POLICY_ITERATE, MAC_CHECK_CALL, MAC_CHECK_RSLT


#define MAC_CHECK(check, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_ ## check != NULL) {                   \
MAC_CHECK_CALL(check, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
MAC_CHECK_RSLT(check, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
Observe que transformando `check` em `socket_check_create` e `args...` em `(cred, domain, type, protocol)` você obtém:
```c
// Note the "##" just get the param name and append it to the prefix
#define MAC_CHECK(socket_check_create, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {                   \
MAC_CHECK_CALL(socket_check_create, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_socket_check_create (args); \
MAC_CHECK_RSLT(socket_check_create, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
A expansão dos macros auxiliares mostra o fluxo de controle concreto:
```c
do {                                                // MAC_CHECK
error = 0;
do {                                            // MAC_POLICY_ITERATE
struct mac_policy_conf *mpc;
u_int i;
for (i = 0; i < mac_policy_list.staticmax; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK); // MAC_CHECK_CALL
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);                    // MAC_CHECK_RSLT
error = mac_error_select(__step_err, error);
}
}
if (mac_policy_list_conditional_busy() != 0) {
for (; i <= mac_policy_list.maxindex; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK);
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);
error = mac_error_select(__step_err, error);
}
}
mac_policy_list_unbusy();
}
} while (0);
} while (0);
```
Em outras palavras, `MAC_CHECK(socket_check_create, ...)` percorre primeiro as políticas estáticas, condicionalmente bloqueia e itera sobre as políticas dinâmicas, emite as probes DTrace ao redor de cada hook, e colapsa o código de retorno de cada hook no único resultado `error` via `mac_error_select()`.


### Etiquetas

O MACF usa **rótulos** que as políticas usam para verificar se devem conceder ou não algum acesso. O código da declaração da struct de rótulos pode ser [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), que é então usado dentro da **`struct ucred`** em [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) na parte **`cr_label`**. O rótulo contém flags e um número de **slots** que podem ser usados por **MACF policies to allocate pointers**. Por exemplo Sanbox apontará para o perfil do container

## MACF Policies

Uma MACF Policy define **regras e condições a serem aplicadas em certas operações do kernel**.

Uma extensão de kernel pode configurar uma struct `mac_policy_conf` e então registrá-la chamando `mac_policy_register`. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered enty point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better aligment on 64bit platforms */
struct mac_policy_conf {
const char		*mpc_name;		/** policy name */
const char		*mpc_fullname;		/** full name */
const char		**mpc_labelnames;	/** managed label namespaces */
unsigned int		 mpc_labelname_count;	/** number of managed label namespaces */
struct mac_policy_ops	*mpc_ops;		/** operation vector */
int			 mpc_loadtime_flags;	/** load time flags */
int			*mpc_field_off;		/** label slot */
int			 mpc_runtime_flags;	/** run time flags */
mpc_t			 mpc_list;		/** List reference */
void			*mpc_data;		/** module data */
};
```
É fácil identificar as kernel extensions que configuram essas políticas verificando chamadas para `mac_policy_register`. Além disso, ao verificar a desmontagem da extensão, também é possível encontrar a struct `mac_policy_conf` utilizada.

Observe que as políticas MACF podem ser registradas e desregistradas também **dinamicamente**.

Um dos principais campos da `mac_policy_conf` é o **`mpc_ops`**. Esse campo especifica em quais operações a política está interessada. Observe que existem centenas delas, então é possível zerar todas e depois selecionar apenas aquelas nas quais a política tem interesse. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
```c
struct mac_policy_ops {
mpo_audit_check_postselect_t		*mpo_audit_check_postselect;
mpo_audit_check_preselect_t		*mpo_audit_check_preselect;
mpo_bpfdesc_label_associate_t		*mpo_bpfdesc_label_associate;
mpo_bpfdesc_label_destroy_t		*mpo_bpfdesc_label_destroy;
mpo_bpfdesc_label_init_t		*mpo_bpfdesc_label_init;
mpo_bpfdesc_check_receive_t		*mpo_bpfdesc_check_receive;
mpo_cred_check_label_update_execve_t	*mpo_cred_check_label_update_execve;
mpo_cred_check_label_update_t		*mpo_cred_check_label_update;
[...]
```
Quase todos os hooks serão chamados pelo MACF quando uma dessas operações for interceptada. Contudo, os hooks **`mpo_policy_*`** são uma exceção porque `mpo_hook_policy_init()` é um callback chamado no momento do registo (ou seja, após `mac_policy_register()`), e `mpo_hook_policy_initbsd()` é chamado durante um registo tardio, uma vez que o subsistema BSD tenha inicializado correctamente.

Além disso, o hook **`mpo_policy_syscall`** pode ser registado por qualquer kext para expor uma **interface** privada do tipo **ioctl**. Então, um user client poderá chamar `mac_syscall` (#381) especificando como parâmetros o **policy name** com um **code** inteiro e **arguments** opcionais.\
Por exemplo, o **`Sandbox.kext`** usa isto frequentemente.

Ao verificar o **`__DATA.__const*`** do kext é possível identificar a estrutura `mac_policy_ops` usada ao registar a policy. É possível encontrá-la porque o seu ponteiro está num offset dentro de `mpo_policy_conf` e também pela quantidade de ponteiros NULL que estarão nessa área.

Além disso, também é possível obter a lista de kexts que configuraram uma policy fazendo o dump da struct **`_mac_policy_list`** na memória, que é atualizada com cada policy registada.

Também é possível usar a ferramenta `xnoop` para fazer o dump de todas as policies registadas no sistema:
```bash
xnoop offline .

Xn👀p> macp
mac_policy_list(@0xfffffff0447159b8): 3 Mac Policies@0xfffffff0447153f0
0: 0xfffffff044886f18:
mpc_name: AppleImage4
mpc_fullName: AppleImage4 hooks
mpc_ops: mac_policy_ops@0xfffffff044886f68
1: 0xfffffff0448d7d40:
mpc_name: AMFI
mpc_fullName: Apple Mobile File Integrity
mpc_ops: mac_policy_ops@0xfffffff0448d72c8
2: 0xfffffff044b0b950:
mpc_name: Sandbox
mpc_fullName: Seatbelt sandbox policy
mpc_ops: mac_policy_ops@0xfffffff044b0b9b0
Xn👀p> dump mac_policy_opns@0xfffffff0448d72c8
Type 'struct mac_policy_opns' is unrecognized - dumping as raw 64 bytes
Dumping 64 bytes from 0xfffffff0448d72c8
```
E então dump todos os checks do check policy com:
```bash
Xn👀p> dump mac_policy_ops@0xfffffff044b0b9b0
Dumping 2696 bytes from 0xfffffff044b0b9b0 (as struct mac_policy_ops)

mpo_cred_check_label_update_execve(@0x30): 0xfffffff046d7fb54(PACed)
mpo_cred_check_label_update(@0x38): 0xfffffff046d7348c(PACed)
mpo_cred_label_associate(@0x58): 0xfffffff046d733f0(PACed)
mpo_cred_label_destroy(@0x68): 0xfffffff046d733e4(PACed)
mpo_cred_label_update_execve(@0x90): 0xfffffff046d7fb60(PACed)
mpo_cred_label_update(@0x98): 0xfffffff046d73370(PACed)
mpo_file_check_fcntl(@0xe8): 0xfffffff046d73164(PACed)
mpo_file_check_lock(@0x110): 0xfffffff046d7309c(PACed)
mpo_file_check_mmap(@0x120): 0xfffffff046d72fc4(PACed)
mpo_file_check_set(@0x130): 0xfffffff046d72f2c(PACed)
mpo_reserved08(@0x168): 0xfffffff046d72e3c(PACed)
mpo_reserved09(@0x170): 0xfffffff046d72e34(PACed)
mpo_necp_check_open(@0x1f0): 0xfffffff046d72d9c(PACed)
mpo_necp_check_client_action(@0x1f8): 0xfffffff046d72cf8(PACed)
mpo_vnode_notify_setextattr(@0x218): 0xfffffff046d72ca4(PACed)
mpo_vnode_notify_setflags(@0x220): 0xfffffff046d72c84(PACed)
mpo_proc_check_get_task_special_port(@0x250): 0xfffffff046d72b98(PACed)
mpo_proc_check_set_task_special_port(@0x258): 0xfffffff046d72ab4(PACed)
mpo_vnode_notify_unlink(@0x268): 0xfffffff046d72958(PACed)
mpo_vnode_check_copyfile(@0x290): 0xfffffff046d726c0(PACed)
mpo_mount_check_quotactl(@0x298): 0xfffffff046d725c4(PACed)
...
```
## Inicialização do MACF no XNU

### Bootstrap inicial e mac_policy_init()

- MACF é inicializado muito cedo. Em `bootstrap_thread` (no código de startup do XNU), após `ipc_bootstrap`, o XNU chama `mac_policy_init()` (em `mac_base.c`).
- `mac_policy_init()` inicializa a `mac_policy_list` global (um array ou lista de slots de políticas) e configura a infraestrutura para MAC (Controle de Acesso Obrigatório) dentro do XNU.
- Mais adiante, `mac_policy_initmach()` é invocado, o qual trata do lado do kernel do registro de políticas para políticas embutidas ou empacotadas.

### `mac_policy_initmach()` e carregamento de “extensões de segurança”

- `mac_policy_initmach()` examina kernel extensions (kexts) que estão pré-carregadas (ou em uma lista de “policy injection”) e inspeciona seu Info.plist em busca da chave `AppleSecurityExtension`.
- Kexts que declaram `<key>AppleSecurityExtension</key>` (ou `true`) no seu Info.plist são consideradas “extensões de segurança” — ou seja, aquelas que implementam uma política MAC ou que se conectam à infraestrutura MACF.
- Exemplos de kexts da Apple com essa chave incluem **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, entre outros (como você já listou).
- O kernel garante que esses kexts sejam carregados cedo, então chama suas rotinas de registro (via `mac_policy_register`) durante o boot, inserindo-os na `mac_policy_list`.

- Cada módulo de política (kext) fornece uma estrutura `mac_policy_conf`, com hooks (`mpc_ops`) para várias operações MAC (verificações de vnode, verificações de exec, atualizações de label, etc.).
- As flags de tempo de carregamento podem incluir `MPC_LOADTIME_FLAG_NOTLATE`, significando “deve ser carregado cedo” (portanto tentativas de registro tardias são rejeitadas).
- Uma vez registrados, cada módulo recebe um handle e ocupa um slot em `mac_policy_list`.
- Quando um hook MAC é invocado posteriormente (por exemplo, acesso a vnode, exec, etc.), o MACF itera por todas as políticas registradas para tomar decisões coletivas.

- Em particular, **AMFI** (Apple Mobile File Integrity) é uma dessas extensões de segurança. Seu Info.plist inclui `AppleSecurityExtension` marcando-o como uma política de segurança.
- Como parte do boot do kernel, a lógica de carregamento do kernel garante que a “security policy” (AMFI, etc.) já esteja ativa antes que muitos subsistemas dependam dela. Por exemplo, o kernel “prepares for tasks ahead by loading … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
```bash
cd /System/Library/Extensions
find . -name Info.plist | xargs grep AppleSecurityExtension 2>/dev/null

./AppleImage4.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./ALF.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./CoreTrust.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleMobileFileIntegrity.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Quarantine.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Sandbox.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleSystemPolicy.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
```
## Dependência de KPI & com.apple.kpi.dsep em kexts de política MAC

Ao escrever um kext que usa o MAC framework (ou seja, chamando `mac_policy_register()` etc.), você deve declarar dependências em KPIs (Interfaces de Programação do Kernel) para que o linker do kext (kxld) possa resolver esses símbolos. Portanto, para declarar que um `kext` depende do MACF você precisa indicá-lo no `Info.plist` com `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), assim o kext fará referência a símbolos como `mac_policy_register`, `mac_policy_unregister`, e ponteiros para funções de hook do MAC. Para resolver esses símbolos, você deve listar `com.apple.kpi.dsep` como uma dependência.

Exemplo de trecho do Info.plist (dentro do seu .kext):
```xml
<key>OSBundleLibraries</key>
<dict>
<key>com.apple.kpi.dsep</key>
<string>18.0</string>
<key>com.apple.kpi.libkern</key>
<string>18.0</string>
<key>com.apple.kpi.bsd</key>
<string>18.0</string>
<key>com.apple.kpi.mach</key>
<string>18.0</string>
… (other kpi dependencies as needed)
</dict>
```
## Chamadas MACF

É comum encontrar callouts para MACF definidos em código como: **`#if CONFIG_MAC`** blocos condicionais. Além disso, dentro desses blocos é possível encontrar chamadas para `mac_proc_check*` que chama MACF para **verificar permissões** para executar certas ações. Além disso, o formato das chamadas MACF é: **`mac_<object>_<opType>_opName`**.

O objeto é um dos seguintes: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
O `opType` é usually check que será usado para permitir ou negar a ação. Entretanto, também é possível encontrar `notify`, que permitirá ao kext reagir à ação em questão.

Você pode encontrar um exemplo em [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
&maxprot);
if (error) {
(void)vnode_put(vp);
goto bad;
}
#endif /* MAC */
[...]
</code></pre>

Em seguida, é possível encontrar o código de `mac_file_check_mmap` em [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
```c
mac_file_check_mmap(struct ucred *cred, struct fileglob *fg, int prot,
int flags, uint64_t offset, int *maxprot)
{
int error;
int maxp;

maxp = *maxprot;
MAC_CHECK(file_check_mmap, cred, fg, NULL, prot, flags, offset, &maxp);
if ((maxp | *maxprot) != *maxprot) {
panic("file_check_mmap increased max protections");
}
*maxprot = maxp;
return error;
}
```
Que chama a macro `MAC_CHECK`, cujo código pode ser encontrado em [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
```c
/*
* MAC_CHECK performs the designated check by walking the policy
* module list and checking with each as to how it feels about the
* request.  Note that it returns its value via 'error' in the scope
* of the caller.
*/
#define MAC_CHECK(check, args...) do {                              \
error = 0;                                                      \
MAC_POLICY_ITERATE({                                            \
if (mpc->mpc_ops->mpo_ ## check != NULL) {              \
DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_CHECK); \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_err); \
error = mac_error_select(__step_err, error);         \
}                                                           \
});                                                             \
} while (0)
```
Que percorrerá todas as políticas mac registradas chamando suas funções e armazenando a saída na variável error, que só poderá ser sobrescrita por `mac_error_select` por códigos de sucesso; assim, se qualquer verificação falhar a verificação completa falhará e a ação não será permitida.

> [!TIP]
> No entanto, lembre-se de que nem todos os callouts MACF são usados apenas para negar ações. Por exemplo, `mac_priv_grant` chama a macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), que concederá o privilégio solicitado se qualquer política responder com 0:
>
> ```c
> /*
> * MAC_GRANT performs the designated check by walking the policy
> * module list and checking with each as to how it feels about the
> * request.  Unlike MAC_CHECK, it grants if any policies return '0',
> * and otherwise returns EPERM.  Note that it returns its value via
> * 'error' in the scope of the caller.
> */
> #define MAC_GRANT(check, args...) do {                              \
>    error = EPERM;                                                  \
>    MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>    });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

These callas are meant to check and provide (tens of) **privilégios** defined in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Algum código do kernel chamaria `priv_check_cred()` de [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) com as credenciais KAuth do processo e um dos códigos de privilégios, o qual chamará `mac_priv_check` para ver se alguma política **nega** conceder o privilégio e então chamará `mac_priv_grant` para ver se alguma política concede o `privilege`.

### proc_check_syscall_unix

This hook allows to intercept all system calls. In `bsd/dev/[i386|arm]/systemcalls.c` it's possible to see the declared function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), which contains this code:
```c
#if CONFIG_MACF
if (__improbable(proc_syscall_filter_mask(proc) != NULL && !bitstr_test(proc_syscall_filter_mask(proc), syscode))) {
error = mac_proc_check_syscall_unix(proc, syscode);
if (error) {
goto skip_syscall;
}
}
#endif /* CONFIG_MACF */
```
Isso verificará no processo chamador **bitmask** se a syscall atual deve chamar `mac_proc_check_syscall_unix`. Isso ocorre porque syscalls são chamadas com tanta frequência que é interessante evitar chamar `mac_proc_check_syscall_unix` toda vez.

Observe que a função `proc_set_syscall_filter_mask()`, que define o bitmask de syscalls em um processo, é chamada pelo Sandbox para aplicar máscaras em processos sandboxed.

## Syscalls expostas do MACF

É possível interagir com o MACF através de algumas syscalls definidas em [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
```c
/*
* Extended non-POSIX.1e interfaces that offer additional services
* available from the userland and kernel MAC frameworks.
*/
#ifdef __APPLE_API_PRIVATE
__BEGIN_DECLS
int      __mac_execve(char *fname, char **argv, char **envv, mac_t _label);
int      __mac_get_fd(int _fd, mac_t _label);
int      __mac_get_file(const char *_path, mac_t _label);
int      __mac_get_link(const char *_path, mac_t _label);
int      __mac_get_pid(pid_t _pid, mac_t _label);
int      __mac_get_proc(mac_t _label);
int      __mac_set_fd(int _fildes, const mac_t _label);
int      __mac_set_file(const char *_path, mac_t _label);
int      __mac_set_link(const char *_path, mac_t _label);
int      __mac_mount(const char *type, const char *path, int flags, void *data,
struct mac *label);
int      __mac_get_mount(const char *path, struct mac *label);
int      __mac_set_proc(const mac_t _label);
int      __mac_syscall(const char *_policyname, int _call, void *_arg);
__END_DECLS
#endif /*__APPLE_API_PRIVATE*/
```
## Referências

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}

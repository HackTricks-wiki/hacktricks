# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** significa **Mandatory Access Control Framework**, que é um sistema de segurança integrado ao sistema operacional para ajudar a proteger seu computador. Ele funciona definindo **regras rígidas sobre quem ou o que pode acessar certas partes do sistema**, como arquivos, aplicações e recursos do sistema. Ao aplicar essas regras automaticamente, o MACF garante que apenas usuários e processos autorizados possam executar ações específicas, reduzindo o risco de acesso não autorizado ou atividades maliciosas.

Observe que o MACF na verdade não toma nenhuma decisão, pois apenas **intercepta** ações; ele deixa as decisões para os **policy modules** (kernel extensions) que chama, como `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` e `mcxalr.kext`.

- Uma policy pode ser enforcing (retornar 0 ou non-zero em alguma operação)
- Uma policy pode ser monitoring (retornar 0, para não objetar, mas aproveitar o hook para fazer algo)
- Uma MACF static policy é instalada no boot e NUNCA será removida
- Uma MACF dynamic policy é instalada por uma KEXT (kextload) e pode, hipoteticamente, ser kextunloaded
- No iOS, apenas static policies são permitidas; no macOS, static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process performs a syscall/mach trap
2. A função relevante é chamada dentro do kernel
3. A função chama o MACF
4. O MACF verifica os policy modules que solicitaram hook para aquela função em sua policy
5. O MACF chama as policies relevantes
6. As policies indicam se permitem ou negam a ação

> [!CAUTION]
> A Apple é a única que pode usar o MAC Framework KPI.

Normalmente, as funções que verificam permissões com MACF chamam a macro `MAC_CHECK`. Como no caso da syscall para criar um socket, que chamará a função `mac_socket_check_create`, que chama `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Além disso, a macro `MAC_CHECK` é definida em security/mac_internal.h como:
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
Note que, transformando `check` em `socket_check_create` e `args...` em `(cred, domain, type, protocol)`, você obtém:
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
Expandindo as helper macros mostra o fluxo de controle concreto:
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
Em outras palavras, `MAC_CHECK(socket_check_create, ...)` percorre primeiro as políticas estáticas, bloqueia condicionalmente e itera sobre as políticas dinâmicas, emite os probes de DTrace em torno de cada hook e consolida o código de retorno de cada hook no único resultado `error` via `mac_error_select()`.


### Labels

MACF usa **labels** que, então, as políticas que verificam se devem conceder algum acesso ou não irão usar. O código da declaração da struct de labels pode ser [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), que então é usado dentro de **`struct ucred`** [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) na parte **`cr_label`**. O label contém flags e um número de **slots** que podem ser usados por **MACF policies to allocate pointers**. Por exemplo, o Sanbox apontará para o container profile

## MACF Policies

Uma MACF Policy define **rule and conditions to be applied in certain kernel operations**.

Uma kernel extension poderia configurar uma struct `mac_policy_conf` e então registrá-la chamando `mac_policy_register`. De [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
É fácil identificar as extensões do kernel que configuram essas políticas verificando chamadas a `mac_policy_register`. Além disso, ao examinar o disassemble da extension, também é possível encontrar a struct `mac_policy_conf` usada.

Observe que as políticas MACF também podem ser registradas e desregistradas de forma **dinâmica**.

Um dos principais campos de `mac_policy_conf` é o **`mpc_ops`**. Este campo especifica em quais operações a policy está interessada. Observe que existem centenas delas, então é possível zerar todas e depois selecionar apenas aquelas em que a policy está interessada. De [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Quase todos os hooks serão chamados de volta pelo MACF quando uma dessas operações for interceptada. No entanto, os hooks **`mpo_policy_*`** são uma exceção porque **`mpo_hook_policy_init()`** é um callback chamado durante o registro (ou seja, após `mac_policy_register()`) e **`mpo_hook_policy_initbsd()`** é chamado durante o registro tardio, uma vez que o subsistema BSD foi inicializado corretamente.

Além disso, o hook **`mpo_policy_syscall`** pode ser registrado por qualquer kext para expor uma **interface** privada no estilo **ioctl**. Então, um user client poderá chamar `mac_syscall` (#381), especificando como parâmetros o **nome da policy** com um inteiro **code** e **arguments** opcionais.\
Por exemplo, a **`Sandbox.kext`** usa isso bastante.

Verificar o **`__DATA.__const*`** da kext permite identificar a estrutura `mac_policy_ops` usada ao registrar a policy. É possível encontrá-la porque o seu ponteiro fica em um offset dentro de `mpo_policy_conf` e também pela quantidade de ponteiros NULL que existirão nessa área.

Além disso, também é possível obter a lista de kexts que configuraram uma policy despejando da memória a struct **`_mac_policy_list`**, que é atualizada com cada policy registrada.

Você também pode usar a ferramenta `xnoop` para despejar todas as policies registradas no sistema:
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
E então descarregue todas as verificações da política de verificação com:
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

### Bootstrap inicial e `mac_policy_init()`

- O MACF é inicializado muito cedo. Em `bootstrap_thread` (no código de startup do XNU), após `ipc_bootstrap`, o XNU chama `mac_policy_init()` (em `mac_base.c`).
- `mac_policy_init()` inicializa a `mac_policy_list` global (um array ou lista de slots de policy) e configura a infraestrutura para MAC (Mandatory Access Control) dentro do XNU.
- Mais tarde, `mac_policy_initmach()` é invocado, que lida com o lado do kernel do registro de policies para policies integradas ou empacotadas.

### `mac_policy_initmach()` e carregamento de “security extensions”

- `mac_policy_initmach()` examina extensões de kernel (kexts) que estão pré-carregadas (ou em uma lista de “policy injection”) e inspeciona o Info.plist delas em busca da chave `AppleSecurityExtension`.
- Kexts que declaram `<key>AppleSecurityExtension</key>` (ou `true`) no Info.plist são consideradas “security extensions” — ou seja, aquelas que implementam uma MAC policy ou se conectam à infraestrutura MACF.
- Exemplos de kexts da Apple com essa chave incluem **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, entre outras (como você já listou).
- O kernel garante que esses kexts sejam carregados cedo e, então, chama suas rotinas de registro (via `mac_policy_register`) durante o boot, inserindo-as na `mac_policy_list`.

- Cada módulo de policy (kext) fornece uma estrutura `mac_policy_conf`, com hooks (`mpc_ops`) para várias operações MAC (verificações de vnode, verificações de exec, atualizações de label, etc.).
- As flags de tempo de carregamento podem incluir `MPC_LOADTIME_FLAG_NOTLATE`, significando “deve ser carregado cedo” (então tentativas tardias de registro são rejeitadas).
- Uma vez registrado, cada módulo recebe um handle e ocupa um slot na `mac_policy_list`.
- Quando um MAC hook é invocado mais tarde (por exemplo, acesso a vnode, exec, etc.), o MACF itera por todas as policies registradas para tomar decisões coletivas.

- Em particular, **AMFI** (Apple Mobile File Integrity) é uma dessas security extensions. Seu Info.plist inclui `AppleSecurityExtension`, marcando-o como uma security policy.
- Como parte do boot do kernel, a lógica de carregamento do kernel garante que a “security policy” (AMFI, etc.) já esteja ativa antes que muitos subsistemas dependam dela. Por exemplo, o kernel “prepara-se para tarefas futuras carregando … security policy, incluindo AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## KPI dependency & com.apple.kpi.dsep in MAC policy kexts

Ao escrever um kext que usa o MAC framework (ou seja, chamando `mac_policy_register()` etc.), você deve declarar dependências em KPIs (Kernel Programming Interfaces) para que o kext linker (kxld) possa resolver esses símbolos. ENTÃO, para declarar que um `kext` depende de MACF, você precisa indicá-lo no `Info.plist` com `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), então o kext irá referenciar símbolos como `mac_policy_register`, `mac_policy_unregister`, e ponteiros de função MAC hook. Para resolver esses, você deve listar `com.apple.kpi.dsep` como uma dependência.

Example Info.plist snippet (inside your .kext):
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
## MACF em releases modernas do macOS

No macOS moderno, as políticas de segurança da Apple geralmente não são melhor abordadas como bundles `.kext` soltos e independentes. Desde o **macOS 11**, as kernel extensions são vinculadas em **kernel collections**; no **Apple Silicon** não existe um **SystemKC** separado, e kexts de terceiros só se tornam carregáveis após serem integrados à **Auxiliary Kernel Collection (AuxKC)** e após um reboot. Para pesquisa de MACF, isso significa que políticas embutidas como **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** ou **Quarantine** geralmente são mais fáceis de enumerar com `kmutil` do que com ferramentas depreciadas como `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Em Apple Silicon, se um security kext não estiver no BootKC, verifique o AuxKC em seguida. Isso geralmente é mais útil do que procurar por um bundle independente em `/System/Library/Extensions`.

## MACF Callouts

É comum encontrar callouts para MACF definidos em código como: blocos condicionais **`#if CONFIG_MAC`**. Além disso, dentro desses blocos é possível encontrar chamadas para `mac_proc_check*`, que chamam MACF para **verificar permissões** para executar certas ações. Além disso, o formato dos callouts de MACF é: **`mac_<object>_<opType>_opName`**.

O object é um dos seguintes: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
O `opType` normalmente é check, que será usado para permitir ou negar a ação. No entanto, também é possível encontrar `notify`, que permitirá ao kext reagir à ação fornecida.

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

Então, é possível encontrar o código de `mac_file_check_mmap` em [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
O qual está chamando a macro `MAC_CHECK`, cujo código pode ser encontrado em [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Que percorrerá todas as políticas MAC registradas chamando suas funções e armazenando a saída dentro da variável `error`, que só poderá ser sobrescrita por `mac_error_select` com códigos de sucesso, então, se qualquer verificação falhar, a verificação completa falhará e a ação não será permitida.

> [!TIP]
> No entanto, lembre-se de que nem todos os callouts do MACF são usados apenas para negar ações. Por exemplo, `mac_priv_grant` chama a macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), que concederá o privilégio solicitado se qualquer policy responder com 0:
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

Esses callas têm o objetivo de verificar e fornecer (dezenas de) **privileges** definidos em [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Algum código do kernel chamaria `priv_check_cred()` de [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) com as credenciais KAuth do processo e um dos códigos de privilege, o que chamará `mac_priv_check` para ver se alguma policy **nega** conceder o privilege e então chama `mac_priv_grant` para ver se alguma policy concede o `privilege`.

### proc_check_syscall_unix

Esse hook permite interceptar todas as system calls. Em `bsd/dev/[i386|arm]/systemcalls.c` é possível ver a função declarada [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), que contém este código:
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
Que irá verificar no processo chamador o **bitmask** para saber se o syscall atual deve chamar `mac_proc_check_syscall_unix`. Isso ocorre porque syscalls são chamados com tanta frequência que é interessante evitar chamar `mac_proc_check_syscall_unix` toda vez.

Observe que a função `proc_set_syscall_filter_mask()`, que define o bitmask de syscalls em um processo, é chamada pelo Sandbox para definir masks em processos sandboxed.

## Exposed MACF syscalls

É possível interagir com o MACF por meio de alguns syscalls definidos em [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
Para reversing ofensivo, **`__mac_syscall`** ainda é um dos melhores chokepoints em userland. Ele carrega um **nome de policy** (por exemplo `"Sandbox"` ou `"AMFI"`), um **selector/code específico da policy**, e um ponteiro para o **blob de argumentos opaco** que será tratado por `mpo_policy_syscall`. Isso é muito útil ao reverter operações undocumented primeiro a partir de userland e só depois fazer pivot para a implementação no kernel. Sandbox normalmente chega até ele via `__sandbox_ms`, e AMFI usa o mesmo mecanismo para decisões de policy do dyld.

## Practical offensive research notes

Recentes bugs no macOS raramente "quebram o MACF" diretamente. Em vez disso, geralmente abusam de uma **dessincronização entre uma decisão de MACF / Sandbox / TCC e a ação privilegiada que acontece depois**.

### Broker path checks vs real privileged action

Um padrão recorrente é um daemon privilegiado fazer uma **userland pre-check** (por exemplo `sandbox_check_by_audit_token()`) em uma versão de um path, e depois executar o verdadeiro privileged sink com um **path diferente ou não canônico controlado pelo atacante**. Pesquisas recentes em `diskarbitrationd` / `storagekitd` são um bom exemplo: **directory traversal** mais **symlink swaps** permitem ao atacante passar pela validação de sandbox do daemon e então montar sobre localizações sensíveis como `~/Library/Application Support/com.apple.TCC`, transformando o bug em um **sandbox escape**, **local privilege escalation** ou **TCC bypass** dependendo do mount point escolhido.

Ao auditar root brokers acessíveis a partir do sandbox, procure primeiro por:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers de canonicalização de path
- privileged sinks como `mount`, `rename`, `copyfile`, métodos XPC de helper-tool, ou qualquer coisa que depois toque paths controlados pelo atacante como root

### Trusted deputies with private entitlements

Outro padrão prático é evitar atacar hooks do MACF diretamente e, em vez disso, abusar de um **trusted process** que já carrega os direitos necessários para cruzar a boundary. Pesquisas recentes em Safari/TCC são um bom exemplo: a primitive interessante não era "desabilitar TCC no kernel", mas modificar policy/configuração local para que um processo assinado pela Apple com **`com.apple.private.tcc.allow`** execute a ação sensível em seu lugar. Na prática, alvos de auditing de alto valor são daemons/apps da Apple que combinam:

- **private entitlements** ou alcance parecido com FDA
- um config / database / mount point / policy file gravável
- uma operação sensível posterior mediada por **Sandbox**, **AMFI**, **TCC** ou outra policy do MACF

Para reversing mais profundo e específico por produto, veja as páginas dedicadas em [macOS Sandbox](macos-sandbox/README.md) e [macOS TCC](macos-tcc/README.md).

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}

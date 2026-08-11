# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** は **Mandatory Access Control Framework** の略で、コンピューターの保護を支援するためにオペレーティングシステムに組み込まれたセキュリティシステムです。これは、ファイル、アプリケーション、システムリソースなど、システム内の特定の部分に誰または何がアクセスできるかについて、**厳格なルールを設定**することで機能します。これらのルールを自動的に適用することで、MACF は承認されたユーザーとプロセスだけが特定の操作を実行できるようにし、不正アクセスや悪意のある活動のリスクを低減します。

MACF 自体は実際には意思決定を行わず、アクションを**インターセプト**するだけである点に注意してください。意思決定は、MACF が呼び出す `AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext`、`mcxalr.kext` などの **policy modules**（kernel extensions）に委ねられます。

- Policy は enforcing（操作によって 0 または non-zero を返す）にできる
- Policy は monitoring（異議を唱えないように 0 を返しつつ、hook に便乗して何らかの処理を行う）にできる
- MACF static policy は boot 時にインストールされ、決して削除されない
- MACF dynamic policy は KEXT（kextload）によってインストールされ、理論上は kextunload できる
- iOS では static policy のみが許可され、macOS では static + dynamic が許可される。<sup>[[7]](#references)</sup>

### Flow

1. Process が syscall/mach trap を実行する
2. 関連する function が kernel 内で呼び出される
3. Function が MACF を呼び出す
4. MACF が、その function に対する hook を policy で要求した policy modules を確認する
5. MACF が関連する policy を呼び出す
6. Policies が、その action を許可するか拒否するかを示す

> [!CAUTION]
> Apple だけが MAC Framework KPI を使用できます。

通常、MACF で permissions を確認する functions は `MAC_CHECK` macro を呼び出します。たとえば、socket を作成する syscall の場合、`mac_socket_check_create` function を呼び出し、この function が `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` を呼び出します。さらに、`MAC_CHECK` macro は security/mac_internal.h で次のように定義されています。<sup>[[3]](#references)</sup>
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
`check` を `socket_check_create` に、`args...` を `(cred, domain, type, protocol)` に変換すると、次のようになります。
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
ヘルパーマクロを展開すると、具体的な制御フローが明らかになります。
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
つまり、`MAC_CHECK(socket_check_create, ...)` はまず静的ポリシーを走査し、条件に応じてロックを取得して動的ポリシーを反復処理し、各フックの前後で DTrace probes を発行し、`mac_error_select()` を介してすべてのフックの戻り値を単一の `error` 結果に集約します。


### ラベル

MACF は **labels** を使用し、アクセスを許可するかどうかを判定するポリシーがこれを使用します。labels struct の宣言コードは[こちら](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h)にあり、これは [**struct ucred**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) 内の **`cr_label`** 部分で使用されます。label には flags と、**MACF policies が pointers を割り当てる**ために使用できる複数の **slots** が含まれます。例えば Sanbox は container profile を指します

## MACF Policies

MACF Policy は、特定の kernel operations に適用する **rule と conditions** を定義します。

kernel extension は `mac_policy_conf` struct を設定し、`mac_policy_register` を呼び出して登録できます。[こちら](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)より:<sup>[[1]](#references)</sup>
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered entry-point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better alignment on 64bit platforms */
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
これらのポリシーを設定している kernel extensions は、`mac_policy_register` への呼び出しを確認することで簡単に特定できます。さらに、extension の逆アセンブルを確認すれば、使用されている `mac_policy_conf` struct も見つけることができます。

MACF policies は **動的に** register および unregister することも可能です。

`mac_policy_conf` の主なフィールドの 1 つが **`mpc_ops`** です。このフィールドは、policy が関心を持つ operations を指定します。operations は数百存在するため、すべてのエントリをゼロにした後、policy が必要とするものだけを選択できます。[こちら](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html) を参照してください。<sup>[[1]](#references)</sup>
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
ほぼすべてのhookは、これらの操作のいずれかがinterceptされると、MACFによってcallbackされます。ただし、**`mpo_policy_*`** hookは例外です。これは、**`mpo_hook_policy_init()`**がregistration時（つまり、`mac_policy_register()`の後）に呼び出されるcallbackであり、**`mpo_hook_policy_initbsd()`**はBSD subsystemが適切にinitialiseされた後のlate registration中に呼び出されるためです。

さらに、**`mpo_policy_syscall`** hookは、任意のkextによってprivateな**ioctl** style call **interface**を公開するためにregistrationできます。その後、user clientは、policy nameとinteger **code**、およびoptionalな**arguments**をparametersとして指定し、`mac_syscall` (#381)をcallできるようになります。\
例えば、**`Sandbox.kext`**はこれを頻繁に使用します。

kextの**`__DATA.__const*`**を確認することで、policyのregistration時に使用された`mac_policy_ops` structureを特定できます。これは、そのpointerが`mpo_policy_conf`内のoffsetに存在することに加え、その領域に存在するNULL pointerの数からも特定できます。

さらに、policyを設定したkextのlistを取得することもできます。そのためには、registrationされた各policyによって更新されるstruct **`_mac_policy_list`**をmemoryからdumpします。

`xnoop` toolを使用して、systemにregistrationされているすべてのpolicyをdumpすることもできます：
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
そして、`check policy` のすべてのチェック項目を次のコマンドでダンプします:
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
## XNU における MACF の初期化

### Early bootstrap と mac_policy_init()

- MACF は非常に早い段階で初期化されます。`bootstrap_thread`（XNU の startup code 内）で、`ipc_bootstrap` の後に XNU は `mac_policy_init()`（`mac_base.c` 内）を呼び出します。
- `mac_policy_init()` はグローバルな `mac_policy_list`（policy slot の配列またはリスト）を初期化し、XNU 内で MAC（Mandatory Access Control）を機能させるためのインフラをセットアップします。
- その後、`mac_policy_initmach()` が呼び出され、組み込みまたは bundled policy の kernel 側での登録を処理します。

### `mac_policy_initmach()` と “security extensions” のロード

- `mac_policy_initmach()` は、preloaded された（または “policy injection” list に含まれる）kernel extension（kext）を調べ、その Info.plist にある `AppleSecurityExtension` キーを確認します。
- Info.plist で `<key>AppleSecurityExtension</key>`（または `true`）を宣言する kext は “security extensions” とみなされます。つまり、MAC policy を実装するか、MACF infrastructure に hook する kext です。
- このキーを持つ Apple kext の例には、**ALF.kext**、**AppleMobileFileIntegrity.kext (AMFI)**、**Sandbox.kext**、**Quarantine.kext**、**TMSafetyNet.kext**、**CoreTrust.kext**、**AppleSystemPolicy.kext** などがあります（すでに列挙したものと同様です）。
- kernel はこれらの kext が早期にロードされることを保証し、boot 中に（`mac_policy_register` 経由で）registration routine を呼び出して、`mac_policy_list` に挿入します。

- 各 policy module（kext）は `mac_policy_conf` structure を提供し、さまざまな MAC operation（vnode check、exec check、label update など）用の hook（`mpc_ops`）を備えています。
- load time flag には、`MPC_LOADTIME_FLAG_NOTLATE`（「早期にロードする必要がある」という意味）が含まれる場合があります。この場合、後からの registration attempt は拒否されます。
- 登録されると、各 module は handle を取得し、`mac_policy_list` の slot を占有します。
- 後で MAC hook が呼び出されると（たとえば vnode access、exec など）、MACF は登録済みのすべての policy を反復処理し、collective decision を行います。

- 特に、**AMFI**（Apple Mobile File Integrity）はこのような security extension です。その Info.plist には、security policy であることを示す `AppleSecurityExtension` が含まれています。
- kernel boot の一環として、kernel の load logic は、多くの subsystem が依存する前に “security policy”（AMFI など）がすでに active になっていることを保証します。たとえば、kernel は「AppleMobileFileIntegrity (AMFI)、Sandbox、Quarantine policy を含む security policy をロードすることで、後続の task に備える」ように動作します。
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

MAC frameworkを使用するkext（つまり、`mac_policy_register()`などを呼び出すもの）を作成する場合、kext linker（kxld）がこれらのシンボルを解決できるように、KPI（Kernel Programming Interfaces）への依存関係を宣言する必要があります。そのため、kextがMACFに依存することを宣言するには、`Info.plist`で`com.apple.kpi.dsep`を指定する必要があります（`find . Info.plist | grep AppleSecurityExtension`）。これにより、kextは`mac_policy_register`、`mac_policy_unregister`、およびMAC hook function pointersなどのシンボルを参照します。これらを解決するには、依存関係として`com.apple.kpi.dsep`を列挙する必要があります。

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
## 最新の macOS リリースにおける MACF

最新の macOS では、Apple の security policy は通常、独立した緩やかな `.kext` bundle として捉えるのが最適ではありません。**macOS 11** 以降、kernel extension は **kernel collection** にリンクされます。**Apple Silicon** では個別の **SystemKC** は存在せず、third-party kext は **Auxiliary Kernel Collection (AuxKC)** に組み込まれ、reboot した後にのみ load 可能になります。MACF の research においては、**Sandbox**、**AMFI**、**AppleSystemPolicy**、**CoreTrust**、**Quarantine** などの組み込み policy は、`kextstat` のような deprecated tooling よりも `kmutil` を使用した方が、通常は簡単に列挙できます。
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Apple Siliconでは、security kextがBootKCに存在しない場合は、次にAuxKCを確認してください。これは、`/System/Library/Extensions`配下でstandalone bundleを探し回るより、通常は有用です。

## MACF Callouts

MACFへのcalloutは、**`#if CONFIG_MAC`** conditional blockのようなコード内で定義されていることがよくあります。さらに、これらのblock内には、特定のアクションを実行する**権限をチェック**するためにMACFを呼び出す`mac_proc_check*`へのcallsが見つかることがあります。また、MACF calloutの形式は次のとおりです: **`mac_<object>_<opType>_opName`**。

objectは次のいずれかです: `bpfdesc`、`cred`、`file`、`proc`、`vnode`、`mount`、`devfs`、`ifnet`、`inpcb`、`mbuf`、`ipq`、`pipe`、`sysv[msg/msq/shm/sem]`、`posix[shm/sem]`、`socket`、`kext`。\
`opType`は通常checkで、アクションを許可または拒否するために使用されます。ただし、`notify`が見つかることもあり、これはkextが指定されたアクションに反応できるようにします。

[https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621)に例があります:

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

続いて、[https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)に`mac_file_check_mmap`のコードがあります。
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
これは `MAC_CHECK` マクロを呼び出しており、そのコードは [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup> にあります。
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
これは登録されているすべての mac policy を順番に処理して各 policy の関数を呼び出し、その出力を `error` 変数に格納します。この変数は、成功コードによって `mac_error_select` によってのみ上書き可能です。そのため、いずれかのチェックが失敗するとチェック全体が失敗し、アクションは許可されません。

> [!TIP]
> ただし、すべての MACF callout がアクションの拒否だけに使用されるわけではないことに注意してください。たとえば、`mac_priv_grant` は [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) マクロを呼び出します。このマクロは、いずれかの policy が 0 を返した場合に、要求された privilege を付与します。
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

これらの call は、[**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) で定義されている多数の **privilege** をチェックおよび付与するために使用されます。\
一部の kernel code は、プロセスの KAuth credentials と privilege code のいずれかを指定して、[**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) の `priv_check_cred()` を呼び出します。この関数は `mac_priv_check` を呼び出し、いずれかの policy が privilege の付与を **拒否** するかを確認します。その後、`mac_priv_grant` を呼び出して、いずれかの policy が `privilege` を付与するかを確認します。<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

この hook を使用すると、すべての system call を intercept できます。`bsd/dev/[i386|arm]/systemcalls.c` では、宣言された [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) 関数を確認できます。この関数には次の code が含まれています。
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
呼び出し元プロセスの **bitmask** を確認し、現在の syscall で `mac_proc_check_syscall_unix` を呼び出すべきかどうかを判定します。syscall は非常に頻繁に呼び出されるため、毎回 `mac_proc_check_syscall_unix` を呼び出すのを避けることが有効です。

プロセス内の syscall の bitmask を設定する関数 `proc_set_syscall_filter_mask()` は、Sandbox によって sandbox 化されたプロセスにマスクを設定するために呼び出される点に注意してください。

## Exposed MACF syscalls

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) で定義されているいくつかの syscall を通じて、MACF とやり取りできます。
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
攻撃目的のreversingでは、**`__mac_syscall`**は依然としてuserlandにおける最良のchokepointの1つです。これは**policy name**（例：`"Sandbox"`または`"AMFI"`）、**policy固有のselector/code**、そして`mpo_policy_syscall`によって処理される**opaque argument blob**へのポインタを渡します。これは、まずuserlandからundocumentedなoperationをreversingし、その後でkernel実装へpivotする場合に非常に有用です。Sandboxは通常、`__sandbox_ms`経由でこれに到達し、AMFIもdyldのpolicy判断に同じmechanismを使用します。<sup>[[2]](#references)[[5]](#references)</sup>

## Practical offensive research notes

近年のmacOS bugがMACFを直接「break」することはほとんどありません。通常は、**MACF / Sandbox / TCCによる判断**と、その後に実行されるprivileged actionとの間にある**desynchronisation**を悪用します。

### Broker path checks vs real privileged action

繰り返し現れるパターンは、privileged daemonが**userland pre-check**（例：`sandbox_check_by_audit_token()`）をあるバージョンのpathに対して実行し、その後、**異なるpathまたはcanonicalではないattacker-controlled path**を使って、実際のprivileged sinkを実行するというものです。最近の`diskarbitrationd` / `storagekitd` researchは良い例です。**directory traversal**と**symlink swaps**を組み合わせることで、attackerはdaemonのsandbox validationを通過し、その後、`~/Library/Application Support/com.apple.TCC`などのsensitive locationをmountできます。これにより、選択したmount pointに応じて、このbugは**sandbox escape**、**local privilege escalation**、または**TCC bypass**へと変化します。<sup>[[6]](#references)</sup>

sandboxから到達可能なroot brokerをauditする場合、まず次をgrepします。

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- `mount`, `rename`, `copyfile`、helper-tool XPC methodsなどのprivileged sink、または後からattacker-controlled pathsをrootとして扱うもの

### Trusted deputies with private entitlements

もう1つの実用的なパターンは、MACF hooksを直接攻撃するのではなく、boundaryを越えるために必要な権限をすでに持つ**trusted process**を悪用することです。最近のSafari/TCC researchは良い例です。興味深いprimitiveは「kernelでTCCをdisableする」ことではなく、local policy/configurationを変更し、**`com.apple.private.tcc.allow`**を持つApple-signed processにsensitive actionを自分の代わりに実行させることでした。<sup>[[8]](#references)</sup> 実際には、次の要素を組み合わせるApple daemon/appが、高価値なaudit targetになります。

- **private entitlements**またはFDA-like reach
- writableなconfig / database / mount point / policy file
- **Sandbox**、**AMFI**、**TCC**、または別のMACF policyによってmediatedされる、後続のsensitive operation

より深いproduct-specificなreversingについては、[macOS Sandbox](macos-sandbox/README.md)および[macOS TCC](macos-tcc/README.md)の専用ページを確認してください。

## References

- [1] [XNU — `security/mac_policy.h`（MACF policy operations vectorの全体）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c`（`mac_policy_register`、`__mac_syscall`）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h`（`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` macros）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h`（`priv_check`/`priv_grant`で使用されるprivilege codes）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall（Offensive Security）](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Apple Vulnerabilitiesの解明：diskarbitrationdとstoragekitdのAudit Part 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference tool](https://newosxbook.com/xxr/index.php)
- [8] [New macOS vulnerability, "HM Surf" could lead to unauthorized data access（Microsoft Security Blog）](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
{{#include ../../../banners/hacktricks-training.md}}

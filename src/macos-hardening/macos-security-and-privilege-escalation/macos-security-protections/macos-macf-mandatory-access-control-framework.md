# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

**MACF** は **Mandatory Access Control Framework** の略で、コンピューターの保護を支援するためにオペレーティングシステムに組み込まれたセキュリティシステムです。これは、ファイル、アプリケーション、システムリソースなど、システムの特定の部分に誰または何がアクセスできるかについて、**厳格なルールを設定**することで機能します。これらのルールを自動的に適用することで、MACF は承認されたユーザーとプロセスだけが特定の操作を実行できるようにし、不正アクセスや悪意のある活動のリスクを低減します。

MACF 自体は実際には判断を下さず、アクションを**インターセプト**するだけである点に注意してください。判断は、`AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext`、`mcxalr.kext` など、MACF が呼び出す**policy modules**（kernel extensions）に委ねられます。

- policy は enforcing を行える（ある操作に対して 0 または non-zero を返す）
- policy は monitoring を行える（異議を申し立てないように 0 を返し、hook に便乗して何らかの処理を実行する）
- MACF static policy は boot 時にインストールされ、決して削除されない
- MACF dynamic policy は KEXT（kextload）によってインストールされ、理論上は kextunload できる
- iOS では static policy のみが許可され、macOS では static + dynamic が許可される。<sup>[[7]](#references)</sup>

### フロー

1. Process が syscall/mach trap を実行する
2. kernel 内で関連する function が呼び出される
3. Function が MACF を呼び出す
4. MACF が、その function を policy 内で hook するよう要求した policy modules を確認する
5. MACF が関連する policies を呼び出す
6. Policies がアクションを許可するか拒否するかを示す

> [!CAUTION]
> Apple だけが MAC Framework KPI を使用できます。

通常、MACF によって permissions を確認する functions は、macro `MAC_CHECK` を呼び出します。たとえば、socket を作成する syscall の場合、function `mac_socket_check_create` が呼び出され、さらに `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` が呼び出されます。また、macro `MAC_CHECK` は security/mac_internal.h で次のように定義されています。<sup>[[3]](#references)</sup>
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
`check`を`socket_check_create`に変換し、`args...`を`(cred, domain, type, protocol)`にすると、次のようになります。
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
ヘルパーマクロを展開すると、具体的な制御フローが明らかになります:
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
つまり、`MAC_CHECK(socket_check_create, ...)` はまず static policies を走査し、条件に応じてロックを取得して dynamic policies を反復処理し、各 hook の前後で DTrace probes を発行し、`mac_error_select()` を介してすべての hook の戻り値を単一の `error` 結果に集約します。


### Labels

MACF は **labels** を使用します。アクセスを許可するかどうかを確認する policies は、これらの labels を利用します。labels struct の宣言コードは[こちら](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h)にあり、これは [**struct ucred**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) 内の **`cr_label`** 部分で使用されます。label には flags と、**MACF policies が pointers を割り当てるために使用できる**複数の **slots** が含まれています。例えば Sanbox は container profile を指します。

## MACF Policies

MACF Policy は、特定の kernel operations に適用される **rule と conditions** を定義します。

kernel extension は `mac_policy_conf` struct を設定し、`mac_policy_register` を呼び出して登録できます。[こちら](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)より:<sup>[[1]](#references)</sup>
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
これらのポリシーを設定している kernel extension は、`mac_policy_register` の呼び出しを確認することで簡単に特定できます。さらに、extension を逆アセンブルして確認することで、使用されている `mac_policy_conf` 構造体を見つけることもできます。

MACF ポリシーは **動的に** 登録および登録解除することもできます。

`mac_policy_conf` の主なフィールドの 1 つが **`mpc_ops`** です。このフィールドは、ポリシーが対象とする操作を指定します。操作は数百種類あるため、すべてをゼロにしたうえで、ポリシーが対象とする操作だけを選択できます。[こちら](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html) を参照してください。<sup>[[1]](#references)</sup>
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
ほぼすべての hooks は、これらの操作のいずれかが intercept されると、MACF によって callback されます。ただし、**`mpo_policy_*`** hooks は例外です。これは、**`mpo_hook_policy_init()`** が registration 時（つまり **`mac_policy_register()`** の後）に呼び出される callback であり、**`mpo_hook_policy_initbsd()`** は BSD subsystem が正常に初期化された後の late registration 中に呼び出されるためです。

さらに、**`mpo_policy_syscall`** hook は、任意の kext によって private な **ioctl** 形式の call **interface** を公開するために registration できます。その後、user client は **policy name**、integer **code**、および optional な **arguments** を parameters として指定し、`mac_syscall` (#381) を call できるようになります。\
たとえば、**`Sandbox.kext`** はこれを頻繁に使用します。

kext の **`__DATA.__const*`** を確認すると、policy の registration 時に使用される `mac_policy_ops` structure を特定できます。これは、その pointer が **`mpo_policy_conf`** 内の offset に存在することに加え、その領域に存在する NULL pointer の数からも特定できます。

さらに、registration されたすべての policy で更新される struct **`_mac_policy_list`** を memory から dump することで、policy を configure した kext の list を取得することもできます。

`xnoop` tool を使用して、system に registration されたすべての policy を dump することもできます。
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
そして、次のコマンドで check policy のすべてのチェックをダンプします:
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
## XNUにおけるMACFの初期化

### Early bootstrapとmac_policy_init()

- MACFは非常に早い段階で初期化されます。`bootstrap_thread`（XNUのstartup code内）で、`ipc_bootstrap`の後に、XNUは`mac_policy_init()`（`mac_base.c`内）を呼び出します。
- `mac_policy_init()`はグローバルな`mac_policy_list`（policy slotの配列またはリスト）を初期化し、XNU内でMAC（Mandatory Access Control）を使用するためのインフラストラクチャをセットアップします。
- その後、`mac_policy_initmach()`が呼び出され、組み込みまたはbundled policyのkernel側でのregistrationを処理します。

### `mac_policy_initmach()`と“security extensions”のロード

- `mac_policy_initmach()`は、preloadedされた（または“policy injection” list内にある）kernel extension（kext）を調べ、そのInfo.plistに`AppleSecurityExtension`キーがあるかを確認します。
- Info.plistで`<key>AppleSecurityExtension</key>`（または`true`）を宣言するkextは、“security extensions”、つまりMAC policyを実装する、またはMACF infrastructureにhookするものとみなされます。
- このキーを持つApple kextの例には、**ALF.kext**、**AppleMobileFileIntegrity.kext (AMFI)**、**Sandbox.kext**、**Quarantine.kext**、**TMSafetyNet.kext**、**CoreTrust.kext**、**AppleSystemPolicy.kext**などがあります（先ほど挙げたものと同様です）。
- kernelはこれらのkextが早期にロードされることを保証し、boot中にregistration routine（`mac_policy_register`経由）を呼び出して、それらを`mac_policy_list`に挿入します。

- 各policy module（kext）は、さまざまなMAC operation（vnode check、exec check、label updateなど）向けのhook（`mpc_ops`）を持つ`mac_policy_conf` structureを提供します。
- load time flagには、`MPC_LOADTIME_FLAG_NOTLATE`（「早期にロードしなければならない」ことを意味します）が含まれる場合があり、その場合、late registrationの試行は拒否されます。
- registrationされると、各moduleはhandleを取得し、`mac_policy_list`内のslotを占有します。
- 後でMAC hookが呼び出されると（例えばvnode accessやexecなど）、MACFは登録済みのすべてのpolicyを反復処理し、collective decisionを行います。

- 特に、**AMFI**（Apple Mobile File Integrity）はこのようなsecurity extensionです。そのInfo.plistには、security policyであることを示す`AppleSecurityExtension`が含まれています。
- kernel bootの一環として、kernelのload logicは、多くのsubsystemが依存する前に“security policy”（AMFIなど）がすでにactiveになっていることを保証します。例えば、kernelは「AppleMobileFileIntegrity（AMFI）、Sandbox、Quarantine policyを含むsecurity policyをロードすることで、後続のtaskに備える」準備を行います。
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
## MAC policy kexts における KPI dependency と com.apple.kpi.dsep

MAC framework を使用する kext（つまり `mac_policy_register()` などを呼び出す kext）を作成する場合、kext linker（kxld）がそれらの symbols を解決できるよう、KPI（Kernel Programming Interfaces）への dependencies を宣言する必要があります。そのため、MACF に依存する `kext` を宣言するには、`Info.plist` で `com.apple.kpi.dsep` を指定する必要があります（`find . Info.plist | grep AppleSecurityExtension`）。これにより kext は、`mac_policy_register`、`mac_policy_unregister`、MAC hook function pointers などの symbols を参照します。これらを解決するには、`com.apple.kpi.dsep` を dependency として列挙する必要があります。

Example Info.plist snippet（.kext 内）：
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
## 現行の macOS リリースにおける MACF

現行の macOS では、Apple のセキュリティポリシーは通常、独立した緩やかな `.kext` バンドルとして捉えるのが適切ではありません。**macOS 11** 以降、kernel extensions は **kernel collections** にリンクされます。**Apple Silicon** では独立した **SystemKC** は存在せず、サードパーティ製 kext は **Auxiliary Kernel Collection (AuxKC)** に組み込まれ、再起動した後にのみロード可能になります。MACF の調査では、これは **Sandbox**、**AMFI**、**AppleSystemPolicy**、**CoreTrust**、**Quarantine** などの組み込みポリシーを、非推奨の **kextstat** などのツールよりも `kmutil` で列挙する方が通常は容易であることを意味します。
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Apple Silicon では、security kext が BootKC にない場合は、次に AuxKC を確認してください。これは通常、`/System/Library/Extensions` 配下で standalone bundle を探し回るよりも有用です。

## MACF Callouts

MACF への callout は、**`#if CONFIG_MAC`** のような conditional block として定義されたコード内で見つかることがよくあります。さらに、これらの block 内では、特定のアクションを実行するための **permissions をチェック**する MACF を呼び出す `mac_proc_check*` 呼び出しを見つけられる場合があります。また、MACF callout の形式は **`mac_<object>_<opType>_opName`** です。

object は次のいずれかです: `bpfdesc`、`cred`、`file`、`proc`、`vnode`、`mount`、`devfs`、`ifnet`、`inpcb`、`mbuf`、`ipq`、`pipe`、`sysv[msg/msq/shm/sem]`、`posix[shm/sem]`、`socket`、`kext`。\
`opType` は通常 `check` で、アクションを許可または拒否するために使用されます。ただし、`notify` が見つかる場合もあり、これは kext が指定されたアクションに反応できるようにします。

次の [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) に例があります:

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

その後、[https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) で `mac_file_check_mmap` のコードを確認できます。
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
`MAC_CHECK` macroを呼び出しており、そのコードは[https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>にあります。
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
登録されているすべての mac ポリシーを順番に処理して各関数を呼び出し、その出力を `error` 変数に格納します。この変数を成功コードによって上書きできるのは `mac_error_select` のみです。そのため、いずれかのチェックが失敗するとチェック全体が失敗し、アクションは許可されません。

> [!TIP]
> ただし、すべての MACF callout がアクションの拒否だけに使用されるわけではないことに注意してください。例えば、`mac_priv_grant` はマクロ [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) を呼び出します。このマクロは、いずれかのポリシーが 0 を返した場合に、要求された privilege を許可します。
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

これらの call は、[**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) で定義されている数十種類の **privilege** をチェックおよび提供するために使用されます。\
一部の kernel code は、プロセスの KAuth credentials といずれかの privilege code を指定して、[**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) の `priv_check_cred()` を呼び出します。この関数は `mac_priv_check` を呼び出して、いずれかのポリシーが privilege の付与を **拒否** するか確認し、その後 `mac_priv_grant` を呼び出して、いずれかのポリシーが `privilege` を許可するか確認します。<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

この hook を使用すると、すべての system call を intercept できます。`bsd/dev/[i386|arm]/systemcalls.c` には、宣言された関数 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) があり、そこには次の code が含まれています。
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
呼び出し元プロセスの **bitmask** を確認し、現在の syscall で `mac_proc_check_syscall_unix` を呼び出すべきかを判定します。syscall は非常に頻繁に呼び出されるため、毎回 `mac_proc_check_syscall_unix` を呼び出さないようにすることが重要です。

プロセス内の syscall の bitmask を設定する関数 `proc_set_syscall_filter_mask()` は、Sandbox が sandboxed process にマスクを設定するために呼び出すことに注意してください。

## 公開されている MACF syscall

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) で定義されている syscall を介して、MACF とやり取りできます。
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
For offensive reversing において、**`__mac_syscall`** は依然として userland における最良の chokepoint の1つです。これは **policy name**（例: `"Sandbox"` や `"AMFI"`）、**policy-specific selector/code**、そして `mpo_policy_syscall` によって処理される **opaque argument blob** へのポインタを渡します。これは、まず userland から undocumented operations を reverse engineering し、その後で kernel implementation に pivot する場合に非常に有用です。Sandbox は一般的に `__sandbox_ms` 経由でこれに到達し、AMFI も dyld policy decisions に同じ mechanism を使用します。<sup>[[2]](#references)[[5]](#references)</sup>

## Practical offensive research notes

最近の macOS bugs は、MACF を直接「break」することはほとんどありません。代わりに、通常は **MACF / Sandbox / TCC による decision と、その後に実行される privileged action の間の desynchronisation** を悪用します。

### Broker path checks vs real privileged action

繰り返し現れる pattern は、privileged daemon が **userland pre-check**（例: `sandbox_check_by_audit_token()`）をある version の path に対して実行し、その後、**異なる、または non-canonical な attacker-controlled path** を使って実際の privileged sink を実行するというものです。最近の `diskarbitrationd` / `storagekitd` research は良い例です。**directory traversal** と **symlink swaps** により、attacker は daemon の sandbox validation を通過したうえで、`~/Library/Application Support/com.apple.TCC` などの sensitive locations に mount できます。これにより、選択した mount point に応じて、この bug は **sandbox escape**、**local privilege escalation**、または **TCC bypass** になります。<sup>[[6]](#references)</sup>

Sandbox から到達可能な root brokers を audit する場合は、まず以下を grep します。

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- `mount`, `rename`, `copyfile`、helper-tool XPC methods などの privileged sinks、または後から attacker-controlled paths を root として扱うあらゆるもの

### Trusted deputies with private entitlements

もう1つの実用的な pattern は、MACF hooks を直接攻撃するのではなく、boundary を越えるために必要な rights をすでに持つ **trusted process** を abuse することです。最近の Safari/TCC research は良い例です。興味深い primitive は「kernel 内で TCC を disable する」ことではなく、local policy/configuration を変更し、**`com.apple.private.tcc.allow`** を持つ Apple-signed process に sensitive action を代わりに実行させることでした。<sup>[[8]](#references)</sup> 実際には、以下を組み合わせる Apple daemons/apps が high-value auditing targets です。

- **private entitlements** または FDA-like reach
- writable config / database / mount point / policy file
- **Sandbox**、**AMFI**、**TCC**、またはその他の MACF policy によって mediated される、後続の sensitive operation

より深い product-specific reversing については、[macOS Sandbox](macos-sandbox/README.md) と [macOS TCC](macos-tcc/README.md) の dedicated pages を確認してください。

## References

- [1] [XNU — `security/mac_policy.h` (the full MACF policy operations vector)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` macros)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (privilege codes used by `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference tool](https://newosxbook.com/xxr/index.php)
- [8] [New macOS vulnerability, "HM Surf", could lead to unauthorized data access (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)

{{#include ../../../banners/hacktricks-training.md}}

# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** は **Mandatory Access Control Framework** の略で、オペレーティングシステムに組み込まれた、コンピュータを保護するためのセキュリティシステムです。これは、**システムの特定の部分に誰または何がアクセスできるかについて厳格なルールを設定する**ことで機能します。たとえば、ファイル、アプリケーション、システムリソースなどです。これらのルールを自動的に強制することで、MACF は認可されたユーザーとプロセスだけが特定の操作を実行できるようにし、不正アクセスや悪意ある活動のリスクを減らします。

MACF は実際には判断を行わず、アクションを**インターセプト**するだけであることに注意してください。判断は、呼び出す **policy modules**（kernel extensions）である `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` and `mcxalr.kext` に任されています。

- A policy may be enforcing (return 0 non-zero on some operation)
- A policy may be monitoring (return 0, so as not to object but piggyback on hook to do something)
- A MACF static policy is installed in boot and will NEVER be removed
- A MACF dynamic policy is installed by a KEXT (kextload) and may hypothetically be kextunloaded
- In iOS only static policies are allowed and in macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process performs a syscall/mach trap
2. The relevant function is called inside the kernel
3. Function calls MACF
4. MACF checks policy modules that requested to hook that function in their policy
5. MACF calls the relevant policies
6. Policies indicates if they allow or deny the action

> [!CAUTION]
> Apple is the only one that can use the MAC Framework KPI.

通常、MACF で権限を確認する関数はマクロ `MAC_CHECK` を呼び出します。たとえば、socket を作成する syscall の場合、`mac_socket_check_create` 関数が呼ばれ、さらに `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` を呼び出します。さらに、`MAC_CHECK` マクロは security/mac_internal.h で次のように定義されています:
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
`check` を `socket_check_create` に、`args...` を `(cred, domain, type, protocol)` に変換すると、次のようになります:
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
ヘルパーマクロを展開すると、具体的な制御フローが示されます:
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
つまり、`MAC_CHECK(socket_check_create, ...)` はまず静的ポリシーを走査し、必要に応じて動的ポリシーをロックして反復処理し、各フックの前後で DTrace プローブを発行し、各フックの戻り値を `mac_error_select()` を使って単一の `error` 結果にまとめます。


### Labels

MACF は **labels** を使い、その後ポリシーはアクセスを許可すべきかどうかを判定する際にこれを利用します。labels 構造体の宣言コードは [ここ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) にあり、これは **`struct ucred`** の **`cr_label`** 部分で [ここ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) の中で使われます。label にはフラグと、**MACF policies がポインタを割り当てるために使える**複数の **slots** が含まれます。例えば Sanbox はコンテナプロファイルを指します。

## MACF Policies

MACF Policy は、**特定の kernel 操作に適用されるルールと条件**を定義します。

kernel extension は `mac_policy_conf` 構造体を設定し、`mac_policy_register` を呼び出して登録できます。[ここ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
`mac_policy_register` への呼び出しを確認することで、これらのポリシーを設定している kernel extension を簡単に特定できる。さらに、extension の disassemble を確認すれば、使用されている `mac_policy_conf` struct も見つけられる。

MACF policies は **動的に** も登録・解除できることに注意。

`mac_policy_conf` の主要なフィールドの1つは **`mpc_ops`** である。この field は、policy がどの operations に関心を持つかを指定する。なお、その数は数百あるため、すべてを zero にしてから、policy が関心を持つものだけを選択することが可能である。From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
ほとんどすべての hooks は、これらの操作のいずれかが検知されたときに MACF によってコールバックされます。ただし、**`mpo_policy_*`** hooks は例外で、**`mpo_hook_policy_init()`** は登録時（つまり `mac_policy_register()` の後）に呼ばれるコールバックであり、**`mpo_hook_policy_initbsd()`** は BSD サブシステムが正しく初期化された後の遅延登録時に呼ばれます。

さらに、**`mpo_policy_syscall`** hook は、private な **ioctl** 風の呼び出し **interface** を公開するために、任意の kext から登録できます。すると、user client はパラメータとして **policy name**、整数の **code**、および任意の **arguments** を指定して `mac_syscall` (#381) を呼び出せるようになります。\
例えば、**`Sandbox.kext`** はこれを頻繁に使用します。

kext の **`__DATA.__const*`** を確認すると、ポリシー登録時に使用される `mac_policy_ops` 構造体を特定できます。これを見つけられるのは、そのポインタが `mpo_policy_conf` 内のオフセットにあり、さらにその領域に多数の NULL ポインタが存在するためです。

また、メモリから struct **`_mac_policy_list`** をダンプすれば、ポリシーを設定している kext の一覧を取得することもできます。この構造体は、登録される各ポリシーごとに更新されます。

ツール `xnoop` を使って、システムに登録されているすべてのポリシーをダンプすることもできます:
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
そして、check policy のすべてのチェックを次でダンプします:
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

### 初期ブートストラップと `mac_policy_init()`

- MACF は非常に早い段階で初期化される。XNU の起動コード内の `bootstrap_thread` で、`ipc_bootstrap` の後に XNU は `mac_policy_init()`（`mac_base.c` 内）を呼び出す。
- `mac_policy_init()` はグローバルな `mac_policy_list`（ポリシースロットの配列またはリスト）を初期化し、XNU 内の MAC（Mandatory Access Control）のインフラを構築する。
- その後、`mac_policy_initmach()` が呼び出され、組み込みまたはバンドルされたポリシーのカーネル側登録を処理する。

### `mac_policy_initmach()` と “security extensions” の読み込み

- `mac_policy_initmach()` は、事前に読み込まれている（または “policy injection” リストにある）カーネル拡張（kexts）を調べ、その `Info.plist` 内の `AppleSecurityExtension` キーを確認する。
- `Info.plist` に `<key>AppleSecurityExtension</key>`（または `true`）を宣言している kexts は “security extensions” と見なされる。つまり、MAC policy を実装するか、MACF インフラにフックするもの。
- そのキーを持つ Apple kexts の例には、**ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** などがある（すでに列挙した通り）。
- カーネルはこれらの kexts が早期に読み込まれることを保証し、その後ブート中にそれらの登録ルーチン（`mac_policy_register` 経由）を呼び出して、`mac_policy_list` に挿入する。

- 各 policy モジュール（kext）は `mac_policy_conf` 構造体を提供し、さまざまな MAC 操作（vnode チェック、exec チェック、label 更新など）向けのフック（`mpc_ops`）を持つ。
- ロード時フラグには `MPC_LOADTIME_FLAG_NOTLATE` が含まれる場合があり、これは「早期にロードされなければならない」を意味する（そのため遅延登録の試みは拒否される）。
- 一度登録されると、各モジュールは handle を得て `mac_policy_list` 内のスロットを占有する。
- 後で MAC フックが呼び出されると（例えば vnode アクセス、exec など）、MACF は登録済みの全ポリシーを反復し、集団として意思決定を行う。

- 特に、**AMFI**（Apple Mobile File Integrity）はそのような security extension の一つである。その `Info.plist` には security policy としてマークする `AppleSecurityExtension` が含まれている。
- カーネルブートの一部として、カーネルのロードロジックは、多くのサブシステムがそれに依存する前に “security policy”（AMFI など）がすでに有効であることを保証する。たとえば、カーネルは「AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy を含む security policy を読み込むことで、先のタスクに備える。」
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

`MAC` framework を使用する kext（つまり `mac_policy_register()` などを呼ぶもの）を書く場合、これらのシンボルを kext linker（kxld）が解決できるように、KPI（Kernel Programming Interfaces）への依存関係を宣言する必要があります。したがって、`kext` が MACF に依存することを宣言するには、`Info.plist` に `com.apple.kpi.dsep` を指定する必要があります（`find . Info.plist | grep AppleSecurityExtension`）。すると、その kext は `mac_policy_register`、`mac_policy_unregister`、および MAC hook function pointers のようなシンボルを参照するようになります。それらを解決するには、`com.apple.kpi.dsep` を依存関係として列挙する必要があります。

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
## modern macOS リリースにおける MACF

modern macOS では、Apple の security policies は通常、独立した `.kext` バンドルとして扱うよりも適切ではありません。**macOS 11** 以降、kernel extensions は **kernel collections** にリンクされます。**Apple Silicon** では別個の **SystemKC** はなく、third-party kext は **Auxiliary Kernel Collection (AuxKC)** に組み込まれ、その後 reboot して初めて loadable になります。MACF research の観点では、**Sandbox**、**AMFI**、**AppleSystemPolicy**、**CoreTrust**、**Quarantine** のような built-in policies は、`kextstat` のような deprecated tooling よりも `kmutil` で列挙する方が通常は簡単です。
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Apple Silicon では、セキュリティ kext が BootKC にない場合、次に AuxKC を確認してください。これは通常、`/System/Library/Extensions` 配下で単独の bundle を探すよりも有用です。

## MACF Callouts

コード内で **`#if CONFIG_MAC`** の条件分岐ブロックのように、MACF への callouts を見つけることはよくあります。さらに、これらのブロック内では `mac_proc_check*` の呼び出しを見つけることがあり、これは MACF を呼び出して特定の操作を実行するための **権限を確認** します。さらに、MACF callouts の形式は **`mac_<object>_<opType>_opName`** です。

object は次のいずれかです: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`。\
`opType` は通常 `check` で、アクションを許可または拒否するために使われます。ただし、`notify` を見つけることも可能で、これは kext が与えられたアクションに反応できるようにします。

例は [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) にあります:

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

その後、`mac_file_check_mmap` のコードは [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) で見つけることができます
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
`MAC_CHECK` マクロを呼び出しており、そのコードは [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) にあります
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
これにより、登録されたすべてのMACポリシーを巡回してそれぞれの関数を呼び出し、その出力を `error` 変数に格納する。`error` は `mac_error_select` によって成功コードのときのみ上書き可能であるため、どれか1つでもチェックが失敗すると、全体のチェックも失敗し、アクションは許可されない。

> [!TIP]
> ただし、すべてのMACF calloutがアクションの拒否だけに使われるわけではないことを覚えておいてください。たとえば、`mac_priv_grant` はマクロ [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) を呼び出し、どのポリシーでも 0 を返せば要求された権限を付与します:
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

これらの callas は、[**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) に定義された [**privileges**] をチェックおよび付与するためのものです。\
カーネルコードの一部は、プロセスの KAuth credentials と権限コードのいずれかを使って [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) の `priv_check_cred()` を呼び出し、`mac_priv_check` を使ってどのポリシーがその権限の付与を **拒否** するかを確認し、その後 `mac_priv_grant` を呼び出してどのポリシーがその `privilege` を付与するかを確認します。

### proc_check_syscall_unix

このフックは、すべての system calls をインターセプトするためのものです。`bsd/dev/[i386|arm]/systemcalls.c` では、宣言された関数 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) を見ることができ、そこには次のコードが含まれています:
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
これは、呼び出し元プロセスの **bitmask** を確認し、現在の syscall が `mac_proc_check_syscall_unix` を呼び出すべきかどうかを判定します。syscalls は非常に頻繁に呼ばれるため、毎回 `mac_proc_check_syscall_unix` を呼び出すのを避けるのが有益だからです。

関数 `proc_set_syscall_filter_mask()` は、プロセス内の bitmask syscalls を設定しますが、sandboxed processes に対して mask を設定するために Sandbox によって呼び出されます。

## Exposed MACF syscalls

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) で定義された一部の syscalls を通じて MACF とやり取りすることが可能です:
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
オフェンシブなリバースエンジニアリングでは、**`__mac_syscall`** は今でも最も優れた userland の chokepoint の1つです。これには **policy name**（たとえば `"Sandbox"` や `"AMFI"`）、**policy-specific selector/code**、そして `mpo_policy_syscall` で処理される **opaque argument blob** へのポインタが含まれます。これは、userland から未文書化の操作をリバースし、その後で kernel 実装へと踏み込むときに非常に有用です。Sandbox は通常 `__sandbox_ms` 経由でこれに到達し、AMFI は dyld の policy decision に同じ仕組みを使います。

## 実践的な offensive research notes

最近の macOS の bug は、MACF を直接 "break" することはほとんどありません。代わりに、たいていは **MACF / Sandbox / TCC の decision と、その後に起こる特権アクションの間の desynchronisation** を悪用します。

### Broker path checks vs real privileged action

繰り返し現れるパターンは、特権デーモンが **userland の pre-check**（たとえば `sandbox_check_by_audit_token()`）を path のある版に対して実行し、その後で **別の、または canonical でない attacker-controlled path** を使って実際の privileged sink を実行する、というものです。最近の `diskarbitrationd` / `storagekitd` の research は良い例です。**directory traversal** と **symlink swaps** により、attacker はデーモンの sandbox validation を通過し、その後 `~/Library/Application Support/com.apple.TCC` のような機密位置の上に mount できます。これにより、bug は選択した mount point に応じて **sandbox escape**、**local privilege escalation**、または **TCC bypass** になります。

sandbox から到達可能な root broker を audit するときは、まず次を grep してください:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helper
- `mount`, `rename`, `copyfile` のような privileged sink、helper-tool の XPC methods、または後で root として attacker-controlled path に触れるもの

### Private entitlements を持つ trusted deputy

もう1つの実践的なパターンは、MACF hooks を直接攻撃するのではなく、境界を越えるのに必要な権限をすでに持っている **trusted process** を悪用することです。最近の Safari/TCC の research は良い例です。重要な primitive は "kernel で TCC を無効化する" ことではなく、**`com.apple.private.tcc.allow`** を持つ Apple-signed process があなたの代わりに sensitive action を実行するよう、local policy/configuration を改変することでした。実際には、価値の高い audit 対象は次の条件を組み合わせた Apple daemon/app です:

- **private entitlements** または FDA のような reach
- 書き込み可能な config / database / mount point / policy file
- **Sandbox**、**AMFI**、**TCC**、または別の MACF policy によって媒介される後続の sensitive operation

より深い product-specific なリバースは、[macOS Sandbox](macos-sandbox/README.md) と [macOS TCC](macos-tcc/README.md) の専用ページを確認してください。

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}

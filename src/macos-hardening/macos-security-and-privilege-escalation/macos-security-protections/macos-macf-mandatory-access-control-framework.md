# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

**MACF** は **Mandatory Access Control Framework** の略で、コンピュータを保護するためにOSに組み込まれたセキュリティシステムです。ファイル、アプリケーション、システムリソースなど、システムの特定部分に誰が何をアクセスできるかについての**厳格なルールを設定**することで動作します。これらのルールを自動的に適用することで、認可されていないアクセスや悪意ある活動のリスクを低減します。

MACF 自体は決定を下すわけではなく、単にアクションを**インターセプト**し、`AppleMobileFileIntegrity.kext`、`Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` や `mcxalr.kext` のようなポリシーモジュール（カーネル拡張）に判断を委ねます。

- ポリシーは強制的である場合がある（ある操作で return 0 以外を返す）
- ポリシーは監視のみである場合がある（反対せずに return 0 を返し、フックに便乗して何かを行う）
- MACF の静的ポリシーはブート時にインストールされ、決して削除されない
- MACF の動的ポリシーは KEXT によってインストールされ（kextload）、理論上は kextunload されうる
- iOS では静的ポリシーのみ許可され、macOS では静的 + 動的が許可される
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### 流れ

1. プロセスが syscall/mach trap を実行する  
2. 関連する関数が kernel 内で呼ばれる  
3. 関数が MACF を呼び出す  
4. MACF は、その関数にフックするようポリシーで要求したポリシーモジュールをチェックする  
5. MACF は該当するポリシーを呼び出す  
6. ポリシーはその操作を許可するか拒否するかを示す

> [!CAUTION]
> Apple のみが MAC Framework KPI を使用できます。

通常、MACF で権限をチェックする関数はマクロ `MAC_CHECK` を呼び出します。例えば、ソケットを作成する syscall の場合、`mac_socket_check_create` を呼び出し、さらに `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` を呼びます。さらに、マクロ `MAC_CHECK` は security/mac_internal.h に次のように定義されています:
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
`check` を `socket_check_create` に変え、`args...` を `(cred, domain, type, protocol)` にすると、以下のようになります:
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
ヘルパーマクロを展開すると、具体的な制御フローが表示されます:
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
In other words, `MAC_CHECK(socket_check_create, ...)` walks the static policies first, conditionally locks and iterates over dynamic policies, emits the DTrace probes around each hook, and collapses every hook’s return code into the single `error` result via `mac_error_select()`.


### Labels

MACF はアクセス許可を付与するかどうかを判断する際にポリシーが使用する **labels** を使用します。ラベル構造体の宣言コードは [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) で確認でき、これは **`struct ucred`** の **`cr_label`** 部分で [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) のように使用されています。ラベルはフラグと複数の **slots** を含んでおり、これらは **MACF policies to allocate pointers** によってポインタを割り当てるために使用できます。例えば Sanbox はコンテナプロファイルを指します。

## MACF Policies

MACF Policy は、**特定のカーネル操作に適用されるルールと条件**を定義します。

カーネル拡張は `mac_policy_conf` 構造体を設定し、`mac_policy_register` を呼び出して登録することができます。From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
これらのポリシーを設定しているカーネル拡張は、`mac_policy_register` への呼び出しを確認することで簡単に特定できます。さらに、拡張の disassemble を確認すれば、使用されている `mac_policy_conf` 構造体を見つけることも可能です。

MACF ポリシーは **動的に** 登録・登録解除されることがある点に注意してください。

`mac_policy_conf` の主要なフィールドの一つが **`mpc_ops`** です。このフィールドはポリシーが関心を持つ操作を指定します。操作は数百に及ぶため、すべてをゼロにしてからポリシーが関心を持つものだけを選択することが可能です。詳細は [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
ほとんどのフックは、これらの操作のいずれかがインターセプトされると MACF によってコールバックされます。ただし、**`mpo_policy_*`** フックは例外で、`mpo_hook_policy_init()` は登録時（つまり `mac_policy_register()` の後）に呼び出されるコールバックであり、`mpo_hook_policy_initbsd()` は BSD サブシステムが適切に初期化された後の遅い登録時に呼び出されます。

さらに、**`mpo_policy_syscall`** フックは任意の kext によって登録され、プライベートな **ioctl** スタイルの呼び出し **interface** を公開できます。すると、ユーザクライアントは `mac_syscall` (#381) を呼び出して、パラメータとして整数の **code** とオプションの **arguments** を伴う **policy name** を指定できます。\
たとえば、**`Sandbox.kext`** はこれを多用します。

kext の **`__DATA.__const*`** を確認することで、ポリシー登録時に使用される `mac_policy_ops` 構造体を特定できます。これは、ポインタが `mpo_policy_conf` 内のオフセットにあることと、その領域に含まれる NULL ポインタの数から見つけられるためです。

また、登録された各ポリシーで更新される構造体 **`_mac_policy_list`** をメモリからダンプすることで、ポリシーを設定した kext の一覧を取得することも可能です。

また、ツール `xnoop` を使用してシステムに登録されているすべてのポリシーをダンプすることもできます:
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
そして、check policy のすべてのチェックを次のコマンドでダンプします:
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

### 初期ブートストラップと mac_policy_init()

- MACF は非常に早い段階で初期化されます。`bootstrap_thread`（XNU の起動コード）内で、`ipc_bootstrap` の後に XNU は `mac_policy_init()`（`mac_base.c`）を呼び出します。
- `mac_policy_init()` はグローバルな `mac_policy_list`（ポリシースロットの配列またはリスト）を初期化し、XNU 内での MAC（Mandatory Access Control）インフラストラクチャを設定します。
- 後で、組み込みまたはバンドルされたポリシーのためのカーネル側登録を扱う `mac_policy_initmach()` が呼び出されます。

### `mac_policy_initmach()` と “security extensions” の読み込み

- `mac_policy_initmach()` は事前にロードされた（または「policy injection」リストにある）カーネル拡張（kext）を調べ、その Info.plist にキー `AppleSecurityExtension` があるかを確認します。
- Info.plist に `<key>AppleSecurityExtension</key>`（または `true`）を宣言している kext は “security extensions” と見なされます — つまり MAC ポリシーを実装するか、MACF インフラにフックするものです。
- そのキーを含む Apple の kext の例には、**ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** などがあります（既にあなたが挙げたものと同様です）。
- カーネルはそれらの kext を早期にロードすることを保証し、起動時に登録ルーチン（`mac_policy_register` 経由）を呼び出して `mac_policy_list` に挿入します。

- 各ポリシーモジュール（kext）は `mac_policy_conf` 構造体を提供し、様々な MAC 操作（vnode チェック、exec チェック、ラベル更新など）に対するフック（`mpc_ops`）を持ちます。
- ロード時のフラグには `MPC_LOADTIME_FLAG_NOTLATE` が含まれる場合があり、これは「早期にロードされる必要がある」（遅い登録試行は拒否される）ことを意味します。
- 登録されると、各モジュールはハンドルを取得し、`mac_policy_list` のスロットを占有します。
- 後で MAC フックが呼び出されるとき（例えば vnode アクセス、exec など）、MACF は登録されている全てのポリシーを反復して集合的に判断を下します。

- 特に、**AMFI**（Apple Mobile File Integrity）はそのようなセキュリティ拡張の一例です。Info.plist に `AppleSecurityExtension` を含み、セキュリティポリシーとしてマークされています。
- カーネルのブート処理の一環として、カーネルのロードロジックは多くのサブシステムが依存する前に「セキュリティポリシー」（AMFI など）が既にアクティブであることを保証します。例えば、カーネルは「今後の処理に備えて … AppleMobileFileIntegrity (AMFI)、Sandbox、Quarantine ポリシーを含むセキュリティポリシーをロードする」といった準備を行います。
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
## MAC policy kexts における KPI 依存関係と com.apple.kpi.dsep

MAC フレームワークを利用する kext（例: `mac_policy_register()` 等を呼ぶ場合）を作成する際は、kext リンカ（kxld）がそれらのシンボルを解決できるように、KPI（Kernel Programming Interfaces）への依存を宣言する必要があります。

そのため、kext が MACF に依存していることを宣言するには、`Info.plist` に `com.apple.kpi.dsep` を指定する必要があります（例: `find . Info.plist | grep AppleSecurityExtension`）。すると kext は `mac_policy_register`、`mac_policy_unregister`、および MAC のフック関数ポインタといったシンボルを参照します。これらを解決するには `com.apple.kpi.dsep` を依存として列挙しなければなりません。

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
## MACF の呼び出し

コード内の **`#if CONFIG_MAC`** のような条件ブロックで MACF への呼び出しを見つけることはよくあります。さらに、これらのブロック内では、特定のアクションを実行するための権限を確認するために MACF を呼び出す `mac_proc_check*` のような呼び出しを見つけることができます。MACF 呼び出しの形式は **`mac_<object>_<opType>_opName`** です。

The object is one of the following: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` は通常 check で、アクションを許可または拒否するために使われます。ただし、`notify` を見つけることもあり、これは kext が該当するアクションに反応することを許可します。

You can find an example in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Then, it's possible to find the code of `mac_file_check_mmap` in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
`MAC_CHECK` マクロを呼び出しており、そのコードは [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) にあります。
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
これは登録されたすべての mac ポリシーを順に呼び出し、それらの関数を実行して出力を error 変数に格納します。error は成功コードによってのみ `mac_error_select` で上書きされるため、いずれかのチェックが失敗すると全体のチェックが失敗し、そのアクションは許可されません。

> [!TIP]
> ただし、すべての MACF コールアウトがアクションを拒否するためだけに使われるわけではないことに注意してください。例えば、`mac_priv_grant` はマクロ [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) を呼び出します。これは、いずれかのポリシーが 0 を返した場合に要求された特権を付与します：
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

これらの呼び出しは、[**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) に定義された（数十の）特権をチェックおよび付与するためのものです。\
一部のカーネルコードは、プロセスの KAuth 認証情報と特権コードの一つを用いて [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) の `priv_check_cred()` を呼び出します。`priv_check_cred()` は `mac_priv_check` を呼び出してどのポリシーが特権の付与を**拒否**するかを確認し、続いて `mac_priv_grant` を呼んでどのポリシーがその `privilege` を付与するかを確認します。

### proc_check_syscall_unix

このフックはすべてのシステムコールをインターセプトすることを可能にします。`bsd/dev/[i386|arm]/systemcalls.c` では宣言された関数 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) を確認でき、そこには次のコードが含まれています：
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
これは、呼び出しプロセスの **bitmask** 内を確認し、現在の syscall が `mac_proc_check_syscall_unix` を呼び出すべきかどうかを判定します。  
これは、syscalls が非常に頻繁に呼び出されるため、毎回 `mac_proc_check_syscall_unix` を呼び出すのを避けるためです。

プロセス内の bitmask syscalls を設定する関数 `proc_set_syscall_filter_mask()` は、Sandbox が sandboxed processes にマスクを設定するために呼び出されることに注意してください。

## 公開された MACF syscalls

MACF と対話するには、[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) に定義されたいくつかの syscalls を通じて可能です：
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
## 参考文献

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}

# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

**MACF** は **Mandatory Access Control Framework** の略で、オペレーティングシステムに組み込まれたセキュリティシステムです。これは、ファイル、アプリケーション、システムリソースなど、システムの特定の部分に誰が何をアクセスできるかについて**厳格なルールを設定**することで機能します。これらのルールを自動的に適用することで、MACFは許可されたユーザーやプロセスだけが特定の操作を実行できるようにし、不正アクセスや悪意のある活動のリスクを低減します。

MACF自体は実際に判断を下すわけではなく、単にアクションを**インターセプト**し、その判断は `AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext`、`mcxalr.kext` のようなポリシーモジュール（カーネル拡張）に委ねられます。

- ポリシーは enforcing（強制）する場合があり（ある操作で0以外を返す）
- ポリシーは monitoring（監視）する場合があり（反対しないよう0を返し、フックに便乗して何かを行う）
- MACFの静的ポリシーはブート時にインストールされ、決して削除されません
- MACFの動的ポリシーはKEXT（kextload）によってインストールされ、理論上はkextunloadされる可能性があります
- iOSでは静的ポリシーのみが許可され、macOSでは静的＋動的が許可されます
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### フロー

1. プロセスが syscall/mach trap を実行する
2. カーネル内で該当する関数が呼び出される
3. その関数が MACF を呼び出す
4. MACF は、ポリシーでその関数へのフックを要求しているポリシーモジュールを確認する
5. MACF は該当するポリシーを呼び出す
6. ポリシーはそのアクションを許可するか拒否するかを示す

> [!CAUTION]
> Apple のみが MAC Framework KPI を使用できます。

通常、MACFで権限をチェックする関数はマクロ `MAC_CHECK` を呼び出します。例えばソケットを作成するためのsyscallの場合、`mac_socket_check_create` という関数が呼ばれ、そこで `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` が呼ばれます。さらに、マクロ `MAC_CHECK` は security/mac_internal.h に次のように定義されています:
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
注意: `check` を `socket_check_create` に、`args...` を `(cred, domain, type, protocol)` に変換すると、次のようになります:
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
言い換えれば、`MAC_CHECK(socket_check_create, ...)` はまず静的ポリシーを走査し、動的ポリシーを条件付きでロックして反復し、各フックの前後で DTrace プローブを発行し、各フックの戻り値を `mac_error_select()` を通じて単一の `error` 結果に集約する。

### ラベル

MACF はポリシーがアクセスを許可すべきかどうかを判断するために使用する **ラベル（labels）** を使用する。labels 構造体の宣言は [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) で確認でき、これは **`struct ucred`** の [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) の **`cr_label`** 部分で使用されている。ラベルはフラグと、**MACF ポリシーがポインタを割り当てるために使用できる** 複数の **スロット（slots）** を含む。例えば Sandbox はコンテナのプロファイルを指す。

## MACF ポリシー

MACF Policy は、特定のカーネル操作に適用される **規則と条件** を定義する。

カーネル拡張は `mac_policy_conf` 構造体を設定し、`mac_policy_register` を呼んで登録できる。From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
これらのポリシーを設定している kernel extensions は、`mac_policy_register` への呼び出しを確認することで簡単に特定できます。さらに、拡張の逆アセンブルを確認することで、使用されている `mac_policy_conf` 構造体を見つけることも可能です。

MACF ポリシーは **動的に** 登録・登録解除できる点に注意してください。

`mac_policy_conf` の主なフィールドの一つが **`mpc_ops`** です。このフィールドはポリシーが関心を持つオペレーションを指定します。オペレーションは数百に及ぶため、全てをゼロにしてからポリシーが必要とするものだけを選択することが可能です。From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
これらの操作のいずれかがインターセプトされると、ほとんどのフックはMACFによってコールバックされます。しかし、**`mpo_policy_*`** フックは例外で、`mpo_hook_policy_init()` は登録時（つまり `mac_policy_register()` の後）に呼び出されるコールバックであり、`mpo_hook_policy_initbsd()` はBSDサブシステムが正しく初期化された後の遅い登録時に呼び出されます。

さらに、**`mpo_policy_syscall`** フックは任意の kext によって登録され、プライベートな **ioctl** スタイルの呼び出し **interface** を公開できます。すると、ユーザクライアントは `mac_syscall` (#381) を呼び出し、パラメータとして **policy name** と整数の **code**、および任意の **arguments** を指定できるようになります。\
例えば、**`Sandbox.kext`** はこれを多用しています。

kext の **`__DATA.__const*`** を確認することで、ポリシー登録時に使用された `mac_policy_ops` 構造体を特定することが可能です。これはそのポインタが `mpo_policy_conf` の内部のオフセットにあり、その領域に含まれる NULL ポインタの数でも見つけられるためです。

さらに、登録された各ポリシーで更新される構造体 **`_mac_policy_list`** をメモリからダンプすることで、ポリシーを設定した kext の一覧を取得することも可能です。

また、ツール `xnoop` を使ってシステムに登録されているすべてのポリシーをダンプすることもできます:
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
その後、check policy のすべてのチェックを次のようにdumpします:
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

### 初期ブートストラップと `mac_policy_init()`

- MACF は非常に早い段階で初期化されます。`bootstrap_thread`（XNU の起動コード）内で、`ipc_bootstrap` の後、XNU は `mac_policy_init()`（`mac_base.c`）を呼び出します。
- `mac_policy_init()` はグローバルな `mac_policy_list`（ポリシースロットの配列またはリスト）を初期化し、XNU 内での MAC（Mandatory Access Control）のインフラを設定します。
- その後、組み込みまたはバンドルされたポリシーのカーネル側登録を扱う `mac_policy_initmach()` が呼び出されます。

### `mac_policy_initmach()` と “security extensions” の読み込み

- `mac_policy_initmach()` は、事前にロードされた（または「policy injection」リストにある）kernel extensions (kexts) を調べ、各 Info.plist に `AppleSecurityExtension` キーがあるかを検査します。
- Info.plist に `<key>AppleSecurityExtension</key>`（または `true`）と宣言している kext は「security extensions」と見なされます — すなわち MAC ポリシーを実装するか、MACF インフラにフックするものです。
- そのキーを持つ Apple の kext の例には **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** などがあります（前述の通り）。
- カーネルはそれらの kext が早期にロードされることを保証し、ブート中にそれらの登録ルーチン（`mac_policy_register` 経由）を呼び出して `mac_policy_list` に挿入します。

- 各ポリシーモジュール（kext）は `mac_policy_conf` 構造体を提供し、さまざまな MAC 操作（vnode チェック、exec チェック、ラベル更新など）用のフック（`mpc_ops`）を備えています。
- ロード時フラグには `MPC_LOADTIME_FLAG_NOTLATE`（早期にロードされなければならない、つまり遅い登録試行は拒否される）などが含まれることがあります。
- 登録されると各モジュールはハンドルを取得し、`mac_policy_list` のスロットを占有します。
- 後に MAC フックが呼び出されると（たとえば vnode アクセス、exec など）、MACF は登録されたすべてのポリシーを反復して集合的な判断を行います。

- 特に **AMFI**（Apple Mobile File Integrity）はそのような security extension の一例です。Info.plist に `AppleSecurityExtension` を含み、セキュリティポリシーとしてマークされています。
- カーネルブートの一部として、カーネルのロードロジックは多くのサブシステムが依存する前に「security policy」（AMFI 等）が既に有効であることを保証します。たとえば、カーネルは「今後の処理に備えて … AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy を含む security policy をロードする」といった準備を行います。
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
## MAC policy kexts における KPI 依存関係 と com.apple.kpi.dsep

MAC フレームワークを使用する kext を作成する際（例: `mac_policy_register()` を呼ぶなど）、kext linker (kxld) がそれらのシンボルを解決できるように、KPI (Kernel Programming Interfaces) への依存関係を宣言する必要があります。したがって、`kext` が MACF に依存することを宣言するには、`Info.plist` に `com.apple.kpi.dsep` を示す必要があります（`find . Info.plist | grep AppleSecurityExtension`）。そうすることで kext は `mac_policy_register`、`mac_policy_unregister`、および MAC hook の関数ポインタといったシンボルを参照します。これらを解決するために、`com.apple.kpi.dsep` を依存関係として列挙しなければなりません。

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
## MACF コールアウト

コード内に定義された MACF への呼び出し（例：**`#if CONFIG_MAC`** のような条件付きブロック）を見つけることがよくあります。さらに、これらのブロック内では `mac_proc_check*` のような呼び出しを見つけることがあり、これは特定の操作を実行するための権限があるかどうかを**チェックする**ために MACF を呼び出します。さらに、MACF 呼び出しの形式は： **`mac_<object>_<opType>_opName`** です。

オブジェクトは次のいずれかです: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` は通常 check で、アクションを許可または拒否するために使われます。ただし、`notify` を見つけることもあり、これは kext がそのアクションに反応することを可能にします。

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
これは `MAC_CHECK` マクロを呼び出しており、そのコードは [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) で確認できます。
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
これは登録されているすべての mac ポリシーを順に呼び出し、それらの戻り値を error 変数に格納します。error は成功コードによって `mac_error_select` のみが上書きできるため、いずれかのチェックが失敗すると全体のチェックが失敗し、そのアクションは許可されません。

> [!TIP]
> ただし、すべての MACF コールアウトがアクションを拒否するためだけに使われるわけではない点に注意してください。例えば、`mac_priv_grant` はマクロ [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) を呼び出します。これは、いずれかのポリシーが 0 を返した場合に要求された特権を付与します:
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

これらの呼び出しは [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) に定義された（数十の） **特権** をチェックおよび付与するためのものです。\
カーネルの一部コードは、プロセスの KAuth 資格情報と特権コードのいずれかを使って [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) にある `priv_check_cred()` を呼び出します。これが `mac_priv_check` を呼び出して、いずれかのポリシーがその特権の付与を **拒否** するかを確認し、その後 `mac_priv_grant` を呼んでいずれかのポリシーがその `privilege` を付与するか確認します。

### proc_check_syscall_unix

このフックはすべてのシステムコールをインターセプトすることを可能にします。`bsd/dev/[i386|arm]/systemcalls.c` では宣言された関数 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) を確認できます。以下にそのコードが含まれています:
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
これにより、呼び出しプロセスの **bitmask** をチェックして、現在の syscall が `mac_proc_check_syscall_unix` を呼ぶべきかを判定します。syscall は非常に頻繁に呼ばれるため、毎回 `mac_proc_check_syscall_unix` を呼ぶのを避けるのが有用だからです。

`proc_set_syscall_filter_mask()` 関数はプロセス内の bitmask syscalls を設定しますが、これは Sandbox によってサンドボックス化されたプロセスのマスクを設定するために呼び出される点に注意してください。

## 公開されている MACF syscalls

いくつかの syscalls は [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) に定義されており、これを通じて MACF と対話することが可能です：
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

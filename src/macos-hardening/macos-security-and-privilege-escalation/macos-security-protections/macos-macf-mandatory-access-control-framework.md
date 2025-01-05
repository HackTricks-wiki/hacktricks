# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

**MACF**は**Mandatory Access Control Framework**の略で、コンピュータを保護するためにオペレーティングシステムに組み込まれたセキュリティシステムです。これは、**特定のシステムの部分にアクセスできるのは誰または何かに関する厳格なルールを設定することによって機能します**。これらのルールを自動的に施行することにより、MACFは認可されたユーザーとプロセスのみが特定のアクションを実行できるようにし、無許可のアクセスや悪意のある活動のリスクを減少させます。

MACFは実際には決定を下すわけではなく、単に**アクションを傍受**するだけであり、決定は`AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext`、および`mcxalr.kext`のような**ポリシーモジュール**（カーネル拡張）に委ねられています。

### フロー

1. プロセスがsyscall/machトラップを実行します
2. 関連する関数がカーネル内で呼び出されます
3. 関数がMACFを呼び出します
4. MACFはその関数をフックするように要求したポリシーモジュールをチェックします
5. MACFは関連するポリシーを呼び出します
6. ポリシーはアクションを許可するか拒否するかを示します

> [!CAUTION]
> AppleだけがMAC Framework KPIを使用できます。

### ラベル

MACFは**ラベル**を使用し、その後ポリシーがアクセスを許可するかどうかを確認します。ラベル構造体の宣言コードは[こちら](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h)で見つけることができ、これは**`struct ucred`**内の[**こちら**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86)の**`cr_label`**部分で使用されます。ラベルにはフラグと**MACFポリシーがポインタを割り当てるために使用できるスロットの数**が含まれています。例えば、Sandboxはコンテナプロファイルを指します。

## MACFポリシー

MACFポリシーは**特定のカーネル操作に適用されるルールと条件を定義します**。

カーネル拡張は`mac_policy_conf`構造体を構成し、次に`mac_policy_register`を呼び出して登録できます。ここから[こちら](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
カーネル拡張がこれらのポリシーを構成していることを特定するのは簡単で、`mac_policy_register`への呼び出しを確認することで行えます。さらに、拡張の逆アセンブルを確認することで、使用されている`mac_policy_conf`構造体を見つけることも可能です。

MACFポリシーは**動的に**登録および登録解除することもできることに注意してください。

`mac_policy_conf`の主なフィールドの1つは**`mpc_ops`**です。このフィールドは、ポリシーが関心を持つ操作を指定します。数百の操作があるため、すべてをゼロに設定し、ポリシーが関心を持つものだけを選択することが可能です。[こちら](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)から:
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
ほとんどすべてのフックは、これらの操作がインターセプトされるときにMACFによってコールバックされます。しかし、**`mpo_policy_*`** フックは例外であり、`mpo_hook_policy_init()`は登録時に呼び出されるコールバックです（したがって、`mac_policy_register()`の後）であり、`mpo_hook_policy_initbsd()`はBSDサブシステムが適切に初期化された後の遅延登録中に呼び出されます。

さらに、**`mpo_policy_syscall`** フックは、任意のkextによってプライベートな**ioctl**スタイルの呼び出し**インターフェース**を公開するために登録できます。これにより、ユーザクライアントは、**ポリシー名**と整数の**コード**、およびオプションの**引数**をパラメータとして指定して`mac_syscall` (#381) を呼び出すことができます。\
例えば、**`Sandbox.kext`** はこれを多く使用します。

kextの**`__DATA.__const*`**をチェックすることで、ポリシーを登録する際に使用される`mac_policy_ops`構造体を特定することが可能です。そのポインタは`mpo_policy_conf`内のオフセットにあり、その領域に存在するNULLポインタの数からも見つけることができます。

さらに、メモリから構造体**`_mac_policy_list`**をダンプすることで、ポリシーを構成したkextのリストを取得することも可能です。この構造体は、登録されるたびに更新されます。

## MACFの初期化

MACFは非常に早く初期化されます。XNUの`bootstrap_thread`で設定され、`ipc_bootstrap`の後に`mac_policy_init()`が呼び出され、`mac_policy_list`が初期化され、その後すぐに`mac_policy_initmach()`が呼び出されます。この関数は、`Info.plist`に`AppleSecurityExtension`キーを持つすべてのApple kext（`ALF.kext`、`AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext`など）を取得してロードします。

## MACFコールアウト

コード内で**`#if CONFIG_MAC`**の条件付きブロックのように、MACFへのコールアウトを見つけることは一般的です。さらに、これらのブロック内では、特定のアクションを実行するための**権限を確認する**ためにMACFを呼び出す`mac_proc_check*`への呼び出しを見つけることができます。さらに、MACFコールアウトの形式は、**`mac_<object>_<opType>_opName`**です。

オブジェクトは次のいずれかです：`bpfdesc`、`cred`、`file`、`proc`、`vnode`、`mount`、`devfs`、`ifnet`、`inpcb`、`mbuf`、`ipq`、`pipe`、`sysv[msg/msq/shm/sem]`、`posix[shm/sem]`、`socket`、`kext`。\
`opType`は通常、アクションを許可または拒否するために使用されるcheckです。ただし、与えられたアクションに反応するためにkextを許可するnotifyを見つけることも可能です。

[https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621)に例があります：

<pre class="language-c"><code class="lang-c">int
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
`MAC_CHECK`マクロを呼び出しているのは、コードは[https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)で見つけることができます。
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
どの登録されたmacポリシーを呼び出し、その関数を実行して出力をエラー変数に格納します。このエラー変数は、成功コードによってのみ`mac_error_select`で上書き可能です。したがって、チェックが失敗した場合、全体のチェックが失敗し、アクションは許可されません。

> [!TIP]
> ただし、すべてのMACFコールアウトがアクションを拒否するためだけに使用されるわけではないことを覚えておいてください。たとえば、`mac_priv_grant`はマクロ[**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274)を呼び出し、ポリシーのいずれかが0で応答した場合に要求された特権を付与します：
>
> ```c
> /*
>  * MAC_GRANTは、ポリシー
>  * モジュールリストを歩き、各ポリシーが
>  * リクエストについてどう感じているかを確認することによって
>  * 指定されたチェックを実行します。MAC_CHECKとは異なり、
>  * いずれかのポリシーが'0'を返す場合は付与し、
>  * そうでない場合はEPERMを返します。呼び出し元の
>  * スコープ内で'error'を介してその値を返すことに注意してください。
>  */
> #define MAC_GRANT(check, args...) do {                              \
>     error = EPERM;                                                  \
>     MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>     });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

これらのコールは、[**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h)で定義された（数十の）**特権**をチェックし、提供することを目的としています。\
一部のカーネルコードは、プロセスのKAuth資格情報と特権コードのいずれかを使用して、[**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c)から`priv_check_cred()`を呼び出し、ポリシーが特権を付与することを**拒否**しているかどうかを確認するために`mac_priv_check`を呼び出し、その後`mac_priv_grant`を呼び出して、ポリシーが`privilege`を付与するかどうかを確認します。

### proc_check_syscall_unix

このフックは、すべてのシステムコールをインターセプトすることを可能にします。`bsd/dev/[i386|arm]/systemcalls.c`では、次のコードを含む宣言された関数[`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25)を見ることができます：
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
呼び出しプロセスの**ビットマスク**をチェックし、現在のシステムコールが`mac_proc_check_syscall_unix`を呼び出すべきかどうかを判断します。これは、システムコールが非常に頻繁に呼び出されるため、毎回`mac_proc_check_syscall_unix`を呼び出すのを避けることが興味深いからです。

関数`proc_set_syscall_filter_mask()`は、プロセス内のビットマスクシステムコールを設定するためにSandboxによって呼び出され、サンドボックス化されたプロセスにマスクを設定します。

## 公開されたMACFシステムコール

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151)で定義された一部のシステムコールを通じてMACFと対話することが可能です。
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

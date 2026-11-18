# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

**MACF** は **Mandatory Access Control Framework** の略で、コンピューターの保護を支援するためにオペレーティングシステムに組み込まれたセキュリティシステムです。ファイル、アプリケーション、システムリソースなど、システムの特定の部分に誰が、または何がアクセスできるかについて、**厳格なルールを設定**して機能します。これらのルールを自動的に適用することで、MACF は許可されたユーザーとプロセスだけが特定の操作を実行できるようにし、不正アクセスや悪意ある活動のリスクを低減します。

MACF は実際には何も判断せず、操作を**インターセプト**するだけである点に注意してください。判断は、`AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext`、`mcxalr.kext` など、MACF が呼び出す**ポリシーモジュール**（kernel extension）に委ねられます。

- ポリシーは、ある操作に対して 0 以外を返すことで適用できます
- ポリシーは、異議を唱えず、フックに便乗して何らかの処理を行うために 0 を返すことで監視できます
- MACF の static policy はブート時にインストールされ、決して削除されません
- MACF の dynamic policy は KEXT（kextload）によってインストールされ、理論上は kextunload でアンロードできます
- iOS では static policy のみが許可され、macOS では static と dynamic の両方が許可されます。<sup>[[7]](#references)</sup>

### フロー

1. プロセスが syscall/mach trap を実行する
2. カーネル内で該当する関数が呼び出される
3. 関数が MACF を呼び出す
4. MACF が、その関数をポリシー内でフックするよう要求したポリシーモジュールを確認する
5. MACF が該当するポリシーを呼び出す
6. ポリシーが、その操作を許可するか拒否するかを示す

> [!CAUTION]
> MAC Framework KPI を使用できるのは Apple だけです。

通常、MACF を使って権限を確認する関数は、マクロ `MAC_CHECK` を呼び出します。たとえば、socket を作成する syscall の場合、`mac_socket_check_create` という関数が呼び出され、その関数が `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` を呼び出します。さらに、マクロ `MAC_CHECK` は security/mac_internal.h で次のように定義されています。<sup>[[3]](#references)</sup>
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

`check`を`socket_check_create`に、`(cred, domain, type, protocol)`内の`args...`を変換すると、次のようになります。

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

helperマクロを展開すると、具体的な制御フローがわかります。

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

つまり、`MAC_CHECK(socket_check_create, ...)` はまず静的ポリシーを走査し、条件に応じてロックを取得して動的ポリシーを反復処理し、各フックの前後で DTrace プローブを発行し、`mac_error_select()` を使ってすべてのフックの戻り値を単一の `error` 結果にまとめます。


### Labels

MACF は **labels** を使用し、アクセスを許可するかどうかを判断するポリシーがこれを利用します。labels 構造体の宣言コードは[こちら](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h)にあり、[こちら](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86)の **`struct ucred`** 内の **`cr_label`** 部分で使用されています。label にはフラグと、**MACF policies がポインターを割り当てるために使用できる slots** がいくつか含まれています。たとえば Sandbox は container profile を指します。

## MACF Policies

MACF Policy は、**特定のカーネル操作に適用するルールと条件**を定義します。

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

これらのポリシーを設定する kernel extensions は、`mac_policy_register` の呼び出しを調べることで簡単に特定できます。さらに、extension の逆アセンブルを調べれば、使用されている `mac_policy_conf` struct も見つけられます。

MACF policies は**動的に**登録および登録解除することもできます。

`mac_policy_conf` の主なフィールドの一つが **`mpc_ops`** です。このフィールドは、ポリシーが対象とする操作を指定します。操作は数百種類あるため、すべてのエントリをゼロにしてから、ポリシーに必要なものだけを選択できます。[こちら](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)を参照してください。<sup>[[1]](#references)</sup>

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

ほぼすべての hook は、これらの操作のいずれかがインターセプトされたときに MACF からコールバックされます。ただし、**`mpo_policy_*`** hook は例外です。`mpo_hook_policy_init()` は登録時（つまり `mac_policy_register()` の後）に呼び出されるコールバックであり、`mpo_hook_policy_initbsd()` は BSD サブシステムが適切に初期化された後、登録処理の後半で呼び出されます。

さらに、**`mpo_policy_syscall`** hook は、任意の kext がプライベートな **ioctl** 形式の呼び出し **interface** を公開するために登録できます。その後、ユーザークライアントは `mac_syscall` (#381) を呼び出し、パラメーターとして **policy name** と整数の **code**、および省略可能な **arguments** を指定できます。\
たとえば、`Sandbox.kext` はこれを頻繁に使用します。

kext の **`__DATA.__const*`** を調べると、policy の登録時に使用される `mac_policy_ops` 構造体を特定できます。これは、そのポインターが `mpo_policy_conf` 内のオフセットにあることと、その領域にある NULL ポインターの数から特定できます。

また、登録済みのすべての policy で更新される **`_mac_policy_list`** 構造体をメモリからダンプすれば、policy を設定した kext の一覧を取得できます。

`xnoop` ツールを使って、システムに登録されたすべての policy をダンプすることもできます:

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

そして、次のコマンドですべての check policy チェックをダンプします：

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

- MACF は非常に早い段階で初期化されます。XNU の起動コードにある `bootstrap_thread` で、`ipc_bootstrap` の後に XNU は `mac_policy_init()`（`mac_base.c` 内）を呼び出します。  
- `mac_policy_init()` はグローバルな `mac_policy_list`（ポリシースロットの配列またはリスト）を初期化し、XNU 内で MAC（Mandatory Access Control）を扱うための基盤をセットアップします。  
- その後、`mac_policy_initmach()` が呼び出され、組み込みまたはバンドルされたポリシーのカーネル側での登録を処理します。

### `mac_policy_initmach()` と「security extensions」の読み込み

- `mac_policy_initmach()` は、事前に読み込まれた（または「policy injection」リストにある）カーネル拡張機能（kext）を調べ、その Info.plist に `AppleSecurityExtension` キーがあるかを確認します。  
- Info.plist で `<key>AppleSecurityExtension</key>`（または `true`）を宣言している kext は、「security extensions」、つまり MAC ポリシーを実装するか、MACF 基盤にフックするものと見なされます。  
- このキーを持つ Apple の kext の例としては、**ALF.kext**、**AppleMobileFileIntegrity.kext (AMFI)**、**Sandbox.kext**、**Quarantine.kext**、**TMSafetyNet.kext**、**CoreTrust.kext**、**AppleSystemPolicy.kext** などがあります（すでに列挙したとおりです）。  
- カーネルはこれらの kext が早期に読み込まれるようにし、起動中に（`mac_policy_register` を介して）登録ルーチンを呼び出し、`mac_policy_list` に登録します。

  - 各ポリシーモジュール（kext）は、さまざまな MAC 操作（vnode チェック、exec チェック、ラベル更新など）用のフック（`mpc_ops`）を持つ `mac_policy_conf` 構造体を提供します。  
  - 読み込み時のフラグには、`MPC_LOADTIME_FLAG_NOTLATE`（「早期に読み込む必要がある」という意味）が含まれる場合があります。これにより、後からの登録試行は拒否されます。  
  - 登録されると、各モジュールにハンドルが割り当てられ、`mac_policy_list` のスロットを占有します。  
  - 後で MAC フックが呼び出されると（たとえば vnode アクセスや exec など）、MACF は登録済みのすべてのポリシーを反復し、総合的な判断を下します。

- 特に、**AMFI**（Apple Mobile File Integrity）はこのような security extension の 1 つです。その Info.plist には、セキュリティポリシーであることを示す `AppleSecurityExtension` が含まれています。  
- カーネルの起動処理では、多くのサブシステムが依存する前に「security policy」（AMFI など）がすでに有効になっているよう、読み込み処理が行われます。たとえば、カーネルは「AppleMobileFileIntegrity（AMFI）、Sandbox、Quarantine policy を含むセキュリティポリシーを読み込むことで、後続のタスクに備えます」。 

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

MAC frameworkを使用するkext（つまり、`mac_policy_register()`などを呼び出すもの）を作成する場合、kextリンカー（kxld）がシンボルを解決できるよう、KPI（Kernel Programming Interfaces）への依存関係を宣言する必要があります。そのため、kextがMACFに依存することを宣言するには、`Info.plist`で`com.apple.kpi.dsep`を指定します（`find . Info.plist | grep AppleSecurityExtension`）。すると、kextは`mac_policy_register`、`mac_policy_unregister`、MAC hook関数ポインターなどのシンボルを参照します。これらを解決するには、依存関係として`com.apple.kpi.dsep`を列挙する必要があります。

Info.plistの例（.kext内）：

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



## 現代の macOS リリースにおける MACF

現代の macOS では、Apple のセキュリティポリシーを、独立した緩い `.kext` バンドルとして捉えるのは一般に適切ではありません。**macOS 11** 以降、kernel extension は**カーネルコレクション**にリンクされます。**Apple Silicon** には独立した **SystemKC** がなく、サードパーティ製 kext は **Auxiliary Kernel Collection (AuxKC)** に組み込まれ、再起動して初めてロード可能になります。MACF の調査では、**Sandbox**、**AMFI**、**AppleSystemPolicy**、**CoreTrust**、**Quarantine** などの組み込みポリシーは、`kextstat` などの非推奨ツールよりも、通常 `kmutil` を使って列挙する方が簡単です。

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Apple Siliconでは、セキュリティkextがBootKCに含まれていない場合は、次にAuxKCを確認してください。通常、`/System/Library/Extensions`の下で単独のバンドルを探し回るよりも有効です。

## MACFのコールアウト

MACFへのコールアウトは、**`#if CONFIG_MAC`** の条件ブロック内に定義されていることがよくあります。また、こうしたブロック内では、特定のアクションを実行する権限を**確認する**ためにMACFを呼び出す`mac_proc_check*`の呼び出しが見つかることがあります。MACFコールアウトの形式は、**`mac_<object>_<opType>_opName`** です。

`object`には、次のいずれかが指定されます: `bpfdesc`、`cred`、`file`、`proc`、`vnode`、`mount`、`devfs`、`ifnet`、`inpcb`、`mbuf`、`ipq`、`pipe`、`sysv[msg/msq/shm/sem]`、`posix[shm/sem]`、`socket`、`kext`。\
`opType`には通常、アクションを許可または拒否するために使われる`check`が指定されます。ただし、kextが指定されたアクションに反応できるようにする`notify`が見つかることもあります。

[https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621)に例があります。

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

次に、[https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)で`mac_file_check_mmap`のコードを確認できます。

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

これは登録済みのポリシーを順に確認し、その結果を `mac_error_select()` で統合します。後続のチェックが 0 を返しても、それ以前の拒否を覆すことはできません。複数のポリシーが拒否した場合、関数は優先順位に基づいてエラーを選択します（たとえば、`EPERM` より `EACCES` が優先されます）。<sup>[[2]](#references)</sup>

> [!TIP]
> ただし、すべての MACF callout がアクションを拒否するためだけに使われるわけではないことに注意してください。たとえば、`mac_priv_grant` はマクロ [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) を呼び出します。このマクロは、いずれかのポリシーが 0 を返した場合、要求された権限を付与します。
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

これらの呼び出しは、[**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h)で定義されている多数の**権限**を確認・付与するためのものです。\
一部のカーネルコードは、プロセスのKAuth credentialsと権限コードの1つを指定して、[**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c)の`priv_check_cred()`を呼び出します。この関数は`mac_priv_check`を呼び出して、権限の付与を**拒否**するポリシーがあるかどうかを確認し、その後`mac_priv_grant`を呼び出して、`privilege`を付与するポリシーがあるかどうかを確認します。<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

このhookを使うと、すべてのシステムコールを傍受できます。`bsd/dev/[i386|arm]/systemcalls.c`では、次のコードを含む宣言済み関数[`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25)を確認できます。

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

呼び出し元プロセスの**ビットマスク**を確認し、現在の syscall で `mac_proc_check_syscall_unix` を呼び出す必要があるかを判定します。syscall は非常に頻繁に呼び出されるため、毎回 `mac_proc_check_syscall_unix` を呼び出さないようにすることが重要です。

プロセス内の syscall のビットマスクを設定する関数 `proc_set_syscall_filter_mask()` は、Sandbox がサンドボックス化されたプロセスにマスクを設定するために呼び出す点に注意してください。

## 公開されている MACF syscall

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) で定義されている一部の syscall を通じて、MACF とやり取りできます。

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

攻撃側のリバースエンジニアリングでは、**`__mac_syscall`** は今でも userland の最適な chokepoint の一つです。ここでは、**policy name**（たとえば `"Sandbox"` や `"AMFI"`）、**policy 固有の selector/code**、そして `mpo_policy_syscall` が処理する **opaque argument blob** へのポインターが渡されます。まず userland から未公開の操作をリバースし、その後で kernel の実装を調べる場合に非常に役立ちます。Sandbox は一般に `__sandbox_ms` 経由でここに到達し、AMFI も dyld の policy 判定に同じ仕組みを使います。<sup>[[2]](#references)[[5]](#references)</sup>

## 実践的な攻撃側の調査メモ

最近の macOS のバグは、MACF を直接「破る」ことはほとんどありません。代わりに、**MACF / Sandbox / TCC の判定と、その後に行われる特権操作との間の非同期化**を悪用することがよくあります。

### MACF 入力としての policy 固有 spawn 属性

`posix_spawnattr_setmacpolicyinfo_np()` は、policy name と opaque bytes を `posix_spawn()` のリクエストに付加します。XNU は、登録済み各 policy の `mpc_name` を使って対応する bytes を検索し、その policy の exec-label hook に渡します。launch-constraints hook も同じ bytes を読み取ります。これは `__mac_syscall` とは別の、攻撃者が制御できる MACF 入力経路です。その policy が bytes を *追加の制限* として扱うのか、それとも親プロセスや実行ファイルの既存 policy を置き換えられるのかを確認してください。<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

管理されたテストでは、制限のある親プロセスから、policy 固有の属性を付けない場合と付ける場合の両方で同じ子プロセスを spawn します。親プロセスが利用できないリソースに対する子プロセスの実効アクセスを比較してください。spawn が成功しただけでは、境界を越えたことの証明にはなりません。<sup>[[12]](#references)[[13]](#references)</sup>

policy をリバースする際は、`mpo_cred_label_update_execve` と `mpo_proc_check_launch_constraints` を追跡し、呼び出し元が属性を指定できるか確認してください。<sup>[[10]](#references)[[11]](#references)</sup> AMFI は過去に、組み込みの launch constraints ではなく指定された launch constraints を受け入れていました。Sandbox は、親プロセスの制限を維持する代わりに、名前付きの組み込み profile を子プロセスに適用できました。<sup>[[13]](#references)[[12]](#references)</sup> どちらの動作も修正済みなので、現在のシステムでも同じだと決めつけないでください。<sup>[[13]](#references)[[12]](#references)</sup>

AMFI の事例については [launch-constraints の分析](macos-launch-environment-constraints.md)を、子プロセスの実効 policy のテストについては [Sandbox のデバッグ](macos-sandbox/macos-sandbox-debug-and-bypass/)を参照してください。

### Broker のパスチェックと実際の特権操作

よくあるパターンは、特権 daemon が **userland で事前チェック**（たとえば `sandbox_check_by_audit_token()`）を行う際にはあるバージョンのパスを使い、その後、実際の特権処理では**異なる、または正規化されていない、攻撃者制御のパス**を使うことです。最近の `diskarbitrationd` / `storagekitd` の調査は好例です。**directory traversal** と **symlink の差し替え**により、攻撃者は daemon の sandbox 検証を通過した後、`~/Library/Application Support/com.apple.TCC` などの機密性の高い場所に mount できます。これにより、選んだ mount point に応じて、バグが **sandbox escape**、**local privilege escalation**、または **TCC bypass** につながります。<sup>[[6]](#references)</sup>

sandbox から到達可能な root broker を監査する場合は、まず次を grep してください。

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, パス正規化 helper
- `mount`, `rename`, `copyfile`、helper-tool の XPC method、または後から root 権限で攻撃者制御のパスにアクセスするものなどの特権処理

### private entitlement を持つ信頼された代理プロセス

もう一つの実践的なパターンは、MACF hook を直接攻撃せず、境界を越えるのに必要な権限をすでに持つ **trusted process** を悪用することです。最近の Safari/TCC の調査が好例です。重要な手法は「kernel で TCC を無効化する」ことではなく、ローカルの policy/configuration を変更し、**`com.apple.private.tcc.allow`** を持つ Apple 署名済みプロセスに、機密操作を代わりに実行させることでした。<sup>[[8]](#references)</sup> 実際には、次の要素を組み合わせて持つ Apple daemon/app が、優先度の高い監査対象です。

- **private entitlement** または FDA に似たアクセス範囲
- 書き込み可能な config / database / mount point / policy file
- **Sandbox**、**AMFI**、**TCC**、または別の MACF policy によって制御される、その後の機密操作

製品ごとの詳細なリバースについては、[macOS Sandbox](macos-sandbox/README.md) と [macOS TCC](macos-tcc/README.md) の専用ページを参照してください。



## References

- [1] [XNU — `security/mac_policy.h`（MACF policy operations vector の全体）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c`（`mac_policy_register`、`__mac_syscall`）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h`（`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` macro）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h`（`priv_check`/`priv_grant` で使われる privilege code）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall（Offensive Security）](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Apple の脆弱性を発見する: diskarbitrationd と storagekitd の監査 Part 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference tool](https://newosxbook.com/xxr/index.php)
- [8] [新たな macOS の脆弱性「HM Surf」で不正なデータアクセスが可能に（Microsoft Security Blog）](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — posix_spawn policy 属性 setter](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — policy 固有の exec-label 属性の dispatch](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — launch-constraints policy の dispatch](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [実行ファイルを spawn して Apple Sandbox から脱出する](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [macOS の Launch Constraints を回避する](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}

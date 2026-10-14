# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

MIGは、**Mach IPC**コードの作成プロセスを**簡素化する**ために開発されました。定義に基づいて、サーバーとクライアントが通信するために必要なコードを**生成します**。生成されるコードが読みにくくても、開発者はそれをインポートするだけでよく、コードは以前よりはるかにシンプルになります。<sup>[[1]](#references)</sup>

定義は、`.defs`拡張子を使用するInterface Definition Language（IDL）で指定します。

これらの定義は5つのセクションで構成されます。

- **サブシステム宣言**: `subsystem`キーワードで**名前**と**ID**を指定します。サーバーをカーネル内で実行する場合は、**`KernelServer`**として指定することもできます。<sup>[[4]](#references)</sup>
- **インクルードとインポート**: MIGはCプリプロセッサを使用するため、インポートを利用できます。また、ユーザーまたはサーバー向けの生成コードには`uimport`と`simport`を使用できます。
- **型宣言**: データ型を定義できますが、通常は`mach_types.defs`と`std_types.defs`をインポートします。独自の型を定義する場合は、次の構文を使用できます。
  - \[i`n/out]tran`: 入力メッセージから、または出力メッセージへ変換する必要がある関数
  - `c[user/server]type`: 別のC型へのマッピング。
  - `destructor`: 型が解放されるときにこの関数を呼び出します。
- **操作**: RPCメソッドの定義です。次の5種類があります。
  - `routine`: 返信を要求する
  - `simpleroutine`: 返信を要求しない
  - `procedure`: 返信を要求する
  - `simpleprocedure`: 返信を要求しない
  - `function`: 返信を要求する

### 例

この場合は非常にシンプルな関数を含む定義ファイルを作成します。

```cpp:myipc.defs
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
    server_port :  mach_port_t;
    n1          :  uint32_t;
    n2          :  uint32_t);
```

最初の**引数はバインドするポート**であり、MIGは（クライアントコードで`mig_get_reply_port()`を呼び出さない限り）**返信ポートを自動的に処理する**ことに注意してください。また、**操作のID**は、指定されたサブシステムIDから始まる連番になります（操作が非推奨になった場合は削除し、そのIDを維持するために`skip`を使用します）。

次にMIGを使って、互いに通信してSubtract関数を呼び出せるサーバーコードとクライアントコードを生成します。

```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```

いくつかの新しいファイルが現在のディレクトリに作成されます。

> [!TIP]
> システム内でより複雑な例を見つけるには、次を実行します: `mdfind mach_port.defs`\
> ファイルと同じフォルダから次のコマンドでコンパイルできます: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

**`myipcServer.c`** と **`myipcServer.h`** には、構造体 **`SERVERPREFmyipc_subsystem`** の宣言と定義があります。この構造体は基本的に、受信したメッセージ ID に基づいて呼び出す関数を定義しています（開始番号は 500 に指定しました）。

{{#tabs}}
{{#tab name="myipcServer.c"}}

```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
	myipc_server_routine,
	500, // start ID
	501, // end ID
	(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
	(vm_address_t)0,
	{
          { (mig_impl_routine_t) 0,
          // Function to call
          (mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
	}
};
```

{{#endtab}}

{{#tab name="myipcServer.h"}}

```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
	mig_server_routine_t	server;	/* Server routine */
	mach_msg_id_t	start;	/* Min routine number */
	mach_msg_id_t	end;	/* Max routine number + 1 */
	unsigned int	maxsize;	/* Max msg size */
	vm_address_t	reserved;	/* Reserved */
	struct routine_descriptor	/* Array of routine descriptors */
		routine[1];
} SERVERPREFmyipc_subsystem;
```

{{#endtab}}
{{#endtabs}}

前述の struct に基づき、関数 **`myipc_server_routine`** は **message ID** を受け取り、呼び出す適切な関数を返します。

```c
mig_external mig_routine_t myipc_server_routine
	(mach_msg_header_t *InHeadP)
{
	int msgh_id;

	msgh_id = InHeadP->msgh_id - 500;

	if ((msgh_id > 0) || (msgh_id < 0))
		return 0;

	return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```

この例では definitions 内に 1 つの関数しか定義していませんが、さらに関数を定義していた場合、それらは **`SERVERPREFmyipc_subsystem`** の配列内に入り、最初の関数には ID **500**、2 番目の関数には ID **501** が割り当てられていたでしょう...

関数が **reply** を返すことを想定している場合、関数 `mig_internal kern_return_t __MIG_check__Reply__<name>` も存在します。

実際、この対応関係は **`myipcServer.h`** の struct **`subsystem_to_name_map_myipc`**（他のファイルでは **`subsystem*to_name_map*\***`）で確認できます。

```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
    { "Subtract", 500 }
#endif
```

最後に、サーバーを動作させるためのもう1つの重要な関数が **`myipc_server`** です。この関数は、受信した ID に関連付けられた関数を実際に **呼び出します**:<sup>[[3]](#references)</sup>

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
	(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
	/*
	 * typedef struct {
	 * 	mach_msg_header_t Head;
	 * 	NDR_record_t NDR;
	 * 	kern_return_t RetCode;
	 * } mig_reply_error_t;
	 */

	mig_routine_t routine;

	OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
	OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
	/* Minimal size: routine() will update it if different */
	OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
	OutHeadP->msgh_local_port = MACH_PORT_NULL;
	OutHeadP->msgh_id = InHeadP->msgh_id + 100;
	OutHeadP->msgh_reserved = 0;

	if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id < 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
		((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
		return FALSE;
	}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

呼び出す関数を ID で取得している、前述の強調表示された行を確認してください。

以下は、クライアントからサーバーの Subtract 関数を呼び出せる、シンプルな **サーバー** と **クライアント** を作成するコードです。

{{#tabs}}
{{#tab name="myipc_server.c"}}

```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
    printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
    return KERN_SUCCESS;
}

int main() {

    mach_port_t port;
    kern_return_t kr;

    // Register the mach service
    kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
    if (kr != KERN_SUCCESS) {
        printf("bootstrap_check_in() failed with code 0x%x\n", kr);
        return 1;
    }

    // myipc_server is the function that handles incoming messages (check previous exlpanation)
    mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```

{{#endtab}}

{{#tab name="myipc_client.c"}}

```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

    // Lookup the receiver port using the bootstrap server.
    mach_port_t port;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
    if (kr != KERN_SUCCESS) {
        printf("bootstrap_look_up() failed with code 0x%x\n", kr);
        return 1;
    }
    printf("Port right name %d\n", port);
    USERPREFSubtract(port, 40, 2);
}
```

{{#endtab}}
{{#endtabs}}

### The NDR_record

NDR_record は `libsystem_kernel.dylib` によってエクスポートされる構造体で、MIG が**データをシステムに依存しない形式に変換する**ために使用します。MIG は同一マシン内だけでなく、異なるシステム間で使用されることを想定して設計されているためです。

興味深いことに、バイナリの依存関係として `_NDR_record` が見つかった場合（`jtool2 -S <binary> | grep NDR` または `nm`）、そのバイナリは MIG client または Server であることを意味します。

さらに、**MIG servers** は `__DATA.__const`（macOS kernel では `__CONST.__constdata`、その他の \*OS kernels では `__DATA_CONST.__const`）にディスパッチテーブルを持っています。これは **`jtool2`** でダンプできます。

また、**MIG clients** は `__NDR_record` を使い、`__mach_msg` で servers にメッセージを送信します。

## バイナリ解析

### jtool

現在、多くのバイナリが MIG を使って mach ports を公開しているため、**MIG が使われているかを特定する方法**と、各メッセージ ID で **MIG が実行する関数**を把握しておくと便利です。

[**jtool2 / disarm**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#disarm-old-jtool2) は Mach-O バイナリから MIG 情報を解析し、メッセージ ID を示すとともに、実行する関数を特定できます。

```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```

さらに、MIG関数は実際に呼び出される関数のラッパーです。そのため、逆アセンブル結果を取得して `BL` を検索すれば、実際に呼び出される関数を特定できる場合があります。

```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```

### Assembly

受信したメッセージ ID に応じて**適切な関数を呼び出す**関数は `myipc_server` だと前述しました。しかし通常、バイナリのシンボル（関数名）は得られないため、**逆コンパイルするとどのように見えるか**を確認しておくと役立ちます（この関数のコードは公開される関数に依存しないため、常によく似たものになります）。

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
    var_10 = arg0;
    var_18 = arg1;
    // Initial instructions to find the proper function ponters
    *(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
    *(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
    *(int32_t *)(var_18 + 0x4) = 0x24;
    *(int32_t *)(var_18 + 0xc) = 0x0;
    *(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
    *(int32_t *)(var_18 + 0x10) = 0x0;
    if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
            rax = *(int32_t *)(var_10 + 0x14);
            // Call to sign_extend_64 that can help to identifyf this function
            // This stores in rax the pointer to the call that needs to be called
            // Check the used of the address 0x100004040 (functions addresses array)
            // 0x1f4 = 500 (the starting ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
            // If - else, the if returns false, while the else call the correct function and returns true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
                    *(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
                    var_4 = 0x0;
            }
            else {
                    // Calculated address that calls the proper function with 2 arguments
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
            }
    }
    else {
            *(var_18 + 0x18) = **_NDR_record;
            *(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
            var_4 = 0x0;
    }
    rax = var_4;
    return rax;
}
</code></pre>

{{#endtab}}

{{#tab name="myipc_server decompiled 2"}}
こちらは別の無料版 Hopper で逆コンパイルした同じ関数です。

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
    r31 = r31 - 0x40;
    saved_fp = r29;
    stack[-8] = r30;
    var_10 = arg0;
    var_18 = arg1;
    // Initial instructions to find the proper function ponters
    *(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f | 0x0;
    *(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
    *(int32_t *)(var_18 + 0x4) = 0x24;
    *(int32_t *)(var_18 + 0xc) = 0x0;
    *(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
    *(int32_t *)(var_18 + 0x10) = 0x0;
    r8 = *(int32_t *)(var_10 + 0x14);
    r8 = r8 - 0x1f4;
    if (r8 > 0x0) {
            if (CPU_FLAGS & G) {
                    r8 = 0x1;
            }
    }
    if ((r8 & 0x1) == 0x0) {
            r8 = *(int32_t *)(var_10 + 0x14);
            r8 = r8 - 0x1f4;
            if (r8 < 0x0) {
                    if (CPU_FLAGS & L) {
                            r8 = 0x1;
                    }
            }
            if ((r8 & 0x1) == 0x0) {
                    r8 = *(int32_t *)(var_10 + 0x14);
                    // 0x1f4 = 500 (the starting ID)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
                    r8 = *(r8 + 0x8);
                    var_20 = r8;
                    r8 = r8 - 0x0;
                    if (r8 != 0x0) {
                            if (CPU_FLAGS & NE) {
                                    r8 = 0x1;
                            }
                    }
                    // Same if else as in the previous version
                    // Check the used of the address 0x100004040 (functions addresses array)
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
                            var_4 = 0x0;
                    }
                    else {
                            // Call to the calculated address where the function should be
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
                    }
            }
            else {
                    *(var_18 + 0x18) = **0x100004000;
                    *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
                    var_4 = 0x0;
            }
    }
    else {
            *(var_18 + 0x18) = **0x100004000;
            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
            var_4 = 0x0;
    }
    r0 = var_4;
    return r0;
}

</code></pre>

{{#endtab}}
{{#endtabs}}

実際に関数 **`0x100004000`** を確認すると、**`routine_descriptor`** 構造体の配列が見つかります。構造体の最初の要素は**関数**が実装されている**アドレス**で、構造体のサイズは **0x28 バイト**です。そのため、0 バイト目から 0x28 バイトごとに 8 バイトを読み取れば、呼び出される**関数のアドレス**を取得できます。

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

このデータは[**この Hopper スクリプトを使って**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py)抽出できます。

ステートフルな MIG メッセージシーケンスをシードして fuzz するワークフローについては、[Stateful Mach IPC fuzzing](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#stateful-mach-ipc-fuzzing)を参照してください。

### Debug

MIG が生成するコードは、操作の開始時と終了時にログを生成するため `kernel_debug` も呼び出します。ログは **`trace`** または **`kdv`** を使って確認できます: `kdv all | grep MIG`



## References

- [1] [bootstrap_cmds — `migcom.tproj`（MIG コンパイラ自体）](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs`（MIG サブシステム定義の例）](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h`（Mach メッセージヘッダーのレイアウト）](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs`（task サブシステムの MIG 定義）](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}

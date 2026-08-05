# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

MIG は **Mach IPC** コード作成のプロセスを**簡略化**するために作られました。基本的には、指定された定義に基づいて、server と client が通信するために必要なコードを**生成**します。生成されたコードが扱いにくいものであっても、開発者はそれを import するだけでよく、コードは以前よりはるかにシンプルになります。

定義は、`.defs` 拡張子を使用する Interface Definition Language（IDL）で指定します。

これらの定義には 5 つのセクションがあります。

- **Subsystem declaration**: `subsystem` キーワードを使用して **name** と **id** を指定します。server を kernel で実行する場合は、**`KernelServer`** として指定することもできます。
- **Inclusions and imports**: MIG は C-prepocessor を使用するため、import を利用できます。さらに、user または server が生成するコード用に `uimport` と `simport` を使用できます。
- **Type declarations**: data type を定義できますが、通常は `mach_types.defs` と `std_types.defs` を import します。custom type には、次の構文を使用できます。
- \[i`n/out]tran`: incoming message から、または outgoing message へ変換する必要がある Function
- `c[user/server]type`: 別の C type への Mapping。
- `destructor`: type が解放されたときに、この Function を呼び出します。
- **Operations**: RPC methods の定義です。5 種類あります。
- `routine`: reply を返す
- `simpleroutine`: reply を返さない
- `procedure`: reply を返す
- `simpleprocedure`: reply を返さない
- `function`: reply を返す

### 例

この例では、非常にシンプルな Function を含む definition file を作成します。
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
最初の **argument は bind する port** であり、MIG は **reply port を自動的に処理**することに注意してください（クライアントコードで `mig_get_reply_port()` を呼び出す場合を除く）。さらに、**operations の ID** は、指定された subsystem ID から始まる **連番**になります（そのため、ある operation が deprecated になった場合は削除され、`skip` を使用してその ID を引き続き使用します）。

ここで MIG を使用して、相互に通信し、Subtract function を呼び出せる server code と client code を生成します。
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
現在のディレクトリに複数の新しいファイルが作成されます。

> [!TIP]
> システム内で、より複雑な例を `mdfind mach_port.defs` で確認できます。\
> また、ファイルと同じフォルダーから `mig -DLIBSYSCALL_INTERFACE mach_ports.defs` を実行してコンパイルできます。

**`myipcServer.c`** および **`myipcServer.h`** では、**`SERVERPREFmyipc_subsystem`** 構造体の宣言と定義を確認できます。この構造体は基本的に、受信したメッセージ ID に基づいて呼び出す関数を定義します（開始番号として 500 を指定しました）。

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

前の struct に基づき、関数 **`myipc_server_routine`** は **message ID** を取得し、呼び出す適切な関数を返します:
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
この例では definitions 内に 1 つの function だけを定義していますが、複数の function を定義していた場合、それらは **`SERVERPREFmyipc_subsystem`** の array 内に格納され、最初の function には ID **500**、2 番目の function には ID **501** が割り当てられます...

function が **reply** を送信することを想定されていた場合、`mig_internal kern_return_t __MIG_check__Reply__<name>` という function も存在します。

実際には、**`myipcServer.h`** の struct **`subsystem_to_name_map_myipc`**（他のファイルでは **`subsystem*to_name_map*\***`）から、この関係を特定できます。
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
最後に、サーバーを動作させるためのもう1つの重要な関数が **`myipc_server`** です。この関数が、受信した id に関連付けられた **function を実際に呼び出します**。

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

先ほど強調表示した、ID によって呼び出す function にアクセスしている行を確認してください。

以下は、クライアントがサーバーから Subtract functions を呼び出せる、シンプルな **server** と **client** を作成するコードです。

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

NDR_record は `libsystem_kernel.dylib` によって export される struct であり、MIG が使用されるシステムに依存せずに **data を変換**できるようにします。MIG は同一マシン内だけでなく、異なるシステム間で使用されることを想定して設計されました。

これは、バイナリ内で `_NDR_record` が dependency として見つかった場合（`jtool2 -S <binary> | grep NDR` または `nm`）、そのバイナリが MIG client または Server であることを意味するため興味深い点です。

さらに、**MIG servers** は `__DATA.__const`（macOS kernel では `__CONST.__constdata`、その他の \*OS kernels では `__DATA_CONST.__const`）に dispatch table を持ちます。これは **`jtool2`** で dump できます。

また、**MIG clients** は `__NDR_record` を使用して、`__mach_msg` とともに servers へ送信します。

## バイナリ解析

### jtool

現在、多くのバイナリが mach ports を expose するために MIG を使用しているため、**MIG が使用されていること**と、各 message ID で MIG が実行する **functions** を特定する方法を知っておくと有用です。

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) は Mach-O binary から MIG information を parse し、message ID を示すとともに、実行する function を特定できます:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
さらに、MIG functionsは実際に呼び出される関数の単なるwrappersであるため、そのdisassemblyを取得してBLをgrepすれば、実際に呼び出されている関数を見つけられる可能性があります。
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### アセンブリ

前述のとおり、**受信したメッセージ ID に応じて正しい関数を呼び出す**役割を担う関数は `myipc_server` です。しかし通常、バイナリのシンボル（関数名）は存在しないため、**逆コンパイルするとどのように見えるか**を確認することは有用です。この関数のコードは公開されている関数から独立しているため、常に非常によく似たものになります。

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
// 0x1f4 = 500 (the strating ID)
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
これは、別の Hopper free version で逆コンパイルした同じ関数です。

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
// 0x1f4 = 500 (the strating ID)
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

実際に **`0x100004000`** の関数へ移動すると、**`routine_descriptor`** 構造体の配列を確認できます。構造体の最初の要素は **関数**が実装されている**アドレス**であり、**構造体のサイズは 0x28 bytes** です。そのため、byte 0 から開始して 0x28 bytes ごとに 8 bytes を取得すると、呼び出される**関数のアドレス**になります。

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

このデータは[**この Hopper script を使用して**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py)抽出できます。

### デバッグ

MIG によって生成されたコードは、entry と exit での操作に関するログを生成するために `kernel_debug` も呼び出します。これらは **`trace`** または **`kdv`** を使用して確認できます: `kdv all | grep MIG`

## 参考資料

- [1] [bootstrap_cmds — `migcom.tproj` (the MIG compiler itself)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (example MIG subsystem definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/task.defs` (task subsystem MIG definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [4] [XNU — `osfmk/mach/message.h` (Mach message header layout)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)

{{#include ../../../../banners/hacktricks-training.md}}

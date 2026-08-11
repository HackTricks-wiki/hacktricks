# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

MIGは、**Mach IPC** codeの作成プロセスを**簡略化する**ために作られました。基本的には、指定された定義を使用してserverとclientが通信するために必要なcodeを**生成します**。生成されたcodeが見づらいものであっても、developerはそれをimportするだけでよく、codeは以前よりはるかにシンプルになります。<sup>[[1]](#references)</sup>

定義は、`.defs`拡張子を使用したInterface Definition Language (IDL)で指定します。

これらの定義には5つのセクションがあります。

- **Subsystem declaration**: `subsystem` keywordは、**name**と**id**を示すために使用されます。serverをkernelで実行する場合は、**`KernelServer`**としてマークすることもできます。<sup>[[4]](#references)</sup>
- **Inclusions and imports**: MIGはC-prepocessorを使用するため、importsを使用できます。さらに、userまたはserverが生成するcode向けに`uimport`と`simport`を使用できます。
- **Type declarations**: data typesを定義することもできますが、通常は`mach_types.defs`と`std_types.defs`をimportします。custom typeには、次のsyntaxを使用できます。
- \[i`n/out]tran`: incoming messageから、またはoutgoing messageへ変換する必要があるFunction
- `c[user/server]type`: 別のC typeへのMapping。
- `destructor`: typeがreleaseされたときにこのfunctionをCallします。
- **Operations**: RPC methodsの定義です。5種類あります。
- `routine`: replyをExpectする
- `simpleroutine`: replyをExpectしない
- `procedure`: replyをExpectする
- `simpleprocedure`: replyをExpectしない
- `function`: replyをExpectする

### Example

この場合は非常に単純なfunctionを含むdefinition fileをCreateします。
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
最初の **argument は bind する port** であり、MIG は **reply port を自動的に処理します**（client code で `mig_get_reply_port()` を呼び出す場合を除く）。さらに、**operations の ID** は、指定された subsystem ID から始まる **連番** になります（そのため、operation が deprecated になると削除され、ID を引き続き使用するために `skip` が使われます）。

次に、MIG を使用して、相互に通信して Subtract function を呼び出せる server code と client code を生成します。
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
現在のディレクトリに複数の新しいファイルが作成されます。

> [!TIP]
> システム上で、より複雑な例を次のコマンドで確認できます: `mdfind mach_port.defs`\
> ファイルと同じフォルダーから次のコマンドでコンパイルできます: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

**`myipcServer.c`** と **`myipcServer.h`** のファイルには、**`SERVERPREFmyipc_subsystem`** 構造体の宣言と定義があります。この構造体は基本的に、受信したメッセージ ID に基づいて呼び出す関数を定義します（開始番号として 500 を指定しました）。

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

前述の struct に基づき、関数 **`myipc_server_routine`** は **message ID** を取得し、呼び出すべき適切な関数を返します：
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
この例では definitions 内に 1 つの function だけを定義していますが、複数の function を定義した場合、それらは **`SERVERPREFmyipc_subsystem`** の array 内に格納され、最初の function には ID **500**、2 番目の function には ID **501** が割り当てられます...

function が **reply** を送信すると想定されていた場合、function `mig_internal kern_return_t __MIG_check__Reply__<name>` も存在します。

実際には、**`myipcServer.h`** にある struct **`subsystem_to_name_map_myipc`**（他のファイルでは **`subsystem*to_name_map*\***`）で、この関係を特定できます：
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
最後に、server を動作させるためのもう1つの重要な function が **`myipc_server`** です。これは、受信した id に関連付けられた **function を実際に呼び出す**ものです:<sup>[[3]](#references)</sup>

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

先ほど強調した、id によって呼び出す function にアクセスしている行を確認してください。

以下は、client が server の Subtract function を呼び出せる、シンプルな **server** と **client** を作成するための code です。

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

NDR_recordは`libsystem_kernel.dylib`によってexportされており、MIGが異なるシステム間で使用されることを想定して設計されたため、**システムに依存しないようにデータを変換**するためのstructです（同一マシン内だけで使用されるものではありません）。

これは興味深い点です。バイナリ内で`_NDR_record`がdependencyとして見つかった場合（`jtool2 -S <binary> | grep NDR`または`nm`）、そのバイナリがMIG clientまたはMIG Serverであることを意味します。

さらに、**MIG servers**は`__DATA.__const`（macOS kernelでは`__CONST.__constdata`、その他の\*OS kernelsでは`__DATA_CONST.__const`）にdispatch tableを持っています。これは**`jtool2`**でdumpできます。

また、**MIG clients**は`__NDR_record`を使用し、`__mach_msg`とともにserversへ送信します。

## Binary Analysis

### jtool

現在、多くのバイナリがmach portsを公開するためにMIGを使用しているため、**MIGが使用されていること**と、各message IDでMIGが実行する**functions**を特定する方法を知っておくことは有用です。

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2)はMach-O binaryからMIG informationをparseし、message IDを示すとともに、実行するfunctionを特定できます。
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
さらに、MIG functionsは実際に呼び出される関数のwrapperです。そのため、disassemblyを取得して`BL`を検索することで、実際に呼び出されている関数を見つけられる場合があります。
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

前述のとおり、**受信した message ID に応じて正しい function を呼び出す**役割を担う function は `myipc_server` でした。ただし通常、binary の symbols（function names）は存在しないため、**decompiled でどのように見えるかを確認する**ことが重要です。この function の code は exposed される functions から独立しているため、常に非常によく似た形になります。

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
これは、別の Hopper free version で decompiled した同じ function です。

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

実際に **`0x100004000`** の function に移動すると、**`routine_descriptor`** structs の array が見つかります。この struct の最初の element は **function** が実装されている **address** であり、**struct は 0x28 bytes** なので、byte 0 から開始して 0x28 bytes ごとに 8 bytes を取得すると、呼び出される **function の address** になります。

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

この data は[**この Hopper script を使用して**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py)抽出できます。

### Debug

MIG によって生成された code は、entry と exit での操作に関する logs を生成するために `kernel_debug` も呼び出します。これらは **`trace`** または **`kdv`** を使用して確認できます: `kdv all | grep MIG`

## References

- [1] [bootstrap_cmds — `migcom.tproj` (MIG compiler 自体)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (MIG subsystem definition の例)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (Mach message header layout)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (task subsystem の MIG definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}

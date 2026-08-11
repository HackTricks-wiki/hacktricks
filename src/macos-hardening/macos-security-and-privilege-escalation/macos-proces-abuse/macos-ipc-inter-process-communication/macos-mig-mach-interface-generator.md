# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## 기본 정보

MIG는 **Mach IPC** 코드 생성 프로세스를 **간소화**하기 위해 만들어졌습니다. 기본적으로 주어진 definition을 기반으로 server와 client가 통신하는 데 필요한 코드를 **생성**합니다. 생성된 코드가 보기 좋지 않더라도, 개발자는 이를 import하기만 하면 되므로 기존보다 훨씬 간단한 코드를 작성할 수 있습니다.<sup>[[1]](#references)</sup>

definition은 `.defs` 확장자를 사용하여 Interface Definition Language (IDL)로 지정합니다.

이 definition에는 5개의 섹션이 있습니다.

- **Subsystem declaration**: `subsystem` 키워드는 **name**과 **id**를 지정하는 데 사용됩니다. server가 kernel에서 실행되어야 하는 경우 **`KernelServer`**로 표시할 수도 있습니다.<sup>[[4]](#references)</sup>
- **Inclusions and imports**: MIG는 C-preprocessor를 사용하므로 import를 사용할 수 있습니다. 또한 user 또는 server generated code에 `uimport`와 `simport`를 사용할 수 있습니다.
- **Type declarations**: data type을 정의할 수 있지만, 일반적으로 `mach_types.defs`와 `std_types.defs`를 import합니다. custom type에는 다음과 같은 syntax를 사용할 수 있습니다.
- \[i`n/out]tran`: incoming message에서 변환하거나 outgoing message로 변환해야 하는 Function
- `c[user/server]type`: 다른 C type으로의 mapping.
- `destructor`: type이 release될 때 이 function을 호출합니다.
- **Operations**: RPC method의 definition입니다. 5가지 type이 있습니다.
- `routine`: reply를 예상함
- `simpleroutine`: reply를 예상하지 않음
- `procedure`: reply를 예상함
- `simpleprocedure`: reply를 예상하지 않음
- `function`: reply를 예상함

### 예제

이 경우 매우 간단한 function을 포함하는 definition file을 생성합니다.
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
첫 번째 **argument는 bind할 port**이며, MIG는 **reply port를 자동으로 처리**합니다(client code에서 `mig_get_reply_port()`를 호출하는 경우는 제외). 또한 **operations의 ID는** 지정된 subsystem ID부터 **순차적으로** 할당됩니다(따라서 operation이 deprecated되면 삭제하고, 해당 ID를 계속 사용하기 위해 `skip`을 사용합니다).

이제 MIG를 사용하여 서로 통신하면서 Subtract 함수를 호출할 수 있는 server 및 client code를 생성합니다:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Several new files will be created in the current directory.

> [!TIP]
> 다음 명령을 사용하면 시스템에서 더 복잡한 예제를 찾을 수 있습니다: `mdfind mach_port.defs`\
> 또한 파일과 같은 폴더에서 다음 명령으로 컴파일할 수 있습니다: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

**`myipcServer.c`** 및 **`myipcServer.h`** 파일에서 **`SERVERPREFmyipc_subsystem`** struct의 declaration과 definition을 확인할 수 있습니다. 이 struct는 기본적으로 수신된 message ID에 따라 호출할 function을 정의합니다(시작 번호로 500을 지정했습니다):

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

이전 struct를 기반으로 **`myipc_server_routine`** 함수는 **message ID**를 가져와 호출할 적절한 함수를 반환합니다:
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
이 예제에서는 definitions에 1개의 function만 정의했지만, 더 많은 function을 정의했다면 **`SERVERPREFmyipc_subsystem`** 배열 안에 포함되며, 첫 번째 function에는 ID **500**, 두 번째 function에는 ID **501**이 할당되는 방식으로 계속 이어집니다...

function이 **reply**를 전송하도록 예상되었다면 `mig_internal kern_return_t __MIG_check__Reply__<name>` function도 존재합니다.

실제로 이 관계는 **`myipcServer.h`**의 struct **`subsystem_to_name_map_myipc`**에서 확인할 수 있습니다(다른 파일에서는 **`subsystem*to_name_map*\***`**):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
마지막으로, server가 작동하도록 하는 또 다른 중요한 function은 **`myipc_server`**입니다. 이 function은 수신된 id와 관련된 **function을 실제로 호출**합니다:<sup>[[3]](#references)</sup>

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

이전에 강조 표시된 줄에서 ID를 사용해 호출할 function에 접근하는 부분을 확인하세요.

다음은 간단한 **server**와 **client**를 생성하는 code입니다. 여기서 client는 server의 Subtract function을 호출할 수 있습니다.

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

NDR_record는 `libsystem_kernel.dylib`에서 export되며, MIG가 서로 다른 시스템 간에 사용될 것을 고려해 설계되었기 때문에(동일한 머신 내에서만 사용되는 것이 아님), MIG가 **데이터를 시스템에 종속되지 않는 형태로 변환**할 수 있도록 하는 struct입니다.

이는 흥미로운 점인데, 바이너리에서 `_NDR_record`가 dependency로 발견되면(`jtool2 -S <binary> | grep NDR` 또는 `nm`), 해당 바이너리가 MIG client 또는 Server라는 의미이기 때문입니다.

또한 **MIG servers**는 `__DATA.__const`(macOS kernel에서는 `__CONST.__constdata`, 다른 \*OS kernels에서는 `__DATA_CONST.__const`)에 dispatch table을 가지고 있습니다. 이는 **`jtool2`**로 dump할 수 있습니다.

그리고 **MIG clients**는 `__NDR_record`를 사용해 `__mach_msg`와 함께 servers로 전송합니다.

## Binary Analysis

### jtool

많은 바이너리가 현재 mach ports를 expose하는 데 MIG를 사용하므로, **MIG가 사용되었는지 식별하는 방법**과 각 message ID에 대해 MIG가 실행하는 **functions**를 파악하는 것이 유용합니다.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2)는 Mach-O binary에서 MIG 정보를 parse하여 message ID를 표시하고 실행할 function을 식별할 수 있습니다:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
또한 MIG 함수는 실제로 호출되는 함수 주위의 wrapper입니다. 따라서 disassembly를 확인하고 `BL`을 검색하면 실제로 호출되는 함수를 찾을 수 있습니다:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

앞서 **수신된 message ID에 따라 올바른 함수를 호출하는 역할**을 담당하는 함수가 `myipc_server`라고 설명했습니다. 하지만 일반적으로 binary의 symbols(함수 이름)는 존재하지 않으므로, **decompiled 상태에서 어떻게 보이는지** 확인하는 것이 중요합니다. 이 함수의 코드는 노출된 함수들과 독립적이므로 항상 매우 유사하게 나타납니다.

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
이는 다른 Hopper free 버전에서 decompiled된 동일한 함수입니다.

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
*(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>

{{#endtab}}
{{#endtabs}}

실제로 **`0x100004000`** 함수로 이동하면 **`routine_descriptor`** structs의 array를 확인할 수 있습니다. struct의 첫 번째 element는 **function**이 구현된 **address**이며, **struct는 0x28 bytes**를 차지합니다. 따라서 byte 0부터 시작해 0x28 bytes마다 8 bytes를 가져오면 호출될 **function의 address**를 얻을 수 있습니다.

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

이 data는 [**이 Hopper script를 사용하여**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) 추출할 수 있습니다.

### Debug

MIG가 생성한 code는 entry 및 exit 시 operation에 관한 logs를 생성하기 위해 `kernel_debug`도 호출합니다. 이러한 logs는 **`trace`** 또는 **`kdv`**를 사용하여 확인할 수 있습니다: `kdv all | grep MIG`

## References

- [1] [bootstrap_cmds — `migcom.tproj` (MIG compiler 자체)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (MIG subsystem definition 예시)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (Mach message header layout)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (task subsystem MIG definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}

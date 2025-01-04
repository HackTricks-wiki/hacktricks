# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

MIG는 **Mach IPC** 코드 생성을 단순화하기 위해 만들어졌습니다. 기본적으로 **서버와 클라이언트가 주어진 정의로 통신하기 위해 필요한 코드를 생성**합니다. 생성된 코드가 지저분하더라도 개발자는 이를 가져오기만 하면 그의 코드는 이전보다 훨씬 간단해질 것입니다.

정의는 `.defs` 확장자를 사용하여 인터페이스 정의 언어(IDL)로 지정됩니다.

이 정의는 5개의 섹션으로 구성됩니다:

- **서브시스템 선언**: 키워드 subsystem은 **이름**과 **id**를 나타내는 데 사용됩니다. 서버가 커널에서 실행되어야 하는 경우 **`KernelServer`**로 표시할 수도 있습니다.
- **포함 및 임포트**: MIG는 C 전처리기를 사용하므로 임포트를 사용할 수 있습니다. 또한, 사용자 또는 서버 생성 코드에 대해 `uimport` 및 `simport`를 사용할 수 있습니다.
- **타입 선언**: 데이터 타입을 정의할 수 있지만 일반적으로 `mach_types.defs` 및 `std_types.defs`를 가져옵니다. 사용자 정의 타입의 경우 일부 구문을 사용할 수 있습니다:
- \[i`n/out]tran`: 들어오는 메시지 또는 나가는 메시지로 변환해야 하는 함수
- `c[user/server]type`: 다른 C 타입에 매핑.
- `destructor`: 타입이 해제될 때 이 함수를 호출합니다.
- **작업**: 이는 RPC 메서드의 정의입니다. 5가지 유형이 있습니다:
- `routine`: 응답을 기대합니다
- `simpleroutine`: 응답을 기대하지 않습니다
- `procedure`: 응답을 기대합니다
- `simpleprocedure`: 응답을 기대하지 않습니다
- `function`: 응답을 기대합니다

### Example

정의 파일을 생성합니다. 이 경우 매우 간단한 함수를 사용합니다:
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
첫 번째 **인자는 바인딩할 포트**이며 MIG는 **응답 포트를 자동으로 처리**합니다(클라이언트 코드에서 `mig_get_reply_port()`를 호출하지 않는 한). 또한, **작업의 ID는** 지정된 서브시스템 ID부터 **순차적**으로 시작합니다(따라서 작업이 더 이상 사용되지 않는 경우 삭제되고 `skip`이 사용되어 여전히 해당 ID를 사용할 수 있습니다).

이제 MIG를 사용하여 서로 통신할 수 있는 서버 및 클라이언트 코드를 생성하여 Subtract 함수를 호출하십시오:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
여러 개의 새 파일이 현재 디렉토리에 생성됩니다.

> [!TIP]
> 시스템에서 더 복잡한 예제를 찾으려면: `mdfind mach_port.defs`\
> 그리고 파일과 동일한 폴더에서 컴파일하려면: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

파일 **`myipcServer.c`**와 **`myipcServer.h`**에서 수신된 메시지 ID에 따라 호출할 함수를 정의하는 구조체 **`SERVERPREFmyipc_subsystem`**의 선언 및 정의를 찾을 수 있습니다(시작 번호로 500을 지정했습니다):

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

이전 구조를 기반으로 함수 **`myipc_server_routine`**은 **메시지 ID**를 가져와 호출할 적절한 함수를 반환합니다:
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
이 예제에서는 정의에서 1개의 함수만 정의했지만, 더 많은 함수를 정의했다면 그것들은 **`SERVERPREFmyipc_subsystem`** 배열 안에 있었을 것이고, 첫 번째 함수는 ID **500**에, 두 번째 함수는 ID **501**에 할당되었을 것입니다...

함수가 **reply**를 보내는 것이 예상되었다면, 함수 `mig_internal kern_return_t __MIG_check__Reply__<name>`도 존재했을 것입니다.

실제로 이 관계는 **`myipcServer.h`**의 구조체 **`subsystem_to_name_map_myipc`**에서 확인할 수 있습니다 (**`subsystem*to_name_map*\***`\*\* 다른 파일에서도):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
마지막으로, 서버가 작동하기 위해 또 다른 중요한 기능은 **`myipc_server`**입니다. 이 기능은 실제로 수신된 ID와 관련된 **함수를 호출**합니다:

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
/* 최소 크기: routine()이 다르면 업데이트합니다 */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id &#x3C; 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

ID로 호출할 함수를 접근하는 이전에 강조된 줄을 확인하세요.

다음은 클라이언트가 서버에서 Subtract 함수를 호출할 수 있는 간단한 **서버** 및 **클라이언트**를 생성하는 코드입니다:

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

### NDR_record

NDR_record는 `libsystem_kernel.dylib`에 의해 내보내지며, MIG가 **시스템에 무관하게 데이터를 변환할 수 있도록** 하는 구조체입니다. MIG는 서로 다른 시스템 간에 사용되도록 설계되었기 때문에 (단지 같은 머신에서만이 아님) 흥미롭습니다.

이것은 `_NDR_record`가 이진 파일에서 의존성으로 발견되면 (`jtool2 -S <binary> | grep NDR` 또는 `nm`), 해당 이진 파일이 MIG 클라이언트 또는 서버임을 의미하기 때문에 흥미롭습니다.

게다가 **MIG 서버**는 `__DATA.__const` (macOS 커널의 경우 `__CONST.__constdata` 및 다른 \*OS 커널의 경우 `__DATA_CONST.__const`)에 디스패치 테이블을 가지고 있습니다. 이는 **`jtool2`**로 덤프할 수 있습니다.

그리고 **MIG 클라이언트**는 `__mach_msg`를 사용하여 서버에 보내기 위해 `__NDR_record`를 사용할 것입니다.

## 이진 분석

### jtool

많은 이진 파일이 이제 MIG를 사용하여 mach 포트를 노출하므로, **MIG가 사용되었음을 식별하는 방법**과 **각 메시지 ID에 대해 MIG가 실행하는 함수**를 아는 것이 흥미롭습니다.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2)는 Mach-O 이진 파일에서 MIG 정보를 구문 분석하여 메시지 ID를 표시하고 실행할 함수를 식별할 수 있습니다:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
또한, MIG 함수는 호출되는 실제 함수의 래퍼에 불과하므로, 해당 함수의 디스어셈블리를 가져오고 BL을 검색하면 호출되는 실제 함수를 찾을 수 있습니다:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

이전에 **수신된 메시지 ID에 따라 올바른 함수를 호출하는** 기능을 담당하는 함수는 `myipc_server`라고 언급되었습니다. 그러나 일반적으로 바이너리의 기호(함수 이름)가 없기 때문에 **디컴파일된 모습이 어떻게 생겼는지 확인하는 것이 흥미롭습니다**. 이 함수의 코드는 노출된 함수와 독립적이기 때문에 항상 매우 유사합니다:

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// 적절한 함수 포인터를 찾기 위한 초기 명령어
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// sign_extend_64 호출, 이 함수 식별에 도움이 될 수 있음
// 이는 rax에 호출해야 할 포인터를 저장합니다
// 주소 0x100004040(함수 주소 배열)의 사용 확인
// 0x1f4 = 500 (시작 ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, if는 false를 반환하고, else는 올바른 함수를 호출하고 true를 반환합니다
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// 두 개의 인수로 적절한 함수를 호출하는 계산된 주소
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
이것은 다른 Hopper 무료 버전에서 디컴파일된 동일한 함수입니다:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// 적절한 함수 포인터를 찾기 위한 초기 명령어
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS &#x26; G) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 &#x3C; 0x0) {
if (CPU_FLAGS &#x26; L) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (시작 ID)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS &#x26; NE) {
r8 = 0x1;
}
}
// 이전 버전과 동일한 if else
// 주소 0x100004040(함수 주소 배열)의 사용 확인
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// 함수가 있어야 할 계산된 주소 호출
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

실제로 **`0x100004000`** 함수로 가면 **`routine_descriptor`** 구조체 배열을 찾을 수 있습니다. 구조체의 첫 번째 요소는 **함수가 구현된 주소**이며, **구조체는 0x28 바이트를 차지하므로**, 0에서 시작하여 0x28 바이트마다 8 바이트를 가져오면 호출될 **함수의 주소**를 얻을 수 있습니다:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

이 데이터는 [**이 Hopper 스크립트를 사용하여**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) 추출할 수 있습니다.

### Debug

MIG에 의해 생성된 코드는 또한 `kernel_debug`를 호출하여 진입 및 종료 작업에 대한 로그를 생성합니다. **`trace`** 또는 **`kdv`**를 사용하여 이를 확인할 수 있습니다: `kdv all | grep MIG`

## References

- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}

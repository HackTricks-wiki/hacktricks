# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## 기본 정보

MIG는 **Mach IPC** 코드 생성 과정을 **간소화**하기 위해 만들어졌습니다. 기본적으로 주어진 정의에 따라 서버와 클라이언트가 통신하는 데 필요한 코드를 **생성합니다**. 생성된 코드가 보기 좋지 않더라도 개발자는 코드를 가져오기만 하면 되므로, 이전보다 훨씬 간결하게 코드를 작성할 수 있습니다.<sup>[[1]](#references)</sup>

정의는 `.defs` 확장자를 사용해 Interface Definition Language (IDL)로 지정합니다.

이러한 정의에는 5개 섹션이 있습니다.

- **Subsystem 선언**: `subsystem` 키워드는 **이름**과 **ID**를 지정하는 데 사용됩니다. 서버를 커널에서 실행해야 하는 경우 **`KernelServer`**로 표시할 수도 있습니다.<sup>[[4]](#references)</sup>
- **포함 및 가져오기**: MIG는 C 전처리기를 사용하므로 가져오기를 사용할 수 있습니다. 또한 사용자 또는 서버용 생성 코드에 `uimport`와 `simport`를 사용할 수 있습니다.
- **유형 선언**: 데이터 유형을 정의할 수 있지만, 보통 `mach_types.defs`와 `std_types.defs`를 가져옵니다. 사용자 지정 유형에는 다음 구문을 사용할 수 있습니다.
  - \[i`n/out]tran`: 들어오는 메시지 또는 나가는 메시지에 대해 변환해야 하는 함수
  - `c[user/server]type`: 다른 C 유형으로 매핑
  - `destructor`: 유형이 해제될 때 이 함수를 호출
- **작업**: RPC 메서드의 정의입니다. 유형은 5가지입니다.
  - `routine`: 응답을 기다림
  - `simpleroutine`: 응답을 기다리지 않음
  - `procedure`: 응답을 기다림
  - `simpleprocedure`: 응답을 기다리지 않음
  - `function`: 응답을 기다림

### 예시

이 경우 매우 간단한 함수가 포함된 정의 파일을 만듭니다.

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

첫 번째 **인수는 바인딩할 포트**이며, MIG가 **reply port를 자동으로 처리**한다는 점에 유의하세요(클라이언트 코드에서 `mig_get_reply_port()`를 호출하는 경우는 제외). 또한 **연산의 ID**는 지정된 subsystem ID부터 순차적으로 지정됩니다(따라서 연산이 deprecated되어 삭제된 경우에도 해당 ID를 계속 사용하려면 `skip`을 사용합니다).

이제 MIG를 사용해 서로 통신하여 Subtract 함수를 호출할 수 있는 서버 및 클라이언트 코드를 생성합니다:

```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```

현재 디렉터리에 여러 새 파일이 생성됩니다.

> [!TIP]
> 시스템에서 더 복잡한 예제를 찾으려면 다음을 실행하세요: `mdfind mach_port.defs`\
> 파일과 같은 폴더에서 다음 명령으로 컴파일할 수 있습니다: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

파일 **`myipcServer.c`**와 **`myipcServer.h`**에서 구조체 **`SERVERPREFmyipc_subsystem`**의 선언과 정의를 확인할 수 있습니다. 이 구조체는 기본적으로 수신한 메시지 ID에 따라 호출할 함수를 정의합니다(시작 번호는 500으로 지정했습니다).

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

이전 struct를 기반으로 **`myipc_server_routine`** 함수는 **message ID**를 받아 호출할 적절한 함수를 반환합니다:

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

이 예제에서는 definitions에 함수 하나만 정의했지만, 함수를 더 정의했다면 **`SERVERPREFmyipc_subsystem`** 배열 안에 들어갔을 것이며, 첫 번째 함수에는 ID **500**, 두 번째 함수에는 ID **501**이 할당되었을 것입니다...

함수가 **reply**를 보내도록 되어 있었다면 `mig_internal kern_return_t __MIG_check__Reply__<name>` 함수도 존재했을 것입니다.

실제로 **`myipcServer.h`**의 **`subsystem_to_name_map_myipc`** 구조체(다른 파일에서는 **`subsystem*to_name_map*\***`로 표시됨)에서 이 관계를 확인할 수 있습니다:

```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
    { "Subtract", 500 }
#endif
```

마지막으로, 서버가 작동하도록 하는 또 다른 중요한 함수는 **`myipc_server`**입니다. 이 함수는 수신한 ID와 관련된 **함수를 실제로 호출합니다**:<sup>[[3]](#references)</sup>

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

앞서 강조한, ID에 따라 호출할 함수를 가져오는 줄을 확인하세요.

다음은 클라이언트가 서버의 Subtract 함수를 호출할 수 있는 간단한 **서버**와 **클라이언트**를 만드는 코드입니다:

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

NDR_record는 `libsystem_kernel.dylib`에서 export되며, MIG가 **시스템에 종속되지 않도록 데이터를 변환할 수 있게 해주는** struct입니다. MIG는 동일한 머신 내에서만이 아니라 서로 다른 시스템 간에도 사용될 것으로 간주되었기 때문입니다.

바이너리에서 `_NDR_record`가 dependency로 확인되면(`jtool2 -S <binary> | grep NDR` 또는 `nm`), 해당 바이너리가 MIG client 또는 server라는 뜻이므로 흥미로운 단서가 됩니다.

또한 **MIG server**의 dispatch table은 `__DATA.__const`에 있습니다(macOS kernel에서는 `__CONST.__constdata`, 다른 \*OS kernel에서는 `__DATA_CONST.__const`에 있음). 이 정보는 **`jtool2`**로 덤프할 수 있습니다.

그리고 **MIG client**는 `__mach_msg`로 server에 메시지를 보낼 때 `__NDR_record`를 사용합니다.

## Binary Analysis

### jtool

현재 많은 바이너리가 mach port를 노출하는 데 MIG를 사용하므로, **MIG가 사용되었는지 식별하는 방법**과 각 message ID로 MIG가 **어떤 함수를 실행하는지** 알아두면 유용합니다.

[**jtool2 / disarm**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#disarm-old-jtool2)은 Mach-O 바이너리의 MIG 정보를 파싱해 message ID를 표시하고 실행할 함수를 식별할 수 있습니다:

```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```

또한 MIG 함수는 실제로 호출되는 함수의 래퍼입니다. 따라서 디스어셈블리를 확인하고 `BL`을 검색하면 실제로 호출되는 함수를 찾을 수 있습니다:

```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```

### 어셈블리

앞서 **수신한 메시지 ID에 따라 올바른 함수를 호출하는** 함수가 `myipc_server`라고 언급했습니다. 하지만 보통 바이너리의 심볼(함수 이름)은 없으므로, 디컴파일된 모습이 어떤지 **확인해 보는 것이 좋습니다**. 이 함수의 코드는 노출된 함수와 무관하므로 항상 매우 비슷한 형태입니다.

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
다음은 다른 무료 버전의 Hopper로 디컴파일한 동일한 함수입니다.

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

실제로 **`0x100004000`** 함수로 이동하면 **`routine_descriptor`** 구조체 배열을 찾을 수 있습니다. 구조체의 첫 번째 요소는 **함수**가 구현된 **주소**이고, **구조체의 크기는 0x28바이트**입니다. 따라서 0바이트부터 시작해 0x28바이트 간격으로 8바이트를 읽으면 호출될 **함수의 주소**를 얻을 수 있습니다.

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

이 데이터는 [**이 Hopper 스크립트를 사용해**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) 추출할 수 있습니다.

stateful MIG 메시지 시퀀스를 생성하고 fuzzing하는 워크플로는 [Stateful Mach IPC fuzzing](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#stateful-mach-ipc-fuzzing)을 참고하세요.

### 디버깅

MIG가 생성한 코드는 진입과 종료 시 작업에 관한 로그를 생성하기 위해 `kernel_debug`도 호출합니다. **`trace`** 또는 **`kdv`**를 사용해 이를 확인할 수 있습니다: `kdv all | grep MIG`



## References

- [1] [bootstrap_cmds — `migcom.tproj` (MIG 컴파일러 자체)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (MIG 서브시스템 정의 예시)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (Mach 메시지 헤더 레이아웃)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (task 서브시스템 MIG 정의)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}

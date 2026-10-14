# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

MIG 的创建是为了**简化 Mach IPC** 代码的创建过程。它基本上会根据给定的定义，**生成服务器端和客户端通信所需的代码**。即使生成的代码不够美观，开发者只需导入它，代码就会比以前简单得多。<sup>[[1]](#references)</sup>

定义使用 Interface Definition Language (IDL) 编写，扩展名为 `.defs`。

这些定义包含 5 个部分：

- **子系统声明**：使用 subsystem 关键字指定**名称**和 **id**。如果服务器应在内核中运行，也可以将其标记为 **`KernelServer`**。<sup>[[4]](#references)</sup>
- **包含和导入**：MIG 使用 C 预处理器，因此可以使用导入。此外，还可以使用 `uimport` 和 `simport`，分别用于生成用户端或服务器端代码。
- **类型声明**：可以定义数据类型，不过通常会导入 `mach_types.defs` 和 `std_types.defs`。对于自定义类型，可以使用以下一些语法：
  - \[i`n/out]tran`：需要对传入或传出消息进行转换的函数
  - `c[user/server]type`：映射到另一种 C 类型。
  - `destructor`：释放该类型时调用此函数。
- **操作**：这些是 RPC 方法的定义。共有 5 种不同类型：
  - `routine`：需要回复
  - `simpleroutine`：不需要回复
  - `procedure`：需要回复
  - `simpleprocedure`：不需要回复
  - `function`：需要回复

### 示例

创建一个定义文件，本例中包含一个非常简单的函数：

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

请注意，第一个 **参数是要绑定的端口**，MIG 会 **自动处理回复端口**（除非在客户端代码中调用 `mig_get_reply_port()`）。此外，**操作 ID** 将从指定的子系统 ID 开始按顺序递增（因此，如果某个操作已弃用，就将其删除并使用 `skip`，以继续使用其 ID）。

现在使用 MIG 生成服务器端和客户端代码，使它们能够相互通信并调用 Subtract 函数：

```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```

当前目录中将创建几个新文件。

> [!TIP]
> 你可以在系统中找到一个更复杂的示例：`mdfind mach_port.defs`\
> 也可以在与文件相同的文件夹中编译它：`mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

在文件 **`myipcServer.c`** 和 **`myipcServer.h`** 中，可以找到结构体 **`SERVERPREFmyipc_subsystem`** 的声明和定义。它基本上定义了根据收到的消息 ID 要调用的函数（我们指定的起始编号是 500）：

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

根据前面的 struct，函数 **`myipc_server_routine`** 会获取 **message ID** 并返回要调用的相应函数：

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

在这个示例中，我们只在定义中定义了 1 个函数；但如果定义了更多函数，它们会位于 **`SERVERPREFmyipc_subsystem`** 数组中，第一个函数会被分配 ID **500**，第二个函数会被分配 ID **501**……

如果该函数预期会发送 **reply**，那么函数 `mig_internal kern_return_t __MIG_check__Reply__<name>` 也会存在。

实际上，可以在 **`myipcServer.h`** 中的结构体 **`subsystem_to_name_map_myipc`**（其他文件中的 **`subsystem*to_name_map*\***）里识别这种对应关系：

```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
    { "Subtract", 500 }
#endif
```

最后，要让服务器正常工作，另一个重要函数是 **`myipc_server`**，它会实际**调用**与收到的 id 对应的函数：<sup>[[3]](#references)</sup>

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

请查看前面标出的、根据 ID 访问要调用函数的代码行。

以下是创建简单 **服务器**和**客户端**的代码，客户端可以调用服务器中的 Subtract 函数：

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

NDR_record 由 `libsystem_kernel.dylib` 导出，它是一个 struct，可让 MIG **转换数据，使其不依赖于特定系统**。MIG 最初被设计为可在不同系统之间使用，而不只是同一台机器上的不同进程之间使用。

这很有意思，因为如果在二进制文件的依赖项中找到 `_NDR_record`（`jtool2 -S <binary> | grep NDR` 或 `nm`），就说明该二进制文件是 MIG client 或 Server。

此外，**MIG servers** 在 `__DATA.__const` 中包含 dispatch table（在 macOS 内核中位于 `__CONST.__constdata`，在其他 *OS 内核中位于 `__DATA_CONST.__const`）。可以使用 **`jtool2`** 将其转储。

而 **MIG clients** 会使用 `__NDR_record`，通过 `__mach_msg` 向 servers 发送消息。

## 二进制分析

### jtool

如今许多二进制文件都使用 MIG 来公开 mach ports，因此了解如何**识别是否使用了 MIG**，以及 **MIG 针对每个 message ID 执行的函数**，很有意思。

[**jtool2 / disarm**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#disarm-old-jtool2) 可以解析 Mach-O 二进制文件中的 MIG 信息，显示 message ID 并识别要执行的函数：

```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```

此外，MIG 函数是对实际调用函数的封装。因此，通过获取反汇编并搜索 `BL`，你或许能找到实际调用的函数：

```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```

### 汇编

前面提到过，负责**根据收到的消息 ID 调用正确函数**的函数是 `myipc_server`。不过，你通常不会有二进制文件的符号（没有函数名），因此可以**看看它反编译后的样子**，因为它通常都非常相似（这个函数的代码与暴露的函数无关）：

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
这是使用不同免费版 Hopper 反编译出的同一个函数：

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

实际上，如果你转到函数 **`0x100004000`**，就会找到 **`routine_descriptor`** 结构体数组。结构体的第一个元素是实现该**函数**的**地址**，而这个**结构体占用 0x28 字节**，因此从第 0 字节开始，每隔 0x28 字节读取 8 个字节，就能得到将要调用的**函数地址**：

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

可以[**使用这个 Hopper 脚本**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py)提取这些数据。

如需了解如何构建种子并对有状态的 MIG 消息序列进行 fuzz，请参阅 [Stateful Mach IPC fuzzing](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#stateful-mach-ipc-fuzzing)。

### 调试

MIG 生成的代码还会调用 `kernel_debug`，以记录操作的进入和退出情况。可以使用 **`trace`** 或 **`kdv`** 查看这些记录：`kdv all | grep MIG`



## References

- [1] [bootstrap_cmds — `migcom.tproj`（MIG 编译器本身）](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs`（MIG 子系统定义示例）](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h`（Mach 消息头布局）](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs`（task 子系统 MIG 定义）](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}

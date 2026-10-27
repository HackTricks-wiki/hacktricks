# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

MIG được tạo ra để **đơn giản hóa quá trình tạo mã Mach IPC**. Về cơ bản, MIG **tạo mã cần thiết** để server và client giao tiếp dựa trên một định nghĩa cho trước. Dù mã được tạo ra không đẹp, nhà phát triển chỉ cần import mã đó và phần mã của họ sẽ đơn giản hơn nhiều.<sup>[[1]](#references)</sup>

Định nghĩa được viết bằng Interface Definition Language (IDL) với phần mở rộng `.defs`.

Các định nghĩa này có 5 phần:

- **Khai báo subsystem**: Từ khóa subsystem được dùng để chỉ định **tên** và **id**. Cũng có thể đánh dấu subsystem là **`KernelServer`** nếu server cần chạy trong kernel.<sup>[[4]](#references)</sup>
- **Các phần bao gồm và import**: MIG sử dụng C-preprocessor nên có thể dùng import. Ngoài ra, có thể dùng `uimport` và `simport` cho mã được tạo ở phía user hoặc server.
- **Khai báo kiểu**: Có thể định nghĩa các kiểu dữ liệu, dù thông thường sẽ import `mach_types.defs` và `std_types.defs`. Với các kiểu tùy chỉnh, có thể dùng một số cú pháp:
  - \[i`n/out]tran`: Hàm cần chuyển đổi từ một message đến hoặc sang một message đi
  - `c[user/server]type`: Ánh xạ sang một kiểu C khác.
  - `destructor`: Gọi hàm này khi kiểu dữ liệu được giải phóng.
- **Các thao tác**: Đây là định nghĩa của các phương thức RPC. Có 5 loại:
  - `routine`: Mong đợi phản hồi
  - `simpleroutine`: Không mong đợi phản hồi
  - `procedure`: Mong đợi phản hồi
  - `simpleprocedure`: Không mong đợi phản hồi
  - `function`: Mong đợi phản hồi

### Ví dụ

Tạo một tệp định nghĩa, trong trường hợp này là một hàm rất đơn giản:

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

Lưu ý rằng **tham số đầu tiên là cổng cần bind** và MIG sẽ **tự động xử lý reply port** (trừ khi gọi `mig_get_reply_port()` trong mã client). Ngoài ra, **ID của các operation** sẽ được đánh số **tuần tự**, bắt đầu từ subsystem ID đã chỉ định (vì vậy, nếu một operation bị deprecated thì operation đó sẽ bị xóa và dùng `skip` để các operation khác vẫn giữ nguyên ID).

Giờ hãy dùng MIG để tạo mã server và client có thể giao tiếp với nhau để gọi hàm Subtract:

```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```

Một số tệp mới sẽ được tạo trong thư mục hiện tại.

> [!TIP]
> Bạn có thể tìm thấy một ví dụ phức tạp hơn trong hệ thống bằng lệnh: `mdfind mach_port.defs`\
> Và bạn có thể biên dịch tệp đó từ cùng thư mục với lệnh: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

Trong các tệp **`myipcServer.c`** và **`myipcServer.h`**, bạn có thể tìm thấy phần khai báo và định nghĩa của struct **`SERVERPREFmyipc_subsystem`**, về cơ bản xác định hàm cần gọi dựa trên message ID nhận được (chúng ta đã chỉ định số bắt đầu là 500):

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

Dựa trên struct trước đó, hàm **`myipc_server_routine`** sẽ nhận **message ID** và trả về hàm thích hợp để gọi:

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

Trong ví dụ này, chúng ta chỉ định nghĩa 1 function trong phần định nghĩa. Nhưng nếu định nghĩa thêm function, chúng sẽ nằm trong array **`SERVERPREFmyipc_subsystem`**, function đầu tiên được gán ID **500**, function thứ hai được gán ID **501**...

Nếu function được kỳ vọng sẽ gửi **reply**, function `mig_internal kern_return_t __MIG_check__Reply__<name>` cũng sẽ tồn tại.

Thực tế, có thể nhận diện mối liên hệ này trong struct **`subsystem_to_name_map_myipc`** từ **`myipcServer.h`** (**`subsystem*to_name_map*\***` trong các file khác):

```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
    { "Subtract", 500 }
#endif
```

Cuối cùng, một hàm quan trọng khác để server hoạt động là **`myipc_server`**. Hàm này sẽ **gọi hàm** liên quan đến id nhận được:<sup>[[3]](#references)</sup>

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

Kiểm tra các dòng được tô sáng ở trên để xem cách truy cập hàm cần gọi theo ID.

Dưới đây là code tạo một **server** và **client** đơn giản, trong đó client có thể gọi các hàm Subtract từ server:

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

NDR_record được `libsystem_kernel.dylib` export; đây là một struct cho phép MIG **chuyển đổi dữ liệu để không phụ thuộc vào hệ thống** đang sử dụng, vì MIG được thiết kế để dùng giữa các hệ thống khác nhau (chứ không chỉ trên cùng một máy).

Điều này đáng chú ý vì nếu tìm thấy `_NDR_record` trong binary dưới dạng dependency (`jtool2 -S <binary> | grep NDR` hoặc `nm`), điều đó có nghĩa binary là MIG client hoặc server.

Ngoài ra, **MIG server** có dispatch table trong `__DATA.__const` (hoặc trong `__CONST.__constdata` ở macOS kernel và `__DATA_CONST.__const` ở các kernel \*OS khác). Có thể dump bảng này bằng **`jtool2`**.

Còn **MIG client** sẽ dùng `__NDR_record` để gửi dữ liệu đến server bằng `__mach_msg`.

## Binary Analysis

### jtool

Vì hiện nay nhiều binary dùng MIG để expose mach ports, nên việc biết cách **xác định MIG đã được sử dụng** và **các function mà MIG thực thi với từng message ID** là rất hữu ích.

[**jtool2 / disarm**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#disarm-old-jtool2) có thể phân tích thông tin MIG từ Mach-O binary, cho biết message ID và xác định function cần thực thi:

```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```

Ngoài ra, các hàm MIG là những wrapper bao quanh hàm thực sự được gọi. Vì vậy, bằng cách lấy disassembly và tìm `BL`, bạn có thể tìm ra hàm thực sự được gọi:

```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```

### Assembly

Trước đó đã đề cập rằng hàm chịu trách nhiệm **gọi hàm thích hợp dựa trên message ID nhận được** là `myipc_server`. Tuy nhiên, thông thường bạn sẽ không có các symbol của binary (tức là không có tên hàm), vì vậy sẽ hữu ích nếu **xem hàm này trông như thế nào khi được decompile**, vì nó luôn rất giống nhau (code của hàm này không phụ thuộc vào các hàm được expose):

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
Đây là cùng hàm được decompile bằng một phiên bản Hopper miễn phí khác:

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

Thực tế, nếu truy cập hàm **`0x100004000`**, bạn sẽ tìm thấy mảng các struct **`routine_descriptor`**. Phần tử đầu tiên của struct là **địa chỉ** nơi **hàm** được triển khai, và **struct có kích thước 0x28 byte**. Vì vậy, cứ mỗi 0x28 byte (bắt đầu từ byte 0), bạn có thể lấy 8 byte, đó sẽ là **địa chỉ của hàm** được gọi:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Có thể trích xuất dữ liệu này [**bằng script Hopper này**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

Để xem quy trình tạo seed và fuzz các chuỗi message MIG có trạng thái, hãy xem [Stateful Mach IPC fuzzing](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#stateful-mach-ipc-fuzzing).

### Debug

Code do MIG tạo ra cũng gọi `kernel_debug` để tạo log về các thao tác khi bắt đầu và kết thúc. Có thể kiểm tra các log này bằng **`trace`** hoặc **`kdv`**: `kdv all | grep MIG`



## References

- [1] [bootstrap_cmds — `migcom.tproj` (bản thân trình biên dịch MIG)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (ví dụ về định nghĩa subsystem MIG)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (bố cục header của Mach message)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (định nghĩa subsystem MIG của task)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}

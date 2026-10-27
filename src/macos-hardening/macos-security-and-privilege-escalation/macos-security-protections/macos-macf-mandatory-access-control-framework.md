# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

**MACF** là viết tắt của **Mandatory Access Control Framework** (Khung kiểm soát truy cập bắt buộc), một hệ thống bảo mật được tích hợp trong hệ điều hành để giúp bảo vệ máy tính của bạn. Hệ thống này hoạt động bằng cách đặt ra **các quy tắc nghiêm ngặt về việc ai hoặc thứ gì có thể truy cập một số phần nhất định của hệ thống**, chẳng hạn như tệp, ứng dụng và tài nguyên hệ thống. Bằng cách tự động thực thi các quy tắc này, MACF đảm bảo chỉ người dùng và tiến trình được ủy quyền mới có thể thực hiện những hành động cụ thể, qua đó giảm nguy cơ truy cập trái phép hoặc hoạt động độc hại.

Lưu ý rằng MACF thực sự không đưa ra quyết định nào, vì nó chỉ **chặn** các hành động; việc quyết định được giao cho các **module chính sách** (kernel extension) mà nó gọi, chẳng hạn như `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` và `mcxalr.kext`.

- Một chính sách có thể thực thi (trả về 0 hoặc giá trị khác 0 cho một số thao tác)
- Một chính sách có thể giám sát (trả về 0 để không phản đối, nhưng tận dụng hook để thực hiện việc gì đó)
- Một chính sách MACF tĩnh được cài đặt khi khởi động và sẽ KHÔNG BAO GIỜ bị gỡ bỏ
- Một chính sách MACF động được cài đặt bởi KEXT (kextload) và về mặt lý thuyết có thể được gỡ bằng kextunload
- Trên iOS, chỉ cho phép các chính sách tĩnh; còn trên macOS, cho phép cả chính sách tĩnh lẫn động.<sup>[[7]](#references)</sup>

### Luồng

1. Tiến trình thực hiện một syscall/mach trap
2. Hàm liên quan được gọi bên trong kernel
3. Hàm gọi MACF
4. MACF kiểm tra các module chính sách đã yêu cầu hook hàm đó trong chính sách của chúng
5. MACF gọi các chính sách liên quan
6. Các chính sách cho biết chúng cho phép hay từ chối hành động

> [!CAUTION]
> Chỉ Apple mới có thể sử dụng MAC Framework KPI.

Thông thường, các hàm kiểm tra quyền bằng MACF sẽ gọi macro `MAC_CHECK`. Ví dụ, syscall tạo socket sẽ gọi hàm `mac_socket_check_create`, hàm này gọi `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Ngoài ra, macro `MAC_CHECK` được định nghĩa trong security/mac_internal.h như sau:<sup>[[3]](#references)</sup>
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

Lưu ý rằng khi chuyển đổi `check` thành `socket_check_create` và `args...` thành `(cred, domain, type, protocol)`, bạn sẽ nhận được:

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

Mở rộng các macro trợ giúp sẽ cho thấy luồng điều khiển cụ thể:

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

Nói cách khác, `MAC_CHECK(socket_check_create, ...)` duyệt qua các policy tĩnh trước, khóa có điều kiện và lặp qua các policy động, phát các DTrace probe xung quanh mỗi hook, rồi gộp mã trả về của từng hook thành một kết quả `error` duy nhất thông qua `mac_error_select()`.


### Labels

MACF sử dụng **labels** mà các policy sẽ dùng để kiểm tra xem có nên cấp quyền truy cập hay không. Có thể tìm thấy phần khai báo struct của labels [tại đây](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h). Struct này được dùng bên trong **`struct ucred`** [tại đây](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), trong phần **`cr_label`**. Label chứa các flags và một số lượng **slots** có thể được các **MACF policy dùng để cấp phát con trỏ**. Ví dụ, Sandbox sẽ trỏ đến profile của container.

## MACF Policies

Một MACF Policy định nghĩa **các quy tắc và điều kiện được áp dụng trong một số thao tác kernel nhất định**.

Một kernel extension có thể cấu hình struct `mac_policy_conf`, sau đó đăng ký struct này bằng cách gọi `mac_policy_register`. Từ [đây](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Có thể dễ dàng xác định các kernel extension cấu hình những policy này bằng cách kiểm tra các lệnh gọi đến `mac_policy_register`. Ngoài ra, bằng cách kiểm tra bản disassemble của extension, cũng có thể tìm thấy struct `mac_policy_conf` được sử dụng.

Lưu ý rằng các MACF policy cũng có thể được đăng ký và hủy đăng ký **động**.

Một trong những trường chính của `mac_policy_conf` là **`mpc_ops`**. Trường này chỉ định những operation nào mà policy quan tâm. Có hàng trăm operation, vì vậy có thể đặt tất cả các entry về 0 rồi chỉ chọn những entry mà policy cần. Từ [đây](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Hầu hết các hook sẽ được MACF gọi lại khi một trong những thao tác đó bị chặn. Tuy nhiên, các hook **`mpo_policy_*`** là ngoại lệ, vì `mpo_hook_policy_init()` là callback được gọi khi đăng ký (tức là sau `mac_policy_register()`), còn `mpo_hook_policy_initbsd()` được gọi trong quá trình đăng ký muộn, sau khi subsystem BSD đã khởi tạo đúng cách.

Ngoài ra, bất kỳ kext nào cũng có thể đăng ký hook **`mpo_policy_syscall`** để cung cấp một **interface** gọi kiểu **ioctl** riêng. Khi đó, một user client có thể gọi `mac_syscall` (#381), chỉ định **tên policy** cùng một **code** số nguyên và các **arguments** tùy chọn làm tham số.\
Ví dụ, **`Sandbox.kext`** sử dụng cách này rất nhiều.

Có thể kiểm tra **`__DATA.__const*`** của kext để xác định cấu trúc `mac_policy_ops` được dùng khi đăng ký policy. Có thể tìm thấy cấu trúc này vì con trỏ của nó nằm ở một offset bên trong `mpo_policy_conf`, đồng thời khu vực đó sẽ chứa nhiều con trỏ NULL.

Ngoài ra, cũng có thể lấy danh sách các kext đã cấu hình policy bằng cách dump cấu trúc **`_mac_policy_list`** từ bộ nhớ. Cấu trúc này được cập nhật mỗi khi có policy được đăng ký.

Bạn cũng có thể dùng công cụ `xnoop` để dump tất cả policy đã đăng ký trong hệ thống:

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

Sau đó dump toàn bộ các kiểm tra của check policy bằng:

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

## Khởi tạo MACF trong XNU

### Khởi động sớm và mac_policy_init()

- MACF được khởi tạo rất sớm. Trong `bootstrap_thread` (ở mã khởi động XNU), sau `ipc_bootstrap`, XNU gọi `mac_policy_init()` (trong `mac_base.c`).  
- `mac_policy_init()` khởi tạo `mac_policy_list` toàn cục (một mảng hoặc danh sách các slot policy) và thiết lập cơ sở hạ tầng cho MAC (Mandatory Access Control) trong XNU.  
- Sau đó, `mac_policy_initmach()` được gọi để xử lý việc đăng ký policy ở phía kernel cho các policy tích hợp sẵn hoặc được đóng gói kèm.

### `mac_policy_initmach()` và việc tải “phần mở rộng bảo mật”

- `mac_policy_initmach()` kiểm tra các kernel extension (kext) được tải trước (hoặc nằm trong danh sách “policy injection”) và kiểm tra Info.plist của chúng để tìm khóa `AppleSecurityExtension`.  
- Các kext khai báo `<key>AppleSecurityExtension</key>` (hoặc `true`) trong Info.plist được xem là “phần mở rộng bảo mật” — tức là những thành phần triển khai một MAC policy hoặc kết nối với cơ sở hạ tầng MACF.  
- Ví dụ về các kext của Apple có khóa này gồm **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, cùng nhiều kext khác (như đã liệt kê).  
- Kernel đảm bảo các kext này được tải sớm, sau đó gọi các hàm đăng ký của chúng (thông qua `mac_policy_register`) trong quá trình khởi động, đưa chúng vào `mac_policy_list`.

  - Mỗi module policy (kext) cung cấp một cấu trúc `mac_policy_conf`, với các hook (`mpc_ops`) cho nhiều thao tác MAC khác nhau (kiểm tra vnode, kiểm tra exec, cập nhật label, v.v.).  
  - Các cờ thời điểm tải có thể bao gồm `MPC_LOADTIME_FLAG_NOTLATE`, nghĩa là “phải được tải sớm” (do đó các lần đăng ký muộn sẽ bị từ chối).  
  - Sau khi đăng ký, mỗi module nhận một handle và chiếm một slot trong `mac_policy_list`.  
  - Khi một MAC hook được gọi sau đó (ví dụ: truy cập vnode, exec, v.v.), MACF lặp qua tất cả policy đã đăng ký để đưa ra quyết định tổng hợp.

- Cụ thể, **AMFI** (Apple Mobile File Integrity) là một phần mở rộng bảo mật như vậy. Info.plist của nó có `AppleSecurityExtension`, đánh dấu nó là một security policy. 
- Trong quá trình kernel khởi động, logic tải của kernel đảm bảo “security policy” (AMFI, v.v.) đã hoạt động trước khi nhiều subsystem phụ thuộc vào nó. Ví dụ, kernel “chuẩn bị cho các tác vụ sắp tới bằng cách tải … security policy, bao gồm AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.” 

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

## Phụ thuộc KPI & com.apple.kpi.dsep trong các MAC policy kext

Khi viết một kext sử dụng framework MAC (tức là gọi `mac_policy_register()` v.v.), bạn phải khai báo các phụ thuộc vào KPI (Kernel Programming Interfaces) để trình liên kết kext (kxld) có thể phân giải các symbol đó. Vì vậy, để khai báo một `kext` phụ thuộc vào MACF, bạn cần chỉ định điều này trong `Info.plist` bằng `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), sau đó kext sẽ tham chiếu đến các symbol như `mac_policy_register`, `mac_policy_unregister` và các con trỏ hàm MAC hook. Để phân giải chúng, bạn phải liệt kê `com.apple.kpi.dsep` là một dependency.

Ví dụ về đoạn Info.plist (bên trong .kext của bạn):

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



## MACF trên các phiên bản macOS hiện đại

Trên macOS hiện đại, các chính sách bảo mật của Apple thường không nên được xem như những gói `.kext` độc lập, rời rạc. Kể từ **macOS 11**, các kernel extension được liên kết vào **kernel collection**; trên **Apple Silicon** không có **SystemKC** riêng, và các kext của bên thứ ba chỉ có thể được tải sau khi được tích hợp vào **Auxiliary Kernel Collection (AuxKC)** và khởi động lại máy. Đối với nghiên cứu MACF, điều này có nghĩa là các chính sách tích hợp sẵn như **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** hoặc **Quarantine** thường dễ liệt kê bằng `kmutil` hơn so với các công cụ đã lỗi thời như `kextstat`.

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Trên Apple Silicon, nếu một security kext không có trong BootKC, hãy kiểm tra AuxKC tiếp theo. Cách này thường hữu ích hơn so với việc tìm một bundle độc lập trong `/System/Library/Extensions`.

## Các điểm gọi MACF

Thường có thể tìm thấy các điểm gọi MACF được định nghĩa trong code, chẳng hạn như bên trong các khối điều kiện **`#if CONFIG_MAC`**. Ngoài ra, bên trong các khối này có thể có các lệnh gọi `mac_proc_check*`, dùng để gọi MACF **kiểm tra quyền** thực hiện một số hành động. Định dạng của các điểm gọi MACF là: **`mac_<object>_<opType>_opName`**.

`object` là một trong các giá trị sau: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` thường là `check`, dùng để cho phép hoặc từ chối hành động. Tuy nhiên, cũng có thể gặp `notify`, cho phép kext phản ứng với hành động được chỉ định.

Bạn có thể xem ví dụ tại [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Sau đó, có thể tìm thấy code của `mac_file_check_mmap` tại [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)

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

Đoạn này gọi macro `MAC_CHECK`, mã của macro có thể tìm thấy tại [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>

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

Điều này sẽ duyệt qua tất cả các chính sách MAC đã đăng ký, gọi các hàm của chúng và lưu kết quả vào biến `error`. Biến này chỉ có thể được `mac_error_select` ghi đè bằng các mã thành công. Vì vậy, nếu bất kỳ lần kiểm tra nào thất bại, toàn bộ quá trình kiểm tra sẽ thất bại và hành động sẽ không được cho phép.

> [!TIP]
> Tuy nhiên, hãy nhớ rằng không phải mọi MACF callout đều chỉ được dùng để từ chối hành động. Ví dụ: `mac_priv_grant` gọi macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), macro này sẽ cấp đặc quyền được yêu cầu nếu bất kỳ chính sách nào trả về 0:
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

Các lời gọi này được dùng để kiểm tra và cấp (hàng chục) **đặc quyền** được định nghĩa trong [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Một số mã kernel gọi `priv_check_cred()` từ [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) với thông tin xác thực KAuth của tiến trình và mã của một trong các đặc quyền. Hàm này sẽ gọi `mac_priv_check` để kiểm tra xem có chính sách nào **từ chối** cấp đặc quyền hay không, sau đó gọi `mac_priv_grant` để kiểm tra xem có chính sách nào cấp `privilege` hay không.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Hook này cho phép chặn mọi lời gọi hệ thống. Trong `bsd/dev/[i386|arm]/systemcalls.c`, có thể thấy hàm [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) được khai báo và chứa đoạn mã sau:

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

Sẽ kiểm tra **bitmask** trong tiến trình gọi để xác định syscall hiện tại có cần gọi `mac_proc_check_syscall_unix` hay không. Vì syscall được gọi rất thường xuyên, nên việc tránh gọi `mac_proc_check_syscall_unix` mỗi lần là hữu ích.

Lưu ý rằng hàm `proc_set_syscall_filter_mask()`, dùng để thiết lập bitmask syscall trong một tiến trình, được Sandbox gọi để đặt mask cho các tiến trình bị sandbox.

## Các syscall MACF được cung cấp

Có thể tương tác với MACF thông qua một số syscall được định nghĩa trong [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):

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

Trong reverse engineering phục vụ khai thác, **`__mac_syscall`** vẫn là một trong những điểm chặn userland tốt nhất. Hàm này nhận **tên policy** (ví dụ `"Sandbox"` hoặc `"AMFI"`), **selector/mã riêng của policy** và con trỏ tới **blob đối số opaque** sẽ được xử lý bởi `mpo_policy_syscall`. Điều này rất hữu ích khi reverse các operation chưa được tài liệu hóa từ userland trước, rồi sau đó mới chuyển sang triển khai trong kernel. Sandbox thường gọi hàm này thông qua `__sandbox_ms`, còn AMFI dùng cùng cơ chế này để đưa ra quyết định về policy của dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Ghi chú thực tế cho nghiên cứu khai thác

Các bug macOS gần đây hiếm khi trực tiếp "phá vỡ MACF". Thay vào đó, chúng thường khai thác **sự mất đồng bộ giữa quyết định của MACF / Sandbox / TCC và hành động đặc quyền diễn ra sau đó**.

### Kiểm tra đường dẫn của broker so với hành động đặc quyền thực tế

Một mẫu thường gặp là daemon đặc quyền thực hiện **kiểm tra trước ở userland** (ví dụ `sandbox_check_by_audit_token()`) trên một phiên bản của đường dẫn, rồi sau đó thực hiện sink đặc quyền thực tế với một đường dẫn khác hoặc không chuẩn hóa do attacker kiểm soát. Nghiên cứu gần đây về `diskarbitrationd` / `storagekitd` là một ví dụ điển hình: **directory traversal** kết hợp với **hoán đổi symlink** cho phép attacker vượt qua bước xác thực sandbox của daemon, rồi mount lên các vị trí nhạy cảm như `~/Library/Application Support/com.apple.TCC`, biến bug thành **sandbox escape**, **leo thang đặc quyền cục bộ** hoặc **TCC bypass**, tùy vào mount point được chọn.<sup>[[6]](#references)</sup>

Khi audit các root broker có thể truy cập từ sandbox, hãy grep trước các mục sau:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, các helper chuẩn hóa đường dẫn
- Các sink đặc quyền như `mount`, `rename`, `copyfile`, các phương thức XPC của helper-tool hoặc bất kỳ thứ gì về sau xử lý đường dẫn do attacker kiểm soát với quyền root

### Trusted deputy với entitlement riêng tư

Một mẫu thực tế khác là không tấn công trực tiếp các MACF hook, mà thay vào đó lạm dụng một **process đáng tin cậy** vốn đã có các quyền cần thiết để vượt qua ranh giới. Nghiên cứu gần đây về Safari/TCC là một ví dụ điển hình: primitive đáng chú ý không phải là "tắt TCC trong kernel", mà là sửa đổi policy/configuration cục bộ để một process do Apple ký, có **`com.apple.private.tcc.allow`**, thực hiện hành động nhạy cảm thay cho bạn.<sup>[[8]](#references)</sup> Trên thực tế, các mục tiêu audit có giá trị cao là những daemon/app của Apple kết hợp:

- **private entitlement** hoặc quyền truy cập tương tự FDA
- config / database / mount point / policy file có thể ghi
- một thao tác nhạy cảm diễn ra sau đó, được **Sandbox**, **AMFI**, **TCC** hoặc một policy MACF khác kiểm soát

Để reverse sâu hơn theo từng sản phẩm, hãy xem các trang riêng về [macOS Sandbox](macos-sandbox/README.md) và [macOS TCC](macos-tcc/README.md).

## References

- [1] [XNU — `security/mac_policy.h` (vector thao tác policy MACF đầy đủ)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (các macro `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (các mã quyền được `priv_check`/`priv_grant` sử dụng)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Phát hiện lỗ hổng Apple: Kiểm tra `diskarbitrationd` và `storagekitd`, Phần 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — Công cụ tham chiếu chéo XNU](https://newosxbook.com/xxr/index.php)
- [8] [Lỗ hổng macOS mới, "HM Surf", có thể dẫn đến truy cập dữ liệu trái phép (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
{{#include ../../../banners/hacktricks-training.md}}

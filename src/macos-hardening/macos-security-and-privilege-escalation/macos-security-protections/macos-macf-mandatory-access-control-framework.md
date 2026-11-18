# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

**MACF** 是 **Mandatory Access Control Framework**（强制访问控制框架）的缩写，是操作系统内置的一种安全系统，可帮助保护你的计算机。它通过设定**严格规则，规定谁或什么可以访问系统的某些部分**，例如文件、应用程序和系统资源。MACF 会自动强制执行这些规则，确保只有经过授权的用户和进程才能执行特定操作，从而降低未经授权访问或恶意活动的风险。

请注意，MACF 本身并不会真正做出任何决定，它只负责**拦截**操作，并将决定交给它调用的**策略模块**（内核扩展），例如 `AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext` 和 `mcxalr.kext`。

- 策略可以用于强制执行（在某些操作中返回非 0）
- 策略可以用于监控（返回 0，以免拦截操作，同时利用 hook 执行其他操作）
- MACF 静态策略会在启动时安装，且永远不会被移除
- MACF 动态策略由 KEXT（kextload）安装，理论上可以通过 kextunload 卸载
- iOS 只允许使用静态策略，而 macOS 允许使用静态和动态策略。<sup>[[7]](#references)</sup>

### 流程

1. 进程执行 syscall/mach trap
2. 内核中调用相关函数
3. 函数调用 MACF
4. MACF 检查在策略中请求 hook 该函数的策略模块
5. MACF 调用相关策略
6. 策略指出是否允许该操作

> [!CAUTION]
> 只有 Apple 能使用 MAC Framework KPI。

通常，使用 MACF 检查权限的函数会调用宏 `MAC_CHECK`。例如，创建 socket 的 syscall 会调用函数 `mac_socket_check_create`，而该函数会调用 `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`。此外，宏 `MAC_CHECK` 在 security/mac_internal.h 中定义如下：<sup>[[3]](#references)</sup>
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

注意，将 `check` 转换为 `socket_check_create`，并将 `(cred, domain, type, protocol)` 作为 `args...`，即可得到：

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

展开辅助宏后，可以看到具体的控制流：

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

换句话说，`MAC_CHECK(socket_check_create, ...)` 会先遍历静态策略，有条件地加锁并遍历动态策略，在每个 hook 周围触发 DTrace probes，并通过 `mac_error_select()` 将每个 hook 的返回码归并为单个 `error` 结果。


### Labels

MACF 使用 **labels**，策略会根据这些 labels 检查是否应授予访问权限。labels 结构体的声明代码[见此处](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h)，随后会在[此处](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86)的 **`struct ucred`** 中使用，位于 **`cr_label`** 部分。label 包含标志，以及一定数量的 **slots**，供 **MACF 策略分配指针**使用。例如，Sandbox 会指向容器配置文件。

## MACF Policies

MACF Policy 定义了**适用于特定内核操作的规则和条件**。

内核扩展可以配置一个 `mac_policy_conf` 结构体，然后调用 `mac_policy_register` 注册它。来源：[此处](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)：<sup>[[1]](#references)</sup>

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

通过检查对 `mac_policy_register` 的调用，可以轻松识别配置这些策略的 kernel extensions。此外，反汇编该扩展后，也可以找到所使用的 `mac_policy_conf` 结构体。

请注意，MACF 策略也可以**动态**注册和注销。

`mac_policy_conf` 的主要字段之一是 **`mpc_ops`**。此字段指定该策略关注哪些操作。操作有数百种，因此可以先将所有条目清零，再仅选择该策略所需的操作。参见[此处](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)：<sup>[[1]](#references)</sup>

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

几乎所有 hook 都会在相关操作被拦截时由 MACF 回调。不过，**`mpo_policy_*`** hook 是个例外：`mpo_hook_policy_init()` 是在注册时调用的回调（也就是在 `mac_policy_register()` 之后），而 `mpo_hook_policy_initbsd()` 则会在 BSD 子系统正确初始化后，于延迟注册期间调用。

此外，任何 kext 都可以注册 **`mpo_policy_syscall`** hook，以提供私有的 **ioctl** 风格调用**接口**。随后，用户客户端便可以调用 `mac_syscall` (#381)，并将**策略名称**、整数**代码**以及可选的**参数**作为参数传入。\
例如，`Sandbox.kext` 就经常这样做。

检查 kext 的 **`__DATA.__const*`**，可以识别注册策略时使用的 `mac_policy_ops` 结构。之所以能找到它，是因为它的指针位于 `mpo_policy_conf` 内的某个偏移处，而且该区域中会有大量 NULL 指针。

此外，也可以从内存中转储结构 **`_mac_policy_list`**，获取配置了策略的 kext 列表；每注册一个策略，该结构都会更新。

你也可以使用工具 `xnoop` 转储系统中注册的所有策略：

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

然后使用以下命令转储 check policy 的所有检查项：

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

## XNU 中的 MACF 初始化

### 早期引导和 mac_policy_init()

- MACF 很早就会初始化。在 `bootstrap_thread`（位于 XNU 启动代码中）里，XNU 在 `ipc_bootstrap` 之后调用 `mac_policy_init()`（位于 `mac_base.c` 中）。  
- `mac_policy_init()` 初始化全局 `mac_policy_list`（一个策略槽位数组或列表），并在 XNU 中搭建 MAC（Mandatory Access Control，强制访问控制）基础设施。  
- 随后会调用 `mac_policy_initmach()`，由它处理内核端内置或捆绑策略的注册。

### `mac_policy_initmach()` 和“安全扩展”的加载

- `mac_policy_initmach()` 检查预加载的（或位于“策略注入”列表中的）内核扩展（kext），并检查其 Info.plist 中是否有 `AppleSecurityExtension` 键。  
- 在 Info.plist 中声明了 `<key>AppleSecurityExtension</key>`（或 `true`）的 kext 会被视为“安全扩展”——也就是说，这些扩展实现了 MAC 策略，或接入了 MACF 基础设施。  
- 包含该键的 Apple kext 示例包括 **ALF.kext**、**AppleMobileFileIntegrity.kext (AMFI)**、**Sandbox.kext**、**Quarantine.kext**、**TMSafetyNet.kext**、**CoreTrust.kext**、**AppleSystemPolicy.kext** 等（如你之前列出的）。  
- 内核会确保这些 kext 尽早加载，然后在启动期间调用它们的注册例程（通过 `mac_policy_register`），将它们加入 `mac_policy_list`。

  - 每个策略模块（kext）都会提供一个 `mac_policy_conf` 结构，其中包含针对各种 MAC 操作的钩子（`mpc_ops`），例如 vnode 检查、exec 检查、标签更新等。  
  - 加载时标志可能包含 `MPC_LOADTIME_FLAG_NOTLATE`，表示“必须尽早加载”（因此会拒绝稍后进行的注册尝试）。  
  - 注册完成后，每个模块都会获得一个句柄，并占用 `mac_policy_list` 中的一个槽位。  
  - 之后调用 MAC 钩子时（例如 vnode 访问、exec 等），MACF 会遍历所有已注册的策略并作出综合决策。

- 特别是，**AMFI**（Apple Mobile File Integrity）就是这样一种安全扩展。其 Info.plist 包含 `AppleSecurityExtension`，以表明它是一项安全策略。  
- 在内核启动过程中，内核加载逻辑会确保“安全策略”（AMFI 等）在许多子系统依赖它们之前就已启用。例如，内核会“为接下来的任务做准备，加载……安全策略，包括 AppleMobileFileIntegrity (AMFI)、Sandbox、Quarantine policy。” 

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

## KPI 依赖项与 MAC policy kext 中的 com.apple.kpi.dsep

编写使用 MAC framework 的 kext（即调用 `mac_policy_register()` 等函数）时，必须声明对 KPI（Kernel Programming Interfaces）的依赖，以便 kext 链接器（kxld）解析这些符号。因此，要声明 `kext` 依赖 MACF，必须在 `Info.plist` 中通过 `com.apple.kpi.dsep` 指明（`find . Info.plist | grep AppleSecurityExtension`）。之后，kext 会引用 `mac_policy_register`、`mac_policy_unregister` 等符号，以及 MAC hook 函数指针。要解析这些符号，必须将 `com.apple.kpi.dsep` 列为依赖项。

`.kext` 中的 `Info.plist` 示例片段：

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



## 现代 macOS 版本中的 MACF

在现代 macOS 中，Apple 安全策略通常不适合被视为松散、独立的 `.kext` bundle。自 **macOS 11** 起，kernel extensions 会链接到 **kernel collections** 中；在 **Apple Silicon** 上，没有独立的 **SystemKC**，第三方 kext 只有在构建到 **Auxiliary Kernel Collection (AuxKC)** 并重启后，才能加载。对于 MACF 研究而言，这意味着使用 `kmutil` 枚举 **Sandbox**、**AMFI**、**AppleSystemPolicy**、**CoreTrust** 或 **Quarantine** 等内置策略，通常比使用 `kextstat` 等已弃用工具更方便。

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> 在 Apple Silicon 上，如果安全 kext 不在 BootKC 中，接下来检查 AuxKC。这通常比在 `/System/Library/Extensions` 下寻找独立 bundle 更有用。

## MACF 回调

在代码中找到 MACF 的调用点很常见，例如位于 **`#if CONFIG_MAC`** 条件块中。此外，在这些代码块内还可能找到调用 MACF 的 `mac_proc_check*`，用于**检查执行特定操作的权限**。此外，MACF 调用点的格式为：**`mac_<object>_<opType>_opName`**。

`object` 是以下其中之一：`bpfdesc`、`cred`、`file`、`proc`、`vnode`、`mount`、`devfs`、`ifnet`、`inpcb`、`mbuf`、`ipq`、`pipe`、`sysv[msg/msq/shm/sem]`、`posix[shm/sem]`、`socket`、`kext`。\
`opType` 通常是 check，用于允许或拒绝操作。不过，也可能会看到 `notify`，它允许 kext 对给定操作作出响应。

你可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) 找到一个示例：

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

接着，可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) 找到 `mac_file_check_mmap` 的代码。

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

它调用了 `MAC_CHECK` 宏，其代码可在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup> 中找到。

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

这会遍历已注册的策略，并使用 `mac_error_select()` 合并它们的结果。后续检查返回 0，无法覆盖先前的拒绝；如果多个策略都拒绝，函数会按优先级选择错误（例如，`EACCES` 优先于 `EPERM`）。<sup>[[2]](#references)</sup>

> [!TIP]
> 不过，请记住，并非所有 MACF callout 都只用于拒绝操作。例如，`mac_priv_grant` 会调用宏 [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274)；只要有任一策略返回 0，该宏就会授予请求的权限：
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

这些调用用于检查和提供 [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) 中定义的（数十种）**权限**。\
某些内核代码会调用 [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) 中的 `priv_check_cred()`，并传入进程的 KAuth 凭据和一个权限代码。该函数会调用 `mac_priv_check`，检查是否有策略**拒绝**授予该权限，然后调用 `mac_priv_grant`，检查是否有策略授予该 `privilege`。<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

此 hook 可以拦截所有系统调用。在 `bsd/dev/[i386|arm]/systemcalls.c` 中，可以看到声明的函数 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25)，其中包含以下代码：

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

它会检查调用进程中的 **bitmask**，以确定当前 syscall 是否应调用 `mac_proc_check_syscall_unix`。这是因为 syscall 的调用频率非常高，因此避免每次都调用 `mac_proc_check_syscall_unix` 很有意义。

请注意，函数 `proc_set_syscall_filter_mask()` 用于设置进程中的 syscall bitmask，由 Sandbox 调用，以便为受 sandbox 保护的进程设置掩码。

## 暴露的 MACF syscalls

可以通过 [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) 中定义的一些 syscall 与 MACF 交互：

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

对于 offensive reversing，**`__mac_syscall`** 仍是 userland 中最好的 chokepoint 之一。它携带一个**策略名称**（例如 `"Sandbox"` 或 `"AMFI"`）、一个**策略专用的 selector/code**，以及一个指向将由 `mpo_policy_syscall` 处理的**不透明参数 blob**的指针。反向分析未公开的操作时，这非常有用：可以先从 userland 入手，之后再转向 kernel 实现。Sandbox 通常通过 `__sandbox_ms` 调用它，而 AMFI 使用相同机制进行 dyld policy 决策。<sup>[[2]](#references)[[5]](#references)</sup>

## 实用 offensive 研究笔记

近期的 macOS bug 很少会直接“攻破 MACF”。相反，它们通常会利用 **MACF / Sandbox / TCC 决策与之后发生的特权操作之间的不同步**。

### 将策略专用的 spawn 属性作为 MACF 输入

`posix_spawnattr_setmacpolicyinfo_np()` 会将策略名称和不透明字节附加到 `posix_spawn()` 请求。XNU 会根据每个已注册策略的 `mpc_name` 查找这些字节，并将其传递给该策略的 exec-label hook；launch-constraints hook 也会读取对应的字节。这是独立于 `__mac_syscall` 的另一条由攻击者控制的 MACF 输入路径。审计策略如何处理这些字节：是将其视为*额外限制*，还是允许它们替换父进程或可执行文件已有的策略。<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

进行受控测试时，先从一个受限的父进程开始，分别在**不带**和**带有**策略专用属性的情况下启动同一个子进程。比较子进程对父进程无法使用的资源的有效访问权限；仅成功启动并不能证明跨越了安全边界。<sup>[[12]](#references)[[13]](#references)</sup>

反向分析策略时，跟踪 `mpo_cred_label_update_execve` 和 `mpo_proc_check_launch_constraints`，然后检查调用方是否可以提供该属性。<sup>[[10]](#references)[[11]](#references)</sup> AMFI 过去会接受用户提供的 launch constraints，而不是使用内置约束；Sandbox 可能会对子进程应用指定名称的内置 profile，而不是保留父进程的限制。<sup>[[13]](#references)[[12]](#references)</sup> 这两种行为都已修补，因此不要假设它们在当前系统上仍然存在。<sup>[[13]](#references)[[12]](#references)</sup>

AMFI 案例请参阅 [launch-constraints 分析](macos-launch-environment-constraints.md)；测试子进程的有效策略请参阅 [Sandbox 调试](macos-sandbox/macos-sandbox-debug-and-bypass/)。

### Broker 路径检查与实际特权操作

一种反复出现的模式是：特权 daemon 先对某个路径版本进行 **userland 预检查**（例如 `sandbox_check_by_audit_token()`），之后却使用**不同或非规范化的攻击者控制路径**执行真正的特权操作。近期对 `diskarbitrationd` / `storagekitd` 的研究就是一个很好的例子：**目录遍历**加上**符号链接交换**，让攻击者通过 daemon 的 sandbox 验证，随后再挂载到 `~/Library/Application Support/com.apple.TCC` 等敏感位置，从而根据所选挂载点将 bug 变成 **sandbox escape**、**本地权限提升**或 **TCC bypass**。<sup>[[6]](#references)</sup>

审计可从 sandbox 访问的 root broker 时，先 grep 查找：

- `sandbox_check`、`sandbox_check_by_audit_token`
- `realpath`、`CFURL*`、路径规范化辅助函数
- 特权 sink，例如 `mount`、`rename`、`copyfile`、helper-tool XPC 方法，或之后会以 root 身份处理攻击者控制路径的任何操作

### 持有私有 entitlement 的可信代理

另一种实用模式是不直接攻击 MACF hook，而是滥用一个已经拥有跨越边界所需权限的**可信进程**。近期的 Safari/TCC 研究就是一个很好的例子：关键原语并非“在 kernel 中禁用 TCC”，而是修改本地策略/配置，让带有 **`com.apple.private.tcc.allow`** 的 Apple 签名进程代你执行敏感操作。<sup>[[8]](#references)</sup> 实际审计时，高价值目标包括同时具备以下特征的 Apple daemon/app：

- **私有 entitlement** 或类似 FDA 的访问能力
- 可写的配置 / 数据库 / 挂载点 / 策略文件
- 后续会执行由 **Sandbox**、**AMFI**、**TCC** 或其他 MACF 策略仲裁的敏感操作

如需进行更深入的产品专项反向分析，请参阅 [macOS Sandbox](macos-sandbox/README.md) 和 [macOS TCC](macos-tcc/README.md) 专页。



## References

- [1] [XNU — `security/mac_policy.h`（完整的 MACF 策略操作向量）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c`（`mac_policy_register`、`__mac_syscall`）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h`（`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` 宏）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h`（`priv_check`/`priv_grant` 使用的权限代码）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall（Offensive Security）](https://www.offsec.com/blog/amfi-syscall/)
- [6] [发现 Apple 漏洞：diskarbitrationd 和 storagekitd 审计（第二部分）](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference 工具](https://newosxbook.com/xxr/index.php)
- [8] [新的 macOS 漏洞“HM Surf”可能导致未授权的数据访问（Microsoft Security Blog）](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — posix_spawn 策略属性设置器](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — 策略专用 exec-label 属性分派](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — launch-constraints 策略分派](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [通过启动可执行文件逃逸 Apple Sandbox](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [绕过 macOS 上的 Launch Constraints](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}

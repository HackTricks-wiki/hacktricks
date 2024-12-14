# macOS MIG - Mach Interface Generator

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

MIG was created to **simplify the process of Mach IPC** code creation. It basically **generates the needed code** for server and client to communicate with a given definition. Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

The definition is specified in Interface Definition Language (IDL) using the `.defs` extension.

These definitions have 5 sections:

* **Subsystem declaration**: The keyword subsystem is used to indicate the **name** and the **id**. It's also possible to mark it as **`KernelServer`** if the server should run in the kernel.
* **Inclusions and imports**: MIG uses the C-prepocessor, so it's able to use imports. Moreover, it's possible to use `uimport` and `simport` for user or server generated code.
* **Type declarations**: It's possible to define data types although usually it will import `mach_types.defs` and `std_types.defs`. For custom ones some syntax can be used:
  * \[i`n/out]tran`: Function that needs to be trasnlated from an incoming or to an outgoing message
  * `c[user/server]type`: Mapping to another C type.
  * `destructor`: Call this function when the type is released.
* **Operations**: These are the definitions of the RPC methods. There are 5 different types:
  * `routine`: Expects reply
  * `simpleroutine`: Doesn't expect reply
  * `procedure`: Expects reply
  * `simpleprocedure`: Doesn't expect reply
  * `function`: Expects reply

### Example

Create a definition file, in this case with a very simple function:

{% code title="myipc.defs" %}
```cpp
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
{% endcode %}

Note that the first **argument is the port to bind** and MIG will **automatically handle the reply port** (unless calling `mig_get_reply_port()` in the client code). Moreover, the **ID of the operations** will be **sequential** starting by the indicated subsystem ID (so if an operation is deprecated it's deleted and `skip` is used to still use its ID).

Now use MIG to generate the server and client code that will be able to communicate within each other to call the Subtract function:

```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```

Several new files will be created in the current directory.

{% hint style="success" %}
You can find a more complex example in your system with: `mdfind mach_port.defs`\
And you can compile it from the same folder as the file with: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`
{% endhint %}

In the files **`myipcServer.c`** and **`myipcServer.h`** you can find the declaration and definition of the struct **`SERVERPREFmyipc_subsystem`**, which basically defines the function to call based on the received message ID (we indicated a starting number of 500):

{% tabs %}
{% tab title="myipcServer.c" %}
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
{% endtab %}

{% tab title="myipcServer.h" %}
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
{% endtab %}
{% endtabs %}

Based on the previous struct the function **`myipc_server_routine`** will get the **message ID** and return the proper function to call:

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

In this example we have only defined 1 function in the definitions, but if we would have defined more functions, they would have been inside the array of **`SERVERPREFmyipc_subsystem`** and the first one would have been assigned to the ID **500**, the second one to the ID **501**...

If the function was expected to send a **reply** the function `mig_internal kern_return_t __MIG_check__Reply__<name>` would also exist.

Actually it's possible to identify this relation in the struct **`subsystem_to_name_map_myipc`** from **`myipcServer.h`** (**`subsystem_to_name_map_***`** in other files):

```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
    { "Subtract", 500 }
#endif
```

Finally, another important function to make the server work will be **`myipc_server`**, which is the one that will actually **call the function** related to the received id:

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

Check the previously highlighted lines accessing the function to call by ID.

The following is the code to create a simple **server** and **client** where the client can call the functions Subtract from the server:

{% tabs %}
{% tab title="myipc_server.c" %}
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
{% endtab %}

{% tab title="myipc_client.c" %}
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
{% endtab %}
{% endtabs %}

### The NDR\_record

The NDR\_record is exported by `libsystem_kernel.dylib`, and it's a struct that allows MIG to **transform data so it's agnostic of the system** it's being used as MIG was thought to be used between different systems (and not only in the same machine).

This is interesting because if `_NDR_record` is found in a binary as a dependency (`jtool2 -S <binary> | grep NDR` or `nm`), it means that the binary is a MIG client or Server.

Moreover **MIG servers** have the dispatch table in `__DATA.__const` (or in `__CONST.__constdata` in macOS kernel and `__DATA_CONST.__const` in other \*OS kernels). This can be dumped with **`jtool2`**.

And **MIG clients** will use the `__NDR_record` to send with `__mach_msg` to the servers.

## Binary Analysis

### jtool

As many binaries now use MIG to expose mach ports, it's interesting to know how to **identify that MIG was used** and the **functions that MIG executes** with each message ID.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) can parse MIG information from a Mach-O binary indicating the message ID and identifying the function to execute:

```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```

Moreover, MIG functions are just wrappers of the actual function that gets called, which means taht getting its dissasembly and grepping for BL you might be able to find the acatual function being called:

```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```

### Assembly

It was previously mentioned that the function that will take care of **calling the correct function depending on the received message ID** was `myipc_server`. However, you usually won't have the symbols of the binary (no functions names), so it's interesting to **check how it looks like decompiled** as it will always be very similar (the code of this function is independent from the functions exposed):

{% tabs %}
{% tab title="myipc_server decompiled 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
    var_10 = arg0;
    var_18 = arg1;
    // Initial instructions to find the proper function ponters
    *(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
    *(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
    *(int32_t *)(var_18 + 0x4) = 0x24;
    *(int32_t *)(var_18 + 0xc) = 0x0;
    *(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
    *(int32_t *)(var_18 + 0x10) = 0x0;
    if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
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
{% endtab %}

{% tab title="myipc_server decompiled 2" %}
This is the same function decompiled in a difefrent Hopper free version:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
    r31 = r31 - 0x40;
    saved_fp = r29;
    stack[-8] = r30;
    var_10 = arg0;
    var_18 = arg1;
    // Initial instructions to find the proper function ponters
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
                    // 0x1f4 = 500 (the strating ID)
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
                    // Same if else as in the previous version
                    // Check the used of the address 0x100004040 (functions addresses array)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
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
{% endtab %}
{% endtabs %}

Actually if you go to the function **`0x100004000`** you will find the array of **`routine_descriptor`** structs. The first element of the struct is the **address** where the **function** is implemented, and the **struct takes 0x28 bytes**, so each 0x28 bytes (starting from byte 0) you can get 8 bytes and that will be the **address of the function** that will be called:

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

This data can be extracted [**using this Hopper script**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

The code generated by MIG also calles `kernel_debug` to generate logs about operations on entry and exit. It's possible to check them using **`trace`** or **`kdv`**: `kdv all | grep MIG`

## References

* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


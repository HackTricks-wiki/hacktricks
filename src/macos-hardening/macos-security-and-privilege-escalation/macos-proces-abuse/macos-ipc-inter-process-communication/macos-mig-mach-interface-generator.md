# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

MIG, **Mach IPC** kodu oluşturma sürecini **basitleştirmek** için oluşturuldu. Verilen bir tanıma göre sunucunun ve istemcinin iletişim kurması için gereken kodu **oluşturur**. Oluşturulan kod çirkin olsa bile geliştiricinin yalnızca bu kodu içe aktarması yeterlidir; böylece kendi kodu öncekinden çok daha basit olur.<sup>[[1]](#references)</sup>

Tanım, `.defs` uzantısı kullanılarak Interface Definition Language (IDL) ile belirtilir.

Bu tanımların 5 bölümü vardır:

- **Alt sistem bildirimi**: `subsystem` anahtar sözcüğü **adı** ve **kimliği** belirtmek için kullanılır. Sunucunun kernel içinde çalışması gerekiyorsa **`KernelServer`** olarak işaretlenmesi de mümkündür.<sup>[[4]](#references)</sup>
- **Dahil etme ve içe aktarma**: MIG, C-preprocessor'ı kullanır; bu nedenle içe aktarmaları kullanabilir. Ayrıca kullanıcı veya sunucu için oluşturulan kodda `uimport` ve `simport` kullanmak mümkündür.
- **Tür bildirimleri**: Veri türleri tanımlamak mümkündür; ancak genellikle `mach_types.defs` ve `std_types.defs` içe aktarılır. Özel türler için bazı sözdizimleri kullanılabilir:
  - \[i`n/out]tran`: Gelen bir mesajdan veya giden bir mesaja çevrilmesi gereken işlev
  - `c[user/server]type`: Başka bir C türüyle eşleme.
  - `destructor`: Tür serbest bırakıldığında bu işlevi çağır.
- **İşlemler**: Bunlar RPC yöntemlerinin tanımlarıdır. 5 farklı tür vardır:
  - `routine`: Yanıt bekler
  - `simpleroutine`: Yanıt beklemez
  - `procedure`: Yanıt bekler
  - `simpleprocedure`: Yanıt beklemez
  - `function`: Yanıt bekler

### Örnek

Bu durumda çok basit bir işlev içeren bir tanım dosyası oluşturun:

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

İlk **argümanın bağlanılacak port** olduğunu ve MIG'in **yanıt portunu otomatik olarak yöneteceğini** (istemci kodunda `mig_get_reply_port()` çağrılmadığı sürece) unutmayın. Ayrıca **işlemlerin ID'leri**, belirtilen alt sistem ID'sinden başlayarak **ardışık** olacaktır (dolayısıyla bir işlem kullanımdan kaldırılırsa silinir ve ID'sini korumak için `skip` kullanılır).

Şimdi, Subtract işlevini çağırmak üzere birbirleriyle iletişim kurabilecek sunucu ve istemci kodunu oluşturmak için MIG kullanın:

```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```

Geçerli dizinde birkaç yeni dosya oluşturulacak.

> [!TIP]
> Sisteminizde daha karmaşık bir örneği şu komutla bulabilirsiniz: `mdfind mach_port.defs`\
> Ve dosyayla aynı klasörden şu komutla derleyebilirsiniz: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

**`myipcServer.c`** ve **`myipcServer.h`** dosyalarında, alınan mesaj ID'sine göre çağrılacak işlevi tanımlayan **`SERVERPREFmyipc_subsystem`** struct'ının bildirimi ve tanımını bulabilirsiniz (başlangıç numarasını 500 olarak belirttik):

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

Önceki struct'a göre **`myipc_server_routine`** fonksiyonu **message ID**'yi alır ve çağrılacak uygun fonksiyonu döndürür:

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

Bu örnekte definitions içinde yalnızca 1 function tanımladık; ancak daha fazla function tanımlamış olsaydık, bunlar **`SERVERPREFmyipc_subsystem`** dizisinin içinde yer alırdı ve ilkine **500**, ikincisine **501** ID'si atanırdı...

Function'ın bir **reply** göndermesi bekleniyorsa, `mig_internal kern_return_t __MIG_check__Reply__<name>` function'ı da bulunurdu.

Aslında bu ilişkiyi **`myipcServer.h`** içindeki **`subsystem_to_name_map_myipc`** struct'ında (**`subsystem*to_name_map*\***`** diğer dosyalarda) tespit etmek mümkündür:

```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
    { "Subtract", 500 }
#endif
```

Son olarak, sunucunun çalışmasını sağlayacak bir diğer önemli işlev **`myipc_server`** olacaktır. Bu işlev, alınan id ile ilişkili **işlevi çağırır**:<sup>[[3]](#references)</sup>

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

Çağrılacak işlevi ID'ye göre belirleyen, yukarıda vurgulanan satırları inceleyin.

Aşağıda, istemcinin sunucudaki Subtract işlevini çağırabildiği basit bir **sunucu** ve **istemci** oluşturmak için kullanılan kod yer alıyor:

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

NDR_record, `libsystem_kernel.dylib` tarafından dışa aktarılır ve MIG'in **verileri, kullanıldığı sistemden bağımsız olacak şekilde dönüştürmesini** sağlayan bir struct'tır. MIG'in aynı makinedeki sistemler arasında değil, farklı sistemler arasında kullanılacağı düşünülerek tasarlanmıştır.

Bu ilginçtir; çünkü `_NDR_record` bir binary'de bağımlılık olarak bulunursa (`jtool2 -S <binary> | grep NDR` veya `nm`), bu, binary'nin bir MIG client veya server olduğu anlamına gelir.

Ayrıca **MIG server'ların** dispatch tablosu `__DATA.__const` içinde (veya macOS kernel'de `__CONST.__constdata`, diğer \*OS kernel'lerinde ise `__DATA_CONST.__const` içinde) bulunur. Bu tablo **`jtool2`** ile dökümlenebilir.

**MIG client'lar** ise sunuculara `__mach_msg` ile mesaj göndermek için `__NDR_record` kullanır.

## Binary Analysis

### jtool

Pek çok binary artık mach port'larını kullanarak MIG'i dışa açtığından, **MIG'in kullanıldığını nasıl belirleyeceğinizi** ve her mesaj ID'siyle **MIG'in hangi fonksiyonları çalıştırdığını** bilmek faydalıdır.

[**jtool2 / disarm**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#disarm-old-jtool2), Mach-O binary'den MIG bilgilerini ayrıştırarak mesaj ID'sini belirtir ve çalıştırılacak fonksiyonu belirler:

```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```

Ayrıca, MIG fonksiyonları çağrılan asıl fonksiyonun etrafındaki sarmalayıcılardır. Bu nedenle, disassembly'yi alıp `BL` araması yaparak çağrılan asıl fonksiyonu bulabilirsiniz:

```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```

### Assembly

Daha önce, **alınan mesaj ID’sine göre doğru fonksiyonu çağıracak** fonksiyonun `myipc_server` olduğu belirtilmişti. Ancak genellikle binary’nin sembollerine (fonksiyon adlarına) sahip olmayacağınız için, decompile edildiğinde nasıl göründüğünü **incelemek** faydalıdır; çünkü bu fonksiyonun kodu, dışa açılan fonksiyonlardan bağımsızdır ve her zaman birbirine çok benzer:

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
Bu, aynı fonksiyonun Hopper'ın farklı bir ücretsiz sürümünde decompile edilmiş hâlidir:

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

Aslında **`0x100004000`** fonksiyonuna giderseniz, **`routine_descriptor`** struct dizisini bulabilirsiniz. Struct'ın ilk öğesi, **fonksiyonun** uygulandığı **adrestir** ve struct **0x28 bayt** uzunluğundadır. Bu nedenle, her 0x28 baytta bir (0. bayttan başlayarak) 8 bayt alabilir ve çağrılacak **fonksiyonun adresini** elde edebilirsiniz:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Bu veriler [**bu Hopper script'i kullanılarak**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) çıkarılabilir.

Stateful MIG mesaj dizilerini oluşturan ve fuzz eden bir iş akışı için bkz. [Stateful Mach IPC fuzzing](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#stateful-mach-ipc-fuzzing).

### Hata Ayıklama

MIG tarafından oluşturulan kod, giriş ve çıkıştaki işlemlerle ilgili loglar oluşturmak için `kernel_debug` işlevini de çağırır. Bunları **`trace`** veya **`kdv`** kullanarak inceleyebilirsiniz: `kdv all | grep MIG`



## References

- [1] [bootstrap_cmds — `migcom.tproj` (MIG derleyicisinin kendisi)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (örnek MIG alt sistemi tanımı)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (Mach mesaj başlığının düzeni)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (task alt sistemi MIG tanımı)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}

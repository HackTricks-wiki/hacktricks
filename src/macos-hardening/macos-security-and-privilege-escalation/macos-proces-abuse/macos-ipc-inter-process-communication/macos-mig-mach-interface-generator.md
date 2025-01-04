# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

MIG को **Mach IPC** कोड निर्माण की प्रक्रिया को सरल बनाने के लिए बनाया गया था। यह मूल रूप से **सर्वर और क्लाइंट के लिए आवश्यक कोड** उत्पन्न करता है ताकि एक दिए गए परिभाषा के साथ संवाद किया जा सके। भले ही उत्पन्न कोड बदसूरत हो, एक डेवलपर को केवल इसे आयात करने की आवश्यकता होगी और उसका कोड पहले से कहीं अधिक सरल होगा।

परिभाषा को इंटरफेस परिभाषा भाषा (IDL) में `.defs` एक्सटेंशन का उपयोग करके निर्दिष्ट किया गया है।

इन परिभाषाओं में 5 अनुभाग होते हैं:

- **Subsystem declaration**: कीवर्ड subsystem का उपयोग **नाम** और **id** को इंगित करने के लिए किया जाता है। यदि सर्वर को कर्नेल में चलाना है तो इसे **`KernelServer`** के रूप में चिह्नित करना भी संभव है।
- **Inclusions and imports**: MIG C-preprocessor का उपयोग करता है, इसलिए यह आयातों का उपयोग करने में सक्षम है। इसके अलावा, उपयोगकर्ता या सर्वर द्वारा उत्पन्न कोड के लिए `uimport` और `simport` का उपयोग करना संभव है।
- **Type declarations**: डेटा प्रकारों को परिभाषित करना संभव है, हालांकि आमतौर पर यह `mach_types.defs` और `std_types.defs` को आयात करेगा। कस्टम के लिए कुछ सिंटैक्स का उपयोग किया जा सकता है:
- \[i`n/out]tran`: फ़ंक्शन जिसे एक आने वाले या जाने वाले संदेश से अनुवादित करने की आवश्यकता है
- `c[user/server]type`: किसी अन्य C प्रकार के लिए मैपिंग।
- `destructor`: जब प्रकार को जारी किया जाता है तो इस फ़ंक्शन को कॉल करें।
- **Operations**: ये RPC विधियों की परिभाषाएँ हैं। 5 विभिन्न प्रकार हैं:
- `routine`: उत्तर की अपेक्षा करता है
- `simpleroutine`: उत्तर की अपेक्षा नहीं करता
- `procedure`: उत्तर की अपेक्षा करता है
- `simpleprocedure`: उत्तर की अपेक्षा नहीं करता
- `function`: उत्तर की अपेक्षा करता है

### Example

एक परिभाषा फ़ाइल बनाएं, इस मामले में एक बहुत सरल फ़ंक्शन के साथ:
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
ध्यान दें कि पहला **आर्गुमेंट बाइंड करने के लिए पोर्ट है** और MIG **स्वचालित रूप से उत्तर पोर्ट को संभालेगा** (जब तक कि क्लाइंट कोड में `mig_get_reply_port()` को कॉल नहीं किया जाता)। इसके अलावा, **ऑपरेशनों का ID** **क्रमिक** होगा जो निर्दिष्ट सबसिस्टम ID से शुरू होगा (इसलिए यदि कोई ऑपरेशन अप्रचलित है, तो इसे हटा दिया जाता है और इसके ID का उपयोग करने के लिए `skip` का उपयोग किया जाता है)।

अब MIG का उपयोग करें ताकि सर्वर और क्लाइंट कोड उत्पन्न किया जा सके जो एक-दूसरे के साथ संवाद कर सके और Subtract फ़ंक्शन को कॉल कर सके:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
कई नए फ़ाइलें वर्तमान निर्देशिका में बनाई जाएंगी।

> [!TIP]
> आप अपने सिस्टम में एक अधिक जटिल उदाहरण पा सकते हैं: `mdfind mach_port.defs`\
> और आप इसे फ़ाइल के समान फ़ोल्डर से संकलित कर सकते हैं: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

फ़ाइलों **`myipcServer.c`** और **`myipcServer.h`** में आप संरचना **`SERVERPREFmyipc_subsystem`** की घोषणा और परिभाषा पा सकते हैं, जो मूल रूप से प्राप्त संदेश ID के आधार पर कॉल करने के लिए फ़ंक्शन को परिभाषित करता है (हमने 500 की प्रारंभिक संख्या निर्दिष्ट की):

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

पिछली संरचना के आधार पर, फ़ंक्शन **`myipc_server_routine`** **संदेश आईडी** प्राप्त करेगा और कॉल करने के लिए उचित फ़ंक्शन लौटाएगा:
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
इस उदाहरण में हमने परिभाषाओं में केवल 1 फ़ंक्शन परिभाषित किया है, लेकिन यदि हम अधिक फ़ंक्शन परिभाषित करते, तो वे **`SERVERPREFmyipc_subsystem`** के ऐरे के अंदर होते और पहला फ़ंक्शन ID **500** को सौंपा जाता, दूसरा फ़ंक्शन ID **501** को...

यदि फ़ंक्शन से **reply** भेजने की अपेक्षा की जाती, तो फ़ंक्शन `mig_internal kern_return_t __MIG_check__Reply__<name>` भी मौजूद होता।

वास्तव में, इस संबंध की पहचान **`myipcServer.h`** में **`subsystem_to_name_map_myipc`** संरचना में की जा सकती है (**`subsystem*to_name_map*\***`\*\* अन्य फ़ाइलों में):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
अंत में, सर्वर को काम करने के लिए एक और महत्वपूर्ण फ़ंक्शन होगा **`myipc_server`**, जो वास्तव में प्राप्त id से संबंधित **फ़ंक्शन को कॉल करेगा**:

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
/* न्यूनतम आकार: routine() इसे अपडेट करेगा यदि अलग हो */
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

पहले हाइलाइट की गई पंक्तियों की जांच करें जो ID द्वारा कॉल करने के लिए फ़ंक्शन को एक्सेस कर रही हैं।

निम्नलिखित सरल **सर्वर** और **क्लाइंट** बनाने का कोड है जहाँ क्लाइंट सर्वर से Subtract फ़ंक्शन को कॉल कर सकता है:

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

NDR_record को `libsystem_kernel.dylib` द्वारा निर्यात किया जाता है, और यह एक संरचना है जो MIG को **डेटा को इस तरह से परिवर्तित करने की अनुमति देती है कि यह उस सिस्टम के प्रति अज्ञेय हो** जिस पर इसका उपयोग किया जा रहा है क्योंकि MIG को विभिन्न सिस्टमों के बीच उपयोग करने के लिए सोचा गया था (और केवल एक ही मशीन में नहीं)।

यह दिलचस्प है क्योंकि यदि `_NDR_record` किसी बाइनरी में एक निर्भरता के रूप में पाया जाता है (`jtool2 -S <binary> | grep NDR` या `nm`), तो इसका मतलब है कि बाइनरी एक MIG क्लाइंट या सर्वर है।

इसके अलावा **MIG सर्वर** में `__DATA.__const` (या macOS कर्नेल में `__CONST.__constdata` और अन्य \*OS कर्नेल में `__DATA_CONST.__const`) में डिस्पैच टेबल होती है। इसे **`jtool2`** के साथ डंप किया जा सकता है।

और **MIG क्लाइंट** `__mach_msg` के साथ सर्वरों को भेजने के लिए `__NDR_record` का उपयोग करेंगे।

## बाइनरी विश्लेषण

### jtool

जैसे कि कई बाइनरी अब MACH पोर्ट्स को उजागर करने के लिए MIG का उपयोग करती हैं, यह जानना दिलचस्प है कि **कैसे पहचानें कि MIG का उपयोग किया गया था** और **फंक्शंस जो MIG प्रत्येक संदेश ID के साथ निष्पादित करता है**।

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) एक Mach-O बाइनरी से MIG जानकारी को पार्स कर सकता है, जो संदेश ID को इंगित करता है और निष्पादित करने के लिए फंक्शन की पहचान करता है:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
इसके अलावा, MIG फ़ंक्शन वास्तव में उस वास्तविक फ़ंक्शन के रैपर हैं जिसे कॉल किया जाता है, जिसका अर्थ है कि इसके डिस्सेम्बली को प्राप्त करना और BL के लिए ग्रेपिंग करना आपको उस वास्तविक फ़ंक्शन को खोजने में सक्षम बना सकता है जिसे कॉल किया जा रहा है:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

यह पहले उल्लेख किया गया था कि वह फ़ंक्शन जो **प्राप्त संदेश ID के आधार पर सही फ़ंक्शन को कॉल करेगा** वह `myipc_server` था। हालाँकि, आपके पास आमतौर पर बाइनरी के प्रतीक नहीं होंगे (कोई फ़ंक्शन नाम नहीं), इसलिए यह दिलचस्प है कि **यह डिकंपाइल्ड में कैसा दिखता है** क्योंकि यह हमेशा बहुत समान होगा (इस फ़ंक्शन का कोड उन फ़ंक्शनों से स्वतंत्र है जो प्रदर्शित होते हैं):

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// उचित फ़ंक्शन पॉइंटर्स खोजने के लिए प्रारंभिक निर्देश
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// sign_extend_64 को कॉल करना जो इस फ़ंक्शन की पहचान करने में मदद कर सकता है
// यह rax में उस कॉल का पॉइंटर स्टोर करता है जिसे कॉल करने की आवश्यकता है
// 0x100004040 (फ़ंक्शनों के पते की सरणी) के पते का उपयोग जांचें
// 0x1f4 = 500 (शुरुआती ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// यदि - अन्यथा, यदि वापस false लौटता है, जबकि अन्यथा सही फ़ंक्शन को कॉल करता है और true लौटाता है
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// 2 तर्कों के साथ उचित फ़ंक्शन को कॉल करने का पता लगाया गया
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
यह एक अलग Hopper मुफ्त संस्करण में डिकंपाइल्ड वही फ़ंक्शन है:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// उचित फ़ंक्शन पॉइंटर्स खोजने के लिए प्रारंभिक निर्देश
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
// 0x1f4 = 500 (शुरुआती ID)
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
// पिछले संस्करण के समान यदि अन्यथा
// 0x100004040 (फ़ंक्शनों के पते की सरणी) के पते का उपयोग जांचें
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// उस पता को कॉल करें जहाँ फ़ंक्शन होना चाहिए
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

वास्तव में, यदि आप फ़ंक्शन **`0x100004000`** पर जाते हैं, तो आप **`routine_descriptor`** संरचनाओं की सरणी पाएंगे। संरचना का पहला तत्व वह **पता** है जहाँ **फ़ंक्शन** लागू किया गया है, और **संरचना 0x28 बाइट्स लेती है**, इसलिए प्रत्येक 0x28 बाइट्स (बाइट 0 से शुरू) आप 8 बाइट्स प्राप्त कर सकते हैं और वह **फ़ंक्शन का पता** होगा जिसे कॉल किया जाएगा:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

इस डेटा को [**इस Hopper स्क्रिप्ट का उपयोग करके निकाला जा सकता है**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

MIG द्वारा उत्पन्न कोड भी `kernel_debug` को कॉल करता है ताकि प्रवेश और निकासी पर संचालन के बारे में लॉग उत्पन्न किया जा सके। इन्हें **`trace`** या **`kdv`** का उपयोग करके जांचा जा सकता है: `kdv all | grep MIG`

## References

- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}

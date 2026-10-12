# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Context

Linux आम तौर पर डिस्क या memory में संग्रहीत executable files से programs चलाता है। यह किसी executable की पहचान pathname या file descriptor से कर सकता है, इसलिए सामान्य filesystem pathname हमेशा आवश्यक नहीं होता।<sup>[[2]](#references)</sup>

DDexec / EverythingExec एक **पहले से चल रही process** की memory का उपयोग करता है। [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) पेज anonymous-file execution और उससे जुड़ी detection तथा forensic collection को कवर करता है; [Memory Bypasses overview](index.html#memory-bypasses) में MemExec और Memdlopen के links भी हैं।<sup>[[1]](#references)</sup>

यह technique आपको **read-only, noexec, file-name whitelisting, hash whitelisting जैसी आम protection techniques को bypass** करने देती है।<sup>[[1]](#references)</sup>

## Dependencies

अंतिम script को काम करने के लिए नीचे दिए गए tools की ज़रूरत होती है। ये उस system पर उपलब्ध होने चाहिए जिस पर आप attack कर रहे हैं (डिफ़ॉल्ट रूप से, ये सभी आपको हर जगह मिल जाएंगे):

```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```

## यह तकनीक

अगर आप किसी process की memory को मनमाने ढंग से modify कर सकते हैं, तो आप उस पर नियंत्रण कर सकते हैं। इसका उपयोग पहले से चल रहे process को hijack करके उसकी जगह कोई दूसरा program चलाने के लिए किया जा सकता है। हम यह `ptrace()` syscall का उपयोग करके (जिसके लिए आपके पास syscalls execute करने की क्षमता या system पर gdb उपलब्ध होना ज़रूरी है) या, अधिक दिलचस्प तरीके से, `/proc/$pid/mem` में लिखकर कर सकते हैं।<sup>[[1]](#references)</sup>

फ़ाइल `/proc/$pid/mem` किसी process के पूरे address space की one-to-one mapping होती है (_जैसे_, x86-64 में `0x0000000000000000` से `0x7ffffffffffff000` तक)। इसका मतलब है कि इस फ़ाइल में offset `x` से पढ़ना या उसमें लिखना, virtual address `x` पर मौजूद सामग्री को पढ़ने या modify करने के समान है।

अब, हमें चार बुनियादी समस्याओं का सामना करना पड़ता है:

- आम तौर पर, केवल root और फ़ाइल का owner program ही इसे modify कर सकते हैं।
- ASLR।
- अगर हम किसी ऐसे address को पढ़ने या लिखने की कोशिश करते हैं जो program के address space में mapped नहीं है, तो हमें I/O error मिलेगा।

इन समस्याओं के समाधान हैं। वे भले ही पूरी तरह सही न हों, लेकिन कारगर हैं:

- ज़्यादातर shell interpreters ऐसे file descriptors बनाने देते हैं जो child processes को inherit होते हैं। हम write permissions के साथ shell की `mem` फ़ाइल की ओर इंगित करने वाला fd बना सकते हैं... ताकि उस fd का उपयोग करने वाले child processes shell की memory modify कर सकें।
- ASLR कोई समस्या नहीं है; process के address space की जानकारी पाने के लिए हम shell की `maps` फ़ाइल या procfs की किसी अन्य फ़ाइल को देख सकते हैं।
- इसलिए हमें फ़ाइल में `lseek()` करना होगा। Shell से यह `dd` के बिना नहीं किया जा सकता, जो इस काम के लिए कुख्यात है।

### विस्तार से

ये चरण काफ़ी आसान हैं और इन्हें समझने के लिए किसी खास विशेषज्ञता की ज़रूरत नहीं है:<sup>[[1]](#references)</sup>

- जिस binary को हम चलाना चाहते हैं और loader को parse करके पता लगाएँ कि उन्हें किन mappings की ज़रूरत है। फिर ऐसा "shell"code तैयार करें जो मोटे तौर पर वही चरण पूरे करेगा जो kernel हर `execve()` call पर करता है:
  - उक्त mappings बनाएँ।
  - Binaries को उनमें पढ़ें।
  - Permissions सेट करें।
  - अंत में, program के arguments के साथ stack initialize करें और auxiliary vector रखें (जिसकी loader को ज़रूरत होती है)।
  - Loader में jump करें और उसे बाकी काम करने दें (program के लिए ज़रूरी libraries load करना)।
- `syscall` फ़ाइल से वह address प्राप्त करें जहाँ syscall पूरा होने के बाद process लौटेगा।
- उस जगह को, जो executable होगी, हमारे shellcode से overwrite करें (`mem` के ज़रिए हम unwritable pages modify कर सकते हैं)।
- जिस program को हम चलाना चाहते हैं, उसे process के stdin में भेजें (उक्त "shell"code उसे `read()` करेगा)।
- इस बिंदु पर, हमारे program के लिए ज़रूरी libraries load करना और उसमें jump करना loader का काम है।

**इस tool को देखें:** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

`dd` के कई विकल्प हैं। उनमें से एक `tail` है, जो फ़िलहाल `mem` फ़ाइल में `lseek()` करने के लिए इस्तेमाल किया जाने वाला default program है (`dd` का उपयोग करने का एकमात्र उद्देश्य यही था)। ये विकल्प हैं:<sup>[[1]](#references)</sup>

```bash
tail
hexdump
cmp
xxd
```

`SEEKER` variable सेट करके, आप इस्तेमाल किए जाने वाले seeker को बदल सकते हैं, _जैसे_:

```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

यदि आपको कोई अन्य मान्य seeker मिलता है जो script में लागू नहीं है, तो भी आप `SEEKER_ARGS` variable सेट करके उसका उपयोग कर सकते हैं:

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

इसे ब्लॉक करो, EDRs.

## References

- [1] [DDexec: Linux पर binaries को बिना फ़ाइल के और चोरी-छिपे चलाने की तकनीक](https://github.com/arget13/DDexec)
- [2] [execveat(2) — Linux मैनुअल पेज](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}

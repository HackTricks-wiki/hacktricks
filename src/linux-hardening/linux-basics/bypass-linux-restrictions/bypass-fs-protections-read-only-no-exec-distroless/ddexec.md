# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Context

Linux में किसी program को run करने के लिए उसका file के रूप में मौजूद होना आवश्यक है और file system hierarchy के माध्यम से उस तक किसी तरह पहुंच होनी चाहिए (यह बस `execve()` के काम करने का तरीका है)। यह file disk या ram (tmpfs, memfd) में हो सकती है, लेकिन आपको एक filepath की आवश्यकता होती है। इससे Linux system पर क्या run किया जा रहा है, इसे नियंत्रित करना, threats और attacker's tools का पता लगाना, या उन्हें अपनी कोई भी चीज execute करने से पूरी तरह रोकना बहुत आसान हो जाता है (_e. g._ unprivileged users को कहीं भी executable files रखने की अनुमति न देना)।

लेकिन यह technique इन सबको बदलने के लिए है। यदि आप अपनी इच्छित process start नहीं कर सकते... **तो पहले से मौजूद process को hijack कर लें**।

यह technique **read-only, noexec, file-name whitelisting, hash whitelisting जैसी सामान्य protection techniques को bypass** करने की अनुमति देती है...<sup>[[1]](#references)</sup>

## Dependencies

अंतिम script के काम करने के लिए निम्नलिखित tools पर निर्भर करती है। जिस system पर आप attack कर रहे हैं, उसमें इन tools का accessible होना आवश्यक है (डिफ़ॉल्ट रूप से आपको ये सभी हर जगह मिल जाएंगे):
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
## तकनीक

यदि आप किसी process की memory को मनमाने ढंग से modify कर सकते हैं, तो आप उस पर नियंत्रण कर सकते हैं। इसका उपयोग पहले से मौजूद process को hijack करके उसे किसी अन्य program से replace करने के लिए किया जा सकता है। हम इसे या तो `ptrace()` syscall का उपयोग करके प्राप्त कर सकते हैं (जिसके लिए आपके पास syscalls execute करने की क्षमता या system पर gdb उपलब्ध होना आवश्यक है), या अधिक रोचक रूप से, `/proc/$pid/mem` में लिखकर।<sup>[[1]](#references)</sup>

फ़ाइल `/proc/$pid/mem` किसी process के पूरे address space की one-to-one mapping होती है (_जैसे_, x86-64 में `0x0000000000000000` से `0x7ffffffffffff000` तक)। इसका अर्थ है कि इस फ़ाइल से offset `x` पर पढ़ना या लिखना, virtual address `x` पर मौजूद contents को पढ़ने या modify करने के समान है।

अब, हमारे सामने चार बुनियादी समस्याएँ हैं:

- सामान्य रूप से, केवल root और फ़ाइल का program owner ही इसे modify कर सकते हैं।
- ASLR।
- यदि हम program के address space में mapped न किए गए address को पढ़ने या उसमें लिखने का प्रयास करते हैं, तो हमें I/O error मिलेगा।

इन समस्याओं के समाधान हैं, हालांकि वे पूर्ण नहीं हैं, फिर भी उपयोगी हैं:

- अधिकांश shell interpreters ऐसे file descriptors बनाने की अनुमति देते हैं जो child processes द्वारा inherit किए जाते हैं। हम write permissions के साथ shell की `mem` फ़ाइल की ओर संकेत करने वाला एक fd बना सकते हैं... इसलिए उस fd का उपयोग करने वाले child processes shell की memory को modify कर पाएँगे।
- ASLR वास्तव में कोई समस्या नहीं है; process के address space के बारे में जानकारी प्राप्त करने के लिए हम shell की `maps` फ़ाइल या procfs की किसी अन्य फ़ाइल को check कर सकते हैं।
- इसलिए हमें फ़ाइल पर `lseek()` करना होगा। Shell से यह तब तक नहीं किया जा सकता जब तक कि infamous `dd` का उपयोग न किया जाए।

### अधिक विस्तार से

Steps अपेक्षाकृत आसान हैं और उन्हें समझने के लिए किसी विशेष expertise की आवश्यकता नहीं है:<sup>[[1]](#references)</sup>

- उस binary और loader को parse करें जिसे हम run करना चाहते हैं, ताकि पता चल सके कि उन्हें किन mappings की आवश्यकता है। फिर एक "shell"code तैयार करें जो व्यापक रूप से वे ही steps perform करेगा जो kernel, `execve()` की प्रत्येक call पर करता है:
- उक्त mappings बनाएँ।
- Binaries को उनमें read करें।
- Permissions set up करें।
- अंत में program के arguments के साथ stack को initialize करें और auxiliary vector रखें (जिसकी loader को आवश्यकता होती है)।
- Loader में jump करें और बाकी काम उसे करने दें (program के लिए आवश्यक libraries load करना)।
- `syscall` फ़ाइल से उस address को प्राप्त करें जहाँ syscall execute करने के बाद process return करेगा।
- उस स्थान को, जो executable होगा, हमारे shellcode से overwrite करें (`mem` के माध्यम से हम unwritable pages को modify कर सकते हैं)।
- जिस program को हम run करना चाहते हैं, उसे process के stdin में pass करें (उक्त "shell"code द्वारा `read()` किया जाएगा)।
- इस बिंदु पर हमारे program के लिए आवश्यक libraries load करना और उसमें jump करना loader का काम है।

**इस tool को देखें:** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)<sup>[[1]](#references)</sup>

## EverythingExec

`dd` के कई alternatives हैं, जिनमें से एक, `tail`, वर्तमान में `mem` फ़ाइल के माध्यम से `lseek()` करने के लिए उपयोग किया जाने वाला default program है (और यही `dd` के उपयोग का एकमात्र उद्देश्य था)। उक्त alternatives हैं:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Variable `SEEKER` सेट करके आप उपयोग किए जाने वाले seeker को बदल सकते हैं, _जैसे_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
यदि आपको script में implement नहीं किया गया कोई अन्य valid seeker मिलता है, तो भी आप `SEEKER_ARGS` variable सेट करके उसका उपयोग कर सकते हैं:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
EDRs, इसे block करें।

## संदर्भ

- [1] [DDexec: A technique to run binaries filelessly and stealthily on Linux](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}

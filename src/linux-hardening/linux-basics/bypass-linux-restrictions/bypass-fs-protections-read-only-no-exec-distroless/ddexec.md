# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## संदर्भ

Linux में किसी program को run करने के लिए उसका file के रूप में मौजूद होना आवश्यक है, और file system hierarchy के माध्यम से किसी तरह accessible होना चाहिए (यह बस इसी तरह `execve()` काम करता है)। यह file disk या ram (tmpfs, memfd) में हो सकती है, लेकिन आपको एक filepath की आवश्यकता होती है। इससे Linux system पर क्या run किया जा रहा है, इसे control करना बहुत आसान हो जाता है; threats और attacker's tools का पता लगाना आसान होता है, या उन्हें अपनी कोई भी चीज़ execute करने से पूरी तरह रोकना आसान होता है (_जैसे_ unprivileged users को कहीं भी executable files रखने की अनुमति न देना)।

लेकिन यह technique इन सबको बदलने के लिए है। यदि आप मनचाहे process को start नहीं कर सकते... **तो पहले से मौजूद process को hijack कर लें**।

यह technique आपको **read-only, noexec, file-name whitelisting, hash whitelisting जैसी common protection techniques को bypass** करने की अनुमति देती है।<sup>[[1]](#references)</sup>

## Dependencies

Final script को काम करने के लिए निम्नलिखित tools पर निर्भरता होती है; जिस system पर आप attack कर रहे हैं, उसमें इनका accessible होना आवश्यक है (by default ये सभी आपको हर जगह मिल जाएंगे):
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
## The technique

यदि आप किसी process की memory को मनमाने ढंग से modify कर सकते हैं, तो आप उस पर नियंत्रण प्राप्त कर सकते हैं। इसका उपयोग पहले से मौजूद process को hijack करके उसे किसी अन्य program से replace करने के लिए किया जा सकता है। हम इसे या तो `ptrace()` syscall का उपयोग करके प्राप्त कर सकते हैं (जिसके लिए आपके पास syscalls execute करने की क्षमता या system पर gdb उपलब्ध होना आवश्यक है), या अधिक रोचक रूप से, `/proc/$pid/mem` में लिखकर।<sup>[[1]](#references)</sup>

फ़ाइल `/proc/$pid/mem` किसी process के पूरे address space का one-to-one mapping होती है (_e. g._ x86-64 में `0x0000000000000000` से `0x7ffffffffffff000` तक)। इसका अर्थ है कि इस फ़ाइल से offset `x` पर पढ़ना या लिखना, virtual address `x` पर मौजूद contents को पढ़ने या modify करने के समान है।

अब, हमारे सामने चार basic समस्याएँ हैं:

- सामान्यतः केवल root और फ़ाइल का program owner ही इसे modify कर सकते हैं।
- ASLR।
- यदि हम program के address space में mapped न किए गए address को पढ़ने या लिखने का प्रयास करते हैं, तो हमें I/O error मिलेगा।

इन समस्याओं के solutions हैं, जो पूर्ण नहीं होने के बावजूद उपयोगी हैं:

- अधिकांश shell interpreters ऐसे file descriptors बनाने की अनुमति देते हैं, जो child processes को inherit हो जाते हैं। हम write permissions के साथ shell की `mem` फ़ाइल की ओर संकेत करने वाला fd बना सकते हैं... इसलिए उस fd का उपयोग करने वाले child processes shell की memory को modify कर सकेंगे।
- ASLR कोई समस्या भी नहीं है; process के address space के बारे में जानकारी प्राप्त करने के लिए हम shell की `maps` फ़ाइल या procfs की किसी अन्य फ़ाइल को देख सकते हैं।
- इसलिए हमें फ़ाइल पर `lseek()` करना होगा। Shell से यह नहीं किया जा सकता, जब तक कि प्रसिद्ध `dd` का उपयोग न किया जाए।

### In more detail

Steps अपेक्षाकृत आसान हैं और उन्हें समझने के लिए किसी विशेष expertise की आवश्यकता नहीं है:<sup>[[1]](#references)</sup>

- उस binary और loader को parse करें जिसे हम run करना चाहते हैं, ताकि पता चल सके कि उन्हें किन mappings की आवश्यकता है। फिर ऐसा "shell"code तैयार करें जो व्यापक रूप से वे सभी steps execute करे, जो kernel `execve()` के प्रत्येक call पर करता है:
- उक्त mappings बनाएँ।
- Binaries को उनमें read करें।
- Permissions set up करें।
- अंत में program के arguments के साथ stack initialize करें और auxiliary vector रखें (जिसकी loader को आवश्यकता होती है)।
- Loader में jump करें और बाकी काम उसे करने दें (program के लिए आवश्यक libraries load करना)।
- `syscall` फ़ाइल से वह address प्राप्त करें, जिस पर process अपने द्वारा execute किए जा रहे syscall के बाद return करेगा।
- उस स्थान को overwrite करें, जो executable होगा, अपने shellcode से (`mem` के माध्यम से हम unwritable pages को modify कर सकते हैं)।
- जिस program को हम run करना चाहते हैं, उसे process के stdin में pass करें (जिसे उक्त "shell"code द्वारा `read()` किया जाएगा)।
- इस बिंदु पर हमारे program के लिए आवश्यक libraries load करना और उसमें jump करना loader का काम है।

**Check out the tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)।<sup>[[1]](#references)</sup>

## EverythingExec

`dd` के कई alternatives हैं, जिनमें से एक `tail` है। वर्तमान में `mem` फ़ाइल के माध्यम से `lseek()` करने के लिए default program के रूप में `tail` का उपयोग किया जाता है (और `dd` का उपयोग करने का यही एकमात्र उद्देश्य था)। ऐसे alternatives हैं:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
वेरिएबल `SEEKER` सेट करके आप उपयोग किए जाने वाले `seeker` को बदल सकते हैं, _उदा._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
यदि आपको script में implement न किया गया कोई अन्य valid seeker मिलता है, तो भी आप `SEEKER_ARGS` variable सेट करके उसका उपयोग कर सकते हैं:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
इसे block करें, EDRs।

## References

- [1] [DDexec: Linux पर binaries को filelessly और stealthily चलाने की एक technique](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}

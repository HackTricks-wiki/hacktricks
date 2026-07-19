# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Context

Linux में किसी program को चलाने के लिए उसका file के रूप में मौजूद होना आवश्यक है और file system hierarchy के माध्यम से किसी तरह accessible होना चाहिए (यह बस `execve()` के काम करने का तरीका है)। यह file disk या ram (tmpfs, memfd) में हो सकती है, लेकिन आपके पास एक filepath होना आवश्यक है। इससे Linux system पर क्या चलाया जा रहा है, इसे नियंत्रित करना बहुत आसान हो जाता है; threats और attacker's tools का पता लगाना आसान होता है या उन्हें अपनी कोई भी चीज़ execute करने से पूरी तरह रोका जा सकता है (_e. g._ unprivileged users को कहीं भी executable files रखने की अनुमति न देना)।

लेकिन यह technique इन सभी चीज़ों को बदलने के लिए है। यदि आप अपने इच्छित process को start नहीं कर सकते... **तो पहले से मौजूद किसी process को hijack कर लें**।

यह technique **read-only, noexec, file-name whitelisting, hash whitelisting जैसी common protection techniques को bypass करने** की अनुमति देती है...

## Dependencies

Final script को काम करने के लिए निम्नलिखित tools पर निर्भरता होती है; जिस system पर आप attack कर रहे हैं, उसमें इनका accessible होना आवश्यक है (default रूप से ये सभी आपको हर जगह मिल जाएंगे):
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

यदि आप किसी process की memory को मनमाने ढंग से modify कर सकते हैं, तो आप उस पर takeover कर सकते हैं। इसका उपयोग पहले से मौजूद process को hijack करके उसे किसी अन्य program से replace करने के लिए किया जा सकता है। हम इसे या तो `ptrace()` syscall का उपयोग करके प्राप्त कर सकते हैं (जिसके लिए syscalls execute करने की क्षमता या system पर gdb उपलब्ध होना आवश्यक है), या अधिक दिलचस्प तरीके से, `/proc/$pid/mem` में लिखकर।

फ़ाइल `/proc/$pid/mem` किसी process के पूरे address space की one-to-one mapping है (_e. g._ x86-64 में `0x0000000000000000` से `0x7ffffffffffff000` तक)। इसका अर्थ है कि इस फ़ाइल से offset `x` पर पढ़ना या लिखना, virtual address `x` पर मौजूद contents को पढ़ने या modify करने के समान है।

अब, हमारे सामने चार basic समस्याएँ हैं:

- सामान्यतः केवल root और फ़ाइल का program owner ही इसे modify कर सकते हैं।
- ASLR।
- यदि हम ऐसे address को read या write करने का प्रयास करते हैं जो program के address space में mapped नहीं है, तो हमें I/O error मिलेगा।

इन समस्याओं के solutions हैं, जो पूर्ण नहीं होने के बावजूद उपयोगी हैं:

- अधिकांश shell interpreters ऐसे file descriptors बनाने की अनुमति देते हैं, जो child processes द्वारा inherit किए जाते हैं। हम write permissions के साथ shell की `mem` फ़ाइल की ओर point करने वाला fd बना सकते हैं... इसलिए उस fd का उपयोग करने वाले child processes shell की memory को modify कर सकेंगे।
- ASLR समस्या भी नहीं है; process के address space के बारे में जानकारी प्राप्त करने के लिए हम shell की `maps` फ़ाइल या procfs की किसी अन्य फ़ाइल को check कर सकते हैं।
- इसलिए हमें फ़ाइल पर `lseek()` करना होगा। shell से यह तब तक नहीं किया जा सकता, जब तक infamous `dd` का उपयोग न किया जाए।

### अधिक विस्तार से

Steps अपेक्षाकृत आसान हैं और इन्हें समझने के लिए किसी विशेष expertise की आवश्यकता नहीं है:

- जिस binary को हम run करना चाहते हैं और loader को parse करके यह पता लगाएँ कि उन्हें किन mappings की आवश्यकता है। फिर ऐसा "shell"code तैयार करें जो व्यापक रूप से वही steps perform करे, जो kernel `execve()` की प्रत्येक call पर करता है:
- उक्त mappings बनाएँ।
- Binaries को उनमें read करें।
- Permissions set up करें।
- अंत में program के arguments के साथ stack को initialize करें और auxiliary vector रखें (जिसकी loader को आवश्यकता होती है)।
- Loader में jump करें और बाकी कार्य उसे करने दें (program के लिए आवश्यक libraries load करना)।
- `syscall` फ़ाइल से वह address प्राप्त करें, जिस पर process execute हो रही syscall के बाद return करेगा।
- उस स्थान को, जो executable होगा, हमारे shellcode से overwrite करें (`mem` के माध्यम से हम unwritable pages को modify कर सकते हैं)।
- जिस program को हम run करना चाहते हैं, उसे process के stdin में pass करें (उक्त "shell"code द्वारा `read()` किया जाएगा)।
- इस बिंदु पर हमारे program के लिए आवश्यक libraries load करना और उसमें jump करना loader की जिम्मेदारी है।

**Tool को यहाँ देखें:** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

`dd` के कई alternatives हैं। उनमें से एक `tail` है, जो वर्तमान में `mem` फ़ाइल में `lseek()` करने के लिए default program है (और `dd` का उपयोग करने का यही एकमात्र उद्देश्य था)। ये alternatives हैं:
```bash
tail
hexdump
cmp
xxd
```
`SEEKER` variable सेट करके, आप उपयोग किए जाने वाले seeker को बदल सकते हैं, _उदाहरण के लिए_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
यदि आपको script में implement न किया गया कोई अन्य valid seeker मिलता है, तो भी आप `SEEKER_ARGS` variable सेट करके उसका उपयोग कर सकते हैं:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
इसे block करें, EDRs।

## संदर्भ

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}

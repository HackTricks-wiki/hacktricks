# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

UTS namespace process द्वारा देखे जाने वाले **hostname** और **NIS domain name** को अलग करता है। पहली नज़र में यह mount, PID या user namespaces की तुलना में मामूली लग सकता है, लेकिन यह container को अपने अलग host जैसा दिखाने में महत्वपूर्ण भूमिका निभाता है। इस namespace के अंदर workload ऐसा hostname देख सकता है और कभी-कभी बदल भी सकता है, जो मशीन के लिए global होने के बजाय उस namespace तक सीमित होता है।

अपने आप में, यह आमतौर पर breakout story का मुख्य केंद्र नहीं होता। हालांकि, जब host UTS namespace साझा किया जाता है, तो पर्याप्त privileges वाला process host की identity-related settings को प्रभावित कर सकता है, जो operational रूप से महत्वपूर्ण और कभी-कभी security के लिहाज़ से भी प्रभाव डाल सकता है।

## Lab

आप इस command से UTS namespace बना सकते हैं:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
hostname में किया गया बदलाव उसी namespace तक सीमित रहता है और host के global hostname को नहीं बदलता। यह isolation property का एक सरल लेकिन प्रभावी प्रदर्शन है।

## Runtime उपयोग

सामान्य containers को एक isolated UTS namespace मिलता है। Docker और Podman `--uts=host` के माध्यम से host UTS namespace से जुड़ सकते हैं, और इसी तरह के host-sharing patterns अन्य runtimes और orchestration systems में भी दिखाई दे सकते हैं। हालांकि, अधिकांश समय private UTS isolation सामान्य container setup का ही हिस्सा होती है और इसके लिए operator का बहुत कम ध्यान आवश्यक होता है।

## Security प्रभाव

हालांकि UTS namespace आमतौर पर share किए जाने वाले सबसे खतरनाक namespaces में से नहीं है, फिर भी यह container boundary की integrity में योगदान देता है। यदि host UTS namespace exposed हो और process के पास आवश्यक privileges हों, तो वह host की hostname-related information को बदलने में सक्षम हो सकता है। इससे monitoring, logging, operational assumptions या host identity data के आधार पर trust decisions लेने वाली scripts प्रभावित हो सकती हैं।

## दुरुपयोग

यदि host UTS namespace shared हो, तो व्यावहारिक प्रश्न यह है कि क्या process host identity settings को केवल read करने के बजाय modify कर सकता है:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
यदि container के पास आवश्यक privilege भी है, तो जाँचें कि क्या hostname बदला जा सकता है:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
यह मुख्य रूप से integrity और operational-impact से जुड़ी समस्या है, न कि full escape, लेकिन फिर भी यह दिखाती है कि container सीधे host-global property को प्रभावित कर सकता है।

Impact:

- host identity tampering
- hostname पर भरोसा करने वाले logs, monitoring या automation में भ्रम
- आमतौर पर अपने आप में full escape नहीं, जब तक कि इसे अन्य weaknesses के साथ combine न किया जाए

Docker-style environments में, एक उपयोगी host-side detection pattern है:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host` दिखाने वाले Containers host UTS namespace को share कर रहे हैं और यदि उनके पास `sethostname()` या `setdomainname()` call करने की अनुमति देने वाली capabilities भी हों, तो उनकी अधिक सावधानी से समीक्षा की जानी चाहिए।

## Checks

यह देखने के लिए कि workload का अपना hostname view है या वह host UTS namespace को share कर रहा है, ये commands पर्याप्त हैं।
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
यहाँ क्या महत्वपूर्ण है:

- किसी host process के साथ namespace identifiers का मेल host UTS sharing का संकेत दे सकता है।
- यदि hostname बदलने से केवल container के बजाय अन्य चीज़ें भी प्रभावित होती हैं, तो workload का host identity पर अपेक्षा से अधिक प्रभाव है।
- यह आमतौर पर PID, mount या user namespace से जुड़ी समस्याओं की तुलना में कम प्राथमिकता वाली finding होती है, लेकिन फिर भी यह पुष्टि करती है कि process वास्तव में कितना isolated है।

अधिकांश environments में, UTS namespace को isolation की एक सहायक layer के रूप में समझना सबसे उचित है। breakout में यह शायद ही कभी पहली चीज़ होती है जिसकी आप जाँच करते हैं, लेकिन फिर भी यह container view की overall consistency और safety का हिस्सा है।

{{#include ../../../../../banners/hacktricks-training.md}}

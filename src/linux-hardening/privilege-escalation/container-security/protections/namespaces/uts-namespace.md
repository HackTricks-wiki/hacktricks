# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

UTS namespace उस प्रक्रिया द्वारा देखे जाने वाले **hostname** और **NIS domain name** को अलग करता है। पहली नज़र में यह mount, PID, या user namespaces की तुलना में तुच्छ लग सकता है, लेकिन यह उन्हीं तत्वों में से एक है जो container को उसके अपने host के रूप में दिखने में मदद करते हैं। Namespace के अंदर, workload उस namespace के स्थानीय hostname को देख सकता है और कभी-कभार बदल भी सकता है, जो मशीन के global hostname से अलग होता है।

अपने आप में यह आमतौर पर किसी breakout कहानी का मुख्य केंद्र नहीं होता। हालांकि, जब host UTS namespace साझा किया जाता है, तो पर्याप्त privileges वाला एक process host identity‑संबंधी सेटिंग्स को प्रभावित कर सकता है, जो ऑपरेशनल रूप से और कभी-कभी सुरक्षा के लिहाज़ से महत्वपूर्ण हो सकता है।

## लैब

आप UTS namespace निम्नलिखित कमांड के साथ बना सकते हैं:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
The hostname change remains local to that namespace and does not alter the host's global hostname. This is a simple but effective demonstration of the isolation property.

## Runtime उपयोग

सामान्य containers को एक अलग UTS namespace मिलता है। Docker और Podman `--uts=host` के जरिए host UTS namespace में शामिल हो सकते हैं, और इसी तरह के host-sharing पैटर्न अन्य runtimes और orchestration systems में भी दिख सकते हैं। हालांकि अधिकतर समय private UTS isolation साधारण container setup का हिस्सा होता है और इसे operator द्वारा कम ध्यान देने की आवश्यकता होती है।

## सुरक्षा प्रभाव

यद्यपि UTS namespace आम तौर पर साझा करने के लिए सबसे खतरनाक नहीं होता, फिर भी यह container boundary की integrity में योगदान देता है। यदि host UTS namespace खुला हो और process के पास आवश्यक privileges हों, तो वह host से संबंधित hostname जानकारी को बदल सकता है। इससे monitoring, logging, operational अनुमान, या ऐसे scripts प्रभावित हो सकते हैं जो host identity डेटा के आधार पर trust निर्णय लेते हैं।

## दुरुपयोग

यदि host UTS namespace साझा किया गया है, तो व्यावहारिक प्रश्न यह है कि क्या process केवल पढ़ने के बजाय host identity सेटिंग्स संशोधित कर सकता है:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
यदि container के पास आवश्यक privilege भी है, तो परीक्षण करें कि hostname बदला जा सकता है या नहीं:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
यह मुख्य रूप से एक अखंडता और संचालनात्मक प्रभाव की समस्या है न कि एक पूर्ण escape, लेकिन यह फिर भी दर्शाता है कि container सीधे एक host-global property को प्रभावित कर सकता है।

Impact:

- host identity में छेड़छाड़
- ऐसी logs, monitoring, या automation को भ्रमित करना जो hostname पर भरोसा करते हैं
- आमतौर पर अकेले यह एक full escape नहीं होता जब तक कि इसे अन्य कमजोरियों के साथ जोड़ा न जाए

On Docker-style environments, a useful host-side detection pattern is:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host` दिखाने वाले Containers होस्ट UTS namespace साझा कर रहे हैं और यदि उनकी पास ऐसी capabilities भी हैं जो उन्हें `sethostname()` या `setdomainname()` कॉल करने देती हैं, तो इन्हें और अधिक सावधानी से समीक्षा किया जाना चाहिए।

## जांच

ये commands इस बात को देखने के लिए पर्याप्त हैं कि workload का अपना hostname view है या वह host UTS namespace साझा कर रहा है।
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- namespace identifiers का किसी host process के साथ मिलना host UTS sharing का संकेत दे सकता है।
- अगर hostname बदलने से container के अलावा और भी चीज़ें प्रभावित होती हैं, तो workload का host identity पर अपेक्षित से अधिक प्रभाव है।
- यह आमतौर पर PID, mount, या user namespace समस्याओं की तुलना में कम प्राथमिकता वाला निष्कर्ष होता है, लेकिन यह फिर भी पुष्टि करता है कि process वास्तव में कितना isolated है।

In most environments, the UTS namespace is best thought of as a supporting isolation layer. It is rarely the first thing you chase in a breakout, but it is still part of the overall consistency and safety of the container view.

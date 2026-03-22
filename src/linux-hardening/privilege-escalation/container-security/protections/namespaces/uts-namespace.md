# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

UTS namespace उस process द्वारा देखे जाने वाले **hostname** और **NIS domain name** को अलग करता है। पहली नज़र में यह mount, PID, या user namespaces की तुलना में तुच्छ लग सकता है, लेकिन यह उस हिस्से का भाग है जो किसी container को उसके अपने host जैसा दिखने में मदद करता है। namespace के भीतर, workload उस hostname को देख सकता है और कभी-कभी बदल भी सकता है, जो machine-स्तर के global hostname के बजाय उस namespace-स्थानीय होता है।

अपने आप में, यह आमतौर पर किसी breakout कहानी का मुख्य केंद्र नहीं होता। हालांकि, एक बार host UTS namespace साझा हो जाने पर, पर्याप्त privileges वाला process host identity-संबंधी सेटिंग्स को प्रभावित कर सकता है, जो ऑपरेशनल रूप से और कभी-कभी सुरक्षा के लिहाज से मायने रख सकता है।

## लैब

आप निम्न के साथ एक UTS namespace बना सकते हैं:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
होस्टनाम में किया गया परिवर्तन उसी namespace तक सीमित रहता है और होस्ट के वैश्विक hostname को बदलता नहीं है। यह isolation property का एक सरल परन्तु प्रभावी प्रदर्शन है।

## रनटाइम उपयोग

सामान्य कंटेनरों को एक पृथक UTS namespace मिलता है। Docker और Podman `--uts=host` के माध्यम से host UTS namespace में जुड़ सकते हैं, और इसी तरह के host-sharing पैटर्न अन्य runtimes और orchestration systems में भी देखने को मिल सकते हैं। हालाँकि ज्यादातर मामलों में, निजी UTS isolation सामान्य container सेटअप का हिस्सा होता है और इसके लिए operator की अधिक ध्यान देने की आवश्यकता नहीं होती।

## सुरक्षा प्रभाव

हालाँकि UTS namespace आम तौर पर साझा करने के लिए सबसे खतरनाक नहीं माना जाता, यह फिर भी container सीमा की integrity में योगदान देता है। यदि host UTS namespace एक्सपोज़ हो और प्रक्रिया के पास आवश्यक privileges हों, तो वह host के hostname-संबंधी जानकारी को बदल सक सकती है। यह monitoring, logging, संचालन संबंधी अनुमान, या ऐसे स्क्रिप्ट्स को प्रभावित कर सकता है जो host identity डेटा के आधार पर trust निर्णय लेते हैं।

## दुरुपयोग

यदि host UTS namespace साझा किया गया है, तो व्यावहारिक प्रश्न यह है कि क्या प्रक्रिया केवल पढ़ने तक सीमित है या host identity सेटिंग्स को संशोधित भी कर सकती है:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
यदि container के पास आवश्यक privilege भी है, तो जाँच करें कि hostname बदला जा सकता है:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
यह मुख्य रूप से पूर्ण escape की बजाय एक अखंडता और संचालन-प्रभाव की समस्या है, फिर भी यह दर्शाता है कि container सीधे एक host-global property को प्रभावित कर सकता है।

प्रभाव:

- host पहचान में छेड़छाड़
- hostname पर भरोसा करने वाले logs, monitoring, या automation को भ्रमित करना
- आमतौर पर अकेले यह एक पूर्ण escape नहीं होता जब तक यह अन्य कमजोरियों के साथ न जुड़ा हो

Docker-style वातावरणों पर, host-side के लिए एक उपयोगी detection पैटर्न है:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
कंटेनर जो `UTSMode=host` दिखाते हैं, होस्ट UTS namespace साझा कर रहे हैं और अगर उनके पास ऐसी capabilities हैं जो उन्हें `sethostname()` या `setdomainname()` कॉल करने देती हैं तो उन्हें और सावधानी से समीक्षा किया जाना चाहिए।

## जाँच

ये commands पर्याप्त हैं यह देखने के लिए कि workload का अपना hostname view है या वह होस्ट UTS namespace साझा कर रहा है।
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
यहाँ दिलचस्प क्या है:

- Namespace identifiers को host process के साथ मैच करना host UTS sharing का संकेत दे सकता है।
- यदि hostname बदलने से container के अलावा और भी चीज़ें प्रभावित होती हैं, तो workload का host identity पर अपेक्षित से अधिक प्रभाव है।
- यह आमतौर पर PID, mount, या user namespace मामलों की तुलना में कम प्राथमिकता वाला निष्कर्ष होता है, लेकिन यह फिर भी पुष्टि करता है कि process वास्तव में कितनी अलग-थलग है।

अधिकांश परिवेशों में, UTS namespace को एक सहायक isolation layer के रूप में माना जाना चाहिए। यह शायद ही कभी breakout में पहली चीज़ होती है जिसे आप निशाना बनाते हैं, लेकिन यह फिर भी container view की समग्र consistency और safety का हिस्सा है।
{{#include ../../../../../banners/hacktricks-training.md}}

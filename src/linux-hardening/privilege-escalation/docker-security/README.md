# Docker सुरक्षा

{{#include ../../../banners/hacktricks-training.md}}

## **बुनियादी Docker इंजन सुरक्षा**

**Docker इंजन** लिनक्स कर्नेल के **Namespaces** और **Cgroups** का उपयोग करके कंटेनरों को अलग करता है, जो सुरक्षा की एक बुनियादी परत प्रदान करता है। **Capabilities dropping**, **Seccomp**, और **SELinux/AppArmor** के माध्यम से अतिरिक्त सुरक्षा प्रदान की जाती है, जो कंटेनर अलगाव को बढ़ाती है। एक **auth plugin** उपयोगकर्ता क्रियाओं को और अधिक सीमित कर सकता है।

![Docker सुरक्षा](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Docker इंजन तक सुरक्षित पहुंच

Docker इंजन को या तो स्थानीय रूप से एक Unix सॉकेट के माध्यम से या HTTP का उपयोग करके दूरस्थ रूप से एक्सेस किया जा सकता है। दूरस्थ पहुंच के लिए, गोपनीयता, अखंडता, और प्रमाणीकरण सुनिश्चित करने के लिए HTTPS और **TLS** का उपयोग करना आवश्यक है।

Docker इंजन, डिफ़ॉल्ट रूप से, `unix:///var/run/docker.sock` पर Unix सॉकेट पर सुनता है। उबंटू सिस्टम पर, Docker के स्टार्टअप विकल्प `/etc/default/docker` में परिभाषित होते हैं। Docker API और क्लाइंट के लिए दूरस्थ पहुंच सक्षम करने के लिए, HTTP सॉकेट के माध्यम से Docker डेमन को उजागर करने के लिए निम्नलिखित सेटिंग्स जोड़ें:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
हालांकि, HTTP के माध्यम से Docker डेमन को उजागर करना सुरक्षा चिंताओं के कारण अनुशंसित नहीं है। कनेक्शनों को HTTPS का उपयोग करके सुरक्षित करना उचित है। कनेक्शन को सुरक्षित करने के लिए दो मुख्य दृष्टिकोण हैं:

1. क्लाइंट सर्वर की पहचान की पुष्टि करता है।
2. क्लाइंट और सर्वर एक-दूसरे की पहचान की आपसी पुष्टि करते हैं।

सर्टिफिकेट का उपयोग सर्वर की पहचान की पुष्टि करने के लिए किया जाता है। दोनों विधियों के विस्तृत उदाहरणों के लिए, [**इस गाइड**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/) को देखें।

### कंटेनर छवियों की सुरक्षा

कंटेनर छवियों को निजी या सार्वजनिक रिपॉजिटरी में संग्रहीत किया जा सकता है। Docker कंटेनर छवियों के लिए कई संग्रहण विकल्प प्रदान करता है:

- [**Docker Hub**](https://hub.docker.com): Docker से एक सार्वजनिक रजिस्ट्री सेवा।
- [**Docker Registry**](https://github.com/docker/distribution): एक ओपन-सोर्स प्रोजेक्ट जो उपयोगकर्ताओं को अपनी खुद की रजिस्ट्री होस्ट करने की अनुमति देता है।
- [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Docker की व्यावसायिक रजिस्ट्री पेशकश, जिसमें भूमिका-आधारित उपयोगकर्ता प्रमाणीकरण और LDAP निर्देशिका सेवाओं के साथ एकीकरण शामिल है।

### छवि स्कैनिंग

कंटेनरों में **सुरक्षा कमजोरियाँ** हो सकती हैं या तो आधार छवि के कारण या आधार छवि के शीर्ष पर स्थापित सॉफ़्टवेयर के कारण। Docker एक प्रोजेक्ट पर काम कर रहा है जिसे **Nautilus** कहा जाता है, जो कंटेनरों का सुरक्षा स्कैन करता है और कमजोरियों की सूची बनाता है। Nautilus प्रत्येक कंटेनर छवि परत की तुलना कमजोरियों के रिपॉजिटरी से करता है ताकि सुरक्षा छिद्रों की पहचान की जा सके।

अधिक [**जानकारी के लिए इसे पढ़ें**](https://docs.docker.com/engine/scan/)।

- **`docker scan`**

**`docker scan`** कमांड आपको छवि नाम या ID का उपयोग करके मौजूदा Docker छवियों को स्कैन करने की अनुमति देती है। उदाहरण के लिए, hello-world छवि को स्कैन करने के लिए निम्नलिखित कमांड चलाएँ:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
- [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <container_name>:<tag>
```
- [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
- [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker Image Signing

Docker इमेज साइनिंग कंटेनरों में उपयोग की जाने वाली इमेज की सुरक्षा और अखंडता सुनिश्चित करता है। यहाँ एक संक्षिप्त व्याख्या है:

- **Docker Content Trust** Notary प्रोजेक्ट का उपयोग करता है, जो The Update Framework (TUF) पर आधारित है, इमेज साइनिंग प्रबंधित करने के लिए। अधिक जानकारी के लिए, देखें [Notary](https://github.com/docker/notary) और [TUF](https://theupdateframework.github.io)।
- Docker कंटेंट ट्रस्ट को सक्रिय करने के लिए, सेट करें `export DOCKER_CONTENT_TRUST=1`। यह सुविधा Docker संस्करण 1.10 और बाद में डिफ़ॉल्ट रूप से बंद है।
- इस सुविधा को सक्षम करने के साथ, केवल साइन की गई इमेज डाउनलोड की जा सकती हैं। प्रारंभिक इमेज पुश के लिए रूट और टैगिंग कुंजियों के लिए पासफ़्रेज़ सेट करना आवश्यक है, Docker Yubikey के लिए भी समर्थन करता है ताकि सुरक्षा बढ़ सके। अधिक विवरण [यहाँ](https://blog.docker.com/2015/11/docker-content-trust-yubikey/) मिल सकते हैं।
- कंटेंट ट्रस्ट सक्षम होने पर एक असाइन की गई इमेज को खींचने का प्रयास करने पर "No trust data for latest" त्रुटि होती है।
- पहले के बाद इमेज पुश के लिए, Docker इमेज को साइन करने के लिए रिपॉजिटरी कुंजी के पासफ़्रेज़ के लिए पूछता है।

अपने निजी कुंजियों का बैकअप लेने के लिए, कमांड का उपयोग करें:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
जब डॉकर होस्ट को स्विच करते हैं, तो संचालन बनाए रखने के लिए रूट और रिपॉजिटरी कुंजियों को स्थानांतरित करना आवश्यक है।

## कंटेनरों की सुरक्षा विशेषताएँ

<details>

<summary>कंटेनर सुरक्षा विशेषताओं का सारांश</summary>

**मुख्य प्रक्रिया पृथक्करण विशेषताएँ**

कंटेनराइज्ड वातावरण में, परियोजनाओं और उनके प्रक्रियाओं को अलग करना सुरक्षा और संसाधन प्रबंधन के लिए अत्यंत महत्वपूर्ण है। यहाँ प्रमुख अवधारणाओं का एक सरल स्पष्टीकरण है:

**नेमस्पेस**

- **उद्देश्य**: प्रक्रियाओं, नेटवर्क और फ़ाइल सिस्टम जैसे संसाधनों का पृथक्करण सुनिश्चित करना। विशेष रूप से डॉकर में, नेमस्पेस एक कंटेनर की प्रक्रियाओं को होस्ट और अन्य कंटेनरों से अलग रखते हैं।
- **`unshare` का उपयोग**: `unshare` कमांड (या अंतर्निहित syscall) का उपयोग नए नेमस्पेस बनाने के लिए किया जाता है, जो पृथक्करण की एक अतिरिक्त परत प्रदान करता है। हालाँकि, जबकि कुबेरनेट्स स्वाभाविक रूप से इसे अवरुद्ध नहीं करता है, डॉकर ऐसा करता है।
- **सीमा**: नए नेमस्पेस बनाने से एक प्रक्रिया को होस्ट के डिफ़ॉल्ट नेमस्पेस में वापस लौटने की अनुमति नहीं मिलती है। होस्ट नेमस्पेस में प्रवेश करने के लिए, आमतौर पर होस्ट के `/proc` निर्देशिका तक पहुँच की आवश्यकता होती है, प्रवेश के लिए `nsenter` का उपयोग करते हुए।

**कंट्रोल ग्रुप्स (CGroups)**

- **कार्य**: मुख्य रूप से प्रक्रियाओं के बीच संसाधनों को आवंटित करने के लिए उपयोग किया जाता है।
- **सुरक्षा पहलू**: CGroups स्वयं पृथक्करण सुरक्षा प्रदान नहीं करते हैं, सिवाय `release_agent` विशेषता के, जो यदि गलत कॉन्फ़िगर की गई हो, तो अनधिकृत पहुँच के लिए शोषित की जा सकती है।

**क्षमता ड्रॉप**

- **महत्व**: यह प्रक्रिया पृथक्करण के लिए एक महत्वपूर्ण सुरक्षा विशेषता है।
- **कार्यात्मकता**: यह रूट प्रक्रिया द्वारा किए जाने वाले कार्यों को कुछ क्षमताओं को ड्रॉप करके प्रतिबंधित करता है। भले ही एक प्रक्रिया रूट विशेषाधिकारों के साथ चल रही हो, आवश्यक क्षमताओं की कमी इसे विशेषाधिकार प्राप्त कार्यों को निष्पादित करने से रोकती है, क्योंकि syscalls अपर्याप्त अनुमतियों के कारण विफल हो जाएंगे।

ये हैं **बची हुई क्षमताएँ** जब प्रक्रिया ने अन्य को ड्रॉप किया:
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
**Seccomp**

यह डॉकर में डिफ़ॉल्ट रूप से सक्षम है। यह **प्रक्रिया द्वारा कॉल किए जा सकने वाले syscalls को और अधिक सीमित करने** में मदद करता है।\
**डिफ़ॉल्ट डॉकर सेकॉम्प प्रोफ़ाइल** [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) में पाई जा सकती है।

**AppArmor**

डॉकर के पास एक टेम्पलेट है जिसे आप सक्रिय कर सकते हैं: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

यह क्षमताओं, syscalls, फ़ाइलों और फ़ोल्डरों तक पहुँच को कम करने की अनुमति देगा...

</details>

### Namespaces

**Namespaces** लिनक्स कर्नेल की एक विशेषता है जो **कर्नेल संसाधनों को विभाजित** करती है ताकि एक सेट के **प्रक्रियाएँ** एक सेट के **संसाधनों** को **देखें** जबकि **दूसरा** सेट के **प्रक्रियाएँ** एक **अलग** सेट के संसाधनों को देखती हैं। यह विशेषता संसाधनों और प्रक्रियाओं के एक सेट के लिए समान namespace होने के द्वारा काम करती है, लेकिन उन namespaces का संदर्भ अलग-अलग संसाधनों की ओर होता है। संसाधन कई स्थानों में मौजूद हो सकते हैं।

डॉकर कंटेनर अलगाव प्राप्त करने के लिए निम्नलिखित लिनक्स कर्नेल namespaces का उपयोग करता है:

- pid namespace
- mount namespace
- network namespace
- ipc namespace
- UTS namespace

**Namespaces के बारे में अधिक जानकारी** के लिए निम्नलिखित पृष्ठ देखें:

{{#ref}}
namespaces/
{{#endref}}

### cgroups

लिनक्स कर्नेल की विशेषता **cgroups** एक सेट के प्रक्रियाओं के बीच **cpu, memory, io, network bandwidth जैसे संसाधनों को प्रतिबंधित करने** की क्षमता प्रदान करती है। डॉकर cgroup विशेषता का उपयोग करके कंटेनर बनाने की अनुमति देता है जो विशेष कंटेनर के लिए संसाधन नियंत्रण की अनुमति देता है।\
निम्नलिखित एक कंटेनर है जिसे उपयोगकर्ता स्थान मेमोरी को 500m, कर्नेल मेमोरी को 50m, cpu शेयर को 512, blkioweight को 400 तक सीमित किया गया है। CPU शेयर एक अनुपात है जो कंटेनर के CPU उपयोग को नियंत्रित करता है। इसका डिफ़ॉल्ट मान 1024 है और यह 0 से 1024 के बीच होता है। यदि तीन कंटेनरों का CPU शेयर 1024 है, तो प्रत्येक कंटेनर CPU संसाधन विवाद की स्थिति में CPU का 33% तक ले सकता है। blkio-weight एक अनुपात है जो कंटेनर के IO को नियंत्रित करता है। इसका डिफ़ॉल्ट मान 500 है और यह 10 से 1000 के बीच होता है।
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
किसी कंटेनर का cgroup प्राप्त करने के लिए आप कर सकते हैं:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
अधिक जानकारी के लिए देखें:

{{#ref}}
cgroups.md
{{#endref}}

### क्षमताएँ

क्षमताएँ **रूट उपयोगकर्ता के लिए अनुमत क्षमताओं पर अधिक बारीक नियंत्रण** की अनुमति देती हैं। Docker Linux कर्नेल क्षमता सुविधा का उपयोग करता है ताकि **कंटेनर के अंदर किए जा सकने वाले संचालन को सीमित किया जा सके**, चाहे उपयोगकर्ता का प्रकार कोई भी हो।

जब एक डॉकर कंटेनर चलाया जाता है, तो **प्रक्रिया संवेदनशील क्षमताओं को छोड़ देती है जिनका उपयोग प्रक्रिया अलगाव से भागने के लिए कर सकती है**। यह सुनिश्चित करने का प्रयास करता है कि प्रक्रिया संवेदनशील क्रियाएँ करने और भागने में सक्षम न हो:

{{#ref}}
../linux-capabilities.md
{{#endref}}

### Docker में Seccomp

यह एक सुरक्षा विशेषता है जो Docker को **कंटेनर के अंदर उपयोग किए जा सकने वाले syscalls को सीमित** करने की अनुमति देती है:

{{#ref}}
seccomp.md
{{#endref}}

### Docker में AppArmor

**AppArmor** एक कर्नेल संवर्धन है जो **कंटेनरों** को **सीमित** संसाधनों के **प्रति-कार्यक्रम प्रोफाइल** के सेट में सीमित करता है।:

{{#ref}}
apparmor.md
{{#endref}}

### Docker में SELinux

- **लेबलिंग सिस्टम**: SELinux प्रत्येक प्रक्रिया और फ़ाइल प्रणाली वस्तु को एक अद्वितीय लेबल असाइन करता है।
- **नीति प्रवर्तन**: यह सुरक्षा नीतियों को लागू करता है जो परिभाषित करती हैं कि एक प्रक्रिया लेबल अन्य लेबल पर क्या क्रियाएँ कर सकती है।
- **कंटेनर प्रक्रिया लेबल**: जब कंटेनर इंजन कंटेनर प्रक्रियाएँ आरंभ करते हैं, तो उन्हें आमतौर पर एक सीमित SELinux लेबल, सामान्यतः `container_t` असाइन किया जाता है।
- **कंटेनरों के भीतर फ़ाइल लेबलिंग**: कंटेनर के भीतर फ़ाइलें आमतौर पर `container_file_t` के रूप में लेबल की जाती हैं।
- **नीति नियम**: SELinux नीति मुख्य रूप से यह सुनिश्चित करती है कि `container_t` लेबल वाली प्रक्रियाएँ केवल `container_file_t` के रूप में लेबल की गई फ़ाइलों के साथ इंटरैक्ट कर सकती हैं (पढ़ना, लिखना, निष्पादित करना)।

यह तंत्र सुनिश्चित करता है कि यदि कंटेनर के भीतर कोई प्रक्रिया समझौता कर ली जाती है, तो यह केवल उन वस्तुओं के साथ इंटरैक्ट करने तक सीमित होती है जिनके पास संबंधित लेबल होते हैं, जिससे ऐसे समझौतों से संभावित नुकसान को काफी हद तक सीमित किया जा सकता है।

{{#ref}}
../selinux.md
{{#endref}}

### AuthZ & AuthN

Docker में, एक प्राधिकरण प्लगइन सुरक्षा में महत्वपूर्ण भूमिका निभाता है यह तय करते हुए कि Docker डेमन के लिए अनुरोधों को अनुमति दी जाए या अवरुद्ध किया जाए। यह निर्णय दो प्रमुख संदर्भों की जांच करके किया जाता है:

- **प्रमाणीकरण संदर्भ**: इसमें उपयोगकर्ता के बारे में व्यापक जानकारी शामिल होती है, जैसे कि वे कौन हैं और उन्होंने स्वयं को कैसे प्रमाणित किया है।
- **कमांड संदर्भ**: इसमें किए जा रहे अनुरोध से संबंधित सभी प्रासंगिक डेटा शामिल होता है।

ये संदर्भ सुनिश्चित करने में मदद करते हैं कि केवल प्रमाणित उपयोगकर्ताओं से वैध अनुरोधों को संसाधित किया जाए, जिससे Docker संचालन की सुरक्षा बढ़ती है।

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## कंटेनर से DoS

यदि आप एक कंटेनर द्वारा उपयोग किए जा सकने वाले संसाधनों को सही तरीके से सीमित नहीं कर रहे हैं, तो एक समझौता किया गया कंटेनर उस होस्ट को DoS कर सकता है जहाँ यह चल रहा है।

- CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
- बैंडविड्थ DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## दिलचस्प Docker फ्लैग

### --privileged फ्लैग

अगली पृष्ठ पर आप **`--privileged` फ्लैग का क्या अर्थ है** जान सकते हैं:

{{#ref}}
docker-privileged.md
{{#endref}}

### --security-opt

#### no-new-privileges

यदि आप एक कंटेनर चला रहे हैं जहाँ एक हमलावर एक निम्न विशेषाधिकार उपयोगकर्ता के रूप में पहुँच प्राप्त करने में सफल होता है। यदि आपके पास एक **गलत कॉन्फ़िगर किया गया suid बाइनरी** है, तो हमलावर इसका दुरुपयोग कर सकता है और **कंटेनर के अंदर विशेषाधिकार बढ़ा सकता है**। जिससे, वह इससे बाहर निकलने में सक्षम हो सकता है।

**`no-new-privileges`** विकल्प सक्षम करके कंटेनर चलाने से **इस प्रकार की विशेषाधिकार वृद्धि को रोका जा सकेगा**।
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### अन्य
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
अधिक **`--security-opt`** विकल्पों के लिए देखें: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## अन्य सुरक्षा विचार

### रहस्यों का प्रबंधन: सर्वोत्तम प्रथाएँ

यह महत्वपूर्ण है कि रहस्यों को सीधे Docker छवियों में या पर्यावरण चर का उपयोग करके एम्बेड करने से बचें, क्योंकि ये तरीके आपकी संवेदनशील जानकारी को किसी भी व्यक्ति के लिए उजागर करते हैं जो `docker inspect` या `exec` जैसे कमांड के माध्यम से कंटेनर तक पहुँच रखता है।

**Docker वॉल्यूम** एक सुरक्षित विकल्प हैं, जिन्हें संवेदनशील जानकारी तक पहुँचने के लिए अनुशंसित किया गया है। इन्हें अस्थायी फ़ाइल सिस्टम के रूप में मेमोरी में उपयोग किया जा सकता है, जो `docker inspect` और लॉगिंग से संबंधित जोखिमों को कम करता है। हालाँकि, रूट उपयोगकर्ता और जिनके पास कंटेनर तक `exec` पहुँच है, वे अभी भी रहस्यों तक पहुँच सकते हैं।

**Docker रहस्य** संवेदनशील जानकारी को संभालने के लिए एक और अधिक सुरक्षित विधि प्रदान करते हैं। उन उदाहरणों के लिए जिनमें छवि निर्माण चरण के दौरान रहस्यों की आवश्यकता होती है, **BuildKit** एक कुशल समाधान प्रस्तुत करता है जो निर्माण समय के रहस्यों का समर्थन करता है, निर्माण गति को बढ़ाता है और अतिरिक्त सुविधाएँ प्रदान करता है।

BuildKit का लाभ उठाने के लिए, इसे तीन तरीकों से सक्रिय किया जा सकता है:

1. एक पर्यावरण चर के माध्यम से: `export DOCKER_BUILDKIT=1`
2. कमांड को पूर्ववर्ती करके: `DOCKER_BUILDKIT=1 docker build .`
3. Docker कॉन्फ़िगरेशन में डिफ़ॉल्ट रूप से सक्षम करके: `{ "features": { "buildkit": true } }`, इसके बाद Docker पुनः प्रारंभ करें।

BuildKit `--secret` विकल्प के साथ निर्माण समय के रहस्यों का उपयोग करने की अनुमति देता है, यह सुनिश्चित करते हुए कि ये रहस्य छवि निर्माण कैश या अंतिम छवि में शामिल नहीं हैं, जैसे कि:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
चलते हुए कंटेनर में आवश्यक रहस्यों के लिए, **Docker Compose और Kubernetes** मजबूत समाधान प्रदान करते हैं। Docker Compose सेवा परिभाषा में रहस्य फ़ाइलों को निर्दिष्ट करने के लिए `secrets` कुंजी का उपयोग करता है, जैसा कि `docker-compose.yml` उदाहरण में दिखाया गया है:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
यह कॉन्फ़िगरेशन Docker Compose के साथ सेवाओं को शुरू करते समय रहस्यों के उपयोग की अनुमति देता है।

Kubernetes वातावरण में, रहस्यों का स्वदेशी समर्थन होता है और इन्हें [Helm-Secrets](https://github.com/futuresimple/helm-secrets) जैसे उपकरणों के साथ और प्रबंधित किया जा सकता है। Kubernetes का भूमिका आधारित पहुँच नियंत्रण (RBAC) रहस्य प्रबंधन सुरक्षा को बढ़ाता है, जो Docker Enterprise के समान है।

### gVisor

**gVisor** एक एप्लिकेशन कर्नेल है, जो Go में लिखा गया है, जो Linux सिस्टम सतह का एक महत्वपूर्ण हिस्सा लागू करता है। इसमें एक [Open Container Initiative (OCI)](https://www.opencontainers.org) रनटाइम शामिल है जिसे `runsc` कहा जाता है, जो **एप्लिकेशन और होस्ट कर्नेल के बीच एक अलगाव सीमा प्रदान करता है**। `runsc` रनटाइम Docker और Kubernetes के साथ एकीकृत होता है, जिससे सैंडबॉक्स किए गए कंटेनरों को चलाना सरल हो जाता है।

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** एक ओपन सोर्स समुदाय है जो हल्के वर्चुअल मशीनों के साथ एक सुरक्षित कंटेनर रनटाइम बनाने के लिए काम कर रहा है, जो कंटेनरों की तरह महसूस और प्रदर्शन करते हैं, लेकिन **हार्डवेयर वर्चुअलाइजेशन** तकनीक का उपयोग करके **मजबूत कार्यभार अलगाव** प्रदान करते हैं।

{% embed url="https://katacontainers.io/" %}

### सारांश टिप्स

- **`--privileged` ध्वज का उपयोग न करें या** [**Docker सॉकेट को कंटेनर के अंदर माउंट न करें**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**।** Docker सॉकेट कंटेनरों को उत्पन्न करने की अनुमति देता है, इसलिए यह होस्ट पर पूर्ण नियंत्रण प्राप्त करने का एक आसान तरीका है, उदाहरण के लिए, `--privileged` ध्वज के साथ एक और कंटेनर चलाकर।
- **कंटेनर के अंदर रूट के रूप में न चलाएं। एक** [**अलग उपयोगकर्ता**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **का उपयोग करें और** [**उपयोगकर्ता नामस्थान**](https://docs.docker.com/engine/security/userns-remap/)**।** कंटेनर में रूट वही होता है जो होस्ट पर होता है जब तक कि इसे उपयोगकर्ता नामस्थान के साथ पुनः मैप नहीं किया जाता। यह मुख्य रूप से Linux नामस्थान, क्षमताओं और cgroups द्वारा हल्के से प्रतिबंधित होता है।
- [**सभी क्षमताएँ हटा दें**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) और केवल आवश्यक क्षमताएँ सक्षम करें** (`--cap-add=...`)। कई कार्यभार को किसी भी क्षमताओं की आवश्यकता नहीं होती है और उन्हें जोड़ने से संभावित हमले का दायरा बढ़ता है।
- [**“no-new-privileges” सुरक्षा विकल्प का उपयोग करें**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) ताकि प्रक्रियाएँ अधिक विशेषाधिकार प्राप्त न कर सकें, उदाहरण के लिए, suid बाइनरी के माध्यम से।
- [**कंटेनर के लिए उपलब्ध संसाधनों को सीमित करें**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**।** संसाधन सीमाएँ मशीन को सेवा से इनकार के हमलों से बचा सकती हैं।
- **seccomp** [**को समायोजित करें**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(या SELinux)** प्रोफाइल को कंटेनर के लिए आवश्यक न्यूनतम क्रियाओं और syscalls को प्रतिबंधित करने के लिए।
- **आधिकारिक Docker छवियों का उपयोग करें** [**और हस्ताक्षर की आवश्यकता करें**](https://docs.docker.com/docker-hub/official_images/) **या उनके आधार पर अपनी खुद की बनाएं। बैकडोर वाली छवियों का उपयोग न करें।** [**https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/**](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) **।** रूट कुंजी, पासफ़्रेज़ को सुरक्षित स्थान पर भी स्टोर करें। Docker की UCP के साथ कुंजी प्रबंधित करने की योजनाएँ हैं।
- **नियमित रूप से** **अपनी छवियों को फिर से बनाएं ताकि** **होस्ट और छवियों पर सुरक्षा पैच लागू हो सकें।**
- अपने **रहस्यों का बुद्धिमानी से प्रबंधन करें** ताकि हमलावर के लिए उन्हें एक्सेस करना कठिन हो।
- यदि आप **Docker डेमन को उजागर करते हैं तो HTTPS का उपयोग करें** क्लाइंट और सर्वर प्रमाणीकरण के साथ।
- अपने Dockerfile में, **ADD के बजाय COPY को प्राथमिकता दें**। ADD स्वचालित रूप से ज़िप फ़ाइलों को निकालता है और URLs से फ़ाइलें कॉपी कर सकता है। COPY में ये क्षमताएँ नहीं होती हैं। जब भी संभव हो, ADD का उपयोग करने से बचें ताकि आप दूरस्थ URLs और ज़िप फ़ाइलों के माध्यम से हमलों के प्रति संवेदनशील न हों।
- प्रत्येक माइक्रो-सेवा के लिए **अलग कंटेनर रखें।**
- **कंटेनर के अंदर ssh न रखें, "docker exec" का उपयोग कंटेनर में ssh करने के लिए किया जा सकता है।**
- **छोटे** कंटेनर **छवियाँ रखें।**

## Docker ब्रेकआउट / विशेषाधिकार वृद्धि

यदि आप **एक Docker कंटेनर के अंदर हैं** या आपके पास **Docker समूह में एक उपयोगकर्ता तक पहुँच है**, तो आप **भागने और विशेषाधिकार बढ़ाने** की कोशिश कर सकते हैं:

{{#ref}}
docker-breakout-privilege-escalation/
{{#endref}}

## Docker प्रमाणीकरण प्लगइन बाईपास

यदि आपके पास Docker सॉकेट तक पहुँच है या आपके पास **Docker समूह में एक उपयोगकर्ता तक पहुँच है लेकिन आपके कार्यों को एक Docker प्रमाणीकरण प्लगइन द्वारा सीमित किया जा रहा है**, तो जांचें कि क्या आप इसे **बाईपास कर सकते हैं:**

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## Docker को मजबूत करना

- उपकरण [**docker-bench-security**](https://github.com/docker/docker-bench-security) एक स्क्रिप्ट है जो उत्पादन में Docker कंटेनरों को तैनात करने के चारों ओर सामान्य सर्वोत्तम प्रथाओं के लिए दर्जनों की जांच करती है। परीक्षण सभी स्वचालित होते हैं, और [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/) पर आधारित होते हैं।\
आपको इसे Docker चला रहे होस्ट से या पर्याप्त विशेषाधिकार वाले कंटेनर से चलाना होगा। जानें **इसे README में कैसे चलाना है:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security)।

## संदर्भ

- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
- [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
- [https://docs.docker.com/engine/extend/plugins_authorization](https://docs.docker.com/engine/extend/plugins_authorization)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

{{#include ../../../banners/hacktricks-training.md}}

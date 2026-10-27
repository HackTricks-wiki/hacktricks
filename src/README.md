# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks के लोगो और मोशन डिज़ाइन_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_ द्वारा।_

### HackTricks को स्थानीय रूप से चलाएँ

```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

HackTricks की आपकी local copy 5 मिनट से कम समय में **[http://localhost:3337](http://localhost:3337)** पर उपलब्ध होगी (इसे book build करने में समय लगता है, कृपया धैर्य रखें)।

वैकल्पिक रूप से, अगर आपके पास Docker Compose है, तो आप repo root से बस यह चला सकते हैं:

```bash
docker compose up
```

यह bundled `docker-compose.yml` का उपयोग करके host पर वर्तमान में checkout की गई branch को [http://localhost:3337](http://localhost:3337) पर live reload के साथ serve करता है। Compose का उपयोग करते समय languages बदलने के लिए, service शुरू करने से पहले इच्छित language branch checkout करें।

## HackTricks पार्टनर्स

---

## HackTricks मित्र

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber penetration testing, security audits, exploit और research work, tools, तथा security-awareness services प्रदान करता है। इसकी साइट के अनुसार, इसकी टीम में एक दशक से अधिक अनुभव वाले penetration testers, programmers और security researchers शामिल हैं।<sup>[[1]](#references)</sup>

आप उनका **blog** [**https://blog.stmcyber.com**](https://blog.stmcyber.com) पर देख सकते हैं।

**STM Cyber** HackTricks जैसे cybersecurity open source projects का भी समर्थन करता है :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti एक crowdsourced security provider है, जो वैश्विक researcher community के ज़रिए bug bounty और penetration-testing services प्रदान करता है। इसका platform continuous bug bounty coverage को on-demand PTaaS और managed vulnerability disclosure programs के साथ जोड़ता है।<sup>[[2]](#references)</sup>

**Bug bounty tip**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) के ज़रिए Intigriti से जुड़ें और इसके bug bounty programs देखें।

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security security engineers, AppSec professionals और developers के लिए self-paced, hands-on AI security training प्रदान करता है। इसका AI Security Certification LLM और agent fundamentals, RAG और vector databases, threat modeling, prompt-injection और MCP attacks, तथा defensive architecture को कवर करता है।<sup>[[3]](#references)</sup>

👉 AI Security course की अधिक जानकारी:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** Google और अन्य search engines के लिए APIs प्रदान करता है, जो location-aware results, Maps, Shopping और Knowledge Graph results जैसी सुविधाओं के साथ structured SERP data लौटाते हैं।<sup>[[4]](#references)</sup>

अधिक जानकारी के लिए उनका [**blog**](https://serpapi.com/blog/) देखें, उनके [**playground**](https://serpapi.com/playground) में एक उदाहरण आज़माएँ, या [**मुफ़्त account बनाएँ**](https://serpapi.com/users/sign_up)।

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** self-paced mobile और AI-security courses प्रदान करता है। इसका catalog Ghidra, Frida और LLDB जैसे tools से mobile application auditing और reversing के साथ-साथ AI/LLM attack और defense labs को कवर करता है।<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy course catalog](https://academy.8ksec.io/) देखें।

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** एक offensive-AI platform प्रस्तुत करता है, जो code और infrastructure को map करता है, फिर static और dynamic agents के ज़रिए exploitable कमजोरियों को ढूँढ़ता और validate करता है, साथ में proof-of-concept evidence और remediation guidance भी देता है।<sup>[[7]](#references)</sup>

**Code security tip**: code और infrastructure पर केंद्रित vulnerability discovery के लिए Naxus देखें।

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec penetration testing, security subscriptions, staffing और vulnerability-assessment services प्रदान करता है। इसकी साइट के अनुसार, यह अंतरराष्ट्रीय स्तर पर काम करता है और offensive security, defensive security, तथा governance, risk और compliance से जुड़े काम करता है।<sup>[[8]](#references)</sup>

अधिक जानकारी के लिए उनकी [**website**](https://websec.net/en/) या [**blog**](https://websec.net/blog/) पर जाएँ।

उपरोक्त के अलावा, WebSec HackTricks का **समर्पित समर्थक** भी है।

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**वास्तविक परिस्थितियों के लिए बना। आपकी ज़रूरतों के अनुसार बना।**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) वास्तविक infrastructures पर आधारित, custom-built content और labs के साथ expert-led cybersecurity training प्रदान करता है। इसके programs संगठन की ज़रूरतों के अनुसार तैयार किए जाते हैं और assessment से लेकर implementation तक शामिल होते हैं।<sup>[[9]](#references)</sup> Custom training के बारे में पूछताछ के लिए [**यहाँ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) संपर्क करें।

**इसकी training की खासियतें:**
* Custom-built content और labs
* शीर्ष स्तर के tools और platforms का समर्थन
* Practitioners द्वारा तैयार और पढ़ाई जाती है

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions **Education** और **FinTech** के लिए cybersecurity consulting पर केंद्रित है। इसकी सेवाओं में cloud assessments, internal और external penetration tests, vulnerability assessments, तथा compliance support शामिल हैं।<sup>[[10]](#references)</sup>

हमारे [**blog**](https://www.lasttowersolutions.com/blog) पर जाकर cybersecurity की नवीनतम जानकारी से अपडेट रहें।

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio एक desktop Kubernetes IDE है, जिसमें CloudMaps visualization, multi-cluster navigation, RBAC, Helm, logs, YAML और terminal views शामिल हैं। Vendor के अनुसार, यह agents install किए बिना kubeconfig के ज़रिए connect होता है और macOS, Windows, Linux तथा air-gapped clusters को support करता है।<sup>[[11]](#references)</sup>

---

## License & Disclaimer

नीचे References में HackTricks Values & FAQ प्रविष्टि देखें।

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Practical AI Security: Attacks, Defenses, and Applications](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks referral](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec sponsorship video](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets courses](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}

# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks के लोगो और मोशन डिज़ाइन इनके द्वारा_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

HackTricks की आपकी स्थानीय प्रति <5 मिनट बाद **[http://localhost:3337](http://localhost:3337)** पर उपलब्ध होगी (इसे पुस्तक बनाने की आवश्यकता है, कृपया धैर्य रखें)।

वैकल्पिक रूप से, यदि आपके पास Docker Compose है, तो आप रेपो के रूट से निम्नलिखित चला सकते हैं:

```bash
docker compose up
```

यह bundled `docker-compose.yml` का उपयोग करके host पर वर्तमान में checkout की गई branch को live reload के साथ [http://localhost:3337](http://localhost:3337) पर serve करता है। Compose का उपयोग करते समय language बदलने के लिए service शुरू करने से पहले इच्छित language branch checkout करें।

## HackTricks के पार्टनर

---

## HackTricks के मित्र

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber penetration testing, security audits, exploit और research कार्य, tools, और security-awareness सेवाएँ प्रदान करता है। इसकी साइट पर एक दशक से अधिक अनुभव वाले penetration testers, programmers, और security researchers की टीम का वर्णन है।<sup>[[1]](#references)</sup>

उनका **ब्लॉग** [**https://blog.stmcyber.com**](https://blog.stmcyber.com) पर देखें।

**STM Cyber** HackTricks जैसे cybersecurity open source projects का भी समर्थन करता है :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti एक crowdsourced security provider है, जो वैश्विक researcher community के माध्यम से bug bounty और penetration-testing सेवाएँ प्रदान करता है। इसका platform निरंतर bug bounty coverage को on-demand PTaaS और managed vulnerability disclosure programs के साथ जोड़ता है।<sup>[[2]](#references)</sup>

**Bug bounty टिप**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) के ज़रिए Intigriti से जुड़ें और इसके bug bounty programs देखें।

---

### [Modern Security – AI और Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security security engineers, AppSec professionals, और developers के लिए अपनी गति से पूरी की जा सकने वाली hands-on AI security training प्रदान करता है। इसका AI Security Certification LLM और agent fundamentals, RAG और vector databases, threat modeling, prompt-injection और MCP attacks, और defensive architecture को कवर करता है।<sup>[[3]](#references)</sup>

👉 AI Security course की अधिक जानकारी:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** Google और अन्य search engines के लिए APIs प्रदान करता है, जो location-aware results, Maps, Shopping, और Knowledge Graph results जैसी सुविधाओं के साथ structured SERP data लौटाते हैं।<sup>[[4]](#references)</sup>

अधिक जानकारी के लिए उनका [**ब्लॉग**](https://serpapi.com/blog/) देखें, उनके [**playground**](https://serpapi.com/playground) में उदाहरण आज़माएँ, या [**मुफ़्त खाता बनाएँ**](https://serpapi.com/users/sign_up)।

---

### [8kSec Academy – Mobile और AI Security के गहन Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** अपनी गति से पूरे किए जा सकने वाले mobile और AI-security courses प्रदान करता है। इसके catalog में Ghidra, Frida, और LLDB जैसे tools के साथ mobile application auditing और reversing, तथा AI/LLM attack और defense labs शामिल हैं।<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy का course catalog](https://academy.8ksec.io/) देखें।

---

### [NaxusAI – Autonomous Offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI का लोगो"><figcaption></figcaption></figure>

**Naxus** एक AI-powered offensive-security platform है, जो पूर्ण external attack-surface scans, mobile app audits, web black-box testing, और source-code reviews करता है। इसके agents exploitable findings को validate करते हैं और traceable evidence, proof-of-concept exploits, तथा कार्रवाई योग्य remediation देते हैं।<sup>[[7]](#references)</sup>

**Security audit टिप**: external assets, mobile apps, web apps, और source code के end-to-end autonomous audits के लिए Naxus का उपयोग करें।

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec penetration testing, security subscriptions, staffing, और vulnerability-assessment सेवाएँ प्रदान करता है। इसकी साइट के अनुसार, यह अंतरराष्ट्रीय स्तर पर काम करता है और offensive security, defensive security, तथा governance, risk, और compliance से जुड़े काम करता है।<sup>[[8]](#references)</sup>

अधिक जानकारी के लिए उनकी [**वेबसाइट**](https://websec.net/en/) या [**ब्लॉग**](https://websec.net/blog/) देखें।

उपरोक्त सेवाओं के अलावा, WebSec **HackTricks का एक प्रतिबद्ध समर्थक** भी है।

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets का लोगो"><figcaption></figcaption></figure>


**मैदान के लिए बना। आपके अनुसार तैयार किया गया।**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) वास्तविक infrastructures पर आधारित custom-built content और labs के साथ expert-led cybersecurity training प्रदान करता है। इसके programs संगठनों की ज़रूरतों के अनुसार तैयार किए जाते हैं और assessment से लेकर implementation तक सब कुछ कवर करते हैं।<sup>[[9]](#references)</sup> Custom training से जुड़ी पूछताछ के लिए [**यहाँ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) संपर्क करें।

**उनकी training को खास बनाने वाली बातें:**
* Custom-built content और labs
* बेहतरीन tools और platforms द्वारा समर्थित
* Practitioners द्वारा डिज़ाइन और सिखाई गई

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower का लोगो"><figcaption></figcaption></figure>

Last Tower Solutions **Education** और **FinTech** के लिए cybersecurity consulting पर ध्यान केंद्रित करता है। इसमें cloud assessments, internal और external penetration tests, vulnerability assessments, और compliance support शामिल हैं।<sup>[[10]](#references)</sup>

हमारे [**ब्लॉग**](https://www.lasttowersolutions.com/blog) पर जाकर cybersecurity की नवीनतम जानकारी से अवगत रहें।

---

### [Beaki — आपके लिए सही भोजन](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki का लोगो"><figcaption></figcaption></figure>

**Beaki** एक personalized food scanner, calorie counter, और nutrition tracker है। Barcodes और supermarket shelves scan करें, meals और restaurant menus की तस्वीर लें या उनका वर्णन करें, और अपने लक्ष्यों, diet, allergies, तथा health profile के अनुसार समझने योग्य scores पाएँ। Beaki calories और macros भी track करता है और shopping lists के साथ personalized meal plans बनाता है।<sup>[[11]](#references)</sup>

Android या iPhone पर [**Beaki मुफ़्त डाउनलोड करें**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks)।

---

## License और Disclaimer

नीचे References में HackTricks Values & FAQ प्रविष्टि देखें।

## Github Stats

![HackTricks के GitHub आँकड़े](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [व्यावहारिक AI Security: Attacks, Defenses, और Applications](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Intigriti HackTricks रेफ़रल](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec प्रायोजन वीडियो](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets courses](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values और FAQ](welcome/hacktricks-values-and-faq.md)

{{#include banners/hacktricks-training.md}}

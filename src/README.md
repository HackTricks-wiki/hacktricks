# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo na motion design za Hacktricks na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks Kwenye Kompyuta Yako Locally
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
# "hi" for HindiP
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Nakala yako ya ndani ya HackTricks itapatikana kwenye [http://localhost:3337](http://localhost:3337) baada ya <5 minutes (inahitaji kujenga kitabu, kuwa mvumilivu).

Vinginevyo, ikiwa una Docker Compose, unaweza tu kuendesha yafuatayo kutoka kwenye repo root:
```bash
docker compose up
```
Hii hutumia `docker-compose.yml` iliyojumuishwa kuhudumia branch iliyochaguliwa kwa sasa kwenye host kupitia [http://localhost:3337](http://localhost:3337), ikiwa na live reload. Ili kubadilisha lugha unapotumia Compose, chagua branch ya lugha unayotaka kabla ya kuanzisha service.

## Washirika wa HackTricks

---

## Marafiki wa HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber hutoa penetration testing, security audits, exploit na research work, tools, pamoja na huduma za security-awareness. Tovuti yake inaeleza kuwa ina timu ya penetration testers, programmers, na security researchers yenye uzoefu wa zaidi ya muongo mmoja.<sup>[[1]](#references)</sup>

Unaweza kuangalia **blogu** yao kwenye [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** pia inaunga mkono miradi ya cybersecurity ya open source kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti ni mtoa huduma wa security unaotumia jamii ya watafiti duniani kote, akitoa bug bounty na penetration-testing services. Platform yake inaunganisha bug bounty coverage endelevu na PTaaS ya mahitaji maalum pamoja na managed vulnerability disclosure programs.<sup>[[2]](#references)</sup>

**Bug bounty tip**: Jiunge na Intigriti kupitia [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) na uchunguze bug bounty programs zake.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security hutoa mafunzo ya AI security yanayojifunzwa kwa kasi yako mwenyewe na yenye mazoezi ya vitendo, kwa security engineers, wataalamu wa AppSec, na developers. AI Security Certification yake inashughulikia misingi ya LLM na agents, RAG na vector databases, threat modeling, prompt-injection na MCP attacks, pamoja na defensive architecture.<sup>[[3]](#references)</sup>

👉 Maelezo zaidi kuhusu kozi ya AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** hutoa APIs za Google na search engines nyingine, ikirejesha structured SERP data yenye vipengele kama matokeo yanayotambua eneo, Maps, Shopping, na Knowledge Graph.<sup>[[4]](#references)</sup>

Kwa maelezo zaidi, angalia [**blogu**](https://serpapi.com/blog/) yao, jaribu mfano kwenye [**playground**](https://serpapi.com/playground), au [**fungua akaunti ya bure**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** hutoa kozi za mobile na AI-security zinazojifunzwa kwa kasi yako mwenyewe. Catalog yake inashughulikia mobile application auditing na reversing kwa kutumia tools kama Ghidra, Frida, na LLDB, pamoja na AI/LLM attack and defense labs.<sup>[[5]](#references)[[6]](#references)</sup>

Vinjari [catalog ya kozi za 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** inatangaza offensive-AI platform inayochora ramani ya code na infrastructure, kisha kutumia static na dynamic agents kutafuta na kuthibitisha udhaifu unaoweza kutumiwa, ikiwa na ushahidi wa proof-of-concept na mwongozo wa remediation.<sup>[[7]](#references)</sup>

**Code security tip**: Ichunguze Naxus kwa ajili ya vulnerability discovery inayolenga code na infrastructure.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec hutoa penetration testing, security subscriptions, staffing, na vulnerability-assessment services. Tovuti yake inasema kuwa inafanya kazi kimataifa na inashughulikia offensive security, defensive security, pamoja na governance, risk, na compliance work.<sup>[[8]](#references)</sup>

Kwa maelezo zaidi, tembelea [**tovuti**](https://websec.net/en/) yao au [**blogu**](https://websec.net/blog/).

Mbali na hayo, WebSec pia ni **mfuasi aliyejitolea wa HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Imeundwa kwa ajili ya uwanja. Imejengwa kukuzingatia wewe.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutoa mafunzo ya cybersecurity yanayoongozwa na wataalamu, yenye maudhui na labs zilizoundwa maalum na zinazotegemea real infrastructures. Programu zake hubadilishwa kulingana na mahitaji ya mashirika na huanzia assessment hadi implementation.<sup>[[9]](#references)</sup> Kwa maswali kuhusu mafunzo maalum, wasiliana nao [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kinachofanya mafunzo yao yawe tofauti:**
* Maudhui na labs zilizoundwa maalum
* Zinaungwa mkono na tools na platforms za kiwango cha juu
* Zimeundwa na kufundishwa na practitioners

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions inalenga consulting ya cybersecurity kwa sekta za **Education** na **FinTech**, ikijumuisha cloud assessments, internal na external penetration tests, vulnerability assessments, na compliance support.<sup>[[10]](#references)</sup>

Endelea kupata taarifa na habari za hivi punde kuhusu cybersecurity kwa kutembelea [**blogu**](https://www.lasttowersolutions.com/blog) yetu.

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio ni Kubernetes IDE ya desktop yenye CloudMaps visualization, multi-cluster navigation, RBAC, Helm, logs, YAML, na terminal views. Vendor anasema inaunganisha kupitia kubeconfig bila kusakinisha agents na inasaidia macOS, Windows, Linux, pamoja na air-gapped clusters.<sup>[[11]](#references)</sup>

---

## Leseni na Kanusho

Angalia ingizo la HackTricks Values & FAQ katika References hapa chini.

## Takwimu za Github

![Takwimu za HackTricks Github](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Udhibitisho wa AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [AI Security ya Vitendo: Attacks, Defenses, na Applications](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks referral](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Video ya udhamini wa WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Kozi za Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}

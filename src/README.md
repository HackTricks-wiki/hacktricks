# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Nembo za Hacktricks na usanifu wa mwendo na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks Kwenye Kompyuta Yako

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

Nakala yako ya ndani ya HackTricks **itapatikana kwenye [http://localhost:3337](http://localhost:3337)** baada ya <5 minutes (inahitaji kuunda kitabu, kuwa mvumilivu).

Vinginevyo, ikiwa una Docker Compose, unaweza kuendesha tu yafuatayo kutoka kwenye mzizi wa repo:

```bash
docker compose up
```

Hii hutumia `docker-compose.yml` iliyojumuishwa kuwasilisha branch iliyo-checkout kwa sasa kwenye host kwenye [http://localhost:3337](http://localhost:3337), huku maudhui yakisasishwa moja kwa moja. Ili kubadilisha lugha unapotumia Compose, checkout branch ya lugha unayotaka kabla ya kuanzisha service.

## Washirika wa HackTricks

---

## Marafiki wa HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber hutoa huduma za penetration testing, ukaguzi wa usalama, kazi za exploit na utafiti, zana, na uhamasishaji kuhusu usalama. Tovuti yake inaeleza kuhusu timu ya penetration testers, programmers, na watafiti wa usalama walio na uzoefu wa zaidi ya muongo mmoja.<sup>[[1]](#references)</sup>

Unaweza kuangalia **blog** yao kwenye [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** pia huunga mkono miradi ya usalama wa mtandao ya open source kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti ni mtoa huduma za usalama unaotegemea umati, anayetoa huduma za bug bounty na penetration testing kupitia jumuiya ya kimataifa ya watafiti. Jukwaa lake huchanganya huduma endelevu za bug bounty na PTaaS inayopatikana inapohitajika pamoja na programu zinazosimamiwa za ufichuzi wa udhaifu.<sup>[[2]](#references)</sup>

**Kidokezo cha bug bounty**: Jiunge na Intigriti kupitia [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) na uchunguze programu zake za bug bounty.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security hutoa mafunzo ya usalama wa AI ya vitendo, yanayofuatwa kwa kasi yako mwenyewe, kwa wahandisi wa usalama, wataalamu wa AppSec, na developers. Cheti chake cha AI Security kinashughulikia misingi ya LLM na agents, RAG na vector databases, threat modeling, mashambulizi ya prompt-injection na MCP, pamoja na usanifu wa ulinzi.<sup>[[3]](#references)</sup>

👉 Maelezo zaidi kuhusu kozi ya AI Security:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** hutoa API za Google na search engines nyingine, zikirejesha data ya SERP iliyopangwa yenye vipengele kama matokeo yanayozingatia eneo, Maps, Shopping, na matokeo ya Knowledge Graph.<sup>[[4]](#references)</sup>

Kwa maelezo zaidi, tembelea [**blog**](https://serpapi.com/blog/) yao, jaribu mfano kwenye [**playground**](https://serpapi.com/playground) yao, au [**fungua akaunti ya bure**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** hutoa kozi za usalama wa mobile na AI ambazo unaweza kufuata kwa kasi yako mwenyewe. Orodha yake ya kozi inashughulikia ukaguzi na reverse engineering ya mobile applications kwa kutumia zana kama Ghidra, Frida, na LLDB, pamoja na maabara za mashambulizi na ulinzi wa AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Vinjari [orodha ya kozi za 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Autonomous Offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** ni jukwaa la offensive security linalotumia AI kwa uchunguzi kamili wa attack surface ya nje, ukaguzi wa mobile apps, majaribio ya black-box ya wavuti, na mapitio ya source code. Agents zake huthibitisha matokeo yanayoweza kutumiwa vibaya na kutoa ushahidi unaoweza kufuatiliwa, exploits za proof-of-concept, na mapendekezo yanayoweza kutekelezwa ya kurekebisha.<sup>[[7]](#references)</sup>

**Kidokezo cha ukaguzi wa usalama**: Tumia Naxus kufanya ukaguzi huru wa mwanzo hadi mwisho wa assets za nje, mobile apps, web apps, na source code.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec hutoa huduma za penetration testing, usajili wa huduma za usalama, upatikanaji wa wataalamu, na tathmini ya udhaifu. Tovuti yake inasema kuwa inafanya kazi kimataifa na inashughulikia offensive security, defensive security, na kazi za governance, risk, and compliance.<sup>[[8]](#references)</sup>

Kwa maelezo zaidi, tembelea [**tovuti**](https://websec.net/en/) au [**blog**](https://websec.net/blog/) yao.

Mbali na hayo, WebSec pia ni **mfuasi wa dhati wa HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Imeundwa kwa ajili ya kazi halisi. Imejengwa kwa kuzingatia mahitaji yako.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutoa mafunzo ya usalama wa mtandao yanayoongozwa na wataalamu, yenye maudhui maalum na maabara zinazotegemea miundombinu halisi. Programu zake hubadilishwa kulingana na mahitaji ya shirika na huanzia tathmini hadi utekelezaji.<sup>[[9]](#references)</sup> Kwa maulizo kuhusu mafunzo maalum, wasiliana nao [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kinachotofautisha mafunzo yao:**
* Maudhui na maabara zilizoundwa mahsusi
* Zinaungwa mkono na zana na majukwaa bora
* Zimeundwa na kufundishwa na wataalamu waliobobea

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions hulenga ushauri wa usalama wa mtandao kwa sekta za **Elimu** na **FinTech**, ikijumuisha tathmini za cloud, penetration tests za ndani na nje, tathmini za udhaifu, na usaidizi wa uzingatiaji wa viwango.<sup>[[10]](#references)</sup>

Pata habari za hivi karibuni kuhusu usalama wa mtandao kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog) yetu.

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio ni IDE ya Kubernetes ya desktop yenye mwonekano wa CloudMaps, urambazaji wa multi-cluster, RBAC, Helm, logs, YAML, na terminal. Mtoa huduma anasema inaunganisha kupitia kubeconfig bila kusakinisha agents na inasaidia macOS, Windows, Linux, na clusters zilizotengwa na mtandao.<sup>[[11]](#references)</sup>

---

## Leseni na Kanusho

Tazama kipengele cha HackTricks Values & FAQ katika References hapa chini.

## Takwimu za Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Cheti cha AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Usalama wa AI wa Vitendo: Mashambulizi, Ulinzi, na Matumizi](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Kiungo cha rufaa cha Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Video ya udhamini wa WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Kozi za Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Maadili na Maswali Yanayoulizwa Mara kwa Mara ya HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}

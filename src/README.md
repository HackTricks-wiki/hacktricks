# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Nembo za HackTricks na usanifu wa michoro inayosogea vimetengenezwa na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

Nakala yako ya ndani ya HackTricks **itapatikana kwenye [http://localhost:3337](http://localhost:3337)** baada ya dakika <5 (kitabu kinahitaji kujengwa, tafadhali subiri).

Vinginevyo, ikiwa una Docker Compose, unaweza tu kutekeleza yafuatayo kutoka kwenye mzizi wa repo:

```bash
docker compose up
```

Hii hutumia `docker-compose.yml` iliyojumuishwa ili kutoa branch iliyochaguliwa kwa sasa kwenye host kwenye [http://localhost:3337](http://localhost:3337), ikiwa na live reload. Ili kubadilisha lugha unapotumia Compose, chagua branch ya lugha unayotaka kabla ya kuanzisha huduma.

## Washirika wa HackTricks

---

## Marafiki wa HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber hutoa huduma za penetration testing, ukaguzi wa usalama, kazi za exploit na utafiti, zana, na uhamasishaji kuhusu usalama. Tovuti yao inaeleza kuwa wana timu ya wataalamu wa penetration testing, watengenezaji programu, na watafiti wa usalama wenye uzoefu wa zaidi ya muongo mmoja.<sup>[[1]](#references)</sup>

Unaweza kuangalia **blog** yao kwenye [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** pia huunga mkono miradi ya usalama wa mtandao ya open source kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti ni mtoa huduma wa usalama unaotegemea umati, anayetoa huduma za bug bounty na penetration testing kupitia jumuiya ya kimataifa ya watafiti. Jukwaa lake linachanganya huduma endelevu za bug bounty na PTaaS ya mahitaji na programu zinazosimamiwa za ufichuaji wa udhaifu.<sup>[[2]](#references)</sup>

**Kidokezo cha bug bounty**: Jiunge na Intigriti kupitia [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) na uchunguze programu zake za bug bounty.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security hutoa mafunzo ya usalama wa AI ya kujifunza kwa kasi yako mwenyewe na yanayohusisha vitendo, kwa wahandisi wa usalama, wataalamu wa AppSec, na watengenezaji programu. Cheti chake cha Usalama wa AI kinashughulikia misingi ya LLM na agent, RAG na hifadhidata za vekta, threat modeling, mashambulizi ya prompt-injection na MCP, pamoja na usanifu wa ulinzi.<sup>[[3]](#references)</sup>

👉 Maelezo zaidi kuhusu kozi ya Usalama wa AI:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** hutoa APIs za Google na injini nyingine za utafutaji, zikirejesha data ya SERP iliyopangwa yenye vipengele kama matokeo yanayotambua eneo, Maps, Shopping, na Knowledge Graph.<sup>[[4]](#references)</sup>

Kwa maelezo zaidi, angalia [**blog**](https://serpapi.com/blog/) yao, jaribu mfano kwenye [**playground**](https://serpapi.com/playground) yao, au [**fungua akaunti ya bure**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** hutoa kozi za mobile na usalama wa AI ambazo unaweza kujifunza kwa kasi yako mwenyewe. Orodha yake ya kozi inashughulikia ukaguzi na reverse engineering ya programu za mobile kwa kutumia zana kama Ghidra, Frida, na LLDB, pamoja na maabara za mashambulizi na ulinzi wa AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Vinjari [orodha ya kozi za 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** hutangaza jukwaa la offensive-AI linalochora ramani ya code na miundombinu, kisha kutumia mawakala tuli na tendaji kutafuta na kuthibitisha udhaifu unaoweza kutumiwa, likitoa ushahidi wa proof-of-concept na mwongozo wa kurekebisha.<sup>[[7]](#references)</sup>

**Kidokezo cha usalama wa code**: Chunguza Naxus kwa ajili ya kugundua udhaifu unaohusu code na miundombinu.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec hutoa huduma za penetration testing, usajili wa huduma za usalama, utoaji wa wataalamu, na tathmini ya udhaifu. Tovuti yao inasema kuwa wanafanya kazi kimataifa na wanashughulikia usalama wa mashambulizi, usalama wa ulinzi, pamoja na kazi za utawala, hatari, na uzingatiaji.<sup>[[8]](#references)</sup>

Kwa maelezo zaidi, tembelea [**tovuti**](https://websec.net/en/) au [**blog**](https://websec.net/blog/) yao.

Mbali na yaliyo hapo juu, WebSec pia ni **mfuasi thabiti wa HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Imejengwa kwa ajili ya kazi za nyanjani. Imeundwa kukufaa.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutoa mafunzo ya usalama wa mtandao yanayoongozwa na wataalamu, yenye maudhui na maabara yaliyoundwa mahususi na yanayotegemea miundombinu halisi. Programu zao hulinganishwa na mahitaji ya mashirika na hujumuisha hatua kuanzia tathmini hadi utekelezaji.<sup>[[9]](#references)</sup> Kwa maswali kuhusu mafunzo maalum, wasiliana nao [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Mambo yanayotofautisha mafunzo yao:**
* Maudhui na maabara zilizoundwa mahususi
* Zinaungwa mkono na zana na majukwaa ya kiwango cha juu
* Zimeundwa na kufundishwa na wataalamu waliobobea

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions hujikita katika ushauri wa usalama wa mtandao kwa **Elimu** na **FinTech**, ikijumuisha tathmini za cloud, penetration tests za ndani na nje, tathmini za udhaifu, na usaidizi wa uzingatiaji.<sup>[[10]](#references)</sup>

Pata habari na taarifa za hivi punde kuhusu usalama wa mtandao kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog) yetu.

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio ni IDE ya Kubernetes ya kompyuta ya mezani yenye uonyeshaji wa CloudMaps, urambazaji wa multi-cluster, RBAC, Helm, kumbukumbu, YAML, na mwonekano wa terminal. Mtoa huduma anasema inaunganisha kupitia kubeconfig bila kusakinisha agents na inasaidia macOS, Windows, Linux, na clusters zilizotengwa na mtandao.<sup>[[11]](#references)</sup>

---

## Leseni na Kanusho

Tazama kipengee cha HackTricks Values & FAQ katika References hapa chini.

## Takwimu za Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Cheti cha Usalama wa AI – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Usalama wa AI wa Vitendo: Mashambulizi, Ulinzi, na Matumizi](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Rufaa ya Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Video ya udhamini wa WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Kozi za Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Maadili na Maswali Yanayoulizwa Mara kwa Mara ya HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}

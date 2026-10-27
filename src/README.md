# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo za HackTricks na muundo wa mwendo umefanywa na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

Nakala yako ya ndani ya HackTricks **itapatikana katika [http://localhost:3337](http://localhost:3337)** baada ya chini ya dakika 5 (kitabu kinahitaji kujengwa, kuwa mvumilivu).

Vinginevyo, ikiwa una Docker Compose, unaweza kutekeleza tu yafuatayo kutoka kwenye mzizi wa repo:

```bash
docker compose up
```

Hii hutumia `docker-compose.yml` iliyojumuishwa ili kuhudumia branch iliyochaguliwa kwa sasa kwenye host katika [http://localhost:3337](http://localhost:3337), ikiwa na live reload. Ili kubadilisha lugha unapotumia Compose, chagua branch ya lugha unayotaka kabla ya kuanzisha huduma.

## Washirika wa HackTricks

---

## Marafiki wa HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber hutoa huduma za penetration testing, ukaguzi wa usalama, kazi za exploit na utafiti, zana, na huduma za uhamasishaji kuhusu usalama. Tovuti yao inaeleza kuhusu timu ya wataalamu wa penetration testing, watengenezaji programu, na watafiti wa usalama walio na uzoefu wa zaidi ya muongo mmoja.<sup>[[1]](#references)</sup>

Unaweza kutembelea **blogu** yao kwenye [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** pia huunga mkono miradi ya open source ya usalama wa mtandao kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti ni mtoa huduma za usalama wa crowdsourced, anayetoa huduma za bug bounty na penetration testing kupitia jumuiya ya kimataifa ya watafiti. Jukwaa lake linachanganya huduma endelevu za bug bounty na PTaaS ya kuhitajiwa pamoja na programu zinazosimamiwa za kuripoti udhaifu.<sup>[[2]](#references)</sup>

**Kidokezo cha bug bounty**: Jiunge na Intigriti kupitia [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) na uchunguze programu zake za bug bounty.

---

### [Modern Security – Jukwaa la Mafunzo ya AI na Usalama wa Programu](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security hutoa mafunzo ya usalama wa AI yanayofanywa kwa kasi ya mwanafunzi mwenyewe na yanayohusisha vitendo, kwa wahandisi wa usalama, wataalamu wa AppSec, na watengenezaji. Cheti chake cha Usalama wa AI kinashughulikia misingi ya LLM na agents, RAG na vector databases, threat modeling, mashambulizi ya prompt injection na MCP, na usanifu wa ulinzi.<sup>[[3]](#references)</sup>

👉 Maelezo zaidi kuhusu kozi ya Usalama wa AI:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** hutoa APIs za Google na injini nyingine za utafutaji, zikirudisha data iliyopangwa ya SERP yenye vipengele kama matokeo yanayotambua eneo, Maps, Shopping, na Knowledge Graph.<sup>[[4]](#references)</sup>

Kwa maelezo zaidi, tembelea [**blogu**](https://serpapi.com/blog/) yao, jaribu mfano kwenye [**playground**](https://serpapi.com/playground) yao, au [**fungua akaunti ya bure**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Kozi za Kina za Usalama wa Simu na AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** hutoa kozi za usalama wa simu na AI zinazofanywa kwa kasi ya mwanafunzi mwenyewe. Orodha yake ya kozi inajumuisha ukaguzi na reversing ya programu za simu kwa kutumia zana kama Ghidra, Frida, na LLDB, pamoja na maabara za mashambulizi na ulinzi wa AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Vinjari [orodha ya kozi za 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Kichanganuzi cha Usalama Kinachotumia AI](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** inatangaza jukwaa la offensive AI linalochora ramani ya code na miundombinu, kisha kutumia agents tuli na za wakati wa utekelezaji kutafuta na kuthibitisha udhaifu unaoweza kutumiwa, likitoa ushahidi wa proof-of-concept na mwongozo wa urekebishaji.<sup>[[7]](#references)</sup>

**Kidokezo cha usalama wa code**: Chunguza Naxus kwa ajili ya kugundua udhaifu unaohusu code na miundombinu.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec hutoa huduma za penetration testing, usajili wa huduma za usalama, upangaji wa wafanyakazi, na tathmini ya udhaifu. Tovuti yao inasema wanafanya kazi kimataifa na hushughulikia usalama wa kukera, usalama wa kujihami, pamoja na utawala, hatari, na uzingatiaji wa kanuni.<sup>[[8]](#references)</sup>

Kwa maelezo zaidi, tembelea [**tovuti**](https://websec.net/en/) au [**blogu**](https://websec.net/blog/) yao.

Mbali na hayo, WebSec pia ni **mfuasi thabiti wa HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="nembo ya cyberhelmets"><figcaption></figcaption></figure>


**Imeundwa kwa ajili ya kazi halisi. Imejengwa kukuzingatia.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutoa mafunzo ya usalama wa mtandao yanayoongozwa na wataalamu, yenye maudhui na maabara maalum yanayotokana na miundombinu halisi. Programu zao hulingana na mahitaji ya mashirika na huanzia tathmini hadi utekelezaji.<sup>[[9]](#references)</sup> Kwa maswali kuhusu mafunzo maalum, wasiliana nao [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kinachotofautisha mafunzo yao:**
* Maudhui na maabara zilizoundwa mahususi
* Zinaungwa mkono na zana na majukwaa ya kiwango cha juu
* Zimeundwa na kufundishwa na wataalamu wa vitendo

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="nembo ya lasttower"><figcaption></figcaption></figure>

Last Tower Solutions hujikita katika ushauri wa usalama wa mtandao kwa sekta za **Elimu** na **FinTech**, ikijumuisha tathmini za cloud, penetration tests za ndani na za nje, tathmini za udhaifu, na usaidizi wa uzingatiaji wa kanuni.<sup>[[10]](#references)</sup>

Pata habari na taarifa za karibuni kuhusu usalama wa mtandao kwa kutembelea [**blogu**](https://www.lasttowersolutions.com/blog) yetu.

---

### [K8Studio - GUI Mahiri Zaidi ya Kusimamia Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="nembo ya k8studio"><figcaption></figcaption></figure>

K8Studio ni IDE ya Kubernetes ya kompyuta ya mezani yenye taswira za CloudMaps, urambazaji wa multi-cluster, RBAC, Helm, kumbukumbu, YAML, na mwonekano wa terminal. Kampuni hiyo inasema huunganisha kupitia kubeconfig bila kusakinisha agents na hutumia macOS, Windows, Linux, na clusters zisizounganishwa na mtandao.<sup>[[11]](#references)</sup>

---

## Leseni na Kanusho

Tazama sehemu ya HackTricks Values & FAQ katika References hapa chini.

## Takwimu za Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Cheti cha Usalama wa AI – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Usalama wa AI kwa Vitendo: Mashambulizi, Ulinzi, na Matumizi](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Rufaa ya Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Video ya udhamini wa WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Kozi za Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Thamani na Maswali Yanayoulizwa Mara kwa Mara ya HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}

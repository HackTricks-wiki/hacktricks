# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo za Hacktricks na usanifu wa mwendo umetengenezwa na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

Nakala yako ya karibu ya HackTricks **itapatikana kwenye [http://localhost:3337](http://localhost:3337)** baada ya <dakika 5 (inahitaji kuunda kitabu, kuwa mvumilivu).

Vinginevyo, ikiwa una Docker Compose, unaweza kuendesha tu yafuatayo kutoka kwenye mzizi wa repo:

```bash
docker compose up
```

Hii hutumia `docker-compose.yml` iliyojumuishwa ili kutoa branch iliyochaguliwa kwa sasa kwenye host kupitia [http://localhost:3337](http://localhost:3337), ikiwa na live reload. Ili kubadilisha lugha unapotumia Compose, chagua branch ya lugha unayotaka kabla ya kuanzisha huduma.

## Washirika wa HackTricks

---

## Marafiki wa HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber hutoa huduma za pentesting, ukaguzi wa usalama, kazi za exploit na utafiti, zana, na uhamasishaji wa usalama. Tovuti yake inaeleza kuhusu timu ya wataalamu wa pentesting, watengenezaji programu, na watafiti wa usalama walio na uzoefu wa zaidi ya muongo mmoja.<sup>[[1]](#references)</sup>

Unaweza kuangalia **blogu** yao kwenye [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** pia huunga mkono miradi ya open source ya cybersecurity kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti ni mtoa huduma wa usalama wa crowdsourced anayetoa huduma za bug bounty na pentesting kupitia jumuiya ya kimataifa ya watafiti. Mfumo wake unajumuisha ufunikaji endelevu wa bug bounty pamoja na PTaaS inayopatikana unapohitajika na programu zinazosimamiwa za kuripoti udhaifu.<sup>[[2]](#references)</sup>

**Kidokezo cha bug bounty**: Jiunge na Intigriti kupitia [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) na uchunguze programu zake za bug bounty.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security hutoa mafunzo ya usalama wa AI ya kujisomea, yenye mazoezi ya vitendo, kwa wahandisi wa usalama, wataalamu wa AppSec, na watengenezaji. Cheti chake cha Usalama wa AI kinashughulikia misingi ya LLM na mawakala, RAG na hifadhidata za vekta, threat modeling, mashambulizi ya prompt injection na MCP, na usanifu wa ulinzi.<sup>[[3]](#references)</sup>

👉 Maelezo zaidi kuhusu kozi ya Usalama wa AI:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** hutoa API za Google na injini nyingine za utafutaji, zinazorejesha data iliyopangwa ya SERP yenye vipengele kama matokeo yanayozingatia eneo, Maps, Shopping, na matokeo ya Knowledge Graph.<sup>[[4]](#references)</sup>

Kwa maelezo zaidi, angalia [**blogu**](https://serpapi.com/blog/) yao, jaribu mfano kwenye [**playground**](https://serpapi.com/playground), au [**fungua akaunti ya bure**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** hutoa kozi za kujisomea za usalama wa mobile na AI. Orodha yake ya kozi inajumuisha ukaguzi na reversing ya programu za mobile kwa kutumia zana kama Ghidra, Frida, na LLDB, pamoja na maabara za mashambulizi na ulinzi wa AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Vinjari [orodha ya kozi za 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Autonomous Offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** ni mfumo wa offensive security unaotumia AI kwa ukaguzi kamili wa attack surface ya nje, ukaguzi wa programu za mobile, majaribio ya black-box ya wavuti, na ukaguzi wa source code. Mawakala wake huthibitisha matokeo yanayoweza kutumiwa vibaya na kutoa ushahidi unaoweza kufuatiliwa, exploits za proof-of-concept, na mapendekezo ya kurekebisha yanayoweza kutekelezwa.<sup>[[7]](#references)</sup>

**Kidokezo cha ukaguzi wa usalama**: Tumia Naxus kufanya ukaguzi huru wa mwanzo hadi mwisho kwenye assets za nje, programu za mobile, programu za wavuti, na source code.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec hutoa huduma za pentesting, usajili wa huduma za usalama, uajiri wa wataalamu, na tathmini ya udhaifu. Tovuti yake inasema kuwa kampuni hiyo inafanya kazi kimataifa na hushughulikia offensive security, defensive security, na kazi za utawala, hatari na uzingatiaji.<sup>[[8]](#references)</sup>

Kwa maelezo zaidi, tembelea [**tovuti**](https://websec.net/en/) au [**blogu**](https://websec.net/blog/) yao.

Mbali na yaliyo hapo juu, WebSec pia ni **mfuasi thabiti wa HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Imeundwa kwa ajili ya kazi halisi. Imejengwa kukuzingatia.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutoa mafunzo ya cybersecurity yanayoongozwa na wataalamu, yenye maudhui na maabara maalum yanayotegemea miundombinu halisi. Programu zake huandaliwa kulingana na mahitaji ya mashirika na hushughulikia hatua kuanzia tathmini hadi utekelezaji.<sup>[[9]](#references)</sup> Kwa maswali kuhusu mafunzo maalum, wasiliana nao [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kinachotofautisha mafunzo yao:**
* Maudhui na maabara maalum
* Yanaungwa mkono na zana na mifumo ya kiwango cha juu
* Yameundwa na kufundishwa na wataalamu waliobobea

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions huzingatia ushauri wa cybersecurity kwa sekta za **Elimu** na **FinTech**, ikijumuisha tathmini za cloud, pentesting za ndani na nje, tathmini za udhaifu, na usaidizi wa uzingatiaji.<sup>[[10]](#references)</sup>

Pata habari za hivi punde kuhusu cybersecurity kwa kutembelea [**blogu**](https://www.lasttowersolutions.com/blog) yetu.

---

### [Beaki — Food that fits you](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki logo"><figcaption></figcaption></figure>

**Beaki** ni kichanganuzi cha vyakula kinachobinafsishwa, kihesabu kalori, na kifuatilia lishe. Changanua misimbo pau na rafu za maduka makubwa, piga picha au eleza milo na menyu za migahawa, kisha upate alama zinazoelezeka na zinazozingatia malengo yako, lishe, mzio, na wasifu wa afya. Beaki pia hufuatilia kalori na macros na kuunda mipango ya milo iliyobinafsishwa pamoja na orodha za ununuzi.<sup>[[11]](#references)</sup>

[**Pakua Beaki bila malipo**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks) kwenye Android au iPhone.

---

## Leseni na Kanusho

Tazama kipengee cha HackTricks Values & FAQ kwenye References hapa chini.

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
- [11] [Beaki](https://www.beaki.app/)
- [12] [Rufaa ya Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Video ya udhamini wa WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Kozi za Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Maadili na Maswali Yanayoulizwa Mara kwa Mara ya HackTricks](welcome/hacktricks-values-and-faq.md)

{{#include banners/hacktricks-training.md}}

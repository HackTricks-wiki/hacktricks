# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logos & motion design by_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks Kwenye Kompyuta Yako
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export LANG="master" # Leave master for english
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
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Your local copy of HackTricks will be **available at [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni nzuri ya usalama wa mtandao ambayo kauli mbiu yake ni **HACK THE UNHACKABLE**. Wanatekeleza utafiti wao wenyewe na kuunda zana zao za udukuzi ili **kutoa huduma kadhaa za thamani za usalama wa mtandao** kama pentesting, Red teams na mafunzo.

Unaweza kuangalia **blog** yao katika [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia inasaidia miradi ya usalama wa mtandao ya chanzo wazi kama HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **lengo la kukuza maarifa ya kiufundi**, kongamano hili ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila taaluma.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni **jukwaa la udukuzi wa kimaadili na bug bounty nambari moja barani Ulaya.**

**Nasaha ya bug bounty**: **jiandikishe** kwa **Intigriti**, jukwaa la **bug bounty la kiwango cha juu lililotengenezwa na hackers, kwa hackers**! Jiunge nasi katika [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata zawadi hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kujenga na **kujiendesha kiotomatiki** kwa urahisi kwa kutumia zana za jamii zenye **maendeleo zaidi** duniani.

Pata Ufikiaji Leo:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na hackers wenye uzoefu na wawindaji wa bug bounty!

- **Maoni ya Udukuzi:** Jihusishe na maudhui yanayoangazia msisimko na changamoto za udukuzi
- **Habari za Udukuzi kwa Wakati Halisi:** Fuata habari za haraka za ulimwengu wa udukuzi kupitia habari na maoni ya wakati halisi
- **Matangazo ya Karibuni:** Kuwa na habari kuhusu bug bounties mpya zinazozinduliwa na masasisho muhimu ya jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na hackers bora leo!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - Zana muhimu za kupima udukuzi

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Pata mtazamo wa hacker kuhusu programu zako za wavuti, mtandao, na wingu**

**Pata na ripoti kuhusu udhaifu muhimu, unaoweza kutumiwa kwa faida halisi ya biashara.** Tumia zana zetu 20+ za kawaida kupanga uso wa shambulio, pata masuala ya usalama yanayokuruhusu kupandisha mamlaka, na tumia mashambulizi ya kiotomatiki kukusanya ushahidi muhimu, ukigeuza kazi yako kuwa ripoti za kushawishi.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** inatoa APIs za wakati halisi kwa urahisi ili **kupata matokeo ya injini za utafutaji**. Wanakusanya data kutoka kwa injini za utafutaji, kushughulikia proxies, kutatua captchas, na kuchambua data zote zenye muundo wa tajiri kwa ajili yako.

Usajili wa moja ya mipango ya SerpApi unajumuisha ufikiaji wa zaidi ya APIs 50 tofauti za kukusanya data kutoka kwa injini mbalimbali za utafutaji, ikiwa ni pamoja na Google, Bing, Baidu, Yahoo, Yandex, na zaidi.\
Tofauti na watoa huduma wengine, **SerpApi haisafishi tu matokeo ya asili**. Majibu ya SerpApi mara kwa mara yanajumuisha matangazo yote, picha na video za ndani, grafu za maarifa, na vipengele na sifa nyingine zilizopo katika matokeo ya utafutaji.

Wateja wa sasa wa SerpApi ni pamoja na **Apple, Shopify, na GrubHub**.\
Kwa maelezo zaidi angalia [**blog**](https://serpapi.com/blog/)** yao,** au jaribu mfano katika [**playground**](https://serpapi.com/playground)** yao.**\
Unaweza **kuunda akaunti ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Kozi za Usalama wa Simu za Mkononi kwa Undani](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Jifunze teknolojia na ujuzi unaohitajika kufanya utafiti wa udhaifu, kupima udukuzi, na uhandisi wa kurudi ili kulinda programu na vifaa vya simu. **Tawala usalama wa iOS na Android** kupitia kozi zetu za on-demand na **pata cheti**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalamu ya usalama wa mtandao iliyo na makao yake nchini **Amsterdam** ambayo husaidia **kulinda** biashara **duniani kote** dhidi ya vitisho vya hivi karibuni vya usalama wa mtandao kwa kutoa **huduma za usalama wa mashambulizi** kwa njia ya **kisasa**.

WebSec ni kampuni ya usalama ya kimataifa yenye ofisi nchini Amsterdam na Wyoming. Wanatoa **huduma za usalama za kila kitu** ambayo inamaanisha wanafanya kila kitu; Pentesting, **Ukaguzi wa** Usalama, Mafunzo ya Uelewa, Kampeni za Phishing, Mapitio ya Kanuni, Maendeleo ya Mashambulizi, Utoaji wa Wataalamu wa Usalama na mengi zaidi.

Jambo lingine zuri kuhusu WebSec ni kwamba tofauti na wastani wa sekta WebSec **ina imani kubwa katika ujuzi wao**, hadi kiwango kwamba **wanahakikishia matokeo bora ya ubora**, inasema kwenye tovuti yao "**Ikiwa hatuwezi kuikabili, Hupaswi kulipa!**". Kwa maelezo zaidi angalia [**tovuti**](https://websec.net/en/) yao na [**blog**](https://websec.net/blog/) yao!

Mbali na hayo WebSec pia ni **mshabiki aliyejitolea wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) ni injini ya kutafuta uvunjaji wa data (leak). \
Tunatoa utafutaji wa mfuatano wa nasibu (kama google) juu ya aina zote za uvunjaji wa data kubwa na ndogo --sio tu kubwa-- kutoka kwa vyanzo vingi. \
Watu wanatafuta, AI inatafuta, utafutaji wa shirika, ufikiaji wa API (OpenAPI), ushirikiano wa theHarvester, vipengele vyote ambavyo pentester anahitaji.\
**HackTricks inaendelea kuwa jukwaa kubwa la kujifunza kwa sisi sote na tunajivunia kuwa wadhamini wake!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions inatoa huduma maalum za usalama wa mtandao kwa **Elimu** na **FinTech**
taasisi, kwa kuzingatia **kupima udukuzi, tathmini za usalama wa wingu**, na
**kujiandaa kwa kufuata** (SOC 2, PCI-DSS, NIST). Timu yetu inajumuisha **wataalamu walioidhinishwa wa OSCP na CISSP**, wakileta utaalamu wa kiufundi wa kina na maarifa ya viwango vya tasnia kwa kila ushirikiano.

Tunazidi skana za kiotomatiki kwa **kupima kwa mikono, kulingana na akili** iliyoundwa kwa mazingira yenye hatari kubwa. Kutoka kulinda rekodi za wanafunzi hadi kulinda shughuli za kifedha,
tunasaidia mashirika kulinda kile ambacho ni muhimu zaidi.

_“Ulinzi wa ubora unahitaji kujua mashambulizi, tunatoa usalama kupitia uelewa.”_

Kuwa na habari na kuwa na habari kuhusu mambo mapya katika usalama wa mtandao kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog) yetu.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

## License & Disclaimer

Check them in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}

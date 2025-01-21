# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logos & motion design by_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks Kwenye Kompyuta Yako
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks
# Run the docker container indicating the path to the hacktricks folder
docker run --rm -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Your local copy of HackTricks will be **available at [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni kubwa ya usalama wa mtandao ambayo kauli mbiu yake ni **HACK THE UNHACKABLE**. Wanatekeleza utafiti wao wenyewe na kuunda zana zao za udukuzi ili **kutoa huduma kadhaa za thamani za usalama wa mtandao** kama pentesting, Red teams na mafunzo.

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

**Intigriti** ni **jukwaa nambari moja** la udukuzi wa kimaadili na **bug bounty** barani **Ulaya**.

**Bug bounty tip**: **jiandikishe** kwa **Intigriti**, jukwaa la **bug bounty la kiwango cha juu lililotengenezwa na hackers, kwa hackers**! Jiunge nasi katika [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata zawadi hadi **$100,000**!

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

- **Hacking Insights:** Jihusishe na maudhui yanayoangazia msisimko na changamoto za udukuzi
- **Real-Time Hack News:** Fuata habari za haraka za ulimwengu wa udukuzi kupitia habari na maarifa ya wakati halisi
- **Latest Announcements:** Kuwa na habari kuhusu bug bounties mpya zinazozinduliwa na masasisho muhimu ya jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na hackers bora leo!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Pata mtazamo wa hacker kuhusu programu zako za wavuti, mtandao, na wingu**

**Pata na ripoti kuhusu udhaifu muhimu, unaoweza kutumiwa kwa faida halisi.** Tumia zana zetu zaidi ya 20 za kawaida kupanga uso wa shambulio, pata masuala ya usalama yanayokuruhusu kupandisha hadhi, na tumia mashambulizi ya kiotomatiki kukusanya ushahidi muhimu, ukigeuza kazi yako kuwa ripoti za kuvutia.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** inatoa APIs za haraka na rahisi za wakati halisi ili **kupata matokeo ya injini za utafutaji**. Wanakusanya data kutoka kwa injini za utafutaji, kushughulikia proxies, kutatua captchas, na kuchambua data yote ya muundo wa tajiri kwa ajili yako.

Usajili wa moja ya mipango ya SerpApi unajumuisha ufikiaji wa zaidi ya APIs 50 tofauti za kukusanya data kutoka kwa injini tofauti za utafutaji, ikiwa ni pamoja na Google, Bing, Baidu, Yahoo, Yandex, na zaidi.\
Tofauti na watoa huduma wengine, **SerpApi haisafishi tu matokeo ya asili**. Majibu ya SerpApi mara kwa mara yanajumuisha matangazo yote, picha na video za ndani, grafu za maarifa, na vipengele na sifa nyingine zilizopo katika matokeo ya utafutaji.

Wateja wa sasa wa SerpApi ni pamoja na **Apple, Shopify, na GrubHub**.\
Kwa maelezo zaidi angalia [**blog**](https://serpapi.com/blog/)** yao,** au jaribu mfano katika [**playground**](https://serpapi.com/playground)** yao.**\
Unaweza **kuunda akaunti ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Jifunze teknolojia na ujuzi unaohitajika kufanya utafiti wa udhaifu, kupima udukuzi, na uhandisi wa kurudi ili kulinda programu na vifaa vya simu. **Tawala usalama wa iOS na Android** kupitia kozi zetu za on-demand na **pata cheti**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.nl/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.nl) ni kampuni ya kitaalamu ya usalama wa mtandao iliyo na makao yake nchini **Amsterdam** ambayo inasaidia **kulinda** biashara **duniani kote** dhidi ya vitisho vya hivi karibuni vya usalama wa mtandao kwa kutoa **huduma za usalama wa mashambulizi** kwa njia ya **kisasa**.

WebSec ni kampuni ya **usalama wa kila kitu** ambayo inamaanisha wanafanya kila kitu; Pentesting, **Ukaguzi wa** Usalama, Mafunzo ya Uelewa, Kampeni za Phishing, Mapitio ya Kanuni, Maendeleo ya Mashambulizi, Utaalamu wa Usalama wa Kukodisha na mengi zaidi.

Jambo lingine zuri kuhusu WebSec ni kwamba tofauti na wastani wa sekta WebSec ni **na uhakika sana katika ujuzi wao**, kwa kiwango ambacho **wanahakikishia matokeo bora**, inasema kwenye tovuti yao "**Ikiwa hatuwezi kuikabili, Hupaswi kulipa!**". Kwa maelezo zaidi angalia [**tovuti**](https://websec.nl/en/) yao na [**blog**](https://websec.nl/blog/)!

Mbali na hayo WebSec pia ni **mshabiki aliyejitolea wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

## License & Disclaimer

Check them in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}

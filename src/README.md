# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logo's & bewegingsontwerp deur_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Voer HackTricks Plaaslik Uit
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Jou plaaslike kopie van HackTricks sal **beskikbaar wees by [http://localhost:3337](http://localhost:3337)** na <5 minute (dit moet die boek bou, wees geduldig).

## Korporatiewe Borge

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) is 'n uitstekende kuberveiligheid maatskappy wie se leuse is **HACK THE UNHACKABLE**. Hulle voer hul eie navorsing uit en ontwikkel hul eie hacking gereedskap om **verskeie waardevolle kuberveiligheid dienste** soos pentesting, Red teams en opleiding aan te bied.

Jy kan hul **blog** in [**https://blog.stmcyber.com**](https://blog.stmcyber.com) nagaan.

**STM Cyber** ondersteun ook kuberveiligheid open source projekte soos HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) is die mees relevante kuberveiligheid gebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n bruisende ontmoetingspunt vir tegnologie en kuberveiligheid professionele in elke dissipline.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** is die **Europa se #1** etiese hacking en **bug bounty platform.**

**Bug bounty wenk**: **meld aan** vir **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) vandag, en begin om bounties tot **$100,000** te verdien!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) om maklik **werkvloei** te bou en te **automate** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskap gereedskap.

Kry Toegang Vandag:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Sluit by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener aan om met ervare hackers en bug bounty jagters te kommunikeer!

- **Hacking Inligting:** Betrek met inhoud wat die opwinding en uitdagings van hacking ondersoek
- **Regstydse Hack Nuus:** Bly op hoogte van die vinnig bewegende hacking wêreld deur regstydse nuus en insigte
- **Laaste Aankondigings:** Bly ingelig oor die nuutste bug bounties wat bekendgestel word en belangrike platform opdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - Die noodsaaklike penetrasietoetsing gereedskapstel

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Kry 'n hacker se perspektief op jou web apps, netwerk, en wolk**

**Vind en rapporteer kritieke, exploiteerbare kwesbaarhede met werklike besigheidsimpak.** Gebruik ons 20+ pasgemaakte gereedskap om die aanvaloppervlak te karteer, vind sekuriteitskwessies wat jou toelaat om bevoegdhede te verhoog, en gebruik geoutomatiseerde eksploit om noodsaaklike bewyse te versamel, wat jou harde werk in oortuigende verslae omskep.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bied vinnige en maklike regstydse API's om **toegang tot soekenjinresultate** te verkry. Hulle scrape soekenjins, hanteer proxies, los captchas op, en parse al die ryk gestruktureerde data vir jou.

'n Intekening op een van SerpApi se planne sluit toegang tot meer as 50 verskillende API's in vir die scraping van verskillende soekenjins, insluitend Google, Bing, Baidu, Yahoo, Yandex, en meer.\
In teenstelling met ander verskaffers, **scrape SerpApi nie net organiese resultate nie**. SerpApi antwoorde sluit konsekwent al die advertensies, inline beelde en video's, kennisgrafieke, en ander elemente en funksies wat in die soekresultate teenwoordig is, in.

Huidige SerpApi kliënte sluit **Apple, Shopify, en GrubHub** in.\
Vir meer inligting, kyk na hul [**blog**](https://serpapi.com/blog/)**,** of probeer 'n voorbeeld in hul [**speelgrond**](https://serpapi.com/playground)**.**\
Jy kan **'n gratis rekening skep** [**hier**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Diepte Mobiele Sekuriteit Kursusse](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Leer die tegnologieë en vaardighede wat nodig is om kwesbaarheid navorsing, penetrasietoetsing, en omgekeerde ingenieurswese uit te voer om mobiele toepassings en toestelle te beskerm. **Meester iOS en Android sekuriteit** deur ons on-demand kursusse en **kry geakkrediteer**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) is 'n professionele kuberveiligheid maatskappy gebaseer in **Amsterdam** wat help om **besighede** **oor die wêreld** teen die nuutste kuberveiligheid bedreigings te beskerm deur **offensiewe-sekuriteit dienste** met 'n **moderne** benadering te bied.

WebSec is 'n internasionale sekuriteitsmaatskappy met kantore in Amsterdam en Wyoming. Hulle bied **alles-in-een sekuriteitsdienste** aan wat beteken dat hulle dit alles doen; Pentesting, **Sekuriteit** Oudit, Bewustheidsopleiding, Phishing Campagnes, Kode Hersiening, Eksploit Ontwikkeling, Sekuriteit Eksperte Uitsourcing en nog baie meer.

Nog 'n interessante ding oor WebSec is dat, in teenstelling met die industrie gemiddelde, WebSec **baie selfversekerd is in hul vaardighede**, tot so 'n mate dat hulle **die beste kwaliteit resultate waarborg**, dit staan op hul webwerf "**As ons dit nie kan hack nie, betaal jy nie!**". Vir meer inligting, kyk na hul [**webwerf**](https://websec.net/en/) en [**blog**](https://websec.net/blog/)!

Benewens die bogenoemde is WebSec ook 'n **toegewyde ondersteuner van HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) is 'n data breuk (leak) soekenjin. \
Ons bied random string soektog (soos google) oor alle tipes data breuke groot en klein --nie net die groot nie-- oor data van verskeie bronne. \
Mense soektog, KI soektog, organisasie soektog, API (OpenAPI) toegang, dieHarvester integrasie, al die funksies wat 'n pentester nodig het.\
**HackTricks bly 'n wonderlike leerplatform vir ons almal en ons is trots om dit te borg!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>

**Gebou vir die veld. Gebou rondom jou.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ontwikkel en lewer effektiewe kuberveiligheid opleiding wat gebou en gelei word deur
bedryf kenners. Hul programme gaan verder as teorie om spanne toe te rus met 'n diep
begrip en uitvoerbare vaardighede, met behulp van pasgemaakte omgewings wat werklike
bedreigings weerspieël. Vir pasgemaakte opleidingsnavrae, kontak ons [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Wat hul opleiding onderskei:**
* Pasgemaakte inhoud en laboratoriums
* Ondersteun deur top-graad gereedskap en platforms
* Ontwerp en geleer deur praktisyns

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions lewer gespesialiseerde kuberveiligheid dienste vir **Onderwys** en **FinTech**
instellings, met 'n fokus op **penetrasietoetsing, wolk sekuriteit assesserings**, en
**nakoming gereedheid** (SOC 2, PCI-DSS, NIST). Ons span sluit **OSCP en CISSP
geakkrediteerde professionele in**, wat diep tegniese kundigheid en bedryfstandaard insig na
elke betrokkenheid bring.

Ons gaan verder as geoutomatiseerde skanderings met **handmatige, intelligensie-gedrewe toetsing** wat aangepas is vir
hoë-stakes omgewings. Van die beveiliging van studentrekords tot die beskerming van finansiële transaksies,
help ons organisasies om te verdedig wat die belangrikste is.

_“'n Kwaliteit verdediging vereis om die aanval te ken, ons bied sekuriteit deur begrip.”_

Bly ingelig en op hoogte van die nuutste in kuberveiligheid deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

## Lisensie & Vrywaring

Kyk na hulle in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Statistieke

![HackTricks Github Statistieke](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}

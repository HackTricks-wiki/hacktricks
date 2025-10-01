# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos e motion design do HackTricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Executar HackTricks localmente
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
Sua cópia local do HackTricks estará **disponível em [http://localhost:3337](http://localhost:3337)** após <5 minutos (precisa construir o livro, seja paciente).

## Patrocinadores Corporativos

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) é uma ótima empresa de cybersecurity cujo slogan é **HACK THE UNHACKABLE**. Eles realizam suas próprias pesquisas e desenvolvem suas próprias ferramentas de hacking para **oferecer vários serviços valiosos de cybersecurity** como pentesting, Red teams e treinamento.

Você pode conferir o **blog** deles em [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** também apoia projetos de segurança open source como o HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) é o evento de cybersecurity mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cybersecurity de todas as disciplinas.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** é a **plataforma #1 da Europa** de ethical hacking e bug bounty.

**Bug bounty tip**: **inscreva-se** na **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje, e comece a ganhar recompensas de até **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar workflows** facilmente, impulsionados pelas ferramentas comunitárias mais **avançadas** do mundo.

Obtenha acesso hoje:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** Engage with content that delves into the thrill and challenges of hacking
- **Real-Time Hack News:** Keep up-to-date with fast-paced hacking world through real-time news and insights
- **Latest Announcements:** Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenha a perspectiva de um hacker sobre suas web apps, rede e cloud**

**Encontre e reporte vulnerabilidades críticas e exploráveis com impacto real no negócio.** Use nossas mais de 20 ferramentas customizadas para mapear a superfície de ataque, encontrar problemas de segurança que permitam escalar privilégios, e usar exploits automatizados para coletar evidências essenciais, transformando seu trabalho em relatórios persuasivos.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferece APIs rápidas e fáceis em tempo real para **acessar resultados de motores de busca**. Eles fazem scraping dos motores de busca, gerenciam proxies, resolvem captchas e analisam todos os dados estruturados ricos para você.

Uma assinatura de um dos planos da SerpApi inclui acesso a mais de 50 APIs diferentes para scraping de diferentes motores de busca, incluindo Google, Bing, Baidu, Yahoo, Yandex e mais.\
Ao contrário de outros provedores, **SerpApi não apenas faz scraping de resultados orgânicos**. As respostas da SerpApi consistentemente incluem todos os anúncios, imagens e vídeos inline, knowledge graphs e outros elementos e features presentes nos resultados de busca.

Clientes atuais da SerpApi incluem **Apple, Shopify e GrubHub**.\
Para mais informações confira o blog deles [**aqui**](https://serpapi.com/blog/)**,** ou experimente um exemplo no [**playground**](https://serpapi.com/playground)**.**\
Você pode **criar uma conta gratuita** [**aqui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Aprenda as tecnologias e habilidades necessárias para realizar pesquisa de vulnerabilidades, penetration testing e reverse engineering para proteger aplicações e dispositivos móveis. **Domine a segurança iOS e Android** através de nossos cursos on-demand e **obtenha certificação**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) é uma empresa profissional de cybersecurity com sede em **Amsterdam** que ajuda a **proteger** empresas **ao redor do mundo** contra as mais recentes ameaças de cybersecurity, oferecendo **offensive-security services** com uma abordagem **moderna**.

A WebSec é uma empresa internacional de segurança com escritórios em Amsterdam e Wyoming. Eles oferecem **serviços de segurança all-in-one**, o que significa que fazem tudo; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing e muito mais.

Outra coisa legal sobre a WebSec é que, ao contrário da média da indústria, a WebSec é **muito confiante em suas habilidades**, a tal ponto que eles **garantem os melhores resultados de qualidade**, conforme afirmam no site deles: "**If we can't hack it, You don't pay it!**". Para mais informações dê uma olhada no [**website**](https://websec.net/en/) e no [**blog**](https://websec.net/blog/)!

Além do acima, a WebSec também é uma **apoiadora comprometida do HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) é um data breach (leak) search engine. \
Nós fornecemos busca por strings aleatórias (como o google) sobre todos os tipos de vazamentos de dados grandes e pequenos --não apenas os grandes-- sobre dados de múltiplas fontes. \
Pesquisa por pessoas, pesquisa por AI, busca por organização, API (OpenAPI) access, integração com theHarvester, todas as features que um pentester precisa.\
**HackTricks continua sendo uma ótima plataforma de aprendizado para todos nós e temos orgulho de patrociná-la!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desenvolve e entrega treinamentos de cybersecurity eficazes, construídos e liderados por especialistas da indústria. Seus programas vão além da teoria para equipar equipes com profundo entendimento e habilidades acionáveis, usando ambientes customizados que refletem ameaças do mundo real. Para consultas sobre treinamentos personalizados, entre em contato [**aqui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**O que diferencia o treinamento deles:**
* Conteúdo e labs customizados
* Apoiado por ferramentas e plataformas de alto nível
* Projetado e ensinado por praticantes

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions oferece serviços especializados de cybersecurity para instituições de **Education** e **FinTech**, com foco em **penetration testing, cloud security assessments**, e **compliance readiness** (SOC 2, PCI-DSS, NIST). Nossa equipe inclui profissionais certificados **OSCP e CISSP**, trazendo profunda expertise técnica e visão baseada em padrões da indústria para cada engajamento.

Nós vamos além de scans automatizados com **testes manuais orientados por inteligência** adaptados a ambientes de alto risco. Desde proteger registros estudantis até proteger transações financeiras, ajudamos organizações a defender o que mais importa.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Mantenha-se informado com o que há de mais recente em cybersecurity visitando o [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE capacita DevOps, DevSecOps e desenvolvedores a gerenciar, monitorar e proteger clusters Kubernetes de forma eficiente. Aproveite nossos insights movidos a AI, framework avançado de segurança e a GUI CloudMaps intuitiva para visualizar seus clusters, entender seu estado e agir com confiança.

Além disso, o K8Studio é **compatível com todas as principais distribuições de kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Confira em:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}

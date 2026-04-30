# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos e design de movimento do Hacktricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Executar HackTricks Localmente
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
Your local copy of HackTricks estará **disponível em [http://localhost:3337](http://localhost:3337)** após <5 minutos (ele precisa compilar o livro, tenha paciência).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) é uma ótima empresa de cybersecurity cujo slogan é **HACK THE UNHACKABLE**. Eles fazem sua própria pesquisa e desenvolvem suas próprias ferramentas de hacking para **oferecer vários serviços valiosos de cybersecurity** como pentesting, Red teams e training.

Você pode conferir o **blog** deles em [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** também apoia projetos open source de cybersecurity como HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** é a **plataforma de ethical hacking e bug bounty #1 da Europa.**

**Bug bounty tip**: **inscreva-se** na **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Junte-se ao servidor [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para se comunicar com hackers experientes e bug bounty hunters!

- **Hacking Insights:** Interaja com conteúdo que aprofunda a emoção e os desafios do hacking
- **Real-Time Hack News:** Fique por dentro do mundo acelerado do hacking por meio de notícias e insights em tempo real
- **Latest Announcements:** Mantenha-se informado sobre os bug bounties mais recentes lançados e atualizações importantes da plataforma

**Junte-se a nós no** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e comece a colaborar com os melhores hackers hoje mesmo!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security oferece **treinamento prático em AI Security** com uma abordagem **hands-on de laboratório, priorizando engenharia**. Nossos cursos são feitos para security engineers, profissionais de AppSec e developers que querem **construir, quebrar e proteger aplicações reais alimentadas por AI/LLM**.

A **AI Security Certification** foca em habilidades do mundo real, incluindo:
- Proteger aplicações com LLM e AI
- Threat modeling para sistemas de AI
- Embeddings, vector databases e segurança de RAG
- Ataques a LLM, cenários de abuso e defesas práticas
- Padrões de design seguro e considerações de deployment

Todos os cursos são **on-demand**, **baseados em laboratórios** e projetados em torno de **tradeoffs de segurança do mundo real**, não apenas teoria.

👉 Mais detalhes sobre o curso de AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferece APIs em tempo real rápidas e fáceis para **acessar resultados de mecanismos de busca**. Eles fazem scraping dos mecanismos de busca, lidam com proxies, resolvem captchas e fazem parse de todos os dados estruturados ricos para você.

Uma assinatura de um dos planos da SerpApi inclui acesso a mais de 50 APIs diferentes para scraping de diferentes mecanismos de busca, incluindo Google, Bing, Baidu, Yahoo, Yandex e outros.\
Ao contrário de outros provedores, a **SerpApi não faz apenas scraping de resultados orgânicos**. As respostas da SerpApi incluem consistentemente todos os anúncios, imagens e vídeos inline, knowledge graphs e outros elementos e recursos presentes nos resultados de busca.

Os clientes atuais da SerpApi incluem **Apple, Shopify e GrubHub**.\
Para mais informações, confira o [**blog**](https://serpapi.com/blog/) deles**,** ou teste um exemplo no [**playground**](https://serpapi.com/playground)**.**\
Você pode **criar uma conta gratuita** [**aqui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Aprenda as tecnologias e habilidades necessárias para realizar vulnerability research, penetration testing e reverse engineering para proteger aplicativos e dispositivos móveis. **Domine a segurança de iOS e Android** por meio dos nossos cursos on-demand e **obtenha certificação**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** é uma plataforma de segurança com AI para encontrar vulnerabilidades exploráveis antes que atacantes o façam.

**Code security tip**: inscreva-se no NaxusAI, uma plataforma inteligente de monitoramento de vulnerabilidades criada para developers e equipes de segurança! Junte-se a nós hoje e comece a usar AI para **detectar, validar e corrigir riscos de segurança reais antes que cheguem à produção**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) é uma empresa profissional de cybersecurity com sede em **Amsterdam** que ajuda a **proteger** empresas **em todo o mundo** contra as ameaças mais recentes de cybersecurity, fornecendo **serviços de offensive-security** com uma abordagem **moderna**.

WebSec é uma empresa de segurança internacional com escritórios em Amsterdam e Wyoming. Eles oferecem **serviços de segurança tudo-em-um**, o que significa que fazem tudo; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing e muito mais.

Outra coisa legal sobre a WebSec é que, ao contrário da média do setor, a WebSec é **muito confiante em suas habilidades**, a tal ponto que **garante resultados da melhor qualidade**; no site deles consta "**If we can't hack it, You don't pay it!**". Para mais informações, dê uma olhada no [**website**](https://websec.net/en/) e no [**blog**](https://websec.net/blog/) deles!

Além do acima, a WebSec também é uma **apoiante comprometida do HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desenvolve e entrega treinamentos eficazes de cybersecurity criados e liderados por especialistas do setor. Seus programas vão além da teoria para capacitar equipes com entendimento profundo e habilidades práticas, usando ambientes personalizados que refletem ameaças do mundo real. Para consultas sobre treinamentos personalizados, fale conosco [**aqui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**O que diferencia seus treinamentos:**
* Conteúdo e laboratórios desenvolvidos sob medida
* Sustentado por ferramentas e plataformas de primeira linha
* Projetado e ministrado por practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions entrega serviços especializados de cybersecurity para instituições de **Education** e **FinTech**,
com foco em **penetration testing, cloud security assessments** e
**compliance readiness** (SOC 2, PCI-DSS, NIST). Nossa equipe inclui profissionais **certificados em OSCP e CISSP**,
trazendo profunda expertise técnica e visão padrão do setor para
cada engagement.

Vamos além de scans automatizados com **manual, intelligence-driven testing** adaptado a
ambientes de alto risco. Da proteção de registros estudantis à proteção de transações financeiras,
ajudamos organizações a defender o que mais importa.

_“Uma defesa de qualidade exige conhecer o ataque, nós fornecemos segurança por meio do entendimento.”_

Fique informado e atualizado com o que há de mais recente em cybersecurity visitando nosso [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE capacita DevOps, DevSecOps e developers a gerenciar, monitorar e proteger clusters Kubernetes com eficiência. Aproveite nossos insights orientados por AI, framework de segurança avançado e a intuitiva GUI CloudMaps para visualizar seus clusters, entender seu estado e agir com confiança.

Além disso, o K8Studio é **compatível com todas as principais distribuições de kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift e mais).

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

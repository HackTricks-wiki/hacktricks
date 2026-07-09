# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipos e motion design do Hacktricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Executar o HackTricks Localmente
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
Your local copy of HackTricks will be **disponível em [http://localhost:3337](http://localhost:3337)** após <5 minutos (ele precisa compilar o livro, tenha paciência).

## Parceiros do HackTricks

---

## Amigos do HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) é uma ótima empresa de cybersecurity cujo slogan é **HACK THE UNHACKABLE**. Eles fazem suas próprias pesquisas e desenvolvem suas próprias ferramentas de hacking para **oferecer vários serviços valiosos de cybersecurity** como pentesting, Red teams e training.

Você pode conferir o **blog** deles em [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** também apoia projetos open source de cybersecurity como HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** é a **plataforma #1 da Europa** de ethical hacking e **bug bounty platform.**

**Bug bounty tip**: **cadastre-se** no **Intigriti**, uma premium **bug bounty platform criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje, e comece a ganhar recompensas de até **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Junte-se ao servidor do [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para se comunicar com hackers experientes e bug bounty hunters!

- **Hacking Insights:** Interaja com conteúdo que explora a emoção e os desafios do hacking
- **Real-Time Hack News:** Fique atualizado sobre o mundo acelerado do hacking por meio de notícias e insights em tempo real
- **Latest Announcements:** Mantenha-se informado sobre os novos bug bounties lançados e atualizações cruciais da plataforma

**Junte-se a nós no** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e comece a colaborar com os melhores hackers hoje!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security oferece **treinamento prático em AI Security** com uma abordagem **engineering-first, hands-on lab**. Nossos cursos são feitos para security engineers, AppSec professionals e developers que querem **build, break, and secure aplicações reais impulsionadas por AI/LLM**.

A **AI Security Certification** foca em habilidades do mundo real, incluindo:
- Proteger aplicações com LLM e impulsionadas por AI
- Threat modeling para sistemas de AI
- Embeddings, vector databases e segurança de RAG
- Ataques a LLM, cenários de abuso e defesas práticas
- Padrões de design seguro e considerações de implantação

Todos os cursos são **on-demand**, **baseados em labs** e projetados em torno de **tradeoffs de segurança do mundo real**, não apenas teoria.

👉 Mais detalhes sobre o curso de AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferece APIs rápidas e fáceis em tempo real para **acessar resultados de mecanismos de busca**. Eles fazem scraping de mecanismos de busca, lidam com proxies, resolvem captchas e analisam todos os dados estruturados ricos para você.

Uma assinatura de um dos planos da SerpApi inclui acesso a mais de 50 APIs diferentes para scraping de vários mecanismos de busca, incluindo Google, Bing, Baidu, Yahoo, Yandex e mais.\
Ao contrário de outros provedores, **SerpApi não faz scraping apenas de resultados orgânicos**. As respostas da SerpApi incluem de forma consistente todos os anúncios, imagens e vídeos inline, knowledge graphs e outros elementos e recursos presentes nos resultados de busca.

Os clientes atuais da SerpApi incluem **Apple, Shopify e GrubHub**.\
Para mais informações, confira o [**blog**](https://serpapi.com/blog/)**,** ou teste um exemplo no [**playground**](https://serpapi.com/playground)**.**\
Você pode **criar uma conta gratuita** [**aqui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** treina você em offensive mobile e AI security, ministrado por pesquisadores ativos – a mesma equipe por trás dos writeups de CVE e palestras no Black Hat, HITB e Zer0con. Os cursos são self-paced, construídos em torno de labs em alvos reais e apoiados por uma certificação hands-on.

O catálogo segue dois trilhos:

**Mobile Security** – iOS e Android da camada de app para baixo: reverse engineering com Ghidra e LLDB, exploração em ARM64, kernel internals e mitigações modernas (PAC, MTE, SELinux), jailbreak e rooting mechanics.

**AI Security** – dois cursos completos cobrindo a área. Practical AI Security aborda como LLMs, pipelines de RAG, AI agents e MCP funcionam, e como atacá-los e defendê-los. Advanced AI Security vai mais a fundo na fronteira: red teaming de sistemas de AI em escala com Garak e PyRIT, exploração de servidores MCP, inserção e detecção de backdoors em modelos, e ataques e defesas de fine-tuning no Apple Silicon.

Cursos e certificações:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** é uma plataforma de segurança impulsionada por AI para encontrar vulnerabilidades exploráveis antes que atacantes o façam.

**Code security tip**: cadastre-se no NaxusAI, uma plataforma inteligente de monitoramento de vulnerabilidades criada para developers e security teams! Junte-se a nós hoje e comece a usar AI para **detectar, validar e corrigir riscos reais de segurança antes que eles cheguem à produção**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) é uma empresa profissional de cybersecurity sediada em **Amsterdam** que ajuda a **proteger** empresas **no mundo todo** contra as ameaças mais recentes de cybersecurity, fornecendo **offensive-security services** com uma abordagem **moderna**.

WebSec é uma empresa de security internacional com escritórios em Amsterdam e Wyoming. Eles oferecem **all-in-one security services**, o que significa que fazem tudo; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing e muito mais.

Outra coisa legal sobre a WebSec é que, ao contrário da média do setor, a WebSec é **muito confiante em suas habilidades**, a tal ponto que **garante os melhores resultados de qualidade**, afirmando em seu site "**If we can't hack it, You don't pay it!**". Para mais informações, dê uma olhada em seu [**website**](https://websec.net/en/) e [**blog**](https://websec.net/blog/)!

Além disso, a WebSec também é uma **apoiadora comprometida do HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Feito para o campo. Feito ao seu redor.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desenvolve e entrega treinamento eficaz de cybersecurity construído e liderado por especialistas do setor. Seus programas vão além da teoria para capacitar equipes com entendimento profundo e habilidades acionáveis, usando ambientes personalizados que refletem ameaças do mundo real. Para solicitações de treinamento personalizado, fale conosco [**aqui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**O que diferencia o treinamento deles:**
* Conteúdo e labs feitos sob medida
* Apoiado por ferramentas e plataformas de alto nível
* Projetado e ministrado por practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions oferece serviços especializados de cybersecurity para instituições de **Education** e **FinTech**
, com foco em **penetration testing, cloud security assessments** e
**compliance readiness** (SOC 2, PCI-DSS, NIST). Nossa equipe inclui profissionais certificados **OSCP e CISSP**,
trazendo profunda expertise técnica e visão alinhada aos padrões do setor para
cada projeto.

Vamos além de scans automatizados com **manual, intelligence-driven testing** adaptado a
ambientes de alto risco. De proteger registros de estudantes a proteger transações financeiras,
ajudamos organizações a defender o que mais importa.

_“Uma defesa de qualidade exige conhecer o ataque, nós fornecemos segurança por meio do entendimento.”_

Fique informado e atualizado com o que há de mais recente em cybersecurity visitando nosso [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE capacita DevOps, DevSecOps e developers a gerenciar, monitorar e proteger clusters Kubernetes com eficiência. Aproveite nossos insights impulsionados por AI, framework avançado de segurança e a interface intuitiva CloudMaps GUI para visualizar seus clusters, entender seu estado e agir com confiança.

Além disso, o K8Studio é **compatível com todas as principais distribuições kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift e mais).

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

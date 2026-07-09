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
Sua cópia local do HackTricks estará **disponível em [http://localhost:3337](http://localhost:3337)** após <5 minutos (ele precisa compilar o livro, tenha paciência).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) é uma ótima empresa de cybersecurity cujo slogan é **HACK THE UNHACKABLE**. Eles fazem sua própria pesquisa e desenvolvem suas próprias ferramentas de hacking para **oferecer vários serviços valiosos de cybersecurity** como pentesting, Red teams e treinamento.

Você pode conferir o **blog** deles em [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** também apoia projetos open source de cybersecurity como HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** é a **plataforma de ethical hacking e bug bounty número 1 da Europa.**

**Dica de bug bounty**: **cadastre-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

A Modern Security oferece **treinamento prático de AI Security** com uma abordagem **hands-on em laboratório, com foco em engenharia**. Nossos cursos são criados para security engineers, profissionais de AppSec e desenvolvedores que querem **construir, quebrar e proteger aplicações reais alimentadas por AI/LLM**.

A **AI Security Certification** foca em habilidades do mundo real, incluindo:
- Proteger aplicações baseadas em LLM e AI
- Threat modeling para sistemas de AI
- Embeddings, bancos de dados vetoriais e segurança de RAG
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

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferece APIs rápidas e fáceis em tempo real para **acessar resultados de mecanismos de busca**. Eles fazem scraping de mecanismos de busca, lidam com proxies, resolvem captchas e fazem parse de todos os dados estruturados ricos para você.

Uma assinatura de um dos planos da SerpApi inclui acesso a mais de 50 APIs diferentes para scraping de diferentes mecanismos de busca, incluindo Google, Bing, Baidu, Yahoo, Yandex e outros.\
Ao contrário de outros provedores, a **SerpApi não faz scraping apenas de resultados orgânicos**. As respostas da SerpApi incluem consistentemente todos os anúncios, imagens e vídeos inline, knowledge graphs e outros elementos e recursos presentes nos resultados de busca.

Os clientes atuais da SerpApi incluem **Apple, Shopify e GrubHub**.\
Para mais informações, confira o [**blog**](https://serpapi.com/blog/)**,** ou teste um exemplo em seu [**playground**](https://serpapi.com/playground)**.**\
Você pode **criar uma conta grátis** [**aqui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

A **8kSec Academy** treina você em offensive mobile e AI security, com aulas ministradas por pesquisadores ativos – a mesma equipe por trás dos writeups de CVE e palestras na Black Hat, HITB e Zer0con. Os cursos são autodidatas, construídos em torno de laboratórios em alvos reais e acompanhados por uma certificação prática.

O catálogo segue dois caminhos:

**Mobile Security** – iOS e Android da camada da aplicação até o fundo: reverse engineering com Ghidra e LLDB, exploitation em ARM64, internals do kernel e mitigações modernas (PAC, MTE, SELinux), jailbreak e rooting mechanics.

**AI Security** – dois cursos completos cobrindo a área. Practical AI Security cobre como LLMs, pipelines de RAG, AI agents e MCP funcionam, e como atacá-los e defendê-los. Advanced AI Security vai pesado em build na fronteira: red teaming de sistemas de AI em escala com Garak e PyRIT, exploração de servidores MCP, implantação e detecção de backdoors em modelos, e ataques e defesas de fine-tuning no Apple Silicon.

Cursos e certificações:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** é uma plataforma de security com AI para encontrar vulnerabilidades exploráveis antes que os atacantes o façam.

**Dica de code security**: cadastre-se no NaxusAI, uma plataforma inteligente de monitoramento de vulnerabilidades criada para desenvolvedores e equipes de segurança! Junte-se a nós hoje e comece a usar AI para **detectar, validar e corrigir riscos reais de segurança antes que cheguem à produção**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) é uma empresa profissional de cybersecurity sediada em **Amsterdã** que ajuda a **proteger** empresas **no mundo todo** contra as ameaças mais recentes de cybersecurity, fornecendo serviços de **offensive-security** com uma abordagem **moderna**.

A WebSec é uma empresa internacional de segurança com escritórios em Amsterdã e Wyoming. Eles oferecem serviços de segurança **all-in-one**, o que significa que fazem tudo; Pentesting, auditorias de **Security**, treinamentos de conscientização, campanhas de phishing, Code Review, Exploit Development, terceirização de especialistas em segurança e muito mais.

Outra coisa legal sobre a WebSec é que, ao contrário da média do setor, a WebSec é **muito confiante em suas habilidades**, a ponto de **garantir os melhores resultados de qualidade**; em seu site, diz "**Se não conseguirmos hackear, você não paga!**". Para mais informações, dê uma olhada no [**website**](https://websec.net/en/) e no [**blog**](https://websec.net/blog/) deles!

Além do acima, a WebSec também é uma **apoiadora comprometida do HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Feito para o campo. Feito ao seu redor.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desenvolve e entrega treinamento eficaz de cybersecurity, criado e liderado por
especialistas do setor. Seus programas vão além da teoria para equipar equipes com profundo
entendimento e habilidades acionáveis, usando ambientes personalizados que refletem ameaças do mundo real. Para solicitações de treinamento personalizado, entre em contato conosco [**aqui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**O que diferencia seu treinamento:**
* Conteúdo e laboratórios criados sob medida
* Apoiado por ferramentas e plataformas de primeira linha
* Projetado e ministrado por profissionais

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

A Last Tower Solutions oferece serviços especializados de cybersecurity para instituições de **Educação** e **FinTech**,
com foco em **pentesting, avaliações de segurança em cloud** e
**preparação para compliance** (SOC 2, PCI-DSS, NIST). Nossa equipe inclui **profissionais
certificados OSCP e CISSP**, trazendo profunda expertise técnica e visão alinhada aos padrões do setor para
cada engajamento.

Vamos além de varreduras automatizadas com testes **manuais, orientados por inteligência**, adaptados a
ambientes de alto risco. Desde proteger registros de estudantes até proteger transações financeiras,
ajudamos organizações a defender o que mais importa.

_“Uma defesa de qualidade exige conhecer o ataque; nós fornecemos segurança por meio do entendimento.”_

Mantenha-se informado e atualizado com o que há de mais recente em cybersecurity visitando nosso [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

O K8Studio IDE capacita DevOps, DevSecOps e developers a gerenciar, monitorar e proteger clusters Kubernetes de forma eficiente. Aproveite nossos insights impulsionados por AI, framework avançado de security e a intuitiva GUI CloudMaps para visualizar seus clusters, entender seu estado e agir com confiança.

Além disso, o K8Studio é **compatível com todas as principais distribuições de kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift e outras).

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

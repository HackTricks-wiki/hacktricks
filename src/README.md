# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos e motion design do Hacktricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Execute o HackTricks localmente
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
Sua cópia local do HackTricks estará **disponível em [http://localhost:3337](http://localhost:3337)** após <5 minutos (é necessário compilar o livro; aguarde).

Como alternativa, se você tiver o Docker Compose, basta executar o seguinte a partir da raiz do repositório:
```bash
docker compose up
```
Isso usa o `docker-compose.yml` incluído para disponibilizar seu checkout local em [http://localhost:3337](http://localhost:3337) com recarga ao vivo.

## Parceiros do HackTricks

---

## Amigos do HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

A [**STM Cyber**](https://www.stmcyber.com) é uma excelente empresa de cybersecurity cujo slogan é **HACK THE UNHACKABLE**. Eles realizam suas próprias pesquisas e desenvolvem suas próprias hacking tools para **oferecer diversos serviços valiosos de cybersecurity**, como pentesting, Red teams e treinamento.

Você pode conferir o **blog** em [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

A **STM Cyber** também apoia projetos open source de cybersecurity, como o HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

A **Intigriti** é a **nº 1 da Europa** em hacking ético e uma **bug bounty platform**.

**Dica de bug bounty**: faça **sign up** na **Intigriti**, uma **bug bounty platform premium criada por hackers para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje mesmo e comece a ganhar bounties de até **US$ 100.000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

A Modern Security oferece **treinamento prático de AI Security** com uma **abordagem hands-on de laboratório, focada em engenharia**. Nossos cursos foram desenvolvidos para security engineers, profissionais de AppSec e desenvolvedores que desejam **criar, explorar e proteger aplicações reais baseadas em AI/LLM**.

A **AI Security Certification** concentra-se em habilidades do mundo real, incluindo:
- Proteção de aplicações baseadas em LLM e AI
- Threat modeling para sistemas de AI
- Embeddings, bancos de dados vetoriais e segurança de RAG
- Ataques a LLM, cenários de abuso e defesas práticas
- Padrões de secure design e considerações de deployment

Todos os cursos são **on-demand**, **orientados por labs** e desenvolvidos com base em **tradeoffs reais de security**, não apenas em teoria.

👉 Mais detalhes sobre o curso de AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

A **SerpApi** oferece APIs rápidas e fáceis em tempo real para **acessar resultados de mecanismos de busca**. Eles fazem scraping de mecanismos de busca, gerenciam proxies, resolvem captchas e analisam todos os dados estruturados avançados para você.

Uma assinatura de qualquer plano da SerpApi inclui acesso a mais de 50 APIs diferentes para fazer scraping de diversos mecanismos de busca, incluindo Google, Bing, Baidu, Yahoo, Yandex e outros.\
Diferentemente de outros provedores, a **SerpApi não faz apenas scraping de resultados orgânicos**. As respostas da SerpApi incluem consistentemente todos os anúncios, imagens e vídeos inline, knowledge graphs e outros elementos e recursos presentes nos resultados de busca.

Os clientes atuais da SerpApi incluem **Apple, Shopify e GrubHub**.\
Para mais informações, confira o [**blog**](https://serpapi.com/blog/)**,** ou experimente um exemplo no [**playground**](https://serpapi.com/playground)**.**\
Você pode **criar uma conta gratuita** [**aqui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

A **8kSec Academy** oferece treinamento em mobile e AI security ofensiva, ministrado por pesquisadores ativos – a mesma equipe responsável pelos CVE writeups e palestras no Black Hat, HITB e Zer0con. Os cursos são self-paced, baseados em labs com alvos reais e acompanhados de uma certificação hands-on.

O catálogo possui duas trilhas:

**Mobile Security** – iOS e Android, da camada da aplicação até níveis inferiores: reverse engineering com Ghidra e LLDB, exploração de ARM64, internals do kernel e mitigações modernas (PAC, MTE, SELinux), mecanismos de jailbreak e rooting.

**AI Security** – dois cursos completos abrangendo a área. Practical AI Security aborda como LLMs, pipelines de RAG, AI agents e MCP funcionam, além de como atacá-los e defendê-los. Advanced AI Security é altamente focado em construção na fronteira da área: red teaming de sistemas de AI em escala com Garak e PyRIT, exploração de MCP servers, inserção e detecção de backdoors em modelos e ataques e defesas de fine-tuning no Apple Silicon.

Cursos e certificações:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

A **NaxusAI** é uma security platform baseada em AI para encontrar vulnerabilidades exploráveis antes que os atacantes o façam.

**Dica de code security**: faça sign up na NaxusAI, uma smart vulnerability monitoring platform desenvolvida para desenvolvedores e security teams! Junte-se a nós hoje mesmo e comece a usar AI para **detectar, validar e corrigir riscos reais de segurança antes que cheguem à produção**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

A [**WebSec**](https://websec.net) é uma empresa profissional de cybersecurity sediada em **Amsterdã** que ajuda a **proteger** empresas **em todo o mundo** contra as ameaças mais recentes de cybersecurity, fornecendo **serviços de offensive security** com uma abordagem **moderna**.

A WebSec é uma empresa internacional de security, com escritórios em Amsterdã e Wyoming. Eles oferecem **serviços de security all-in-one**, o que significa que fazem de tudo: Pentesting, auditorias de **Security**, treinamentos de conscientização, campanhas de phishing, Code Review, Exploit Development, terceirização de Security Experts e muito mais.

Outra característica interessante da WebSec é que, diferentemente da média do setor, a WebSec é **muito confiante em suas habilidades**, a ponto de **garantir os melhores resultados de qualidade**. Em seu website, eles afirmam: "**If we can't hack it, You don't pay it!**". Para mais informações, consulte o [**website**](https://websec.net/en/) e o [**blog**](https://websec.net/blog/)!

Além disso, a WebSec também é uma **apoiadora comprometida do HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Feito para o campo. Feito para você.**\
A [**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desenvolve e oferece treinamentos eficazes de cybersecurity, criados e ministrados por especialistas do setor. Seus programas vão além da teoria para fornecer às equipes conhecimento aprofundado e habilidades práticas, usando ambientes personalizados que refletem ameaças do mundo real. Para consultas sobre treinamentos personalizados, entre em contato conosco [**aqui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**O que diferencia seus treinamentos:**
* Conteúdo e labs desenvolvidos sob medida
* Apoio de ferramentas e plataformas de alto nível
* Desenvolvidos e ministrados por profissionais atuantes

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

A Last Tower Solutions oferece serviços especializados de cybersecurity para instituições de **Education** e **FinTech**, com foco em **penetration testing, cloud security assessments** e **compliance readiness** (SOC 2, PCI-DSS, NIST). Nossa equipe inclui **profissionais certificados OSCP e CISSP**, que oferecem profundo conhecimento técnico e visão alinhada aos padrões do setor em cada trabalho.

Vamos além de scans automatizados com **testes manuais orientados por inteligência**, adaptados a ambientes críticos. Desde a proteção de registros estudantis até a proteção de transações financeiras, ajudamos as organizações a defender o que realmente importa.

_“Uma defesa de qualidade exige conhecer o ataque; oferecemos security por meio do entendimento.”_

Mantenha-se informado e atualizado com as novidades em cybersecurity visitando nosso [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

A K8Studio IDE capacita equipes de DevOps, DevSecOps e desenvolvedores a gerenciar, monitorar e proteger clusters Kubernetes com eficiência. Aproveite nossos insights orientados por AI, nosso framework avançado de security e a intuitiva GUI CloudMaps para visualizar seus clusters, entender o estado deles e agir com confiança.

Além disso, o K8Studio é **compatível com todas as principais distribuições de kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift e outras).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Licença e Disclaimer

Confira em:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Estatísticas do Github

![Estatísticas do Github do HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

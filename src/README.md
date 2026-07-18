# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipos e motion design do Hacktricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Execute o HackTricks localmente
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Sua cópia local do HackTricks estará **disponível em [http://localhost:3337](http://localhost:3337)** após <5 minutos (é necessário compilar o livro, tenha paciência).

Como alternativa, se você tiver Docker Compose, basta executar o seguinte a partir da raiz do repositório:
```bash
docker compose up
```
Isso usa o `docker-compose.yml` incluído para disponibilizar a branch atualmente selecionada no host em [http://localhost:3337](http://localhost:3337), com live reload. Para alterar os idiomas ao usar o Compose, selecione a branch do idioma desejado antes de iniciar o serviço.

## Parceiros do HackTricks

---

## Amigos do HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) é uma excelente empresa de cybersecurity cujo slogan é **HACK THE UNHACKABLE**. Eles realizam suas próprias pesquisas e desenvolvem suas próprias hacking tools para **oferecer diversos serviços valiosos de cybersecurity**, como pentesting, Red teams e training.

Você pode conferir o **blog** em [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

A **STM Cyber** também apoia projetos open source de cybersecurity, como o HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

A **Intigriti** é a **nº 1 da Europa** em hacking ético e uma **bug bounty platform.**

**Dica de bug bounty**: faça **sign up** na **Intigriti**, uma **bug bounty platform premium criada por hackers para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar bounties de até **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – Plataforma de Training de AI & Application Security](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

A Modern Security oferece **training prático de AI Security** com uma **abordagem de laboratório prática e focada em engenharia**. Nossos cursos foram desenvolvidos para security engineers, profissionais de AppSec e developers que desejam **criar, explorar e proteger aplicações reais baseadas em AI/LLM**.

A **AI Security Certification** concentra-se em habilidades do mundo real, incluindo:
- Proteção de aplicações baseadas em LLM e AI
- Threat modeling para sistemas de AI
- Embeddings, bancos de dados vetoriais e segurança de RAG
- Ataques a LLM, cenários de abuso e defesas práticas
- Padrões de design seguro e considerações de deployment

Todos os cursos são **on-demand**, **orientados por labs** e desenvolvidos com base em **tradeoffs de segurança do mundo real**, não apenas em teoria.

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
Ao contrário de outros provedores, a **SerpApi não faz apenas scraping de resultados orgânicos**. As respostas da SerpApi incluem consistentemente todos os anúncios, imagens e vídeos inline, knowledge graphs e outros elementos e recursos presentes nos resultados de busca.

Entre os clientes atuais da SerpApi estão **Apple, Shopify e GrubHub**.\
Para mais informações, confira o [**blog**](https://serpapi.com/blog/)**,** ou experimente um exemplo no [**playground**](https://serpapi.com/playground)**.**\
Você pode **criar uma conta gratuita** [**aqui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Cursos aprofundados de Mobile & AI Security](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

A **8kSec Academy** oferece training em mobile e AI security ofensiva, ministrado por pesquisadores ativos — a mesma equipe responsável pelos CVE writeups e palestras no Black Hat, HITB e Zer0con. Os cursos são no seu próprio ritmo, baseados em labs com alvos reais e acompanhados por uma certificação prática.

O catálogo possui duas trilhas:

**Mobile Security** – iOS e Android, desde a camada de aplicação até níveis inferiores: reverse engineering com Ghidra e LLDB, exploração de ARM64, internals de kernel e mitigações modernas (PAC, MTE, SELinux), mecanismos de jailbreak e rooting.

**AI Security** – dois cursos completos que abrangem a área. Practical AI Security explica como LLMs, pipelines de RAG, AI agents e MCP funcionam e como atacá-los e defendê-los. Advanced AI Security é altamente focado em construção e aborda a fronteira da área: red teaming de sistemas de AI em escala com Garak e PyRIT, exploração de MCP servers, inserção e detecção de model backdoors e ataques e defesas de fine-tuning em Apple Silicon.

Cursos e certificações:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – Security Scanner baseado em AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

A **NaxusAI** é uma plataforma de segurança baseada em AI para encontrar vulnerabilidades exploráveis antes dos atacantes.

**Dica de segurança de código**: faça sign up na NaxusAI, uma plataforma inteligente de monitoramento de vulnerabilidades criada para developers e security teams! Junte-se a nós hoje e comece a usar AI para **detectar, validar e corrigir riscos reais de segurança antes que cheguem à produção**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

A [**WebSec**](https://websec.net) é uma empresa profissional de cybersecurity sediada em **Amsterdã** que ajuda a **proteger** empresas **em todo o mundo** contra as ameaças mais recentes de cybersecurity, oferecendo **serviços de offensive security** com uma abordagem **moderna**.

A WebSec é uma empresa internacional de segurança com escritórios em Amsterdã e Wyoming. Eles oferecem **serviços de segurança all-in-one**, o que significa que fazem de tudo: Pentesting, auditorias de **Security**, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, terceirização de Security Experts e muito mais.

Outro aspecto interessante da WebSec é que, ao contrário da média do setor, a WebSec é **muito confiante em suas habilidades**, a ponto de **garantir os melhores resultados de qualidade**. Em seu site, afirmam: "**If we can't hack it, You don't pay it!**". Para mais informações, consulte o [**site**](https://websec.net/en/) e o [**blog**](https://websec.net/blog/)!

Além do mencionado acima, a WebSec também é uma **apoiadora dedicada do HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Feito para o campo. Feito para você.**\
A [**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desenvolve e oferece training eficaz de cybersecurity, criado e conduzido por
especialistas do setor. Seus programas vão além da teoria para fornecer às equipes
um entendimento profundo e habilidades práticas, utilizando ambientes personalizados que refletem ameaças do mundo real. Para consultas sobre training personalizado, entre em contato conosco [**aqui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**O que diferencia o training deles:**
* Conteúdo e labs criados sob medida
* Apoio de ferramentas e plataformas de primeira linha
* Desenvolvido e ministrado por profissionais

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

A Last Tower Solutions oferece serviços especializados de cybersecurity para instituições de **Education** e **FinTech**, com foco em **penetration testing, avaliações de cloud security** e **preparação para compliance** (SOC 2, PCI-DSS, NIST). Nossa equipe inclui **profissionais certificados OSCP e CISSP**, trazendo profundo conhecimento técnico e experiência alinhada aos padrões do setor para cada trabalho.

Vamos além de scans automatizados com **testes manuais orientados por inteligência**, adaptados a ambientes de alto risco. Desde a proteção de registros estudantis até a proteção de transações financeiras, ajudamos organizações a defender o que mais importa.

_“Uma defesa de qualidade exige conhecer o ataque; fornecemos segurança por meio do entendimento.”_

Mantenha-se informado e atualizado com as novidades em cybersecurity visitando nosso [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - A GUI mais inteligente para gerenciar Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

A K8Studio IDE capacita DevOps, DevSecOps e developers a gerenciar, monitorar e proteger clusters Kubernetes com eficiência. Aproveite nossos insights orientados por AI, framework avançado de segurança e GUI intuitiva do CloudMaps para visualizar seus clusters, entender seu estado e agir com confiança.

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

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

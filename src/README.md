# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipos e motion design do Hacktricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Executar o HackTricks localmente
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

[**STM Cyber**](https://www.stmcyber.com) é uma ótima empresa de cibersegurança cujo slogan é **HACK THE UNHACKABLE**. Eles realizam suas próprias pesquisas e desenvolvem suas próprias ferramentas de hacking para **oferecer vários serviços valiosos de cibersegurança** como pentesting, Red teams e treinamento.

Você pode conferir o **blog** deles em [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** também apoia projetos open source de cibersegurança como HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança de todas as disciplinas.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** é a **plataforma #1 da Europa** para ethical hacking e bug bounty.

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar bounties de até **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** com facilidade, impulsionados pelas **ferramentas comunitárias mais avançadas** do mundo.

Obtenha Acesso Hoje:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Junte-se ao servidor [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para se comunicar com hackers experientes e caçadores de bug bounty!

- **Hacking Insights:** Envolva-se com conteúdo que explora a emoção e os desafios do hacking
- **Real-Time Hack News:** Mantenha-se atualizado com o mundo do hacking em ritmo acelerado através de notícias e insights em tempo real
- **Latest Announcements:** Fique informado sobre os novos bug bounties lançados e atualizações cruciais da plataforma

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e comece a colaborar com os melhores hackers hoje!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenha a perspectiva de um hacker sobre suas web apps, rede e cloud**

**Encontre e reporte vulnerabilidades críticas e exploráveis com impacto real nos negócios.** Use nossas 20+ ferramentas customizadas para mapear a superfície de ataque, encontrar problemas de segurança que permitam escalar privilégios e utilizar exploits automatizados para coletar evidências essenciais, transformando seu trabalho em relatórios persuasivos.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferece APIs em tempo real rápidas e fáceis para **acessar resultados de motores de busca**. Eles fazem scraping dos motores de busca, cuidam de proxies, resolvem captchas e analisam todos os dados estruturados ricos para você.

Uma assinatura de um dos planos da SerpApi inclui acesso a mais de 50 APIs diferentes para raspar diferentes motores de busca, incluindo Google, Bing, Baidu, Yahoo, Yandex e mais.\
Ao contrário de outros provedores, **SerpApi não se limita a raspar resultados orgânicos**. As respostas da SerpApi incluem consistentemente todos os anúncios, imagens e vídeos inline, knowledge graphs e outros elementos e recursos presentes nos resultados de busca.

Clientes atuais da SerpApi incluem **Apple, Shopify, and GrubHub**.\
Para mais informações, confira o [**blog**](https://serpapi.com/blog/)**,** ou experimente um exemplo no [**playground**](https://serpapi.com/playground)**.**\
Você pode **criar uma conta gratuita** [**aqui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Aprenda as tecnologias e habilidades necessárias para realizar pesquisa de vulnerabilidades, penetration testing e engenharia reversa para proteger aplicações e dispositivos móveis. **Domine a segurança iOS e Android** através de nossos cursos on-demand e **obtenha certificação**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) é uma empresa profissional de cibersegurança com sede em **Amsterdam** que ajuda a **proteger** empresas **em todo o mundo** contra as mais recentes ameaças de cibersegurança, fornecendo serviços de **offensive-security** com uma abordagem **moderna**.

WebSec é uma empresa internacional de segurança com escritórios em Amsterdam e Wyoming. Eles oferecem **serviços de segurança all-in-one**, o que significa que fazem de tudo; Pentesting, Security Audits, Awareness Trainings, Campanhas de Phishing, Code Review, Exploit Development, Security Experts Outsourcing e muito mais.

Outra coisa legal sobre a WebSec é que, ao contrário da média da indústria, a WebSec é **muito confiante em suas habilidades**, a ponto de **garantir os melhores resultados de qualidade**, conforme consta em seu site: "**If we can't hack it, You don't pay it!**". Para mais informações, veja o [**website**](https://websec.net/en/) e o [**blog**](https://websec.net/blog/)!

Além do acima, a WebSec também é uma **apoiante comprometida do HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) é um mecanismo de busca de data breach (leak). \
Oferecemos pesquisa por strings aleatórias (como google) sobre todos os tipos de data leaks, grandes e pequenos — não apenas os grandes — sobre dados de múltiplas fontes. \
Pesquisa por pessoas, pesquisa por AI, pesquisa por organização, acesso API (OpenAPI), integração theHarvester, todas as features que um pentester precisa.\
**HackTricks continua sendo uma ótima plataforma de aprendizado para todos nós e temos orgulho em patrociná-la!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desenvolve e entrega treinamentos de cibersegurança eficazes, construídos e liderados por especialistas da indústria. Seus programas vão além da teoria para equipar equipes com entendimento profundo e habilidades acionáveis, usando ambientes personalizados que refletem ameaças do mundo real. Para consultas sobre treinamentos customizados, entre em contato [**aqui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**O que diferencia os treinamentos deles:**
* Conteúdo e labs customizados
* Suportado por ferramentas e plataformas de alto nível
* Projetado e ensinado por praticantes

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fornece serviços especializados de cibersegurança para instituições de **Educação** e **FinTech**, com foco em **penetration testing, cloud security assessments**, e **preparação para conformidade** (SOC 2, PCI-DSS, NIST). Nossa equipe inclui profissionais certificados **OSCP and CISSP**, trazendo profundo conhecimento técnico e visão baseada em padrões do setor para cada engagement.

Vamos além de scans automatizados com **testes manuais, orientados por inteligência**, adaptados a ambientes de alto risco. Desde proteger registros estudantis até proteger transações financeiras, ajudamos organizações a defender o que mais importa.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Mantenha-se informado e atualizado com as últimas novidades em cibersegurança visitando nosso [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE capacita DevOps, DevSecOps e desenvolvedores a gerenciar, monitorar e proteger clusters Kubernetes de forma eficiente. Aproveite nossos insights impulsionados por AI, framework de segurança avançado e a intuitiva CloudMaps GUI para visualizar seus clusters, entender seu estado e agir com confiança.

Além disso, o K8Studio é **compatível com todas as principais distribuições de kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift e mais).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Licença & Disclaimer

Confira em:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Estatísticas do Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}

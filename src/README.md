# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos e design em movimento do Hacktricks por_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_._

### Execute o HackTricks Localmente
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
Sua cópia local do HackTricks estará **disponível em [http://localhost:3337](http://localhost:3337)** após <5 minutos (ele precisa construir o livro, seja paciente).

## Patrocinadores Corporativos

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) é uma ótima empresa de cibersegurança cujo slogan é **HACK THE UNHACKABLE**. Eles realizam suas próprias pesquisas e desenvolvem suas próprias ferramentas de hacking para **oferecer vários serviços valiosos de cibersegurança** como pentesting, Red teams e treinamento.

Você pode conferir seu **blog** em [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** também apoia projetos de código aberto em cibersegurança como o HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** é a **plataforma de hacking ético e bug bounty #1 da Europa.**

**Dica de bug bounty**: **inscreva-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas comunitárias mais avançadas** do mundo.

Acesse hoje:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Junte-se ao servidor [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para se comunicar com hackers experientes e caçadores de bugs!

- **Insights de Hacking:** Envolva-se com conteúdo que mergulha na emoção e nos desafios do hacking
- **Notícias de Hack em Tempo Real:** Mantenha-se atualizado com o mundo do hacking em ritmo acelerado através de notícias e insights em tempo real
- **Últimos Anúncios:** Fique informado sobre os novos bug bounties lançados e atualizações cruciais da plataforma

**Junte-se a nós no** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e comece a colaborar com os melhores hackers hoje!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - O kit de ferramentas essencial para testes de penetração

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenha a perspectiva de um hacker sobre seus aplicativos web, rede e nuvem**

**Encontre e relate vulnerabilidades críticas e exploráveis com impacto real nos negócios.** Use nossas mais de 20 ferramentas personalizadas para mapear a superfície de ataque, encontrar problemas de segurança que permitem escalar privilégios e usar exploits automatizados para coletar evidências essenciais, transformando seu trabalho árduo em relatórios persuasivos.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferece APIs rápidas e fáceis em tempo real para **acessar resultados de mecanismos de busca**. Eles raspam mecanismos de busca, lidam com proxies, resolvem captchas e analisam todos os dados estruturados ricos para você.

Uma assinatura de um dos planos da SerpApi inclui acesso a mais de 50 APIs diferentes para raspagem de diferentes mecanismos de busca, incluindo Google, Bing, Baidu, Yahoo, Yandex e mais.\
Ao contrário de outros provedores, **a SerpApi não apenas raspa resultados orgânicos**. As respostas da SerpApi incluem consistentemente todos os anúncios, imagens e vídeos inline, gráficos de conhecimento e outros elementos e recursos presentes nos resultados de busca.

Os atuais clientes da SerpApi incluem **Apple, Shopify e GrubHub**.\
Para mais informações, confira seu [**blog**](https://serpapi.com/blog/)**,** ou experimente um exemplo em seu [**playground**](https://serpapi.com/playground)**.**\
Você pode **criar uma conta gratuita** [**aqui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Cursos de Segurança Móvel em Profundidade](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Aprenda as tecnologias e habilidades necessárias para realizar pesquisa de vulnerabilidades, testes de penetração e engenharia reversa para proteger aplicativos e dispositivos móveis. **Domine a segurança de iOS e Android** através de nossos cursos sob demanda e **obtenha certificação**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) é uma empresa profissional de cibersegurança com sede em **Amsterdã** que ajuda a **proteger** empresas **em todo o mundo** contra as mais recentes ameaças de cibersegurança, fornecendo **serviços de segurança ofensiva** com uma abordagem **moderna**.

WebSec é uma empresa de segurança internacional com escritórios em Amsterdã e Wyoming. Eles oferecem **serviços de segurança tudo-em-um**, o que significa que fazem tudo; Pentesting, **Auditorias** de Segurança, Treinamentos de Conscientização, Campanhas de Phishing, Revisão de Código, Desenvolvimento de Exploits, Terceirização de Especialistas em Segurança e muito mais.

Outra coisa legal sobre a WebSec é que, ao contrário da média do setor, a WebSec é **muito confiante em suas habilidades**, a tal ponto que **garante os melhores resultados de qualidade**, afirmando em seu site "**Se não conseguimos hackear, você não paga!**". Para mais informações, dê uma olhada em seu [**site**](https://websec.net/en/) e [**blog**](https://websec.net/blog/)!

Além do acima, a WebSec também é um **apoiador comprometido do HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) é um mecanismo de busca de vazamentos de dados (leak). \
Fornecemos busca de strings aleatórias (como o google) sobre todos os tipos de vazamentos de dados grandes e pequenos --não apenas os grandes-- de dados de várias fontes. \
Busca de pessoas, busca de IA, busca de organizações, acesso API (OpenAPI), integração com oTheHarvester, todos os recursos que um pentester precisa.\
**HackTricks continua sendo uma ótima plataforma de aprendizado para todos nós e estamos orgulhosos de patrociná-la!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

## Licença & Isenção de Responsabilidade

Confira-os em:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Estatísticas do Github

![Estatísticas do Github do HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}

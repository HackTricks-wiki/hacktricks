# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos e motion design do Hacktricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

Sua cópia local do HackTricks estará **disponível em [http://localhost:3337](http://localhost:3337)** em menos de 5 minutos (é necessário compilar o livro; aguarde).

Alternativamente, se você tiver Docker Compose, basta executar o seguinte a partir da raiz do repositório:

```bash
docker compose up
```

Isso usa o `docker-compose.yml` incluído para servir a branch atualmente selecionada no host em [http://localhost:3337](http://localhost:3337), com recarga ao vivo. Para mudar de idioma ao usar o Compose, selecione a branch do idioma desejado antes de iniciar o serviço.

## Parceiros HackTricks

---

## Amigos HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

A STM Cyber oferece testes de intrusão, auditorias de segurança, trabalhos de exploração e pesquisa, ferramentas e serviços de conscientização sobre segurança. Seu site descreve uma equipe de profissionais de testes de intrusão, programadores e pesquisadores de segurança com mais de uma década de experiência.<sup>[[1]](#references)</sup>

Confira o **blog** em [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

A **STM Cyber** também apoia projetos open source de cibersegurança, como o HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

A Intigriti é uma provedora de segurança crowdsourced que oferece serviços de bug bounty e testes de intrusão por meio de uma comunidade global de pesquisadores. Sua plataforma combina cobertura contínua de bug bounty com PTaaS sob demanda e programas gerenciados de divulgação de vulnerabilidades.<sup>[[2]](#references)</sup>

**Dica de bug bounty**: participe da Intigriti em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) e explore seus programas de bug bounty.

---

### [Modern Security – Plataforma de treinamento em segurança de IA e aplicações](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

A Modern Security oferece treinamento prático e individualizado em segurança de IA para engenheiros de segurança, profissionais de AppSec e desenvolvedores. Sua certificação em segurança de IA aborda fundamentos de LLMs e agentes, RAG e bancos de dados vetoriais, modelagem de ameaças, ataques de prompt injection e MCP, além de arquitetura defensiva.<sup>[[3]](#references)</sup>

👉 Mais detalhes sobre o curso de segurança de IA:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

A **SerpApi** fornece APIs para o Google e outros mecanismos de busca, retornando dados estruturados de SERP com recursos como resultados baseados em localização, Maps, Shopping e Knowledge Graph.<sup>[[4]](#references)</sup>

Para saber mais, confira o [**blog**](https://serpapi.com/blog/), experimente um exemplo no [**playground**](https://serpapi.com/playground) ou [**crie uma conta gratuita**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Cursos aprofundados de segurança mobile e de IA](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

A **8kSec Academy** oferece cursos individualizados de segurança mobile e de IA. Seu catálogo aborda auditoria e engenharia reversa de aplicações mobile com ferramentas como Ghidra, Frida e LLDB, além de laboratórios de ataque e defesa de IA/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Explore o [catálogo de cursos da 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Segurança ofensiva autônoma](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

A **Naxus** é uma plataforma de segurança ofensiva com tecnologia de IA para varreduras completas da superfície de ataque externa, auditorias de aplicações mobile, testes black-box de aplicações web e análise de código-fonte. Seus agentes validam descobertas exploráveis e fornecem evidências rastreáveis, exploits de prova de conceito e recomendações práticas de correção.<sup>[[7]](#references)</sup>

**Dica de auditoria de segurança**: use a Naxus para auditorias autônomas de ponta a ponta em ativos externos, aplicações mobile e web e código-fonte.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

A WebSec oferece testes de intrusão, assinaturas de segurança, serviços de alocação de profissionais e avaliação de vulnerabilidades. Seu site informa que atua internacionalmente e cobre segurança ofensiva, segurança defensiva e trabalhos de governança, risco e conformidade.<sup>[[8]](#references)</sup>

Para saber mais, visite o [**site**](https://websec.net/en/) ou o [**blog**](https://websec.net/blog/).

Além do que foi mencionado acima, a WebSec também é uma **apoiadora comprometida do HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Feito para o campo. Feito para você.**\
A [**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) oferece treinamento em cibersegurança ministrado por especialistas, com conteúdo e laboratórios personalizados baseados em infraestruturas reais. Seus programas são adaptados às necessidades das organizações e abrangem desde a avaliação até a implementação.<sup>[[9]](#references)</sup> Para solicitar treinamento personalizado, entre em contato [**aqui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**O que diferencia o treinamento:**
* Conteúdo e laboratórios personalizados
* Apoiado por ferramentas e plataformas de primeira linha
* Criado e ministrado por profissionais da área

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

A Last Tower Solutions é especializada em consultoria de cibersegurança para os setores de **educação** e **FinTech**, incluindo avaliações de cloud, testes de intrusão internos e externos, avaliações de vulnerabilidades e apoio à conformidade.<sup>[[10]](#references)</sup>

Mantenha-se informado e atualizado sobre as novidades em cibersegurança visitando nosso [**blog**](https://www.lasttowersolutions.com/blog).

---

### [Beaki — Comida que combina com você](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki logo"><figcaption></figcaption></figure>

A **Beaki** é um scanner de alimentos personalizado, contador de calorias e rastreador nutricional. Escaneie códigos de barras e prateleiras de supermercados, fotografe ou descreva refeições e menus de restaurantes e obtenha avaliações explicáveis, adaptadas às suas metas, dieta, alergias e perfil de saúde. A Beaki também monitora calorias e macronutrientes e cria planos de refeições personalizados com listas de compras.<sup>[[11]](#references)</sup>

[**Baixe a Beaki gratuitamente**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks) para Android ou iPhone.

---

## Licença e isenção de responsabilidade

Consulte a entrada Valores e FAQ do HackTricks nas Referências abaixo.

## Estatísticas do Github

![Estatísticas do Github do HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certificação em segurança de IA – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Segurança prática de IA: ataques, defesas e aplicações](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Indicação do HackTricks para a Intigriti](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Vídeo de patrocínio da WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cursos da Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Valores e FAQ do HackTricks](welcome/hacktricks-values-and-faq.md)

{{#include banners/hacktricks-training.md}}

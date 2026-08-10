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
Sua cópia local do HackTricks estará **disponível em [http://localhost:3337](http://localhost:3337)** em menos de 5 minutos (é necessário compilar o livro; aguarde).

Como alternativa, se você tiver o Docker Compose, basta executar o seguinte a partir da raiz do repositório:
```bash
docker compose up
```
Isso usa o `docker-compose.yml` incluído para servir a branch atualmente selecionada no host em [http://localhost:3337](http://localhost:3337), com live reload. Para alterar os idiomas ao usar o Compose, selecione a branch do idioma desejado antes de iniciar o serviço.

## Parceiros do HackTricks

---

## Amigos do HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

A STM Cyber fornece testes de penetração, auditorias de segurança, trabalhos de exploit e pesquisa, ferramentas e serviços de conscientização em segurança. O site descreve uma equipe de pentesters, programadores e pesquisadores de segurança com mais de uma década de experiência.<sup>[[1]](#references)</sup>

Você pode conferir o **blog** em [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

A **STM Cyber** também apoia projetos open source de cybersecurity, como o HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

A Intigriti é uma provedora de segurança crowdsourced que oferece serviços de bug bounty e testes de penetração por meio de uma comunidade global de pesquisadores. Sua plataforma combina cobertura contínua de bug bounty com PTaaS sob demanda e programas gerenciados de divulgação de vulnerabilidades.<sup>[[2]](#references)</sup>

**Dica de bug bounty**: participe da Intigriti por meio de [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) e explore seus programas de bug bounty.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

A Modern Security oferece treinamento de segurança de AI prático e no seu próprio ritmo para engenheiros de segurança, profissionais de AppSec e desenvolvedores. Sua certificação de AI Security abrange fundamentos de LLM e agentes, RAG e bancos de dados vetoriais, threat modeling, ataques de prompt-injection e MCP e arquitetura defensiva.<sup>[[3]](#references)</sup>

👉 Mais detalhes sobre o curso de AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

A **SerpApi** fornece APIs para o Google e outros mecanismos de busca, retornando dados estruturados de SERP com recursos como resultados baseados em localização, Maps, Shopping e Knowledge Graph.<sup>[[4]](#references)</sup>

Para obter mais informações, confira o [**blog**](https://serpapi.com/blog/), experimente um exemplo no [**playground**](https://serpapi.com/playground) ou [**crie uma conta gratuita**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

A **8kSec Academy** oferece cursos de segurança mobile e AI no seu próprio ritmo. Seu catálogo abrange auditoria e reversing de aplicações mobile com ferramentas como Ghidra, Frida e LLDB, além de labs de ataque e defesa de AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Consulte o [catálogo de cursos da 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

A **Naxus** oferece uma plataforma de offensive AI que mapeia código e infraestrutura e, em seguida, usa agentes estáticos e dinâmicos para encontrar e validar fraquezas exploráveis, com evidências de proof-of-concept e orientações de remediação.<sup>[[7]](#references)</sup>

**Dica de segurança de código**: explore a Naxus para descobrir vulnerabilidades com foco em código e infraestrutura.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

A WebSec fornece testes de penetração, assinaturas de segurança, alocação de profissionais e serviços de avaliação de vulnerabilidades. Seu site informa que a empresa atua internacionalmente e abrange trabalhos de segurança ofensiva, segurança defensiva e governança, risco e compliance.<sup>[[8]](#references)</sup>

Para obter mais informações, visite o [**site**](https://websec.net/en/) ou o [**blog**](https://websec.net/blog/).

Além do mencionado acima, a WebSec também é uma **apoiadora comprometida do HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Feito para o campo. Feito pensando em você.**\
A [**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) fornece treinamento de cybersecurity conduzido por especialistas, com conteúdo e labs personalizados baseados em infraestruturas reais. Seus programas são adaptados às necessidades organizacionais e abrangem desde a avaliação até a implementação.<sup>[[9]](#references)</sup> Para consultas sobre treinamentos personalizados, entre em contato [**aqui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**O que diferencia o treinamento:**
* Conteúdo e labs personalizados
* Apoiado por ferramentas e plataformas de primeira linha
* Projetado e ministrado por profissionais atuantes

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

A Last Tower Solutions concentra-se em consultoria de cybersecurity para **Educação** e **FinTech**, incluindo avaliações de cloud, testes de penetração internos e externos, avaliações de vulnerabilidades e suporte a compliance.<sup>[[10]](#references)</sup>

Mantenha-se informado e atualizado com as novidades em cybersecurity visitando nosso [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

O K8Studio é uma IDE desktop para Kubernetes com visualização do CloudMaps, navegação em múltiplos clusters, RBAC, Helm, logs, YAML e visualizações de terminal. O fornecedor afirma que a ferramenta se conecta por meio do kubeconfig sem instalar agentes e oferece suporte a macOS, Windows, Linux e clusters air-gapped.<sup>[[11]](#references)</sup>

---

## Licença e Isenção de Responsabilidade

Consulte a entrada HackTricks Values & FAQ nas References abaixo.

## Estatísticas do Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certificação de AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [AI Security Prática: Ataques, Defesas e Aplicações](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Indicação da Intigriti para o HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Vídeo de patrocínio da WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cursos da Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}

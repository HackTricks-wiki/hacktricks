# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos y diseño de movimiento de Hacktricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Ejecutar HackTricks localmente
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
Tu copia local de HackTricks estará disponible en [http://localhost:3337](http://localhost:3337) en menos de 5 minutos (necesita compilar el libro; ten paciencia).

Como alternativa, si tienes Docker Compose, simplemente ejecuta lo siguiente desde la raíz del repositorio:
```bash
docker compose up
```
Esto utiliza el `docker-compose.yml` incluido para servir la branch actualmente seleccionada en el host en [http://localhost:3337](http://localhost:3337) con live reload. Para cambiar de idioma al usar Compose, selecciona la branch del idioma deseado antes de iniciar el servicio.

## Socios de HackTricks

---

## Amigos de HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber ofrece servicios de penetration testing, auditorías de seguridad, exploit y trabajos de investigación, herramientas y servicios de concienciación en seguridad. Su sitio describe un equipo de penetration testers, programadores y security researchers con más de una década de experiencia.<sup>[[1]](#references)</sup>

Puedes consultar su **blog** en [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** también apoya proyectos open source de ciberseguridad como HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti es un proveedor de seguridad crowdsourced que ofrece servicios de bug bounty y penetration testing a través de una comunidad global de investigadores. Su plataforma combina cobertura continua de bug bounty con PTaaS bajo demanda y programas gestionados de divulgación de vulnerabilidades.<sup>[[2]](#references)</sup>

**Consejo sobre bug bounty**: Únete a Intigriti mediante [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) y explora sus programas de bug bounty.

---

### [Modern Security – Plataforma de Formación en Seguridad de IA y Aplicaciones](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security ofrece formación práctica y autodidacta en seguridad de IA para security engineers, profesionales de AppSec y desarrolladores. Su certificación de AI Security cubre los fundamentos de LLM y agentes, RAG y bases de datos vectoriales, threat modeling, ataques de prompt injection y MCP, y arquitectura defensiva.<sup>[[3]](#references)</sup>

👉 Más información sobre el curso de AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** proporciona APIs para Google y otros motores de búsqueda, devolviendo datos SERP estructurados con funcionalidades como resultados basados en la ubicación, Maps, Shopping y Knowledge Graph.<sup>[[4]](#references)</sup>

Para obtener más información, consulta su [**blog**](https://serpapi.com/blog/), prueba un ejemplo en su [**playground**](https://serpapi.com/playground) o [**crea una cuenta gratuita**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Cursos Exhaustivos de Seguridad Móvil y de IA](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** ofrece cursos autodidactas de seguridad móvil y de IA. Su catálogo cubre auditoría y reversing de aplicaciones móviles con herramientas como Ghidra, Frida y LLDB, además de laboratorios de ataque y defensa de AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Consulta el [catálogo de cursos de 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Escáner de Seguridad Basado en IA](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** comercializa una plataforma de offensive AI que mapea el código y la infraestructura, y después utiliza agentes estáticos y dinámicos para encontrar y validar debilidades explotables con evidencias de proof-of-concept y orientación para la remediación.<sup>[[7]](#references)</sup>

**Consejo sobre seguridad del código**: Explora Naxus para descubrir vulnerabilidades centradas en el código y la infraestructura.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec ofrece servicios de penetration testing, suscripciones de seguridad, staffing y evaluación de vulnerabilidades. Su sitio afirma que opera internacionalmente y cubre trabajos de offensive security, defensive security y governance, risk, and compliance.<sup>[[8]](#references)</sup>

Para obtener más información, visita su [**sitio web**](https://websec.net/en/) o su [**blog**](https://websec.net/blog/).

Además de lo anterior, WebSec también es un **colaborador comprometido con HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Creado para el trabajo de campo. Creado pensando en ti.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ofrece formación en ciberseguridad dirigida por expertos, con contenido y laboratorios personalizados basados en infraestructuras reales. Sus programas se adaptan a las necesidades de las organizaciones y abarcan desde la evaluación hasta la implementación.<sup>[[9]](#references)</sup> Para consultas sobre formación personalizada, ponte en contacto [**aquí**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Lo que distingue a su formación:**
* Contenido y laboratorios personalizados
* Respaldados por herramientas y plataformas de primer nivel
* Diseñados e impartidos por profesionales del sector

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions se centra en la consultoría de ciberseguridad para **Educación** y **FinTech**, incluyendo evaluaciones de cloud, penetration tests internos y externos, evaluaciones de vulnerabilidades y soporte de compliance.<sup>[[10]](#references)</sup>

Mantente informado y al día con las últimas novedades en ciberseguridad visitando nuestro [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - La GUI Más Inteligente para Gestionar Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio es un IDE de Kubernetes para escritorio con visualización de CloudMaps, navegación entre múltiples clusters, RBAC, Helm, logs, YAML y vistas de terminal. El proveedor afirma que se conecta mediante kubeconfig sin instalar agentes y que es compatible con macOS, Windows, Linux y clusters air-gapped.<sup>[[11]](#references)</sup>

---

## Licencia y Descargo de Responsabilidad

Consulta la entrada HackTricks Values & FAQ en las References siguientes.

## Estadísticas de Github

![Estadísticas de Github de HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certificación de AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Seguridad práctica de IA: ataques, defensas y aplicaciones](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Referral de Intigriti para HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Vídeo de patrocinio de WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cursos de Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Valores y FAQ de HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}

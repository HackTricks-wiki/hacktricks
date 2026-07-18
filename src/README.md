# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos y diseño de movimiento de HackTricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Tu copia local de HackTricks estará **disponible en [http://localhost:3337](http://localhost:3337)** en menos de 5 minutos (necesita compilar el libro; ten paciencia).

Como alternativa, si tienes Docker Compose, simplemente ejecuta lo siguiente desde la raíz del repo:
```bash
docker compose up
```
Esto utiliza el `docker-compose.yml` incluido para servir la branch actualmente seleccionada en el host en [http://localhost:3337](http://localhost:3337) con live reload. Para cambiar de idioma al utilizar Compose, selecciona la branch del idioma deseado antes de iniciar el servicio.

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) es una excelente empresa de ciberseguridad cuyo eslogan es **HACK THE UNHACKABLE**. Realizan sus propias investigaciones y desarrollan sus propias herramientas de hacking para **ofrecer varios servicios valiosos de ciberseguridad**, como pentesting, Red teams y formación.

Puedes consultar su **blog** en [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** también apoya proyectos open source de ciberseguridad como HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** es la **plataforma de ethical hacking y **bug bounty** número 1 de Europa.**

**Consejo sobre bug bounty**: ¡**regístrate** en **Intigriti**, una plataforma premium de **bug bounty creada por hackers para hackers**! Únete hoy en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) y empieza a conseguir recompensas de hasta **100.000 $**.

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – Plataforma de formación en AI & Application Security](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security ofrece **formación práctica en AI Security** con un **enfoque de laboratorio práctico y centrado en la ingeniería**. Nuestros cursos están diseñados para security engineers, profesionales de AppSec y desarrolladores que quieren **crear, romper y proteger aplicaciones reales impulsadas por AI/LLM**.

La **certificación de AI Security** se centra en habilidades del mundo real, incluyendo:
- Protección de aplicaciones impulsadas por LLM y AI
- Threat modeling para sistemas de AI
- Embeddings, bases de datos vectoriales y seguridad de RAG
- Ataques contra LLM, escenarios de abuso y defensas prácticas
- Patrones de diseño seguro y consideraciones de despliegue

Todos los cursos son **on-demand**, están **basados en laboratorios** y se han diseñado en torno a **tradeoffs de seguridad del mundo real**, no solo a la teoría.

👉 Más información sobre el curso de AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** ofrece APIs rápidas y sencillas en tiempo real para **acceder a resultados de motores de búsqueda**. Realizan scraping de motores de búsqueda, gestionan proxies, resuelven captchas y analizan todos los datos estructurados enriquecidos por ti.

Una suscripción a cualquiera de los planes de SerpApi incluye acceso a más de 50 APIs diferentes para realizar scraping de distintos motores de búsqueda, incluidos Google, Bing, Baidu, Yahoo, Yandex y otros.\
A diferencia de otros proveedores, **SerpApi no se limita a realizar scraping de resultados orgánicos**. Las respuestas de SerpApi incluyen constantemente todos los anuncios, imágenes y vídeos integrados, knowledge graphs y otros elementos y funciones presentes en los resultados de búsqueda.

Entre los clientes actuales de SerpApi se encuentran **Apple, Shopify y GrubHub**.\
Para obtener más información, consulta su [**blog**](https://serpapi.com/blog/)**,** o prueba un ejemplo en su [**playground**](https://serpapi.com/playground)**.**\
Puedes **crear una cuenta gratuita** [**aquí**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Cursos detallados de Mobile & AI Security](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** te forma en seguridad ofensiva mobile y AI, impartida por investigadores en activo: el mismo equipo que está detrás de los writeups de CVE y de las charlas en Black Hat, HITB y Zer0con. Los cursos son autodidácticos, se basan en laboratorios sobre objetivos reales y cuentan con una certificación práctica.

El catálogo ofrece dos itinerarios:

**Mobile Security** – iOS y Android desde la capa de aplicación hacia abajo: reverse engineering con Ghidra y LLDB, explotación de ARM64, internals del kernel y mitigaciones modernas (PAC, MTE, SELinux), mecanismos de jailbreak y rooting.

**AI Security** – dos cursos completos que abarcan el campo. Practical AI Security explica cómo funcionan los LLM, los pipelines de RAG, los agentes de AI y MCP, y cómo atacarlos y defenderlos. Advanced AI Security se centra en la práctica en la frontera tecnológica: red teaming de sistemas de AI a escala con Garak y PyRIT, explotación de servidores MCP, inserción y detección de backdoors en modelos, y ataques y defensas de fine-tuning en Apple Silicon.

Cursos y certificaciones:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – Security Scanner impulsado por AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** es una plataforma de seguridad impulsada por AI para encontrar vulnerabilidades explotables antes que los atacantes.

**Consejo de seguridad de código**: ¡regístrate en NaxusAI, una plataforma inteligente de monitorización de vulnerabilidades creada para desarrolladores y equipos de seguridad! Únete hoy y empieza a utilizar AI para **detectar, validar y solucionar riesgos reales de seguridad antes de que lleguen a producción**.

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) es una empresa profesional de ciberseguridad con sede en **Ámsterdam** que ayuda a **proteger** empresas **de todo el mundo** frente a las amenazas de ciberseguridad más recientes, proporcionando **servicios de seguridad ofensiva** con un enfoque **moderno**.

WebSec es una empresa internacional de seguridad con oficinas en Ámsterdam y Wyoming. Ofrece **servicios de seguridad integrales**, lo que significa que lo hacen todo: Pentesting, auditorías de **Security**, formaciones de concienciación, campañas de phishing, revisión de código, desarrollo de exploits, externalización de expertos en seguridad y mucho más.

Otro aspecto interesante de WebSec es que, a diferencia de la media del sector, WebSec tiene **mucha confianza en sus habilidades**, hasta el punto de que **garantiza resultados de la mejor calidad**. En su sitio web afirma: "**If we can't hack it, You don't pay it!**". Para obtener más información, consulta su [**sitio web**](https://websec.net/en/) y su [**blog**](https://websec.net/blog/).

Además de lo anterior, WebSec también es un **colaborador comprometido de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Diseñado para el entorno profesional. Diseñado pensando en ti.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desarrolla e imparte formación eficaz en ciberseguridad, creada y dirigida por
expertos del sector. Sus programas van más allá de la teoría para proporcionar a los equipos un profundo
conocimiento y habilidades prácticas, utilizando entornos personalizados que reflejan las amenazas del mundo real. Para consultas sobre formación personalizada, contáctanos [**aquí**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Lo que diferencia a su formación:**
* Contenido y laboratorios creados a medida
* Respaldados por herramientas y plataformas de primer nivel
* Diseñados e impartidos por profesionales en activo

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions ofrece servicios especializados de ciberseguridad para instituciones de **Education** y **FinTech**,
con especial atención a **penetration testing, evaluaciones de seguridad cloud** y
**preparación para el cumplimiento normativo** (SOC 2, PCI-DSS, NIST). Nuestro equipo incluye profesionales
**certificados en OSCP y CISSP**, que aportan una profunda experiencia técnica y conocimientos alineados con los estándares del sector a
cada proyecto.

Vamos más allá de los escaneos automatizados con **pruebas manuales guiadas por inteligencia**, adaptadas a
entornos críticos. Desde proteger los registros de estudiantes hasta proteger las transacciones financieras,
ayudamos a las organizaciones a defender lo que más importa.

_“Una defensa de calidad requiere conocer el ataque; nosotros proporcionamos seguridad mediante la comprensión.”_

Mantente informado y al día con las últimas novedades en ciberseguridad visitando nuestro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - La GUI más inteligente para gestionar Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

El IDE K8Studio permite a DevOps, DevSecOps y desarrolladores gestionar, monitorizar y proteger clústeres de Kubernetes de forma eficiente. Aprovecha nuestros insights impulsados por AI, nuestro framework avanzado de seguridad y nuestra intuitiva GUI CloudMaps para visualizar tus clústeres, comprender su estado y actuar con confianza.

Además, K8Studio es **compatible con todas las principales distribuciones de kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift y otras).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Licencia y Disclaimer

Consúltalos en:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Estadísticas de Github

![Estadísticas de Github de HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

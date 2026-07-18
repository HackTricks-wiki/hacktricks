# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos y diseño de motion de HackTricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Ejecutar HackTricks localmente
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
Tu copia local de HackTricks estará **disponible en [http://localhost:3337](http://localhost:3337)** después de <5 minutos (necesita compilar el libro; ten paciencia).

Como alternativa, si tienes Docker Compose, simplemente ejecuta lo siguiente desde la raíz del repositorio:
```bash
docker compose up
```
Esto usa el `docker-compose.yml` incluido para servir tu copia local en [http://localhost:3337](http://localhost:3337) con recarga en vivo.

## Partners de HackTricks

---

## Amigos de HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) es una excelente empresa de ciberseguridad cuyo lema es **HACK THE UNHACKABLE**. Realizan sus propias investigaciones y desarrollan sus propias hacking tools para **ofrecer varios servicios valiosos de ciberseguridad**, como pentesting, Red teams y formación.

Puedes consultar su **blog** en [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** también apoya proyectos open source de ciberseguridad como HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** es la **plataforma de ethical hacking y bug bounty número 1 de Europa.**

**Consejo sobre bug bounty**: ¡**regístrate** en **Intigriti**, una **plataforma de bug bounty creada por hackers para hackers**! Únete hoy en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) y empieza a ganar recompensas de hasta **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security ofrece **formación práctica en AI Security** con un **enfoque práctico de laboratorio centrado en la ingeniería**. Nuestros cursos están diseñados para security engineers, profesionales de AppSec y desarrolladores que quieren **crear, romper y proteger aplicaciones reales impulsadas por AI/LLM**.

La **certificación de AI Security** se centra en habilidades del mundo real, incluyendo:
- Protección de aplicaciones impulsadas por LLM y AI
- Threat modeling para sistemas de AI
- Embeddings, bases de datos vectoriales y seguridad de RAG
- Ataques a LLM, escenarios de abuso y defensas prácticas
- Patrones de diseño seguro y consideraciones de deployment

Todos los cursos son **on-demand**, están **orientados a laboratorios** y se diseñan en torno a **tradeoffs de seguridad del mundo real**, no solo a la teoría.

👉 Más detalles sobre el curso de AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** ofrece APIs rápidas y sencillas en tiempo real para **acceder a resultados de motores de búsqueda**. Realizan scraping de motores de búsqueda, gestionan proxies, resuelven captchas y analizan todos los datos estructurados enriquecidos por ti.

Una suscripción a cualquiera de los planes de SerpApi incluye acceso a más de 50 APIs diferentes para hacer scraping de distintos motores de búsqueda, incluidos Google, Bing, Baidu, Yahoo, Yandex y muchos más.\
A diferencia de otros proveedores, **SerpApi no se limita a hacer scraping de resultados orgánicos**. Las respuestas de SerpApi incluyen sistemáticamente todos los anuncios, imágenes y vídeos integrados, knowledge graphs y otros elementos y funciones presentes en los resultados de búsqueda.

Entre los clientes actuales de SerpApi se encuentran **Apple, Shopify y GrubHub**.\
Para obtener más información, consulta su [**blog**](https://serpapi.com/blog/)**,** o prueba un ejemplo en su [**playground**](https://serpapi.com/playground)**.**\
Puedes **crear una cuenta gratuita** [**aquí**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** te forma en offensive mobile y AI security, impartida por investigadores activos: el mismo equipo responsable de los CVE writeups y las charlas en Black Hat, HITB y Zer0con. Los cursos son autodidactas, se basan en laboratorios sobre objetivos reales y cuentan con una certificación práctica.

El catálogo ofrece dos itinerarios:

**Mobile Security** – iOS y Android desde la capa de la aplicación hacia abajo: reverse engineering con Ghidra y LLDB, explotación de ARM64, internals del kernel y mitigaciones modernas (PAC, MTE, SELinux), así como los mecanismos de jailbreak y rooting.

**AI Security** – dos cursos completos que abarcan el campo. Practical AI Security explica cómo funcionan los LLM, los pipelines de RAG, los agentes de AI y MCP, además de cómo atacarlos y defenderlos. Advanced AI Security se centra en la construcción práctica en la frontera tecnológica: red teaming de sistemas de AI a escala con Garak y PyRIT, explotación de servidores MCP, instalación y detección de backdoors en modelos, y ataques y defensas de fine-tuning en Apple Silicon.

Cursos y certificaciones:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** es una plataforma de seguridad impulsada por AI para encontrar vulnerabilidades explotables antes que los atacantes.

**Consejo sobre code security**: ¡regístrate en NaxusAI, una plataforma inteligente de monitorización de vulnerabilidades creada para desarrolladores y equipos de seguridad! Únete hoy y empieza a usar AI para **detectar, validar y corregir riesgos de seguridad reales antes de que lleguen a producción**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) es una empresa profesional de ciberseguridad con sede en **Ámsterdam** que ayuda a **proteger** empresas **de todo el mundo** frente a las amenazas de ciberseguridad más recientes, proporcionando **servicios de offensive security** con un enfoque **moderno**.

WebSec es una empresa internacional de seguridad con oficinas en Ámsterdam y Wyoming. Ofrecen **servicios de seguridad all-in-one**, lo que significa que lo hacen todo: Pentesting, **auditorías de seguridad**, formación de concienciación, campañas de phishing, revisión de código, desarrollo de exploits, externalización de expertos en seguridad y mucho más.

Otro aspecto interesante de WebSec es que, a diferencia de la media del sector, WebSec tiene **mucha confianza en sus capacidades**, hasta el punto de que **garantizan los mejores resultados de calidad**. En su sitio web afirman: "**If we can't hack it, You don't pay it!**". Para obtener más información, visita su [**sitio web**](https://websec.net/en/) y su [**blog**](https://websec.net/blog/)!

Además de lo anterior, WebSec también es un **colaborador comprometido de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Creado para el campo. Creado pensando en ti.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desarrolla e imparte formación eficaz en ciberseguridad, creada y dirigida por
expertos del sector. Sus programas van más allá de la teoría para proporcionar a los equipos un conocimiento
profundo y habilidades prácticas, utilizando entornos personalizados que reflejan las
amenazas del mundo real. Para consultas sobre formación personalizada, contáctanos [**aquí**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Lo que distingue a su formación:**
* Contenido y laboratorios creados a medida
* Respaldados por herramientas y plataformas de primer nivel
* Diseñados e impartidos por profesionales

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions ofrece servicios especializados de ciberseguridad para instituciones de **Educación** y **FinTech**,
con especial atención a **penetration testing, evaluaciones de seguridad cloud**
y **preparación para el cumplimiento normativo** (SOC 2, PCI-DSS, NIST). Nuestro equipo incluye **profesionales certificados en OSCP y CISSP**,
que aportan una amplia experiencia técnica y conocimientos alineados con los estándares del sector a
cada proyecto.

Vamos más allá de los análisis automatizados con **pruebas manuales basadas en inteligencia**, adaptadas a
entornos de alto riesgo. Desde proteger los registros de estudiantes hasta proteger las transacciones financieras,
ayudamos a las organizaciones a defender lo que más importa.

_“Una defensa de calidad requiere conocer la ofensiva; proporcionamos seguridad mediante el conocimiento.”_

Mantente informado y al día con las últimas novedades en ciberseguridad visitando nuestro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

El IDE de K8Studio permite a DevOps, DevSecOps y desarrolladores gestionar, monitorizar y proteger clústeres de Kubernetes de forma eficiente. Aprovecha nuestros insights basados en AI, nuestro framework avanzado de seguridad y nuestra intuitiva GUI CloudMaps para visualizar tus clústeres, comprender su estado y actuar con confianza.

Además, K8Studio es **compatible con todas las principales distribuciones de Kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift y otras).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Licencia y descargo de responsabilidad

Consúltalos en:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Estadísticas de GitHub

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

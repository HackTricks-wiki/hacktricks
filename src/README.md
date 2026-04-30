# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo y diseño de movimiento de Hacktricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Ejecuta HackTricks localmente
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
Your local copy of HackTricks estará **disponible en [http://localhost:3337](http://localhost:3337)** después de <5 minutos (necesita compilar el libro, ten paciencia).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) es una gran empresa de ciberseguridad cuyo lema es **HACK THE UNHACKABLE**. Realizan su propia investigación y desarrollan sus propias herramientas de hacking para **ofrecer varios valiosos servicios de ciberseguridad** como pentesting, Red teams y training.

Puedes consultar su **blog** en [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** también apoya proyectos open source de ciberseguridad como HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** es la **plataforma de ethical hacking y bug bounty n.º 1 de Europa.**

**Bug bounty tip**: **regístrate** en **Intigriti**, una plataforma premium de **bug bounty creada por hackers, para hackers**. Únete hoy en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) y empieza a ganar recompensas de hasta **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

¡Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y bug bounty hunters!

- **Hacking Insights:** Interactúa con contenido que explora la emoción y los desafíos del hacking
- **Real-Time Hack News:** Mantente al día con el mundo del hacking a través de noticias e información en tiempo real
- **Latest Announcements:** Mantente informado sobre los nuevos bug bounties que se lanzan y las actualizaciones cruciales de la plataforma

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y empieza a colaborar con los mejores hackers hoy mismo!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security ofrece **formación práctica en AI Security** con un enfoque **engineering-first y de laboratorio práctico**. Nuestros cursos están diseñados para security engineers, profesionales de AppSec y desarrolladores que quieren **construir, romper y asegurar aplicaciones reales impulsadas por AI/LLM**.

La **AI Security Certification** se centra en habilidades del mundo real, incluyendo:
- Proteger aplicaciones basadas en LLM y AI
- Threat modeling para sistemas de AI
- Embeddings, bases de datos vectoriales y seguridad de RAG
- Ataques a LLM, escenarios de abuso y defensas prácticas
- Patrones de diseño seguro y consideraciones de despliegue

Todos los cursos son **on-demand**, **basados en laboratorios** y están diseñados en torno a **compromisos reales de seguridad**, no solo teoría.

👉 Más detalles sobre el curso de AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** ofrece APIs rápidas y fáciles en tiempo real para **acceder a resultados de motores de búsqueda**. Ellos scrapean motores de búsqueda, gestionan proxies, resuelven captchas y analizan todos los datos estructurados enriquecidos por ti.

Una suscripción a uno de los planes de SerpApi incluye acceso a más de 50 APIs diferentes para scrapear distintos motores de búsqueda, incluidos Google, Bing, Baidu, Yahoo, Yandex y más.\
A diferencia de otros proveedores, **SerpApi no solo scrapea los resultados orgánicos**. Las respuestas de SerpApi incluyen de forma consistente todos los anuncios, imágenes y videos inline, knowledge graphs y otros elementos y funciones presentes en los resultados de búsqueda.

Los clientes actuales de SerpApi incluyen **Apple, Shopify y GrubHub**.\
Para más información, consulta su [**blog**](https://serpapi.com/blog/)**,** o prueba un ejemplo en su [**playground**](https://serpapi.com/playground)**.**\
Puedes **crear una cuenta gratis** [**aquí**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Aprende las tecnologías y habilidades necesarias para realizar vulnerability research, penetration testing y reverse engineering para proteger aplicaciones y dispositivos móviles. **Domina la seguridad de iOS y Android** a través de nuestros cursos on-demand y **obtén la certificación**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** es una plataforma de seguridad impulsada por AI para encontrar vulnerabilidades explotables antes que lo hagan los atacantes.

**Code security tip**: regístrate en NaxusAI, una plataforma inteligente de monitorización de vulnerabilidades creada para developers y equipos de seguridad. Únete hoy y empieza a usar AI para **detectar, validar y corregir riesgos de seguridad reales antes de que lleguen a producción**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) es una empresa profesional de ciberseguridad con sede en **Ámsterdam** que ayuda a **proteger** a empresas **de todo el mundo** frente a las últimas amenazas de ciberseguridad proporcionando **servicios de offensive-security** con un enfoque **moderno**.

WebSec es una empresa de seguridad internacional con oficinas en Ámsterdam y Wyoming. Ofrecen **servicios de seguridad todo en uno**, lo que significa que hacen de todo: Pentesting, auditorías de **Security**, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing y mucho más.

Otra cosa genial de WebSec es que, a diferencia de la media del sector, WebSec tiene **mucha confianza en sus habilidades**, hasta el punto de que **garantizan los mejores resultados de calidad**; en su web dice "**If we can't hack it, You don't pay it!**". Para más información, echa un vistazo a su [**website**](https://websec.net/en/) y [**blog**](https://websec.net/blog/)!

Además de lo anterior, WebSec también es un **apoyo comprometido de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desarrolla y ofrece formación eficaz en ciberseguridad construida y dirigida por expertos del sector. Sus programas van más allá de la teoría para dotar a los equipos de una comprensión profunda y habilidades accionables, usando entornos personalizados que reflejan amenazas del mundo real. Para consultas sobre formación a medida, contáctanos [**aquí**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions ofrece servicios especializados de ciberseguridad para instituciones de **Education** y **FinTech**
, con un enfoque en **penetration testing, cloud security assessments** y
**compliance readiness** (SOC 2, PCI-DSS, NIST). Nuestro equipo incluye profesionales
certificados **OSCP y CISSP**, aportando una profunda experiencia técnica y una visión estándar del sector a
cada proyecto.

Vamos más allá de los escaneos automatizados con **pruebas manuales e impulsadas por inteligencia** adaptadas a
entornos de alto riesgo. Desde proteger registros estudiantiles hasta salvaguardar transacciones financieras,
ayudamos a las organizaciones a defender lo que más importa.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Mantente informado y al día con lo último en ciberseguridad visitando nuestro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE capacita a DevOps, DevSecOps y developers para gestionar, monitorizar y asegurar clústeres de Kubernetes de forma eficiente. Aprovecha nuestras insights impulsadas por AI, un framework avanzado de seguridad y la GUI intuitiva CloudMaps para visualizar tus clústeres, entender su estado y actuar con confianza.

Además, K8Studio es **compatible con todas las principales distribuciones de kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift y más).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Consúltalos en:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}

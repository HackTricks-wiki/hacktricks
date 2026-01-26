# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logotipos y diseño de motion por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Su copia local de HackTricks estará **available at [http://localhost:3337](http://localhost:3337)** después de <5 minutos (necesita construir el libro, tenga paciencia).

## Patrocinadores Corporativos

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) es una gran empresa de ciberseguridad cuyo eslogan es **HACK THE UNHACKABLE**. Realizan su propia investigación y desarrollan sus propias herramientas de hacking para **ofrecer varios servicios valiosos de ciberseguridad** como pentesting, Red teams y formación.

Puedes consultar su **blog** en [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** también apoya proyectos open source de ciberseguridad como HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro clave para profesionales de la tecnología y la ciberseguridad de todas las disciplinas.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** es la plataforma #1 de Europa para ethical hacking y bug bounty.

**Consejo de bug bounty**: **regístrate** en **Intigriti**, una plataforma premium de bug bounty creada por hackers, para hackers. Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy y empieza a ganar recompensas de hasta **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar workflows** fácilmente, impulsados por las herramientas comunitarias más avanzadas del mundo.

Obtén acceso hoy:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de bug bounty.

- **Hacking Insights:** Participa con contenido que profundiza en la emoción y los desafíos del hacking
- **Real-Time Hack News:** Mantente al día con el mundo del hacking a través de noticias e información en tiempo real
- **Latest Announcements:** Infórmate sobre los nuevos bug bounties que se lanzan y las actualizaciones importantes de la plataforma

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y empieza a colaborar con los mejores hackers hoy mismo!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security ofrece **formación práctica en AI Security** con un enfoque **engineering-first y laboratorios hands-on**. Nuestros cursos están diseñados para security engineers, AppSec professionals y desarrolladores que quieren **construir, romper y asegurar aplicaciones reales potenciadas por AI/LLM**.

El **AI Security Certification** se centra en habilidades del mundo real, incluyendo:
- Asegurar aplicaciones potenciadas por LLM y AI
- Threat modeling para sistemas AI
- Embeddings, vector databases y RAG security
- LLM attacks, escenarios de abuso y defensas prácticas
- Patrones de diseño seguros y consideraciones de despliegue

Todos los cursos están **on-demand**, **lab-driven** y diseñados alrededor de **compensaciones de seguridad del mundo real**, no solo teoría.

👉 Más detalles sobre el curso AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** ofrece APIs rápidas y sencillas en tiempo real para **acceder a search engine results**. Rastrea motores de búsqueda, gestiona proxies, resuelve captchas y parsea todos los datos ricos y estructurados por ti.

Una suscripción a uno de los planes de SerpApi incluye acceso a más de 50 APIs diferentes para scraping de distintos motores de búsqueda, incluyendo Google, Bing, Baidu, Yahoo, Yandex y más.\
A diferencia de otros proveedores, **SerpApi no solo raspa resultados orgánicos**. Las respuestas de SerpApi incluyen de forma consistente todos los anuncios, imágenes y videos inline, knowledge graphs y otros elementos y funcionalidades presentes en los resultados de búsqueda.

Entre los clientes actuales de SerpApi están **Apple, Shopify y GrubHub**.\
Para más información consulta su [**blog**](https://serpapi.com/blog/)**,** o prueba un ejemplo en su [**playground**](https://serpapi.com/playground)**.**\
Puedes **crear una cuenta gratis** [**aquí**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Aprende las tecnologías y habilidades necesarias para realizar research de vulnerabilidades, penetration testing y reverse engineering para proteger aplicaciones y dispositivos móviles. **Domina la seguridad iOS y Android** a través de nuestros cursos on-demand y **obtén certificación**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) es una compañía profesional de ciberseguridad con sede en **Amsterdam** que ayuda a **proteger** negocios **en todo el mundo** contra las últimas amenazas de ciberseguridad proporcionando **servicios ofensive-security** con un enfoque **moderno**.

WebSec es una compañía internacional de seguridad con oficinas en Amsterdam y Wyoming. Ofrecen **servicios de seguridad todo-en-uno**, lo que significa que lo hacen todo: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campaigns, Code Review, Exploit Development, External Security Experts Outsourcing y mucho más.

Otra cosa interesante sobre WebSec es que, a diferencia del promedio de la industria, WebSec está **muy segura de sus habilidades**, hasta tal punto que **garantizan los mejores resultados de calidad**, como indican en su web: "**If we can't hack it, You don't pay it!**". Para más información visita su [**website**](https://websec.net/en/) y su [**blog**](https://websec.net/blog/)!

Además de lo anterior, WebSec también es un **apoyador comprometido de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desarrolla e imparte formación efectiva en ciberseguridad creada e impartida por expertos de la industria. Sus programas van más allá de la teoría para dotar a los equipos de un entendimiento profundo y habilidades accionables, usando entornos personalizados que reflejan amenazas del mundo real. Para consultas sobre formación a medida, contáctanos [**aquí**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Qué distingue su formación:**
* Contenido y laboratorios personalizados
* Respaldado por herramientas y plataformas de primer nivel
* Diseñado e impartido por practicantes

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions ofrece servicios especializados de ciberseguridad para instituciones de **Education** y **FinTech**, con enfoque en **penetration testing, cloud security assessments**, y **compliance readiness** (SOC 2, PCI-DSS, NIST). Nuestro equipo incluye profesionales certificados OSCP y CISSP, aportando profunda experiencia técnica y visión basada en estándares de la industria en cada proyecto.

Vamos más allá de los escaneos automatizados con **pruebas manuales e intelligence-driven** adaptadas a entornos de alto riesgo. Desde asegurar historiales estudiantiles hasta proteger transacciones financieras, ayudamos a las organizaciones a defender lo que más importa.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Mantente informado y al día con lo último en ciberseguridad visitando nuestro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permite a DevOps, DevSecOps y desarrolladores gestionar, monitorizar y asegurar clústeres Kubernetes de forma eficiente. Aprovecha nuestras insights impulsadas por AI, marco de seguridad avanzado y la intuitiva GUI CloudMaps para visualizar tus clústeres, entender su estado y actuar con confianza.

Además, K8Studio es **compatible con todas las principales distribuciones de kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift y más).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## Licencia y Descargo de responsabilidad

Consúltalas en:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}

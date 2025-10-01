# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipos y motion design de Hacktricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Tu copia local de HackTricks estará disponible en **[http://localhost:3337](http://localhost:3337)** después de <5 minutos (necesita construir el libro, ten paciencia).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) es una gran empresa de ciberseguridad cuyo eslogan es **HACK THE UNHACKABLE**. Realizan su propia investigación y desarrollan sus propias herramientas de hacking para **ofrecer varios servicios de ciberseguridad valiosos** como pentesting, Red teams y formación.

Puedes consultar su **blog** en [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** también apoya proyectos open source de ciberseguridad como HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) es el evento de ciberseguridad más relevante en **Spain** y uno de los más importantes en **Europe**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro candente para profesionales de la tecnología y la ciberseguridad de todas las disciplinas.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** es la **Europe's #1** plataforma de ethical hacking y **bug bounty.**

**Consejo de bug bounty**: **regístrate** en **Intigriti**, ¡una plataforma premium de bug bounty creada por hackers, para hackers! Únete hoy a [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) y comienza a ganar recompensas de hasta **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para crear fácilmente y **automatizar flujos de trabajo** impulsados por las **herramientas comunitarias más avanzadas** del mundo.

Obtén acceso hoy:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de bug bounty!

- **Hacking Insights:** Participa en contenido que profundiza en la emoción y los retos del hacking
- **Real-Time Hack News:** Mantente al día con el vertiginoso mundo del hacking mediante noticias e información en tiempo real
- **Latest Announcements:** Mantente informado sobre los nuevos bug bounties que se lanzan y actualizaciones cruciales de plataformas

**¡Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **y comienza a colaborar con los mejores hackers hoy!**

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtén la perspectiva de un hacker sobre tus aplicaciones web, red y cloud**

**Encuentra y reporta vulnerabilidades explotables críticas con impacto real en el negocio.** Usa nuestras más de 20 herramientas personalizadas para mapear la superficie de ataque, encontrar problemas de seguridad que permitan escalar privilegios y usar exploits automatizados para recopilar evidencia esencial, convirtiendo tu trabajo en informes persuasivos.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** ofrece APIs en tiempo real rápidas y sencillas para **acceder a resultados de motores de búsqueda**. Rastrean search engines, gestionan proxies, resuelven captchas y parsean todos los datos estructurados ricos por ti.

Una suscripción a uno de los planes de SerpApi incluye acceso a más de 50 APIs diferentes para scrapear distintos motores de búsqueda, incluyendo Google, Bing, Baidu, Yahoo, Yandex y más.\
A diferencia de otros proveedores, **SerpApi no solo scrapea resultados orgánicos**. Las respuestas de SerpApi incluyen consistentemente todos los anuncios, imágenes y vídeos en línea, knowledge graphs y otros elementos y funcionalidades presentes en los resultados de búsqueda.

Clientes actuales de SerpApi incluyen a **Apple, Shopify y GrubHub**.\
Para más información consulta su [**blog**](https://serpapi.com/blog/)**,** o prueba un ejemplo en su [**playground**](https://serpapi.com/playground)**.**\
Puedes **crear una cuenta gratuita** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Aprende las tecnologías y habilidades necesarias para realizar investigación de vulnerabilidades, penetration testing y reverse engineering para proteger aplicaciones y dispositivos móviles. **Domina iOS and Android security** a través de nuestros cursos on-demand y **obtén certificación**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) es una empresa profesional de ciberseguridad con sede en **Amsterdam** que ayuda a **proteger** negocios **en todo el mundo** contra las últimas amenazas de ciberseguridad proporcionando **servicios de offensive-security** con un enfoque **moderno**.

WebSec es una compañía de seguridad internacional con oficinas en Amsterdam y Wyoming. Ofrecen **servicios de seguridad todo en uno**, lo que significa que lo hacen todo: Pentesting, **Security** Audits, Awareness Trainings, campañas de Phishing, Code Review, Exploit Development, Security Experts Outsourcing y mucho más.

Otra cosa interesante sobre WebSec es que, a diferencia de la media de la industria, WebSec es **muy confiada en sus habilidades**, hasta tal punto que **garantizan los mejores resultados**, como indican en su web "**If we can't hack it, You don't pay it!**". Para más info echa un vistazo a su [**website**](https://websec.net/en/) y [**blog**](https://websec.net/blog/)!

Además de lo anterior, WebSec también es un **apoyador comprometido de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) es un motor de búsqueda de data breach (leak). \
Ofrecemos búsqueda por cadenas aleatorias (como google) sobre todo tipo de data leaks grandes y pequeños --no solo los grandes-- sobre datos de múltiples fuentes. \
Búsqueda por personas, búsqueda por IA, búsqueda por organización, acceso API (OpenAPI), integración con theHarvester, todas las funcionalidades que un pentester necesita.\
**¡HackTricks sigue siendo una gran plataforma de aprendizaje para todos y estamos orgullosos de patrocinarla!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) desarrolla e imparte formación efectiva en ciberseguridad creada y liderada por expertos de la industria. Sus programas van más allá de la teoría para dotar a los equipos de una comprensión profunda y habilidades accionables, usando entornos personalizados que reflejan amenazas del mundo real. Para consultas de formación a medida, contáctanos [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Qué distingue su formación:**
* Contenido y laboratorios personalizados
* Respaldados por herramientas y plataformas de primer nivel
* Diseñados e impartidos por practicantes

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions ofrece servicios especializados de ciberseguridad para instituciones de **Education** y **FinTech**, con un enfoque en **penetration testing, cloud security assessments**, y **compliance readiness** (SOC 2, PCI-DSS, NIST). Nuestro equipo incluye profesionales certificados **OSCP and CISSP**, aportando profunda experiencia técnica y perspectiva basada en estándares de la industria en cada compromiso.

Vamos más allá de los escaneos automatizados con **pruebas manuales e intelligence-driven** adaptadas a entornos de alto riesgo. Desde asegurar registros de estudiantes hasta proteger transacciones financieras, ayudamos a las organizaciones a defender lo que más importa.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Mantente informado y al día con lo último en ciberseguridad visitando nuestro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE capacita a DevOps, DevSecOps y desarrolladores para gestionar, monitorizar y asegurar clústeres de Kubernetes de manera eficiente. Aprovecha nuestras insights impulsadas por IA, framework de seguridad avanzado y la intuitiva GUI CloudMaps para visualizar tus clústeres, entender su estado y actuar con confianza.

Además, K8Studio es **compatible con todas las principales distribuciones de kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

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

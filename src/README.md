# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Los logos y el diseño en movimiento de Hacktricks son de_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_._

### Ejecutar HackTricks Localmente
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
Tu copia local de HackTricks estará **disponible en [http://localhost:3337](http://localhost:3337)** después de <5 minutos (necesita construir el libro, ten paciencia).

## Patrocinadores Corporativos

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) es una gran empresa de ciberseguridad cuyo lema es **HACK THE UNHACKABLE**. Realizan su propia investigación y desarrollan sus propias herramientas de hacking para **ofrecer varios servicios valiosos de ciberseguridad** como pentesting, Red teams y capacitación.

Puedes consultar su **blog** en [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** también apoya proyectos de código abierto en ciberseguridad como HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro vibrante para profesionales de la tecnología y la ciberseguridad en todas las disciplinas.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** es la **plataforma de hacking ético y bug bounty #1 de Europa.**

**Consejo de bug bounty**: **regístrate** en **Intigriti**, una plataforma premium de **bug bounty creada por hackers, para hackers**! Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy, y comienza a ganar recompensas de hasta **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente impulsados por las herramientas comunitarias **más avanzadas** del mundo.

Obtén acceso hoy:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de bug bounty!

- **Perspectivas de Hacking:** Participa en contenido que profundiza en la emoción y los desafíos del hacking
- **Noticias de Hackeo en Tiempo Real:** Mantente al día con el mundo del hacking de ritmo rápido a través de noticias e información en tiempo real
- **Últimos Anuncios:** Mantente informado sobre las nuevas recompensas de bug bounty que se lanzan y actualizaciones cruciales de la plataforma

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - El kit de herramientas esencial para pruebas de penetración

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtén la perspectiva de un hacker sobre tus aplicaciones web, red y nube**

**Encuentra y reporta vulnerabilidades críticas y explotables con un impacto real en los negocios.** Usa nuestras más de 20 herramientas personalizadas para mapear la superficie de ataque, encontrar problemas de seguridad que te permitan escalar privilegios, y usar exploits automatizados para recopilar evidencia esencial, convirtiendo tu arduo trabajo en informes persuasivos.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** ofrece APIs rápidas y fáciles en tiempo real para **acceder a resultados de motores de búsqueda**. Ellos extraen datos de motores de búsqueda, manejan proxies, resuelven captchas y analizan todos los datos estructurados ricos por ti.

Una suscripción a uno de los planes de SerpApi incluye acceso a más de 50 APIs diferentes para extraer datos de diferentes motores de búsqueda, incluyendo Google, Bing, Baidu, Yahoo, Yandex, y más.\
A diferencia de otros proveedores, **SerpApi no solo extrae resultados orgánicos**. Las respuestas de SerpApi incluyen consistentemente todos los anuncios, imágenes y videos en línea, gráficos de conocimiento y otros elementos y características presentes en los resultados de búsqueda.

Los actuales clientes de SerpApi incluyen **Apple, Shopify y GrubHub**.\
Para más información, consulta su [**blog**](https://serpapi.com/blog/)**,** o prueba un ejemplo en su [**playground**](https://serpapi.com/playground)**.**\
Puedes **crear una cuenta gratuita** [**aquí**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Cursos de Seguridad Móvil en Profundidad](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Aprende las tecnologías y habilidades requeridas para realizar investigación de vulnerabilidades, pruebas de penetración y ingeniería inversa para proteger aplicaciones y dispositivos móviles. **Domina la seguridad de iOS y Android** a través de nuestros cursos a demanda y **certifícate**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) es una empresa profesional de ciberseguridad con sede en **Ámsterdam** que ayuda a **proteger** negocios **en todo el mundo** contra las últimas amenazas de ciberseguridad al proporcionar **servicios de seguridad ofensiva** con un enfoque **moderno**.

WebSec es una empresa de seguridad internacional con oficinas en Ámsterdam y Wyoming. Ofrecen **servicios de seguridad todo en uno**, lo que significa que lo hacen todo; Pentesting, **Auditorías** de Seguridad, Capacitación en Conciencia, Campañas de Phishing, Revisión de Código, Desarrollo de Exploits, Externalización de Expertos en Seguridad y mucho más.

Otra cosa interesante sobre WebSec es que, a diferencia del promedio de la industria, WebSec es **muy confiado en sus habilidades**, hasta el punto de que **garantizan los mejores resultados de calidad**, se indica en su sitio web "**Si no podemos hackearlo, ¡no pagas!**". Para más información, echa un vistazo a su [**sitio web**](https://websec.net/en/) y [**blog**](https://websec.net/blog/)!

Además de lo anterior, WebSec también es un **apoyo comprometido de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) es un motor de búsqueda de filtraciones de datos (leak). \
Proporcionamos búsqueda de cadenas aleatorias (como google) sobre todo tipo de filtraciones de datos grandes y pequeñas --no solo las grandes-- de múltiples fuentes. \
Búsqueda de personas, búsqueda de IA, búsqueda de organizaciones, acceso a API (OpenAPI), integración de theHarvester, todas las características que un pentester necesita.\
**HackTricks sigue siendo una gran plataforma de aprendizaje para todos nosotros y estamos orgullosos de patrocinarla!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions ofrece servicios de ciberseguridad especializados para instituciones de **Educación** y **FinTech**, con un enfoque en **pruebas de penetración, evaluaciones de seguridad en la nube** y **preparación para cumplimiento** (SOC 2, PCI-DSS, NIST). Nuestro equipo incluye **profesionales certificados OSCP y CISSP**, aportando una profunda experiencia técnica y conocimientos estándar de la industria a cada compromiso.

Vamos más allá de los escaneos automatizados con **pruebas manuales impulsadas por inteligencia** adaptadas a entornos de alto riesgo. Desde asegurar registros de estudiantes hasta proteger transacciones financieras, ayudamos a las organizaciones a defender lo que más importa.

_“Una defensa de calidad requiere conocer la ofensiva, proporcionamos seguridad a través de la comprensión.”_

Mantente informado y al día con lo último en ciberseguridad visitando nuestro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

## Licencia y Descargo de Responsabilidad

Consúltalos en:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Estadísticas de Github

![Estadísticas de Github de HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}

# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipos y diseño de movimiento de Hacktricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

Tu copia local de HackTricks estará **disponible en [http://localhost:3337](http://localhost:3337)** en menos de 5 minutos (necesita compilar el libro, ten paciencia).

Como alternativa, si tienes Docker Compose, puedes ejecutar lo siguiente desde la raíz del repositorio:

```bash
docker compose up
```

Esto usa el `docker-compose.yml` incluido para servir la rama actualmente activa en el host en [http://localhost:3337](http://localhost:3337), con recarga en vivo. Para cambiar de idioma al usar Compose, cambia a la rama del idioma deseado antes de iniciar el servicio.

## Socios de HackTricks

---

## Amigos de HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber ofrece servicios de pentesting, auditorías de seguridad, exploits e investigación, herramientas y concienciación sobre seguridad. Su sitio describe un equipo de pentesters, programadores e investigadores de seguridad con más de una década de experiencia.<sup>[[1]](#references)</sup>

Puedes consultar su **blog** en [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** también apoya proyectos de código abierto de ciberseguridad como HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti es un proveedor de seguridad colaborativa que ofrece servicios de bug bounty y pruebas de penetración a través de una comunidad global de investigadores. Su plataforma combina cobertura continua de bug bounty con PTaaS bajo demanda y programas gestionados de divulgación de vulnerabilidades.<sup>[[2]](#references)</sup>

**Consejo sobre bug bounty**: Únete a Intigriti a través de [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) y explora sus programas de bug bounty.

---

### [Modern Security – Plataforma de formación en seguridad de IA y aplicaciones](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security ofrece formación práctica y a ritmo propio sobre seguridad de IA para ingenieros de seguridad, profesionales de AppSec y desarrolladores. Su certificación de seguridad de IA abarca fundamentos de LLM y agentes, RAG y bases de datos vectoriales, modelado de amenazas, ataques de prompt injection y MCP, y arquitectura defensiva.<sup>[[3]](#references)</sup>

👉 Más detalles sobre el curso de seguridad de IA:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** ofrece APIs para Google y otros motores de búsqueda, que devuelven datos estructurados de SERP con funciones como resultados según la ubicación, Maps, Shopping y Knowledge Graph.<sup>[[4]](#references)</sup>

Para obtener más información, visita su [**blog**](https://serpapi.com/blog/), prueba un ejemplo en su [**entorno de pruebas**](https://serpapi.com/playground) o [**crea una cuenta gratuita**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Cursos avanzados de seguridad móvil y de IA](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** ofrece cursos a ritmo propio sobre seguridad móvil y de IA. Su catálogo abarca auditoría y reversing de aplicaciones móviles con herramientas como Ghidra, Frida y LLDB, además de laboratorios de ataque y defensa de IA/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Explora el [catálogo de cursos de 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Seguridad ofensiva autónoma](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** es una plataforma de seguridad ofensiva basada en IA para escaneos completos de la superficie de ataque externa, auditorías de aplicaciones móviles, pruebas web de caja negra y revisiones de código fuente. Sus agentes validan los hallazgos explotables y proporcionan evidencias rastreables, exploits de prueba de concepto y medidas de corrección concretas.<sup>[[7]](#references)</sup>

**Consejo para auditorías de seguridad**: Usa Naxus para realizar auditorías autónomas de extremo a extremo en activos externos, aplicaciones móviles y web, y código fuente.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec ofrece servicios de pruebas de penetración, suscripciones de seguridad, dotación de personal y evaluación de vulnerabilidades. Su sitio indica que opera a nivel internacional y cubre seguridad ofensiva y defensiva, así como gobernanza, riesgo y cumplimiento.<sup>[[8]](#references)</sup>

Para obtener más información, visita su [**sitio web**](https://websec.net/en/) o su [**blog**](https://websec.net/blog/).

Además de lo anterior, WebSec también es un **colaborador comprometido de HackTricks**.

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Diseñado para el trabajo de campo. Diseñado pensando en ti.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ofrece formación en ciberseguridad impartida por expertos, con contenido y laboratorios personalizados basados en infraestructuras reales. Sus programas se adaptan a las necesidades de cada organización y abarcan desde la evaluación hasta la implementación.<sup>[[9]](#references)</sup> Para consultar sobre formación personalizada, ponte en contacto [**aquí**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Qué distingue su formación:**
* Contenido y laboratorios personalizados
* Respaldados por herramientas y plataformas de primer nivel
* Diseñados e impartidos por profesionales en activo

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions se especializa en consultoría de ciberseguridad para **Educación** y **FinTech**, con servicios que incluyen evaluaciones de cloud, pruebas de penetración internas y externas, evaluaciones de vulnerabilidades y apoyo para el cumplimiento normativo.<sup>[[10]](#references)</sup>

Mantente al día de las últimas novedades en ciberseguridad visitando nuestro [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - La interfaz gráfica más inteligente para gestionar Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio es un IDE de Kubernetes para escritorio con visualización de CloudMaps, navegación entre varios clústeres, RBAC, Helm, registros, YAML y vistas de terminal. Según el proveedor, se conecta mediante kubeconfig sin instalar agentes y es compatible con macOS, Windows, Linux y clústeres aislados de Internet.<sup>[[11]](#references)</sup>

---

## Licencia y descargo de responsabilidad

Consulta la sección Valores y preguntas frecuentes de HackTricks en las Referencias siguientes.

## Estadísticas de Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certificación de seguridad de IA – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Seguridad práctica de IA: ataques, defensas y aplicaciones](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Enlace de referencia de Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Video sobre el patrocinio de WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cursos de Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Valores y preguntas frecuentes de HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}

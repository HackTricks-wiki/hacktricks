# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipos y diseño de movimiento de HackTricks por_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

Tu copia local de HackTricks estará **disponible en [http://localhost:3337](http://localhost:3337)** en menos de 5 minutos (necesita compilar el libro, ten paciencia).

Como alternativa, si tienes Docker Compose, puedes ejecutar lo siguiente desde la raíz del repositorio:

```bash
docker compose up
```

Esto usa el `docker-compose.yml` incluido para servir la rama actualmente activa en el host en [http://localhost:3337](http://localhost:3337) con recarga en vivo. Para cambiar de idioma al usar Compose, cambia a la rama del idioma deseado antes de iniciar el servicio.

## Socios de HackTricks

---

## Amigos de HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber ofrece pruebas de penetración, auditorías de seguridad, trabajos de exploit e investigación, herramientas y servicios de concienciación sobre seguridad. Su sitio describe un equipo de pentesters, programadores e investigadores de seguridad con más de una década de experiencia.<sup>[[1]](#references)</sup>

Puedes consultar su **blog** en [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** también apoya proyectos de código abierto de ciberseguridad como HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti es un proveedor de seguridad colectiva que ofrece servicios de bug bounty y pruebas de penetración a través de una comunidad global de investigadores. Su plataforma combina cobertura continua de bug bounty con PTaaS bajo demanda y programas gestionados de divulgación de vulnerabilidades.<sup>[[2]](#references)</sup>

**Consejo sobre bug bounty**: Únete a Intigriti a través de [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) y explora sus programas de bug bounty.

---

### [Modern Security – Plataforma de formación en seguridad de IA y aplicaciones](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security ofrece formación práctica y autodidacta en seguridad de IA para ingenieros de seguridad, profesionales de AppSec y desarrolladores. Su certificación de seguridad de IA abarca fundamentos de LLM y agentes, RAG y bases de datos vectoriales, modelado de amenazas, ataques de prompt injection y MCP, y arquitectura defensiva.<sup>[[3]](#references)</sup>

👉 Más información sobre el curso de seguridad de IA:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** ofrece APIs para Google y otros motores de búsqueda, que proporcionan datos SERP estructurados con funciones como resultados según la ubicación, Maps, Shopping y resultados de Knowledge Graph.<sup>[[4]](#references)</sup>

Para obtener más información, consulta su [**blog**](https://serpapi.com/blog/), prueba un ejemplo en su [**playground**](https://serpapi.com/playground) o [**crea una cuenta gratuita**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Cursos avanzados de seguridad móvil e IA](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** ofrece cursos autodidactas de seguridad móvil y de IA. Su catálogo abarca auditoría y reversing de aplicaciones móviles con herramientas como Ghidra, Frida y LLDB, además de laboratorios de ataque y defensa de IA/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Explora el [catálogo de cursos de 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Escáner de seguridad con IA](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** ofrece una plataforma de IA ofensiva que mapea código e infraestructura y, luego, usa agentes estáticos y dinámicos para encontrar y validar debilidades explotables, con pruebas de concepto y recomendaciones para su corrección.<sup>[[7]](#references)</sup>

**Consejo de seguridad de código**: Explora Naxus para descubrir vulnerabilidades en código e infraestructura.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec ofrece pruebas de penetración, suscripciones de seguridad, dotación de personal y servicios de evaluación de vulnerabilidades. Su sitio indica que opera a nivel internacional y cubre seguridad ofensiva, seguridad defensiva y tareas de gobernanza, riesgo y cumplimiento.<sup>[[8]](#references)</sup>

Para obtener más información, visita su [**sitio web**](https://websec.net/en/) o su [**blog**](https://websec.net/blog/).

Además de lo anterior, WebSec también es un **colaborador comprometido de HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Diseñado para el terreno. Diseñado para ti.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ofrece formación en ciberseguridad impartida por expertos, con contenido y laboratorios personalizados basados en infraestructuras reales. Sus programas se adaptan a las necesidades de cada organización y abarcan desde la evaluación hasta la implementación.<sup>[[9]](#references)</sup> Para consultas sobre formación personalizada, ponte en contacto [**aquí**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Qué distingue su formación:**
* Contenido y laboratorios personalizados
* Respaldados por herramientas y plataformas de primer nivel
* Diseñados e impartidos por profesionales del sector

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions se centra en la consultoría de ciberseguridad para **educación** y **FinTech**, incluidos análisis de cloud, pruebas de penetración internas y externas, evaluaciones de vulnerabilidades y asistencia para el cumplimiento.<sup>[[10]](#references)</sup>

Mantente informado y al día de las últimas novedades en ciberseguridad visitando nuestro [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - La interfaz gráfica más inteligente para gestionar Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio es un IDE de Kubernetes para escritorio con visualización de CloudMaps, navegación entre varios clústeres y vistas de RBAC, Helm, logs, YAML y terminal. El proveedor indica que se conecta mediante kubeconfig sin instalar agentes y que es compatible con macOS, Windows, Linux y clústeres aislados de la red.<sup>[[11]](#references)</sup>

---

## Licencia y aviso legal

Consulta la entrada Valores y preguntas frecuentes de HackTricks en las Referencias a continuación.

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
- [12] [Referencia de Intigriti para HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Vídeo de patrocinio de WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cursos de Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Valores y preguntas frecuentes de HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}

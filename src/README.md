# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos y diseño de movimiento de_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

Tu copia local de HackTricks estará **disponible en [http://localhost:3337](http://localhost:3337)** en menos de 5 minutos (necesita compilar el libro; ten paciencia).

Como alternativa, si tienes Docker Compose, puedes ejecutar lo siguiente desde la raíz del repositorio:

```bash
docker compose up
```

This usa el `docker-compose.yml` incluido para servir la rama que está actualmente seleccionada en el host en [http://localhost:3337](http://localhost:3337), con recarga en vivo. Para cambiar de idioma al usar Compose, selecciona la rama del idioma deseado antes de iniciar el servicio.

## Socios de HackTricks

---

## Amigos de HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber ofrece pruebas de penetración, auditorías de seguridad, trabajos de exploit e investigación, herramientas y servicios de concienciación sobre seguridad. En su sitio describe un equipo de pentesters, programadores e investigadores de seguridad con más de una década de experiencia.<sup>[[1]](#references)</sup>

Puedes consultar su **blog** en [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** también apoya proyectos de código abierto de ciberseguridad como HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti es un proveedor de seguridad colaborativa que ofrece servicios de bug bounty y pruebas de penetración mediante una comunidad global de investigadores. Su plataforma combina cobertura continua de bug bounty con PTaaS bajo demanda y programas gestionados de divulgación de vulnerabilidades.<sup>[[2]](#references)</sup>

**Consejo sobre bug bounty**: Únete a Intigriti a través de [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) y explora sus programas de bug bounty.

---

### [Modern Security – Plataforma de formación en seguridad de IA y aplicaciones](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security ofrece formación práctica y a ritmo propio en seguridad de IA para ingenieros de seguridad, profesionales de AppSec y desarrolladores. Su certificación en seguridad de IA abarca fundamentos de LLM y agentes, RAG y bases de datos vectoriales, modelado de amenazas, ataques de prompt injection y MCP, y arquitectura defensiva.<sup>[[3]](#references)</sup>

👉 Más información sobre el curso de seguridad de IA:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** ofrece APIs para Google y otros motores de búsqueda, que devuelven datos SERP estructurados con funciones como resultados basados en la ubicación, Maps, Shopping y Knowledge Graph.<sup>[[4]](#references)</sup>

Para obtener más información, consulta su [**blog**](https://serpapi.com/blog/), prueba un ejemplo en su [**entorno de pruebas**](https://serpapi.com/playground) o [**crea una cuenta gratuita**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Cursos especializados de seguridad móvil e IA](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** ofrece cursos de seguridad móvil y de IA a ritmo propio. Su catálogo abarca auditoría y reversing de aplicaciones móviles con herramientas como Ghidra, Frida y LLDB, además de laboratorios de ataque y defensa de IA/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Explora el [catálogo de cursos de 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Seguridad ofensiva autónoma](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** es una plataforma de seguridad ofensiva basada en IA que permite realizar análisis completos de la superficie de ataque externa, auditorías de aplicaciones móviles, pruebas web de caja negra y revisiones de código fuente. Sus agentes validan los hallazgos explotables y proporcionan evidencias trazables, exploits de prueba de concepto y medidas correctivas concretas.<sup>[[7]](#references)</sup>

**Consejo para auditorías de seguridad**: Usa Naxus para realizar auditorías autónomas integrales de activos externos, aplicaciones móviles y web, y código fuente.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec ofrece pruebas de penetración, suscripciones de seguridad, servicios de contratación y evaluaciones de vulnerabilidades. Según su sitio, opera internacionalmente y abarca seguridad ofensiva, seguridad defensiva y trabajos de gobernanza, riesgo y cumplimiento.<sup>[[8]](#references)</sup>

Para obtener más información, visita su [**sitio web**](https://websec.net/en/) o su [**blog**](https://websec.net/blog/).

Además de lo anterior, WebSec también es un **colaborador comprometido de HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Diseñado para el trabajo de campo. Diseñado pensando en ti.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ofrece formación en ciberseguridad impartida por expertos, con contenido y laboratorios personalizados basados en infraestructuras reales. Sus programas se adaptan a las necesidades de cada organización y abarcan desde la evaluación hasta la implementación.<sup>[[9]](#references)</sup> Para consultar sobre formación personalizada, contacta [**aquí**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Qué distingue su formación:**
* Contenido y laboratorios personalizados
* Respaldada por herramientas y plataformas de primer nivel
* Diseñada e impartida por profesionales del sector

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions se centra en la consultoría de ciberseguridad para **Educación** y **FinTech**, e incluye evaluaciones de cloud, pruebas de penetración internas y externas, evaluaciones de vulnerabilidades y asistencia para el cumplimiento normativo.<sup>[[10]](#references)</sup>

Mantente al día con las últimas novedades en ciberseguridad visitando nuestro [**blog**](https://www.lasttowersolutions.com/blog).

---

### [Beaki — Alimentos a tu medida](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki logo"><figcaption></figcaption></figure>

**Beaki** es una aplicación personalizada para escanear alimentos, contar calorías y hacer seguimiento de la nutrición. Escanea códigos de barras y estantes de supermercado, fotografía o describe comidas y menús de restaurantes, y obtén puntuaciones explicables adaptadas a tus objetivos, dieta, alergias y perfil de salud. Beaki también registra calorías y macronutrientes y crea planes de comidas personalizados con listas de compras.<sup>[[11]](#references)</sup>

[**Descarga Beaki gratis**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks) en Android o iPhone.

---

## Licencia y descargo de responsabilidad

Consulta la entrada de HackTricks Valores y preguntas frecuentes en las Referencias de abajo.

## Estadísticas de GitHub

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certificación en seguridad de IA – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Seguridad práctica de IA: ataques, defensas y aplicaciones](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Enlace de referencia de Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Vídeo de patrocinio de WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cursos de Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Valores y preguntas frecuentes de HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}

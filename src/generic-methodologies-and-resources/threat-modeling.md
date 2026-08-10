# Modelado de amenazas

¡Bienvenido a la guía completa de HackTricks sobre el modelado de amenazas! Explora este aspecto crítico de la ciberseguridad, en el que identificamos, comprendemos y diseñamos estrategias contra posibles vulnerabilidades en un sistema. Este hilo sirve como guía paso a paso, con ejemplos del mundo real, software útil y explicaciones fáciles de entender. Es ideal tanto para principiantes como para profesionales experimentados que buscan reforzar sus defensas de ciberseguridad.

### Escenarios de uso comunes

1. **Desarrollo de software**: Como parte del Ciclo de Vida de Desarrollo de Software Seguro (SSDLC), el modelado de amenazas ayuda a **identificar posibles fuentes de vulnerabilidades** en las primeras etapas del desarrollo.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: El Penetration Testing Execution Standard (PTES) considera que el modelado de amenazas es necesario para una ejecución correcta y exige documentar los activos empresariales, los procesos empresariales, las comunidades de amenazas y sus capacidades.<sup>[[2]](#references)</sup>

### Modelo de amenazas en pocas palabras

Un modelo de amenazas suele representarse mediante un diagrama, una imagen u otra ilustración visual de una arquitectura planificada o de una aplicación existente. Los diagramas de flujo de datos (DFD) son una forma habitual de modelar un sistema y sus interacciones, mientras que el modelado de amenazas añade un análisis centrado en la seguridad.<sup>[[1]](#references)</sup>

En Microsoft's Threat Modeling Tool, las líneas rojas discontinuas indican límites de confianza; otras herramientas pueden utilizar convenciones visuales diferentes.<sup>[[4]](#references)</sup> Para agilizar la identificación de riesgos, los equipos pueden utilizar la tríada CIA (Confidencialidad, Integridad, Disponibilidad) o las categorías de amenazas STRIDE, pero la metodología adecuada depende del contexto y los requisitos del proyecto.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### La tríada CIA

La tríada CIA es un modelo de seguridad de la información ampliamente reconocido que representa Confidencialidad, Integridad y Disponibilidad. Estas propiedades se utilizan habitualmente para describir los objetivos de seguridad de los datos y los sistemas.<sup>[[3]](#references)</sup>

1. **Confidencialidad**: Garantiza que los datos o el sistema no sean accedidos por personas no autorizadas. Este es un aspecto central de la seguridad, que requiere controles de acceso adecuados, cifrado y otras medidas para evitar breaches de datos.
2. **Integridad**: La precisión, consistencia y fiabilidad de los datos durante todo su ciclo de vida. Este principio garantiza que los datos no sean modificados ni manipulados por partes no autorizadas. A menudo implica checksums, hashing y otros métodos de verificación de datos.
3. **Disponibilidad**: Garantiza que los datos y servicios sean accesibles para los usuarios autorizados cuando sea necesario. Esto suele implicar redundancia, tolerancia a fallos y configuraciones de alta disponibilidad para mantener los sistemas operativos incluso ante interrupciones.

### Metodologías de modelado de amenazas

1. **STRIDE**: El enfoque STRIDE de Microsoft clasifica las amenazas de software como **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service y Elevation of Privilege**. Estas categorías ayudan a los analistas a identificar posibles amenazas en cada punto vulnerable de un diseño.<sup>[[5]](#references)</sup>
2. **DREAD**: Este enfoque de evaluación de Microsoft puntúa las amenazas mediante **Damage, Reproducibility, Exploitability, Affected users y Discoverability**. La puntuación resultante puede ayudar a priorizar las amenazas para su mitigación.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Es una metodología de siete etapas **centrada en el riesgo** que abarca los objetivos, el alcance técnico, la descomposición de la aplicación, el análisis de amenazas, el análisis de vulnerabilidades y debilidades, el modelado de ataques y el análisis de riesgos e impacto.<sup>[[8]](#references)</sup>
4. **Trike**: Este framework de auditoría de seguridad aborda el modelado de amenazas desde una perspectiva de **gestión de riesgos** y defensiva.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Este método hace hincapié en modelos de amenazas escalables y utilizables para las vistas de aplicaciones y operaciones, y puede integrarse con los ciclos de vida de desarrollo y DevOps.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Creado por la CERT Division del Software Engineering Institute de Carnegie Mellon, OCTAVE es un método estratégico de evaluación y planificación basado en riesgos, centrado en el riesgo organizativo y no únicamente en la tecnología.<sup>[[10]](#references)</sup>

## Herramientas

Existen varias herramientas y soluciones de software disponibles que pueden **ayudar** a crear y gestionar modelos de amenazas. Estas son algunas que puedes considerar.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite es un web crawler multiplataforma para profesionales de la seguridad que permite mapear la superficie de ataque, descubrir endpoints y analizar aplicaciones web.<sup>[[6]](#references)</sup>

**Uso**

1. Elige una URL y haz Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualiza el Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon es una aplicación gratuita, open source y multiplataforma de modelado de amenazas para dibujar diagramas, sugerir amenazas y registrar mitigaciones. Está disponible como aplicación web y de escritorio.<sup>[[7]](#references)</sup>

**Uso**

1. Crea un proyecto nuevo

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

A veces puede verse así:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Inicia el proyecto nuevo

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Guarda el proyecto nuevo

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Crea tu modelo

Puedes utilizar herramientas como SpiderSuite Crawler para obtener inspiración; un modelo básico tendría un aspecto similar a este:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Una breve explicación sobre las entidades:

- Process (La propia entidad, como Webserver o una funcionalidad web)
- Actor (Una persona, como un visitante del sitio web, un usuario o un administrador)
- Data Flow Line (Indicador de interacción)
- Trust Boundary (Diferentes segmentos o ámbitos de red)
- Store (Lugares donde se almacenan los datos, como las bases de datos)

5. Crea una amenaza (Paso 1)

Primero debes elegir la capa a la que deseas añadir una amenaza.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Ahora puedes crear la amenaza.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Ten en cuenta que existe una diferencia entre Actor Threats y Process Threats. Si añadieras una amenaza a un Actor, solo podrías elegir "Spoofing" y "Repudiation". Sin embargo, en nuestro ejemplo añadimos la amenaza a una entidad Process, por lo que veremos lo siguiente en el cuadro de creación de amenazas:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Listo

Ahora tu modelo terminado debería tener un aspecto similar a este. Así es como se crea un modelo de amenazas sencillo con OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft's Threat Modeling Tool es una herramienta gratuita descargable para analizar el diseño de software. Su flujo de trabajo crea un diagrama, identifica amenazas y permite realizar la mitigación y validación mediante el enfoque STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Hoja de referencia de modelado de amenazas](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Modelado de amenazas - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Fundamentos de seguridad - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Introducción a Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Modelado de amenazas para controladores - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [Modelado de amenazas PASTA: explicación de las 7 etapas](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Documento de metodología Trike v1](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Modelado de amenazas: resumen de los métodos disponibles](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}

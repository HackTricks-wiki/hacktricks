# Modelado de amenazas

{{#include ../banners/hacktricks-training.md}}

## Modelado de amenazas

¡Bienvenido a la guía completa de HackTricks sobre el modelado de amenazas! Explora este aspecto crítico de la ciberseguridad, en el que identificamos, comprendemos y desarrollamos estrategias contra posibles vulnerabilidades en un sistema. Este hilo sirve como guía paso a paso, repleta de ejemplos del mundo real, software útil y explicaciones fáciles de entender. Es ideal tanto para principiantes como para profesionales experimentados que buscan reforzar sus defensas de ciberseguridad.

### Escenarios de uso común

1. **Desarrollo de software**: Como parte del Secure Software Development Life Cycle (SSDLC), el modelado de amenazas ayuda a **identificar posibles fuentes de vulnerabilidades** en las primeras etapas del desarrollo.
2. **Penetration Testing**: El marco Penetration Testing Execution Standard (PTES) requiere **modelar las amenazas para comprender las vulnerabilidades del sistema** antes de llevar a cabo el test.

### Modelo de amenazas en pocas palabras

Un modelo de amenazas normalmente se representa como un diagrama, una imagen u otra forma de ilustración visual que muestra la arquitectura planificada o la implementación existente de una aplicación. Se parece a un **diagrama de flujo de datos**, pero la diferencia clave reside en su diseño orientado a la seguridad.

Los modelos de amenazas suelen incluir elementos marcados en rojo, que simbolizan posibles vulnerabilidades, riesgos o barreras. Para agilizar el proceso de identificación de riesgos, se emplea la tríada CIA (Confidentiality, Integrity, Availability), que constituye la base de muchas metodologías de modelado de amenazas, siendo STRIDE una de las más comunes. Sin embargo, la metodología elegida puede variar según el contexto y los requisitos específicos.

### La tríada CIA

La tríada CIA es un modelo ampliamente reconocido en el campo de la seguridad de la información y representa Confidentiality, Integrity y Availability. Estos tres pilares constituyen la base sobre la que se construyen muchas medidas y políticas de seguridad, incluidas las metodologías de modelado de amenazas.

1. **Confidentiality**: Garantizar que personas no autorizadas no accedan a los datos o al sistema. Este es un aspecto central de la seguridad, que requiere controles de acceso adecuados, cifrado y otras medidas para evitar data breaches.
2. **Integrity**: La exactitud, coherencia y fiabilidad de los datos durante todo su ciclo de vida. Este principio garantiza que los datos no sean alterados ni manipulados por partes no autorizadas. A menudo implica checksums, hashing y otros métodos de verificación de datos.
3. **Availability**: Garantiza que los datos y servicios sean accesibles para los usuarios autorizados cuando sea necesario. Esto suele implicar redundancia, tolerancia a fallos y configuraciones de alta disponibilidad para mantener los sistemas en funcionamiento incluso ante interrupciones.

### Metodologías de modelado de amenazas

1. **STRIDE**: Desarrollado por Microsoft, STRIDE es un acrónimo de **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service y Elevation of Privilege**. Cada categoría representa un tipo de amenaza, y esta metodología se utiliza habitualmente durante la fase de diseño de un programa o sistema para identificar posibles amenazas.
2. **DREAD**: Esta es otra metodología de Microsoft utilizada para la evaluación de riesgos de las amenazas identificadas. DREAD representa **Damage potential, Reproducibility, Exploitability, Affected users y Discoverability**. Cada uno de estos factores recibe una puntuación, y el resultado se utiliza para priorizar las amenazas identificadas.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Es una metodología **centrada en el riesgo** de siete pasos. Incluye la definición e identificación de objetivos de seguridad, la creación de un alcance técnico, la descomposición de la aplicación, el análisis de amenazas, el análisis de vulnerabilidades y la evaluación de riesgos/triage.
4. **Trike**: Es una metodología basada en riesgos que se centra en la protección de activos. Parte de una perspectiva de **risk management** y analiza las amenazas y vulnerabilidades en ese contexto.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Este enfoque pretende ser más accesible y se integra en entornos de desarrollo Agile. Combina elementos de las demás metodologías y se centra en las **representaciones visuales de las amenazas**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Desarrollado por el CERT Coordination Center, este framework está orientado a la **evaluación de riesgos organizativos en lugar de sistemas o software específicos**.

## Herramientas

Existen varias herramientas y soluciones de software disponibles que pueden **ayudar** en la creación y gestión de modelos de amenazas. Estas son algunas que puedes considerar.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Un spider/crawler web GUI avanzado, multiplataforma y con múltiples funcionalidades para profesionales de la ciberseguridad. Spider Suite puede utilizarse para el mapeo y análisis de la superficie de ataque.

**Uso**

1. Selecciona una URL y realiza el Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualiza el Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Threat Dragon es un proyecto open source de OWASP. Se trata de una aplicación web y de escritorio que incluye diagramación de sistemas, además de un motor de reglas para generar automáticamente amenazas/mitigaciones.

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

Puedes utilizar herramientas como SpiderSuite Crawler para inspirarte; un modelo básico tendría un aspecto similar a este:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Una breve explicación sobre las entidades:

- Process (La propia entidad, como un Webserver o una funcionalidad web)
- Actor (Una persona, como un visitante del sitio web, un usuario o un administrador)
- Data Flow Line (Indicador de interacción)
- Trust Boundary (Diferentes segmentos o ámbitos de red.)
- Store (Lugares donde se almacenan los datos, como las bases de datos)

5. Crea una Threat (Paso 1)

Primero tienes que seleccionar la capa a la que deseas añadir una threat

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Ahora puedes crear la threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Ten en cuenta que existe una diferencia entre Actor Threats y Process Threats. Si añades una threat a un Actor, solo podrás elegir "Spoofing" y "Repudiation". Sin embargo, en nuestro ejemplo añadimos una threat a una entidad Process, por lo que veremos esto en el cuadro de creación de threats:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Listo

Ahora tu modelo terminado debería tener un aspecto similar a este. Así es como se crea un modelo de amenazas sencillo con OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Esta es una herramienta gratuita de Microsoft que ayuda a encontrar amenazas durante la fase de diseño de proyectos de software. Utiliza la metodología STRIDE y es especialmente adecuada para quienes desarrollan sobre el stack de Microsoft.

{{#include ../banners/hacktricks-training.md}}

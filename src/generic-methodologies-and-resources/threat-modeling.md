# Modelado de Amenazas

## Modelado de Amenazas

¡Bienvenido a la guía completa de HackTricks sobre Modelado de Amenazas! Emprende una exploración de este aspecto crítico de la ciberseguridad, donde identificamos, entendemos y diseñamos estrategias contra posibles vulnerabilidades en un sistema. Este hilo sirve como una guía paso a paso repleta de ejemplos del mundo real, software útil y explicaciones fáciles de entender. Ideal tanto para novatos como para profesionales experimentados que buscan fortalecer sus defensas de ciberseguridad.

### Escenarios Comúnmente Usados

1. **Desarrollo de Software**: Como parte del Ciclo de Vida de Desarrollo de Software Seguro (SSDLC), el modelado de amenazas ayuda a **identificar posibles fuentes de vulnerabilidades** en las primeras etapas del desarrollo.
2. **Pruebas de Penetración**: El estándar de ejecución de pruebas de penetración (PTES) requiere **modelado de amenazas para entender las vulnerabilidades del sistema** antes de llevar a cabo la prueba.

### Modelo de Amenazas en Breve

Un Modelo de Amenazas se representa típicamente como un diagrama, imagen u otra forma de ilustración visual que representa la arquitectura planificada o la construcción existente de una aplicación. Se asemeja a un **diagrama de flujo de datos**, pero la distinción clave radica en su diseño orientado a la seguridad.

Los modelos de amenazas a menudo presentan elementos marcados en rojo, simbolizando posibles vulnerabilidades, riesgos o barreras. Para agilizar el proceso de identificación de riesgos, se emplea el triángulo CIA (Confidencialidad, Integridad, Disponibilidad), que forma la base de muchas metodologías de modelado de amenazas, siendo STRIDE una de las más comunes. Sin embargo, la metodología elegida puede variar según el contexto y los requisitos específicos.

### El Triángulo CIA

El Triángulo CIA es un modelo ampliamente reconocido en el campo de la seguridad de la información, que representa Confidencialidad, Integridad y Disponibilidad. Estos tres pilares forman la base sobre la cual se construyen muchas medidas y políticas de seguridad, incluidas las metodologías de modelado de amenazas.

1. **Confidencialidad**: Asegurar que los datos o el sistema no sean accedidos por individuos no autorizados. Este es un aspecto central de la seguridad, que requiere controles de acceso apropiados, cifrado y otras medidas para prevenir filtraciones de datos.
2. **Integridad**: La precisión, consistencia y confiabilidad de los datos a lo largo de su ciclo de vida. Este principio asegura que los datos no sean alterados o manipulados por partes no autorizadas. A menudo implica sumas de verificación, hashing y otros métodos de verificación de datos.
3. **Disponibilidad**: Esto asegura que los datos y servicios sean accesibles para los usuarios autorizados cuando sea necesario. Esto a menudo implica redundancia, tolerancia a fallos y configuraciones de alta disponibilidad para mantener los sistemas en funcionamiento incluso frente a interrupciones.

### Metodologías de Modelado de Amenazas

1. **STRIDE**: Desarrollado por Microsoft, STRIDE es un acrónimo de **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**. Cada categoría representa un tipo de amenaza, y esta metodología se utiliza comúnmente en la fase de diseño de un programa o sistema para identificar amenazas potenciales.
2. **DREAD**: Esta es otra metodología de Microsoft utilizada para la evaluación de riesgos de amenazas identificadas. DREAD significa **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**. Cada uno de estos factores se puntúa, y el resultado se utiliza para priorizar las amenazas identificadas.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Esta es una metodología de siete pasos, **centrada en el riesgo**. Incluye la definición e identificación de objetivos de seguridad, la creación de un alcance técnico, la descomposición de la aplicación, el análisis de amenazas, el análisis de vulnerabilidades y la evaluación de riesgos/triage.
4. **Trike**: Esta es una metodología basada en riesgos que se centra en defender activos. Comienza desde una perspectiva de **gestión de riesgos** y examina amenazas y vulnerabilidades en ese contexto.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Este enfoque busca ser más accesible e integrarse en entornos de desarrollo ágil. Combina elementos de las otras metodologías y se centra en **representaciones visuales de amenazas**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Desarrollado por el CERT Coordination Center, este marco está orientado a **la evaluación de riesgos organizacionales en lugar de sistemas o software específicos**.

## Herramientas

Hay varias herramientas y soluciones de software disponibles que pueden **asistir** en la creación y gestión de modelos de amenazas. Aquí hay algunas que podrías considerar.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Un avanzado spider/crawler GUI multiplataforma y multifuncional para profesionales de ciberseguridad. Spider Suite se puede utilizar para el mapeo y análisis de la superficie de ataque.

**Uso**

1. Elige una URL y rastrea

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Ver gráfico

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Un proyecto de código abierto de OWASP, Threat Dragon es tanto una aplicación web como de escritorio que incluye diagramación de sistemas así como un motor de reglas para generar automáticamente amenazas/mitigaciones.

**Uso**

1. Crear nuevo proyecto

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

A veces podría verse así:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Lanzar nuevo proyecto

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Guardar el nuevo proyecto

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Crea tu modelo

Puedes usar herramientas como SpiderSuite Crawler para inspirarte, un modelo básico podría verse algo así

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Solo un poco de explicación sobre las entidades:

- Proceso (La entidad misma como Servidor web o funcionalidad web)
- Actor (Una persona como un visitante del sitio web, usuario o administrador)
- Línea de flujo de datos (Indicador de interacción)
- Límite de confianza (Diferentes segmentos o ámbitos de red.)
- Almacén (Cosas donde se almacenan los datos como Bases de datos)

5. Crear una amenaza (Paso 1)

Primero debes elegir la capa a la que deseas agregar una amenaza

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Ahora puedes crear la amenaza

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Ten en cuenta que hay una diferencia entre amenazas de Actor y amenazas de Proceso. Si agregaras una amenaza a un Actor, solo podrás elegir "Spoofing" y "Repudiation". Sin embargo, en nuestro ejemplo agregamos una amenaza a una entidad de Proceso, por lo que veremos esto en el cuadro de creación de amenazas:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Listo

Ahora tu modelo terminado debería verse algo así. Y así es como haces un modelo de amenaza simple con OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Esta es una herramienta gratuita de Microsoft que ayuda a encontrar amenazas en la fase de diseño de proyectos de software. Utiliza la metodología STRIDE y es particularmente adecuada para aquellos que desarrollan en la pila de Microsoft.

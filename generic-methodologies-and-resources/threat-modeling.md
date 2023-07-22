# Modelado de Amenazas

## Modelado de Amenazas

¡Bienvenido a la guía completa de HackTricks sobre el Modelado de Amenazas! Embárcate en una exploración de este aspecto crítico de la ciberseguridad, donde identificamos, comprendemos y diseñamos estrategias contra posibles vulnerabilidades en un sistema. Este hilo sirve como una guía paso a paso repleta de ejemplos del mundo real, software útil y explicaciones fáciles de entender. Ideal tanto para principiantes como para profesionales experimentados que buscan fortalecer sus defensas de ciberseguridad.

### Escenarios Comúnmente Utilizados

1. **Desarrollo de Software**: Como parte del Ciclo de Vida de Desarrollo de Software Seguro (SSDLC), el modelado de amenazas ayuda a **identificar posibles fuentes de vulnerabilidades** en las etapas iniciales del desarrollo.
2. **Pruebas de Penetración**: El marco de Ejecución Estándar de Pruebas de Penetración (PTES) requiere el **modelado de amenazas para comprender las vulnerabilidades del sistema** antes de llevar a cabo la prueba.

### Modelo de Amenazas en Resumen

Un Modelo de Amenazas se representa típicamente como un diagrama, imagen u otra forma de ilustración visual que muestra la arquitectura planificada o la estructura existente de una aplicación. Se asemeja a un **diagrama de flujo de datos**, pero la distinción clave radica en su diseño orientado a la seguridad.

Los modelos de amenazas a menudo presentan elementos marcados en rojo, que simbolizan posibles vulnerabilidades, riesgos o barreras. Para agilizar el proceso de identificación de riesgos, se utiliza la tríada CIA (Confidencialidad, Integridad, Disponibilidad), que forma la base de muchas metodologías de modelado de amenazas, siendo STRIDE una de las más comunes. Sin embargo, la metodología elegida puede variar según el contexto y los requisitos específicos.

### La Tríada CIA

La Tríada CIA es un modelo ampliamente reconocido en el campo de la seguridad de la información, que representa Confidencialidad, Integridad y Disponibilidad. Estos tres pilares forman la base sobre la cual se construyen muchas medidas y políticas de seguridad, incluyendo las metodologías de modelado de amenazas.

1. **Confidencialidad**: Asegurar que los datos o el sistema no sean accedidos por personas no autorizadas. Este es un aspecto central de la seguridad, que requiere controles de acceso adecuados, cifrado y otras medidas para prevenir brechas de datos.
2. **Integridad**: La precisión, consistencia y confiabilidad de los datos a lo largo de su ciclo de vida. Este principio garantiza que los datos no sean alterados o manipulados por partes no autorizadas. A menudo implica el uso de sumas de verificación, funciones hash y otros métodos de verificación de datos.
3. **Disponibilidad**: Esto garantiza que los datos y servicios estén accesibles para los usuarios autorizados cuando sea necesario. A menudo implica redundancia, tolerancia a fallos y configuraciones de alta disponibilidad para mantener los sistemas en funcionamiento incluso ante interrupciones.

### Metodologías de Modelado de Amenazas

1. **STRIDE**: Desarrollado por Microsoft, STRIDE es un acrónimo de **Suplantación, Manipulación, Repudio, Divulgación de Información, Denegación de Servicio y Elevación de Privilegios**. Cada categoría representa un tipo de amenaza, y esta metodología se utiliza comúnmente en la fase de diseño de un programa o sistema para identificar posibles amenazas.
2. **DREAD**: Esta es otra metodología de Microsoft utilizada para la evaluación de riesgos de amenazas identificadas. DREAD significa **Potencial de Daño, Reproducibilidad, Explotabilidad, Usuarios Afectados y Descubribilidad**. Cada uno de estos factores se puntúa y el resultado se utiliza para priorizar las amenazas identificadas.
3. **PASTA** (Proceso para Simulación de Ataques y Análisis de Amenazas): Esta es una metodología de siete pasos centrada en el riesgo. Incluye la definición e identificación de objetivos de seguridad, la creación de un alcance técnico, la descomposición de la aplicación, el análisis de amenazas, el análisis de vulnerabilidades y la evaluación de riesgos/triage.
4. **Trike**: Esta es una metodología basada en el riesgo que se centra en la defensa de activos. Parte de una perspectiva de **gestión de riesgos** y analiza las amenazas y vulnerabilidades en ese contexto.
5. **VAST** (Modelado de Amenazas Visual, Ágil y Simple): Este enfoque tiene como objetivo ser más accesible e integrarse en entornos de desarrollo ágil. Combina elementos de otras metodologías y se centra en **representaciones visuales de amenazas**.
6. **OCTAVE** (Evaluación de Amenazas, Activos y Vulnerabilidades Críticas Operativas): Desarrollado por el Centro de Coordinación CERT, este marco está orientado a la **evaluación de riesgos organizacionales en lugar de sistemas o software específicos**.

## Herramientas

Existen varias herramientas y soluciones de software disponibles que pueden **ayudar** en la creación y gestión de modelos de amenazas. Aquí tienes algunas que podrías considerar.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Una avanzada herramienta gráfica multiplataforma de araña/rastreador web para profesionales de la ciberseguridad. Spider Suite se puede utilizar para mapear y analizar la superficie de ataque.

**Uso**

1. Selecciona una URL y rastrea

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Ver el gráfico

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Un proyecto de código abierto de OWASP, Threat Dragon es una aplicación web y de escritorio que incluye diagramas de sistemas y un motor de reglas para generar automáticamente amenazas/mitigaciones.

**Uso**

1. Crear un nuevo proyecto

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

A veces podría verse así:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Iniciar nuevo proyecto

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Guardar el nuevo proyecto

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Crear tu modelo

Puedes usar herramientas como SpiderSuite Crawler para inspirarte, un modelo básico se vería así

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Solo un poco de explicación sobre las entidades:

* Proceso (La entidad en sí, como un servidor web o una funcionalidad web)
* Actor (Una persona, como un visitante del sitio web, usuario o administrador)
* Línea de flujo de datos (Indicador de interacción)
* Límite de confianza (Segmentos de red o ámbitos diferentes)
* Almacenamiento (Cosas donde se almacenan los datos, como bases de datos)

5. Crear una amenaza (Paso 1)

Primero debes elegir la capa a la que deseas agregar una amenaza

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Ahora puedes crear la amenaza

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Ten en cuenta que hay una diferencia entre las amenazas de los actores y las amenazas de los procesos. Si agregaras una amenaza a un Actor, solo podrás elegir "Suplantación" y "Repudio". Sin embargo, en nuestro ejemplo, agregamos una amenaza a una entidad de Proceso, por lo que veremos esto en el cuadro de creación de amenazas:

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Hecho

Ahora tu modelo terminado debería verse algo así. Y así es como se crea un modelo de amenazas simple con OWASP Threat Dragon.

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>
### [Herramienta de Modelado de Amenazas de Microsoft](https://aka.ms/threatmodelingtool)

Esta es una herramienta gratuita de Microsoft que ayuda a encontrar amenazas en la fase de diseño de proyectos de software. Utiliza la metodología STRIDE y es especialmente adecuada para aquellos que desarrollan en la plataforma de Microsoft.

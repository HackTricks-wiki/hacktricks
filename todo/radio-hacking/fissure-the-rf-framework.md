# FISSURE - El marco de RF

**Comprensión y reversión de señales basadas en SDR independientes de frecuencia**

FISSURE es un marco de trabajo de RF y reversión de código abierto diseñado para todos los niveles de habilidad con ganchos para la detección y clasificación de señales, el descubrimiento de protocolos, la ejecución de ataques, la manipulación de IQ, el análisis de vulnerabilidades, la automatización y la IA/ML. El marco fue construido para promover la integración rápida de módulos de software, radios, protocolos, datos de señales, scripts, gráficos de flujo, material de referencia y herramientas de terceros. FISSURE es un habilitador de flujo de trabajo que mantiene el software en una ubicación y permite a los equipos ponerse al día sin esfuerzo mientras comparten la misma configuración de línea de base probada para distribuciones específicas de Linux.

El marco y las herramientas incluidas en FISSURE están diseñados para detectar la presencia de energía de RF, comprender las características de una señal, recopilar y analizar muestras, desarrollar técnicas de transmisión y/o inyección, y crear cargas útiles o mensajes personalizados. FISSURE contiene una biblioteca en crecimiento de información de protocolos y señales para ayudar en la identificación, la creación de paquetes y el fuzzing. Existen capacidades de archivo en línea para descargar archivos de señal y construir listas de reproducción para simular el tráfico y probar sistemas.

El amigable código Python y la interfaz de usuario permiten a los principiantes aprender rápidamente sobre herramientas y técnicas populares que involucran RF y reversión de código. Los educadores en ciberseguridad e ingeniería pueden aprovechar el material incorporado o utilizar el marco para demostrar sus propias aplicaciones del mundo real. Los desarrolladores e investigadores pueden usar FISSURE para sus tareas diarias o para exponer sus soluciones de vanguardia a una audiencia más amplia. A medida que la conciencia y el uso de FISSURE crecen en la comunidad, también lo hará la extensión de sus capacidades y la amplitud de la tecnología que abarca.

**Información adicional**

* [Página de AIS](https://www.ainfosec.com/technologies/fissure/)
* [Diapositivas de GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Papel de GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Video de GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transcripción de Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Empezando

**Soportado**

Hay tres ramas dentro de FISSURE para facilitar la navegación de archivos y reducir la redundancia de código. La rama Python2\_maint-3.7 contiene una base de código construida alrededor de Python2, PyQt4 y GNU Radio 3.7; la rama Python3\_maint-3.8 está construida alrededor de Python3, PyQt5 y GNU Radio 3.8; y la rama Python3\_maint-3.10 está construida alrededor de Python3, PyQt5 y GNU Radio 3.10.

|   Sistema operativo   |   Rama de FISSURE   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**En progreso (beta)**

Estos sistemas operativos todavía están en estado beta. Están en desarrollo y se sabe que faltan varias características. Los elementos en el instalador pueden entrar en conflicto con programas existentes o no instalarse hasta que se elimine el estado.

|     Sistema operativo     |    Rama de FISSURE   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Nota: Ciertas herramientas de software no funcionan para todos los sistemas operativos. Consulte [Software y conflictos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Esto instalará las dependencias de software de PyQt necesarias para lanzar las GUIs de instalación si no se encuentran.

A continuación, seleccione la opción que mejor se adapte a su sistema operativo (debería detectarse automáticamente si su sistema operativo coincide con una opción).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Se recomienda instalar FISSURE en un sistema operativo limpio para evitar conflictos existentes. Seleccione todas las casillas recomendadas (botón predeterminado) para evitar errores al operar las diversas herramientas dentro de FISSURE. Habrá múltiples solicitudes durante la instalación, en su mayoría solicitando permisos elevados y nombres de usuario. Si un elemento contiene una sección "Verificar" al final, el instalador ejecutará el comando que sigue y resaltará el elemento de la casilla de verificación en verde o rojo dependiendo de si el comando produce errores. Los elementos marcados sin una sección "Verificar" permanecerán en negro después de la instalación.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Uso**

Abra una terminal e ingrese:
```
fissure
```
Consulta el menú de ayuda de FISSURE para obtener más detalles sobre su uso.

## Detalles

**Componentes**

* Panel de control
* Centro de control (HIPRFISR)
* Identificación de señal objetivo (TSI)
* Descubrimiento de protocolo (PD)
* Gráfico de flujo y ejecutor de scripts (FGE)

![componentes](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capacidades**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detector de señal**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulación de IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Búsqueda de señal**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconocimiento de patrones**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Ataques**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Listas de reproducción de señales**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galería de imágenes**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Creación de paquetes**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integración de Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculadora de CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Registro**_            |

**Hardware**

A continuación se muestra una lista de hardware "compatible" con diferentes niveles de integración:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adaptadores 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lecciones

FISSURE viene con varias guías útiles para familiarizarse con diferentes tecnologías y técnicas. Muchas incluyen pasos para usar varias herramientas que están integradas en FISSURE.

* [Lección 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lección 2: Disectores Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lección 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lección 4: Placas ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lección 5: Rastreo de radiosondas](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lección 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lección 7: Tipos de datos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lección 8: Bloques GNU Radio personalizados](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lección 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lección 10: Exámenes de radioaficionados](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lección 11: Herramientas Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Hoja de ruta

* [ ] Agregar más tipos de hardware, protocolos de RF, parámetros de señal, herramientas de análisis
* [ ] Soportar más sistemas operativos
* [ ] Desarrollar material de clase sobre FISSURE (ataques de RF, Wi-Fi, GNU Radio, PyQt, etc.)
* [ ] Crear un acondicionador de señal, extractor de características y clasificador de señal con técnicas AI/ML seleccionables
* [ ] Implementar mecanismos de demodulación recursiva para producir un flujo de bits a partir de señales desconocidas
* [ ] Transicionar los componentes principales de FISSURE a un esquema de implementación de nodos de sensor genéricos

## Contribuciones

Se sugiere fuertemente hacer sugerencias para mejorar FISSURE. Deja un comentario en la página de [Discusiones](https://github.com/ainfosec/FISSURE/discussions) o en el servidor de Discord si tienes alguna idea con respecto a lo siguiente:

* Nuevas sugerencias de características y cambios de diseño
* Herramientas de software con pasos de instalación
* Nuevas lecciones o material adicional para lecciones existentes
* Protocolos de RF de interés
* Más tipos de hardware y SDR para integración
* Scripts de análisis de IQ en Python
* Correcciones y mejoras de instalación

Las contribuciones para mejorar FISSURE son cruciales para acelerar su desarrollo. Cualquier contribución que hagas es muy apreciada. Si deseas contribuir a través del desarrollo de código, haz un fork del repositorio y crea una solicitud de extracción:

1. Haz un fork del proyecto
2. Crea tu rama de características (`git checkout -b feature/AmazingFeature`)
3. Haz tus cambios (`git commit -m 'Agregar una característica increíble'`)
4. Haz push a la rama (`git push origin feature/AmazingFeature`)
5. Abre una solicitud de extracción

También se aceptan la creación de [Issues](https://github.com/ainfosec/FISSURE/issues) para llamar la atención sobre errores.

## Colaboración

Contacta al Desarrollo de Negocios de Assured Information Security, Inc. (AIS) para proponer y formalizar cualquier oportunidad de colaboración de FISSURE, ya sea dedicando tiempo a integrar tu software, teniendo a las personas talentosas de AIS desarrollando soluciones para tus desafíos técnicos o integrando FISSURE en otras plataformas/aplicaciones.

## Licencia

GPL-3.0

Para detalles de la licencia, consulta el archivo LICENSE.

## Contacto

Únete al servidor de Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Sigue en Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Desarrollo de Negocios - Assured Information Security, Inc. - bd@ainfosec.com

## Créditos

Reconocemos y estamos agradecidos con estos desarrolladores:

[Créditos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Agradecimientos

Agradecimientos especiales al Dr. Samuel Mantravadi y Joseph Reith por sus contribuciones a este proyecto.

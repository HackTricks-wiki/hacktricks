# FISSURE - El Framework de RF

{{#include ../../banners/hacktricks-training.md}}

**Comprensión y Reverse Engineering de señales basada en SDR e independiente de la frecuencia**

FISSURE es un framework de RF y reverse engineering de código abierto, diseñado para todos los niveles de habilidad, con hooks para la detección y clasificación de señales, el descubrimiento de protocolos, la ejecución de ataques, la manipulación de IQ, el análisis de vulnerabilidades, la automatización y la IA/ML. El framework se creó para promover la integración rápida de módulos de software, radios, protocolos, datos de señales, scripts, flow graphs, material de referencia y herramientas de terceros. FISSURE facilita los workflows al mantener el software en una única ubicación y permitir que los equipos se pongan al día fácilmente mientras comparten la misma configuración base probada para distribuciones específicas de Linux.<sup>[[1]](#references)[[2]](#references)</sup>

El framework y las herramientas incluidas con FISSURE están diseñados para detectar la presencia de energía RF, comprender las características de una señal, recopilar y analizar muestras, desarrollar técnicas de transmisión y/o inyección, y crear payloads o mensajes personalizados. FISSURE contiene una biblioteca en crecimiento de información sobre protocolos y señales para ayudar en la identificación, la creación de paquetes y el fuzzing. Existen capacidades de archivo online para descargar archivos de señales y crear playlists que permitan simular tráfico y probar sistemas.

La base de código y la interfaz de usuario, desarrolladas en Python, permiten a los principiantes aprender rápidamente sobre herramientas y técnicas populares relacionadas con RF y reverse engineering. Los educadores de ciberseguridad e ingeniería pueden aprovechar el material integrado o utilizar el framework para demostrar sus propias aplicaciones del mundo real. Los desarrolladores e investigadores pueden usar FISSURE para sus tareas diarias o para mostrar sus soluciones de vanguardia a un público más amplio. A medida que aumenten el conocimiento y el uso de FISSURE en la comunidad, también crecerán sus capacidades y la amplitud de la tecnología que abarca.

**Información adicional**

* [Página de AIS](https://www.ainfosec.com/technologies/fissure/)
* [Diapositivas de GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Artículo de GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Vídeo de GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transcripción del Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Primeros pasos

**Compatibles**

Hay tres branches dentro de FISSURE para facilitar la navegación por los archivos y reducir la redundancia del código. La branch Python2\_maint-3.7 contiene una base de código desarrollada en torno a Python2, PyQt4 y GNU Radio 3.7; la branch Python3\_maint-3.8 está desarrollada en torno a Python3, PyQt5 y GNU Radio 3.8; y la branch Python3\_maint-3.10 está desarrollada en torno a Python3, PyQt5 y GNU Radio 3.10.

|   Sistema operativo   |   Branch de FISSURE   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**En desarrollo (beta)**

Estos sistemas operativos todavía se encuentran en estado beta. Están en desarrollo y se sabe que faltan varias funcionalidades. Los elementos del instalador podrían entrar en conflicto con programas existentes o no instalarse hasta que se elimine este estado.

|     Sistema operativo     |    Branch de FISSURE   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Nota: Algunas herramientas de software no funcionan en todos los sistemas operativos. Consulta [Software y conflictos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Instalación**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Esto instalará las dependencias de software de PyQt necesarias para iniciar las interfaces gráficas de instalación si no se encuentran.

A continuación, selecciona la opción que mejor coincida con tu sistema operativo (debería detectarse automáticamente si tu sistema operativo coincide con alguna opción).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Se recomienda instalar FISSURE en un sistema operativo limpio para evitar conflictos existentes. Selecciona todas las casillas recomendadas (botón Default) para evitar errores al utilizar las distintas herramientas de FISSURE. Durante la instalación aparecerán varias solicitudes, principalmente para pedir permisos elevados y nombres de usuario. Si un elemento contiene una sección "Verify" al final, el instalador ejecutará el comando siguiente y resaltará la casilla en verde o rojo, según si el comando produce algún error. Los elementos marcados que no tengan una sección "Verify" permanecerán en negro después de la instalación.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Uso**

Abre una terminal e introduce:
```
fissure
```
Consulta el menú Help de FISSURE para obtener más detalles sobre el uso.

## Detalles

**Components**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capabilities**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detector de señales**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulación de IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Búsqueda de señales**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconocimiento de patrones**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Listas de reproducción de señales**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galería de imágenes**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Creación de paquetes**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integración con Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculadora CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

La siguiente es una lista del hardware "compatible", con distintos niveles de integración:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adaptadores 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lessons

FISSURE incluye varias guías útiles para familiarizarse con diferentes tecnologías y técnicas. Muchas incluyen pasos para usar diversas herramientas integradas en FISSURE.

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] Añadir más tipos de hardware, protocolos RF, parámetros de señal y herramientas de análisis
* [ ] Compatibilidad con más sistemas operativos
* [ ] Desarrollar material didáctico sobre FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt, etc.)
* [ ] Crear un acondicionador de señales, un extractor de características y un clasificador de señales con técnicas de AI/ML seleccionables
* [ ] Implementar mecanismos de demodulación recursiva para producir un bitstream a partir de señales desconocidas
* [ ] Migrar los componentes principales de FISSURE a un esquema genérico de implementación de nodos sensores

## Contributing

Se recomiendan encarecidamente las sugerencias para mejorar FISSURE. Deja un comentario en la página de [Discussions](https://github.com/ainfosec/FISSURE/discussions) o en el Discord Server si tienes alguna propuesta relacionada con lo siguiente:

* Sugerencias de nuevas funcionalidades y cambios de diseño
* Herramientas de software con pasos de instalación
* Nuevas lecciones o material adicional para las lecciones existentes
* Protocolos RF de interés
* Más hardware y tipos de SDR para la integración
* Scripts de análisis de IQ en Python
* Correcciones y mejoras de instalación

Las contribuciones para mejorar FISSURE son cruciales para acelerar su desarrollo. Agradecemos enormemente cualquier contribución. Si deseas contribuir mediante el desarrollo de código, haz fork del repo y crea un pull request:

1. Haz fork del proyecto
2. Crea tu feature branch (`git checkout -b feature/AmazingFeature`)
3. Haz commit de tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Haz push a la branch (`git push origin feature/AmazingFeature`)
5. Abre un pull request

También se agradece la creación de [Issues](https://github.com/ainfosec/FISSURE/issues) para llamar la atención sobre bugs.

## Collaborating

Contacta con el departamento de Business Development de Assured Information Security, Inc. (AIS) para proponer y formalizar cualquier oportunidad de colaboración con FISSURE, ya sea dedicando tiempo a integrar tu software, haciendo que las personas talentosas de AIS desarrollen soluciones para tus desafíos técnicos o integrando FISSURE en otras plataformas/aplicaciones.

## License

GPL-3.0

Para consultar los detalles de la licencia, revisa el archivo LICENSE.

## Contact

Únete al Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Sigue a FISSURE en Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

Reconocemos y agradecemos a estos desarrolladores:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Acknowledgments

Agradecimientos especiales al Dr. Samuel Mantravadi y a Joseph Reith por sus contribuciones a este proyecto.

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}

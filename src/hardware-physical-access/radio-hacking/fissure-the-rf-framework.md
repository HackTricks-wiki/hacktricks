# FISSURE - El framework de RF

{{#include ../../banners/hacktricks-training.md}}

**Comprensión y reverse engineering de señales basada en SDR e independiente de la frecuencia**

FISSURE es un framework de RF y reverse engineering de código abierto, diseñado para todos los niveles de habilidad, con hooks para la detección y clasificación de señales, el descubrimiento de protocolos, la ejecución de ataques, la manipulación de IQ, el análisis de vulnerabilidades, la automatización y la IA/ML. El framework se creó para promover la integración rápida de módulos de software, radios, protocolos, datos de señales, scripts, flow graphs, material de referencia y herramientas de terceros. FISSURE facilita los flujos de trabajo al mantener el software en una sola ubicación y permitir que los equipos se pongan al día sin esfuerzo y compartan la misma configuración base probada para distribuciones específicas de Linux.<sup>[[1]](#references)[[2]](#references)</sup>

El framework y las herramientas incluidas con FISSURE están diseñados para detectar energía de RF, caracterizar señales, recopilar y analizar muestras, desarrollar técnicas de transmisión o inyección, y crear payloads o mensajes personalizados. FISSURE también proporciona información de protocolos y señales para su identificación, la creación de paquetes y el fuzzing, además de archivos y listas de reproducción para simular y probar tráfico.<sup>[[1]](#references)[[2]](#references)</sup>

La base de código Python y la interfaz gráfica ayudan a los principiantes a aprender sobre RF y herramientas de reverse engineering. Los educadores pueden utilizar las lecciones integradas, mientras que los desarrolladores e investigadores pueden integrar sus propios módulos y flujos de trabajo. Las versiones actuales también admiten nodos de sensores distribuidos, integración con TAK, flujos de trabajo de geolocalización y despliegues de Apptainer específicos por rol.<sup>[[1]](#references)[[3]](#references)</sup>

**Información adicional**

* [Página de AIS](https://www.ainfosec.com/technologies/fissure/)
* [Diapositivas de GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Artículo de GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Video de GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transcripción de Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Primeros pasos

**Compatible**

La versión actual de FISSURE utiliza la rama **`Python3`** para el desarrollo activo con PyQt5 y GNU Radio 3.8 o 3.10. La rama obsoleta **`Python2_maint-3.7`** sigue disponible para sistemas operativos antiguos y herramientas de terceros que requieren GNU Radio 3.7. Los nombres anteriores de las ramas `Python3_maint-3.8` y `Python3_maint-3.10` son históricos; la selección de la versión de mantenimiento de GNU Radio ahora se gestiona desde la rama `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Sistema operativo | Rama de FISSURE | Rama predeterminada de GNU Radio |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | usar una versión compatible de Linux | usar la versión correspondiente |

**En desarrollo (beta)**

Estos sistemas operativos aún están en estado beta. Siguen en desarrollo y se sabe que faltan varias funciones. Los elementos del instalador podrían entrar en conflicto con programas existentes o no instalarse hasta que se retire este estado.

| Sistema operativo | Rama de FISSURE | Rama predeterminada de GNU Radio |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Algunas herramientas de terceros no funcionan en todos los sistemas operativos. Antes de instalar, consulta la documentación actual sobre [conflictos conocidos y software de terceros](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts).<sup>[[3]](#references)</sup>

**Instalación**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

El paso del submódulo descarga los módulos out-of-tree de GNU Radio que utiliza FISSURE y es necesario para instalar esos módulos. El instalador también instalará las dependencias de PyQt que falten y que se necesitan para iniciar sus GUI de instalación.<sup>[[3]](#references)</sup>

A continuación, selecciona la opción que mejor se ajuste a tu sistema operativo (debería detectarse automáticamente si tu sistema operativo coincide con alguna opción).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Se recomienda instalar FISSURE en un sistema operativo limpio para evitar conflictos existentes. Selecciona todas las casillas recomendadas (botón Default) para evitar errores al usar las distintas herramientas de FISSURE. Durante la instalación aparecerán varias solicitudes, principalmente para pedir permisos elevados y nombres de usuario. Si un elemento incluye una sección "Verify" al final, el instalador ejecutará el comando que aparece a continuación y resaltará la casilla del elemento en verde o rojo, según si el comando genera errores. Los elementos marcados que no tengan una sección "Verify" permanecerán en negro después de la instalación.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Uso**

Abre una terminal e introduce:

```
fissure
```

Consulta el menú Help de FISSURE para obtener más detalles sobre su uso.

## Details

**Components**

* Panel
* Hub central (HIPRFISR)
* Identificación de señales objetivo (TSI)
* Descubrimiento de protocolos (PD)
* Ejecutor de diagramas de flujo y scripts (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capabilities**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detector de señales**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulación de IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Búsqueda de señales**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconocimiento de patrones**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Ataques**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Listas de reproducción de señales**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galería de imágenes**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Creación de paquetes**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integración con Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculadora CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Registro**_            |

**Hardware**

El siguiente hardware cuenta con distintos niveles de integración en FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* Adaptadores 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lessons

FISSURE incluye varias guías útiles para familiarizarse con distintas tecnologías y técnicas. Muchas incluyen pasos para usar diversas herramientas integradas en FISSURE.

* [Lección 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lección 2: Disectores Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lección 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lección 4: Placas ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lección 5: Seguimiento de radiosondas](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lección 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lección 7: Tipos de datos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lección 8: Bloques personalizados de GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lección 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lección 10: Exámenes de radioaficionado](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lección 11: Herramientas Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Lección 12: Creación de USB de arranque](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lección 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lección 14: Ventiladores de techo](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Roadmap

* [ ] Añadir más tipos de hardware, protocolos RF, parámetros de señal y herramientas de análisis
* [ ] Admitir más sistemas operativos
* [ ] Desarrollar material didáctico sobre FISSURE (ataques RF, Wi-Fi, GNU Radio, PyQt, etc.)
* [ ] Crear un acondicionador de señales, un extractor de características y un clasificador de señales con técnicas de AI/ML seleccionables
* [ ] Implementar mecanismos de demodulación recursiva para producir un flujo de bits a partir de señales desconocidas
* [ ] Transicionar los componentes principales de FISSURE a un esquema genérico de despliegue de nodos sensores

## Contributing

Se agradecen mucho las sugerencias para mejorar FISSURE. Deja un comentario en la página de [Discussions](https://github.com/ainfosec/FISSURE/discussions) o en el servidor de Discord si tienes ideas sobre alguno de estos temas:

* Sugerencias de nuevas funciones y cambios de diseño
* Herramientas de software con pasos de instalación
* Nuevas lecciones o material adicional para las lecciones existentes
* Protocolos RF de interés
* Más tipos de hardware y SDR para integrar
* Scripts de análisis de IQ en Python
* Correcciones y mejoras de la instalación

Las contribuciones para mejorar FISSURE son fundamentales para acelerar su desarrollo. Agradecemos enormemente cualquier contribución que realices. Si quieres contribuir mediante el desarrollo de código, haz un fork del repositorio y crea un pull request:

1. Haz un fork del proyecto
2. Crea tu rama de funcionalidad (`git checkout -b feature/AmazingFeature`)
3. Confirma tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Sube los cambios a la rama (`git push origin feature/AmazingFeature`)
5. Abre un pull request

También se agradece la creación de [Issues](https://github.com/ainfosec/FISSURE/issues) para dar a conocer errores.

## Collaborating

Contacta con el departamento de Desarrollo Empresarial de Assured Information Security, Inc. (AIS) para proponer y formalizar oportunidades de colaboración en FISSURE, ya sea dedicando tiempo a integrar tu software, haciendo que el talentoso equipo de AIS desarrolle soluciones para tus desafíos técnicos o integrando FISSURE en otras plataformas/aplicaciones.

## License

GPL-3.0

Para conocer los detalles de la licencia, consulta el archivo LICENSE.

## Contact

Únete al servidor de Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Síguenos en Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Desarrollo Empresarial - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

Reconocemos y agradecemos a estos desarrolladores:

[Créditos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Acknowledgments

Agradecemos especialmente al Dr. Samuel Mantravadi y a Joseph Reith por sus contribuciones a este proyecto.

## References

- [1] [FISSURE - El framework RF (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [Artículo sobre FISSURE (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [Documentación de FISSURE - Instalación](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}

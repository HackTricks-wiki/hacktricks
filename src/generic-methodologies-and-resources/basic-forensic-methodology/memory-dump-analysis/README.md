# Análisis de volcados de memoria

{{#include ../../../banners/hacktricks-training.md}}

## Inicio

Empieza **buscando** **malware** dentro del pcap. Usa las **herramientas** mencionadas en [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility es un framework de código abierto para el análisis de volcados de memoria**. Esta herramienta de Python analiza volcados de fuentes externas o máquinas virtuales de VMware, identificando datos como procesos y contraseñas según el perfil del sistema operativo del volcado. Es extensible mediante plugins, lo que la hace muy versátil para investigaciones forenses.<sup>[[1]](#references)[[2]](#references)</sup>

[**Encuentra aquí una cheatsheet**](volatility-cheatsheet.md)

## Informe de fallo de minivolcado

Cuando el volcado es pequeño (solo algunos KB, quizá unos pocos MB), puede tratarse de un informe de fallo de minivolcado en lugar de un volcado completo de memoria.<sup>[[3]](#references)</sup>

![Volatility - Informe de fallo de minivolcado: Un archivo de volcado pequeño identificado como un informe de fallo Mini DuMP](<../../../images/image (532).png>)

Si tienes Visual Studio instalado, puedes abrir este archivo para ver información básica como el nombre del proceso, la arquitectura, los detalles de la excepción y los módulos cargados:<sup>[[4]](#references)</sup>

![Volatility - Informe de fallo de minivolcado: Si tienes Visual Studio instalado, puedes abrir este archivo y obtener información básica como el nombre del proceso, la arquitectura, la información de la excepción y...](<../../../images/image (263).png>)

También puedes inspeccionar la excepción y ver el desensamblado del módulo.<sup>[[4]](#references)</sup>

![Panel de acciones de Visual Studio para minivolcados con opciones para depurar de forma nativa y establecer rutas de símbolos](<../../../images/image (142).png>)

![Desensamblado de Visual Studio de instrucciones de la excepción del minivolcado](<../../../images/image (610).png>)

En cualquier caso, Visual Studio no es la mejor herramienta para realizar un análisis profundo del volcado.

Debes **abrirlo** con **IDA** o **Radare** para inspeccionarlo en **profundidad**.

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Uso de Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Archivos Minidump](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Usar archivos de volcado en el depurador de Visual Studio](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}

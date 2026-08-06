# Análisis de volcado de memoria

{{#include ../../../banners/hacktricks-training.md}}

## Inicio

Comienza **buscando** **malware** dentro del pcap. Usa las **herramientas** mencionadas en [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility es el framework open-source principal para el análisis de volcados de memoria**. Esta herramienta de Python analiza volcados de fuentes externas o de máquinas virtuales VMware, identificando datos como procesos y contraseñas basándose en el perfil del sistema operativo del volcado. Es extensible mediante plugins, lo que la hace muy versátil para investigaciones forenses.

[**Encuentra aquí una cheatsheet**](volatility-cheatsheet.md)

## Informe de crash de un mini volcado

Cuando el volcado es pequeño (solo algunos KB, quizá unos pocos MB), probablemente se trate de un informe de crash de un mini volcado y no de un volcado de memoria.

![Volatility - Informe de crash de un mini volcado: Cuando el volcado es pequeño (solo algunos KB, quizá unos pocos MB), probablemente se trate de un informe de crash de un mini volcado y no de un volcado de memoria](<../../../images/image (532).png>)

Si tienes Visual Studio instalado, puedes abrir este archivo y obtener información básica como el nombre del proceso, la arquitectura, la información de la excepción y los módulos que se están ejecutando:

![Volatility - Informe de crash de un mini volcado: Si tienes Visual Studio instalado, puedes abrir este archivo y obtener información básica como el nombre del proceso, la arquitectura, la información de la excepción y...](<../../../images/image (263).png>)

También puedes cargar la excepción y ver las instrucciones decompiladas

![Volatility - Informe de crash de un mini volcado: También puedes cargar la excepción y ver las instrucciones decompiladas](<../../../images/image (142).png>)

![Volatility - Informe de crash de un mini volcado: También puedes cargar la excepción y ver las instrucciones decompiladas](<../../../images/image (610).png>)

De todos modos, Visual Studio no es la mejor herramienta para realizar un análisis profundo del volcado.

Deberías **abrirlo** usando **IDA** o **Radare** para inspeccionarlo en **profundidad**.

{{#include ../../../banners/hacktricks-training.md}}

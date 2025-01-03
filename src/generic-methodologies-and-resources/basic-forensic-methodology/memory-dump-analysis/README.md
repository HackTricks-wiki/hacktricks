# Análisis de volcado de memoria

{{#include ../../../banners/hacktricks-training.md}}

## Comenzar

Comienza **buscando** **malware** dentro del pcap. Usa las **herramientas** mencionadas en [**Análisis de Malware**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility es el principal marco de código abierto para el análisis de volcado de memoria**. Esta herramienta de Python analiza volcados de fuentes externas o máquinas virtuales de VMware, identificando datos como procesos y contraseñas basados en el perfil del SO del volcado. Es extensible con plugins, lo que la hace altamente versátil para investigaciones forenses.

[**Encuentra aquí una hoja de trucos**](volatility-cheatsheet.md)

## Informe de fallo de mini volcado

Cuando el volcado es pequeño (solo algunos KB, tal vez unos pocos MB), entonces probablemente sea un informe de fallo de mini volcado y no un volcado de memoria.

![](<../../../images/image (532).png>)

Si tienes Visual Studio instalado, puedes abrir este archivo y vincular información básica como el nombre del proceso, arquitectura, información de excepciones y módulos que se están ejecutando:

![](<../../../images/image (263).png>)

También puedes cargar la excepción y ver las instrucciones decompiladas

![](<../../../images/image (142).png>)

![](<../../../images/image (610).png>)

De todos modos, Visual Studio no es la mejor herramienta para realizar un análisis en profundidad del volcado.

Deberías **abrirlo** usando **IDA** o **Radare** para inspeccionarlo en **profundidad**.

​

{{#include ../../../banners/hacktricks-training.md}}

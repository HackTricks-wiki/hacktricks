# Análisis de volcado de memoria

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR a los repositorios [hacktricks](https://github.com/carlospolop/hacktricks) y [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro hirviente para los profesionales de la tecnología y la ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Comenzar

Comience **buscando** **malware** dentro del archivo pcap. Use las **herramientas** mencionadas en [**Análisis de malware**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

El marco de código abierto líder para el análisis de volcado de memoria es [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md). Volatility es un script de Python para analizar volcados de memoria que se recopilaron con una herramienta externa (o una imagen de memoria de VMware recopilada al pausar la VM). Por lo tanto, dado el archivo de volcado de memoria y el "perfil" relevante (el sistema operativo desde el que se recopiló el volcado), Volatility puede comenzar a identificar las estructuras en los datos: procesos en ejecución, contraseñas, etc. También es extensible mediante plugins para extraer varios tipos de artefactos.\
De: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

## Informe de fallo de volcado mínimo

Cuando el volcado es pequeño (solo algunos KB, tal vez algunos MB), entonces probablemente sea un informe de fallo de volcado mínimo y no un volcado de memoria.

![](<../../../.gitbook/assets/image (216).png>)

Si tiene Visual Studio instalado, puede abrir este archivo y vincular información básica como el nombre del proceso, la arquitectura, la información de excepción y los módulos que se están ejecutando:

![](<../../../.gitbook/assets/image (217).png>)

También puede cargar la excepción y ver las instrucciones descompiladas

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

De todos modos, Visual Studio no es la mejor herramienta para realizar un análisis en profundidad del volcado.

Debe **abrirlo** usando **IDA** o **Radare** para inspeccionarlo en **profundidad**.

# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

timeRoasting, la causa principal es el mecanismo de autenticación obsoleto dejado por Microsoft en su extensión a los servidores NTP, conocido como MS-SNTP. En este mecanismo, los clientes pueden usar directamente el Identificador Relativo (RID) de cualquier cuenta de computadora, y el controlador de dominio utilizará el hash NTLM de la cuenta de computadora (generado por MD4) como la clave para generar el **Código de Autenticación de Mensaje (MAC)** del paquete de respuesta.

Los atacantes pueden explotar este mecanismo para obtener valores de hash equivalentes de cuentas de computadora arbitrarias sin autenticación. Claramente, podemos usar herramientas como Hashcat para realizar ataques de fuerza bruta.

El mecanismo específico se puede ver en la sección 3.1.5.1 "Comportamiento de Solicitud de Autenticación" de la [documentación oficial de Windows para el protocolo MS-SNTP](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf).

En el documento, la sección 3.1.5.1 cubre el Comportamiento de Solicitud de Autenticación.
![](../../images/Pasted%20image%2020250709114508.png)
Se puede ver que cuando el elemento ADM ExtendedAuthenticatorSupported se establece en `false`, se conserva el formato Markdown original.

>Citado en el artículo original：
>>Si el elemento ADM ExtendedAuthenticatorSupported es falso, el cliente DEBE construir un mensaje de Solicitud NTP del Cliente. La longitud del mensaje de Solicitud NTP del Cliente es de 68 bytes. El cliente establece el campo Autenticador del mensaje de Solicitud NTP del Cliente como se describe en la sección 2.2.1, escribiendo los 31 bits menos significativos del valor RID en los 31 bits menos significativos del subcampo Identificador de Clave del autenticador, y luego escribiendo el valor del Selector de Clave en el bit más significativo del subcampo Identificador de Clave.

En la sección 4 del documento Ejemplos de Protocolo punto 3

>Citado en el artículo original：
>>3. Después de recibir la solicitud, el servidor verifica que el tamaño del mensaje recibido sea de 68 bytes. Si no lo es, el servidor o bien descarta la solicitud (si el tamaño del mensaje no es igual a 48 bytes) o la trata como una solicitud no autenticada (si el tamaño del mensaje es de 48 bytes). Suponiendo que el tamaño del mensaje recibido sea de 68 bytes, el servidor extrae el RID del mensaje recibido. El servidor lo utiliza para llamar al método NetrLogonComputeServerDigest (como se especifica en la sección 3.5.4.8.2 de [MS-NRPC]) para calcular los crypto-checksums y seleccionar el crypto-checksum basado en el bit más significativo del subcampo Identificador de Clave del mensaje recibido, como se especifica en la sección 3.2.5. Luego, el servidor envía una respuesta al cliente, estableciendo el campo Identificador de Clave en 0 y el campo Crypto-Checksum en el crypto-checksum calculado.

De acuerdo con la descripción en el documento oficial de Microsoft anterior, los usuarios no necesitan ninguna autenticación; solo necesitan llenar el RID para iniciar una solicitud, y luego pueden obtener el checksum criptográfico. El checksum criptográfico se explica en la sección 3.2.5.1.1 del documento.

>Citado en el artículo original：
>>El servidor recupera el RID de los 31 bits menos significativos del subcampo Identificador de Clave del campo Autenticador del mensaje de Solicitud NTP del Cliente. El servidor utiliza el método NetrLogonComputeServerDigest (como se especifica en la sección 3.5.4.8.2 de [MS-NRPC]) para calcular los crypto-checksums con los siguientes parámetros de entrada:
>>>![](../../images/Pasted%20image%2020250709115757.png)

El checksum criptográfico se calcula utilizando MD5, y el proceso específico se puede consultar en el contenido del documento. Esto nos da la oportunidad de realizar un ataque de roasting.

## cómo atacar

Cita a https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Scripts de Timeroasting de Tom Tervoort
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
{{#include ../../banners/hacktricks-training.md}}

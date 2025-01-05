# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Este es un pequeño resumen de los capítulos de persistencia de máquina de la increíble investigación de [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## **Comprendiendo el robo de credenciales de usuario activas con certificados – PERSIST1**

En un escenario donde un usuario puede solicitar un certificado que permite la autenticación de dominio, un atacante tiene la oportunidad de **solicitar** y **robar** este certificado para **mantener persistencia** en una red. Por defecto, la plantilla `User` en Active Directory permite tales solicitudes, aunque a veces puede estar deshabilitada.

Usando una herramienta llamada [**Certify**](https://github.com/GhostPack/Certify), se puede buscar certificados válidos que habiliten el acceso persistente:
```bash
Certify.exe find /clientauth
```
Se destaca que el poder de un certificado radica en su capacidad para **autenticar como el usuario** al que pertenece, independientemente de cualquier cambio de contraseña, siempre que el certificado permanezca **válido**.

Los certificados se pueden solicitar a través de una interfaz gráfica utilizando `certmgr.msc` o a través de la línea de comandos con `certreq.exe`. Con **Certify**, el proceso para solicitar un certificado se simplifica de la siguiente manera:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Al realizar una solicitud exitosa, se genera un certificado junto con su clave privada en formato `.pem`. Para convertir esto en un archivo `.pfx`, que es utilizable en sistemas Windows, se utiliza el siguiente comando:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
El archivo `.pfx` puede ser subido a un sistema objetivo y utilizado con una herramienta llamada [**Rubeus**](https://github.com/GhostPack/Rubeus) para solicitar un Ticket Granting Ticket (TGT) para el usuario, extendiendo el acceso del atacante mientras el certificado sea **válido** (típicamente un año):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Una advertencia importante se comparte sobre cómo esta técnica, combinada con otro método descrito en la sección **THEFT5**, permite a un atacante obtener de manera persistente el **hash NTLM** de una cuenta sin interactuar con el Local Security Authority Subsystem Service (LSASS), y desde un contexto no elevado, proporcionando un método más sigiloso para el robo de credenciales a largo plazo.

## **Gaining Machine Persistence with Certificates - PERSIST2**

Otro método implica inscribir la cuenta de máquina de un sistema comprometido para un certificado, utilizando la plantilla predeterminada `Machine` que permite tales acciones. Si un atacante obtiene privilegios elevados en un sistema, puede usar la cuenta **SYSTEM** para solicitar certificados, proporcionando una forma de **persistence**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Este acceso permite al atacante autenticarse en **Kerberos** como la cuenta de máquina y utilizar **S4U2Self** para obtener tickets de servicio de Kerberos para cualquier servicio en el host, otorgando efectivamente al atacante acceso persistente a la máquina.

## **Extensión de la Persistencia a Través de la Renovación de Certificados - PERSIST3**

El método final discutido implica aprovechar los **períodos de validez** y **renovación** de las plantillas de certificados. Al **renovar** un certificado antes de su expiración, un atacante puede mantener la autenticación en Active Directory sin necesidad de inscripciones adicionales de tickets, lo que podría dejar rastros en el servidor de la Autoridad de Certificación (CA).

Este enfoque permite un método de **persistencia extendida**, minimizando el riesgo de detección a través de menos interacciones con el servidor CA y evitando la generación de artefactos que podrían alertar a los administradores sobre la intrusión.

{{#include ../../../banners/hacktricks-training.md}}

# Persistencia de Cuenta de AD CS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

**Este es un pequeño resumen de los capítulos de persistencia de máquina de la increíble investigación de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## **Comprendiendo el Robo de Credenciales de Usuario Activo con Certificados – PERSIST1**

En un escenario donde un usuario puede solicitar un certificado que permita la autenticación de dominio, un atacante tiene la oportunidad de **solicitar** y **robar** este certificado para **mantener la persistencia** en una red. Por defecto, la plantilla `User` en Active Directory permite tales solicitudes, aunque a veces puede estar deshabilitada.

Utilizando una herramienta llamada [**Certify**](https://github.com/GhostPack/Certify), uno puede buscar certificados válidos que habiliten el acceso persistente:
```bash
Certify.exe find /clientauth
```
Se destaca que el poder de un certificado radica en su capacidad para **autenticarse como el usuario** al que pertenece, independientemente de cualquier cambio de contraseña, siempre y cuando el certificado siga siendo **válido**.

Los certificados pueden solicitarse a través de una interfaz gráfica utilizando `certmgr.msc` o mediante la línea de comandos con `certreq.exe`. Con **Certify**, el proceso para solicitar un certificado se simplifica de la siguiente manera:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Una vez realizada la solicitud exitosa, se genera un certificado junto con su clave privada en formato `.pem`. Para convertir esto en un archivo `.pfx`, que es utilizable en sistemas Windows, se utiliza el siguiente comando:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
El archivo `.pfx` puede ser luego cargado en un sistema objetivo y utilizado con una herramienta llamada [**Rubeus**](https://github.com/GhostPack/Rubeus) para solicitar un Ticket Granting Ticket (TGT) para el usuario, extendiendo el acceso del atacante siempre que el certificado sea **válido** (normalmente un año):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Un importante aviso se comparte sobre cómo esta técnica, combinada con otro método descrito en la sección **THEFT5**, permite a un atacante obtener persistentemente el **hash NTLM** de una cuenta sin interactuar con el Local Security Authority Subsystem Service (LSASS), y desde un contexto no elevado, proporcionando un método más sigiloso para el robo de credenciales a largo plazo.

## **Obteniendo Persistencia en la Máquina con Certificados - PERSIST2**

Otro método implica inscribir la cuenta de máquina comprometida en un certificado, utilizando la plantilla predeterminada `Machine` que permite tales acciones. Si un atacante obtiene privilegios elevados en un sistema, pueden utilizar la cuenta **SYSTEM** para solicitar certificados, proporcionando una forma de **persistencia**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Este acceso permite al atacante autenticarse en **Kerberos** como la cuenta de máquina y utilizar **S4U2Self** para obtener tickets de servicio de Kerberos para cualquier servicio en el host, otorgando efectivamente al atacante acceso persistente a la máquina.

## **Ampliando la Persistencia a Través de la Renovación de Certificados - PERSIST3**

El método final discutido implica aprovechar los **períodos de validez** y **renovación** de plantillas de certificados. Al **renovar** un certificado antes de su vencimiento, un atacante puede mantener la autenticación en Active Directory sin necesidad de inscripciones adicionales de tickets, lo que podría dejar rastros en el servidor de Autoridad de Certificación (CA).

Este enfoque permite un método de **persistencia extendida**, minimizando el riesgo de detección a través de menos interacciones con el servidor de CA y evitando la generación de artefactos que podrían alertar a los administradores sobre la intrusión.

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

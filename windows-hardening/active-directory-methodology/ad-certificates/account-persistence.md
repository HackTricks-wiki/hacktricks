# Persistencia de Cuenta en AD CS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Robo de Credenciales de Usuario Activo a través de Certificados – PERSIST1

Si al usuario se le permite solicitar un certificado que permita la autenticación de dominio, un atacante podría **solicitar** y **robar** dicho certificado para **mantener** **persistencia**.

La plantilla **`User`** permite esto y viene por **defecto**. Sin embargo, podría estar deshabilitada. Por lo tanto, [**Certify**](https://github.com/GhostPack/Certify) te permite encontrar certificados válidos para persistir:
```
Certify.exe find /clientauth
```
Tenga en cuenta que un **certificado se puede utilizar para autenticación** como ese usuario mientras el certificado sea **válido**, **incluso** si el usuario **cambia** su **contraseña**.

Desde la **GUI** es posible solicitar un certificado con `certmgr.msc` o a través de la línea de comandos con `certreq.exe`.

Utilizando [**Certify**](https://github.com/GhostPack/Certify) puedes ejecutar:
```
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
El resultado será un bloque de texto en formato `.pem` que incluye un **certificado** + **clave privada**
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Para **usar ese certificado**, se puede **subir** el `.pfx` a un objetivo y **utilizarlo con** [**Rubeus**](https://github.com/GhostPack/Rubeus) para **solicitar un TGT** para el usuario inscrito, mientras el certificado sea válido (la duración predeterminada es de 1 año):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
{% hint style="warning" %}
Combinado con la técnica descrita en la sección [**THEFT5**](certificate-theft.md#ntlm-credential-theft-via-pkinit-theft5), un atacante también puede **obtener de manera persistente el hash NTLM de la cuenta**, que el atacante podría usar para autenticarse mediante **pass-the-hash** o **crackear** para obtener la **contraseña en texto plano**. \
Este es un método alternativo de **robo de credenciales a largo plazo** que **no interactúa con LSASS** y es posible desde un **contexto no elevado.**
{% endhint %}

## Persistencia en Máquinas a través de Certificados - PERSIST2

Si una plantilla de certificado permite **Domain Computers** como principios de inscripción, un atacante podría **inscribir la cuenta de máquina de un sistema comprometido**. La plantilla por defecto **`Machine`** coincide con todas esas características.

Si un **atacante eleva privilegios** en un sistema comprometido, el atacante puede usar la cuenta **SYSTEM** para inscribirse en plantillas de certificado que otorgan privilegios de inscripción a cuentas de máquina (más información en [**THEFT3**](certificate-theft.md#machine-certificate-theft-via-dpapi-theft3)).

Puedes usar [**Certify**](https://github.com/GhostPack/Certify) para recopilar un certificado para la cuenta de máquina elevando automáticamente a SYSTEM con:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Tenga en cuenta que con acceso a un certificado de cuenta de máquina, el atacante puede **autenticarse en Kerberos** como la cuenta de máquina. Utilizando **S4U2Self**, un atacante puede obtener un **ticket de servicio Kerberos para cualquier servicio en el host** (por ejemplo, CIFS, HTTP, RPCSS, etc.) como cualquier usuario.

En última instancia, esto le da al ataque un método de persistencia de máquina.

## Persistencia de Cuenta a través de la Renovación de Certificado - PERSIST3

Las plantillas de certificados tienen un **Periodo de Validez** que determina cuánto tiempo se puede usar un certificado emitido, así como un **Periodo de Renovación** (generalmente 6 semanas). Esta es una ventana de **tiempo antes** de que el certificado **caduque** donde una **cuenta puede renovarlo** desde la autoridad emisora del certificado.

Si un atacante compromete un certificado capaz de autenticación de dominio a través del robo o inscripción maliciosa, el atacante puede **autenticarse en AD por la duración del periodo de validez del certificado**. Sin embargo, el atacante puede **renovar el certificado antes de su expiración**. Esto puede funcionar como un enfoque de **persistencia extendida** que **evita que se soliciten inscripciones adicionales de tickets**, lo que **puede dejar artefactos** en el servidor de CA.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

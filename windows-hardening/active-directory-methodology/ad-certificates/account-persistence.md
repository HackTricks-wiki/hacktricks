# Persistencia de cuenta de AD CS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Robo de credenciales de usuario activo a través de certificados - PERSIST1

Si se permite al usuario solicitar un certificado que permita la autenticación de dominio, un atacante podría **solicitarlo** y **robarlo** para **mantener** la **persistencia**.

La plantilla **`User`** lo permite y viene por **defecto**. Sin embargo, podría estar deshabilitada. Por lo tanto, [**Certify**](https://github.com/GhostPack/Certify) te permite encontrar certificados válidos para persistir:
```
Certify.exe find /clientauth
```
Ten en cuenta que un **certificado puede ser utilizado para autenticación** como ese usuario mientras el certificado sea **válido**, **incluso** si el usuario **cambia** su **contraseña**.

Desde la interfaz gráfica de usuario (GUI) es posible solicitar un certificado con `certmgr.msc` o mediante la línea de comandos con `certreq.exe`.

Usando [**Certify**](https://github.com/GhostPack/Certify) puedes ejecutar:
```
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
El resultado será un bloque de texto con formato `.pem` que incluye el **certificado** y la **clave privada**.
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Para **usar ese certificado**, se puede **subir** el archivo `.pfx` al objetivo y **usarlo con** [**Rubeus**](https://github.com/GhostPack/Rubeus) para **solicitar un TGT** para el usuario inscrito, mientras el certificado sea válido (el tiempo de vida predeterminado es de 1 año):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
{% hint style="warning" %}
Combinado con la técnica descrita en la sección [**THEFT5**](certificate-theft.md#ntlm-credential-theft-via-pkinit-theft5), un atacante también puede obtener de manera persistente el **hash NTLM de la cuenta**, que el atacante podría usar para autenticarse a través de **pass-the-hash** o **crackear** para obtener la **contraseña en texto plano**. \
Este es un método alternativo de **robo de credenciales a largo plazo** que no toca LSASS y es posible desde un **contexto no elevado**.
{% endhint %}

## Persistencia de máquina a través de certificados - PERSIST2

Si una plantilla de certificado permitía a **Domain Computers** como principios de inscripción, un atacante podría **inscribir la cuenta de máquina de un sistema comprometido**. La plantilla **`Machine`** por defecto coincide con todas esas características.

Si un **atacante eleva privilegios** en un sistema comprometido, el atacante puede usar la cuenta **SYSTEM** para inscribirse en plantillas de certificado que otorgan privilegios de inscripción a cuentas de máquina (más información en [**THEFT3**](certificate-theft.md#machine-certificate-theft-via-dpapi-theft3)).

Puede usar [**Certify**](https://github.com/GhostPack/Certify) para obtener un certificado para la cuenta de máquina elevando automáticamente a SYSTEM con:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Tenga en cuenta que con acceso a un certificado de cuenta de máquina, el atacante puede **autenticarse en Kerberos** como la cuenta de máquina. Usando **S4U2Self**, un atacante puede obtener un **ticket de servicio Kerberos para cualquier servicio en el host** (por ejemplo, CIFS, HTTP, RPCSS, etc.) como cualquier usuario.

En última instancia, esto le da al ataque un método de persistencia de máquina.

## Persistencia de cuenta a través de la renovación de certificados - PERSIST3

Las plantillas de certificados tienen un **Período de validez** que determina cuánto tiempo se puede usar un certificado emitido, así como un **período de renovación** (generalmente 6 semanas). Este es un período de tiempo **antes de que** el certificado **caduque** donde una **cuenta puede renovarlo** desde la autoridad de certificación emisora.

Si un atacante compromete un certificado capaz de autenticación de dominio a través de robo o inscripción maliciosa, el atacante puede **autenticarse en AD durante el período de validez del certificado**. Sin embargo, el atacante puede **renovar el certificado antes de la expiración**. Esto puede funcionar como un enfoque de **persistencia extendida** que **evita que se soliciten inscripciones de tickets adicionales**, lo que **puede dejar artefactos** en el propio servidor CA.

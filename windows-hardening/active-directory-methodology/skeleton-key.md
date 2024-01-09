# Skeleton Key

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Skeleton Key**

**De:** [**https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/**](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)

Hay varios métodos que los atacantes pueden usar para comprometer cuentas de Active Directory, elevar privilegios y crear persistencia una vez que se han establecido en tu dominio. Skeleton Key es un malware particularmente aterrador dirigido a dominios de Active Directory para facilitar alarmantemente el secuestro de cualquier cuenta. Este malware **se inyecta en LSASS y crea una contraseña maestra que funcionará para cualquier cuenta en el dominio**. Las contraseñas existentes también seguirán funcionando, por lo que es muy difícil saber que este ataque ha ocurrido a menos que sepas qué buscar.

No es sorprendente que este sea uno de los muchos ataques que está empaquetado y es muy fácil de realizar usando [Mimikatz](https://github.com/gentilkiwi/mimikatz). Veamos cómo funciona.

### Requisitos para el Ataque Skeleton Key

Para perpetrar este ataque, **el atacante debe tener derechos de Administrador del Dominio**. Este ataque debe ser **realizado en cada controlador de dominio para un compromiso completo, pero incluso apuntar a un solo controlador de dominio puede ser efectivo**. **Reiniciar** un controlador de dominio **eliminará este malware** y tendrá que ser redistribuido por el atacante.

### Realizando el Ataque Skeleton Key

Realizar el ataque es muy sencillo. Solo requiere el siguiente **comando que se debe ejecutar en cada controlador de dominio**: `misc::skeleton`. Después de eso, puedes autenticarte como cualquier usuario con la contraseña predeterminada de Mimikatz.

![Inyectando una skeleton key usando el comando misc::skeleton en un controlador de dominio con Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/1-3.png)

Aquí hay una autenticación para un miembro de Administrador del Dominio usando la skeleton key como contraseña para obtener acceso administrativo a un controlador de dominio:

![Usando la skeleton key como contraseña con el comando misc::skeleton para obtener acceso administrativo a un controlador de dominio con la contraseña predeterminada de Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/2-5.png)

Nota: Si recibes un mensaje que dice, “System error 86 has occurred. The specified network password is not correct”, solo intenta usar el formato dominio\cuenta para el nombre de usuario y debería funcionar.

![Usando el formato dominio\cuenta para el nombre de usuario si recibes un mensaje que dice System error 86 has occurred The specified network password is not correct](https://blog.stealthbits.com/wp-content/uploads/2017/07/3-3.png)

Si lsass ya fue **parcheado** con skeleton, entonces aparecerá este **error**:

![](<../../.gitbook/assets/image (160).png>)

### Mitigaciones

* Eventos:
* ID de Evento del Sistema 7045 - Un servicio fue instalado en el sistema. (Tipo de driver de Modo Kernel)
* ID de Evento de Seguridad 4673 – Uso de Privilegio Sensible ("Audit privilege use" debe estar habilitado)
* ID de Evento 4611 – Un proceso de inicio de sesión confiable ha sido registrado con la Autoridad de Seguridad Local ("Audit privilege use" debe estar habilitado)
* `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "`_`Kernel Mode Driver"}`_
* Esto solo detecta mimidrv `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$`_`.message -like "Kernel Mode Driver" -and $`_`.message -like "`_`mimidrv`_`"}`
* Mitigación:
* Ejecutar lsass.exe como un proceso protegido, obliga a un atacante a cargar un driver de modo kernel
* `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`
* Verificar después de reiniciar: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "`_`protected process"}`_

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

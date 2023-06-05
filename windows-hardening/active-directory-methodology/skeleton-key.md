# Skeleton Key

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Skeleton Key**

**De:** [**https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/**](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)

Existen varios métodos para comprometer cuentas de Active Directory que los atacantes pueden utilizar para elevar privilegios y crear persistencia una vez que se han establecido en su dominio. El Skeleton Key es un malware especialmente peligroso dirigido a dominios de Active Directory que hace que sea alarmantemente fácil secuestrar cualquier cuenta. Este malware **se inyecta en LSASS y crea una contraseña maestra que funcionará para cualquier cuenta en el dominio**. Las contraseñas existentes también seguirán funcionando, por lo que es muy difícil saber que se ha producido este ataque a menos que se sepa qué buscar.

No es sorprendente que este sea uno de los muchos ataques que se empaquetan y que es muy fácil de realizar con [Mimikatz](https://github.com/gentilkiwi/mimikatz). Veamos cómo funciona.

### Requisitos para el ataque Skeleton Key

Para perpetrar este ataque, **el atacante debe tener derechos de administrador de dominio**. Este ataque debe ser **realizado en cada controlador de dominio para una completa compromisión, pero incluso apuntar a un solo controlador de dominio puede ser efectivo**. **Reiniciar** un controlador de dominio **eliminará este malware** y tendrá que ser redeployado por el atacante.

### Realización del ataque Skeleton Key

Realizar el ataque es muy sencillo. Solo se requiere que se ejecute el siguiente **comando en cada controlador de dominio**: `misc::skeleton`. Después de eso, se puede autenticar como cualquier usuario con la contraseña predeterminada de Mimikatz.

![Inyectando una clave skeleton usando misc::skeleton en un controlador de dominio con Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/1-3.png)

Aquí hay una autenticación para un miembro de Domain Admin usando la clave skeleton como contraseña para obtener acceso administrativo a un controlador de dominio:

![Usando la clave skeleton como contraseña con el comando misc::skeleton para obtener acceso administrativo a un controlador de dominio con la contraseña predeterminada de Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/2-5.png)

Nota: Si recibe un mensaje que dice: "Error del sistema 86 ha ocurrido. La contraseña de red especificada no es correcta", simplemente intente usar el formato dominio\cuenta para el nombre de usuario y debería funcionar.

![Usando el formato dominio\cuenta para el nombre de usuario si recibe un mensaje que dice que se ha producido un error del sistema 86. La contraseña de red especificada no es correcta](https://blog.stealthbits.com/wp-content/uploads/2017/07/3-3.png)

Si lsass ya estaba parcheado con skeleton, entonces aparecerá este **error**:

![](<../../.gitbook/assets/image (160).png>)

### Mitigaciones

* Eventos:
  * ID de evento del sistema 7045 - Se instaló un servicio en el sistema. (Tipo de controlador de modo kernel)
  * ID de evento de seguridad 4673 - Uso de privilegios sensibles (debe estar habilitada la "Auditoría del uso de privilegios")
  * ID de evento 4611 - Se ha registrado un proceso de inicio de sesión de confianza con la Autoridad de seguridad local (debe estar habilitada la "Auditoría del uso de privilegios")
* `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "`_`Kernel Mode Driver"}`_
* Esto solo detecta mimidrv `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$`_`.message -like "Kernel Mode Driver" -and $`_`.message -like "`_`mimidrv`_`"}`
* Mitigación:
  * Ejecutar lsass.exe como un proceso protegido, obliga al atacante a cargar un controlador de modo kernel
  * `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`
  * Verificar después del reinicio: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "`_`proceso protegido"}`_

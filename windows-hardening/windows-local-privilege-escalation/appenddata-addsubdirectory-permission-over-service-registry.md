<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de HackTricks para AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


**El post original está en** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Resumen
La salida del script indica que el usuario actual posee permisos de escritura en dos claves de registro:

- `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
- `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

Para investigar más a fondo los permisos del servicio RpcEptMapper, el usuario menciona el uso de la GUI de regedit y destaca la utilidad de la pestaña de Permisos Efectivos de la ventana de Configuración de Seguridad Avanzada. Esta pestaña permite a los usuarios verificar los permisos efectivos otorgados a un usuario o grupo específico sin inspeccionar los ACE individuales.

La captura de pantalla proporcionada muestra los permisos para la cuenta de usuario de laboratorio con privilegios bajos. La mayoría de los permisos son estándar, como Consultar Valor, pero un permiso destaca: Crear Subclave. El nombre genérico para este permiso es AppendData/AddSubdirectory, lo que coincide con lo reportado por el script.

El usuario procede a explicar que esto significa que no pueden modificar ciertos valores directamente, sino que solo pueden crear nuevas subclaves. Muestran un ejemplo donde intentar modificar el valor de ImagePath resulta en un error de acceso denegado.

Sin embargo, aclaran que esto no es un falso positivo y que hay una oportunidad interesante aquí. Investigan la estructura del registro de Windows y descubren una forma potencial de aprovechar la subclave Performance, que no existe por defecto para el servicio RpcEptMapper. Esta subclave podría permitir el registro de DLL y el monitoreo de rendimiento, ofreciendo una oportunidad para la escalada de privilegios.

Mencionan que encontraron documentación relacionada con la subclave Performance y cómo usarla para el monitoreo de rendimiento. Esto los lleva a crear una DLL de prueba de concepto y muestran el código para implementar las funciones requeridas: OpenPerfData, CollectPerfData y ClosePerfData. También exportan estas funciones para uso externo.

El usuario demuestra la prueba de la DLL usando rundll32 para asegurarse de que funcione como se espera, registrando información con éxito.

A continuación, explican que el desafío es engañar al servicio RPC Endpoint Mapper para que cargue su DLL de Performance. Mencionan que observaron que su archivo de registro se creaba al consultar clases WMI relacionadas con Datos de Rendimiento en PowerShell. Esto les permite ejecutar código arbitrario en el contexto del servicio WMI, que se ejecuta como LOCAL SYSTEM. Esto les proporciona un acceso elevado e inesperado.

En conclusión, el usuario destaca la persistencia inexplicada de esta vulnerabilidad y su posible impacto, que podría extenderse a la post-explotación, el movimiento lateral y la evasión de antivirus/EDR.

También mencionan que, aunque inicialmente hicieron pública la vulnerabilidad de forma no intencionada a través de su script, su impacto se limita a versiones no soportadas de Windows (por ejemplo, Windows 7 / Server 2008 R2) con acceso local.


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de HackTricks para AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

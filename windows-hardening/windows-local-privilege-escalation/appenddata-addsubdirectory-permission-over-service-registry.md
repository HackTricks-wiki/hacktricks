<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


**La publicación original es** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Resumen

Se encontraron dos claves de registro que podían ser escritas por el usuario actual:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Se sugirió verificar los permisos del servicio **RpcEptMapper** utilizando la **interfaz gráfica de regedit**, específicamente la pestaña **Permisos efectivos** de la ventana **Configuración de seguridad avanzada**. Este enfoque permite evaluar los permisos otorgados a usuarios o grupos específicos sin necesidad de examinar cada Entrada de Control de Acceso (ACE) individualmente.

Se mostró una captura de pantalla de los permisos asignados a un usuario con privilegios bajos, entre los cuales destacaba el permiso **Crear subclave**. Este permiso, también conocido como **AppendData/AddSubdirectory**, coincide con los hallazgos del script.

Se observó la incapacidad de modificar ciertos valores directamente, pero la capacidad de crear nuevas subclaves. Se destacó un ejemplo de un intento de modificar el valor **ImagePath**, que resultó en un mensaje de acceso denegado.

A pesar de estas limitaciones, se identificó un potencial de escalada de privilegios a través de la posibilidad de aprovechar la subclave **Performance** dentro de la estructura de registro del servicio **RpcEptMapper**, una subclave que no está presente de forma predeterminada. Esto podría permitir el registro de DLL y el monitoreo del rendimiento.

Se consultó la documentación sobre la subclave **Performance** y su utilización para el monitoreo del rendimiento, lo que llevó al desarrollo de una DLL de prueba de concepto. Esta DLL, que demostraba la implementación de las funciones **OpenPerfData**, **CollectPerfData** y **ClosePerfData**, se probó a través de **rundll32**, confirmando su éxito operativo.

El objetivo era forzar al servicio **RPC Endpoint Mapper** a cargar la DLL de rendimiento creada. Las observaciones revelaron que la ejecución de consultas de clases WMI relacionadas con los Datos de Rendimiento a través de PowerShell resultó en la creación de un archivo de registro, lo que permitió la ejecución de código arbitrario bajo el contexto de **LOCAL SYSTEM**, otorgando así privilegios elevados.

Se destacó la persistencia y las posibles implicaciones de esta vulnerabilidad, resaltando su relevancia para estrategias de post-explotación, movimiento lateral y evasión de sistemas antivirus/EDR.

Aunque la vulnerabilidad se divulgó inicialmente de forma no intencional a través del script, se enfatizó que su explotación está limitada a versiones antiguas de Windows (por ejemplo, **Windows 7 / Server 2008 R2**) y requiere acceso local.

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

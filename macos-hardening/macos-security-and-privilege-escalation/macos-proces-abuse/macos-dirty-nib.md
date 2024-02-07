# macOS Dirty NIB

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Para más detalles sobre la técnica, consulta la publicación original en: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Aquí tienes un resumen:

Los archivos NIB, parte del ecosistema de desarrollo de Apple, están destinados a definir **elementos de interfaz de usuario** y sus interacciones en aplicaciones. Incluyen objetos serializados como ventanas y botones, y se cargan en tiempo de ejecución. A pesar de su uso continuo, Apple ahora recomienda Storyboards para una visualización más completa del flujo de la interfaz de usuario.

### Preocupaciones de Seguridad con Archivos NIB
Es crítico tener en cuenta que los **archivos NIB pueden ser un riesgo de seguridad**. Tienen el potencial de **ejecutar comandos arbitrarios**, y las alteraciones a los archivos NIB dentro de una aplicación no impiden que Gatekeeper ejecute la aplicación, lo que representa una amenaza significativa.

### Proceso de Inyección de Dirty NIB
#### Creación y Configuración de un Archivo NIB
1. **Configuración Inicial**:
- Crea un nuevo archivo NIB usando XCode.
- Agrega un objeto a la interfaz, configurando su clase como `NSAppleScript`.
- Configura la propiedad inicial `source` a través de Atributos de Tiempo de Ejecución Definidos por el Usuario.

2. **Gadget de Ejecución de Código**:
- La configuración facilita la ejecución de AppleScript a demanda.
- Integra un botón para activar el objeto `Apple Script`, activando específicamente el selector `executeAndReturnError:`.

3. **Pruebas**:
- Un simple Apple Script para propósitos de prueba:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Prueba ejecutando en el depurador de XCode y haciendo clic en el botón.

#### Apuntando a una Aplicación (Ejemplo: Pages)
1. **Preparación**:
- Copia la aplicación objetivo (por ejemplo, Pages) en un directorio separado (por ejemplo, `/tmp/`).
- Inicia la aplicación para evitar problemas con Gatekeeper y cachéala.

2. **Sobrescribiendo el Archivo NIB**:
- Reemplaza un archivo NIB existente (por ejemplo, Panel Acerca de NIB) con el archivo DirtyNIB creado.

3. **Ejecución**:
- Desencadena la ejecución interactuando con la aplicación (por ejemplo, seleccionando el elemento de menú `Acerca de`).

#### Prueba de Concepto: Accediendo a Datos de Usuario
- Modifica el AppleScript para acceder y extraer datos de usuario, como fotos, sin el consentimiento del usuario.

### Ejemplo de Código: Archivo .xib Malicioso
- Accede y revisa un [**ejemplo de un archivo .xib malicioso**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) que demuestra la ejecución de código arbitrario.

### Abordando Restricciones de Inicio
- Las Restricciones de Inicio impiden la ejecución de aplicaciones desde ubicaciones inesperadas (por ejemplo, `/tmp`).
- Es posible identificar aplicaciones no protegidas por Restricciones de Inicio y apuntarlas para la inyección de archivos NIB.

### Protecciones Adicionales de macOS
Desde macOS Sonoma en adelante, las modificaciones dentro de los paquetes de aplicaciones están restringidas. Sin embargo, métodos anteriores involucraban:
1. Copiar la aplicación a una ubicación diferente (por ejemplo, `/tmp/`).
2. Renombrar directorios dentro del paquete de la aplicación para evitar protecciones iniciales.
3. Después de ejecutar la aplicación para registrarse con Gatekeeper, modificar el paquete de la aplicación (por ejemplo, reemplazando MainMenu.nib con Dirty.nib).
4. Renombrar los directorios nuevamente y volver a ejecutar la aplicación para ejecutar el archivo NIB inyectado.

**Nota**: Actualizaciones recientes de macOS han mitigado esta vulnerabilidad al evitar modificaciones de archivos dentro de los paquetes de aplicaciones después de la caché de Gatekeeper, volviendo la vulnerabilidad ineficaz.

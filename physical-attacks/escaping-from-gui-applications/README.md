# Revisión de posibles acciones dentro de la aplicación GUI

Los **cuadros de diálogo comunes** son aquellas opciones de **guardar un archivo**, **abrir un archivo**, seleccionar una fuente, un color... La mayoría de ellos **ofrecerán una funcionalidad completa de Explorer**. Esto significa que podrás acceder a las funcionalidades de Explorer si puedes acceder a estas opciones:

* Cerrar/Cerrar como
* Abrir/Abrir con
* Imprimir
* Exportar/Importar
* Buscar
* Escanear

Deberías comprobar si puedes:

* Modificar o crear nuevos archivos
* Crear enlaces simbólicos
* Acceder a áreas restringidas
* Ejecutar otras aplicaciones

## Ejecución de comandos

Tal vez **usando una opción de **_**Abrir con**_** puedas abrir/ejecutar algún tipo de shell.

### Windows

Por ejemplo _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ encuentra más binarios que se pueden usar para ejecutar comandos (y realizar acciones inesperadas) aquí: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Más aquí: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Saltándose las restricciones de ruta

* **Variables de entorno**: Hay muchas variables de entorno que apuntan a alguna ruta
* **Otros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Enlaces simbólicos**
* **Atajos**: CTRL+N (abrir nueva sesión), CTRL+R (Ejecutar comandos), CTRL+SHIFT+ESC (Administrador de tareas),  Windows+E (abrir explorador), CTRL-B, CTRL-I (Favoritos), CTRL-H (Historial), CTRL-L, CTRL-O (Diálogo de archivo/abrir), CTRL-P (Diálogo de impresión), CTRL-S (Guardar como)
  * Menú administrativo oculto: CTRL-ALT-F8, CTRL-ESC-F9
* **URI de shell**: _shell:Herramientas administrativas, shell:Biblioteca de documentos, shell:Bibliotecas, shell:Perfiles de usuario, shell:Personal, shell:Carpeta de inicio de búsqueda, shell:Carpeta de lugares de red, shell:
### Atajos de Safari

| Atajo                   | Acción                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Comando-L)          | Abrir ubicación                                  |
| ⌘T                      | Abrir una nueva pestaña                          |
| ⌘W                      | Cerrar la pestaña actual                         |
| ⌘R                      | Actualizar la pestaña actual                     |
| ⌘.                      | Detener la carga de la pestaña actual            |
| ^⇥                      | Cambiar a la siguiente pestaña                   |
| ^⇧⇥ (Control-Shift-Tab) | Moverse a la pestaña anterior                     |
| ⌘L                      | Seleccionar el campo de entrada de texto/URL     |
| ⌘⇧T (Comando-Shift-T)   | Abrir la última pestaña cerrada (se puede usar varias veces) |
| ⌘\[                     | Retroceder una página en el historial de navegación |
| ⌘]                      | Avanzar una página en el historial de navegación |

### Atajos de Correo

| Atajo                   | Acción                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Abrir ubicación                |
| ⌘T                         | Abrir una nueva pestaña               |
| ⌘W                         | Cerrar la pestaña actual        |
| ⌘R                         | Actualizar la pestaña actual      |
| ⌘.                         | Detener la carga de la pestaña actual |
| ⌘⌥F (Comando-Option/Alt-F) | Buscar en tu buzón de correo       |

## Referencias

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

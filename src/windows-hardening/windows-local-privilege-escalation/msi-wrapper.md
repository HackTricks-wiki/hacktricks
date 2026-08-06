# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

Descarga la versión gratuita de la aplicación desde [https://www.exemsi.com/documentation/getting-started/](https://www.exemsi.com/download/), ejecútala y crea un wrapper del binario "**malicioso**".\
Ten en cuenta que puedes crear un wrapper de un archivo "**.bat**" si **solo** quieres **ejecutar** **líneas de comandos** (en lugar de cmd.exe, selecciona el archivo .bat).

![MSI Wrapper: Ten en cuenta que puedes crear un wrapper de un archivo " .bat " si solo quieres ejecutar líneas de comandos (en lugar de cmd.exe, selecciona el archivo .bat)](<../../images/image (417).png>)

Y esta es la parte más importante de la configuración:

![MSI Wrapper: Y esta es la parte más importante de la configuración](<../../images/image (312).png>)

![MSI Wrapper: Y esta es la parte más importante de la configuración](<../../images/image (346).png>)

![MSI Wrapper: Y esta es la parte más importante de la configuración](<../../images/image (1072).png>)

(Ten en cuenta que si intentas empaquetar tu propio binario, podrás modificar estos valores).

Desde aquí, simplemente haz clic en los **botones Next** y, por último, en el **botón Build**; se generará tu installer/wrapper.

{{#include ../../banners/hacktricks-training.md}}

# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper puede empaquetar un ejecutable o script como un archivo de Windows Installer (`.msi`). Descarga e inicia la edición gratuita y, a continuación, selecciona el ejecutable que quieres empaquetar.<sup>[[3]](#references)</sup> Para ejecutar una secuencia de comandos, selecciona un archivo `.bat` como entrada en lugar de empaquetar `cmd.exe`.<sup>[[1]](#references)</sup>

![Selección del ejecutable de origen o script por lotes en MSI Wrapper](<../../images/image (417).png>)

Configura cuidadosamente el contexto de ejecución y las demás propiedades del instalador:

![Configuración del ID de la aplicación y el contexto de seguridad en MSI Wrapper](<../../images/image (312).png>)

![Configuración de las propiedades del instalador en MSI Wrapper](<../../images/image (346).png>)

![Revisión de la configuración de compilación de MSI Wrapper](<../../images/image (1072).png>)

Estos valores se pueden cambiar al empaquetar un binario personalizado.

Continúa por las páginas restantes del asistente y selecciona **Build** para generar el instalador.<sup>[[1]](#references)</sup>

> [!WARNING]
> Crear un MSI no concede privilegios elevados por sí mismo. Que la instalación se ejecute con privilegios elevados depende de la directiva de Windows Installer, el contexto del paquete y la autorización del usuario. Microsoft advierte que habilitar `AlwaysInstallElevated` tanto para el usuario como para el equipo permite a los usuarios que no son administradores instalar paquetes con privilegios del sistema.<sup>[[2]](#references)</sup>

## References

- [1] [Documentación de MSI Wrapper - Primeros pasos](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Instalación de un paquete con privilegios elevados para un usuario que no es administrador](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Descarga](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}

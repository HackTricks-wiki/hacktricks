# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper puede empaquetar un ejecutable o script como un archivo de Windows Installer (`.msi`). Descarga e inicia la edición gratuita y, luego, selecciona el ejecutable que quieres empaquetar.<sup>[[3]](#references)</sup> Para ejecutar una secuencia de comandos, selecciona un archivo `.bat` como entrada en lugar de empaquetar `cmd.exe`.<sup>[[1]](#references)</sup>

![Seleccionar el ejecutable de origen o el script por lotes en MSI Wrapper](<../../images/image (417).png>)

Configura cuidadosamente el contexto de ejecución y otras propiedades del instalador:

![Configurar el ID de la aplicación y el contexto de seguridad en MSI Wrapper](<../../images/image (312).png>)

![Configurar las propiedades del instalador en MSI Wrapper](<../../images/image (346).png>)

![Revisar la configuración de compilación de MSI Wrapper](<../../images/image (1072).png>)

Estos valores se pueden cambiar al empaquetar un binario personalizado.

Continúa por las páginas restantes del asistente y selecciona **Build** para generar el instalador.<sup>[[1]](#references)</sup>

## Verificar el contexto de ejecución del comando empaquetado

Para crear un paquete de prueba, empaqueta un archivo `.bat` que registre su token, en lugar de asumir que la configuración de elevación del MSI se aplica a su proceso secundario.<sup>[[4]](#references)</sup> En el asistente, elige el contexto de seguridad **System** en lugar de **User** y selecciona una instalación por equipo con privilegios elevados si ese es el método previsto.<sup>[[5]](#references)</sup> La opción **System** no omite la autorización: un usuario que no sea administrador sigue necesitando una vía de instalación con privilegios elevados, como la [configuración incorrecta de las dos políticas `AlwaysInstallElevated`](index.html#alwaysinstallelevated) o un flujo de instalación privilegiado.<sup>[[2]](#references)</sup> Si eliges **User**, el comando empaquetado se ejecutará con el contexto del usuario que realiza la instalación, lo que puede ser necesario para acceder a recursos específicos del usuario o de la red.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Crea el MSI usando este archivo batch como entrada, luego ejecútalo en el host de prueba e inspecciona la identidad y los privilegios registrados.<sup>[[4]](#references)</sup> MSI Wrapper asigna el código de salida distinto de cero de un batch al error de instalación 1603, por lo que la salida explícita con cero evita un fallo falso después de una prueba exitosa.<sup>[[4]](#references)</sup> El archivo de salida es un artefacto de prueba; no deduzcas que se ejecutó como SYSTEM solo porque `msiexec` finalizó correctamente o la instalación se realizó en modo silencioso.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` silencia la interfaz de usuario de MSI, pero no necesariamente la interfaz propia del ejecutable incluido.<sup>[[6]](#references)[[7]](#references)</sup> Para un instalador incluido, configura sus argumentos silenciosos compatibles en el asistente; la propiedad dinámica `WRAPPED_ARGUMENTS` de MSI Wrapper es una función PRO.<sup>[[1]](#references)[[7]](#references)</sup> Consulta [el enfoque de acciones personalizadas de WiX](create-msi-with-wix.md) si necesitas controlar directamente la secuencia de acciones personalizadas y la suplantación.

> [!WARNING]
> Crear un MSI no otorga privilegios elevados por sí solo. Que la instalación se ejecute con privilegios elevados depende de la directiva de Windows Installer, el contexto del paquete y la autorización del usuario. Microsoft advierte que habilitar `AlwaysInstallElevated` tanto para el usuario como para el equipo permite a los usuarios que no son administradores instalar paquetes con privilegios de sistema.<sup>[[2]](#references)</sup>



## References

- [1] [Documentación de MSI Wrapper - Primeros pasos](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Instalar un paquete con privilegios elevados para un usuario que no es administrador](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Descargar](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Crear un MSI a partir de un archivo batch](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Páginas del asistente](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Opciones de línea de comandos](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Argumentos de línea de comandos](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}

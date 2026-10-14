# Bypasses de comprobación de acceso a archivos en modo kernel

{{#include ../../banners/hacktricks-training.md}}

## Patrón de driver vulnerable

Un driver no preserva el límite de seguridad de quien llama simplemente suplantándolo. Las aperturas de objetos en modo kernel normalmente omiten las comprobaciones de acceso. `OBJ_KERNEL_HANDLE` solo hace que el handle resultante sea accesible desde el modo kernel. Cuando un driver abre o manipula un objeto en nombre del modo usuario, también debe usar `OBJ_FORCE_ACCESS_CHECK` para que el Object Manager evalúe el acceso solicitado con el token efectivo.<sup>[[3]](#references)[[4]](#references)</sup>

Audita los IOCTL de manejo de archivos y las callbacks de creación para detectar esta secuencia:<sup>[[3]](#references)[[4]](#references)</sup>

1. El modo usuario proporciona una ruta, un handle de origen, el acceso deseado o el tipo de operación.
2. El driver suplanta al caller, pero llama a `IoCreateFileEx`, `ZwCreateFile` o una rutina similar sin `OBJ_FORCE_ACCESS_CHECK`.
3. Se guarda un handle de archivo o directorio exclusivo del kernel en el estado por handle.
4. Una operación posterior decide si suplanta al caller basándose en un estado influido por el atacante, como la máscara de acceso solicitada durante la primera apertura.
5. La rama privilegiada realiza un rename o un link con una clase de información `BypassAccessCheck`.

Esto es una **primitiva de archivo confused-deputy**, no necesariamente una corrupción de memoria. Una inversión de estado especialmente peligrosa es «si se solicita escritura, suplantar; si no, permanecer privilegiado». En ese diseño, solicitar deliberadamente solo acceso de lectura puede desbloquear la ruta más potente.<sup>[[3]](#references)</sup>

## Ejemplo de vSMB: root privilegiado más rename privilegiado

`storvsp.sys` implementa Virtual Server Message Block (vSMB). Cuando está habilitada la característica **Virtual Machine Platform**, el modo usuario puede acceder a `\Device\STORVSP` mediante `\\.\STORVSP`. Una ruta del sistema de archivos vSMB tiene la forma `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 y CVE-2025-64673 mostraron cómo dos decisiones de control de acceso incoherentes podían convertir esta interfaz en una escalada de privilegios local.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

La correspondencia entre las funciones del código fuente y los CVE se basa en ingeniería inversa del binario parcheado, no en el código fuente de Microsoft. Los investigadores advierten que los dos identificadores podrían corresponder a las funciones opuestas.<sup>[[3]](#references)</sup>

### 1. Crear un recurso compartido de solo lectura con raíz en un directorio protegido

La ruta de creación vulnerable registraba los derechos solicitados en flags persistentes como `HasReadAccess`, `HasWriteAccess` y `HasAppendAccess`. Después abría la ruta subyacente con `OBJ_KERNEL_HANDLE`, pero sin `OBJ_FORCE_ACCESS_CHECK`. Por lo tanto, el intento de suplantación no hacía que la apertura del archivo respetara los permisos NTFS del caller.<sup>[[3]](#references)[[4]](#references)</sup>

Solicita solo `FILE_READ_DATA`. Esto deja `HasWriteAccess` sin establecer y, aun así, obtiene un recurso compartido cuya raíz interna es un directorio protegido:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

El artefacto importante no es un identificador de directorio System32 en modo usuario. Es un identificador de dispositivo vSMB asociado con un estado del driver que contiene un identificador raíz privilegiado del kernel.<sup>[[3]](#references)</sup>

### 2. Convertir la discrepancia de estado en un reemplazo de archivos protegidos

El IOCTL `0x240330` aceptaba un identificador de archivo de origen, una clase de información y un búfer de información de longitud variable:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

El handler vulnerable aceptaba `FileRenameInformation`, `FileLinkInformation` y `FileRenameInformationEx`. Para una ruta de cambio de nombre normal, separaba la ruta del directorio principal del componente final y luego abría el directorio principal relativo al identificador raíz almacenado. Esa apertura también usaba `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` sin `OBJ_FORCE_ACCESS_CHECK`. Se rechazaba un `RootDirectory` distinto de cero proporcionado por el atacante dentro de la estructura de cambio de nombre, por lo que el driver proporcionaba su propio identificador de directorio privilegiado.<sup>[[3]](#references)</sup>

La rama explotable se seleccionaba **al no solicitar acceso de escritura durante la etapa 1**:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: suplantar el contexto de seguridad raíz guardado.
- `HasWriteAccess == 0`: omitir la suplantación y convertir `FileRenameInformation` o `FileRenameInformationEx` en su variante `BypassAccessCheck`.

El handler duplicaba el identificador de origen proporcionado por el atacante en `PsInitialSystemProcess`, lo referenciaba como un objeto de archivo, instalaba el identificador privilegiado del directorio de destino en la estructura de cambio de nombre y llamaba a `ZwSetInformationFile`. Con `ReplaceIfExists = TRUE`, un archivo controlado por quien llama podía reemplazar un archivo existente bajo la raíz protegida.<sup>[[3]](#references)</sup>

Al revisar un handler similar, rastrea **tanto la procedencia de los identificadores como el contexto de seguridad** en todas las ramas. La validación de entradas, las comprobaciones de desbordamiento de enteros, `IO_STOP_ON_SYMLINK` y la restricción de las clases de información aceptadas no compensan la combinación de un identificador de raíz privilegiado con una operación que omite la comprobación de acceso.<sup>[[3]](#references)</sup>

## De una escritura protegida a la ejecución como SYSTEM

Una primitiva de reemplazo de archivos protegidos permite ejecutar código cuando un proceso privilegiado carga posteriormente el módulo reemplazado. En la cadena demostrada, el destino era `C:\Windows\System32\wuapi.dll`. Activar la clase COM de servidor local `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` para la interfaz `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` y llamar a `IWaaSRemediation::LaunchDetectionOnly()` hacía que un proceso SYSTEM cargara esa DLL.<sup>[[3]](#references)</sup>

Esta llamada COM es un **activador**, no un [secuestro del registro COM](com-hijacking.md). La primitiva de archivos proporciona el módulo colocado y el cargador privilegiado proporciona la ejecución. Para otras cadenas de escritura protegida, identifica la imagen exacta, la ruta de la DLL, la política de firmas, la arquitectura, las funciones exportadas y un activador fiable antes de elegir un objetivo. Consulta [encadenar una escritura arbitraria de archivos con el secuestro de una DLL](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) para conocer el flujo de trabajo general de análisis del cargador.<sup>[[3]](#references)</sup>

### Mover un token de Session 0 al escritorio interactivo

Una carga útil cargada por un servicio normalmente se ejecuta en Session 0. Para crear un proceso interactivo, puede obtener la sesión de consola activa con `WTSGetActiveConsoleSessionId`, habilitar los privilegios de token necesarios, duplicar el token SYSTEM actual como token principal y establecer su `TokenSessionId` en la sesión activa. Luego, `CreateProcessAsUserW` usa ese token con `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` es necesario para establecer el ID de sesión de un token en este escenario. La estación de ventanas interactiva y el escritorio también deben conceder acceso al token. Consulta [duplicación de tokens desde la Session 0](sedebug-+-seimpersonate-copy-token.md) para conocer el flujo de trabajo más amplio de copia de tokens.<sup>[[3]](#references)[[5]](#references)</sup>

## Guía de revisión y parches

Las actualizaciones de Microsoft de diciembre de 2025 corrigieron la cadena demostrada. La ingeniería inversa descubrió que la ruta de creación de vSMB con el parche aplicado rechaza a los llamadores no confiables que solicitan una raíz de recurso compartido sin `FILE_WRITE_DATA`. Las operaciones pertinentes también incorporaron la comprobación de acceso forzada. Esto bloquea la inversión de estado antes de que un llamador sin privilegios pueda obtener la raíz privilegiada.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Para el código de los controladores, aplica estas reglas:<sup>[[3]](#references)[[4]](#references)</sup>

- Añade `OBJ_FORCE_ACCESS_CHECK` siempre que se abra un objeto en nombre de una solicitud de modo usuario. No trates `OBJ_KERNEL_HANDLE` como un control de autorización.<sup>[[4]](#references)</sup>
- Captura y valida el modo del solicitante y el contexto efectivo del sujeto. No permitas que los derechos solicitados seleccionen una rama de ejecución con más privilegios.
- Valida los handles de usuario con el tipo de objeto, la máscara de acceso y `UserMode` correctos. Duplicar un handle en el proceso del sistema no valida la autoridad de la operación solicitada.
- Mantén la resolución del destino relativa a un handle de confianza, pero asegúrate de que ese handle se haya abierto con la comprobación de acceso exigida para el solicitante.
- Evita las clases `File*BypassAccessCheck` en operaciones iniciadas por el usuario. Si el código interno realmente las necesita, restringe esa ruta mediante una decisión de autorización independiente de los indicadores de acceso controlados por el usuario.
- Aplica los parches a los sistemas afectados. La superficie vulnerable es relevante cuando Virtual Machine Platform carga `storvsp.sys`.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - De recurso compartido virtual a shell físico: aprovechar el control de acceso inconsistente de Windows para LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Handles de objetos](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - Función CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}

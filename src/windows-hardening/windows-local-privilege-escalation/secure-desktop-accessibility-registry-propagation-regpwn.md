# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Las funciones de Accessibility de Windows conservan la configuración del usuario en HKCU y la propagan a ubicaciones HKLM por sesión. Durante una transición a **Secure Desktop** (pantalla de bloqueo o aviso de UAC), los componentes de **SYSTEM** vuelven a copiar estos valores. Si la **clave HKLM por sesión es modificable por el usuario**, se convierte en un punto de escritura privilegiado que puede redirigirse mediante **enlaces simbólicos del registro**, lo que permite una **escritura arbitraria en el registro como SYSTEM**.<sup>[[1]](#references)</sup>

La técnica RegPwn abusa de esta cadena de propagación mediante una pequeña ventana de race condition, estabilizada con un **opportunistic lock (oplock)** en un archivo utilizado por `osk.exe`.<sup>[[1]](#references)</sup>

## Cadena de propagación del registro (Accessibility -> Secure Desktop)

Ejemplo de función: **On-Screen Keyboard** (`osk`). Las ubicaciones relevantes son:

- **Lista de funciones de todo el sistema**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Configuración por usuario (modificable por el usuario)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Configuración HKLM por sesión (creada por `winlogon.exe`, modificable por el usuario)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Hive del usuario predeterminado/Secure Desktop (contexto SYSTEM)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagación durante una transición a Secure Desktop (simplificada):

1. El `atbroker.exe` del **usuario** copia `HKCU\...\ATConfig\osk` en `HKLM\...\Session<session id>\ATConfig\osk`.
2. El `atbroker.exe` de **SYSTEM** copia `HKLM\...\Session<session id>\ATConfig\osk` en `HKU\.DEFAULT\...\ATConfig\osk`.
3. El `osk.exe` de **SYSTEM** copia `HKU\.DEFAULT\...\ATConfig\osk` de vuelta a `HKLM\...\Session<session id>\ATConfig\osk`.

Si el subárbol HKLM de la sesión es modificable por el usuario, los pasos 2/3 proporcionan una escritura como SYSTEM a través de una ubicación que el usuario puede reemplazar.<sup>[[1]](#references)</sup>

## Primitiva: escritura arbitraria en el registro como SYSTEM mediante enlaces del registro

Reemplaza la clave por sesión modificable por el usuario con un **enlace simbólico del registro** que apunte a un destino elegido por el atacante. Cuando se produce la copia como SYSTEM, sigue el enlace y escribe valores controlados por el atacante en la clave de destino arbitraria.

Idea principal:

- Destino de escritura de la víctima (modificable por el usuario):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- El atacante reemplaza esa clave con un **enlace del registro** hacia cualquier otra clave.
- SYSTEM realiza la copia y escribe en la clave elegida por el atacante con permisos de SYSTEM.

Esto proporciona una primitiva de **escritura arbitraria en el registro como SYSTEM**.<sup>[[1]](#references)</sup>

## Ganar la ventana de race condition con Oplocks

Existe una breve ventana temporal entre el inicio de **`osk.exe` como SYSTEM** y la escritura de la clave por sesión. Para hacerla fiable, el exploit coloca un **oplock** en:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Cuando se activa el oplock, el atacante intercambia la clave HKLM por sesión por un enlace del registro, permite que se complete la escritura de SYSTEM y luego elimina el enlace.<sup>[[1]](#references)</sup>

## Flujo de explotación de ejemplo (alto nivel)

1. Obtener el **ID de sesión** actual del token de acceso.
2. Iniciar una instancia oculta de `osk.exe` y esperar brevemente (para garantizar que el oplock se active).
3. Escribir valores controlados por el atacante en:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Establecer un **oplock** en `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Activar **Secure Desktop** (`LockWorkstation()`), lo que hace que SYSTEM inicie `atbroker.exe` / `osk.exe`.
6. Cuando se active el oplock, reemplazar `HKLM\...\Session<session id>\ATConfig\osk` por un **enlace del registro** a un destino arbitrario.
7. Esperar brevemente a que se complete la copia de SYSTEM y, después, eliminar el enlace.<sup>[[1]](#references)</sup>

## Convertir la primitiva en ejecución como SYSTEM

Una cadena sencilla consiste en sobrescribir un valor de **configuración de servicio** (por ejemplo, `ImagePath`) y después iniciar el servicio. El PoC de RegPwn sobrescribe `ImagePath` de **`msiserver`** y lo activa mediante la instanciación del **objeto COM de MSI**, lo que da como resultado la ejecución de código como **SYSTEM**.<sup>[[1]](#references)[[2]](#references)</sup>

## Relacionado

Para consultar otros comportamientos de Secure Desktop / UIAccess, véase:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Referencias

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}

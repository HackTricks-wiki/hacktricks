# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Las características de Accessibility de Windows guardan la configuración de usuario bajo HKCU y la propagan a ubicaciones HKLM por sesión. Durante una transición de **Secure Desktop** (pantalla de bloqueo o el aviso de UAC), los componentes **SYSTEM** vuelven a copiar estos valores. Si la **clave HKLM por sesión es escribible por el usuario**, se convierte en un punto de estrangulamiento privilegiado para escrituras que puede ser redirigido con **enlaces simbólicos del registro**, produciendo una **escritura arbitraria en el registro con permisos SYSTEM**.

La técnica RegPwn abusa de esa cadena de propagación explotando una pequeña ventana de carrera, estabilizada mediante un **opportunistic lock (oplock)** en un archivo usado por `osk.exe`.

## Cadena de propagación del registro (Accessibility -> Secure Desktop)

Ejemplo de función: **On-Screen Keyboard** (`osk`). Las ubicaciones relevantes son:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Hive de usuario predeterminado/Secure Desktop (contexto SYSTEM)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagación durante una transición de Secure Desktop (simplificado):

1. **User `atbroker.exe`** copia `HKCU\...\ATConfig\osk` a `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** copia `HKLM\...\Session<session id>\ATConfig\osk` a `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** copia `HKU\.DEFAULT\...\ATConfig\osk` de vuelta a `HKLM\...\Session<session id>\ATConfig\osk`.

Si el subárbol HKLM de la sesión es escribible por el usuario, los pasos 2/3 proporcionan una escritura con permisos SYSTEM a través de una ubicación que el usuario puede reemplazar.

## Primitiva: Escritura arbitraria en el registro con permisos SYSTEM mediante enlaces simbólicos del registro

Reemplaza la clave por sesión escribible por el usuario con un **enlace simbólico del registro** que apunte a un destino elegido por el atacante. Cuando ocurre la copia por parte de SYSTEM, sigue el enlace y escribe valores controlados por el atacante en la clave objetivo arbitraria.

Idea clave:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- El atacante reemplaza esa clave por un **enlace simbólico del registro** a cualquier otra clave.
- SYSTEM realiza la copia y escribe en la clave elegida por el atacante con permisos SYSTEM.

Esto da lugar a una primitiva de **escritura arbitraria en el registro con permisos SYSTEM**.

## Ganando la ventana de carrera con Oplocks

Hay una breve ventana temporal entre el inicio de **SYSTEM `osk.exe`** y la escritura de la clave por sesión. Para hacerlo fiable, el exploit coloca un **oplock** en:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Cuando el oplock se activa, el atacante intercambia la clave HKLM por sesión por un enlace de registro, permite que SYSTEM escriba y luego elimina el enlace.

## Flujo de explotación de ejemplo (visión general)

1. Obtener el **session ID** actual del token de acceso.
2. Iniciar una instancia oculta de `osk.exe` y dormir brevemente (asegurar que el oplock se activará).
3. Escribir valores controlados por el atacante en:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Establecer un **oplock** en `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Provocar **Secure Desktop** (`LockWorkstation()`), causando que SYSTEM `atbroker.exe` / `osk.exe` se inicien.
6. Al activarse el oplock, reemplazar `HKLM\...\Session<session id>\ATConfig\osk` con un **enlace de registro** a un objetivo arbitrario.
7. Esperar brevemente a que la copia realizada por SYSTEM se complete, luego eliminar el enlace.

## Convertir el primitivo a ejecución SYSTEM

Una cadena sencilla es sobrescribir un valor de **service configuration** (p. ej., `ImagePath`) y luego iniciar el servicio. El RegPwn PoC sobrescribe el `ImagePath` de **`msiserver`** y lo desencadena instanciando el **MSI COM object**, resultando en ejecución de código con **SYSTEM**.

## Relacionado

Para otros comportamientos de Secure Desktop / UIAccess, vea:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Referencias

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}

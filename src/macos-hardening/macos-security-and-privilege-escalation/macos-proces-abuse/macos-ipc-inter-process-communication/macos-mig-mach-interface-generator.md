# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Información Básica

MIG fue creado para **simplificar el proceso de creación de código Mach IPC**. Básicamente **genera el código necesario** para que el servidor y el cliente se comuniquen con una definición dada. Aunque el código generado es feo, un desarrollador solo necesitará importarlo y su código será mucho más simple que antes.

La definición se especifica en el Lenguaje de Definición de Interfaces (IDL) utilizando la extensión `.defs`.

Estas definiciones tienen 5 secciones:

- **Declaración de subsistema**: La palabra clave subsistema se utiliza para indicar el **nombre** y el **id**. También es posible marcarlo como **`KernelServer`** si el servidor debe ejecutarse en el kernel.
- **Inclusiones e importaciones**: MIG utiliza el preprocesador C, por lo que puede usar importaciones. Además, es posible usar `uimport` y `simport` para código generado por el usuario o el servidor.
- **Declaraciones de tipo**: Es posible definir tipos de datos aunque generalmente importará `mach_types.defs` y `std_types.defs`. Para los personalizados se puede usar alguna sintaxis:
- \[i`n/out]tran`: Función que necesita ser traducida de un mensaje entrante o a un mensaje saliente
- `c[user/server]type`: Mapeo a otro tipo C.
- `destructor`: Llama a esta función cuando el tipo es liberado.
- **Operaciones**: Estas son las definiciones de los métodos RPC. Hay 5 tipos diferentes:
- `routine`: Espera respuesta
- `simpleroutine`: No espera respuesta
- `procedure`: Espera respuesta
- `simpleprocedure`: No espera respuesta
- `function`: Espera respuesta

### Ejemplo

Crea un archivo de definición, en este caso con una función muy simple:
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
Tenga en cuenta que el primer **argumento es el puerto a enlazar** y MIG **manejará automáticamente el puerto de respuesta** (a menos que se llame a `mig_get_reply_port()` en el código del cliente). Además, el **ID de las operaciones** será **secuencial** comenzando por el ID del subsistema indicado (así que si una operación está obsoleta, se elimina y se usa `skip` para seguir utilizando su ID).

Ahora use MIG para generar el código del servidor y del cliente que podrá comunicarse entre sí para llamar a la función Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Se crearán varios archivos nuevos en el directorio actual.

> [!TIP]
> Puedes encontrar un ejemplo más complejo en tu sistema con: `mdfind mach_port.defs`\
> Y puedes compilarlo desde la misma carpeta que el archivo con: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

En los archivos **`myipcServer.c`** y **`myipcServer.h`** puedes encontrar la declaración y definición de la estructura **`SERVERPREFmyipc_subsystem`**, que básicamente define la función a llamar según el ID del mensaje recibido (indicamos un número inicial de 500):

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

Basado en la estructura anterior, la función **`myipc_server_routine`** obtendrá el **ID del mensaje** y devolverá la función adecuada a llamar:
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
En este ejemplo, solo hemos definido 1 función en las definiciones, pero si hubiéramos definido más funciones, estarían dentro del array de **`SERVERPREFmyipc_subsystem`** y la primera se habría asignado al ID **500**, la segunda al ID **501**...

Si se esperaba que la función enviara una **respuesta**, la función `mig_internal kern_return_t __MIG_check__Reply__<name>` también existiría.

De hecho, es posible identificar esta relación en la estructura **`subsystem_to_name_map_myipc`** de **`myipcServer.h`** (**`subsystem*to_name_map*\***`\*\* en otros archivos):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Finalmente, otra función importante para hacer que el servidor funcione será **`myipc_server`**, que es la que realmente **llamará a la función** relacionada con el id recibido:

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
/* Tamaño mínimo: routine() lo actualizará si es diferente */
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

Verifique las líneas resaltadas anteriormente que acceden a la función para llamar por ID.

El siguiente es el código para crear un **servidor** y un **cliente** simples donde el cliente puede llamar a las funciones Subtract del servidor:

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

El NDR_record es exportado por `libsystem_kernel.dylib`, y es una estructura que permite a MIG **transformar datos para que sea agnóstico del sistema** en el que se está utilizando, ya que se pensó que MIG se usaría entre diferentes sistemas (y no solo en la misma máquina).

Esto es interesante porque si se encuentra `_NDR_record` en un binario como una dependencia (`jtool2 -S <binary> | grep NDR` o `nm`), significa que el binario es un cliente o servidor MIG.

Además, los **servidores MIG** tienen la tabla de despacho en `__DATA.__const` (o en `__CONST.__constdata` en el núcleo de macOS y `__DATA_CONST.__const` en otros núcleos \*OS). Esto se puede volcar con **`jtool2`**.

Y los **clientes MIG** usarán el `__NDR_record` para enviar con `__mach_msg` a los servidores.

## Análisis de Binarios

### jtool

Como muchos binarios ahora utilizan MIG para exponer puertos mach, es interesante saber cómo **identificar que se utilizó MIG** y las **funciones que MIG ejecuta** con cada ID de mensaje.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) puede analizar información de MIG de un binario Mach-O indicando el ID de mensaje e identificando la función a ejecutar:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Además, las funciones MIG son solo envolturas de la función real que se llama, lo que significa que al obtener su desensamblado y buscar BL, es posible que puedas encontrar la función real que se está llamando:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Se mencionó anteriormente que la función que se encargará de **llamar a la función correcta dependiendo del ID de mensaje recibido** era `myipc_server`. Sin embargo, generalmente no tendrás los símbolos del binario (sin nombres de funciones), por lo que es interesante **ver cómo se ve decompilado** ya que siempre será muy similar (el código de esta función es independiente de las funciones expuestas):

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Instrucciones iniciales para encontrar los punteros de función adecuados
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Llamada a sign_extend_64 que puede ayudar a identificar esta función
// Esto almacena en rax el puntero a la llamada que necesita ser llamada
// Ver el uso de la dirección 0x100004040 (array de direcciones de funciones)
// 0x1f4 = 500 (el ID de inicio)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, el if devuelve falso, mientras que el else llama a la función correcta y devuelve verdadero
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Dirección calculada que llama a la función adecuada con 2 argumentos
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
Esta es la misma función decompilada en una versión diferente de Hopper free:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Instrucciones iniciales para encontrar los punteros de función adecuados
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
// 0x1f4 = 500 (el ID de inicio)
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
// Mismo if else que en la versión anterior
// Ver el uso de la dirección 0x100004040 (array de direcciones de funciones)
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Llamada a la dirección calculada donde debería estar la función
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

En realidad, si vas a la función **`0x100004000`** encontrarás el array de **`routine_descriptor`** structs. El primer elemento de la struct es la **dirección** donde se implementa la **función**, y la **struct ocupa 0x28 bytes**, así que cada 0x28 bytes (comenzando desde el byte 0) puedes obtener 8 bytes y esa será la **dirección de la función** que será llamada:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Estos datos pueden ser extraídos [**usando este script de Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

El código generado por MIG también llama a `kernel_debug` para generar registros sobre operaciones de entrada y salida. Es posible revisarlos usando **`trace`** o **`kdv`**: `kdv all | grep MIG`

## References

- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}

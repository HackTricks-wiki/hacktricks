# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Informações básicas

O MIG foi criado para **simplificar o processo de criação de código para Mach IPC**. Ele basicamente **gera o código necessário** para que o server e o client se comuniquem com base em uma determinada definição. Mesmo que o código gerado seja confuso, um developer só precisará importá-lo, e seu código será muito mais simples do que antes.<sup>[[1]](#references)</sup>

A definição é especificada em Interface Definition Language (IDL), usando a extensão `.defs`.

Essas definições têm 5 seções:

- **Declaração do subsystem**: A palavra-chave subsystem é usada para indicar o **nome** e o **id**. Também é possível marcá-lo como **`KernelServer`** se o server precisar ser executado no kernel.<sup>[[4]](#references)</sup>
- **Inclusões e imports**: O MIG usa o pré-processador C, portanto é capaz de usar imports. Além disso, é possível usar `uimport` e `simport` para o código gerado do user ou do server.
- **Declarações de tipos**: É possível definir tipos de dados, embora normalmente sejam importados `mach_types.defs` e `std_types.defs`. Para tipos personalizados, é possível usar algumas sintaxes:
- \[i`n/out]tran`: Função que precisa ser traduzida a partir de uma mensagem recebida ou para uma mensagem enviada
- `c[user/server]type`: Mapeamento para outro tipo C.
- `destructor`: Chama essa função quando o tipo é liberado.
- **Operações**: Estas são as definições dos métodos RPC. Existem 5 tipos diferentes:
- `routine`: Espera uma resposta
- `simpleroutine`: Não espera uma resposta
- `procedure`: Espera uma resposta
- `simpleprocedure`: Não espera uma resposta
- `function`: Espera uma resposta

### Exemplo

Crie um arquivo de definição, neste caso com uma função muito simples:
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
Observe que o primeiro **argumento é a porta à qual fazer bind** e o MIG **gerenciará automaticamente a porta de resposta** (a menos que `mig_get_reply_port()` seja chamado no código do client). Além disso, os **IDs das operações** serão **sequenciais**, começando pelo ID do subsystem indicado (portanto, se uma operação for deprecated, ela será excluída e `skip` será usado para continuar usando seu ID).

Agora use o MIG para gerar o código do server e do client que poderá se comunicar internamente para chamar a função Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Vários arquivos novos serão criados no diretório atual.

> [!TIP]
> Você pode encontrar um exemplo mais complexo no sistema com: `mdfind mach_port.defs`\
> E pode compilá-lo na mesma pasta do arquivo com: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

Nos arquivos **`myipcServer.c`** e **`myipcServer.h`**, você pode encontrar a declaração e a definição da struct **`SERVERPREFmyipc_subsystem`**, que basicamente define a função a ser chamada com base no ID da mensagem recebida (indicamos um número inicial de 500):

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

Com base na struct anterior, a função **`myipc_server_routine`** obterá o **message ID** e retornará a função apropriada a ser chamada:
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
Neste exemplo, definimos apenas 1 função nas definições, mas, se tivéssemos definido mais funções, elas estariam dentro do array de **`SERVERPREFmyipc_subsystem`**, e a primeira teria recebido o ID **500**, a segunda, o ID **501**...

Se fosse esperado que a função enviasse uma **reply**, a função `mig_internal kern_return_t __MIG_check__Reply__<name>` também existiria.

Na verdade, é possível identificar essa relação na struct **`subsystem_to_name_map_myipc`** de **`myipcServer.h`** (**`subsystem*to_name_map*\***`** em outros arquivos):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Finalmente, outra função importante para fazer o servidor funcionar será **`myipc_server`**, que é a função que realmente **chamará a função** relacionada ao id recebido:<sup>[[3]](#references)</sup>

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

Verifique as linhas destacadas anteriormente que acessam a função a ser chamada pelo ID.

A seguir está o código para criar um **servidor** e um **cliente** simples, no qual o cliente pode chamar as funções Subtract do servidor:

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

### The NDR_record

O NDR_record é exportado por `libsystem_kernel.dylib` e é uma struct que permite ao MIG **transformar dados para que sejam agnósticos ao sistema** em que estão sendo usados, pois o MIG foi projetado para ser usado entre sistemas diferentes (e não apenas na mesma máquina).

Isso é interessante porque, se `_NDR_record` for encontrado em um binário como uma dependência (`jtool2 -S <binary> | grep NDR` ou `nm`), significa que o binário é um cliente ou Server MIG.

Além disso, **MIG servers** têm a dispatch table em `__DATA.__const` (ou em `__CONST.__constdata` no macOS kernel e em `__DATA_CONST.__const` em outros kernels \*OS). Isso pode ser extraído com o **`jtool2`**.

E **MIG clients** usarão o `__NDR_record` para enviar mensagens com `__mach_msg` aos servers.

## Binary Analysis

### jtool

Como muitos binários agora usam MIG para expor mach ports, é interessante saber como **identificar que o MIG foi usado** e as **funções que o MIG executa** com cada message ID.

O [**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) pode analisar informações do MIG a partir de um binário Mach-O, indicando o message ID e identificando a função a ser executada:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Além disso, as funções MIG são wrappers em torno da função real que é chamada. Portanto, ao obter o disassembly e procurar por `BL`, você poderá encontrar a função real que está sendo chamada:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Foi mencionado anteriormente que a função responsável por **chamar a função correta dependendo do message ID recebido** era `myipc_server`. No entanto, normalmente você não terá os símbolos do binary (nomes das funções), portanto é interessante **ver como ela aparece decompilada**, pois será sempre muito semelhante (o código dessa função é independente das funções expostas):

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
Esta é a mesma função decompilada em uma versão free diferente do Hopper:

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

Na prática, se você acessar a função **`0x100004000`**, encontrará o array de structs **`routine_descriptor`**. O primeiro elemento da struct é o **endereço** onde a **função** está implementada, e a **struct ocupa 0x28 bytes**. Assim, a cada 0x28 bytes (começando no byte 0), você pode obter 8 bytes, que serão o **endereço da função** a ser chamada:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Esses dados podem ser extraídos [**usando este script do Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

O código gerado pelo MIG também chama `kernel_debug` para gerar logs sobre as operações de entrada e saída. É possível inspecioná-los usando **`trace`** ou **`kdv`**: `kdv all | grep MIG`

## References

- [1] [bootstrap_cmds — `migcom.tproj` (o próprio compilador MIG)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (exemplo de definição de subsystem MIG)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (layout do header de mensagem Mach)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (definição MIG do subsystem de task)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}

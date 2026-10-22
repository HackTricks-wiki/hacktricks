# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Εκτέλεση payload σε εικονικοποιημένα Windows

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

Για να κάνετε έναν τοπικό listener προσβάσιμο μέσω internet, δείτε [επιλογές για δημόσια HTTP και TCP tunnels](../expose-local-to-the-internet.md).

---

## Εργαλεία shell αυτόματης δημιουργίας

Πολλά βοηθητικά εργαλεία web και γραμμής εντολών μπορούν να δημιουργούν payloads bind και reverse shell για διαφορετικούς interpreters και λειτουργικά συστήματα:

- Τα **reverse-shell.sh** και **revshells.com** παρέχουν generators payloads μέσω browser.<sup>[[1]](#references)[[2]](#references)</sup>
- Τα **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** και **rsg** δημιουργούν payloads μέσω της γραμμής εντολών ή ενός τοπικού interface.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Το **xc** είναι ένα μικρό cross-platform reverse shell για Linux και Windows.<sup>[[7]](#references)</sup>
- Το **pyminifier** δεν είναι generator shell, αλλά μπορεί να κάνει minify ή obfuscate Python payloads όταν αυτή η μετατροπή είναι χρήσιμη.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Δημιουργός reverse shell](https://reverse-shell.sh/)
- [2] [revshells.com - Δημιουργός reverse shell](https://www.revshells.com/)
- [3] [Shellerator - Εργαλείο CLI για τη δημιουργία bind και reverse shells σε πολλές γλώσσες](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Εκτέλεσε shells σαν μάστορας](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Δημιουργός reverse shell για python, perl, ruby, bash, netcat, php, java, powershell κ.λπ.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Minifier/obfuscator κώδικα Python](https://liftoff.github.io/pyminifier/)
- [7] [xc - Μικρό reverse shell για Linux και Windows](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Δημιουργός reverse shell γραμμένος σε Python 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Εργαλείο για τη δημιουργία διάφορων τρόπων εκτέλεσης reverse shell](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}

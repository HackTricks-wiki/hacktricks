# Linux-Grundlagen

{{#include ../../banners/hacktricks-training.md}}

Dies ist der Ausgangspunkt für die Prüfung von Linux-Hosts. Die Seiten behandeln einen umfassenden Workflow zur privilege escalation, praktische Befehle, Umgebungsvariablen und häufige Einschränkungen, die beeinflussen, was auf einem Host ausgeführt werden kann.

- [Linux privilege escalation](linux-privilege-escalation/README.md) führt durch die Enumeration und mögliche lokale Eskalationspfade. Eine kürzere Aufgabenliste findest du in der [Checkliste zur privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
- [Shell-Start, Aliase und Verlauf](shell-startup-aliases-and-history.md) erklärt die Befehlsauflösung, die Ausführung von Startdateien und Hinweise im Verlauf.
- [Nützliche Linux-Befehle](useful-linux-commands.md) enthält Befehle zur Untersuchung von Dateien, Prozessen, Diensten und der Umgebung.
- [Linux-Umgebungsvariablen](linux-environment-variables.md) erklärt, wie Umgebungswerte die Ausführung beeinflussen und wo sensible Werte auftauchen können.
- [Linux-Einschränkungen umgehen](bypass-linux-restrictions/README.md) behandelt eingeschränkte Shells und Ausführungsumgebungen, einschließlich Dateisystemschutz, `noexec` und distroless-Systemen.

## Native Binary Exploitation

Wenn eine Prüfung zu einer verwundbaren ausführbaren Linux-Datei führt, nutze die relevanten Inhalte unter Binary Exploitation:

- [ELF-Format und Loader-Verhalten](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) und [Binary-Schutzmechanismen und Bypasses](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) erklären das Layout ausführbarer Dateien und deren Schutzmaßnahmen.
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) und [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) behandeln Control-Flow-Angriffe.
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) und [format strings](../../binary-exploitation/format-strings/README.md) behandeln weitere gängige Wege zur Ausnutzung von Speicherfehlern.

Fallstudien zu Kernel-spezifischen Themen sind unter [Material zu Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md) verlinkt.
{{#include ../../banners/hacktricks-training.md}}

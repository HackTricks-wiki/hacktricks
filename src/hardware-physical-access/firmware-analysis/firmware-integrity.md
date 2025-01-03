{{#include ../../banners/hacktricks-training.md}}

## Firmware-Integrität

Die **benutzerdefinierte Firmware und/oder kompilierten Binärdateien können hochgeladen werden, um Integritäts- oder Signaturüberprüfungsfehler auszunutzen**. Die folgenden Schritte können für die Kompilierung eines Backdoor-Bind-Shells befolgt werden:

1. Die Firmware kann mit firmware-mod-kit (FMK) extrahiert werden.
2. Die Ziel-Firmware-Architektur und Endianness sollten identifiziert werden.
3. Ein Cross-Compiler kann mit Buildroot oder anderen geeigneten Methoden für die Umgebung erstellt werden.
4. Die Backdoor kann mit dem Cross-Compiler erstellt werden.
5. Die Backdoor kann in das extrahierte Firmware-Verzeichnis /usr/bin kopiert werden.
6. Die geeignete QEMU-Binärdatei kann in das extrahierte Firmware-Rootfs kopiert werden.
7. Die Backdoor kann mit chroot und QEMU emuliert werden.
8. Die Backdoor kann über netcat erreicht werden.
9. Die QEMU-Binärdatei sollte aus dem extrahierten Firmware-Rootfs entfernt werden.
10. Die modifizierte Firmware kann mit FMK neu verpackt werden.
11. Die mit einer Backdoor versehene Firmware kann getestet werden, indem sie mit dem Firmware-Analyse-Toolkit (FAT) emuliert und eine Verbindung zur Ziel-Backdoor-IP und dem Port über netcat hergestellt wird.

Wenn bereits über dynamische Analyse, Bootloader-Manipulation oder Hardware-Sicherheitstests eine Root-Shell erlangt wurde, können vorkompilierte bösartige Binärdateien wie Implantate oder Reverse-Shells ausgeführt werden. Automatisierte Payload/Implant-Tools wie das Metasploit-Framework und 'msfvenom' können mit den folgenden Schritten genutzt werden:

1. Die Ziel-Firmware-Architektur und Endianness sollten identifiziert werden.
2. Msfvenom kann verwendet werden, um die Ziel-Payload, die IP des Angreifers, die hörende Portnummer, den Dateityp, die Architektur, die Plattform und die Ausgabedatei anzugeben.
3. Die Payload kann auf das kompromittierte Gerät übertragen werden, und es sollte sichergestellt werden, dass sie Ausführungsberechtigungen hat.
4. Metasploit kann vorbereitet werden, um eingehende Anfragen zu bearbeiten, indem msfconsole gestartet und die Einstellungen gemäß der Payload konfiguriert werden.
5. Die Meterpreter-Reverse-Shell kann auf dem kompromittierten Gerät ausgeführt werden.

{{#include ../../banners/hacktricks-training.md}}

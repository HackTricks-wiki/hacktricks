{{#include ../../banners/hacktricks-training.md}}

# Identifizierung gepackter Binaries

- **Mangel an Strings**: Es ist üblich, dass gepackte Binaries fast keine Strings haben.
- Viele **ungenutzte Strings**: Wenn Malware eine Art kommerziellen Packers verwendet, ist es auch üblich, viele Strings ohne Querverweise zu finden. Selbst wenn diese Strings existieren, bedeutet das nicht, dass die Binary nicht gepackt ist.
- Sie können auch einige Tools verwenden, um zu versuchen herauszufinden, welcher Packer verwendet wurde, um eine Binary zu packen:
- [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
- [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
- [Language 2000](http://farrokhi.net/language/)

# Grundlegende Empfehlungen

- **Beginnen** Sie mit der Analyse der gepackten Binary **von unten in IDA und bewegen Sie sich nach oben**. Unpacker beenden, sobald der entpackte Code endet, daher ist es unwahrscheinlich, dass der Unpacker die Ausführung zu Beginn an den entpackten Code übergibt.
- Suchen Sie nach **JMP's** oder **CALLs** zu **Registern** oder **Speicherbereichen**. Suchen Sie auch nach **Funktionen, die Argumente und eine Adressrichtung pushen und dann `retn` aufrufen**, da die Rückkehr der Funktion in diesem Fall die Adresse aufrufen kann, die zuvor auf den Stack gepusht wurde.
- Setzen Sie einen **Breakpoint** auf `VirtualAlloc`, da dies Speicher im Speicher allokiert, in dem das Programm entpackten Code schreiben kann. "Run to user code" oder verwenden Sie F8, um **den Wert in EAX zu erhalten**, nachdem Sie die Funktion ausgeführt haben, und "**folgen Sie dieser Adresse im Dump**". Sie wissen nie, ob dies der Bereich ist, in dem der entpackte Code gespeichert wird.
- **`VirtualAlloc`** mit dem Wert "**40**" als Argument bedeutet Lesen+Schreiben+Ausführen (einige Code, der ausgeführt werden muss, wird hier kopiert).
- **Beim Entpacken** von Code ist es normal, **mehrere Aufrufe** zu **arithmetischen Operationen** und Funktionen wie **`memcopy`** oder **`Virtual`**`Alloc` zu finden. Wenn Sie sich in einer Funktion befinden, die anscheinend nur arithmetische Operationen und vielleicht einige `memcopy` durchführt, ist die Empfehlung, zu versuchen, **das Ende der Funktion zu finden** (vielleicht ein JMP oder ein Aufruf zu einem Register) **oder** zumindest den **Aufruf zur letzten Funktion** und dorthin zu springen, da der Code nicht interessant ist.
- Während des Entpackens von Code **notieren** Sie, wann immer Sie **den Speicherbereich ändern**, da eine Änderung des Speicherbereichs den **Beginn des Entpackungscodes** anzeigen kann. Sie können einen Speicherbereich einfach mit Process Hacker dumpen (Prozess --> Eigenschaften --> Speicher).
- Wenn Sie versuchen, Code zu entpacken, ist eine gute Möglichkeit, **zu wissen, ob Sie bereits mit dem entpackten Code arbeiten** (damit Sie ihn einfach dumpen können), die **Strings der Binary zu überprüfen**. Wenn Sie zu einem bestimmten Zeitpunkt einen Sprung ausführen (vielleicht den Speicherbereich ändern) und feststellen, dass **viele weitere Strings hinzugefügt wurden**, dann können Sie wissen, **dass Sie mit dem entpackten Code arbeiten**.\
Wenn der Packer jedoch bereits viele Strings enthält, können Sie sehen, wie viele Strings das Wort "http" enthalten und überprüfen, ob diese Zahl steigt.
- Wenn Sie eine ausführbare Datei aus einem Speicherbereich dumpen, können Sie einige Header mit [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases) reparieren.

{{#include ../../banners/hacktricks-training.md}}

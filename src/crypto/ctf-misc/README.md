# Crypto CTF: Sonstiges

{{#include ../../banners/hacktricks-training.md}}

Dieser Abschnitt enthält Techniken aus Kryptografie-Challenges, die sich nicht ohne Weiteres den anderen Kategorien zuordnen lassen.

## Esoterische Sprachen

### Technik

Verwende diesen Ablauf, wenn eine Challenge das Ausführen eines Programms in einer esoterischen Sprache und das Decodieren seiner Ausgabe erfordert.

Wenn eine Challenge Code enthält, der nicht wie eine Standardsprache aussieht:

- Identifiziere die Sprache, indem du nach einem markanten Token oder einer bestimmten Befehlsfolge suchst.
- Verwende einen Online-Interpreter oder ein Docker-Image.
- Wenn die Ausgabe ungewöhnlich ist, achte nach der Ausführung auf weitere Encoding- oder Komprimierungsschichten.

Ein nützliches Sprachenverzeichnis ist das Esolang-Wiki.<sup>[[1]](#references)</sup> Für gewöhnliche Encoding- und Komprimierungsschichten verwende den [Crypto-CTF-Ablauf](../ctf-workflow/). Wenn der Hinweis aus unsichtbarem Text statt aus ausführbarer Syntax besteht, siehe [Text-Steganografie](../../stego/text/).

### Vorab geladenen Interpreter-Zustand exfiltrieren

Wenn eine Challenge Quellcode in einer esoterischen Sprache akzeptiert und ihn in einem **benutzerdefinierten Interpreter** ausführt, untersuche dessen anfänglichen Speicher, Stack und Ausgabeanweisungen, bevor du den Quellcode als Decodierungsrätsel behandelst. Wenn der Interpreter ein Geheimnis vorab auf einen Befunge-Stack lädt, kann ein kurzes Programm die vorhandenen Bytes aus dem Stack nehmen und ausgeben, ohne sie zu berechnen. Dafür musst du den ausgeführten Quellcode kontrollieren und einen Ausgabe-Opcode verwenden können; mit einem normalen, leeren Interpreter funktioniert das nicht. Bei einer Befunge-Challenge gab die folgende Eingabe wiederholt Zeichen eines vorab in umgekehrter Reihenfolge auf dem Stack abgelegten Flags aus.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` startet die Ausführung nach rechts, `,` nimmt ein Zeichen vom Stack und gibt es aus, und `<` schickt den Befehlszeiger zurück zu `,`. Prüfe das Verhalten des benutzerdefinierten Interpreters bei Stack-Unterlauf und beim Erreichen des Befehlslimits: Die zitierte Implementierung hält an, wenn der Stack leer ist oder nach 1.024 Befehlen. Falls das Secret nicht direkt auf dem Stack liegt, untersuche stattdessen andere initialisierte Zustände sowie verfügbare Ausgabe- und Leseinstruktionen, anstatt standardmäßige Befunge-Semantik anzunehmen.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, das Wiki zu esoterischen Programmiersprachen](https://esolangs.org/wiki/Main_Page)
- [2] [Original-Writeup zu WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [Quellcode des WolvCTF-2024-Befuddled1-Interpreters](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Befunge-Sprachreferenz](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}

{{#include ../banners/hacktricks-training.md}}

# CBC

Wenn das **Cookie** **nur** der **Benutzername** ist (oder der erste Teil des Cookies der Benutzername ist) und Sie den Benutzernamen "**admin**" nachahmen möchten. Dann können Sie den Benutzernamen **"bdmin"** erstellen und das **erste Byte** des Cookies **bruteforcen**.

# CBC-MAC

**Cipher block chaining message authentication code** (**CBC-MAC**) ist eine Methode, die in der Kryptographie verwendet wird. Sie funktioniert, indem sie eine Nachricht blockweise verschlüsselt, wobei die Verschlüsselung jedes Blocks mit dem vorherigen verknüpft ist. Dieser Prozess erstellt eine **Kette von Blöcken**, die sicherstellt, dass die Änderung auch nur eines einzelnen Bits der ursprünglichen Nachricht zu einer unvorhersehbaren Änderung im letzten Block der verschlüsselten Daten führt. Um eine solche Änderung vorzunehmen oder rückgängig zu machen, ist der Verschlüsselungsschlüssel erforderlich, was die Sicherheit gewährleistet.

Um den CBC-MAC der Nachricht m zu berechnen, verschlüsselt man m im CBC-Modus mit einem Null-Initialisierungsvektor und behält den letzten Block. Die folgende Abbildung skizziert die Berechnung des CBC-MAC einer Nachricht, die aus Blöcken besteht![https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) unter Verwendung eines geheimen Schlüssels k und eines Blockchiffrierverfahrens E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png](<https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png>)

# Verwundbarkeit

Bei CBC-MAC ist normalerweise der **IV 0**.\
Das ist ein Problem, weil 2 bekannte Nachrichten (`m1` und `m2`) unabhängig 2 Signaturen (`s1` und `s2`) erzeugen. Also:

- `E(m1 XOR 0) = s1`
- `E(m2 XOR 0) = s2`

Dann wird eine Nachricht, die aus m1 und m2 concatenated (m3) besteht, 2 Signaturen (s31 und s32) erzeugen:

- `E(m1 XOR 0) = s31 = s1`
- `E(m2 XOR s1) = s32`

**Was möglich ist, ohne den Schlüssel der Verschlüsselung zu kennen.**

Stellen Sie sich vor, Sie verschlüsseln den Namen **Administrator** in **8-Byte**-Blöcken:

- `Administ`
- `rator\00\00\00`

Sie können einen Benutzernamen namens **Administ** (m1) erstellen und die Signatur (s1) abrufen.\
Dann können Sie einen Benutzernamen erstellen, der das Ergebnis von `rator\00\00\00 XOR s1` ist. Dies wird `E(m2 XOR s1 XOR 0)` erzeugen, was s32 ist.\
Jetzt können Sie s32 als die Signatur des vollständigen Namens **Administrator** verwenden.

### Zusammenfassung

1. Holen Sie sich die Signatur des Benutzernamens **Administ** (m1), die s1 ist
2. Holen Sie sich die Signatur des Benutzernamens **rator\x00\x00\x00 XOR s1 XOR 0**, die s32 ist.
3. Setzen Sie das Cookie auf s32 und es wird ein gültiges Cookie für den Benutzer **Administrator** sein.

# Angriff auf die Kontrolle des IV

Wenn Sie den verwendeten IV kontrollieren können, könnte der Angriff sehr einfach sein.\
Wenn das Cookie nur der verschlüsselte Benutzername ist, können Sie, um den Benutzer "**administrator**" nachzuahmen, den Benutzer "**Administrator**" erstellen und Sie erhalten sein Cookie.\
Jetzt, wenn Sie den IV kontrollieren können, können Sie das erste Byte des IV ändern, sodass **IV\[0] XOR "A" == IV'\[0] XOR "a"** und das Cookie für den Benutzer **Administrator** regenerieren. Dieses Cookie wird gültig sein, um den Benutzer **administrator** mit dem ursprünglichen **IV** nachzuahmen.

## Referenzen

Weitere Informationen unter [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)

{{#include ../banners/hacktricks-training.md}}

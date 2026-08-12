# Cloning a Website

{{#include ../../banners/hacktricks-training.md}}

For a phishing assessment sometimes it might be useful to completely **clone/dump a website**.

Note that you can add also some payloads to the cloned website like a BeEF hook to "control" the tab of the user.

There are different tools you can use for this purpose:

## wget

The following command uses Wget's mirroring, page-requisite, link-conversion, and extension-adjustment modes, then serves the downloaded files from the current directory with Python's `http.server` module on port 8000.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```

## goclone

The goclone repository describes the utility as downloading a website to a local directory while preserving its relative link structure, and documents the `goclone <url>` invocation.<sup>[[3]](#references)</sup>

```bash
#https://github.com/imthaghost/goclone
goclone <url>
```

## Social Engineering Toolit

The Social-Engineer Toolkit (SET) repository identifies SET as an open-source penetration-testing framework for authorized social-engineering assessments.<sup>[[4]](#references)</sup>

```bash
#https://github.com/trustedsec/social-engineer-toolkit
```

## References

- [1] [GNU Wget Manual](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python `http.server` documentation](https://docs.python.org/3/library/http.server.html)
- [3] [goclone repository](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer Toolkit repository](https://github.com/trustedsec/social-engineer-toolkit)

{{#include ../../banners/hacktricks-training.md}}

# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Chromium-based browsers like Google Chrome, Microsoft Edge, Brave, and others. These browsers are built on the Chromium open-source project, which means they share a common base and, therefore, have similar functionalities and developer options.

#### `--load-extension` Flag

The `--load-extension` flag is used when starting a Chromium-based browser from the command line or a script. This flag allows to **automatically load one or more extensions** into the browser upon startup.

#### `--use-fake-ui-for-media-stream` Flag

The `--use-fake-ui-for-media-stream` flag is another command-line option that can be used to start Chromium-based browsers. This flag is designed to **bypass the normal user prompts that ask for permission to access media streams from the camera and microphone**. When this flag is used, the browser automatically grants permission to any website or application that requests access to the camera or microphone.

### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Example

```bash
# Intercept traffic
voodoo intercept -b chrome
```

Find more examples in the tools links

## References

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}




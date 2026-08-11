# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

For background on iButton technology, see:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

In the following image, the **blue** area shows how to place a physical iButton against the Flipper Zero's contacts for reading. The **green** area shows which contacts should touch a reader during emulation.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

In Read mode, the Flipper Zero waits for a key to touch its contacts, detects the protocol, and displays the protocol above the key ID. The built-in application supports Dallas, Cyfral, and Metakom access-control keys.<sup>[[2]](#references)</sup>

### Add manually

You can manually enter key data for the Dallas, Cyfral, and Metakom protocols.<sup>[[2]](#references)</sup>

### Emulate

You can emulate a saved key, whether it was read from a physical key or entered manually.<sup>[[2]](#references)</sup>

> [!TIP]
> If the built-in contacts cannot reach the reader, connect the data and ground contacts through the GPIO pins.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero documentation - Reading iButton keys](https://docs.flipper.net/zero/ibutton/read)

{{#include ../../../banners/hacktricks-training.md}}


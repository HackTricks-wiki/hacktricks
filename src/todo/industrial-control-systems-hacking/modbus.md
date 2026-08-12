# The Modbus Protocol

{{#include ../../banners/hacktricks-training.md}}

## Introduction to Modbus

Modbus is an open application-layer protocol widely implemented by PLCs, sensors, actuators, and other industrial devices. Its request/response model exposes coils and registers through function codes. Security testing therefore focuses on unauthorized reads/writes, traffic observation, replay, and unsafe device behavior—not merely on finding TCP port 502.<sup>[[1]](#references)</sup>

Many deployments retain legacy serial equipment because upgrades require downtime, recertification, or replacement of field devices. Traditional Modbus provides neither confidentiality nor peer authentication; Modbus Security is a separate TLS-based profile using X.509 certificates and TCP port 802. Because the specification is public and independently implementable, vendor behavior and optional-function support vary and should be fingerprinted rather than assumed.<sup>[[1]](#references)[[2]](#references)</sup>

## The Client-Server Architecture

In current terminology, a **client** initiates a transaction and a **server** returns a response. Older documentation uses **master/slave**. Do not confuse this application relationship with SPI or I2C: those are different bus protocols.<sup>[[1]](#references)</sup>

## Serial and Ethernet transports

The same Modbus application data can be carried by serial variants (RTU or ASCII framing) and by Modbus TCP. Modbus TCP adds an MBAP header and normally uses TCP port 502; serial RTU uses compact binary framing and a CRC, while serial ASCII represents bytes as hexadecimal characters and uses an LRC.<sup>[[1]](#references)[[3]](#references)</sup>

## Data representation

The data model consists of single-bit coils/discrete inputs and 16-bit input/holding registers. Multi-register values, byte order, scaling, and semantic meaning are device-specific and must be confirmed against the vendor's register map.<sup>[[1]](#references)</sup>

## Function codes

Function codes select operations such as reading coils (`0x01`), reading holding registers (`0x03`), writing a single coil/register (`0x05`/`0x06`), and writing multiple coils/registers (`0x0F`/`0x10`). A captured write request may be replayable when the deployment has no compensating authentication or process-state checks. With authorized physical access to long serial runs, an assessor may also capture or inject frames directly on the wiring after identifying the electrical interface, termination, and safe connection method. Either action can affect the physical process, so use a lab or explicit operational authorization.<sup>[[1]](#references)[[3]](#references)</sup>

## Addressing

Serial devices use a unit address. Modbus TCP uses IP addressing plus a Unit Identifier in the MBAP header, which is particularly relevant when a TCP-to-serial gateway routes requests to downstream units. Register references shown by product documentation can be one-based (`40001`) while protocol addresses are zero-based, a common source of off-by-one errors.<sup>[[1]](#references)[[3]](#references)</sup>

Serial framing includes transmission-error checks (CRC for RTU and LRC for ASCII), and TCP supplies its normal transport checksum. These detect accidental corruption; they are not cryptographic integrity or origin authentication.<sup>[[3]](#references)</sup>

During an authorized assessment, test exposure, permitted function codes, writable address ranges, exception handling, rate limits, and whether network segmentation or a Modbus-aware firewall constrains clients. Relevant threats include passive disclosure, unauthorized command injection, replay, data forgery, and denial of service. Coordinate all active tests with process owners because apparently small register changes can alter a physical process.

## References

- [1] [Modbus Organization — Modbus Application Protocol Specification V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Modbus Security Protocol and implementation guides](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Modbus over Serial Line Specification and Implementation Guide V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)

{{#include ../../banners/hacktricks-training.md}}

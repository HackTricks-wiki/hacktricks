# Enrolling Devices in Other Organisations

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Apple Automated Device Enrollment (formerly DEP) begins by identifying a device assigned to an organization. The 2018 research summarized here showed that knowledge of an assigned serial number was sufficient to retrieve some organizations' enrollment profiles because those organizations did not require adequate additional authentication. This is a historical finding, not a claim that every current MDM can be joined with only a serial number. Profiles may contain certificates, applications, Wi-Fi secrets, VPN settings, and other sensitive configuration.<sup>[[1]](#references)[[2]](#references)</sup>

**The following is a summary of the research [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Check it for further technical details!**<sup>[[1]](#references)</sup>

## Overview of DEP and MDM Binary Analysis

The research analyzed binaries associated with DEP and MDM on the macOS versions current at the time. Component names and responsibilities can change across releases:

- **`mdmclient`**: Communicates with MDM servers and triggers DEP check-ins on macOS versions before 10.13.4.
- **`profiles`**: Manages Configuration Profiles, and triggers DEP check-ins on macOS versions 10.13.4 and later.
- **`cloudconfigurationd`**: Manages DEP API communications and retrieves Device Enrollment profiles.

DEP check-ins utilize the `CPFetchActivationRecord` and `CPGetActivationRecord` functions from the private Configuration Profiles framework to fetch the Activation Record, with `CPFetchActivationRecord` coordinating with `cloudconfigurationd` through XPC.<sup>[[1]](#references)</sup>

## Tesla Protocol and Absinthe Scheme Reverse Engineering

The DEP check-in involves `cloudconfigurationd` sending an encrypted, signed JSON payload to _iprofiles.apple.com/macProfile_. The payload includes the device's serial number and the action "RequestProfileConfiguration". The encryption scheme used is referred to internally as "Absinthe". Unraveling this scheme is complex and involves numerous steps, which led to exploring alternative methods for inserting arbitrary serial numbers in the Activation Record request.<sup>[[1]](#references)</sup>

## Proxying DEP Requests

Attempts to intercept and modify DEP requests to _iprofiles.apple.com_ using tools like Charles Proxy were hindered by payload encryption and SSL/TLS security measures. However, enabling the `MCCloudConfigAcceptAnyHTTPSCertificate` configuration allows bypassing the server certificate validation, although the payload's encrypted nature still prevents modification of the serial number without the decryption key.<sup>[[1]](#references)</sup>

## Instrumenting System Binaries Interacting with DEP

Instrumenting system binaries like `cloudconfigurationd` requires disabling System Integrity Protection (SIP) on macOS. With SIP disabled, tools like LLDB can be used to attach to system processes and potentially modify the serial number used in DEP API interactions. This method is preferable as it avoids the complexities of entitlements and code signing.<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation:**
Modifying the DEP request payload before JSON serialization in `cloudconfigurationd` proved effective. The process involved:

1. Attaching LLDB to `cloudconfigurationd`.
2. Locating the point where the system serial number is fetched.
3. Injecting an arbitrary serial number into the memory before the payload is encrypted and sent.

This method allowed the researchers to retrieve DEP profiles for supplied, assigned serial numbers. It did not make an unassigned arbitrary serial number valid.<sup>[[1]](#references)</sup>

### Automating Instrumentation with Python

The exploitation process was automated using Python with the LLDB API, making it feasible to programmatically inject arbitrary serial numbers and retrieve corresponding DEP profiles.<sup>[[1]](#references)</sup>

### Potential Impacts of DEP and MDM Vulnerabilities

The research highlighted significant security concerns:

1. **Information Disclosure**: By providing a DEP-registered serial number, sensitive organizational information contained in the DEP profile can be retrieved.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)

{{#include ../../../banners/hacktricks-training.md}}

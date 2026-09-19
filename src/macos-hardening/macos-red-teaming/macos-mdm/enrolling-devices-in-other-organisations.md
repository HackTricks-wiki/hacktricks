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

## 2025 Revisit: Rogue Enrollment from a VM

Black Hat Asia 2025 research demonstrated that the original trust-boundary problem can still matter at the **MDM layer**: instead of patching `cloudconfigurationd` with LLDB, the researchers ran macOS under QEMU/KVM with OpenCore and supplied the candidate identity through the VM's SMBIOS. The unmodified macOS enrollment stack then performed the encrypted Apple exchange. Publicly leaked serials and valid-looking candidates can therefore be tested without possessing the corresponding physical Mac; a hit still requires that the serial is assigned to an organization and that the organization's enrollment path is insufficiently authenticated.<sup>[[3]](#references)</sup>

For an authorized lab device, the relevant OpenCore `PlatformInfo` values include a product model and serial (real deployments also keep the ROM and UUID internally consistent):<sup>[[3]](#references)</sup>

```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```

The same research identified `CheckProfilesFetchRateLimit` state in the private file `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Because the check was maintained on the client, modifying the stored time values defeated it. These paths are undocumented and version-dependent, but they are useful reversing pivots when assessing a current macOS build:<sup>[[3]](#references)</sup>

```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```

The second artifact can disclose the cached activation record, including whether the flow uses a direct `ConfigurationURL` or an authenticated `ConfigurationWebURL`. Test both the advertised flow and any MDM-specific legacy enrollment endpoints: enabling SSO only on the main web flow does not protect a parallel direct endpoint. For the complete protocol sequence, see the [macOS MDM overview](README.md).<sup>[[3]](#references)</sup>

### Post-Enrollment Secret Hunting

A rogue enrollment is only the entry point. After enrollment, inspect every delivered profile, bootstrap policy, package-repository configuration, agent installation script, and self-service item. The 2025 research recovered examples of Wi-Fi credentials, shared local-administrator passwords, signed cloud-storage URLs, webhook URLs, security-agent activation data, and MDM/API credentials. A tenant API credential in a delivered script can turn one rogue endpoint into control over other managed devices, so search both the live filesystem and downloaded/cached policy content.<sup>[[3]](#references)</sup>

Useful review targets include:<sup>[[3]](#references)</sup>

- Installed `.mobileconfig` payloads and the Configuration Profiles database.
- PreStage/bootstrap scripts and packages that create accounts or install EDR/VPN agents.
- Munki or other package repository URLs, especially query strings containing bearer/SAS-style signatures.
- Self-service catalogs and their backing policy APIs, including legacy routes that may not enforce the enrollment SSO policy.
- Shell history and cached policy output for `password`, `token`, `secret`, `Authorization`, webhook hostnames, and vendor API endpoints.

### Hardening the Trust Boundary

Treat a serial number as an inventory/routing attribute, **not** proof of possession. Require user authentication for enrollment and self service, generate unique per-device local administrator passwords, and never embed tenant API credentials or reusable infrastructure secrets in profiles or scripts. Keep any unavoidable bootstrap token short-lived and restricted to the single action and device being provisioned.<sup>[[3]](#references)</sup>

On Apple-silicon Macs running macOS 14 or later, Managed Device Attestation can cryptographically bind identity to the Secure Enclave. Its Apple-rooted attestation can carry a fresh nonce plus the serial number, UDID, OS version, SIP state, and secure-boot state; ACME can then issue a hardware-bound client identity. Use that identity to protect the MDM channel and gate high-value certificates, VPN access, and other resources, while retaining separate user authentication because device attestation proves the device rather than the operator.<sup>[[4]](#references)</sup>

## Potential Impacts of DEP and MDM Vulnerabilities

The research highlighted significant security concerns:

1. **Information Disclosure**: By providing a DEP-registered serial number, sensitive organizational information contained in the DEP profile can be retrieved.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Hacking Apple MDMs Using Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}

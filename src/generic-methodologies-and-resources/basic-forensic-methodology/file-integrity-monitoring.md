{{#include ../../banners/hacktricks-training.md}}

# Baseline

A baseline consists of taking a snapshot of certain parts of a system to **compare it with a future status to highlight changes**.

For example, you can calculate and store the hash of each file of the filesystem to be able to find out which files were modified.\
This can also be done with the user accounts created, processes running, services running and any other thing that shouldn't change much, or at all.

## File Integrity Monitoring

File Integrity Monitoring (FIM) is a critical security technique that protects IT environments and data by tracking changes in files. It involves two key steps:

1. **Baseline Comparison:** Establish a baseline using file attributes or cryptographic checksums (like MD5 or SHA-2) for future comparisons to detect modifications.
2. **Real-Time Change Notification:** Get instant alerts when files are accessed or altered, typically through OS kernel extensions.

## Tools

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## References

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}




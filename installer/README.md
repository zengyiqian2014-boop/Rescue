# Installing the RescueMon kernel driver

Two scripts:

| Script | What it does |
| --- | --- |
| `Install-RescueDriver.ps1` | Detects which signing path the driver qualifies for and installs it |
| `Uninstall-RescueDriver.ps1` | Reverses **every** change the installer made, using its own install record |

```powershell
# production: the .sys is Microsoft-signed - nothing about the machine changes
.\Install-RescueDriver.ps1

# development on your own test machine, Secure Boot off, explicit consent
.\Install-RescueDriver.ps1 -LabMode

.\Uninstall-RescueDriver.ps1
```

---

## Read this before planning a "just let the user trust our certificate" flow

It is an intuitive idea: self-sign the driver, and during installation offer the
user a choice — accept our certificate and get the kernel protection tier, or
decline and don't. Put it in the T&C, have them agree, install the certificate
as trusted.

**It does not work.** Not "it's frowned upon" — the driver still will not load.
The reason is worth understanding because it shapes what the installer can
honestly offer:

- **Kernel Code Integrity does not consult the user's certificate stores.**
  User-mode Authenticode does: trust a root, and code signed by it validates.
  Kernel-mode signing is a *different, stricter* check made by the loader
  before any user context exists. Since **Windows 10 1607**, a new kernel driver
  loads only when **Microsoft** has signed it (Dev Portal attestation, or full
  WHCP). Importing your own root into `LocalMachine\Root` changes nothing about
  that decision.
- **The remaining legacy loophole is closed.** Cross-signed drivers (an EV cert
  chaining to a Microsoft cross-certificate) used to load. The
  **April 2026 Windows update removed default trust for cross-signed kernel
  drivers** on Windows 11 24H2/25H2/26H1 and Windows Server 2025 — by default
  only WHCP-signed drivers, or drivers on Microsoft's curated allow list, load.
- **So the only thing a user *could* consent to** is putting the whole machine
  into **test-signing mode**, which requires **Secure Boot off**. That is not
  "trusting Rescue" — it makes the machine load *any* test-signed driver, from
  anyone. It is a machine-wide downgrade, and it is exactly the state a rootkit
  would like the machine to be in.

There is a second problem, independent of whether it works.

**Burying a root-certificate install in a T&C checkbox is the Superfish /
eDellRoot pattern.** Lenovo shipped a trusted root with a recoverable private
key and ended up under an **FTC consent order** requiring 20 years of audited
security programs; Dell had to publish removal instructions for eDellRoot. The
harm in those cases was not that users were never *told* — it was that consent
buried in boilerplate is not informed consent for a change of that magnitude. A
security tool that establishes itself this way has undermined the thing it
claims to defend, and it is precisely the behaviour that gets a product
classified as a PUA by other AV vendors.

So this repo will not ship that flow. What it ships instead:

---

## Path 1 — production (the one that works on other people's machines)

Get the driver **Microsoft-signed**. There is no substitute.

1. **EV code-signing certificate** from a CA (DigiCert, Sectigo, GlobalSign…).
   Identity-validated, hardware-token-backed. Budget roughly **US$300–600/year**
   and 1–3 weeks for the organisation vetting. An OV certificate is **not**
   sufficient for driver submission.
2. **Microsoft Partner Center** hardware account, verified with that EV
   certificate.
3. Build the driver with the WDK, package it as a **CAB**, sign the CAB with the
   EV certificate, submit for **attestation signing**.
4. Microsoft returns the driver **signed by Microsoft**. It now loads on normal
   machines — **Secure Boot on, no test-signing, no certificate for the user to
   accept, no consent screen.**

For a filesystem minifilter shipping to real users you also want:
- a **unique altitude allocated by Microsoft** (the INF currently uses the
  development placeholder `329100`);
- **HVCI compatibility**, since Memory Integrity is on by default on much
  current hardware and will block a non-compliant driver even when signed;
- and, if the goal is genuine anti-tamper, eventually **WHCP** and the
  ELAM/anti-malware protected-process work that goes with it.

The installer's production path does nothing clever: it copies the `.sys`,
registers the INF and service, and loads the filter. No certificates, no boot
configuration.

## Path 2 — lab mode (your own development machine)

For actually testing the driver while you work on it. `-LabMode`:

1. **Preflight** — reports Windows build, Secure Boot, Memory Integrity,
   test-signing state, and the driver's real signature chain, and stops with an
   explanation if Secure Boot is on (`bcdedit` will refuse the change).
2. **Consent that is actually informed** — every consequence itemised on screen
   in plain language, including the one that matters most (test-signing lowers
   the bar for *every* driver, not just this one), and the operator must type
   `I ACCEPT LAB MODE`. Not a checkbox, not a T&C line.
3. **A deliberately narrow certificate** — self-signed, 3072-bit RSA, **Code
   Signing EKU only**, so even while trusted it cannot be used to forge a TLS
   certificate and intercept traffic. The private key never leaves
   `LocalMachine\My`; only the public certificate goes into `Root` and
   `TrustedPublisher`.
4. **A recorded install** — the thumbprint it created, and whether *it* was what
   enabled test-signing, are written to
   `%ProgramData%\Rescue\driver-install-state.json`.
5. **An exact revert** — the uninstaller removes that certificate and no other,
   and turns test-signing back off **only if the installer turned it on** (if
   the machine was already in test-signing mode for some other driver, silently
   disabling it would break that driver at the next boot).

Lab mode is labelled throughout as a developer facility. Do not put it in front
of end users.

## Status of these scripts

**Written and parse-checked; not yet executed on Windows.** They were developed
in a Linux cross-build environment where the rest of Rescue is compiled — the
PowerShell parses cleanly, but `bcdedit`, `fltmc`, `pnputil`, the certificate
stores and an actual driver load cannot be exercised there. Treat the first run
on a real test machine as the thing that validates them, and read them before
running them: they change boot configuration.

## Sources

- [Driver Signing Policy — Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)
- [Advancing Windows driver security: Removing trust for the cross-signed driver program — Microsoft](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-driver-security-removing-trust-for-the-cross-signed-driver-pro/4504818)
- [Signing Kernel Mode Drivers — DigiCert](https://knowledge.digicert.com/solution/signing-kernel-mode-drivers)

<p align="center">
  <img width="200" src="https://github.com/HarriBellThomas/citadel/blob/master/images/citadel.png?raw=true">
</p>

## Citadel — Trusted Reference Monitors for Linux using Intel SGX Enclaves

> Disclaimer: This is a research prototype and not intended for production environments. \
> Thesis: [https://www.cl.cam.ac.uk/~ahb36/citadel.pdf](https://www.cl.cam.ac.uk/~ahb36/citadel.pdf)

### Abstract
Information Flow Control (IFC) is a powerful tool for protecting data in a computersystem, enforcing not only who may access it, but also how it may be used throughout its lifespan. Intel’s Software Guard Extension (SGX) affords complementary protection, providing a general-purpose Trusted Execution Environment for applications and their data. To date, no work has been conducted considering the overlap between the two, and how they may mutually reinforce each other.

Citadel is a modular, SGX-backed reference monitor to securely and verifiably implement IFC methods in the Linux kernel. The prototype externalises policy decisions from its enforcement security module, providing a userspace promise-of-access model with asynchronous fulfillment. By aliasing system calls, the system transparently integrates with unmodified applications, and amortises the performance cost of integration by inferring processes’ underlying security contexts.

Observed results are promising, demonstrating a worst-case median performance overhead of 25%.  In addition, the Nginx webserver is demonstrated running under Citadel; high bandwidth transfers exhibit near parity with the native Linux kernel’s performance. This work illustrates the potential viability of a symbiotic enclave-kernel relationship for security implementations, something that may, in the long run, benefit both.


### Build the Prototype
The following steps assume a Linux-based system running on an SGX-capable processor. Before starting the SGX driver needs to be installed.

Prepare a fresh kernel (v5.6.2) with the Citadel LSM using ```make DEBUG=1```.

Once initialised, build and install the kernel using ```make kernel``` (this may take a while).

Before booting into the ```5.6.2-citadel``` kernel properly, the SGX driver needs to be installed for it as well. This can be achieved either by;
- Booting into the new kernel (the reference monitor will fail to initialise), installing the driver and rebooting.
- Modifying the driver's Makefile to target the new kernel's modules folder.

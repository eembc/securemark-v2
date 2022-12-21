# Introduction

SecureMark®-V2 is a benchmark created by EEMBC® to help glean insight into the performance and power costs associated with implementing cryptography in an embedded product. It does this by providing several pre-defined cryptographic suites running on top of a portable API. The API facilitates the use of any type of cryptographic acceleration, from external hardware peripherals, to specific ISA instructions, to even different cryptographic libraries. On top of the API, each suite is based on the analysis of a real-world scenario, but presented in way that isolates the compute portion while avoiding the need to worry about other application related middleware, such as the TCP stack, or hardware drivers. Instead, it focuses specifically on the cryptographic primitives.

The three suites SecureMark-V2 focuses on are the TLSv1.3 and TLSv1.2 handshakes, and secure boot. Each suite, when run, produces a single score consisting of a weighted combination of the primitive time and/or energy cost. The suites can be configured to use different strengths: light, medium and heavy. These strengths reflect common design choices based on what type of hardware is available in the product’s budget. In addition to the suites, SecureMark-V2 also provides a sandbox for exploring the characteristics of the primitives as well.

Through these capabilities, SecureMark-V2 enables all aspects of a project design, from marketing, to engineering, to validation, and software verification. These capabilities make SecureMark-V2 a highly functional analysis tool.

SecureMark-V2 is the second version of our security suite that started with [SecureMark-TLS](https://github.com/eembc/securemark-tls).

# Overview

The benchmark consists of a core firmware that acts as the primary application once the DUT setup has completed. The application enters a UART Rx polling loop waiting for instructions from a host that tell it what suites to run, and how to configure them. The host application is a GUI that runs on Windows, Mac or Linux, and connects to the DUT two different ways: directly via a UART, or through the energy framework. The first mode of connection is called “performance mode”, and the latter is referred to as “energy mode”. Performance mode has fewer hardware components in the framework, but as the name suggests, you can only measure performance. To measure energy, additional hardware is required. The same host GUI can run both modes, only the connectivity to the DUT changes.

# Theory of Operation

Each of the suites executes a set of primitives that reflect the cryptographic compute load of a particular application. The size of the inputs and the weighted contribution of the results were all determined by profiling libraries. For example, the TLSv1.3 light handshake suite was extracted from an OpenSSL handshake using the mbedTLS library. GDB was used to extract the function calls at each handshake stage. From this matrix of data, we could extract each primitive’s context, how long it persisted, and each call to it including the size of the input data per call. Since the cryptographic functions are >99% of the runtime, the intermediate buffering has no impact on the score, so we can discard this and instead create a benchmark based on just the extracted profiling data, reducing it to cryptographic calls. The same was done for Secure Boot using MCUboot. We refer to these suites as “Synthetic Secure Boot” because the energy & performance cost of actually booting are not counted, just the crypto load.

<img width="665" alt="image" src="https://user-images.githubusercontent.com/8249735/206804882-c4642d86-c675-4371-809c-27a4f56929dd.png">

Each suite contains from one to 14 primitive invocations, each with differing input messages and sizes. The total number of seconds or joules per iteration is measured by the framework. This metric is multiplied by a weighting factor, and the sum of these weighted values is then inverted and multiplied by a scalar. The result is a benchmark score that increases when runtime or energy per iteration decreases.

# More information

A self-hosted version is provided here for experiementation. Please refer to the `examples/seflhosted/` directory.

To obtain a full version, contact EEMBC about purchasing a licese at <a href='mailto:support@eembc.org'>support@eembc.org</a>.

Copyright (C) EEMBC (R), All rights reserved.

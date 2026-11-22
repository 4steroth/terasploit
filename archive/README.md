# Shellcode Catalog & Payload Artifacts

> **Security Notice:** Files in this directory may contain shellcode, encoded payloads, or exploit primitives. Handle and inspect all artifacts strictly within isolated virtual machines or sandboxed environments.

## Overview
This directory serves as an isolated workspace for cataloging raw shellcodes and dissecting payloads to understand their internal mechanics during security research and framework development. None of the binaries, payloads, or analysis files in this directory are directly imported, bundled, or executed by the core framework at runtime.

## Purpose
* Shellcode Cataloging: Stores raw, assembled, or encoded shellcode samples organized by architecture, OS, and execution behavior.
* Payload Analysis: Stores payload for reverse engineering.
* Exploit Artifact Examination: Contains memory dumps, shellcode stubs, and dissected payload captures used to study memory layout, control-flow hijacking primitives, and byte-level constraints.

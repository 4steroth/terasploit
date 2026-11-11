# Terasploit Module Development Guide

Covers how to write, structure, and test modules for the Terasploit Framework (TSF). Assumes familiarity with Python and the TSF console.

## Table of Contents

- [Module System](#module-system)
- [Shared Module Skeleton](#shared-module-skeleton)
- [Module Types](#module-types)
  - [Exploit](#exploit)
  - [Auxiliary](#auxiliary)
  - [Post](#post)
  - [Encoder](#encoder)
  - [Nops](#nops)
  - [Evasion](#evasion)
- [Option System](#option-system)
- [Ranks](#ranks)
- [Platform and Architecture Constants](#platform-and-architecture-constants)
- [Naming Conventions](#naming-conventions)
- [Summary](#summary)

## Module System

Every module is a single Python file containing one class named TerasploitModule, which inherits from the base class that matches its type. The framework discovers modules by walking the modules directory at startup, so no registration step is needed: drop a correctly structured file in the right place and it shows up after a reload. Internally this is handled by ModuleIndex, which scans recursively for Python files (excluding `__init__.py`), builds a map from dotted module names to file paths, and caches that map until the reload command invalidates it.

Modules are organized by category into subdirectories: auxiliary for scanners, fuzzers, brute-forcers and other info-gathering tools; encoder for payload encoders; evasion for AV/EDR bypass exploits; exploit for exploits proper; nop for NOP sled generators; payload for stagers, stages, singles and adapters; and post for post-exploitation modules. Within a category, files are organized by increasing specificity: topic alone, or topic under a platform, or topic under a platform and architecture, so a typical path looks like `modules/<category>/<platform>/<architecture>/<topic>/<n>.py`.

The dotted name used with the use command is just that path with slashes turned into dots and the `.py` extension dropped, so `modules/exploit/multi/handler.py` becomes `use exploit/multi/handler`. The word "multi" in a path means the module supports more than one platform or architecture, so you don't invent a separate multi constant for this; you just list every compatible value in PLATFORM and ARCH, and multi only ever shows up as a path segment, never as a value in those lists.

## Shared Module Skeleton

Every module type starts from the same shape, shown below. The per-type sections further down only describe what's different from this skeleton, not a complete rewrite of it.

```python
class TerasploitModule(<BaseClass>):
    NAME        = "Module Name"
    DESCRIPTION = "Short description."
    AUTHOR      = "handle"
    LICENSE     = "BSD-3-CLAUSE"      # SPDX identifier
    VERSION     = "1.0"               # semantic version
    RANK        = "normal"            # see Ranks
    REFERENCES  = [["URL", "https://example.com/advisory"]]  # optional

    ARCH        = [ARCH_X86, ARCH_X64]      # or [ARCH_ALL]
    PLATFORM    = [PLATFORM_LINUX]          # or [PLATFORM_ALL]

    OPTIONS          = ["RHOST", "RPORT"]   # keys shown by `show options`
    ADVANCED_OPTIONS = []                   # keys shown by `show advanced`
    EVASION_OPTIONS  = []                   # keys shown by `show evasion`

    def __init__(self, *args, **kwargs):
        # Only override __init__ if you need custom options or state.
        super().__init__(*args, **kwargs)

    def run(self, ctx):
        ...
```

`NAME`, `DESCRIPTION`, `AUTHOR`,`LICENSE`, `VERSION`,` RANK`, `ARCH` and `PLATFORM` are required on every module regardless of type. `OPTIONS`, `ADVANCED_OPTIONS`, `EVASION_OPTIONS` and `REFERENCES` are optional and default sensibly when omitted. If you do override `__init__`, always forward the incoming *args and **kwargs to `super().__init__()` before doing anything else, since the base class relies on receiving them.

## Module Types

***Exploit modules*** live under the exploit base class and path, use `ExploitContext`, and additionally require `PAYLOAD_SPACE` and `TARGET` beyond the shared attributes; they implement run, with check and stop being optional.

***Auxiliary modules*** use the auxiliary base class and path and an `AuxiliaryContext`, add no attributes beyond the shared set, and implement run with an optional check.

***Post modules*** use the post base class and path and a `PostContext`, add `SESSION_TYPES`, and implement only run.

***Encoder modules*** use the encoder base class and path, have no context object at all, add nothing beyond the shared attributes, and implement encode instead of run.

***Nops modules*** use the nops base class and path, also have no context object, add `SAVE_REGISTERS`, and implement `generate_sled` with an optional `can_avoid` instead of run.

***Evasion modules*** combine the Exploit base class with an Evasion mixin, live under the evasion path, use `ExploitContext` like exploits do, and need everything an exploit needs plus `EVASION_TECHNIQUE` and `NEEDS_CLEANUP`; they implement run with an optional cleanup.

### Exploit

Exploit modules deliver a payload to a target and open a session. They're driven by `ExploitDriver`, which transparently handles the TCP connection, payload assembly, encoding, and NOP sled prepending, so the module itself mostly just needs to describe the target and the delivery mechanism. `PAYLOAD_SPACE` tells the driver the buffer size the delivery mechanism can carry; set it to None to skip the size check entirely rather than guessing a number. `TARGET` is a list of (index, label) pairs that populates the `set TARGET` command; it's required for that command to do anything, and index 0 is selected automatically when the module loads. Both check and stop are optional and can simply be omitted if the module doesn't need them.

```python
TARGET = [
    (0, "Windows x86 Automatic"),
    (1, "Windows x64 Automatic"),
]
PAYLOAD_SPACE = 4096
```

### Auxiliary

Auxiliary modules handle supporting tasks: scanning, fuzzing, brute-forcing, information gathering, all without ever delivering a payload or opening a session. There's nothing beyond the shared skeleton here, just implement run, and optionally check, and you're done.

### Post

Post modules run against a session that's already open rather than establishing one themselves. `SESSION_TYPES` is advisory metadata rather than an enforced constraint, so use `["shell"]` or an empty list to accept any session type. The live session itself is available as `ctx.session`, a `ShellSession` object you interact with through `send_command` and `read_output`. The user is expected to set the target session with `set SESSION` before running the module.

### Encoder

Encoder modules transform payload bytes to avoid bad characters or evade signature-based detection, and they're invoked automatically by `EncoderFactory` during payload assembly rather than being run directly by the user. The interface is a single encode method:

```python
def encode(
    self, raw_bytes: bytes, bad_bytes: frozenset[int], ctx: object | None = None
) -> EncoderResult: ...
```

Encoders rank themselves with EncoderRank rather than the plain string ranks other module types use, see Ranks below. Because encoding logic can get structurally complex, there's no fixed skeleton of helper methods beyond implementing encode itself with the same signature and conventions as the base Encoder class, which keeps it interoperable with the rest of the framework.

### Nops

Nops modules generate NOP sleds, sequences of bytes that are semantically equivalent to doing nothing, used to pad the delivery buffer ahead of the payload. They expose two methods: `can_avoid` is a fast pre-filter that should return false early when the sled's fixed NOP byte can't dodge the given bad characters, which saves `EncoderFactory` from wasting time trying a sled that can never work; `generate_sled` does the actual work and should return exactly the requested number of bytes, raising `ValueError` if that's not possible. Framework code never calls `generate_sled` directly; it goes through a wrapper called generate, which catches exceptions, double-checks that no bad bytes slipped through, and returns a `NopsResult`. `SAVE_REGISTERS` is advisory metadata listing which registers a given sled preserves, so callers can choose a sled that won't clobber one they still need. Nops modules aren't invoked with the run command at all; they use generate instead, for example:

```
use nop/x86/single_byte
generate 32
generate 32 -b \x00\x0a
```

### Evasion

Evasion modules are exploit modules with AV/EDR bypass logic embedded directly in run. Everything described under Exploit above still applies, including the same driver and the same PAYLOAD_SPACE/TARGET requirements. They're declared as `class TerasploitModule(Exploit, Evasion):`, and Exploit has to come first in that inheritance list so the method resolution order ends up TerasploitModule, then Exploit, then Evasion, then the common base. EVASION_TECHNIQUE is just a short descriptive string shown in info output and module listings. NEEDS_CLEANUP should be true whenever run leaves artefacts behind on the target, such as dropped files, registry keys, or injected threads, and when it's true, cleanup is called unconditionally from the driver's finally block, receiving the same ExploitContext that run received. A cleanup method that throws is only logged as a warning; it never blocks teardown.

## Option System

Options are key-value pairs stored in the framework's global `DATASTORE`. Every key referenced by a module has to either already exist in the shared `OPTION_REGISTRY`, or be registered by the module itself at instantiation time. The simple case is referencing existing keys by listing them in OPTIONS:

```python
OPTIONS = ["RHOST", "RPORT"]
```

Any key listed this way shows up under `show options` and gets enforced automatically by missing_required when the module runs. For options that don't already exist in the registry, register them yourself inside `__init__`:

```python
from teralibs.terasploit.framework.options.validators import OptionType


def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.register_options(
        [
            self.opt(
                name="TIMEOUT",
                default="5",
                required=False,
                desc="Connection timeout in seconds",
                opt_type=OptionType.INTEGER,
            ),
            self.opt(
                name="USERNAME",
                default="admin",
                required=True,
                desc="Target username",
                opt_type=OptionType.STRING,
            ),
        ]
    )
```

`self.opt` is just a shorthand for constructing the Option dataclass, and `self.opt_type` is a shorthand for the `OptionType` enum, whose values cover  the usual cases: arbitrary strings, integers, floats, booleans, TCP/UDP ports (validated to the 1-65535 range), IP addresses or hostnames, and filesystem paths. However a module gets its options onto the datastore, reading them back at runtime always goes through `ctx.get_option`, which every context object exposes the same way regardless of module type; `ctx.datastore` is also available for direct access, but `get_option` is preferred when it covers the case.

## Ranks

Exploit, auxiliary, post and nops modules all rank themselves with one of five plain strings, from least to most reliable: "manual" for modules that need significant manual steps and aren't automated, "low" for modules that are unreliable or crash the target often, "normal" as the sensible default for a new module that's reliable under specific known conditions, "high" for modules reliable across a wide range of targets, and "excellent" for modules that work reliably across essentially all common configurations.

Encoders rank themselves differently, using `EncoderRank`,  an `IntEnum` where higher numbers are preferred during automatic encoder selection: MANUAL is `0`, LOW is `100`, NORMAL is `200`, GOOD is `300`, GREAT is `400`, and EXCELLENT is `500`.

## Platform and Architecture Constants

All of these constants are exported identically from every base class, so import them from whichever base class you're already importing for your module type. On the architecture side there's ARCH_X86 for 32-bit x86, ARCH_X64 for AMD64/Intel 64, ARCH_ARM for 32-bit ARM, ARCH_AARCH64 for  64-bit ARM, ARCH_MIPS and ARCH_MIPS64 for 32- and 64-bit MIPS, and ARCH_CMD for a command interpreter target where the payload is a shell string rather than shellcode. On the platform side there's PLATFORM_LINUX, PLATFORM_UNIX for generic POSIX systems, PLATFORM_WINDOWS, PLATFORM_MACOS, PLATFORM_BSD covering FreeBSD/OpenBSD/NetBSD, and PLATFORM_ANDROID.

When a module genuinely doesn't care about architecture or platform, use `[ARCH_ALL]` or `[PLATFORM_ALL]` rather than trying to enumerate every value by hand.

## Naming Conventions

The module class itself is always named TerasploitModule, regardless of what the module does. File and directory names use snake_case throughout, for example `handler.py`, `polymorphic_xor_additive_feedback.py`, `windows/smb/`, `linux/x64/`. 

Option keys and class-level attribute names both use `UPPER_SNAKE_CASE`, as in `RHOST`, `LPORT`, `TIMEOUT`, `PAYLOAD_SPACE` and `SESSION_TYPES`.

Private helper methods that aren't part of the module's public interface are prefixed with an underscore and written in lower snake_case, like `_tcp_connect` or `_build_rop_chain`.

## Summary

Writing a module comes down to putting one TerasploitModule-named file in the right modules subdirectory, where the framework will pick it up automatically on the next reload with no separate registration step. Start every module from the shared skeleton, the eight required attributes, the optional options lists, an `__init__` that forwards its arguments to super if it needs one at all, and then layer in only what the specific module type demands on top of that: PAYLOAD_SPACE and TARGET for exploits, SESSION_TYPES for post modules, an encode method instead of run for encoders, generate_sled and can_avoid instead of run for nops, and the evasion-specific attributes stacked on top of a full exploit module for evasion modules.

Pull options from the shared registry when they already exist there, or register new ones yourself in `__init__` when they don't, and always read them back through the context's get_option rather than touching the datastore directly. Inside run, validate whatever the user gave you and report problems through the context's error method instead of raising, and if the module runs a long loop, check whether it's been killed on every iteration so stop actually works. Once a module seems done, reload the framework, use the module, and run show options to confirm it loads without errors before considering it finished.

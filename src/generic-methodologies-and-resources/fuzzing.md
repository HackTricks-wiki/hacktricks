# Fuzzing

Fuzzing is an automated testing technique that feeds programs with large volumes of mutated inputs to uncover crashes, assertion failures, memory corruption, and logic bugs. Coverage-guided fuzzers aim to maximize code coverage and prioritize inputs that exercise new paths.

## Mach message fuzzing on macOS / CoreAudio

Google Project Zero’s “Breaking the Sound Barrier Part I: Fuzzing CoreAudio with Mach Messages” outlines a knowledge-driven, in-process fuzzing approach for the macOS `coreaudiod` daemon. This technique bypasses kernel IPC overhead while preserving sufficient message structure to trigger deep parsing logic, enabling discovery of high-risk type confusion bugs.

### 1. Fuzzing Workflow

A hybrid cycle is employed:

1. Identify an IPC attack vector (Mach service).
2. Choose a sandbox-accessible service (e.g., `com.apple.audio.audiohald`).
3. Create a direct, in-process fuzzing harness.
4. Seed the fuzzer with legitimate Mach messages captured via LLDB.
5. Run a coverage-guided fuzzer with instrumentation.
6. Analyze crashes and coverage reports.
7. Iterate (refine harness, seeds, and instrumentation).

### 2. Target Selection and Preparation

1. Inspect sandbox profiles under `/System/Volumes/Preboot/.../WebKit.framework/.../com.apple.WebKit.GPUProcess.sb`.
2. Enumerate allowed Mach services using Jonathan Levin’s `sbtool`:

   ```bash
   $ ./sbtool 2813 mach
   ```

3. Identify the `coreaudiod` daemon and locate its dependency on the CoreAudio framework:

   ```bash
   $ otool -L /usr/sbin/coreaudiod
   ```

4. Extract the `CoreAudio` binary from the dyld shared cache (e.g., using `dyld-shared-cache-extractor`).
5. Load `CoreAudio` into IDA Pro and list MIG subsystem symbols:

   ```bash
   $ nm -m CoreAudio | grep subsystem
   ```

### 3. MIG Subsystem Analysis

1. Identify the MIG server dispatch function (_e.g._, `_HALB_MIGServer_server`) by cross-referencing `_HALS_HALB_MIGServer_subsystem` in IDA.
2. On a live `coreaudiod` process (with SIP disabled), set an LLDB breakpoint to confirm the function’s invocation (_e.g._, observing `_XObject_HasProperty` when changing system volume).

### 4. Fuzzing Harness Construction

Build an in-process harness (`harness.mm`) that:

- Extracts the `_HALB_MIGServer_server` symbol at runtime via TinyInst’s Mach-O parser (from `p0tools/helpers/initialization.cc`).
- Reads raw Mach message bytes from input files.
- Calls the dispatch function directly:

  ```bash
  $ ./harness -f corpora/basic/1 -v
  ```

```cpp
// Example snippet from harness.mm
void runFuzz(uint8_t* data, size_t size) {
    // Resolve server function pointer
    auto handler = reinterpret_cast<server_func>(resolveSymbol("_HALB_MIGServer_server"));
    // Call the dispatch function
    handler(msg_request_port, msg, nullptr, nullptr);
}
```

### 5. Fuzzing with Jackalope

Seed the corpus by dumping messages via LLDB, then drive Jackalope with TinyInst instrumentation:

```bash
$ jackalope \
    -in in/ -out out/ \
    -delivery file \
    -instrument_module CoreAudio \
    -target_module harness \
    -target_method _fuzz \
    -nargs 1 \
    -iterations 1000 \
    -persist -loop \
    -dump_coverage -cmp_coverage \
    -generate_unwind \
    -nthreads 5 -- ./harness -f @@
```

The initial fuzzing run yields crashes, which guide harness refinement to satisfy CoreAudio’s initialization requirements.

## References

- Breaking the Sound Barrier Part I: Fuzzing CoreAudio with Mach Messages – Google Project Zero Blog: https://googleprojectzero.blogspot.com/2025/05/breaking-sound-barrier-part-i-fuzzing.html
- sbtool by Jonathan Levin: https://github.com/username/sbtool
- dyld-shared-cache-extractor: https://github.com/0xbb/dyld-shared-cache-extractor
- TinyInst: https://github.com/googleprojectzero/TinyInst
- Jackalope: https://github.com/googleprojectzero/jackalope

# eBPF Solana

This is a fork of https://github.com/Nalen98/eBPF-for-Ghidra and modified to
support Solana eBPF programs.

# Development
It is recommended to use Eclipse with the GhidraDev plugin for development.
See `${GHIDRA_INSTALLATION}/Extensions/Eclipse/GhidraDev/GhidraDev_README.html`
on how this works.

Once installed, go to `File > Open Projects from File System` and select this
directory. Click on `GhidraDev` in the menu bar and select `link ghidra`.
You now should be able to right click on the project and choose
`Run as > Ghidra` to start ghidra with the extension installed.

# Installation

- Download Release version of extension and install it in Ghidra `File → Install Extensions...` 
- Use gradle to build extension: `GHIDRA_INSTALL_DIR=${GHIDRA_HOME} gradle` and use Ghidra to install it: `File → Install Extensions...` 

# Known Issues
- Rebasing after a program has been imported might lead to messed up relocations.
  Everything should work as expected when specifying base address in import options.

# Useful links

* [Main source for how solana eBPF works](https://github.com/solana-labs/rbpf).
  Contains a disassembler, implements relocations, etc.
* [General Ghidra processor module resource](https://swarm.ptsecurity.com/creating-a-ghidra-processor-module-in-sleigh-using-v8-bytecode-as-an-example/).
  Covers implementing a processor module for V8 bytecode with lots of background
  info.


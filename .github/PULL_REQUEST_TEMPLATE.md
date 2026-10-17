## Description
Describe your changes and the rationale behind them.

## Related Issues
Closes #(issue number)

## Subsystem Checklist
- [ ] `kash-kernel` (`kernel/`)
- [ ] `kash-ui` (`kash-ui/`)
- [ ] `kblock` (`kblock/`)
- [ ] `kvault` (`kvault/`)
- [ ] `kscheduler` / `kpaging` / `kcore`
- [ ] Documentation / Scripts

## Verification & Testing
- [ ] `cargo check --target x86_64-unknown-none --manifest-path kernel/Cargo.toml` passes cleanly
- [ ] `cargo test --workspace --exclude kernel` passes (100%)
- [ ] Tested in VirtualBox or QEMU
- [ ] Zero dynamic heap allocations introduced in post-boot kernel paths
- [ ] Mathematical contracts and comments updated where applicable

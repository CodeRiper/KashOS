#!/usr/bin/env bash
set -u
check() {
    id="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "$id PRESENT (finding still true)"
    else
        echo "$id ABSENT (finding fixed or wrong)"
    fi
}

check F1 grep -q "Congratulations" kernel/src/net.rs
check F2 grep -q "Default Tor Exit" kernel/src/net.rs
check F3 grep -q "TcpState::Established" knet/src/lib.rs
check F4 bash -c '! grep -rq smoltcp --include=Cargo.toml .'
check F5 grep -q "pcr_bank" kernel/src/arch/x86_64/tpm.rs
check F6 grep -q "generating fresh master key" kernel/src/kms.rs
check F7 grep -q "Err(open_fail)" kernel/src/vfs.rs
check F8 grep -q "0x2000_0000" kernel/src/arch/x86_64/vtd.rs
check F9 grep -q "s.tpm2_crtm = crate::status::ComponentStatus::Real" kernel/src/selftest.rs
check F10 grep -q "gui::run" kernel/src/main.rs
check F11 grep -q "todo.txt" kash-ui/crates/kash-ui/src/apps/files.rs
check F12 grep -q "about:privacy" kernel/src/browser.rs

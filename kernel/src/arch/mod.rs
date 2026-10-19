//! Top-level arch re-export. Selects implementation at compile time.
//! Every other kernel module calls `crate::arch::*` — never the arch-specific path.

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    boot_stack_top, busy_delay, clear_screen, discover, enable_wx_paging, get_char, hw_entropy, init, kernel_end,
    kernel_sections, scan_pci, find_ahci, find_nic, find_audio, shutdown, zero_phys, probe_vbox, VirtualBoxProfile, AtaDriveInfo,
    init_vtd, get_iommu_status, init_tpm, get_tpm_status, init_input, poll_input_event, get_xhci_status, init_nic, nic_transmit, nic_receive, nic_mac, rdtsc,
    framebuffer, fill_gradient_test, clear_framebuffer, read_rtc_unix_seconds, elapsed_seconds, tsc_frequency_hz, sse_selftest,
    print_hardware_report, detect_hardware_tier, HardwareTier,
    print_pcr_report, print_tcg_event_log, print_anti_rollback_status, get_security_epoch, verify_and_ratify_epoch,
};

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    boot_stack_top, busy_delay, clear_screen, discover, enable_wx_paging, get_char, hw_entropy, init, kernel_end,
    kernel_sections, scan_pci, find_ahci, find_nic, find_audio, shutdown, zero_phys, probe_vbox, VirtualBoxProfile, AtaDriveInfo,
    init_vtd, get_iommu_status, init_input, poll_input_event, get_xhci_status, init_nic, nic_transmit, nic_receive, nic_mac, rdtsc,
    framebuffer, fill_gradient_test, clear_framebuffer, read_rtc_unix_seconds, elapsed_seconds, tsc_frequency_hz, sse_selftest,
};

#[cfg(target_arch = "x86_64")]  pub mod x86_64;
#[cfg(target_arch = "aarch64")] pub mod aarch64;

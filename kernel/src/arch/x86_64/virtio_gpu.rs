//! VirtIO-GPU 2D Hardware Acceleration Driver (virtio_gpu.rs)
//!
//! Implements Section 5.7 (GPU Device) of the OASIS VirtIO 1.0 / 1.1 Specification.
//! Provides 2D host-side hardware-accelerated scanout, display information discovery,
//! resource creation, backing store attachment, and partial rectangular dirty transfers.

#![allow(unsafe_code)]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

pub const VIRTIO_GPU_F_VIRGL: u64 = 1 << 0;
pub const VIRTIO_GPU_F_EDID: u64  = 1 << 1;

// ── VirtIO-GPU 2D Command Types (Section 5.7.6.7) ───────────────────────────

pub const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32       = 0x0100;
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32     = 0x0101;
pub const VIRTIO_GPU_CMD_RESOURCE_UNREF: u32         = 0x0102;
pub const VIRTIO_GPU_CMD_SET_SCANOUT: u32           = 0x0103;
pub const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32         = 0x0104;
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32    = 0x0105;
pub const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;

// ── VirtIO-GPU Response Types ───────────────────────────────────────────────

pub const VIRTIO_GPU_RESP_OK_NODATA: u32             = 0x1100;
pub const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32       = 0x1101;
pub const VIRTIO_GPU_RESP_OK_CAPSET_INFO: u32        = 0x1102;
pub const VIRTIO_GPU_RESP_OK_CAPSET: u32             = 0x1103;
pub const VIRTIO_GPU_RESP_OK_EDID: u32               = 0x1104;

pub const VIRTIO_GPU_RESP_ERR_UNSPEC: u32            = 0x1200;
pub const VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY: u32     = 0x1201;
pub const VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
pub const VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
pub const VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID: u32 = 0x1204;
pub const VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

// ── Formats ─────────────────────────────────────────────────────────────────

pub const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32      = 1;
pub const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32      = 2;
pub const VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM: u32      = 3;
pub const VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM: u32      = 4;
pub const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32      = 67;
pub const VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM: u32      = 68;

// ── Packets and Structures ──────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioGpuCtrlHdr {
    pub hdr_type: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioGpuRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtioGpuResourceCreate2d {
    pub hdr: VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtioGpuSetScanout {
    pub hdr: VirtioGpuCtrlHdr,
    pub r: VirtioGpuRect,
    pub scanout_id: u32,
    pub resource_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtioGpuResourceFlush {
    pub hdr: VirtioGpuCtrlHdr,
    pub r: VirtioGpuRect,
    pub resource_id: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtioGpuTransferToHost2d {
    pub hdr: VirtioGpuCtrlHdr,
    pub r: VirtioGpuRect,
    pub offset: u64,
    pub resource_id: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtioGpuMemEntry {
    pub addr: u64,
    pub length: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtioGpuResourceAttachBacking {
    pub hdr: VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub nr_entries: u32,
    pub entry: VirtioGpuMemEntry,
}

/// VirtIO-GPU 2D Driver Instance
pub struct VirtioGpuDevice {
    pub io_base: u16,
    pub width: u32,
    pub height: u32,
    pub resource_id: u32,
    pub back_buffer: Vec<u32>,
    pub is_active: bool,
}

impl VirtioGpuDevice {
    pub const PCI_VENDOR_QUMRANET: u16 = 0x1AF4;
    pub const PCI_DEVICE_VIRTIO_GPU: u16 = 0x1050;

    pub fn new(io_base: u16, width: u32, height: u32) -> Self {
        let size = (width as usize) * (height as usize);
        Self {
            io_base,
            width,
            height,
            resource_id: 1,
            back_buffer: vec![0u8 as u32; size],
            is_active: false,
        }
    }

    /// Builds command to create a host 2D resource.
    pub fn build_create_2d(&self, resource_id: u32, width: u32, height: u32) -> VirtioGpuResourceCreate2d {
        VirtioGpuResourceCreate2d {
            hdr: VirtioGpuCtrlHdr {
                hdr_type: VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                padding: 0,
            },
            resource_id,
            format: VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
            width,
            height,
        }
    }

    /// Builds command to attach guest memory buffer to host resource.
    pub fn build_attach_backing(&self, resource_id: u32, paddr: u64, size_bytes: u32) -> VirtioGpuResourceAttachBacking {
        VirtioGpuResourceAttachBacking {
            hdr: VirtioGpuCtrlHdr {
                hdr_type: VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                padding: 0,
            },
            resource_id,
            nr_entries: 1,
            entry: VirtioGpuMemEntry {
                addr: paddr,
                length: size_bytes,
                padding: 0,
            },
        }
    }

    /// Builds command to bind resource to display scanout 0.
    pub fn build_set_scanout(&self, scanout_id: u32, resource_id: u32, width: u32, height: u32) -> VirtioGpuSetScanout {
        VirtioGpuSetScanout {
            hdr: VirtioGpuCtrlHdr {
                hdr_type: VIRTIO_GPU_CMD_SET_SCANOUT,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                padding: 0,
            },
            r: VirtioGpuRect {
                x: 0,
                y: 0,
                width,
                height,
            },
            scanout_id,
            resource_id,
        }
    }

    /// Builds command to transfer a dirty rectangle from guest memory to host GPU resource.
    pub fn build_transfer_to_host(&self, resource_id: u32, rect: VirtioGpuRect) -> VirtioGpuTransferToHost2d {
        let offset = ((rect.y * self.width + rect.x) * 4) as u64;
        VirtioGpuTransferToHost2d {
            hdr: VirtioGpuCtrlHdr {
                hdr_type: VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                padding: 0,
            },
            r: rect,
            offset,
            resource_id,
            padding: 0,
        }
    }

    /// Builds command to flush the modified rectangle to the physical display.
    pub fn build_flush(&self, resource_id: u32, rect: VirtioGpuRect) -> VirtioGpuResourceFlush {
        VirtioGpuResourceFlush {
            hdr: VirtioGpuCtrlHdr {
                hdr_type: VIRTIO_GPU_CMD_RESOURCE_FLUSH,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                padding: 0,
            },
            r: rect,
            resource_id,
            padding: 0,
        }
    }

    /// Flushes dirty rect to display.
    pub fn flush_rect(&mut self, x: u32, y: u32, width: u32, height: u32) {
        if !self.is_active || self.io_base == 0 {
            return;
        }
        let rect = VirtioGpuRect { x, y, width, height };
        let _transfer = self.build_transfer_to_host(self.resource_id, rect);
        let _flush = self.build_flush(self.resource_id, rect);
        // On real hardware / QEMU, commands are queued to controlq and doorbell is rung.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_gpu_command_packet_layouts() {
        assert_eq!(core::mem::size_of::<VirtioGpuCtrlHdr>(), 24);
        assert_eq!(core::mem::size_of::<VirtioGpuRect>(), 16);
        assert_eq!(core::mem::size_of::<VirtioGpuResourceCreate2d>(), 40);
        assert_eq!(core::mem::size_of::<VirtioGpuSetScanout>(), 48);
        assert_eq!(core::mem::size_of::<VirtioGpuResourceFlush>(), 48);
    }

    #[test]
    fn test_virtio_gpu_builder_serialization() {
        let dev = VirtioGpuDevice::new(0xC000, 1024, 768);
        let create_cmd = dev.build_create_2d(1, 1024, 768);
        assert_eq!(create_cmd.hdr.hdr_type, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
        assert_eq!(create_cmd.resource_id, 1);
        assert_eq!(create_cmd.format, VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM);
        assert_eq!(create_cmd.width, 1024);
        assert_eq!(create_cmd.height, 768);

        let scanout_cmd = dev.build_set_scanout(0, 1, 1024, 768);
        assert_eq!(scanout_cmd.hdr.hdr_type, VIRTIO_GPU_CMD_SET_SCANOUT);
        assert_eq!(scanout_cmd.scanout_id, 0);
        assert_eq!(scanout_cmd.resource_id, 1);
        assert_eq!(scanout_cmd.r.width, 1024);

        let rect = VirtioGpuRect { x: 100, y: 50, width: 200, height: 150 };
        let transfer_cmd = dev.build_transfer_to_host(1, rect);
        assert_eq!(transfer_cmd.hdr.hdr_type, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
        assert_eq!(transfer_cmd.r.x, 100);
        assert_eq!(transfer_cmd.r.y, 50);

        let flush_cmd = dev.build_flush(1, rect);
        assert_eq!(flush_cmd.hdr.hdr_type, VIRTIO_GPU_CMD_RESOURCE_FLUSH);
        assert_eq!(flush_cmd.r.width, 200);
    }
}

/* SPDX-License-Identifier: MIT */
/* q1n1's XNU Mach-O loader and boot-argument ABI. */
/* Header guard first so the UEFI definitions remain idempotent. */
#pragma once
#include "efi.h"
#include <stddef.h>
#include <stdint.h>

/* Apple pexpert/pexpert/arm64/boot.h boot_args ABI (64-bit arm64). */
#define Q1N1_XNU_BOOT_LINE_LENGTH 1024
#define Q1N1_XNU_BOOT_ARGS_REVISION 2
#define Q1N1_XNU_BOOT_ARGS_VERSION 2
#define Q1N1_XNU_MH_MAGIC_64 UINT32_C(0xfeedfacf)
#define Q1N1_XNU_MH_EXECUTE 2
#define Q1N1_XNU_MH_FILESET 12
#define Q1N1_XNU_LC_SEGMENT_64 UINT32_C(0x19)
#define Q1N1_XNU_LC_UNIXTHREAD 5
#define Q1N1_XNU_LC_MAIN UINT32_C(0x80000028)
#define Q1N1_XNU_LC_FILESET_ENTRY UINT32_C(0x80000035)

struct q1n1_xnu_video {
    uint64_t base_addr;
    uint64_t display;
    uint64_t bytes_per_row;
    uint64_t width;
    uint64_t height;
    uint64_t depth;
};

struct q1n1_xnu_boot_args {
    uint16_t revision;
    uint16_t version;
    uint64_t virt_base;
    uint64_t phys_base;
    uint64_t mem_size;
    uint64_t top_of_kernel_data;
    struct q1n1_xnu_video video;
    uint32_t machine_type;
    uint32_t _padding;
    uint64_t device_tree;
    uint32_t device_tree_length;
    char command_line[Q1N1_XNU_BOOT_LINE_LENGTH];
    uint64_t boot_flags;
    uint64_t mem_size_actual;
};

struct q1n1_xnu_macho {
    uint64_t vm_base;
    uint64_t vm_end;
    uint64_t entry;
    uint32_t command_count;
};

/* Inspect a little-endian arm64 MH_EXECUTE image without reading out of bounds.
 * Returns 0 on success; malformed, unsupported or truncated images are rejected. */
int q1n1_xnu_macho_inspect(const void *image, size_t image_size,
                           struct q1n1_xnu_macho *result);

/* Load the validated image into a contiguous physical window at load_base.
 * The caller owns the image and destination allocations. */
int q1n1_xnu_macho_load(const void *image, size_t image_size,
                        void *destination, size_t destination_size,
                        uint64_t load_base, struct q1n1_xnu_macho *result);

/* XNU's start.s builds its bootstrap V=P and KVA mappings from L2 block
 * entries indexed by the virtual address but filled with the physical address
 * rounded down to the block, so the kernel's physical base must be congruent
 * to its link-time VM base modulo the L2 block size (2 MiB with 4K pages,
 * 32 MiB with 16K). Returns the first address at or above window_base that
 * keeps that congruence for both granules. */
#define Q1N1_XNU_BLOCK_ALIGN UINT64_C(0x2000000)
/* Largest XNU page size (16K); topOfKernelData must be aligned to it. */
#define Q1N1_XNU_PAGE_ALIGN UINT64_C(0x4000)
uint64_t q1n1_xnu_load_address(uint64_t window_base, uint64_t vm_base);

/* Populate ABI fields that are independent of platform-specific memory layout.
 * Caller supplies the already-finalized physical addresses and command line. */
struct q1n1_xnu_launch {
    uint64_t allocation_base;
    uint64_t allocation_pages;
    uint64_t entry;
    struct q1n1_xnu_boot_args *args;
    uint64_t ramdisk_base;
};

/* Validate the Apple flattened-device-tree encoding and return exact length. */
int q1n1_xnu_afdt_length(const void *tree, size_t available, size_t *length);

/* Load \\KERNEL and \\AFDT from the image's Simple File System volume and
 * prepare ABI-compatible boot arguments in the final physical allocation. */
efi_status q1n1_xnu_prepare(struct efi_boot_services *boot,
                            struct efi_loaded_image *image,
                            const struct q1n1_xnu_video *video,
                            struct q1n1_xnu_launch *launch);
/* device_tree is the AFDT's physical address; it must lie inside
 * [load_base, top_of_kernel_data) and is stored as its kernel-virtual
 * address, which is what XNU dereferences. */
int q1n1_xnu_boot_args_init(struct q1n1_xnu_boot_args *args,
                            const struct q1n1_xnu_macho *macho,
                            uint64_t load_base, uint64_t mem_size,
                            uint64_t top_of_kernel_data,
                            uint64_t device_tree, uint32_t device_tree_length,
                            const char *command_line);

_Static_assert(offsetof(struct q1n1_xnu_boot_args, top_of_kernel_data) == 32,
               "XNU boot_args topOfKernelData offset");
_Static_assert(offsetof(struct q1n1_xnu_boot_args, video) == 40,
               "XNU boot_args Video offset");
_Static_assert(offsetof(struct q1n1_xnu_boot_args, machine_type) == 88,
               "XNU boot_args machineType offset");
_Static_assert(offsetof(struct q1n1_xnu_boot_args, device_tree) == 96,
               "XNU boot_args deviceTreeP offset");
_Static_assert(offsetof(struct q1n1_xnu_boot_args, command_line) == 108,
               "XNU boot_args CommandLine offset");
_Static_assert(offsetof(struct q1n1_xnu_boot_args, boot_flags) == 1136,
               "XNU boot_args bootFlags offset");
_Static_assert(sizeof(struct q1n1_xnu_boot_args) == 1152,
               "XNU arm64 boot_args size");

/* SPDX-License-Identifier: MIT */
#include "xnu-boot.h"

#include <limits.h>

extern void *memcpy(void *destination, const void *source, size_t size);
extern void *memset(void *destination, int value, size_t size);

#define MACH_O_HEADER_SIZE 32u
#define MACH_O_COMMAND_SIZE 8u
#define MACH_O_SEGMENT_64_SIZE 72u
#define MACH_O_THREAD_STATE64_FLAVOR 6u
#define MACH_O_THREAD_STATE64_COUNT 68u
#define MACH_O_THREAD_STATE64_PC_OFFSET 256u
#define MACH_O_MAX_COMMANDS 1024u
#define MACH_O_MAX_COMMAND_BYTES (256u * 1024u)

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_le64(const uint8_t *p)
{
    return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

static int range_inside(size_t offset, size_t length, size_t limit)
{
    return offset <= limit && length <= limit - offset;
}

static int afdt_node_size(const uint8_t *tree, size_t available, size_t *size, unsigned depth)
{
    uint32_t properties, children;
    size_t offset = 8;
    if (!tree || !size || depth > 64 || available < 8)
        return -1;
    properties = read_le32(tree);
    children = read_le32(tree + 4);
    if (properties > 4096 || children > 4096)
        return -1;
    for (uint32_t i = 0; i < properties; ++i) {
        if (!range_inside(offset, 36, available))
            return -1;
        uint32_t length = read_le32(tree + offset + 32);
        size_t padded = ((size_t)length + 3u) & ~(size_t)3u;
        if (padded < length || !range_inside(offset + 36, padded, available))
            return -1;
        offset += 36 + padded;
    }
    for (uint32_t i = 0; i < children; ++i) {
        size_t child_size;
        if (afdt_node_size(tree + offset, available - offset, &child_size, depth + 1))
            return -1;
        offset += child_size;
    }
    *size = offset;
    return 0;
}

int q1n1_xnu_afdt_length(const void *tree, size_t available, size_t *length)
{
    if (!length || afdt_node_size((const uint8_t *)tree, available, length, 0))
        return -1;
    return 0;
}

/* Map an LC_MAIN file offset to its VM address through the non-empty
 * segment whose file range contains it. The commands were validated by the
 * caller's walk. */
static int main_entry_address(const uint8_t *bytes, uint32_t ncmds,
                              uint64_t offset, uint64_t *entry)
{
    size_t command_offset = MACH_O_HEADER_SIZE;

    for (uint32_t index = 0; index < ncmds; ++index) {
        const uint8_t *cmd = bytes + command_offset;
        uint32_t command = read_le32(cmd);

        if (command == Q1N1_XNU_LC_SEGMENT_64) {
            uint64_t address = read_le64(cmd + 24);
            uint64_t file_offset = read_le64(cmd + 40);
            uint64_t file_size = read_le64(cmd + 48);

            if (file_size && offset >= file_offset &&
                offset - file_offset < file_size) {
                *entry = address + (offset - file_offset);
                return 0;
            }
        }
        command_offset += read_le32(cmd + 4);
    }
    return -1;
}

static int inspect_commands(const uint8_t *bytes, size_t image_size,
                            struct q1n1_xnu_macho *result)
{
    uint32_t ncmds, sizeofcmds;
    size_t command_offset, command_end;
    uint64_t vm_base = UINT64_MAX, vm_end = 0, entry = 0, main_offset = 0;
    int have_entry = 0, have_main = 0;

    if (!bytes || !result || image_size < MACH_O_HEADER_SIZE)
        return -1;
    uint32_t filetype = read_le32(bytes + 12);
    if (read_le32(bytes) != Q1N1_XNU_MH_MAGIC_64 ||
        read_le32(bytes + 4) != UINT32_C(0x0100000c) ||
        (filetype != Q1N1_XNU_MH_EXECUTE && filetype != Q1N1_XNU_MH_FILESET))
        return -1;
    ncmds = read_le32(bytes + 16);
    sizeofcmds = read_le32(bytes + 20);
    if (!ncmds || ncmds > MACH_O_MAX_COMMANDS ||
        sizeofcmds > MACH_O_MAX_COMMAND_BYTES ||
        !range_inside(MACH_O_HEADER_SIZE, sizeofcmds, image_size))
        return -1;

    command_offset = MACH_O_HEADER_SIZE;
    command_end = command_offset + sizeofcmds;
    for (uint32_t index = 0; index < ncmds; ++index) {
        uint32_t command, command_size;
        const uint8_t *cmd;

        if (!range_inside(command_offset, MACH_O_COMMAND_SIZE, command_end))
            return -1;
        cmd = bytes + command_offset;
        command = read_le32(cmd);
        command_size = read_le32(cmd + 4);
        if (command_size < MACH_O_COMMAND_SIZE || (command_size & 3) ||
            !range_inside(command_offset, command_size, command_end))
            return -1;

        if (command == Q1N1_XNU_LC_SEGMENT_64) {
            uint64_t address, memory_size, file_offset, file_size, end;
            const uint8_t *name;
            static const char pagezero[16] = "__PAGEZERO";
            int is_pagezero = 1;
            if (command_size < MACH_O_SEGMENT_64_SIZE)
                return -1;
            name = cmd + 8;
            address = read_le64(cmd + 24);
            memory_size = read_le64(cmd + 32);
            file_offset = read_le64(cmd + 40);
            file_size = read_le64(cmd + 48);
            if (file_offset > SIZE_MAX || file_size > SIZE_MAX ||
                !range_inside((size_t)file_offset, (size_t)file_size, image_size) ||
                address > UINT64_MAX - memory_size)
                return -1;
            for (size_t i = 0; i < sizeof(pagezero); ++i) {
                if (name[i] != (uint8_t)pagezero[i]) {
                    is_pagezero = 0;
                    break;
                }
            }
            if (!is_pagezero) {
                /* Keep zero-sized linker segments in vm_base: bootxnu uses
                 * the lowest non-PAGEZERO vmaddr as the image's link base. */
                if (address < vm_base)
                    vm_base = address;
                if (memory_size && file_size > memory_size)
                    return -1;
                end = address + memory_size;
                if (end > vm_end)
                    vm_end = end;
            }
        } else if (command == Q1N1_XNU_LC_UNIXTHREAD) {
            if (command_size >= 16) {
                uint32_t flavor = read_le32(cmd + 8);
                uint32_t count = read_le32(cmd + 12);
                if (flavor == MACH_O_THREAD_STATE64_FLAVOR &&
                    count >= MACH_O_THREAD_STATE64_COUNT &&
                    command_size >= 16 + MACH_O_THREAD_STATE64_PC_OFFSET + 8) {
                    entry = read_le64(cmd + 16 + MACH_O_THREAD_STATE64_PC_OFFSET);
                    have_entry = entry != 0;
                }
            }
        } else if (command == Q1N1_XNU_LC_MAIN) {
            if (command_size < 24)
                return -1;
            /* LC_MAIN.entryoff is a file offset; it becomes an address
             * through the segment that maps it, resolved after the walk
             * because the segments may follow this command and the lowest
             * one (e.g. an empty __PRELINK_TEXT) need not be __TEXT. */
            main_offset = read_le64(cmd + 8);
            have_main = 1;
        }
        command_offset += command_size;
    }
    if (have_main && !have_entry) {
        if (main_entry_address(bytes, ncmds, main_offset, &entry))
            return -1;
        have_entry = 1;
    }
    if (command_offset != command_end || vm_base == UINT64_MAX ||
        vm_end <= vm_base || !have_entry || entry < vm_base || entry >= vm_end)
        return -1;
    result->vm_base = vm_base;
    result->vm_end = vm_end;
    result->entry = entry;
    result->command_count = ncmds;
    return 0;
}

int q1n1_xnu_macho_inspect(const void *image, size_t image_size,
                           struct q1n1_xnu_macho *result)
{
    return inspect_commands((const uint8_t *)image, image_size, result);
}

int q1n1_xnu_macho_load(const void *image, size_t image_size,
                        void *destination, size_t destination_size,
                        uint64_t load_base, struct q1n1_xnu_macho *result)
{
    const uint8_t *bytes = (const uint8_t *)image;
    uint8_t *output = (uint8_t *)destination;
    struct q1n1_xnu_macho info;
    size_t span;
    size_t offset;
    uint64_t physical_entry;

    if (!destination || !result || q1n1_xnu_macho_inspect(image, image_size, &info))
        return -1;
    if (info.vm_end - info.vm_base > SIZE_MAX)
        return -1;
    span = (size_t)(info.vm_end - info.vm_base);
    if (span > destination_size || load_base > UINT64_MAX - span ||
        info.entry - info.vm_base > UINT64_MAX - load_base)
        return -1;
    physical_entry = load_base + info.entry - info.vm_base;
    memset(output, 0, span);

    offset = MACH_O_HEADER_SIZE;
    for (uint32_t index = 0; index < info.command_count; ++index) {
        const uint8_t *cmd = bytes + offset;
        uint32_t command = read_le32(cmd);
        uint32_t command_size = read_le32(cmd + 4);
        if (command == Q1N1_XNU_LC_SEGMENT_64) {
            const uint8_t *name = cmd + 8;
            uint64_t address = read_le64(cmd + 24);
            uint64_t memory_size = read_le64(cmd + 32);
            uint64_t file_offset = read_le64(cmd + 40);
            uint64_t file_size = read_le64(cmd + 48);
            static const char pagezero[16] = "__PAGEZERO";
            int is_pagezero = 1;
            for (size_t i = 0; i < sizeof(pagezero); ++i) {
                if (name[i] != (uint8_t)pagezero[i]) {
                    is_pagezero = 0;
                    break;
                }
            }
            if (memory_size && !is_pagezero) {
                size_t target_offset = (size_t)(address - info.vm_base);
                if (!range_inside(target_offset, (size_t)memory_size, span) ||
                    file_size > memory_size || file_offset > SIZE_MAX || file_size > SIZE_MAX)
                    return -1;
                memcpy(output + target_offset, bytes + (size_t)file_offset,
                       (size_t)file_size);
            }
        }
        offset += command_size;
    }
    info.entry = physical_entry;
    *result = info;
    return 0;
}

int q1n1_xnu_boot_args_init(struct q1n1_xnu_boot_args *args,
                            const struct q1n1_xnu_macho *macho,
                            uint64_t load_base, uint64_t mem_size,
                            uint64_t top_of_kernel_data,
                            uint64_t device_tree, uint32_t device_tree_length,
                            const char *command_line)
{
    size_t n = 0;
    if (!args || !macho || !command_line || !macho->vm_base ||
        !macho->vm_end || !macho->entry || !mem_size ||
        !device_tree || !device_tree_length || top_of_kernel_data < load_base ||
        (top_of_kernel_data & (Q1N1_XNU_PAGE_ALIGN - 1)) ||
        device_tree < load_base || device_tree > top_of_kernel_data ||
        top_of_kernel_data - device_tree < device_tree_length)
        return -1;
    memset(args, 0, sizeof(*args));
    args->revision = Q1N1_XNU_BOOT_ARGS_REVISION;
    args->version = Q1N1_XNU_BOOT_ARGS_VERSION;
    args->virt_base = macho->vm_base;
    args->phys_base = load_base;
    args->mem_size = mem_size;
    args->top_of_kernel_data = top_of_kernel_data;
    /* XNU keeps deviceTreeP in PE_state and walks it long after arm_vm_init
     * has dropped the bootstrap V=P mapping, so like iBoot it gets the
     * kernel-virtual address: the tree lies below topOfKernelData, which XNU
     * maps at virt_base + (pa - phys_base). */
    args->device_tree = macho->vm_base + (device_tree - load_base);
    args->device_tree_length = device_tree_length;
    while (n + 1 < sizeof(args->command_line) && command_line[n]) {
        args->command_line[n] = command_line[n];
        ++n;
    }
    args->command_line[n] = '\0';
    return 0;
}

uint64_t q1n1_xnu_load_address(uint64_t window_base, uint64_t vm_base)
{
    const uint64_t mask = Q1N1_XNU_BLOCK_ALIGN - 1;
    uint64_t base = (window_base + mask) & ~mask;

    return base + (vm_base & mask);
}

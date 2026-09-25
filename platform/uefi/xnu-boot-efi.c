/* SPDX-License-Identifier: MIT */
#include "xnu-boot.h"

extern void *memcpy(void *destination, const void *source, size_t size);
extern void *memset(void *destination, int value, size_t size);

#define EFI_ALLOCATE_ANY_PAGES 0u
#define EFI_ALLOCATE_ADDRESS 2u
#define EFI_READ_ONLY 1u
#define XNU_LOAD_BASE UINT64_C(0x48000000)
#define XNU_MANAGED_END UINT64_C(0x80000000)
#define XNU_PANIC_LOG_SIZE UINT64_C(0x80000)
#define XNU_RAMDISK_BASE UINT64_C(0x58000000)
#define XNU_RAMDISK_SIZE UINT64_C(0x1000)
#define XNU_MAX_KERNEL_SIZE UINT64_C(0x20000000)
#define XNU_MAX_AFDT_SIZE UINT64_C(0x100000)
#define PAGE_SIZE UINT64_C(4096)
#define PAGE_MASK (PAGE_SIZE - 1)

static efi_guid simple_file_system_guid = {
    0x964e5b22, 0x6459, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}
};
static efi_guid file_info_guid = {
    0x09576e92, 0x6d3f, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}
};

static efi_status get_file_size(struct efi_file *file, uint64_t *size)
{
    uint64_t info[128];
    uint64_t bytes = sizeof(info);
    efi_status status;
    if (!file || !size || !file->get_info)
        return EFI_INVALID_PARAMETER;
    status = file->get_info(file, &file_info_guid, &bytes, info);
    if (status)
        return status;
    if (bytes < 80 || bytes > sizeof(info) || info[0] < 80 || info[0] > bytes ||
        (info[9] & 0x10))
        return EFI_INVALID_PARAMETER;
    *size = info[1];
    return 0;
}

static efi_status read_file_exact(struct efi_file *file, void *buffer, uint64_t size)
{
    uint8_t *out = (uint8_t *)buffer;
    uint64_t remaining = size;
    while (remaining) {
        uint64_t wanted = remaining > UINT64_C(1048576) ? UINT64_C(1048576) : remaining;
        uint64_t got = wanted;
        efi_status status = file->read(file, &got, out);
        if (status)
            return status;
        if (!got || got > wanted)
            return EFI_INVALID_PARAMETER;
        remaining -= got;
        out += got;
    }
    uint8_t extra;
    uint64_t got = 1;
    efi_status status = file->read(file, &got, &extra);
    if (status)
        return status;
    return got ? EFI_INVALID_PARAMETER : 0;
}

static efi_status load_file(struct efi_boot_services *boot, struct efi_file *root,
                            const char16 *path, uint64_t max_size,
                            uint64_t *address, uint64_t *size)
{
    struct efi_file *file = 0;
    efi_status status;
    uint64_t pages;
    *address = 0;
    *size = 0;
    status = root->open(root, &file, path, EFI_READ_ONLY, 0);
    if (status)
        return status;
    if (!file)
        return EFI_INVALID_PARAMETER;
    status = get_file_size(file, size);
    if (status)
        goto done;
    if (!*size || *size > max_size) {
        status = EFI_INVALID_PARAMETER;
        goto done;
    }
    pages = (*size + PAGE_MASK) / PAGE_SIZE;
    status = boot->allocate_pages(EFI_ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, pages, address);
    if (status)
        goto done;
    status = read_file_exact(file, (void *)(uintptr_t)*address, *size);
    if (status) {
        boot->free_pages(*address, pages);
        *address = 0;
    }
done:
    file->close(file);
    return status;
}

static void release_pages(struct efi_boot_services *boot, uint64_t *address, uint64_t pages)
{
    if (*address) {
        boot->free_pages(*address, pages);
        *address = 0;
    }
}

static uint64_t align_up(uint64_t value, uint64_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

efi_status q1n1_xnu_prepare(struct efi_boot_services *boot,
                            struct efi_loaded_image *image,
                            const struct q1n1_xnu_video *video,
                            struct q1n1_xnu_launch *launch)
{
    static const char16 kernel_path[] = {'\\', 'K', 'E', 'R', 'N', 'E', 'L', 0};
    static const char16 afdt_path[] = {'\\', 'A', 'F', 'D', 'T', 0};
    static const char command_line[] =
        "rd=md0 -v serial=3 debug=0x14e keepsyms=1 serial-device-name=uart0";
    struct efi_simple_fs *fs = 0;
    struct efi_file *root = 0;
    uint64_t kernel = 0, kernel_size = 0, afdt = 0, afdt_size = 0;
    uint64_t target = 0, target_pages = 0, ramdisk = 0, ramdisk_address, load_address;
    size_t afdt_length = 0, image_span, args_offset, tree_offset;
    uint64_t allocation_bytes, mem_size;
    struct q1n1_xnu_macho inspected, loaded;
    efi_status status;

    if (!boot || !image || !image->device || !launch)
        return EFI_INVALID_PARAMETER;
    memset(launch, 0, sizeof(*launch));
    status = boot->handle_protocol(image->device, &simple_file_system_guid, (void **)&fs);
    if (status)
        return status;
    if (!fs || !fs->open_volume)
        return EFI_INVALID_PARAMETER;
    status = fs->open_volume(fs, &root);
    if (status)
        return status;
    if (!root)
        return EFI_INVALID_PARAMETER;
    if (!root || !root->open || !root->close || !root->read || !root->get_info) {
        status = EFI_UNSUPPORTED;
        goto done;
    }

    status = load_file(boot, root, kernel_path, XNU_MAX_KERNEL_SIZE, &kernel, &kernel_size);
    if (status)
        goto done;
    status = load_file(boot, root, afdt_path, XNU_MAX_AFDT_SIZE, &afdt, &afdt_size);
    if (status)
        goto done;
    if (q1n1_xnu_macho_inspect((const void *)(uintptr_t)kernel, (size_t)kernel_size, &inspected) ||
        q1n1_xnu_afdt_length((const void *)(uintptr_t)afdt, (size_t)afdt_size, &afdt_length) ||
        afdt_length != afdt_size) {
        status = EFI_INVALID_PARAMETER;
        goto done;
    }
    if (inspected.vm_end - inspected.vm_base > SIZE_MAX ||
        inspected.vm_end - inspected.vm_base > XNU_MAX_KERNEL_SIZE) {
        status = EFI_INVALID_PARAMETER;
        goto done;
    }
    image_span = (size_t)(inspected.vm_end - inspected.vm_base);
    args_offset = (size_t)align_up(image_span, 16);
    tree_offset = args_offset + sizeof(struct q1n1_xnu_boot_args);
    allocation_bytes = align_up((uint64_t)tree_offset + afdt_size, UINT64_C(0x10000));
    load_address = q1n1_xnu_load_address(XNU_LOAD_BASE, inspected.vm_base);
    if (allocation_bytes > UINT64_MAX - load_address ||
        load_address + allocation_bytes > XNU_MANAGED_END - XNU_PANIC_LOG_SIZE ||
        load_address + allocation_bytes > XNU_RAMDISK_BASE) {
        status = EFI_INVALID_PARAMETER;
        goto done;
    }
    target_pages = (allocation_bytes + PAGE_MASK) / PAGE_SIZE;
    target = load_address;
    status = boot->allocate_pages(EFI_ALLOCATE_ADDRESS, EFI_LOADER_DATA, target_pages, &target);
    if (status)
        goto done;
    if (target != load_address) {
        status = EFI_INVALID_PARAMETER;
        goto failed_target;
    }

    if (q1n1_xnu_macho_load((const void *)(uintptr_t)kernel, (size_t)kernel_size,
                            (void *)(uintptr_t)target, image_span, target, &loaded)) {
        status = EFI_INVALID_PARAMETER;
        goto failed_target;
    }
    struct q1n1_xnu_boot_args *args = (void *)(uintptr_t)(target + args_offset);
    uint64_t afdt_address = target + tree_offset;
    mem_size = XNU_MANAGED_END - target - XNU_PANIC_LOG_SIZE;
    /* XNU carves its first page tables from topOfKernelData, so it must be
     * the page-aligned end of everything placed here (kernel, boot_args,
     * AFDT), never the AFDT itself. allocation_bytes is 64 KiB-aligned. */
    if (q1n1_xnu_boot_args_init(args, &inspected, target, mem_size,
                                target + allocation_bytes, afdt_address, (uint32_t)afdt_size,
                                command_line)) {
        status = EFI_INVALID_PARAMETER;
        goto failed_target;
    }
    if (video)
        args->video = *video;
    memcpy((void *)(uintptr_t)afdt_address, (const void *)(uintptr_t)afdt, afdt_length);

    /* The QEMU AFDT describes a 4 KiB RAMDisk at this address. Reserve and
     * clear it so XNU cannot allocate over the placeholder while probing it. */
    ramdisk_address = XNU_RAMDISK_BASE;
    status = boot->allocate_pages(EFI_ALLOCATE_ADDRESS, EFI_LOADER_DATA,
                                  XNU_RAMDISK_SIZE / PAGE_SIZE, &ramdisk_address);
    if (status)
        goto failed_target;
    if (ramdisk_address != XNU_RAMDISK_BASE) {
        boot->free_pages(ramdisk_address, XNU_RAMDISK_SIZE / PAGE_SIZE);
        status = EFI_INVALID_PARAMETER;
        goto failed_target;
    }
    ramdisk = ramdisk_address;
    memset((void *)(uintptr_t)ramdisk, 0, (size_t)XNU_RAMDISK_SIZE);

    launch->allocation_base = target;
    launch->allocation_pages = target_pages;
    launch->entry = loaded.entry;
    launch->ramdisk_base = ramdisk;
    launch->args = args;
    status = 0;
    goto done;

failed_target:
    if (ramdisk)
        boot->free_pages(ramdisk, XNU_RAMDISK_SIZE / PAGE_SIZE);
    release_pages(boot, &target, target_pages);
done:
    if (kernel)
        boot->free_pages(kernel, (kernel_size + PAGE_MASK) / PAGE_SIZE);
    if (afdt)
        boot->free_pages(afdt, (afdt_size + PAGE_MASK) / PAGE_SIZE);
    if (root && root->close)
        root->close(root);
    return status;
}

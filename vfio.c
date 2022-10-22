#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <linux/vfio.h>

#include "vfio.h"


static char* region_name[VFIO_PCI_NUM_REGIONS] = {
    "BAR0", "BAR1", "BAR2", "BAR3", "BAR4", "BAR5", "ROM", "CONFIG", "VGA"};

static char* irq_name[VFIO_PCI_NUM_IRQS] = {"INTX", "MSI", "MISX", "ERR",
                                            "REQ"};
                                            
void get_device_info(struct device* dev) {
    int i;
    ioctl(dev->fd, VFIO_DEVICE_GET_INFO, &dev->device_info);

    debug("num_regions: %d", dev->device_info.num_regions);
    debug("flags = CAPS, MMAP, WRITE, READ");
    for (i = 0; i < dev->device_info.num_regions; i++) {
        dev->regs[i].index = i;
        ioctl(dev->fd, VFIO_DEVICE_GET_REGION_INFO, &dev->regs[i]);
        debug("region %d.flags = %d%d%d%d (%s)", i,
              !!(dev->regs[i].flags & VFIO_REGION_INFO_FLAG_CAPS),
              !!(dev->regs[i].flags & VFIO_REGION_INFO_FLAG_MMAP),
              !!(dev->regs[i].flags & VFIO_REGION_INFO_FLAG_WRITE),
              !!(dev->regs[i].flags & VFIO_REGION_INFO_FLAG_READ),
              region_name[i]);
    }

    debug("num_irqs: %d", dev->device_info.num_irqs);
    debug("flags = NORESIZE, AUTOMASKED, MASKABLE, NORESIZE");
    for (i = 0; i < dev->device_info.num_irqs; i++) {
        dev->irqs[i].index = i;
        ioctl(dev->fd, VFIO_DEVICE_GET_IRQ_INFO, &dev->irqs[i]);

        debug("IRQ info %d (%s)", i, irq_name[i]);
        debug("  irq.flags = %d%d%d%d",
              !!(dev->irqs[i].flags & VFIO_IRQ_INFO_NORESIZE),
              !!(dev->irqs[i].flags & VFIO_IRQ_INFO_AUTOMASKED),
              !!(dev->irqs[i].flags & VFIO_IRQ_INFO_MASKABLE),
              !!(dev->irqs[i].flags & VFIO_IRQ_INFO_EVENTFD));
        debug("  irq.index = %d", dev->irqs[i].index);
        debug("  irq.count = %d", dev->irqs[i].count);
    }
}

void open_vfio(struct device* dev, const char* pci_addr) {
    dev->device_info.argsz = sizeof(struct vfio_device_info);
    dev->group_status.argsz = sizeof(struct vfio_group_status);
    dev->iommu_info.argsz = sizeof(struct vfio_iommu_type1_info);
    for (int i = 0; i < VFIO_PCI_NUM_REGIONS; i++) {
        dev->regs[i].argsz = sizeof(struct vfio_region_info);
    }
    for (int i = 0; i < VFIO_PCI_NUM_IRQS; i++) {
        dev->irqs[i].argsz = sizeof(struct vfio_irq_info);
    }

    // find iommu group for the device
    // `readlink /sys/bus/pci/device/<segn:busn:devn.funcn>/iommu_group`
    char path[128], iommu_group_path[128];
    struct stat st;
    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/", pci_addr);
    int ret = stat(path, &st);
    ASSERT(ret >= 0, "No such device: %s", path);
    strncat(path, "iommu_group", sizeof(path) - strlen(path) - 1);

    int len = readlink(path, iommu_group_path, sizeof(iommu_group_path));
    ASSERT(len > 0, "No iommu_group for device");

    iommu_group_path[len] = '\0';
    char* group_name = basename(iommu_group_path);
    int groupid;
    ret = sscanf(group_name, "%d", &groupid);
    ASSERT(ret == 1, "unknown group");
    debug("group_id: %d", groupid);

    // open vfio file
    dev->cfd = open("/dev/vfio/vfio", O_RDWR);
    ASSERT(dev->cfd >= 0, "failed to open /dev/vfio/vfio");

    snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);
    dev->gfd = open(path, O_RDWR);
    ASSERT(dev->gfd >= 0, "failed to open %s", path);

    ret = ioctl(dev->gfd, VFIO_GROUP_GET_STATUS, &dev->group_status);
    ASSERT(
        dev->group_status.flags & VFIO_GROUP_FLAGS_VIABLE,
        "VFIO group is not visible (probably not all devices bound for vfio?)");

    // set container
    ret = ioctl(dev->gfd, VFIO_GROUP_SET_CONTAINER, &dev->cfd);
    ASSERT(ret == 0, "failed to set container");
    // set vfio type (type1 is for IOMMU like VT-d or AMD-Vi)
    ret = ioctl(dev->cfd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
    ASSERT(ret == 0, "failed to set iommu type");

    // get device descriptor
    snprintf(path, sizeof(path), "%s", pci_addr);
    dev->fd = ioctl(dev->gfd, VFIO_GROUP_GET_DEVICE_FD, path);
    ASSERT(dev->fd >= 0, "cannot get device fd");
}

void dump_configuration_space(struct device* dev) {
    char buf[4096];
    struct vfio_region_info* cs_info = &dev->regs[VFIO_PCI_CONFIG_REGION_INDEX];
    int ret = pread(dev->fd, buf, cs_info->size > 4096 ? 4096 : cs_info->size,
                    cs_info->offset);
    ASSERT(ret >= 0, "pread error");

    int len;
    for (len = ret - 1; len >= 0; len--) {
        if (buf[len] != 0)
            break;
    }
    len = (len + 16) - (len + 16) % 16;

    for (int i = 0; i < len;) {
        printf("%3X: ", i);
        for (int j = 0; j < 16 && i < len; i++, j++) {
            printf("%02X ", (u8)buf[i]);
        }
        printf("\n");
    }
}


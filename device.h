#include <linux/vfio.h>

struct tx_queue{
	struct tdesc* descriptors;
	struct mempool* mempool;
	uint16_t num_entries;
	uint16_t clean_index;
	uint16_t tx_index;
	void* virtual_addresses[];
};

struct rx_queue{
	struct rdesc* descriptors;   
	struct mempool* mempool;                      
	uint16_t num_entries;                        
	// position we are reading from
	uint16_t rx_index;                        
	// virtual addresses to map descriptors back to their mbuf for freeing
	void* virtual_addresses[];
};

struct device {
    //struct rdesc* rqueue;
    //struct tdesc* tqueue;
    const char* pci_addr;
    void* device_rx_queues;
    void* device_tx_queues;
    int fd;                         // VFIO device fd
    int gfd;                        // VFIO group fd
    int cfd;                        // VFIO container fd
    int efd;                        // event fd (for INTx, MSI)
    int efds[MAX_MSIX_VECTOR_NUM];  // event fd (for MSI-x)
    int epfd;                       // epoll fd
    struct vfio_device_info device_info;
    struct vfio_group_status group_status;
    struct vfio_iommu_type1_info iommu_info;
    struct vfio_region_info regs[VFIO_PCI_NUM_REGIONS];
    struct vfio_irq_info irqs[VFIO_PCI_NUM_IRQS];
    void* addr;  // mmio address (BAR0);
    
    uint64_t rx_pkts;
    uint64_t tx_pkts;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
};

static inline void write_u32(struct device* dev, int offset, uint32_t value) {
    __asm__ volatile("" : : : "memory");
    *((volatile uint32_t*)(dev->addr + offset)) = value;
}

static inline uint32_t read_u32(struct device* dev, int offset) {
    __asm__ volatile("" : : : "memory");
    return *((volatile uint32_t*)(dev->addr + offset));
}

static inline void set_flags_u32(struct device* dev, int offset,
                                 uint32_t flags) {
    write_u32(dev, offset, read_u32(dev, offset) | flags);
}

static inline void clear_flags_u32(struct device* dev, int offset,
                                   uint32_t flags) {
    write_u32(dev, offset, read_u32(dev, offset) & ~flags);
}
static uint32_t huge_pg_id;

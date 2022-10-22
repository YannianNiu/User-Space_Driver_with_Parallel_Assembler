#include <fcntl.h>
#include <linux/limits.h>
#include <linux/mman.h>
#include <linux/vfio.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>


#include "memory.h"


#define PKT_SIZE 60
#define BATCHSIZE 1024
#define NUM_OF_DESC 4096     //(Note that the variable must be power of 2)
#define NUM_ENTRIES 4096     //(same as above)

#define wrap_ring(index, ring_size) (uint16_t) ((index + 1) & (ring_size - 1))
const int TX_CLEAN_BATCH = 1024;
//#define MAP_HUGE_2MB (1 << 21)

static u64 get_iova(u64 virt_addr, ssize_t size) {
    static u64 _iova = 0;
#if defined(IDENTITY_MAP)
    // Use virtual address as IOVA
    // Note that some architecture only support 3-level page table (39-bit) and
    // cannot use virtual address as IOVA
    return virt_addr;
#elif defined(PHYSADDR_MAP)
    // Use physical address as IOVA
    return (u64)virt_to_phys(virt_addr);
#else
    // Assign IOVA from 0
    u64 ret = _iova;
    _iova += size;
    return ret;
#endif
}

uint64_t time_batch = 1000000000000;
#define MAX_MSIX_VECTOR_NUM 5
ssize_t MIN_DMA_MEMORY = 4096; // we can not allocate less than page_size memory

static uint8_t pkt_data[64] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst MAC
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, // src 
	0x08, 0x00,                         // ether type: IPv4
	0x45, 0x00,                         // Version, IHL, TOS
	(PKT_SIZE - 14) >> 8,               // ip len excluding ethernet, high byte
	(PKT_SIZE - 14) & 0xFF,             // ip len exlucding ethernet, low byte
	0x00, 0x00, 0x00, 0x00,             // id, flags, fragmentation
	0x40, 0x11, 0x00, 0x00,             // TTL (64), protocol (UDP), checksum
	0xC0, 0xA8, 0xFE, 0x1E,             // src ip (192.168.254.30)
	0xC0, 0xA8, 0xFE, 0x01,             // dst ip (192.168.254.1)
	0x0A, 0x00, 0x00, 0x02, 
	0x2C, 0x8C, 0x10, 0xE1,             // src and dst ports (11404 -> 4321)
	(PKT_SIZE - 20 - 14) >> 8,          // udp len excluding ip & ethernet, high byte
	(PKT_SIZE - 20 - 14) & 0xFF,        // udp len exlucding ip & ethernet, low byte
	0x00, 0x00,                         // udp checksum, optional
	'E', 'C', 'N', 'U'                  // payload
	// rest of the payload is zero-filled because mempools guarantee empty bufs
};

static uintptr_t virt_to_phys(void* virt) {
    long pagesize = sysconf(_SC_PAGESIZE);
    int fd = open("/proc/self/pagemap", O_RDONLY);
    ASSERT(fd != -1, "failed to open /proc/self/pagemap");
    off_t ret =
        lseek(fd, (uintptr_t)virt / pagesize * sizeof(uintptr_t), SEEK_SET);
    ASSERT(ret != -1, "lseek error");
    uintptr_t entry = 0;
    ssize_t rc = read(fd, &entry, sizeof(entry));
    ASSERT(rc > 0, "read error");
    ASSERT(entry != 0,
           "failed to get physical address for %p (perhaps forgot sudo?)",
           virt);
    close(fd);

    return (entry & 0x7fffffffffffffULL) * pagesize +
           ((uintptr_t)virt) % pagesize;
}

uint64_t vfio_map_dma(struct device* dev, void* vaddr, uint32_t size) {
	uint64_t iova = get_iova((u64)vaddr, size);//vaddr; // map iova to process virtual address 
	struct vfio_iommu_type1_dma_map dma_map = {
		.vaddr = (uint64_t) vaddr,
		.iova = iova,
		.size = size < MIN_DMA_MEMORY ? MIN_DMA_MEMORY : size,
		.argsz = sizeof(dma_map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE};
	//vfio get memory addresses mapped by IOMMU through VFIO_IOMMU_MAP_DMA, this is equivalent to the user-space driver directly using the iommu interface.
	debug("%d",dev->cfd);
	check_err(ioctl(dev -> cfd, VFIO_IOMMU_MAP_DMA, &dma_map), "IOMMU Map DMA Memory"); 
	//debug("i have done");
	return iova;
}

struct dma_memory memory_allocate_dma(struct device* dev, size_t size) {
	// VFIO == -1 means that there is no VFIO container set, i.e. VFIO / IOMMU is not activated
	debug("allocating dma memory via VFIO");
	void* virt_addr = (void*) check_err(mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB, -1, 0), "mmap hugepage");
	//MAP_HUGETLB | MAP_HUGE_2MB
	// create IOMMU mapping
	uint64_t iova = (uint64_t) vfio_map_dma(dev, virt_addr, size);
	debug("iova = %ld",iova);
	return (struct dma_memory){
		// for VFIO, this needs to point to the device view memory = IOVA!
		.virt = virt_addr,     //address returned by mmap
		.phy = iova            //address start from 0
	};
}

struct mempool* memory_allocate_mempool(struct device* dev, uint32_t num_entries, uint32_t entry_size) {
	entry_size = entry_size ? entry_size : 1024;
	debug("entry_size = %d",entry_size);
	//debug("allocate mempool，entry_size:%d,block size entry_size is:%d",num_entries,entry_size);
	// require entries that neatly fit into the page size, this makes the memory pool much easier
	// otherwise our base_addr + index * size formula would be wrong because we can't cross a page-boundary
	debug("in memory_allocate_mempool dev->cfd = %d",dev->cfd);
	if ((dev -> cfd == -1) && HUGE_PAGE_SIZE % entry_size) {
		error("entry size must be a divisor of the huge page size (%d)", HUGE_PAGE_SIZE);
		//size of huge_page_size is 2^21 = 2MB，size of entry_size is 2048，2^11 = 2kb.
		//entry is a memory block in mempool.
	}
	
	struct mempool* mempool = (struct mempool*) malloc(sizeof(struct mempool) + num_entries * sizeof(uint32_t));
	//struct mempool* mempool = (struct mempool*) mmap(NULL, sizeof(struct mempool) + num_entries*sizeof(uint32_t), 
	//PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB, -1, 0);
	struct dma_memory mem = memory_allocate_dma(dev, num_entries * entry_size);
	mempool->num_entries = num_entries; //2048
	mempool->buf_size = entry_size;     //2048
	mempool->base_addr = mem.virt; 
	mempool->free_stack_top = num_entries;   //the initial value of free_stack_top is 2048   
	for (uint32_t i = 0; i < num_entries; i++) {
		mempool->free_stack[i] = i;
		struct pkt_buf* buf = (struct pkt_buf*) (((uint8_t*) mempool->base_addr) + i * entry_size);
		// "physical" memory is iova address which is identity mapped to vaddr
		buf->buf_addr_phy = (uintptr_t) buf;
		buf->mempool_idx = i;
		buf->mempool = mempool;
		buf->size = 0;
	}
	return mempool;
}

static uint16_t calc_ip_checksum(uint8_t* data, uint32_t len) {
	if (len % 1) error("odd-sized checksums NYI");
	uint32_t cs = 0;
	for (uint32_t i = 0; i < len / 2; i++) {
		cs += ((uint16_t*)data)[i];
		if (cs > 0xFFFF) {
			cs = (cs & 0xFFFF) + 1; // 16 bit one's complement
		}
	}
	return ~((uint16_t) cs);
}

static struct mempool* init_mempool(struct device* dev, uint32_t num_entries, uint32_t entry_size) {

	const int NUM_BUFS = num_entries;
	struct mempool* mempool = memory_allocate_mempool(dev, num_entries, 0);  //allocate mempool in memory
	struct pkt_buf* bufs[NUM_BUFS];
	for (int buf_id = 0; buf_id < NUM_BUFS; buf_id++) {
		struct pkt_buf* buf = pkt_buf_alloc(mempool);
		buf->size = 0;  //60
		//nanosleep(&tim , NULL);
		//copy data from pkt_data to buf_data
		uint64_t last_time = monotonic_time();
		for(int i=0;i<4;i++)
	        {
	        //    nanosleep(&tim , NULL);
		    strncat(buf->data, pkt_data, 64);
		    buf->size += 256;
		    uint64_t this_time = monotonic_time();
			if(monotonic_time() - last_time > time_batch)
			    break;
		}
		memcpy(buf->data, pkt_data, sizeof(pkt_data)); //copy data from pkt_data to buf_data
		//*(uint16_t*) (buf->data + 24) = calc_ip_checksum(buf->data + 14, 20);
		bufs[buf_id] = buf;
		//printf("buf.data: %d buf.length:%d\n",bufs[i].data,bufs[i].size);
	}
	
	for (int buf_id = 0; buf_id < NUM_BUFS; buf_id++) {
		pkt_buf_free(bufs[buf_id]);
		
	}
	return mempool;
}


struct pkt_buf* pkt_buf_alloc(struct mempool* mempool) {
	struct pkt_buf* buf = NULL;
	pkt_buf_alloc_batch(mempool, &buf, 1);
	return buf;
}

uint32_t pkt_buf_alloc_batch(struct mempool* mempool, struct pkt_buf* bufs[], uint32_t num_bufs) {
	if (mempool->free_stack_top < num_bufs) {
		warn("memory pool %p only has %d free bufs, requested %d", mempool, mempool->free_stack_top, num_bufs);
		num_bufs = mempool->free_stack_top;
	}
	for (uint32_t i = 0; i < num_bufs; i++) {
		uint32_t entry_id = mempool->free_stack[--mempool->free_stack_top]; 
		bufs[i] = (struct pkt_buf*) (((uint8_t*) mempool->base_addr) + entry_id * mempool->buf_size);
	}
	return num_bufs;
}

void pkt_buf_free(struct pkt_buf* buf) {
        
	struct mempool* mempool = buf->mempool;
	
	mempool->free_stack[mempool->free_stack_top++] = buf->mempool_idx;
}

// Enable DMA
void enable_bus_master(struct device* dev) {
    struct vfio_region_info* cs_info = &dev->regs[VFIO_PCI_CONFIG_REGION_INDEX];
    char buf[2];
    pread(dev->fd, buf, 2, cs_info->offset + 4);
    *(u16*)(buf) |= 1 << 2;
    pwrite(dev->fd, buf, 2, cs_info->offset + 4);
    debug("PCI configuration space command reg = %04X\n", *(u16*)buf);
}

struct device* init_device(const char* pci_addr){
	struct device* dev = (struct device*) malloc(sizeof(struct device));
	dev->pci_addr = strdup(pci_addr);
	open_vfio(dev, pci_addr);
	get_device_info(dev);
#ifndef NDEBUG
    dump_configuration_space(dev);
#endif

	enable_bus_master(dev);
	struct vfio_region_info* bar0_info = &dev->regs[VFIO_PCI_BAR0_REGION_INDEX];
	dev->addr = mmap(NULL, bar0_info->size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, dev->fd, bar0_info->offset);
	ASSERT(dev->addr != MAP_FAILED, "mmap failed");
	//dev->device_rx_queues = calloc(1, sizeof(struct rx_queue) + sizeof(void*) * NUM_ENTRIES);
	dev->device_tx_queues = calloc(1, sizeof(struct tx_queue) + sizeof(void*) * NUM_ENTRIES);
	//init_rx_queue(dev);
	init_tx_queue(dev);
	debug("device = %p",dev);
	return dev;
}

void init_rx_queue(struct device* dev){
	uint32_t ring_size_bytes = NUM_OF_DESC * sizeof(struct rdesc);
	debug("allocate dma_memory for rx_queue");
	struct dma_memory mem = memory_allocate_dma(dev, ring_size_bytes);
	debug("done dma_memory for rx_queue");
	memset(mem.virt, -1, ring_size_bytes);
	write_u32(dev, RDBAL, (u32)(mem.phy & 0xFFFFFFFFull));
	write_u32(dev, RDBAH, (u32)(mem.phy >> 32));
	write_u32(dev, RDLEN, NUM_OF_DESC * sizeof(struct rdesc));
	struct rx_queue* queue = (struct rx_queue*) dev -> device_rx_queues;
	queue->num_entries = NUM_ENTRIES;
	queue->rx_index = 0;
	queue->descriptors = (struct rdesc*) mem.virt;
	debug("allocate mempool for rx_queue");
	
	queue->mempool = memory_allocate_mempool(dev, 4096, 2048);//(1024,2048)
	debug("done allocate mempool for rx_queue");
	for (int i = 0; i < queue->num_entries; i++) {
		struct rdesc* rxd = queue->descriptors;  
		struct pkt_buf* buf = pkt_buf_alloc(queue->mempool);
		if (!buf) {
			error("failed to allocate rx descriptor");
		}
		rxd->buffer = buf->buf_addr_phy; //+ offsetof(struct pkt_buf, data);
		//rxd->read.hdr_addr = 0;
		// we need to return the virtual address in the rx function which the descriptor doesn't know by default
		queue->virtual_addresses[i] = buf;
	}
	
	write_u32(dev, RDH, 0);
	write_u32(dev, RDT, NUM_OF_DESC - 1);
	// Enable receive
	write_u32(dev, RCTL,
              RCTL_EN |         /* Enable */
                  RCTL_UPE |    /* Unicast Promiscuous Enable*/
                  RCTL_MPE |    /* Multicast Promiscuous Enable */
                  RCTL_BSIZE1 | /* BSIZE == 11b => 4096 bytes (if BSEX = 1) */
                  RCTL_BSIZE2 | /* */
                  RCTL_LPE |    /* Long Packet Enable */
                  RCTL_BAM |    /* Broadcast Accept Mode */
                  RCTL_BSEX |   /* Buffer Size Extension */
                  RCTL_SECRC    /* Strip Ethernet CRC from incoming packet */
	);
}


void init_tx_queue(struct device* dev){
	uint32_t ring_size_bytes = NUM_OF_DESC * sizeof(struct tdesc);
	debug("allocate dma_memory for tx_queue");
	struct dma_memory mem = memory_allocate_dma(dev, ring_size_bytes);
	debug("done dma_memory for tx_queue");
	memset(mem.virt, -1, ring_size_bytes);
	write_u32(dev, TDBAL, (u32)(mem.phy & 0xFFFFFFFFull));
	write_u32(dev, TDBAH, (u32)(mem.phy >> 32));
	write_u32(dev, TDLEN, NUM_OF_DESC * sizeof(struct tdesc));
	struct tx_queue* queue = (struct tx_queue*) dev->device_tx_queues;
	queue->num_entries = NUM_ENTRIES;
	queue->descriptors = (struct tdesc*) mem.virt;
	
	write_u32(dev, TDH, 0);
	write_u32(dev, TDT, 0);
	//enable transmit	
	write_u32(dev, TCTL,
              TCTL_EN |    /* Enable */
                  TCTL_PSP /* Pad short packets */
	);	
}

uint32_t transmit(struct device* dev, struct pkt_buf* bufs[], uint32_t num_bufs) {
	//debug("in transmit");
        struct tx_queue* queue = dev->device_tx_queues;
        uint16_t clean_index = queue->clean_index; // next descriptor to clean up
        //debug("clean_index = %d",clean_index);
        while(true){
            int32_t cleanable = queue->tx_index - clean_index;
            if (cleanable < 0) // handle wrap-around
                cleanable = queue->num_entries + cleanable;
            //debug("cleanable = %d",cleanable);
            if (cleanable < TX_CLEAN_BATCH)
                break;
            int32_t cleanup_to = clean_index + TX_CLEAN_BATCH - 1;   //cleanup_to means the index in the ring to be cleaned in this round
            //debug("cleanup_to = %d",cleanup_to);
            if (cleanup_to >= queue->num_entries)
                cleanup_to -= queue->num_entries;
            //debug("cleanup_to = %d",cleanup_to);
            struct tdesc* txd = queue->descriptors + cleanup_to;
            //debug("read_u32(dev, GPTC) = %d",read_u32(dev, GPTC));
            //debug("%d",txd->dd);
            if (txd->dd) {
                int32_t i = clean_index;
                    while (true) {
                        struct pkt_buf* buf = queue->virtual_addresses[i];
                        pkt_buf_free(buf);
                        if (i == cleanup_to)
                            break;
                        i = wrap_ring(i, queue->num_entries);
                    }
                    // next descriptor to be cleaned up is one after the one we just cleaned
                    clean_index = wrap_ring(cleanup_to, queue->num_entries);
            } 
            else
	    // clean the whole batch or nothing; yes, this leaves some packets in
	    // the queue forever if you stop transmitting, but that's not a real concern
                break;
            //debug("read_u32(dev, GPTC) = %d",read_u32(dev, GPTC));
	}
	queue->clean_index = clean_index;
	//debug("queue->clean_index = %d",clean_index);
	uint32_t sent;
	for (sent = 0; sent < num_bufs; sent++) {
		//debug("sent = %u",sent);
		uint32_t next_index = wrap_ring(queue->tx_index, queue->num_entries);
		// we are full if the next index is the one we are trying to reclaim
		//debug("clean_index = %u, next_index = %u",clean_index,next_index);
		if (clean_index == next_index) {
			debug("break in line 341");
			break;
		}
		struct pkt_buf* buf = bufs[sent];
		// remember virtual address to clean it up later
		queue->virtual_addresses[queue->tx_index] = (void*) buf;
		struct tdesc* txd = queue->descriptors + queue->tx_index;
		queue->tx_index = next_index;
		txd->buffer = buf->buf_addr_phy + offsetof(struct pkt_buf, data);
        txd->length = 128;
        txd->ifcs = 1;  // insert FCS
        txd->eop = 1;   // end of packets
        txd->rs = 1;  // report status
        //debug("%d",txd->dd);
        //debug("%d",buf->size);
        dev->tx_bytes += buf->size;//buf->size;
		dev->tx_pkts++;
        //debug("read_u32(dev, GPTC) = %d",read_u32(dev, GPTC));
	}
	write_u32(dev, TDT, queue->tx_index % NUM_OF_DESC);
	//debug("read_u32(dev, GPTC) = %d",read_u32(dev, GPTC));
	return sent;
}

uint32_t receive(struct device* dev, struct pkt_buf* bufs[], uint32_t num_bufs) {
	struct rx_queue* queue = dev->device_rx_queues;
	uint16_t rx_index = queue->rx_index; // rx index we checked in the last run of this function
	
	uint16_t last_rx_index = rx_index; // index of the descriptor we checked in the last iteration of the loop
	uint32_t buf_index; 
	for (buf_index = 0; buf_index < num_bufs; buf_index++) {
            struct rdesc* rxd = queue->descriptors + rx_index;
            if (rxd->dd) {
                if (!(rxd->eop))
                    error("multi-segment packets are not supported - increase buffer size or decrease MTU");
                // got a packet, read and copy the whole descriptor
                struct rdesc desc = *rxd;
                struct pkt_buf* buf = (struct pkt_buf*) queue->virtual_addresses[rx_index]; //
                buf->size = desc.length;
                // this would be the place to implement RX offloading by translating the device-specific flags
                // to an independent representation in the buf (similiar to how DPDK works)
                // need a new mbuf for the descriptor
                struct pkt_buf* new_buf = pkt_buf_alloc(queue->mempool);
                if (!new_buf)
                    error("failed to allocate new mbuf for rx, you are either leaking memory or your mempool is too small");
                // reset the descriptor
                rxd->buffer = new_buf->buf_addr_phy + offsetof(struct pkt_buf, data); 
                // pkt_addr:physical address of messages, 
				// The network card writes the message data to the memory of the physical address through DMA
                queue->virtual_addresses[rx_index] = new_buf;
                bufs[buf_index] = buf;
                // want to read the next one in the next iteration, but we still need the last/current to update RDT later
                last_rx_index = rx_index;
                rx_index = wrap_ring(rx_index, queue->num_entries);
	    } 
	    else{
                break;
            }
	}
	if (rx_index != last_rx_index) {  
            // tell hardware that we are done
            // this is intentionally off by one, otherwise we'd set RDT=RDH if we are receiving faster than packets are coming in
            // RDT=RDH means queue is full
            write_u32(dev, RDT, last_rx_index);
            queue->rx_index = rx_index;
	}
	return buf_index; // number of packets stored in bufs; buf_index points to the next index
}



static void tx_batch_busy_wait(struct device* dev, struct pkt_buf* bufs[], uint32_t num_bufs) {
	uint32_t num_sent = 0;
	//pthread_mutex_lock(&mute);
	while ((num_sent += transmit(dev, bufs + num_sent, num_bufs - num_sent)) != num_bufs) {
		// busy wait
		//debug("num_sent = %d", num_sent);
		//debug("num_bufs = %u", num_bufs);
	}
	//pthread_mutex_unlock(&mute);       
}

static void refull_mempool(struct mempool* mempool, uint32_t num_entries) {    //refull mempool
	const int NUM_BUFS = num_entries;
	struct pkt_buf* bufs[NUM_BUFS];
	for (int buf_id = 0; buf_id < NUM_BUFS; buf_id++) {
		struct pkt_buf* buf = pkt_buf_alloc(mempool);
		buf->size = 256;
		uint64_t last_time = monotonic_time();
		for(int i=0;i<3;i++)
	      	{
			strncat(buf->data, pkt_data, 256);
			buf->size += 256;
			uint64_t this_time = monotonic_time();
			if(monotonic_time() - last_time > time_batch)
			    break;
		}
		debug("%d",buf->size);
		memcpy(buf->data, pkt_data, sizeof(pkt_data)); 
		bufs[buf_id] = buf;
	}
	
	for (int buf_id = 0; buf_id < NUM_BUFS; buf_id++) {
		pkt_buf_free(bufs[buf_id]);
		
	}
}

typedef struct{
    struct device* dev;
    struct mempool* mempool;
}Param;

pthread_mutex_t mute1, mute2, mutex;
pthread_cond_t cond;
struct pkt_buf* refull_bufs[3000];

int assemble_count = 0;

void *mythread1(void *arg)
{
	Param *param;
	param = (Param *)arg;
	struct pkt_buf* bufs[BATCHSIZE];
	uint64_t counter = 0;
	uint64_t last_stats_printed = monotonic_time();
	struct device_stats stats_old, stats;
	stats_init(&stats, param->dev);
	stats_init(&stats_old, param->dev);
	int sent_num = 0;
	while (true) {
        	if(sent_num >= 4096){
        		pthread_mutex_lock(&mute2);
        		assemble_count = 0;
        		pthread_mutex_unlock(&mute2);
        		pthread_mutex_lock(&mutex);
                       pthread_cond_signal(&cond);
                       pthread_mutex_unlock(&mutex);
                       
        		while(true) {
        			pthread_mutex_lock(&mute1);
				struct pkt_buf* buf = pkt_buf_alloc(param->mempool);
				pthread_mutex_unlock(&mute1);
				buf->size = 256;
				uint64_t last_time = monotonic_time();
				for(int i=0;i<3;i++)
	      			{
					strncat(buf->data, pkt_data, 256);
					buf->size += 256;
					uint64_t this_time = monotonic_time();
					if(monotonic_time() - last_time > time_batch)
			    			break;
				}
				memcpy(buf->data, pkt_data, sizeof(pkt_data));
				
				pthread_mutex_lock(&mute2);
				refull_bufs[assemble_count] = buf;
				assemble_count++;
				pthread_mutex_unlock(&mute2);
				if(assemble_count >= 3000)
				    break;
			}
			for (int buf_id = 0; buf_id < assemble_count; buf_id++) {
				pkt_buf_free(refull_bufs[buf_id]);	
			}
        		sent_num = 0;
        	}
        
        	//pthread_mutex_lock(&mute);
		pkt_buf_alloc_batch(param->mempool, bufs, BATCHSIZE); // 64
		tx_batch_busy_wait(param->dev, bufs, BATCHSIZE); 
        	//pthread_mutex_unlock(&mute);
        	//debug("xxxxxxxxxxxx");
        	sent_num = sent_num + BATCHSIZE;
        	//debug("%d",sent_num);
        	if ((counter++ & 0xFFF) == 0) {
			uint64_t time = monotonic_time();
			//debug("read_u32(dev, GPTC) = %d",read_u32(dev, GPTC));
			if (time - last_stats_printed > 1000 * 1000 * 1000) {
			// every second
				dev_read_stats(param->dev, &stats);
                		print_stats_diff(&stats, &stats_old, time - last_stats_printed);
                		stats_old = stats;
                		last_stats_printed = time;
            		}
		}
	}
}


void *mythread2(void *arg)
{
	Param *param;
	param = (Param *)arg;
	
	while(true){
	pthread_mutex_lock(&mutex);
	//if (flag == false)
	pthread_cond_wait(&cond, &mutex);
	//debug("i have done");   
	pthread_mutex_unlock(&mutex);
	
	
	while(true) {
	//debug("xxxxxxxxxxxxxx");
        	pthread_mutex_lock(&mute1);
		struct pkt_buf* buf = pkt_buf_alloc(param->mempool);
		pthread_mutex_unlock(&mute1);
		buf->size = 256;
		uint64_t last_time = monotonic_time();
		for(int i = 0;i < 3; i++)
	      	{
			strncat(buf->data, pkt_data, 256);
			buf->size += 256;
			uint64_t this_time = monotonic_time();
			if(monotonic_time() - last_time > time_batch)
	   			break;
		}
		//debug("%d",buf->size);
		memcpy(buf->data, pkt_data, sizeof(pkt_data));
		pthread_mutex_lock(&mute2);
		refull_bufs[assemble_count] = buf;
		assemble_count++;
		pthread_mutex_unlock(&mute2);
		if(assemble_count >= 3000)
		    break;
	}
	//debug("i have done");
	}
}



int main(int argc, char* argv[]) {
    struct device* dev = init_device(argv[1]);
    debug("allocating mempool");
    debug("device = %p",dev);
    for(int i=49; i<64; i++){
        pkt_data[i] = 'a';
    }
    Param param;
    struct mempool* mempool = init_mempool(dev, 4096*2, 0);
    
    param.dev = dev;
    param.mempool = mempool;
    
    
    int ret = 0;
    pthread_t pid1, pid2, pid3, pid4;
    pthread_mutex_init(&mutex, NULL);
    pthread_mutex_init(&mute1, NULL);
    pthread_mutex_init(&mute2, NULL);
    ret = pthread_create(&pid1, NULL, (void *)mythread1, &(param));
    if(ret)
    {
        printf("Create pthread error!\n");
	    return 1;
    }

    
    ret = pthread_create(&pid2, NULL, (void *)mythread2, &(param));
    if(ret)
    {
        printf("Create pthread error!\n");
        return 1;
    }
    
    
    ret = pthread_create(&pid3, NULL, (void *)mythread2, &(param));
    if(ret)
    {
        printf("Create pthread error!\n");
        return 1;
    }
    
    ret = pthread_create(&pid4, NULL, (void *)mythread2, &(param));
    if(ret)
    {
        printf("Create pthread error!\n");
        return 1;
    }
    
    
    pthread_join(pid1,NULL);
    pthread_join(pid2,NULL);
    pthread_join(pid3,NULL);
    pthread_join(pid4,NULL);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&mute1);
    pthread_mutex_destroy(&mute2);
    return 1;
}


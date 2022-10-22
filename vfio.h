#include "stats.h"



void init_vfio(struct device* dev, const char* pci_addr);
void dump_configuration_space(struct device* dev);
void get_device_info(struct device* dev);
void open_vfio(struct device* dev, const char* pci_addr);

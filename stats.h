#ifndef IXY_STATS_H
#define IXY_STATS_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>


#include "device_types.h"
#include "device.h"
#include "log.h"

struct device_stats {
	struct device* device;
	size_t rx_pkts;
	size_t tx_pkts;
	size_t rx_bytes;
	size_t tx_bytes;
};



void print_stats(struct device_stats* stats);
void print_stats_diff(struct device_stats* stats_new, struct device_stats* stats_old, uint64_t nanos_passed);
void stats_init(struct device_stats* stats, struct device* dev);
void dev_read_stats(struct device* dev, struct device_stats* stats);

uint64_t monotonic_time();

#endif //IXY_STATS_H


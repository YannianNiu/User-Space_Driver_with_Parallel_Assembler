# User-Space Driver with Parallel Assembler
This is a upgrade version of the repository "User-Space Driver with Assembler", we integrated parallel assembling method in the user-space driver to get a higher data throughput.

One of the corresponding papers "Throughput-Efficient Communication Device Driver for IoT Gateways" has been accepted by 2022 IEEE International Conference on Systems, Man, and Cybernetics(SMC). The other one of the papers "Assembler: A Throughput-Efficient Module for Network Driver of Edge Computing Gateways" has been accepted by the 23rd Asia-Pacific Network Operations and Management Symposium (APNOMS). However, both of them are not yet searchable on Xplore, please wait for a moment.

We thanks the authors of paper "User Space Network Drivers" and the authors of paper "PostMan: Rapidly Mitigating Bursty Traffic by Offloading Packet Processing" for their inspiration in our papers.

First, if you want to run the code, you must have a certain environment, because the driver-related code has strict requirements for hardware models. One of the suitable environments is Ubuntu OS + Intel 82545 Gigabit NIC (we also include Intel 82545 developer manual). If you do not have those devices, please use VMware Workstation + Ubuntu directly.

Running Steps:

1. Open the terminal, use "lspci | grep Ethernet" to view pci addresses of NIC devices. Assume the pci addresses of the NIC cards are 0000:02:01.0, 0000:02:02.0 and 0000:02:03.0.

2. Using "sudo su" command to enter administrator mode.

3. Using "./vfio-pci-bind.sh 0000:02:01.0" command to unbind all NIC devices that are in the same iommu group from their current driver and bind them to vfio-pci.(We thank Andre Richter for his shell script 'vfio-pci-bind.sh').

* A introduction for VFIO: Virtual Function I/O (VFIO) is a modern device passthrough solution that takes advantage of the DMA Remapping and Interrupt Remapping features provided by VT-d/AMD-Vi technology to ensure the DMA security of passthrough devices while achieving close to physical device I/O performance. User-state processes can directly access the hardware using the VFIO driver, and the whole process is very secure because it is protected by the IOMMU and can be used directly by unprivileged users. In other words, VFIO is a complete userspace driver solution because it can safely present device I/O, interrupts, DMA and other capabilities to the userspace.

4. Using "./setup-hugetlbfs.sh" command to allocate 2MB memory pages for the driver (for higher performance). Of course, you can also use "./setup-hugetlbfs_1G.sh" command to allocate 1GB memory pages fot the driver.

5. Using "gcc memory.c vfio.c stats.c –o driver_forwarding -lpthread" to compile the code file.

6. Using "./driver_forwarding 0000:02:01.0" to run the user-space driver forwarding test.

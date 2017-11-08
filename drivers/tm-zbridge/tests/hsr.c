#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <sched.h>
#include <libpmem.h>

#define COMMIT_DEFAULT_ADDR	0xEFB5C000000
#define COMMIT_SIZE	(8 * 1024 * 1024)
#define COMMIT_REGISTER_SIZE	(64 * 1024)
#define COMMIT_HSR_MASK	0x000000000000FFFF

#define ZBCSR_DEFAULT_ADDR	0xEFB58000000
#define ZBCSR_SIZE	(1024 * 1024)
#define NVM_MAP_CONTAINMENT_STATE0	0x0400
#define NVM_MAP_CONTAINMENT_STATE1	0x0408
#define NVM_MAP_CONTAINMENT_STATE2	0x0410
#define NVM_MAP_CONTAINMENT_STATE3	0x0418

static void *commit_table;
static void *zbcsr_table;
static uint64_t current_commit_hsr;
static uint64_t current_contain0;
static uint64_t current_contain1;
static uint64_t current_contain2;
static uint64_t current_contain3;

int check_WRITE_COMMIT(void)
{
	void *hsr_register;
	uint64_t commit_hsr;
	int cpu;
	
	/* Load the HA_WRITE_COMMIT_CONTAINMENT_HSR */
	cpu = sched_getcpu();
	/*
	 * If getcpu failed for some reason, use cpu 1. The HSR space has
	 * 128 threads available, so use mod to wrap if necessary.
 	 */
	cpu = (cpu == -1) ? 1 : cpu % 128;
	hsr_register = commit_table + (cpu * COMMIT_REGISTER_SIZE);
	commit_hsr = (*(uint64_t *)hsr_register) & COMMIT_HSR_MASK;
	
	/* The 16 bit counter wraps, so just look for a different value. */
	if (commit_hsr != current_commit_hsr) {
		/* We have an error. */
		uint64_t contain0;
		uint64_t contain1;
		uint64_t contain2;
		uint64_t contain3;

		printf("current commit_hsr is %ld commit_hsr for cpu %d is %ld\n",
			(long)current_commit_hsr, sched_getcpu(),
			(long)commit_hsr);
		/* Update the current state */
		current_commit_hsr = commit_hsr;

		/* check to interleave containment CSR to see which inlv */
		contain0 = *((uint64_t *)zbcsr_table +
				NVM_MAP_CONTAINMENT_STATE0);
		contain1 = *((uint64_t *)zbcsr_table +
				NVM_MAP_CONTAINMENT_STATE1);
		contain2 = *((uint64_t *)zbcsr_table +
				NVM_MAP_CONTAINMENT_STATE2);
		contain3 = *((uint64_t *)zbcsr_table +
				NVM_MAP_CONTAINMENT_STATE3);
	
		if (current_contain0 != contain0) {
			printf("contain0 changed from 0x%x to 0x%x\n",
				(int)current_contain0, (int)contain0);
			current_contain0 = contain0;
		}
		if (current_contain1 != contain1) {
			printf("contain1 changed from 0x%x to 0x%x\n",
				(int)current_contain1, (int)contain1);
			current_contain1 = contain1;
		}
		if (current_contain2 != contain2) {
			printf("contain2 changed from 0x%x to 0x%x\n",
				(int)current_contain2, (int)contain2);
			current_contain2 = contain2;
		}
		if (current_contain3 != contain3) {
			printf("contain3 changed from 0x%x to 0x%x\n",
				(int)current_contain3, (int)contain3);
			current_contain3 = contain3;
		}
		return 1;
	}
	return 0;
}

#define PMEM_LEN (1024l * 1024l * 1024l)

int main(void)
{
	off_t          zbcsr_base = ZBCSR_DEFAULT_ADDR;
	int            zbcfd;
	int            memfd;
	int	status;
	char	*vaddr;
	int	is_pmem;
	size_t	 mapped_len;
	int	i;


	/* Initialzation to map the HSR */
	zbcfd = open("/dev/zbcommit", O_RDONLY);
	if (zbcfd == -1)  {
		printf("open failed %s\n", strerror(errno));
		errx(1, "zbc open failure");
	}
	commit_table = mmap(0, COMMIT_SIZE, PROT_READ, MAP_SHARED,
		zbcfd, 0);
	if (commit_table == MAP_FAILED)
		errx(1, "zbc mmap failure");

	/*
	 * Load the HA_WRITE_COMMIT_CONTAINMENT_HSR for thread 0 and
	 * initialize the global current count.
	 */
	current_commit_hsr = (*(uint64_t *)commit_table) & COMMIT_HSR_MASK;

	printf("current_commit_hsr is %d\n", (int) current_commit_hsr);

	/* Initialzation to map the zbridge CSRs */
	memfd = open("/dev/mem", O_RDWR | O_SYNC);
	zbcsr_table = mmap(0, ZBCSR_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED,
		memfd, zbcsr_base);
	if (commit_table == MAP_FAILED)
		errx(1, "mem mmap failure");

	/* check to interleave containment CSR to see which inlv */
	current_contain0 = *(uint64_t *)(zbcsr_table +
			NVM_MAP_CONTAINMENT_STATE0);
	current_contain1 = *(uint64_t *)(zbcsr_table +
			NVM_MAP_CONTAINMENT_STATE1);
	current_contain2 = *(uint64_t *)(zbcsr_table +
			NVM_MAP_CONTAINMENT_STATE2);
	current_contain3 = *(uint64_t *)(zbcsr_table +
			NVM_MAP_CONTAINMENT_STATE3);
	
	printf("Initial state: WRITE_COMMIT: %d\n\tCONTAINMENT_STATE0: 0x%x\n\tCONTAINMENT_STATE1: 0x%x\n\tCONTAINMENT_STATE2: 0x%x\n\tCONTAINMENT_STATE3: 0x%x\n",
		(int)current_commit_hsr, (int)current_contain0,
		(int)current_contain1, (int)current_contain2,
		(int)current_contain3);
	is_pmem = 1;
	vaddr = (char *)pmem_map_file("/lfs/foo", PMEM_LEN, PMEM_FILE_CREATE,
				0666, &mapped_len, &is_pmem);
	if (vaddr == NULL) {
		perror("pmem_map_file: ");
		goto leave;
	}

	for (i = 0; i < PMEM_LEN; i++) {
		*(vaddr+i) = 1;
		if (is_pmem)
			pmem_persist(vaddr, PMEM_LEN);
	
		status = *(vaddr+1);
	}
	/* Use the function to see the HSR */
	printf("calling check_WRITE_COMMIT\n");
	status = check_WRITE_COMMIT();
	printf("check_WRITE_COMMIT() returns %d\n", status);

	pmem_unmap(vaddr, PMEM_LEN);

leave:
	/* Exit to unmap the HSR */
	munmap(commit_table, COMMIT_SIZE);

	close(zbcfd);

	return 0;
}


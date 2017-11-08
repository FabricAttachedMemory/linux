#ifndef _FLUSHTM_H
#define _FLUSHTM_H

#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/smp.h>

#define FLUSHTM_NAME	"flushtm"

#define FLUSHTM_DEBUG

/* When stable, git commit, then git tag, then commit again (for the tag) */
#define FLUSHTM_VERSION	"flushtm git version v0.9"

#ifdef FLUSHTM_DEBUG
#define PR_VERBOSE1(a...)	{ if (flushtm_verbose) pr_info(a); }
#define PR_VERBOSE2(a...)	{ if (flushtm_verbose > 1) pr_info(a); }
#define PR_VERBOSE3(a...)	{ if (flushtm_verbose > 2) pr_info(a); }
#else
#define PR_VERBOSE1(a...)
#define PR_VERBOSE2(a...)
#define PR_VERBOSE3(a...)
#endif

#define _F_		__func__
#define PR_ENTER(a...)	{ if (flushtm_verbose) { \
			pr_info("flushtm: enter %s: ", _F_); pr_cont(a); } }
#define PR_EXIT(a...)	{ if (flushtm_verbose) { \
			pr_info("flushtm: exit %s: ", _F_); pr_cont(a); } }

/* needed for flushing */
#define FLUSH_ALIGN	((uintptr_t)64)

/*
 * During callgraph generation, "flipping" these values will create a
 * more detailed map.  Otherwise use normal/idiot-proofing/performant values.
 */

#ifdef CALLGRAPH
#define STATIC
#define NOINLINE	noinline
#else
#define STATIC		static
#define NOINLINE
#endif

#define STREQ(s1, s2) (!strcmp(s1, s2))
#define STARTS(s1, s2) (!strncmp(s1, s2, strlen(s2)))

struct flushtm_configuration {
	u64 something;
};

/* flushtm.c - globals from insmod parameters, then routines */

extern int flushtm_verbose;

void flushtm_dcache_phys_area(phys_addr_t addr, uint64_t len);
void __flush_dcache_all(void);

/* flush_[arm|x86].c */

int flushtm_init_arch(void);

void flushtm_exit_arch(void);

#endif

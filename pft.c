/*
 *  Copyright (c) 2006, 2014 SGI. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  #  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Originally:  Christoph Lameter's "Page Fault Test" tool.
 *
 * Posted to LKML:  http://lkml.org/lkml/2006/8/29/294
 *
 * Modified by Lee Schermerhorn for mem policy testing
 * Change to allocate single large region before creating worker
 * threads/tasks.
 * Then, carve up the region, giving each worker a piece to fault in.
 * This will cause the workers to contend for the cache line[s]
 * holding the in-kernel memory policy structure, the zone locks
 * and page lists, ...
 * In multi-thread mode, the workers will also contend for the
 * single test task's mmap semaphore.
 *
 * See usage below.
 */

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <numa.h>
#include <numaif.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "version.h"

#if defined(USE_RUSAGE_THREAD) && !defined(RUSAGE_THREAD)
#define RUSAGE_THREAD 1
#endif

#ifdef USE_NOCLEAR
/*
 * N.B., make sure this matches the value used in the 'noclear' kernel patch
 */
#define MPOL_MF_NOCLEAR (MPOL_MF_MOVE_ALL << 1)
#endif

struct test_rusage {
	struct timespec wall_start;
	struct timespec wall_end;

	struct rusage ruse_start;
	struct rusage ruse_end;
};

enum test_state {
	TEST_CREATED = 0,
	TEST_READY,
	TEST_DONE,
	TEST_REAPED,
};

static struct test_info {
	pthread_t	ptid;
	pid_t		pid;	/* not worth a union */
	volatile enum test_state state;

	int            idx;
	int            cpu;	/* if bound */

	char		*mem;	/* this test's memory segment */

	struct test_rusage rusage;
} **test_info;

static pthread_attr_t thread_attributes;
static pthread_key_t  tip_key;

static int pft_sched_policy = SCHED_FIFO; /* if we use it */

static struct rusage ruse_start;	/* earliest worker's start rusage */

/*
 * parent/child communication - shared anon segment
 *
 * We extend this struct by nr_tests - 1 struct test_info, where
 * nr_tests = nr_proc + nr_thread, one of which will be 0.
 *
 * Why do we need both this array of test_info in the comm area
 * and the array of pointers to allocated test_infos?
 * Well, we don't really -- for this test.
 * We need this array in the comm area for the multi-task tests,
 * to communicate the results back to the parent/launch task.
 * The array of pointers to test_infos allocated locally to the
 * thread/task is a hold over from another multi-threaded tool
 * whose thread setup infrastructure I cloned for this test.
 * The measured loop of the test doesn't actually touch the test_info,
 * so we could use the array in the comm area directly.
 * However, I chose to keep the per test local test_info and then
 * push the results back to the comm area at the end, in case we
 * ever DO want to access the test_info in the test loop.  That
 * and I was too lazy to rip it out.  It does complicate things, tho'.
 */
struct pft_comm {
	volatile long    go;

	struct timespec wall_end;
	struct timespec wall_start;

	struct rusage rusage;

	int    shmid;
	int    abort;

	struct test_info test_info[1];
} *comm;

#define CACHELINE_SIZE_DEFAULT (128)

/*
 * fairly arbitrary limits
 */
#define MAX_TESTS 128

#define ROUND_UP(x,y) (((x) + (y) - 1) & ~((y)-1))

static  char*	OPTSTR = "ac:fhlm:n:ps:t:vzCFLMNPSTVZ";
static char *usage = "\n\
Usage:  %s [-afhpvzCFLMNPSTVZ] [-c <cachelines>] [-m <size>[KMGP]]\n\
           [-s <sleep_seconds>] [{-n <nr_proc>|-t <nr_thread>}] [<tag>]\n\
 Where:\n\
	-h = show help/usage.\n\n\
	-m <size> = total size of test region.  Optional scale factor:\n\
	            K = kilo, M = mega, G = giga, P = pages\n\
	-p = use vma/shared memPolicy; else use sys default policy.\n\
	-z = bzero the per-thread memory area; else touch cachelines.\n\
	-c <cachelines> = number of cachelines to touch if !-z.\n\
	            configured cacheline size:  %d bytes.\n\
	-l = mlock() the region instead of bzero or touch.\n\
	-M = mmap() separate regions for each test task/thread to avoid\n\
	     anon_vma sharing.\n\
	-S = use SysV shared memory test area; else anonymous test memory.\n\
	-L = SHM_LOCK the SysV shared memory test area.  Implies -S\n\n\
	-n <nr_proc> = number of test processes.\n\
	-t <nr_thread> = number of threads.\n\
		'-t' and '-n' are mutually exclusive options\n\
		<nr_proc>|<nr_thread>  should <= nr_cpus\n\
		Each process/thread will touch <size>/<nr_*> memory.\n"
#if 0
"\
	-F = force use of <nr_proc>|nr_thread > nr_cpus_allowed\n"
#endif
"	-a = affinitize test processes/threads to cpus.\n\
	-f = use SCHED_FIFO policy for tests.\n\
	-Z = mmap() /dev/zero for anonymous regions\n"
#ifdef USE_NOCLEAR
"	-C = request kernel not to Clear pages to eliminate this\n\
	     overhead.  Requires special kernel patch.\n"
#endif
"\n	-N = dump numa_maps at end of test\n\
	-P = pause after test to examine maps\n\
	-T = emit title/header line and 'tag' for plots.\n\
	-s <sleep_seconds> = sleep delay at end of tests.\n\
	-v = enable verbosity.\n\
	-V = just emit version/build-stamp and exit.\n\n\
	<tag> = annotation, e.g., for plots.\n\n\
";

size_t   bytes;		/* total size of test memory */

unsigned long     nr_proc = 0;	// TODO:  make this default?
unsigned long     nr_thread = 0;
unsigned long     nr_tests;

long     cachelines = 1;

int      do_cpubind = 0;
int      do_mempol = 0;
int      do_numa_maps = 0;
int      do_pause = 0;
int      do_shm = 0;
int      do_shmlock = 0;
int      do_title = 0;
int      verbose = 0;
int      do_bzero = 0;
int      use_sched_fifo = 0;
int      force = 0;
long     sleepsec = 0;
int      do_mlock = 0;
int      no_clear = 0;		/* define even when !defined(USE_NOCLEAR) */
size_t   multimap = 0L;		/* mmap() per test area */

int	mmap_fd;		/* for /dev/zero mappings */
int	mmap_flags = MAP_ANONYMOUS;	/* default */

int      launch_cpu;

long faults;
long pages;
long pages_per_test;
size_t bytes_per_test;

char *test_memory;
char **test_memories;

pid_t	lpid;		/* launch() pid */

int	rusage_who;

void
perrorx(char *mesg)
{
	perror(mesg);
	if (comm)
		comm->abort++;
	exit(1);
}

void
vprint(int level, char *format, ...)
{
	va_list ap;

	if (level > verbose)
		goto out;

	va_start(ap, format);

	(void)vfprintf(stderr, format, ap);
	fflush(stderr);

out:
	va_end(ap);
	return;
}

/*
 * ============================================================================
 * Support for determining allowed cpus, for distributing children over allowed
 * cpus.
 */

typedef enum{false = 0, true} bool;
const unsigned int BITSPERINT = 8 * sizeof(int);

static int max_cpu_allowed = -1;
static int nr_cpus_allowed = -1;
static struct bitmask *cpus_allowed_mask;	/* bit map */
static unsigned int *cpus_allowed;	/* dense array */

/*
 * ----------------------------------------------------------------------------
 */

static bool
cpu_allowed(int cpuid)
{
	return numa_bitmask_isbitset(cpus_allowed_mask, cpuid);
}

/*
 * ----------------------------------------------------------------------------
 */

/*
 * cpus_allowed_init():   fetch task's Cpus_allowed mask using libnuma API
 */
#define CA_STRLEN 4096	/* large enough for most ? */
void
cpus_allowed_init(void)
{
	unsigned int *prev_cpus_allowed;
	int ret, max_cpus_allowed;
	int i, cpuid, prev_nr_cpus_allowed;

	/*
	 * libnuma wrapper returns bitmask
	 */
	cpus_allowed_mask = numa_allocate_cpumask();
	ret = numa_sched_getaffinity(lpid, cpus_allowed_mask);
	if (ret == -1)
		perrorx("Can't fetch sched affinity");

	// broken in numactl 2.0.3:  wrong symbol name [numa_num_tread_cpus()]
	// in sources and numa(3) man page.  Requires patched libnuma and numa(3).
	max_cpus_allowed = numa_num_task_cpus();

	prev_cpus_allowed = cpus_allowed;	/* for re-init */
	prev_nr_cpus_allowed = nr_cpus_allowed;

	/*
	 * Populate cpus_allowed[] dense array.
	 */
	nr_cpus_allowed = 0;
	cpus_allowed = calloc(sizeof(int), max_cpus_allowed);
	if (!cpus_allowed)
		perrorx("Can't allocate cpus_allowed array");

	for (i=0; i < max_cpus_allowed; ++i) {
		if (cpu_allowed(i)) {
			max_cpu_allowed = i;
			cpus_allowed[nr_cpus_allowed++] = i;
		}
	}

	/*
	 * TODO:  on re-init, notify application of change in cpus_allowed:
	 * E.g., redistribute tasks over new set of allowed cpus.
	 */
}

/*
 * ----------------------------------------------------------------------------
 */

/*
 * cpus_init() -- fetch/parse allowed cpus
 */
static void
cpus_init()
{
	cpus_allowed_init();
	launch_cpu = cpus_allowed[0];
}

/*
 * ============================================================================
 */

/*
 * cachline_size_init() - fetch cacheline size from kernel, if supported
 */
size_t cacheline_size = 0;
void
cacheline_size_init(void)
{
	if(!cacheline_size) {
#ifdef _SC_LEVEL1_DCACHE_LINESIZE
		long cls = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
		if (cls > 0)
			cacheline_size = (size_t)cls;
		else
#endif
			cacheline_size = CACHELINE_SIZE_DEFAULT;
	}
}

/*
 * Does the kernel support RUSAGE_THREAD?
 */
void
check_rusage_thread(void)
{
#ifdef RUSAGE_THREAD
	struct rusage rusage;

	if(!getrusage(RUSAGE_THREAD, &rusage)) {
		rusage_who = RUSAGE_THREAD;
		vprint(1, "Using RUSAGE_THREAD\n");
	}
#endif
}

/*
 * pagesize_init() - fetch pagesize when needed
 */
ssize_t pagesize = -1;
#define PAGE_ALIGN(addr)        ROUND_UP((addr), pagesize)
static void
pagesize_init(void)
{
	if (pagesize == -1) {
		pagesize = sysconf(_SC_PAGESIZE);
		if (pagesize <= 0) {
			perror("sysconf(_SC_PAGESIZE) failed");
			exit(1);
		}
	}
}

/*
 * use_dev_zero() -- open /dev/zero for use by pft_mmap()
 */
static void
use_dev_zero(void)
{
	int dzfd = open("/dev/zero", O_RDWR);

	if (dzfd < 0)
		perrorx("open of /dev/zero failed ");

	mmap_fd = dzfd;
	mmap_flags = 0;		/* zap MAP_ANONYMOUS */
}

/*
 * pft_mmap() - "allocate" page aligned memory using mmap(ANON)
 * flags:  MAP_PRIVATE or MAP_SHARED
 */
static void *
pft_mmap(size_t size, int flags, void *where)
{
	char *addr;

	pagesize_init();
	if (!size)
		size = pagesize;

	if (where)
		flags |= MAP_FIXED;

	/*
	 * mmap(2) page aligns size/len
	 */
	addr = (char *)mmap(where, size,
			PROT_READ|PROT_WRITE,
			flags|mmap_flags,
			mmap_fd, 0);
	if (addr == MAP_FAILED)
		addr = NULL;	/* like valloc(3) */
	return addr;
}

/*
 * valloc_private() - "allocate" page-aligned, private anon memory.
 */
static void *
valloc_private(size_t size)
{
	return pft_mmap(size, MAP_PRIVATE, NULL);
}

/*
 * valloc_shared() - "allocate" page-aligned, shared anon memory.
 */
static void *
valloc_shared(size_t size)
{
	return pft_mmap(size, MAP_SHARED, NULL);
}

/*
 * pft_free() -- free memory "allocated" via pft_mmap() or valloc_*()
 * need 'size' for munmap
 */
static void
pft_free(void *mem, size_t size)
{
	munmap(mem, size);
}

/*
 * bind_to_cpu() - bind calling thread [main program] to specified
 * cpu before creating per cpu thread.
 * Thread id 'tid' for debug printing only
 */
static int
bind_to_cpu(int cpu, int tid)
{
	cpu_set_t cpu_mask;

	if (!do_cpubind)
		return 1;

	if (nr_cpus_allowed == 1)
		return 1;		/* why bother? */

	CPU_ZERO(&cpu_mask);
	CPU_SET(cpu, &cpu_mask);

	if (sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask) == -1) {
		perror("sched_setaffinity");
		return 0;	/* assume no such cpu? */
	}
	vprint(2, "worker %d bound to cpu %d\n", tid, cpu);
	return 1;
}

/*
 * borrowed from memtoy
 *  size_kmgp() -- convert ascii arg to numeric and scale as requested
 */
#define BOGUS_SIZE ((size_t)-1)	/* memtoy */
#define KILO_SHIFT 10	/* shift count to multiply by 1K */

static size_t
size_kmgp(char *arg)
{
	size_t argval;
	char *next;

	argval = strtoul(arg, &next, 0);
	if (*next == '\0')
		return argval;

	switch (tolower(*next)) {
	case 'p':	/* pages */
		argval *= pagesize;
		break;

	case 'k':
		argval <<= KILO_SHIFT;
		break;

	case 'm':
		argval <<= KILO_SHIFT * 2;
		break;

	case 'g':
		argval <<= KILO_SHIFT * 3;
		break;

	default:
		return BOGUS_SIZE;	/* bogus chars after number */
	}

	return argval;
}

/*
 * choose an arbitrary priority for pft_sched_policy tests.
 * use mid-point of pft_sched_policy priority range.
 */
static int get_run_priority(void)
{
	int pri_min, pri_max, sched_pri;

	pri_min = sched_get_priority_min(pft_sched_policy);
	if (pri_min < 0) {
		perror("sched_get_priority_min");
		return 0;
	}
	pri_max = sched_get_priority_max(pft_sched_policy);
	if (pri_max < 0) {
		perror("sched_get_priority_max");
		return 0;
	}

	sched_pri = (pri_min + pri_max) / 2;
	vprint(2, "%s returning sched_pri = %d\n", __FUNCTION__, sched_pri);
	return sched_pri;
}

/*
 * Set scheduler for task to SCHED_FIFO.  For launch() task/thread
 * [test == 0], augment the priority by 1 to retain control while
 * starting workers on each cpu.
 *
 * Returns:
 *	!0 on success
 *	0  on failure.
 *
 */
static void set_task_scheduler(int test)
{
	struct sched_param sched_params;

	if (!use_sched_fifo)
		return;

	memset(&sched_params, 0, sizeof(sched_params));

	sched_params.sched_priority = get_run_priority() + !test;

	vprint(2, "setting test %d scheduler to %d @ %d\n", test,
		pft_sched_policy, sched_params.sched_priority);
	if (sched_setscheduler(0, pft_sched_policy, &sched_params)) {
		perror("sched_setscheduler");
	}

}

/*
 * Set scheduler to SCHED_FIFO and priorty high to minimize
 * variability from other processes during test loop.
 * Returns:
 *	!0 on success
 *	0  on failure.
 *
 */
static int create_thread_attributes(void)
{
	pthread_attr_t *attr = &thread_attributes;
	struct sched_param sched_params;

	if (pthread_attr_init(attr)) {
		perror("pthread_attr_init");
		return 0;
	}

	if (!use_sched_fifo)
		return 1;

	if (pthread_attr_setschedpolicy(attr, pft_sched_policy)) {
		perror("pthread_attr_setschedpolicy");
		return 0;
	}

	sched_params.sched_priority = get_run_priority();
	vprint(2, "setting thread scheduler to %d @ %d\n", pft_sched_policy,
		sched_params.sched_priority);
	if (pthread_attr_setschedparam(attr, &sched_params)) {
		perror("pthread_attr_setschedparam");
		return 0;
	}

	return 1;
}

/*
 * show_tip_node() -- fetch numa node id of thread info struct
 */
static void show_tip_node(struct test_info *tip)
{
#ifdef MPOL_F_NODE
	int rc, node;

	rc = get_mempolicy(&node, NULL, 0, tip, MPOL_F_NODE|MPOL_F_ADDR);
	if (rc)
		return;

	vprint(2, "test info struct for test %d [cpu %d] on node %d\n",
		 tip->idx, tip->cpu, node);
#endif
}

/*
 * create_test_info() - allocate private, page-aligned per process/thread
 * info for test 'tidx'.  For NUMA platforms, the test info struct should
 * be allocated locally to the cpu where the thread is running at the time.
 * At end of test, the worker thread/task will dump its test info into the
 * shared communication area.
 * If the '-a' [affinitize] option was specified, the thread or process
 * should already be bound to its run time cpu.
 */
struct test_info *
create_test_info(int tidx)
{
	struct test_info *tip;

	if (tidx) {
		tip = test_info[tidx] = valloc_private(sizeof(*tip));
		if (!tip)
			perrorx("valloc_private(test_info)");
	} else
		tip = comm->test_info;	/* use comm area directly for test 0 */

	bzero(tip, sizeof(*tip));
	tip->idx = tidx;
	return tip;
}

char *
alloc_shm(size_t shmlen)
{
	char    *p, *locked = "";

	vprint(3, "Try to allocate TOTAL shm segment of %ld bytes\n", shmlen);

	if ((comm->shmid = shmget(IPC_PRIVATE, shmlen, SHM_R|SHM_W))  == -1)
		perrorx("shmget failed");
	p = (char*)shmat(comm->shmid, (void*)0, SHM_R|SHM_W);

	if (do_shmlock) {
		if (shmctl(comm->shmid, SHM_LOCK, NULL) == -1)
			perrorx("shmctl(SHM_LOCK) failed");
		locked = "/SHM_LOCKED";
	}
	vprint(3, "shm created, attached @ adr: 0x%lx\n", locked, (long)p);
	return p;
}

/*
 * do_mbind() -- apply vma policy to test memory region
 * Use "explicit local" policy -- MPOL_PREFERRED w/ NULL nodemask
 */
void
do_mbind(char *start, size_t length)
{
	if (!do_mempol)
		return;

	if (mbind(start, length, MPOL_PREFERRED, (void *)0, 0, 0)  < 0)
		perrorx("mbind failed");
}

#ifdef USE_NOCLEAR
void
do_noclear(char *start, size_t length)
{
	if (!no_clear)
		return;
	/*
	 * length, policy, nodemask/maxnodes all ignored.
	 * this is just a "backdoor" to set "no clear" on
	 * the vma, if supported
	 */
	if (mbind(start, length, MPOL_PREFERRED, (void *)0, 0, MPOL_MF_NOCLEAR)  < 0)
		perrorx("mbind 'NOCLEAR failed/not supported");
	vprint(1, "enabled 'NOCLEAR' on test memory\n");
}
#else
#define do_noclear(P, L)	/* no-op, but should never be invoked */
#endif

/*
 * alloc_test_memory:  allocate the test memory region and divide up between
 * threads.
 */
void
alloc_test_memory(void)
{
	char *p = NULL;
	int j;

	if (do_shm) {
		if (p = alloc_shm(bytes)) {
			do_mbind(p, bytes);
			do_noclear(p, bytes);
		}
	} else {
		/*
		 * mmap()'ed test area[s].
		 */
		if (!multimap) {
			/*
			 * one large test area => single anon_vma
			 */
			if (p = valloc_private(bytes)) {
				do_mbind(p, bytes);
				do_noclear(p, bytes);
			}
		} else {
			/*
			 * multimap:  per test mmap area => separate anon_vmas
			 */
			void *where;
			size_t abytes = bytes + (nr_tests + 1) * pagesize;
			size_t tbytes = bytes_per_test + pagesize;

			/*
			 * reserve VA range with room for "holes"
			 */
			where = valloc_private(abytes);
			if(!where)
				perrorx("valloc_private() of multimap region failed");
			vprint(3, "multimap va range:  0x%lx - 0x%lx\n", where, where+abytes);
			if (munmap(where, pagesize))
					perrorx("munmap() of 1st test region page failed");
			where += pagesize;

			for (j = 0; j < nr_tests; ++j) {
				/*
				 * unmap per test region + a 1 page hole
				 */
				if (munmap(where, tbytes))
					perrorx("munmap() of per test region failed");

				/*
				 * map per test region below the hole
				 */
				if (p = pft_mmap(bytes_per_test, MAP_PRIVATE, where)) {
					vprint(3, "test %d memory @ 0x%lx - 0x%lx\n",
					        j, p, p+bytes_per_test);
					do_mbind(p, bytes_per_test);
					do_noclear(p, bytes_per_test);
					test_memories[j] = p;

					where += tbytes;	/* advance past the hole */
				} else
					goto err;
			}
		}
	}

	if (p == 0) {
	err:
	    printf("malloc of %Ld bytes failed.\n", bytes);
	    exit(1);
	}

	if (!multimap) {
		test_memory = p;
		vprint(3, "test memory @ 0x%lx\n", test_memory);
	}
}

/*
 * calc_elapsed_time() -- elapsed "wall clock" time
 */
static double
calc_elapsed_time(struct timespec *ws, struct timespec *we)
{
	struct timespec wall;

	wall.tv_sec = we->tv_sec - ws->tv_sec;
	wall.tv_nsec = we->tv_nsec - ws->tv_nsec;

	if (wall.tv_nsec <0 )	{
		 wall.tv_sec--;
		wall.tv_nsec += 1000000000;
	}

	if (wall.tv_nsec >1000000000) {
		wall.tv_sec++;
		wall.tv_nsec -= 1000000000;
	}

	return ((double) wall.tv_sec + (double) wall.tv_nsec / 1000000000.0);
}

/*
 * calc_cpu_time() -- user and/or system time for all workers
 */
static double
calc_cpu_time(struct timeval *tvp)
{

	return ((double) tvp->tv_sec + (double) tvp->tv_usec / 1000000.0);
}

/*
 * test_to_cpu() - distribute threads/processes, round robin, over cpus
 *
 * cpu_offset:  used to prevent other worker threads from binding to
 * the launch cpu as that causes startup problems.
 */
static int cpu_offset = 0;

static int
test_to_cpu(int t)
{
	return (cpus_allowed[(t + cpu_offset) % nr_cpus_allowed]);
}

//TODO : temp for debug
void
show_rusage(char *tag, struct rusage *rusage)
{
	fprintf(stderr, "%s %8d.%06d %8d.%06d %8d %8d\n", tag,
	rusage->ru_utime.tv_sec, rusage->ru_utime.tv_usec,
	rusage->ru_stime.tv_sec, rusage->ru_stime.tv_usec,
	rusage->ru_minflt, rusage->ru_majflt);
}

/*
 * actual measured test loop
 */
void
pft_loop(struct test_info *tip)
{
	char    *pe, *p = tip->mem;
	int cl;

	/*
	 * Start Measurement Interval and snap initial rusage.
	 * Note preemption window between 'gettime and getrusage
	 * that can skew results if we get preempted there.
	 * Fortunately, we only use the wall clock time to
	 * select the earliest/latest workers' rusage when
	 * running mult-thread test on kernel that doesn't
	 * support RUSAGE_THREAD.
	 */
	clock_gettime(CLOCK_REALTIME, &tip->rusage.wall_start);
	getrusage(rusage_who, &tip->rusage.ruse_start);

	if (do_mlock) {
		mlock(p, bytes_per_test);
		vprint(2, "  mlocked\n");
	} else if (do_bzero) {
		bzero(p, bytes_per_test);
		vprint(2, "  zeroed\n");
	} else {
		/*
		 * Touch 'cachelines' every pagesize bytes.
		 * Use 'write' access to force anon page allocation.
		 * TODO:  if we decide to add page cache [mapped file]
		 *        tests, may want to select read or write access
		 *        to test page cache minor read faults vs COW
		 */
		for(pe = p + bytes_per_test; p < pe; p += pagesize)
			for(cl = 0; cl < cachelines; cl++)
				p[cl * cacheline_size] = 'r';
	}

	/*
	 * End Thread Measurement Interval and snap ending rusage.
	 * Note preemption window.
	 */
	getrusage(rusage_who, &tip->rusage.ruse_end);
	clock_gettime(CLOCK_REALTIME, &tip->rusage.wall_end);
}

void
check_wall_time(int id, struct timespec *tsp, char *what)
{
	if (tsp->tv_sec)
		return;
	vprint(0, "!!! Test %d - %s time is zero\n", id, what);
	verbose = 3;
}

/*
 * per test "main-line" function
 */
void*
test_main(void *arg)
{
	struct test_info *tip;
	struct timespec sleepfor = { 0, 2500L }; /* 0.0000025 sec */
	long    id;

	tip = (struct test_info *)arg;
	id  = tip->idx;

	tip->state = TEST_READY;
	/*
	 * push local test_info to comm area so that launch()
	 * sees state and ptid/pid.
	 */
	comm->test_info[id] = *tip;

	while(!comm->go) {
//TODO:  may need one of these if nr_tests > nr_cpus ...
#if 0
#if 0
		if (tip->cpu == launch_cpu)
			nanosleep(&sleepfor, NULL);	/* relax... */
#else
		sched_yield();
#endif
#endif
	}

	vprint (2, "test %d running\n", id);

	pft_loop(tip);

	if (sleepsec) {
		vprint (2, "test %d sleeping\n", id);
		sleep(sleepsec);
	}

	check_wall_time(tip->idx, &tip->rusage.wall_start, "test_main wall_start");
	check_wall_time(tip->idx, &tip->rusage.wall_end, "test_main wall_end");

	vprint (2, "test %d done\n", id);
	tip->state = TEST_DONE;

	/*
	 * push results back into comm area
	 */
	comm->test_info[id] = *tip;

	if (nr_thread)
		pthread_exit(0);
	else {
		comm = NULL;	/* don't cleanup */
		exit(0);
	}
}


/*
 * start workers -- start nr_tests-1 threads or tasks for test, distributed
 * across cpus.  launch() thread/task will run a test as well, for a total
 * of nr_tests.
 * Allocate test info structs local to test's cpu--i.e., after binding.
 * Return !0 [nr tests created] on success; 0 on failure;
 */
static int
start_workers(void)
{
	cpu_set_t main_mask;
	struct test_info **tipp;
	int j;
	int tests_created = 0;
	int ret = 0;

	vprint(2, "Starting %d test %s\n", nr_tests, nr_thread ? "threads" : "tasks");

	test_info = valloc_private(nr_tests * sizeof(*test_info));
	if (!test_info)
		perrorx("malloc of test_info failed");

	if (nr_thread) {
		if (!create_thread_attributes()) {
			fprintf(stderr, "Failed to create thread attributes\n");
			return 0;
		}

		/*
		 * for signal handlers, if needed
		 */
		if (pthread_key_create(&tip_key, NULL)) {
			perror("pthread_key_create");
			fprintf(stderr, "Failed to create TSD key\n");
			return 0;
		}
	}

	/*
	 * try to start requested number of test threads/tasks
	 */
	for (tipp = test_info, j = 0; j < nr_tests; ++j, ++tipp) {
		struct test_info *tip;
		int cpu = test_to_cpu(j);

		/*
		 * don't allow other worker threads to bind to launch_cpu.
		 * This can only occur when we run more workers than we
		 * have allowed cpus.  Bump the the cpu_offset and try
		 * again.  If we only have one cpu, this won't prevent
		 * us from piling onto the launch cpu, but them's the breaks.
		 */
		if (j && cpu == launch_cpu) {
			cpu_offset++;
			cpu = test_to_cpu(j);
		}

		/*
		 * bind launch thread to 'cpu' so that per test info,
		 * stacks, ... get allocated locally to test's cpu.
		 */
		if (!bind_to_cpu(cpu, j)) {
			fprintf(stderr, "Unable to bind test %d to cpu %d - "
					"aborting.\n", j, cpu);
			exit(1);
		}

		*tipp = tip = create_test_info(j);	/* create locally */

		tip->cpu = cpu;
		show_tip_node(tip);	/* debug */

		if (multimap)
			tip->mem = test_memories[j];
		else
			tip->mem = j * bytes_per_test + test_memory;
		vprint(3, "thread %d test mem @ 0x%lx - 0x%lx\n", j,
		           tip->mem, tip->mem + bytes_per_test );

		if (!j) {
			/*
			 * launch() thread/task will run test loop as test 0.
			 * save its thread's cpu affinity for restoration below
			 */
			sched_getaffinity(lpid, sizeof(main_mask), &main_mask);
			continue;
		}

		if (nr_thread) {
			/*
			 * Create the test threads: 1..nr_thread-1
			 */
			if (pthread_create(&tip->ptid, &thread_attributes,
					 test_main, tip)) {
				perrorx("pthread_create");
			}
		} else {
			/*
			 * Create the test tasks: 1..nr_proc-1
			 */
			switch (tip->pid = fork()) {
			case 0:
				set_task_scheduler(j);
				test_main(tip);
				break;
			case -1:
				perrorx("fork() of test process failed");
			}
		}
		++tests_created;

	} /* for each requested thread */

	ret = tests_created;	/* success */

out:
	/*
	 * restore "launch task's" cpu affinity
	 */
	sched_setaffinity(lpid, sizeof(main_mask), &main_mask);
	return ret;
}

/*
 * update_walltime_and_rusage() -- select later of current comm area wall_end
 * and the specified thread's wall_end.  Update the rusage from the latest
 * test.
 *
 * Details:
 * If running multi-thread tests and RUASGE_THREAD is not supported by the system
 * select start rusage of earliest thread to start and end usage from the latest
 * thread to complete.   Otherwise, we have the start and end usage of the tests
 * in the comm area.  We'll accumulate them after all tests complete.
 */
static void
update_walltime_and_rusage(struct test_info *tip)
{
	struct timespec *cws = &comm->wall_start;
	struct timespec *cwe = &comm->wall_end;
	struct timespec *tws = &tip->rusage.wall_start;
	struct timespec *twe = &tip->rusage.wall_end;

	check_wall_time(tip->idx, cws, "comm->wall_start");
	check_wall_time(tip->idx, cwe, "comm->wall_end");
	check_wall_time(tip->idx, tws, "test wall_start");
	check_wall_time(tip->idx, twe, "test wall_end");

	vprint(3, "test %d\n\tstart time %lu,%lu\n", tip->idx, tws->tv_sec,
			tws->tv_nsec);
	if (tws->tv_sec < cws->tv_sec ||
	    tws->tv_sec == cws->tv_sec && tws->tv_nsec < cws->tv_nsec) {
		vprint(2, "selecting start time and rusage for thread %d\n",
			tip->idx);
		*cws = *tws;
		if (rusage_who == RUSAGE_SELF && nr_thread)
			ruse_start   = tip->rusage.ruse_start;
	}

	vprint(3, "\tend time %lu,%lu\n", twe->tv_sec, twe->tv_nsec);
	if (cwe->tv_sec < twe->tv_sec ||
	    cwe->tv_sec == twe->tv_sec && cwe->tv_nsec < twe->tv_nsec) {
		vprint(2, "selecting end time and rusage for thread %d\n",
			tip->idx);
		*cwe = *twe;
		if (rusage_who == RUSAGE_SELF && nr_thread)
			comm->rusage = tip->rusage.ruse_end;
	}

	vprint(3, "\telapsed time:  %8.3f\n", calc_elapsed_time(tws, twe));
}

void
timeval_subtract(struct timeval *tve, struct timeval *tvs)
{
	tve->tv_sec -= tvs->tv_sec;
	tve->tv_usec -= tvs->tv_usec;
	if (tve->tv_usec < 0)	{
		tve->tv_sec--;
		tve->tv_usec += 1000000;
	}
}

void
timeval_add(struct timeval *tvsum, struct timeval *tvadd)
{
	tvsum->tv_sec += tvadd->tv_sec;
	tvsum->tv_usec += tvadd->tv_usec;
	if (tvsum->tv_usec > 1000000)	{
		tvsum->tv_usec -= 1000000;
		tvsum->tv_sec++;
	}
}

/*
 * Each test should incur at least 'pages_per_test' minor faults.
 * Did it?
 */
void
check_test_rusage(int id, struct rusage *sru, struct rusage *eru)
{
	long minflts, maxflts;

	minflts = eru->ru_minflt - sru->ru_minflt;
	if (minflts < pages_per_test) {
		vprint(0, "!!! test %d:  expected %ld faults -- measured %ld\n"
			  "    user time %8.4g, system time: %8.4g\n",
			id, pages_per_test, minflts,
			calc_cpu_time(&eru->ru_utime), calc_cpu_time(&eru->ru_stime));
	}

	maxflts = eru->ru_majflt - sru->ru_majflt;
	if (maxflts)
		vprint(0, "!!! test %d:  unexpected major faults:  %ld\n",
			id, maxflts);
}

/*
 * calc_test_rusage() -
 * For multithread test, and not using RUSAGE_THREAD, subtract earliest thread's
 * start rusage from last thread's end rusage in comm area.
 * Otherwise, accumulate each thread's or task's rusage in comm area.
 */
void
calc_test_rusage(void)
{
	if (rusage_who == RUSAGE_SELF && nr_thread) {
		/*
		 * multi-thread test; no RUSAGE_THREAD
		 */
		struct rusage *sru = &ruse_start;	/* earliest starting thread */
		struct rusage *eru = &comm->rusage;	/* latest ending thread */

		timeval_subtract(&eru->ru_utime, &sru->ru_utime);
		timeval_subtract(&eru->ru_stime, &sru->ru_stime);

		eru->ru_minflt -= sru->ru_minflt;
		eru->ru_majflt -= sru->ru_majflt;

	} else {
		/*
		 * multi-task test, or multi-thread test using RUSAGE_THREAD;
		 * accumulate all tests' rusage during test loop
		 */
		struct rusage *sumru = &comm->rusage;	/* the accumulator */
		int j;
		bzero(sumru, sizeof(struct rusage));/* the accumulator */
		for (j = 0;  j < nr_tests; j++) {
			struct test_info *tip = comm->test_info + j;
			struct rusage *sru = &tip->rusage.ruse_start;
			struct rusage *eru = &tip->rusage.ruse_end;

			/*
			 * cpu usage in pft_loop() for test j
			 */
			timeval_subtract(&eru->ru_utime, &sru->ru_utime);
			timeval_subtract(&eru->ru_stime, &sru->ru_stime);

			timeval_add(&sumru->ru_utime, &eru->ru_utime);
			timeval_add(&sumru->ru_stime, &eru->ru_stime);

			/*
			 * faults in pft_loop() for test j
			 */
			check_test_rusage(j, sru, eru);
			sumru->ru_minflt += eru->ru_minflt - sru->ru_minflt;
			sumru->ru_majflt += eru->ru_majflt - sru->ru_majflt;
		}
	}
}

/*
 * launch() - Allocate test region, create/start threads, time threads.
 */
void
launch()
{
	struct timespec sleepfor = { 0, 500000L }; /* 0.5 sec */
	struct test_info *tip0 = comm->test_info;
	int     i, j, n;

	lpid = getpid();
	bind_to_cpu(launch_cpu, -2);	/* assume 'launch_cpu' exists */

	/*
	 * Pre-allocate test memory, outside of measurement interval
	 * but don't touch!
	 */
	alloc_test_memory();

	comm->go = 0;			/* threads will wait for go ahead */

	set_task_scheduler(1);		/* before starting threads */

	if (start_workers() < (nr_tests -1)) {
		fprintf(stderr, "Unable to create %d worker %s - aborting\n",
			nr_tests, nr_thread ? "threads" : "tasks");
		exit(1);
	}

	vprint(2, "%s:  waiting for workers to get ready\n", __FUNCTION__);
	nanosleep(&sleepfor, NULL);
	do {
		n = 0;
		for (j = 1; j < nr_tests; j++)
			if (comm->test_info[j].state == TEST_READY)
				n++;
	} while(n < (nr_tests - 1));

	/*
	 * Initialize wall clock end time to known "early" time
	 */
	clock_gettime(CLOCK_REALTIME, &comm->wall_end);

	comm->go = 1;		/* give all tests the go_ahead */
	pft_loop(tip0);	/* run thread/process 0 test */
	tip0->state = TEST_DONE;

	/*
	 * Initialize clock start to known "late" time
	 */
	clock_gettime(CLOCK_REALTIME, &comm->wall_start);
	update_walltime_and_rusage(tip0);	/* for test 0 */

	/*
	 * launch() thread will sleep in pthread_join() or waitpid()
	 * waiting for DONE tests to exit.
	 */
	vprint(2, "%s:  waiting for tests to finish.\n", __FUNCTION__);
	do {
		n = 0;
		nanosleep(&sleepfor, NULL);

		for (j = 1; j < nr_tests; j++) {
			struct test_info *tip = &comm->test_info[j];
			if (tip->state == TEST_REAPED) {
				n++;
				continue;
			}
			if (tip->state != TEST_DONE)
				continue;	/* don't reap unfinished tests */
			if (nr_thread) {
				pthread_join(tip->ptid, NULL);
				vprint(2, "%s:  joined thread %d\n", __FUNCTION__, tip->idx);
			} else {
				waitpid(tip->pid, NULL, 0);
				vprint(2, "%s:  process %d exited\n", __FUNCTION__, tip->idx);
			}
			update_walltime_and_rusage(tip);
			tip->state = TEST_REAPED;
			n++;
		}
	} while(n < (nr_tests - 1));

	calc_test_rusage();

	if (do_pause) {
		vprint(0, "pausing...\n");
		pause();
	}

	if (do_numa_maps) {
		char cmdbuf[80];
		int ret = snprintf(cmdbuf, 80,
			"cat /proc/%d/numa_maps | grep '^%lx'",
			 lpid, test_memory);
		if (ret < 0) {
			perror("snprintf - dumping numa_maps");
		} else {
			ret = system(cmdbuf);
			if (ret == -1)
				perror("system(3) - dumping numa_maps");
		}
	}

	exit(0);
}

/*
 * cleanup() - at exit cleanup routine
 */
static void
cleanup()
{
	vprint(3, "cleanup() entered\n");

	if (comm && comm->shmid >= 0) {
		if (shmctl(comm->shmid,IPC_RMID,0) == -1)
			perror("removal of test shmem failed");
		else vprint(3, "test shmem removed\n");
		comm->shmid = -1;
	}
}

int
main(int argc, char *argv[])
{
	extern int	optind, opterr;
	extern char	*optarg;

	int	i, j, c, stat, er=0;
	pid_t   ppid;		/* parent's pid */
	char 	*tag = NULL;
	size_t	comm_size;

	long	gbyte;
	double	faults_per_sec, faults_per_sec_per_cpu;
	double	elapsed_time, user_time, sys_time;

	ppid = getpid();
	setpgid(0, ppid);

	pagesize_init();
	bytes = pagesize;

	opterr=1;
	while ((c = getopt(argc, argv, OPTSTR)) != EOF)
		switch (c) {
		case 'a':	/* affinitize threads to cpus */
			do_cpubind++;
			break;
		case 'c':	/* number of cachelines to touch per page */
			cachelines = atol(optarg);
			break;

		case 'f':
			use_sched_fifo++;
			break;

		case 'l':
			do_mlock++;
			if (do_shmlock) {
				do_shmlock = 0;
				vprint(0,
				  "Option -l [mlock] overriding '-L' [SHM_LOCK]\n");
			}
			break;

		case 'm':	/* memory [size] */
			bytes = size_kmgp(optarg);
			if (bytes == BOGUS_SIZE) {
				vprint(0, "Bogus size:  -b %s\n", optarg);
				er++;
			}
			break;

		case 'n':	/* number of processes */
			nr_proc = atol(optarg);
			if (nr_proc > MAX_TESTS) {
				nr_proc = MAX_TESTS;
				vprint(0, "nr_proc clipped at %d\n", nr_proc);
			}
			if (nr_thread) {
				vprint(0, "nr_proc overriding nr_thread -- switching to process mode\n");
				nr_thread = 0;
			}
			break;

		case 'p':	/* use vma/shared policy */
			do_mempol++;
			break;

		case 's':	/* sleep/delay for test threads */
			sleepsec = atol(optarg);
			break;

		case 't':	/* number of threads */
			nr_thread = atol(optarg);
			if (nr_thread > MAX_TESTS) {
				nr_thread = MAX_TESTS;
				vprint(0, "nr_thread clipped at %d\n", nr_thread);
			}
			if (nr_proc) {
				vprint(0, "nr_thread overriding nr_proc -- switching to thread mode\n");
				nr_thread = 0;
			}
			break;

		case 'v':	/* multiple times for debug verbosity */
			verbose++;
			break;

		case 'z':	/* bzero() test region instead of "touch" */
			do_bzero++;
			break;

#if 0
		case 'F':	/* this doesn't really work.  Rip it out. */
			force++;
			break;
#endif

		case 'L':	/* SHM_LOCK the shared memory test area */
			do_shm++;	/* assume '-S' */
			do_shmlock++;
			multimap = 0;
			if (do_mlock) {
				do_mlock = 0;
				vprint(0,
				  "Option -L [SHM_LOCK] overriding '-l' [mlock]\n");
			}
			break;

		case 'M':	/* multimap - mmap() separate regions */
			if (do_shm) {
				vprint(0, "Ignoring '-M' for shmem\n");
			}
			multimap = pagesize;
			break;

		case 'N':	/* dump numa_maps after test */
			do_numa_maps++;
			break;

		case 'P':	/* pause after test */
			do_pause++;
			break;

		case 'S':	/* use SysV shared memory for test region */
			do_shm++;
			multimap = 0;
			break;

		case 'T':	/* emit title and tag */
			do_title++;
			break;

		case 'V':	/* show version and "build stamp" */
			vprint(0, "pft_mpol " PFT_MPOL_VERSION " built "
			         __DATE__ " @ " __TIME__  "\n");
			exit(0);
			/* NOTREACHED */

#ifdef	USE_NOCLEAR
		case 'C':	/* eliminate kernel page clearing, if supported */
			no_clear++;
			break;
#endif

		case 'Z':		/* use /dev/zero for private mappings */
			use_dev_zero();
			break;

		case 'h':	/* help */
			er++;
			break;
		case '?':
			er = 1;
			break;
		}
	if (er) {
		printf(usage, argv[0], cacheline_size);
		exit(1);
	}

	if (optind < argc) {
		tag = argv[optind++];
		// TODO:  warn about ignoring extraneous args?
	}

	cpus_init();
	cacheline_size_init();

	check_rusage_thread();		/* can we use it? */

	if (!(nr_proc | nr_thread)) {
		vprint(0, "Using 1 thread\n");
		nr_thread = 1;
	}
	nr_tests = nr_proc + nr_thread;

	bind_to_cpu(launch_cpu, -1);	/* park mainline on 'launch_cpu' */

	if (!force && nr_tests > nr_cpus_allowed) {
		vprint(0, "clipping nr_tests to nr_cpus_allowed [%d]\n",
			nr_cpus_allowed);
		nr_tests = nr_cpus_allowed;
	}

	if (multimap) {
		test_memories = calloc(nr_tests, sizeof(*test_memories));
		if (!test_memories)
			perrorx("can't alloc test_memories");
	}

	/*
	 * adjust [round up] sizes
	 */
	pages = PAGE_ALIGN(bytes) / pagesize;
	pages_per_test = ROUND_UP(pages, nr_tests) / nr_tests;
	pages = pages_per_test * nr_tests;

	bytes_per_test = pages_per_test * pagesize;
	bytes = pages * pagesize;
	gbyte = (bytes + pagesize * nr_tests) / (1024*1024*1024);

	if (pages_per_test < 1) {
		vprint(0, "Memory size too small.  "
			"Need at least 1 page per test\n");
		exit(2);
	}

	vprint(2, "Calculated pages=%ld,pages/test = %ld,pagesize=%ld\n",
			pages, pages_per_test, pagesize);

	/*
	 * Register cleanup handler
	 */
	if (atexit(cleanup) != 0)
		perrorx("atexit(cleanup) registration failed");

	/*
	 * parent/child comm area
	 */
	comm_size = sizeof(struct pft_comm) + (nr_tests - 1) * sizeof(struct test_info);
	comm = (struct pft_comm *)valloc_shared(comm_size);
	bzero(comm, comm_size);
	comm->shmid = -1;

	/*
	 * run multi-{process|thread} test in a child process
	 */
	if ((lpid = fork()) == 0)
		launch();
	while (wait(&stat) > 0);

	if (comm->abort)
		exit(1);

	elapsed_time = calc_elapsed_time(&comm->wall_start, &comm->wall_end);
	vprint(2, "elapsed time = %8.2f\n", elapsed_time);
	user_time    = calc_cpu_time(&comm->rusage.ru_utime);
	vprint(2, "user time   = %8.2f\n", user_time);
	sys_time     = calc_cpu_time(&comm->rusage.ru_stime);
	vprint(2, "system time = %8.2f\n", sys_time);

	/*
	 * Warn if number of minor faults differs "significantly" from
	 * expected value == number of pages in test memory
	 */
	if (abs(pages - comm->rusage.ru_minflt) > pages/10) {
		vprint(0, "expected faults differs from actual faults by > 10%\n");
		verbose = 1;	/* to emit calculated, actual below */
	}

	vprint(1, "Calculated faults=%ld."
		" Real minor faults=%ld,"
		" major faults=%ld\n",
		pages, comm->rusage.ru_minflt, comm->rusage.ru_majflt);

	faults_per_sec         = (double) pages / elapsed_time;
	faults_per_sec_per_cpu = (double) pages / (user_time + sys_time);

	if (do_title) {
		if (tag) {
			/* for plot post-processing */
			printf("TAG pft:%s-%s%s:%s\n",
				do_shm ? "shmem" : "anon",
				do_mempol ? "vma-policy" : "sys-default",
				do_mlock ? "-mlocked" :
				do_shmlock ? "-shm_locked" : "",
				tag);
		}
		printf("  Gb  Thr CLine   User     System     Wall"
			"    flt/cpu/s fault/wsec\n");
	}

	printf(" %3ld %4ld %3ld %8.2fs %8.2fs %8.2fs  %10.3f %10.3f\n",
		gbyte, nr_tests, cachelines,
		user_time, sys_time, elapsed_time,
		faults_per_sec_per_cpu, faults_per_sec);

	exit(0);
}

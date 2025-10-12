#pragma once

#include <fcntl.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "uoj_work_path.h"

// Forward declaration from run_program.cpp
struct RunProgramConfig;

#ifdef __x86_64__
typedef unsigned long long int reg_val_t;
#define REG_SYSCALL orig_rax
#define REG_RET rax
#define REG_ARG0 rdi
#define REG_ARG1 rsi
#define REG_ARG2 rdx
#define REG_ARG3 rcx
#else
#error "Only x86-64 is supported"
#endif

const int N_SYSCALL = 512;
const int SYSCALL_SOFT_BAN_MASK = 996 << 18;

enum EX_CHECK_TYPE : unsigned {
	ECT_NONE = 0,
	ECT_CNT = 1,
	ECT_FILE_OP = 1 << 1,
	ECT_END_AT = 1 << 2,
	ECT_FILEAT_OP = ECT_FILE_OP | ECT_END_AT,
	ECT_FILE_W = 1 << 3,
	ECT_FILE_R = 1 << 4,
	ECT_FILE_S = 1 << 5,
	ECT_CHECK_OPEN_FLAGS = 1 << 6,
	ECT_FILE2_W = 1 << 7,
	ECT_CLONE_THREAD = 1 << 10,
};

struct syscall_info {
	EX_CHECK_TYPE extra_check;
	int max_cnt;
	bool should_soft_ban = false;
	bool is_kill = false;

	syscall_info() : extra_check(ECT_CNT), max_cnt(0) {}
	syscall_info(unsigned extra_check, int max_cnt) :
	    extra_check((EX_CHECK_TYPE)extra_check), max_cnt(max_cnt) {}

	static syscall_info unlimited() { return syscall_info(ECT_NONE, -1); }

	static syscall_info count_based(int max_cnt) { return syscall_info(ECT_CNT, max_cnt); }

	static syscall_info with_extra_check(unsigned extra_check, int max_cnt = -1) {
		if (max_cnt != -1) {
			extra_check |= ECT_CNT;
		}
		return syscall_info(extra_check, max_cnt);
	}

	static syscall_info kill_type_syscall(unsigned extra_check = ECT_CNT, int max_cnt = 0) {
		if (max_cnt != -1) {
			extra_check |= ECT_CNT;
		}
		syscall_info res(extra_check, max_cnt);
		res.is_kill = true;
		return res;
	}

	static syscall_info soft_ban() {
		syscall_info res(ECT_CNT, 0);
		res.should_soft_ban = true;
		return res;
	}
};

std::map<std::string, std::vector<std::pair<int, syscall_info>>> allowed_syscall_list = {
    {"default",
     {
         {__NR_read, syscall_info::unlimited()},
         {__NR_pread64, syscall_info::unlimited()},
         {__NR_write, syscall_info::unlimited()},
         {__NR_pwrite64, syscall_info::unlimited()},
         {__NR_readv, syscall_info::unlimited()},
         {__NR_writev, syscall_info::unlimited()},
         {__NR_preadv, syscall_info::unlimited()},
         {__NR_pwritev, syscall_info::unlimited()},
         {__NR_sendfile, syscall_info::unlimited()},

         {__NR_close, syscall_info::unlimited()},
         {__NR_fstat, syscall_info::unlimited()},
         {__NR_fstatfs, syscall_info::unlimited()},
         {__NR_lseek, syscall_info::unlimited()},
         {__NR_dup, syscall_info::unlimited()},
         {__NR_dup2, syscall_info::unlimited()},
         {__NR_dup3, syscall_info::unlimited()},
         {__NR_ioctl, syscall_info::unlimited()},
         {__NR_fcntl, syscall_info::unlimited()},

         {__NR_gettid, syscall_info::unlimited()},
         {__NR_getpid, syscall_info::unlimited()},

         {__NR_mmap, syscall_info::unlimited()},
         {__NR_mprotect, syscall_info::unlimited()},
         {__NR_munmap, syscall_info::unlimited()},
         {__NR_brk, syscall_info::unlimited()},
         {__NR_mremap, syscall_info::unlimited()},
         {__NR_msync, syscall_info::unlimited()},
         {__NR_mincore, syscall_info::unlimited()},
         {__NR_madvise, syscall_info::unlimited()},

         {__NR_rt_sigaction, syscall_info::unlimited()},
         {__NR_rt_sigprocmask, syscall_info::unlimited()},
         {__NR_rt_sigreturn, syscall_info::unlimited()},
         {__NR_rt_sigpending, syscall_info::unlimited()},
         {__NR_sigaltstack, syscall_info::unlimited()},

         {__NR_getcwd, syscall_info::unlimited()},
         {__NR_uname, syscall_info::unlimited()},

         {__NR_exit, syscall_info::unlimited()},
         {__NR_exit_group, syscall_info::unlimited()},

         {__NR_arch_prctl, syscall_info::unlimited()},

         {__NR_getrusage, syscall_info::unlimited()},
         {__NR_getrlimit, syscall_info::unlimited()},

         {__NR_gettimeofday, syscall_info::unlimited()},
         {__NR_times, syscall_info::unlimited()},
         {__NR_time, syscall_info::unlimited()},
         {__NR_clock_gettime, syscall_info::unlimited()},
         {__NR_clock_getres, syscall_info::unlimited()},

         {__NR_restart_syscall, syscall_info::unlimited()},

         // for startup
         {__NR_setitimer, syscall_info::count_based(1)},
         {__NR_execve, syscall_info::count_based(1)},
         {__NR_set_robust_list, syscall_info::unlimited()},

         {__NR_set_tid_address, syscall_info::count_based(1)},
         {__NR_rseq, syscall_info::count_based(1)},

         // need to check file permissions
         {__NR_open, syscall_info::with_extra_check(ECT_FILE_OP | ECT_CHECK_OPEN_FLAGS)},
         {__NR_openat, syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_CHECK_OPEN_FLAGS)},
         {__NR_readlink, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_S)},
         {__NR_readlinkat, syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_S)},
         {__NR_access, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_R)},
         {__NR_faccessat, syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_R)},
         {__NR_faccessat2, syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_R)},
         {__NR_stat, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_S)},
         {__NR_statfs, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_S)},
         {__NR_lstat, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_S)},
         {__NR_newfstatat, syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_S)},

         // kill could be DGS or RE
         {__NR_kill, syscall_info::kill_type_syscall()},
         {__NR_tkill, syscall_info::kill_type_syscall()},
         {__NR_tgkill, syscall_info::kill_type_syscall()},

         // for python
         {__NR_prlimit64, syscall_info::soft_ban()},

         // for python and java
         {__NR_sysinfo, syscall_info::unlimited()},

         // python3 uses this call to generate random numbers
         // for fairness, all types of programs can use this call
         {__NR_getrandom, syscall_info::unlimited()},

         // futex
         {__NR_futex, syscall_info::unlimited()},

         // some python library uses epoll (e.g., z3-solver)
         {__NR_epoll_create, syscall_info::unlimited()},
         {__NR_epoll_create1, syscall_info::unlimited()},
         {__NR_epoll_ctl, syscall_info::unlimited()},
         {__NR_epoll_wait, syscall_info::unlimited()},
         {__NR_epoll_pwait, syscall_info::unlimited()},

         // for java
         {__NR_geteuid, syscall_info::unlimited()},
         {__NR_getuid, syscall_info::unlimited()},
         {__NR_setrlimit, syscall_info::soft_ban()},
         {__NR_socket, syscall_info::soft_ban()},
         {__NR_connect, syscall_info::soft_ban()},
     }},
    {"allow_proc",
     {
         {__NR_clone, syscall_info::unlimited()},
         {__NR_clone3, syscall_info::unlimited()},
         {__NR_fork, syscall_info::unlimited()},
         {__NR_vfork, syscall_info::unlimited()},
         {__NR_nanosleep, syscall_info::unlimited()},
         {__NR_clock_nanosleep, syscall_info::unlimited()},
         {__NR_wait4, syscall_info::unlimited()},

         {__NR_execve, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_R)},
     }},
    {"python",
     {
         {__NR_getdents, syscall_info::unlimited()},
         {__NR_getdents64, syscall_info::unlimited()},
     }},
    {"java",
     {
         {__NR_clone, syscall_info::with_extra_check(ECT_CLONE_THREAD, -1)},
         {__NR_clone3, syscall_info::with_extra_check(ECT_CLONE_THREAD, -1)},
         {__NR_rseq, syscall_info::unlimited()},
         {__NR_getdents, syscall_info::unlimited()},
         {__NR_getdents64, syscall_info::unlimited()},
         {__NR_sched_getaffinity, syscall_info::unlimited()},
         {__NR_sched_yield, syscall_info::unlimited()},
         {__NR_prctl, syscall_info::unlimited()},
         {__NR_prlimit64, syscall_info::unlimited()},
         {__NR_socket, syscall_info::soft_ban()},
         {__NR_connect, syscall_info::soft_ban()},
         {__NR_nanosleep, syscall_info::unlimited()},
         {__NR_clock_nanosleep, syscall_info::unlimited()},
     }},
    {"compiler",
     {
         {__NR_clone, syscall_info::unlimited()},
         {__NR_clone3, syscall_info::unlimited()},
         {__NR_fork, syscall_info::unlimited()},
         {__NR_vfork, syscall_info::unlimited()},
         {__NR_execve, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_R)},
         {__NR_wait4, syscall_info::unlimited()},
         {__NR_set_tid_address, syscall_info::unlimited()},
         {__NR_getdents, syscall_info::unlimited()},
         {__NR_getdents64, syscall_info::unlimited()},
         {__NR_umask, syscall_info::unlimited()},
         {__NR_prlimit64, syscall_info::unlimited()},
         {__NR_rename, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_W | ECT_FILE2_W)},
         {__NR_unlink, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_W)},
         {__NR_chmod, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_W)},
         {__NR_mkdir, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_W)},
         {__NR_rmdir, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_W)},
         {__NR_chdir, syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_S)},
         {__NR_fchdir, syscall_info::unlimited()},
         {__NR_ftruncate, syscall_info::unlimited()},
         {__NR_prctl, syscall_info::unlimited()},
         {__NR_rseq, syscall_info::unlimited()},
         {__NR_statx, syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_S)},
         {__NR_newfstatat, syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_S)},
         {__NR_unlinkat, syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_W)},
         {__NR_renameat, syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_W | ECT_FILE2_W)},
         {__NR_mkdirat, syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_W)},
         {__NR_fchmod, syscall_info::unlimited()},
         {__NR_fchmodat, syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_W)},
         {__NR_socketpair, syscall_info::unlimited()},
     }},
};

std::map<std::string, std::vector<std::string>> readable_file_name_list = {
    {"default",
     {
         "/lib/x86_64-linux-gnu/", "/usr/lib/x86_64-linux-gnu/", "/usr/lib/locale/",
         "/usr/share/zoneinfo/", "/etc/ld.so.nohwcap", "/etc/ld.so.preload", "/etc/ld.so.cache",
         "/etc/timezone", "/etc/localtime", "/etc/locale.alias", "/proc/self/", "/proc/*",
         "/dev/random", "/dev/urandom",
         "/sys/devices/system/cpu/",  // for java & some python libraries
         "/proc/sys/vm/",             // for java
     }},
    {"python2",
     {
         "/etc/python2.7/",
         "/usr/bin/python2.7",
         "/usr/lib/python2.7/",
         "/usr/bin/lib/python2.7/",
         "/usr/local/lib/python2.7/",
         "/usr/lib/pymodules/python2.7/",
         "/usr/bin/Modules/",
         "/usr/bin/pybuilddir.txt",
     }},
    {"python3",
     {
         "/etc/python" UOJ_JUDGER_PYTHON3_VERSION "/",
         "/usr/bin/python" UOJ_JUDGER_PYTHON3_VERSION "",
         "/usr/lib/python" UOJ_JUDGER_PYTHON3_VERSION "/",
         "/usr/lib/python3/dist-packages/",
         "/usr/bin/lib/python" UOJ_JUDGER_PYTHON3_VERSION "/",
         "/usr/local/lib/python" UOJ_JUDGER_PYTHON3_VERSION "/",
         "/usr/bin/pyvenv.cfg",
         "/usr/pyvenv.cfg",
         "/usr/bin/Modules/",
         "/usr/bin/pybuilddir.txt",
         "/usr/lib/dist-python",
     }},
    {"java", {"/sys/fs/cgroup/", "/proc/", "/usr/share/java/"}},
    {"java8", {"/usr/lib/jvm/java-8-openjdk-amd64/", "/etc/java-8-openjdk/"}},
    {"java11", {"/usr/lib/jvm/java-11-openjdk-amd64/", "/etc/java-11-openjdk/"}},
    {"compiler",
     {
         "system_root",
         "/dev/",
         "/usr/",
         "/lib/",
         "/lib64/",
         "/bin/",
         "/sbin/",
         "/sys/fs/cgroup/",
         "/proc/",
         "/etc/timezone",
         "/etc/python2.7/",
         "/etc/python" UOJ_JUDGER_PYTHON3_VERSION "/",
         "/etc/fpc-" UOJ_JUDGER_FPC_VERSION ".cfg",
         "/etc/java-8-openjdk/",
         "/etc/java-11-openjdk/",
     }},
};

std::map<std::string, std::vector<std::string>> writable_file_name_list = {
    {"default", {"/dev/null", "/proc/self/coredump_filter"}},
    {"compiler", {"/tmp/"}},
};

std::map<std::string, std::vector<std::string>> statable_file_name_list = {
    {"python", {"/usr", "/usr/bin/", "/usr/lib/"}},
    {"java", {"system_root", "/tmp/"}},
    {"compiler", {"/*", "/boot/"}},
};

std::map<std::string, std::vector<std::string>> soft_ban_file_name_list = {
    {"default", {"/dev/tty", "/dev/pts/", "/etc/nsswitch.conf", "/etc/passwd"}},
};

const size_t MaxPathLen = PATH_MAX;
std::set<std::string> writable_file_name_set;
std::set<std::string> readable_file_name_set;
std::set<std::string> statable_file_name_set;
std::set<std::string> soft_ban_file_name_set;
syscall_info syscall_info_set[N_SYSCALL];

std::string my_dirname(const std::string &path) {
	size_t p = path.rfind('/');
	if (p == std::string::npos) return ".";
	if (p == 0) return "/";
	return path.substr(0, p);
}

std::string realpath_safe(const std::string &path) {
	char real[PATH_MAX + 1] = {};
	if (realpath(path.c_str(), real) == NULL) return "";
	return real;
}

inline bool is_in_set_smart(std::string name, const std::set<std::string> &s) {
	if (name.size() > MaxPathLen) return false;
	if (s.count(name)) return true;
	for (int level = 0; !name.empty() && name != "/"; name = my_dirname(name), level++) {
		if (level == 0 && s.count(name + "/")) return true;
		if (s.count(name + "/")) return true;
	}
	if (s.count("/*")) return true;
	if (s.count("/")) return true;
	return false;
}

inline bool is_writable_file(const std::string &name) {
	if (name == "/") return writable_file_name_set.count("system_root");
	return is_in_set_smart(name, writable_file_name_set);
}
inline bool is_readable_file(const std::string &name) {
	if (is_writable_file(name)) return true;
	if (name == "/") return readable_file_name_set.count("system_root");
	return is_in_set_smart(name, readable_file_name_set);
}
inline bool is_statable_file(const std::string &name) {
	if (is_readable_file(name)) return true;
	if (name == "/") return statable_file_name_set.count("system_root");
	return is_in_set_smart(name, statable_file_name_set);
}
inline bool is_soft_ban_file(const std::string &name) {
	if (name == "/") return soft_ban_file_name_set.count("system_root");
	return is_in_set_smart(name, soft_ban_file_name_set);
}

void add_file_permission(const std::string &file_name, char mode) {
	if (file_name.empty()) return;
	std::string real_fn = realpath_safe(file_name);

	if (real_fn.empty()) {
		real_fn = file_name;
	} else {
		// realpath strips the trailing slash, add it back if it was there
		if (!file_name.empty() && file_name.back() == '/' && real_fn.back() != '/') {
			real_fn += '/';
		}
	}

	if (mode == 'w')
		writable_file_name_set.insert(real_fn);
	else if (mode == 'r')
		readable_file_name_set.insert(real_fn);
	else if (mode == 's')
		statable_file_name_set.insert(real_fn);

	if (real_fn == "system_root" || real_fn == "/*" || real_fn == "/") return;
	for (std::string name = my_dirname(real_fn); !name.empty() && name != ".";
	     name = my_dirname(name)) {
		statable_file_name_set.insert(name);
		if (name == "/") break;
	}
}

void init_conf(const RunProgramConfig &config);  // Implemented in run_program.cpp

enum CHILD_PROC_FLAG : unsigned { CPF_STARTUP = 1u << 0, CPF_IGNORE_ONE_SIGSTOP = 1u << 2 };

struct rp_child_proc {
	pid_t pid;
	unsigned flags;
	struct user_regs_struct reg = {};
	int syscall = -1;
	bool try_to_create_new_process = false;

	void soft_ban_syscall(int set_no = EPERM) {
		this->reg.REG_SYSCALL = SYSCALL_SOFT_BAN_MASK | set_no;
		ptrace(PTRACE_SETREGS, pid, NULL, &this->reg);
	}
};

std::string read_string_from_addr(reg_val_t addr, pid_t pid) {
	char res[MaxPathLen + 1], *ptr = res;
	while (ptr != res + MaxPathLen) {
		*(reg_val_t *)ptr = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
		for (size_t i = 0; i < sizeof(reg_val_t); i++, ptr++, addr++) {
			if (*ptr == 0) return res;
		}
	}
	res[MaxPathLen] = 0;
	return res;
}

std::string abspath_safe(const std::string &path, pid_t pid) {
	if (path.empty() || path[0] != '/') {
		char cwd[PATH_MAX];
		snprintf(cwd, sizeof(cwd), "/proc/%d/cwd", pid);
		char real_cwd[PATH_MAX];
		if (readlink(cwd, real_cwd, sizeof(real_cwd)) == -1) return "";
		return std::filesystem::path(real_cwd) / path;
	}
	return std::filesystem::weakly_canonical(path).string();
}

std::string read_abspath_from_addr(reg_val_t addr, pid_t pid) {
	return abspath_safe(read_string_from_addr(addr, pid), pid);
}

std::string read_abspath_from_fd_and_addr(reg_val_t fd, reg_val_t addr, pid_t pid) {
	std::string path_str = read_string_from_addr(addr, pid);
	if (path_str.empty()) return "";
	if (path_str[0] == '/') return abspath_safe(path_str, pid);
	if ((int)fd == AT_FDCWD) return abspath_safe(path_str, pid);

	char fd_path[64];
	sprintf(fd_path, "/proc/%d/fd/%llu", pid, fd);
	char base_path_buf[PATH_MAX];
	ssize_t len = readlink(fd_path, base_path_buf, sizeof(base_path_buf) - 1);
	if (len == -1) return "";
	base_path_buf[len] = '\0';
	return abspath_safe(std::string(base_path_buf) + "/" + path_str, pid);
}

bool check_file_permission(rp_child_proc *cp, const std::string &fn, char mode,
                           bool need_show_trace_details) {
	if (fn.empty()) return true;
	std::string real_fn = realpath_safe(fn);
	if (real_fn.empty()) real_fn = fn;

	bool ok = false;
	switch (mode) {
		case 'w':
			ok = is_writable_file(real_fn);
			break;
		case 'r':
			ok = is_readable_file(real_fn);
			break;
		case 's':
			ok = is_statable_file(real_fn);
			break;
		default:
			ok = false;
	}
	if (ok) return true;

	if (need_show_trace_details) {
		fprintf(stderr, "Permission denied on '%s' (mode: %c)\n", real_fn.c_str(), mode);
	}
	if (is_soft_ban_file(real_fn)) {
		cp->soft_ban_syscall(EACCES);
		return true;
	}
	return false;
}

bool check_safe_syscall(rp_child_proc *cp, bool need_show_trace_details) {
	ptrace(PTRACE_GETREGS, cp->pid, NULL, &cp->reg);
	cp->syscall = (int)cp->reg.REG_SYSCALL;

	if (cp->syscall < 0 || cp->syscall >= N_SYSCALL) return false;
	if (need_show_trace_details) fprintf(stderr, "syscall %d\n", cp->syscall);

	cp->try_to_create_new_process =
	    (cp->syscall == __NR_fork || cp->syscall == __NR_clone || cp->syscall == __NR_vfork);

	auto &cursc = syscall_info_set[cp->syscall];
	if (cursc.extra_check & ECT_CNT) {
		if (cursc.max_cnt == 0) {
			if (cursc.should_soft_ban) {
				cp->soft_ban_syscall();
				return true;
			}
			return false;
		}
		if (cursc.max_cnt > 0) cursc.max_cnt--;
	}

	if (cursc.extra_check & ECT_FILE_OP) {
		std::string fn1, fn2;
		char mode1 = '?', mode2 = '?';

		if (cursc.extra_check & ECT_END_AT)
			fn1 = read_abspath_from_fd_and_addr(cp->reg.REG_ARG0, cp->reg.REG_ARG1, cp->pid);
		else
			fn1 = read_abspath_from_addr(cp->reg.REG_ARG0, cp->pid);

		if (cursc.extra_check & ECT_CHECK_OPEN_FLAGS) {
			reg_val_t flags =
			    (cursc.extra_check & ECT_END_AT) ? cp->reg.REG_ARG2 : cp->reg.REG_ARG1;
			mode1 = 's';
			if ((flags & O_ACCMODE) == O_RDONLY)
				mode1 = (flags & (O_CREAT | O_EXCL | O_TRUNC)) == 0 ? 'r' : 'w';
			else
				mode1 = 'w';
		} else if (cursc.extra_check & ECT_FILE_S)
			mode1 = 's';
		else if (cursc.extra_check & ECT_FILE_R)
			mode1 = 'r';
		else if (cursc.extra_check & ECT_FILE_W)
			mode1 = 'w';

		if (!check_file_permission(cp, fn1, mode1, need_show_trace_details)) return false;

		if (cursc.extra_check & ECT_FILE2_W) {
			mode2 = 'w';
			if (cursc.extra_check & ECT_END_AT)
				fn2 = read_abspath_from_fd_and_addr(cp->reg.REG_ARG2, cp->reg.REG_ARG3, cp->pid);
			else
				fn2 = read_abspath_from_addr(cp->reg.REG_ARG1, cp->pid);
			if (!check_file_permission(cp, fn2, mode2, need_show_trace_details)) return false;
		}
	}

	if (cursc.extra_check & ECT_CLONE_THREAD) {
		reg_val_t flags = cp->reg.REG_ARG0;
		if (!(flags & CLONE_THREAD && flags & CLONE_VM && flags & CLONE_SIGHAND)) return false;
	}
	return true;
}

bool set_seccomp_bpf() {
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRACE(0));
	if (!ctx) return false;
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SYSCALL_SOFT_BAN_MASK | EPERM, 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SYSCALL_SOFT_BAN_MASK | EACCES, 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOENT), SYSCALL_SOFT_BAN_MASK | ENOENT, 0);
	for (int i = 0; i < N_SYSCALL; i++) {
		if (syscall_info_set[i].extra_check == ECT_NONE) {
			seccomp_rule_add(ctx, SCMP_ACT_ALLOW, i, 0);
		}
	}
	if (seccomp_load(ctx) < 0) {
		seccomp_release(ctx);
		return false;
	}
	seccomp_release(ctx);
	return true;
}

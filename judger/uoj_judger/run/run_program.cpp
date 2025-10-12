#include <argp.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "uoj_env.h"

struct RunResult {
	int result;
	int ust;
	int usm;
	int exit_code;

	RunResult(int _result, int _ust = -1, int _usm = -1, int _exit_code = -1) :
	    result(_result), ust(_ust), usm(_usm), exit_code(_exit_code) {
		if (result != RS_AC) {
			ust = -1, usm = -1;
		}
	}
};

struct RunProgramConfig {
	int time_limit;
	int real_time_limit;
	int memory_limit;
	int output_limit;
	int stack_limit;
	std::string input_file_name;
	std::string output_file_name;
	std::string error_file_name;
	std::string result_file_name;
	std::string work_path;
	std::string type;
	std::vector<std::string> extra_readable_files;
	std::vector<std::string> extra_writable_files;
	bool allow_proc;
	bool safe_mode;
	bool need_show_trace_details;

	std::string program_name;
	std::string program_basename;
	std::vector<std::string> argv;
};

#include "run_program_conf.h"

int put_result(std::string result_file_name, RunResult res) {
	FILE *f;
	if (result_file_name == "stdout")
		f = stdout;
	else if (result_file_name == "stderr")
		f = stderr;
	else
		f = fopen(result_file_name.c_str(), "w");
	fprintf(f, "%d %d %d %d\n", res.result, res.ust, res.usm, res.exit_code);
	if (f != stdout && f != stderr) fclose(f);
	return res.result == RS_JGF ? 1 : 0;
}

// Global config
RunProgramConfig run_program_config;

void init_conf(const RunProgramConfig &config) {
	std::vector<std::string> profiles_to_load;
	profiles_to_load.push_back("default");
	if (config.allow_proc) profiles_to_load.push_back("allow_proc");
	if (config.type == "python2") profiles_to_load.push_back("python");
	if (config.type == "python3") profiles_to_load.push_back("python");
	if (config.type == "java8" || config.type == "java11") profiles_to_load.push_back("java");
	if (config.type != "default") profiles_to_load.push_back(config.type);

	for (const auto &profile : profiles_to_load) {
		if (allowed_syscall_list.count(profile)) {
			for (const auto &pair : allowed_syscall_list[profile]) {
				syscall_info_set[pair.first] = pair.second;
			}
		}
	}

	auto load_file_perms = [&](const std::map<std::string, std::vector<std::string>> &list,
	                           char mode) {
		for (const auto &profile : profiles_to_load) {
			if (list.count(profile)) {
				for (const auto &name : list.at(profile)) add_file_permission(name, mode);
			}
		}
	};
	load_file_perms(readable_file_name_list, 'r');
	load_file_perms(writable_file_name_list, 'w');
	load_file_perms(statable_file_name_list, 's');

	if (soft_ban_file_name_list.count("default")) {
		for (const auto &name : soft_ban_file_name_list["default"]) {
			soft_ban_file_name_set.insert(name);
		}
	}

	add_file_permission(config.work_path, 'r');
	if (config.type == "compiler") {
		add_file_permission(config.work_path + "/", 'w');
	}

	if (config.type != "java8" && config.type != "java11") {
		add_file_permission(config.program_name, 'r');
	} else {
		add_file_permission(config.work_path + "/", 'r');
	}

	for (const auto &file : config.extra_readable_files) add_file_permission(file, 'r');
	for (const auto &file : config.extra_writable_files) add_file_permission(file, 'w');
}

argp_option run_program_argp_options[] = {
    {"tl", 'T', "TIME_LIMIT", 0, "Set time limit (in second)", 1},
    {"rtl", 'R', "TIME_LIMIT", 0, "Set real time limit (in second)", 2},
    {"ml", 'M', "MEMORY_LIMIT", 0, "Set memory limit (in mb)", 3},
    {"ol", 'O', "OUTPUT_LIMIT", 0, "Set output limit (in mb)", 4},
    {"sl", 'S', "STACK_LIMIT", 0, "Set stack limit (in mb)", 5},
    {"in", 'i', "IN", 0, "Set input file name", 6},
    {"out", 'o', "OUT", 0, "Set output file name", 7},
    {"err", 'e', "ERR", 0, "Set error file name", 8},
    {"work-path", 'w', "WORK_PATH", 0, "Set the work path of the program", 9},
    {"type", 't', "TYPE", 0, "Set the program type (for some program such as python)", 10},
    {"res", 'r', "RESULT_FILE", 0, "Set the file name for outputing the result            ", 10},
    {"add-readable", 500, "FILE", 0, "Add a readable file", 11},
    {"add-writable", 505, "FILE", 0, "Add a writable file", 11},
    {"unsafe", 501, 0, 0, "Don't check dangerous syscalls", 12},
    {"show-trace-details", 502, 0, 0, "Show trace details", 13},
    {"allow-proc", 503, 0, 0, "Allow fork, exec... etc.", 14},
    {"add-readable-raw", 504, "FILE", 0, "Add a readable (don't transform to its real path)", 15},
    {"add-writable-raw", 506, "FILE", 0, "Add a writable (don't transform to its real path)", 15},
    {0}};
error_t run_program_argp_parse_opt(int key, char *arg, struct argp_state *state) {
	RunProgramConfig *config = (RunProgramConfig *)state->input;
	switch (key) {
		case 'T':
			config->time_limit = atoi(arg);
			break;
		case 'R':
			config->real_time_limit = atoi(arg);
			break;
		case 'M':
			config->memory_limit = atoi(arg);
			break;
		case 'O':
			config->output_limit = atoi(arg);
			break;
		case 'S':
			config->stack_limit = atoi(arg);
			break;
		case 'i':
			config->input_file_name = arg;
			break;
		case 'o':
			config->output_file_name = arg;
			break;
		case 'e':
			config->error_file_name = arg;
			break;
		case 'w':
			config->work_path = realpath_safe(arg);
			if (config->work_path.empty()) argp_usage(state);
			break;
		case 'r':
			config->result_file_name = arg;
			break;
		case 't':
			config->type = arg;
			break;
		case 500:
			config->extra_readable_files.push_back(realpath_safe(arg));
			break;
		case 501:
			config->safe_mode = false;
			break;
		case 502:
			config->need_show_trace_details = true;
			break;
		case 503:
			config->allow_proc = true;
			break;
		case 504:
			config->extra_readable_files.push_back(arg);
			break;
		case 505:
			config->extra_writable_files.push_back(realpath_safe(arg));
			break;
		case 506:
			config->extra_writable_files.push_back(arg);
			break;
		case ARGP_KEY_ARG:
			config->argv.push_back(arg);
			for (int i = state->next; i < state->argc; i++) config->argv.push_back(state->argv[i]);
			state->next = state->argc;
			break;
		case ARGP_KEY_END:
			if (state->arg_num == 0) argp_usage(state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
char run_program_argp_args_doc[] = "program arg1 arg2 ...";
char run_program_argp_doc[] = "run_program: a tool to run program safely";
argp run_program_argp = {run_program_argp_options, run_program_argp_parse_opt,
                         run_program_argp_args_doc, run_program_argp_doc};

void parse_args(int argc, char **argv) {
	run_program_config.time_limit = 1;
	run_program_config.real_time_limit = -1;
	run_program_config.memory_limit = 256;
	run_program_config.output_limit = 64;
	run_program_config.stack_limit = 1024;
	run_program_config.input_file_name = "stdin";
	run_program_config.output_file_name = "stdout";
	run_program_config.error_file_name = "stderr";
	run_program_config.work_path = "";
	run_program_config.result_file_name = "stdout";
	run_program_config.type = "default";
	run_program_config.safe_mode = true;
	run_program_config.need_show_trace_details = false;
	run_program_config.allow_proc = false;

	argp_parse(&run_program_argp, argc, argv, ARGP_NO_ARGS | ARGP_IN_ORDER, 0, &run_program_config);

	if (run_program_config.real_time_limit == -1)
		run_program_config.real_time_limit = run_program_config.time_limit + 2;
	run_program_config.stack_limit =
	    std::min(run_program_config.stack_limit, run_program_config.memory_limit);

	if (!run_program_config.work_path.empty()) {
		if (chdir(run_program_config.work_path.c_str()) == -1) {
			exit(put_result(run_program_config.result_file_name, RS_JGF));
		}
	}

	if (run_program_config.type == "java8" || run_program_config.type == "java11") {
		run_program_config.program_name = run_program_config.argv[0];
	} else {
		run_program_config.program_name = realpath_safe(run_program_config.argv[0]);
	}
	if (run_program_config.work_path.empty()) {
		run_program_config.work_path = my_dirname(run_program_config.program_name);
		char *path_copy = strdup(run_program_config.program_name.c_str());
		run_program_config.program_basename = basename(path_copy);
		free(path_copy);
		run_program_config.argv[0] = "./" + run_program_config.program_basename;
		if (chdir(run_program_config.work_path.c_str()) == -1) {
			exit(put_result(run_program_config.result_file_name, RS_JGF));
		}
	}

	if (run_program_config.type == "python2") {
		std::string pre[4] = {"/usr/bin/python2", "-E", "-s", "-B"};
		run_program_config.argv.insert(run_program_config.argv.begin(), pre, pre + 4);
	} else if (run_program_config.type == "python3") {
		std::string pre[3] = {"/usr/bin/python3", "-I", "-B"};
		run_program_config.argv.insert(run_program_config.argv.begin(), pre, pre + 3);
	} else if (run_program_config.type == "java8") {
		std::string pre[3] = {"/usr/lib/jvm/java-8-openjdk-amd64/bin/java", "-Xmx1024m",
		                      "-Xss1024m"};
		run_program_config.argv.insert(run_program_config.argv.begin(), pre, pre + 3);
	} else if (run_program_config.type == "java11") {
		std::string pre[3] = {"/usr/lib/jvm/java-11-openjdk-amd64/bin/java", "-Xmx1024m",
		                      "-Xss1024m"};
		run_program_config.argv.insert(run_program_config.argv.begin(), pre, pre + 3);
	}
}

void set_limit(int r, int rcur, int rmax = -1) {
	if (rmax == -1) rmax = rcur;
	struct rlimit l;
	if (getrlimit(r, &l) == -1) exit(55);
	l.rlim_cur = rcur;
	l.rlim_max = rmax;
	if (setrlimit(r, &l) == -1) exit(55);
}

void set_user_cpu_time_limit(double tl) {
	itimerval val;
	val.it_value.tv_sec = (time_t)tl;
	val.it_value.tv_usec = (suseconds_t)((tl - val.it_value.tv_sec) * 1000000);
	val.it_interval = {0, 100000};
	val.it_value.tv_usec += 100000;
	if (val.it_value.tv_usec >= 1000000) {
		val.it_value.tv_sec++;
		val.it_value.tv_usec -= 1000000;
	}
	setitimer(ITIMER_VIRTUAL, &val, NULL);
}

[[noreturn]] void run_child() {
	setpgid(0, 0);
	set_limit(RLIMIT_FSIZE, run_program_config.output_limit << 20);
	set_limit(RLIMIT_STACK, run_program_config.stack_limit << 20);

	if (run_program_config.input_file_name != "stdin") {
		if (freopen(run_program_config.input_file_name.c_str(), "r", stdin) == NULL) exit(11);
	}
	if (run_program_config.output_file_name != "stdout"
	    && run_program_config.output_file_name != "stderr") {
		if (freopen(run_program_config.output_file_name.c_str(), "w", stdout) == NULL) exit(12);
	}
	if (run_program_config.error_file_name != "stderr") {
		if (run_program_config.error_file_name == "stdout") {
			if (dup2(1, 2) == -1) exit(13);
		} else {
			if (freopen(run_program_config.error_file_name.c_str(), "w", stderr) == NULL) exit(14);
		}
		if (run_program_config.output_file_name == "stderr") {
			if (dup2(2, 1) == -1) exit(15);
		}
	}

	char *env_path_str = getenv("PATH");
	char *env_lang_str = getenv("LANG");
	char *env_shell_str = getenv("SHELL");
	std::string env_path = env_path_str ? env_path_str : "";
	std::string env_lang = env_lang_str ? env_lang_str : "";
	std::string env_shell = env_shell_str ? env_shell_str : "";

	clearenv();
	setenv("USER", "poor_program", 1);
	setenv("LOGNAME", "poor_program", 1);
	setenv("HOME", run_program_config.work_path.c_str(), 1);
	if (env_lang_str) {
		setenv("LANG", env_lang.c_str(), 1);
	}
	if (env_path_str) {
		setenv("PATH", env_path.c_str(), 1);
	}
	setenv("PWD", run_program_config.work_path.c_str(), 1);
	if (env_shell_str) {
		setenv("SHELL", env_shell.c_str(), 1);
	}

	char **program_c_argv = new char *[run_program_config.argv.size() + 1];
	for (size_t i = 0; i < run_program_config.argv.size(); i++) {
		program_c_argv[i] = strdup(run_program_config.argv[i].c_str());
	}
	program_c_argv[run_program_config.argv.size()] = NULL;

	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) exit(16);
	kill(getpid(), SIGSTOP);
	if (run_program_config.safe_mode && !set_seccomp_bpf()) exit(99);

	set_user_cpu_time_limit(run_program_config.time_limit);

	execv(program_c_argv[0], program_c_argv);
	_exit(17);
}

const size_t MAX_TOTAL_RP_CHILDREN = 100;
size_t total_rp_children = 0;
pid_t rp_timer_pid;
std::vector<rp_child_proc> rp_children;

void stop_all(RunResult res) {
	kill(rp_timer_pid, SIGKILL);
	if (!rp_children.empty()) {
		killpg(rp_children[0].pid, SIGKILL);
	}
	for (auto &rpc : rp_children) {
		kill(rpc.pid, SIGKILL);
	}
	int stat;
	while (wait(&stat) > 0);
	exit(put_result(run_program_config.result_file_name, res));
}

int rp_children_pos(pid_t pid) {
	for (size_t i = 0; i < rp_children.size(); i++) {
		if (rp_children[i].pid == pid) return (int)i;
	}
	return -1;
}
void rp_children_add(pid_t pid) {
	rp_child_proc rpc;
	rpc.pid = pid;
	rpc.flags = CPF_STARTUP | CPF_IGNORE_ONE_SIGSTOP;
	rp_children.push_back(rpc);
}
void rp_children_del(pid_t pid) {
	size_t new_n = 0;
	for (size_t i = 0; i < rp_children.size(); i++) {
		if (rp_children[i].pid != pid) rp_children[new_n++] = rp_children[i];
	}
	rp_children.resize(new_n);
}

[[noreturn]] void trace_children() {
	rp_timer_pid = fork();
	if (rp_timer_pid == -1)
		stop_all(RunResult(RS_JGF));
	else if (rp_timer_pid == 0) {
		struct timespec ts = {.tv_sec = run_program_config.real_time_limit, .tv_nsec = 0};
		ts.tv_nsec += 100'000'000;
		if (ts.tv_nsec >= 1'000'000'000) {
			ts.tv_sec += 1;
			ts.tv_nsec -= 1'000'000'000;
		}
		nanosleep(&ts, NULL);
		exit(0);
	}

	while (true) {
		int stat = 0;
		struct rusage ruse;
		pid_t pid = wait4(-1, &stat, __WALL, &ruse);

		if (pid < 0) {
			if (errno == ECHILD) stop_all(RunResult(RS_AC, 0, 0, 0));  // No more children
			continue;
		}

		if (pid == rp_timer_pid) {
			if (WIFEXITED(stat) || WIFSIGNALED(stat)) stop_all(RunResult(RS_TLE));
			continue;
		}

		int p = rp_children_pos(pid);
		if (p == -1) {
			if (run_program_config.need_show_trace_details) fprintf(stderr, "new_proc %d\n", pid);
			rp_children_add(pid);
			p = (int)rp_children.size() - 1;
		}
		rp_child_proc *cp = &rp_children[p];

		// Resource checks should be valid for all tracked child processes
		int usertim = ruse.ru_utime.tv_sec * 1000 + ruse.ru_utime.tv_usec / 1000;
		int usermem = ruse.ru_maxrss;
		if (usertim > run_program_config.time_limit * 1000) stop_all(RunResult(RS_TLE));
		if (usermem > run_program_config.memory_limit * 1024) stop_all(RunResult(RS_MLE));

		if (WIFEXITED(stat)) {
			if (p == 0) {
				stop_all(RunResult(RS_AC, usertim, usermem, WEXITSTATUS(stat)));
			} else {
				rp_children_del(pid);
			}
			continue;
		}
		if (WIFSIGNALED(stat)) {
			if (p == 0) {
				int signal_num = WTERMSIG(stat);
				if (signal_num == SIGXFSZ) stop_all(RunResult(RS_OLE));
				stop_all(RunResult(RS_RE));
			} else {
				rp_children_del(pid);
			}
			continue;
		}

		if (!WIFSTOPPED(stat)) continue;

		int sig = WSTOPSIG(stat);
		int pevent = (unsigned)stat >> 16;

		if (cp->flags & CPF_STARTUP) {
			int ptrace_opt = PTRACE_O_EXITKILL;
			if (run_program_config.safe_mode) {
				ptrace_opt |= PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
				ptrace_opt |= PTRACE_O_TRACESECCOMP;
			}
			if (ptrace(PTRACE_SETOPTIONS, pid, NULL, ptrace_opt) == -1) stop_all(RunResult(RS_JGF));
			cp->flags &= ~CPF_STARTUP;
		}

		bool is_event_trap = (pevent == PTRACE_EVENT_SECCOMP || pevent == PTRACE_EVENT_FORK
		                      || pevent == PTRACE_EVENT_CLONE || pevent == PTRACE_EVENT_VFORK);

		if (sig == SIGTRAP) {
			if (is_event_trap) {
				// This is the ptrace event we expect to handle
				if (pevent == PTRACE_EVENT_SECCOMP) {
					if (run_program_config.safe_mode) {
						if (!check_safe_syscall(cp, run_program_config.need_show_trace_details)) {
							stop_all(RunResult(RS_DGS));
						}
						if (cp->try_to_create_new_process) {
							total_rp_children++;
							if (total_rp_children > MAX_TOTAL_RP_CHILDREN)
								stop_all(RunResult(RS_DGS));
						}
					}
				}
				// For fork/clone events, we don’t need to do additional processing, just continue
			}
			// For all SIGTRAP (whether normal trap or event trap), we should not pass it to the
			// child process
			sig = 0;
		} else if (sig == SIGSTOP && (cp->flags & CPF_IGNORE_ONE_SIGSTOP)) {
			sig = 0;
			cp->flags &= ~CPF_IGNORE_ONE_SIGSTOP;
		} else if (sig == SIGVTALRM) {  // User CPU TLE signal
			sig = 0;                    // Ignore, we use rusage
		} else if (sig == SIGXFSZ) {
			stop_all(RunResult(RS_OLE));
		}
		// For other signals (such as SIGSEGV, SIGFPE, etc.), we retain the value of sig,
		// This way PTRACE_CONT will pass them to the child process and let the child process handle
		// it in the default way (usually crash) This is important for catching real Runtime Errors.

		ptrace(PTRACE_CONT, pid, NULL, sig);
	}
}

int main(int argc, char **argv) {
	parse_args(argc, argv);

	init_conf(run_program_config);

	pid_t pid = fork();
	if (pid == -1) {
		return put_result(run_program_config.result_file_name, RS_JGF);
	} else if (pid == 0) {
		run_child();
	} else {
		rp_children_add(pid);
		trace_children();
	}
	return put_result(run_program_config.result_file_name, RS_JGF);
}

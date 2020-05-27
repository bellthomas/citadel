
#include <citadel/citadel.h>
#include <time.h>
#include <string>
#include <map>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include "../includes/app.h"
#include "../includes/benchmarking.h"
#include "../includes/tests.h"

enum Action {
	A_BENCHMARK,
	A_FILE_TEST,
	A_SOCKET_I_TEST,
	A_SOCKET_E_TEST,
	A_PIPE_TEST,
	A_FIFO_TEST,
	A_SHM_TEST,
	A_TAINT,
	A_PTY,
};
static std::map<std::string, Action> actions;
static bool hold = true;

void init_actions(void) {
	actions["benchmark"] = A_BENCHMARK;
	actions["file"] = A_FILE_TEST;
	actions["socketi"] = A_SOCKET_I_TEST;
	actions["sockete"] = A_SOCKET_E_TEST;
	actions["pipe"] = A_PIPE_TEST;
	actions["fifo"] = A_FIFO_TEST;
	actions["shm"] = A_SHM_TEST;
	actions["taint"] = A_TAINT;
	actions["pty"] = A_PTY;
} 

int to_action(std::string str) {
	if (actions.find(str) == actions.end()) return -1;
	else return actions[str];
}

void signal_handler(int s) {
    printf("\nMoving on...\n");
	if (!hold) exit(1);
    hold = false;
}

bool on_hold(void) {
	return hold;
}

void reset_hold(void) {
	hold = true;
}

int main(int argc, char** argv) {

	// if (argc == 1) {
	// 	printf("No arguments given!\n");
	// 	return 0;
	// }

	// Catch Ctrl+C and systemd stop commands.
    struct sigaction interrupt_handler;
    interrupt_handler.sa_handler = signal_handler;
    sigemptyset(&interrupt_handler.sa_mask);
    interrupt_handler.sa_flags = 0;
    sigaction(SIGINT, &interrupt_handler, NULL);
    sigaction(SIGTERM, &interrupt_handler, NULL);

	printf("PID: %d\n", getpid());
	init_actions();
	run_init();
	for (int i = 1; i < argc; i++) {
		std::string s_arg(argv[i]);
		switch (to_action(s_arg)) {
		case A_BENCHMARK:
			run_benchmarks();
			break;
		case A_TAINT:
			run_taint();
			break;
		case A_FILE_TEST:
			run_file_test();
			break;
		case A_SOCKET_I_TEST:
			run_socket_i_test();
			break;
		case A_SOCKET_E_TEST:
			run_socket_e_test();
			break;		
		case A_PIPE_TEST:
			run_pipe_test();
			break;		
		case A_FIFO_TEST:
			run_fifo_test();
			break;
		case A_SHM_TEST:
			run_shm_test();
			break;
		case A_PTY:
			run_pty();
			break;
		default:
			printf("Invalid option: %s, %d\n", s_arg.c_str(), to_action(s_arg));
			break;
		}
	}
	
}


#include <citadel/citadel.h>
#include <time.h>
#include <string>
#include <map>

#include "../includes/app.h"
#include "../includes/benchmarking.h"
#include "../includes/tests.h"

enum Action {
	A_BENCHMARK,
	A_FILE_TEST
};
static std::map<std::string, Action> actions;

void init_actions(void) {
	actions["benchmark"] = A_BENCHMARK;
	actions["file"] = A_FILE_TEST;
} 

int to_action(std::string str) {
	if (actions.find(str) == actions.end()) return -1;
	else return actions[str];
}

int main(int argc, char** argv) {

	if (argc == 1) {
		printf("No arguments given!\n");
		return 0;
	}

	init_actions();
	for (int i = 1; i < argc; i++) {
		std::string s_arg(argv[i]);
		switch (to_action(s_arg)) {
		case A_BENCHMARK:
			run_benchmarks();
			break;
		case A_FILE_TEST:
			run_file_test();
			break;
		default:
			printf("Invalid option: %s, %d\n", s_arg.c_str(), to_action(s_arg));
			break;
		}
	}
	
}

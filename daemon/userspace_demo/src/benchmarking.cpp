#include <citadel/citadel.h>
#include <time.h>

#include "../includes/benchmarking.h"

static int repetitions = 50000;


void run_benchmarks(void) {
	FILE *fp;
	fp = fopen("/opt/citadel-perf/libcitadel-benchmarks", "a");
	if(!fp) return;

	printf("1. citadel_init()\n");
	uint64_t diff;
	struct timespec start, end;
	for (int i = 0; i < repetitions; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		citadel_init();
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(fp, "citadel_init,%llu\n", (long long unsigned int) diff);
	}

	
	sleep(1);
	printf("2. citadel_claim()\n");

	const char path[] = "/opt/testing_dir/userspace_file.txt";
	for (int i = 0; i < repetitions; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		citadel_file_recreate((char*)path, sizeof(path));
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(fp, "citadel_claim,%llu\n", (long long unsigned int) diff);
	}

	sleep(1);
	printf("3. citadel_open()\n");
	for (int i = 0; i < repetitions; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		citadel_file_open((char*)path, sizeof(path));
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(fp, "citadel_open,%llu\n", (long long unsigned int) diff);
	}

	fclose(fp);
}

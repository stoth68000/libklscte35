/* Copyright Kernel Labs Inc 2016 */

#include <stdio.h>
#include <string.h>
#include <libgen.h>

/* External tool hooks */
extern int demo_main(int argc, char *argv[]);
extern int parse_main(int argc, char *argv[]);
extern int scte104_main(int argc, char *argv[]);

typedef int (*func_ptr)(int, char *argv[]);

int main(int argc, char *argv[])
{
	struct app_s {
		char *name;
		func_ptr func;
	} apps[] = {
		{ "klscte35_util",		demo_main, },
		{ "klscte35_parse",		parse_main, },
		{ "klscte35_scte104",		scte104_main, },
		{ 0, 0 },
	};
	char *appname = basename(argv[0]);

	int i = 0;
	struct app_s *app = &apps[i++];
	while (app->name) {
		if (strcmp(appname, app->name) == 0)
			return app->func(argc, argv);

		app = &apps[i++];
	}

	printf("No application called %s, aborting.\n", appname);
	i = 0;
	app = &apps[i++];
	while (app->name) {
		printf("%s ", app->name);
		app = &apps[i++];
	}

	return 1;
}

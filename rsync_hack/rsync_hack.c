#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>

static int fd_err = -1;
static FILE *debug;
void _init(void)
{
	debug=stderr;
	/* Make sure that nothing gets spit to stdout */
	stdout = stderr;
	/* save a file descriptor for stderr because rsync seams to close it
	 * at the and I want to write some debuging messages */
	fd_err = dup(2);
	fprintf(debug, "starting\n");
}
void _fini(void)
{
	fprintf(debug, "ending\n");
}

int mkstemp(char *template)
{
	fprintf(debug, "file_template: %s\n", template);
	open(template, O_RDWR|O_CREAT, 0600);
	return 1;
}
int mkstemp64(char *template)
{
	return mkstemp(template);
}
int rename(const char *oldpath, const char *newpath)
{
	dup2(fd_err, 2);
	fprintf(debug, "newpath: %s\n", newpath);
	if(strstr(oldpath, "XXXXXX")) {
		char command[300] = "touch -r ";
		fprintf(debug, "removeing %s\n", oldpath);
		/* rsync changes the mtime on the temporal file, so use that
		 * to touch owr file */
		snprintf(command, sizeof(command), "touch -r %s %s",
				oldpath, newpath);
		system(command);
		return unlink(oldpath);
	} else{
		fprintf(debug, "renaiming %s\n\n", oldpath);
		return syscall(SYS_rename, oldpath, newpath);
	}
}

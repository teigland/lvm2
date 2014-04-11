#define _GNU_SOURCE
#include "lvmlockd-client.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

static int quit;
static int info;
static int dump;
static int gl_enable;
static int gl_disable;

static char *vg_name;

static int cmd_pipe[2];
static int cmd_argc;
static char *cmd_name;
static char **cmd_argv;

daemon_handle _lvmlockd;

#define log_debug(fmt, args...) \
do { \
	printf(fmt "\n", ##args); \
} while (0)

#define log_error(fmt, args...) \
do { \
	printf(fmt "\n", ##args); \
} while (0)


static daemon_reply _lvmlockd_send(const char *req_name, ...)
{
	va_list ap;
	daemon_reply repl;
	daemon_request req;

	req = daemon_request_make(req_name);

	va_start(ap, req_name);
	daemon_request_extend_v(req, ap);
	va_end(ap);

	repl = daemon_send(_lvmlockd, req);

	daemon_request_destroy(req);

	return repl;
}

static int _lvmlockd_result(daemon_reply reply, int *result)
{
	int reply_result;
	const char *reply_flags;
	const char *lock_type;

	if (reply.error) {
		log_error("lvmlockd_result reply error %d", reply.error);
		return 0;
	}

	if (strcmp(daemon_reply_str(reply, "response", ""), "OK")) {
		log_error("lvmlockd_result bad response");
		return 0;
	}

	/* FIXME: using -1000 is dumb */

	reply_result = daemon_reply_int(reply, "op_result", -1000);
	if (reply_result == -1000) {
		log_error("lvmlockd_result no op_result");
		return 0;
	}

	/* The lock_type that lvmlockd used for locking. */
	lock_type = daemon_reply_str(reply, "lock_type", "none");

	*result = reply_result;

	reply_flags = daemon_reply_str(reply, "result_flags", NULL);

	log_debug("lvmlockd_result %d %s lm %s", reply_result, reply_flags, lock_type);
	return 1;
}

static int do_quit(void)
{
	daemon_reply reply;
	int rv = 0;

	reply = daemon_send_simple(_lvmlockd, "quit", NULL);

	if (reply.error) {
		log_error("reply error %d", reply.error);
		rv = reply.error;
	}

	daemon_reply_destroy(reply);
	return rv;
}

#define DUMP_SOCKET_NAME "lvmlockd-dump.sock"
#define DUMP_BUF_SIZE (1024 * 1024)
static char dump_buf[DUMP_BUF_SIZE];
static struct sockaddr_un dump_addr;
static socklen_t dump_addrlen;

static int setup_dump_socket(void)
{
	int s, rv;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0)
		return s;

	memset(&dump_addr, 0, sizeof(dump_addr));
	dump_addr.sun_family = AF_LOCAL;
	strcpy(&dump_addr.sun_path[1], DUMP_SOCKET_NAME);
	dump_addrlen = sizeof(sa_family_t) + strlen(dump_addr.sun_path+1) + 1;

	rv = bind(s, (struct sockaddr *) &dump_addr, dump_addrlen);
	if (rv < 0)
		return rv;

	return s;
}

static int do_dump(const char *req_name)
{
	daemon_reply reply;
	int result;
	int dump_len;
	int fd, rv;

	fd = setup_dump_socket();
	if (fd < 0) {
		log_error("socket error %d", fd);
		return fd;
	}

	reply = daemon_send_simple(_lvmlockd, req_name, NULL);

	if (reply.error) {
		log_error("reply error %d", reply.error);
		rv = reply.error;
		goto out;
	}

	result = daemon_reply_int(reply, "result", 0);
	dump_len = daemon_reply_int(reply, "dump_len", 0);

	daemon_reply_destroy(reply);

	if (result < 0)
		log_error("result %d", result);

	if (!dump_len)
		goto out;

	memset(dump_buf, 0, sizeof(dump_buf));

	rv = recvfrom(fd, dump_buf, dump_len, MSG_WAITALL,
		      (struct sockaddr *)&dump_addr, &dump_addrlen);
	if (rv < 0) {
		log_error("recvfrom error %d %d", rv, errno);
		rv = -errno;
		goto out;
	}

	rv = 0;
	printf("%s\n", dump_buf);
out:
	close(fd);
	return rv;
}

static int do_able(const char *req_name)
{
	daemon_reply reply;
	int result;
	int rv;

	reply = _lvmlockd_send(req_name,
				"cmd = %s", "lvmlock",
				"pid = %d", getpid(),
				"vg_name = %s", vg_name,
				NULL);

	if (!_lvmlockd_result(reply, &result)) {
		log_error("lvmlockd result %d", result);
		rv = result;
	} else {
		rv = 0;
	}

	daemon_reply_destroy(reply);
	return rv;
}

static void print_usage(void)
{
	printf("--help\n");
	printf("--quit\n");
	printf("--info\n");
	printf("--dump\n");
	printf("--gl-enable <vg_name>\n");
	printf("--gl-disable <vg_name>\n");
}

static int read_options(int argc, char *argv[])
{
	int option_index = 0;
	int i, j, c, len;

	static struct option long_options[] = {
		{"help",       no_argument,       0,  'h' },
		{"quit",       no_argument,       0,  'q' },
		{"info",       no_argument,       0,  'i' },
		{"dump",       no_argument,       0,  'd' },
		{"gl-enable",  required_argument, 0,  'E' },
		{"gl-disable", required_argument, 0,  'D' },
		{"sleep",      required_argument, 0,  's' },
		{"command",    required_argument, 0,  'c' },
		{0, 0, 0, 0 }
	};

	/*
	if (argc == 1) {
		print_usage();
		exit(0);
	}
	*/

	while (1) {
		c = getopt_long(argc, argv, "hqidE:D:s:c:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			/* --help */
			print_usage();
			exit(0);
		case 'q':
			/* --quit */
			quit = 1;
			break;
		case 'i':
			/* --info */
			info = 1;
			break;
		case 'd':
			/* --dump */
			dump = 1;
			break;
		case 'E':
			gl_enable = 1;
			vg_name = strdup(optarg);
			break;
		case 'D':
			gl_disable = 1;
			vg_name = strdup(optarg);
			break;
		case 'c':
			/* --command path args */
			cmd_name = strdup(optarg);
			break;
		default:
			print_usage();
			exit(1);
		}

		if (cmd_name)
			break;
	}

	if (cmd_name) {
		/*
		 * optind is the index in argv of the first argv element that
		 * is not an option.
		 */

		cmd_argc = argc - optind + 1; /* +1 for cmd_name */

		len = (cmd_argc + 1) * sizeof(char *); /* +1 for final NULL */
		cmd_argv = malloc(len);
		if (!cmd_argv)
			return -ENOMEM;
		memset(cmd_argv, 0, len);

		j = 0;
		cmd_argv[j++] = cmd_name;

		for (i = optind; i < argc; i++) {
			cmd_argv[j++] = strdup(argv[i]);
			if (!cmd_argv[j-1])
				return -ENOMEM;
		}
	}

	return 0;
}

static void run_command(void)
{
	char go[1];
	int rv;

	while (1) {
		/* wait for parent to tell us to go */
		rv = read(cmd_pipe[0], go, 1);
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv == 1 && go[0] == 'g')
			break;
		else
			exit(-1);
	}

	execv(cmd_name, cmd_argv);
	log_error("execv failed");
}

int main(int argc, char **argv)
{
	int status;
	int pid = 0;
	int rv = 0;

	rv = read_options(argc, argv);
	if (rv < 0)
		return rv;

	/*
	 * fork child for command before acquiring locks,
	 * exec command in child after acquiring locks,
	 * release locks after child exits.
	 */

	if (cmd_name) {
		if (pipe(cmd_pipe)) {
			log_error("pipe error");
			return -1;
		}
		pid = fork();
		if (pid < 0) {
			log_error("cannot fork");
			return -1;
		}
		if (!pid) {
			run_command();
			return -1;
		}
	}

	_lvmlockd = lvmlockd_open(NULL);

	if (_lvmlockd.socket_fd < 0 || _lvmlockd.error) {
		log_error("lvmlockd open error %d", _lvmlockd.error);
		goto out_pid;
	}

	if (quit) {
		rv = do_quit();
		goto out;
	}

	if (info) {
		rv = do_dump("info");
		goto out;
	}

	if (dump) {
		rv = do_dump("dump");
		goto out;
	}

	if (gl_enable) {
		rv = do_able("enable_gl");
		goto out;
	}

	if (gl_disable) {
		rv = do_able("disable_gl");
		goto out;
	}

	if (pid) {
		/* tell child to exec */
		write(cmd_pipe[1], "g", 1);
		waitpid(pid, &status, 0);
		pid = 0;
	}
out:
	lvmlockd_close(_lvmlockd);
out_pid:
	if (pid) {
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
	}

	return rv;
}


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
#include <sys/types.h>
#include <sys/wait.h>

static int hello;
static int test;
static int quit;

static int lock_init;
static int lock_start;
static int lock_stop;
static int lock_enable;
static int lock_disable;
static int lock_gl;
static int lock_vg;
static int lock_lv;

static int gl_arg;
static int vg_arg;
static int lv_arg;

static char *gl_mode;
static char *vg_mode;
static char *lv_mode;

static char *vg_name;
static char *lv_name;

static char *lm_type;
static char *lm_args;
static char *host_id = (char *)"none";
static char *vg_uuid = (char *)"none";
static char *lock_args;
static char send_opts[128];
static int sleep_sec;
static int update;

static int cmd_pipe[2];
static int cmd_argc;
static char *cmd_name;
static char **cmd_argv;

daemon_handle _lvmlockd_handle;

#define log_debug(fmt, args...) \
do { \
	printf(fmt "\n", ##args); \
} while (0)

#define log_error(fmt, args...) \
do { \
	printf(fmt "\n", ##args); \
} while (0)


static int handle_reply(daemon_reply reply)
{
	int64_t result;

	if (reply.error) {
		log_error("reply error: %d", reply.error);
		return reply.error;
	}

	/* TODO: 100 is a random num I don't think the daemon returns */

	if (!strcmp(daemon_reply_str(reply, "response", ""), "OK")) {
		result = daemon_reply_int(reply, "op_result", 100);

		return (int)result;
	} else {
		log_error("reply error: invalid response");
		return -1;
	}
}

static int do_hello(void)
{
	daemon_reply reply;
	const char *str;
	int64_t val;
	int rv = 0;

	reply = daemon_send_simple(_lvmlockd_handle, "hello", NULL);

	if (reply.error) {
		printf("reply error %d\n", reply.error);
		rv = reply.error;
		goto out;
	}

	str = daemon_reply_str(reply, "response", NULL);
	if (str)
		printf("response: %s\n", str);

	str = daemon_reply_str(reply, "protocol", NULL);
	if (str)
		printf("protocol: %s\n", str);

	val = daemon_reply_int(reply, "version", 0);
	if (val)
		printf("version: %lld\n", (long long)val);
out:
	daemon_reply_destroy(reply);
	return rv;
}

static int do_test(void)
{
	daemon_reply reply;
	char *mode = NULL;
	int rv, op;

	if (gl_mode)
		mode = gl_mode;
	else if (vg_mode)
		mode = vg_mode;
	else if (lv_mode)
		mode = lv_mode;

	reply = daemon_send_simple(_lvmlockd_handle, "test",
			       "mode = %s", mode ?: "test",
			       "vg_name = %s", vg_name ?: "test",
			       "lv_name = %s", lv_name ?: "test",
			       "lock_type = %s", lm_type ?: "test",
			       "lock_args = %s", lm_args ?: "test",
			       NULL);

	rv = handle_reply(reply);

	op = (int)daemon_reply_int(reply, "op", 100);

	log_debug("result %d op %d", rv, op);

	daemon_reply_destroy(reply);
	return rv;
}

static int do_quit(void)
{
	daemon_reply reply;
	int rv = 0;

	reply = daemon_send_simple(_lvmlockd_handle, "quit", NULL);

	if (reply.error) {
		log_error("reply error %d\n", reply.error);
		rv = reply.error;
	}

	daemon_reply_destroy(reply);
	return rv;
}

static int do_lock_init_vg(void)
{
	daemon_reply reply;
	int rv;

	if (!vg_name) {
		log_error("missing vg_name");
		return -EINVAL;
	}

	if (!lm_type) {
		log_error("missing lm_type");
		return -EINVAL;
	}

	reply = daemon_send_simple(_lvmlockd_handle,
				"init_vg",
				"vg_name = %s", vg_name,
				"lock_type = %s", lm_type,
				"lock_args = %s", lm_args,
				NULL);

	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

static int do_lock_init_lv(void)
{
	daemon_reply reply;
	int rv;

	if (!vg_name) {
		log_error("missing vg_name");
		return -EINVAL;
	}

	if (!lv_name) {
		log_error("missing lv_name");
		return -EINVAL;
	}

	if (!lm_type) {
		log_error("missing lm_type");
		return -EINVAL;
	}

	/*
	 * Sending lm_type is not strictly necessary here
	 * because lm_type would be inherited from the
	 * vg in lvmlockd.  But, the way the command line
	 * options work, we get the lm_type by way of using
	 * --lock-init.
	 */

	reply = daemon_send_simple(_lvmlockd_handle,
				"init_lv",
				"vg_name = %s", vg_name,
				"lv_name = %s", lv_name,
				"lock_type = %s", lm_type,
				NULL);

	rv = handle_reply(reply);

	lock_args = (char *)daemon_reply_str(reply, "lock_args", NULL);

	daemon_reply_destroy(reply);
	return rv;
}

static int do_lock_start_gl(void)
{
	daemon_reply reply;
	int rv;

	if (!lm_type) {
		log_error("missing lm_type");
		return -EINVAL;
	}

	reply = daemon_send_simple(_lvmlockd_handle,
				"start_gl",
				"lock_type = %s", lm_type,
				"lock_args = %s", lm_args ?: "none",
				"host_id = %s", host_id,
				NULL);

	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

static int do_lock_start_vg(void)
{
	daemon_reply reply;
	int rv;

	if (!lm_type) {
		log_error("missing lm_type");
		return -EINVAL;
	}

	if (!vg_name) {
		log_error("missing vg_name");
		return -EINVAL;
	}

	reply = daemon_send_simple(_lvmlockd_handle,
				"start_vg",
				"vg_name = %s", vg_name,
				"lock_type = %s", lm_type,
				"lock_args = %s", lm_args ?: "none",
				"vg_uuid = %s", vg_uuid,
				"host_id = %s", host_id,
				NULL);

	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

static int do_lock_stop_gl(void)
{
	daemon_reply reply;
	int rv;

	reply = daemon_send_simple(_lvmlockd_handle, "stop_gl", NULL);

	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

static int do_lock_stop_vg(void)
{
	daemon_reply reply;
	int rv;

	if (!vg_name) {
		log_error("missing vg_name");
		return -EINVAL;
	}

	reply = daemon_send_simple(_lvmlockd_handle,
				"stop_vg",
				"vg_name = %s", vg_name,
				NULL);

	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

static int do_lock_stop_all(void)
{
	daemon_reply reply;
	int rv;

	reply = daemon_send_simple(_lvmlockd_handle, "stop_all", NULL);

	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

/* --lock-gl enable|disable */
static int do_lock_able(void)
{
	daemon_reply reply;
	const char *cmd;
	int rv;

	if (!vg_name) {
		log_error("missing vg_name");
		return -EINVAL;
	}

	if (lock_enable)
		cmd = "enable_gl";
	else
		cmd = "disable_gl";

	reply = daemon_send_simple(_lvmlockd_handle, cmd,
				   "vg_name = %s", vg_name,
				    NULL);

	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

/* --lock-init lm_type --xy */
static int do_lock_init(void)
{
	if (vg_arg && lv_arg)
		return do_lock_init_lv();
	else if (vg_arg)
		return do_lock_init_vg();

	return -1;
}

/* --lock-xy start */
static int do_lock_start(void)
{
	if (lock_gl)
		return do_lock_start_gl();
	else if (lock_vg)
		return do_lock_start_vg();
	else if (lock_lv)
		return -1;

	return -1;
}

/* --lock-xy stop, or --lock-stop (all) */
static int do_lock_stop(void)
{
	if (lock_gl)
		return do_lock_stop_gl();
	else if (lock_vg)
		return do_lock_stop_vg();
	else if (lock_lv)
		return -1;

	return do_lock_stop_all();
}

/* --lock-gl mode */
static int do_lock_gl(void)
{
	daemon_reply reply;
	int rv;

	if (!gl_mode) {
		log_error("missing gl_mode");
		return -EINVAL;
	}

	reply = daemon_send_simple(_lvmlockd_handle,
				"lock_gl",
				"mode = %s", gl_mode,
				"opts = %s", send_opts,
				NULL);
	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

/* --lock-vg mode */
static int do_lock_vg(void)
{
	daemon_reply reply;
	int rv;

	if (!vg_mode) {
		log_error("missing vg_mode");
		return -EINVAL;
	}

	if (!vg_name) {
		log_error("missing vg_name");
		return -EINVAL;
	}

	reply = daemon_send_simple(_lvmlockd_handle,
				"lock_vg",
				"mode = %s", vg_mode,
				"opts = %s", send_opts,
				"vg_name = %s", vg_name,
				NULL);
	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

/* --lock-lv mode */
static int do_lock_lv(void)
{
	daemon_reply reply;
	int rv;

	if (!lv_mode) {
		log_error("missing lv_mode");
		return -EINVAL;
	}

	if (!vg_name) {
		log_error("missing vg_name");
		return -EINVAL;
	}

	if (!lv_name) {
		log_error("missing lv_name");
		return -EINVAL;
	}

	reply = daemon_send_simple(_lvmlockd_handle,
				"lock_lv",
				"mode = %s", lv_mode,
				"opts = %s", send_opts,
				"vg_name = %s", vg_name,
				"lv_name = %s", lv_name,
				"lock_args = %s", lm_args ?: "none",
				NULL);
	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

static int do_update_gl(void)
{
	daemon_reply reply;
	int rv;

	reply = daemon_send_simple(_lvmlockd_handle,
				"gl_update",
				"opts = %s", "next_version",
				NULL);
	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

static int do_update_vg(void)
{
	daemon_reply reply;
	int rv;

	reply = daemon_send_simple(_lvmlockd_handle,
				"vg_update",
				"vg_name = %s", vg_name,
				"opts = %s", "next_version",
				NULL);
	rv = handle_reply(reply);
	daemon_reply_destroy(reply);
	return rv;
}

static void print_usage(void)
{
	printf("initialize new vg lockspace and vg lock:\n");
	printf("--lock-init lm_type --vg vg_name --lock-args lm_args\n");
	printf(". for sanlock lm_args is the path to the leases lv\n");
	printf(". for dlm, lock-init does nothing\n");
	printf("\n");

	printf("initialize new lv lock in vg lockspace:\n");
	printf("--lock-init lm_type --vg vg_name --lv lv_name\n");
	printf(". for sanlock, this returns a new offset to be\n");
	printf("  used as lm_args when acquiring the lv lock\n");
	printf(". for dlm, lock-init does nothing\n");
	printf("\n");

	printf("start or stop dlm global lockspace:\n");
	printf("--lock-gl start|stop --lock-type dlm\n");
	printf(". wait option possible with start\n");
	printf(". force option possible with stop\n");
	printf("\n");

	printf("enable or disable sanlock global lock:\n");
	printf("--lock-gl enable|disable --vg vg_name\n");
	printf("\n");

	printf("start vg lockspace:\n");
	printf("--lock-vg start --vg vg_name --lock-type lm_type\n");
	printf("[--lock-args lm_args] [--vg-uuid uuid] [--host-id num] [--wait]\n");
	printf(". lm_type must match what was used in lock-init\n");
	printf(". lm_args must match what was used in lock-init (for sanlock only)\n");
	printf(". uuid identifies the vg in lvmetad\n");
	printf(". num is the host id of the local host (for sanlock only)\n");
	printf("\n");

	printf("stop vg lockspace:\n");
	printf("--lock-vg stop --vg vg_name [--force]\n");
	printf("\n");

	printf("stop all lockspaces:\n");
	printf("--lock-stop [--force] [--wait]\n");
	printf("\n");

	printf("acquire or release a lock:\n");
	printf("--lock-gl ex|sh|un\n");
	printf("\n");
	printf("--lock-vg ex|sh|un --vg vg_name\n");
	printf("\n");
	printf("--lock-lv ex|sh|un --vg vg_name --lv lv_name [--lock-args lm_args]\n");
	printf(". lm_args is the offset that was returned by lock-init;\n");
	printf("  if empty, lvmlockd will scan the leases lv to find the\n");
	printf("  resource lease location for lv_name.\n");
	printf("\n");

	printf("other options\n");
	printf("--persistent\n");
	printf(". use with lock-gl/lock-vg/lock-lv to acquire and release\n");
	printf("--update\n");
	printf(". use with lock-gl/lock-vg to update version on ex release\n");
	printf("--sleep sec\n");
	printf(". sleep between acquiring and releasing locks\n");
	printf("--command path args\n");
	printf(". run command between acquire and release (must be final option)\n");
	printf("\n");
	printf("daemon options\n");
	printf("--help\n");
	printf("--hello\n");
	printf("--test\n");
	printf("--quit\n");
}

static char *get_mode(char *arg)
{
	if (!strcmp(arg, "start")) {
		lock_start = 1;
		return NULL;
	} else if (!strcmp(arg, "stop")) {
		lock_stop = 1;
		return NULL;
	} else if (!strcmp(arg, "enable")) {
		lock_enable = 1;
		return NULL;
	} else if (!strcmp(arg, "disable")) {
		lock_disable = 1;
		return NULL;
	}
	return arg;
}

static int read_options(int argc, char *argv[])
{
	int option_index = 0;
	int i, j, c, len;

	static struct option long_options[] = {
		{"help",       no_argument,       0,  'h' },
		{"hello",      no_argument,       0,  'H' },
		{"test",       no_argument,       0,  'T' },
		{"quit",       no_argument,       0,  'q' },
		{"wait",       no_argument,       0,  'w' },
		{"force",      no_argument,       0,  'f' },
		{"lock-init",  required_argument, 0,  'I' },
		{"lock-gl",    required_argument, 0,  'g' },
		{"lock-vg",    required_argument, 0,  'v' },
		{"lock-lv",    required_argument, 0,  'l' },
		{"lock-type",  required_argument, 0,  't' },
		{"lock-args",  required_argument, 0,  'a' },
		{"lock-stop",  no_argument,       0,  'S' },
		{"update",     no_argument,       0,  'u' },
		{"persistent", no_argument,       0,  'p' },
		{"gl",         no_argument,       0,  'G' },
		{"vg",         required_argument, 0,  'V' },
		{"lv",         required_argument, 0,  'L' },
		{"vg-uuid",    required_argument, 0,  'U' },
		{"host-id",    required_argument, 0,  'i' },
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
		c = getopt_long(argc, argv, "hHTqI:g:v:l:t:a:pGV:L:i:s:c:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			/* --help */
			print_usage();
			exit(0);
		case 'H':
			/* --hello */
			hello = 1;
			break;
		case 'T':
			/* --test */
			test = 1;
			break;
		case 'q':
			/* --quit */
			quit = 1;
			break;
		case 'I':
			/* --lock-init lm_type */
			lock_init = 1;
			lm_type = strdup(optarg);
			break;
		case 'g':
			/* --lock-gl start|stop|enable|disable|mode */
			lock_gl = 1;
			gl_mode = get_mode(optarg);
			break;
		case 'v':
			/* --lock-vg start|stop|mode */
			lock_vg = 1;
			vg_mode = get_mode(optarg);
			break;
		case 'l':
			/* --lock-lv mode */
			lock_lv = 1;
			lv_mode = get_mode(optarg);
			break;
		case 't':
			/* --lock-type lm_type */
			lm_type = strdup(optarg);
			break;
		case 'a':
			/* --lock-args str */
			lm_args = strdup(optarg);
			break;
		case 'S':
			/* --lock-stop */
			lock_stop = 1;
			break;
		case 'u':
			/* --update */
			update = 1;
			break;
		case 'p':
			/* --persistent */
			strcat(send_opts, "persistent,");
			break;
		case 'w':
			/* --wait */
			strcat(send_opts, "wait,");
			break;
		case 'f':
			/* --force */
			strcat(send_opts, "force,");
			break;
		case 'G':
			/* --gl */
			gl_arg = 1;
			break;
		case 'V':
			/* --vg vg_name */
			vg_arg = 1;
			vg_name = strdup(optarg);
			break;
		case 'L':
			/* --lv lv_name */
			lv_arg = 1;
			lv_name = strdup(optarg);
			break;
		case 'U':
			/* --vg-uuid uuid */
			vg_uuid = strdup(optarg);
			break;
		case 'i':
			/* --host-id num */
			host_id = strdup(optarg);
			break;
		case 's':
			/* --sleep sec */
			sleep_sec = atoi(optarg);
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

	if (!send_opts[0])
		strcat(send_opts, "none");

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

#if 0
	printf("cmd_name %s cmd_argc %d\n", cmd_name, cmd_argc);
	for (i = 0; i < cmd_argc; i++)
		printf("cmd_argv[%d] %s\n", i, cmd_argv[i]);
#endif

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

	_lvmlockd_handle = lvmlockd_open(NULL);

	if (_lvmlockd_handle.socket_fd < 0 || _lvmlockd_handle.error) {
		log_error("lvmlockd open error %d", _lvmlockd_handle.error);
		goto out_pid;
	}

	if (hello) {
		rv = do_hello();
		goto out;
	}

	if (test) {
		rv = do_test();
		goto out;
	}

	if (quit) {
		rv = do_quit();
		goto out;
	}

	if (lock_enable || lock_disable) {
		rv = do_lock_able();
		log_debug("lock able %d", rv);
		goto out;
	}

	if (lock_init) {
		rv = do_lock_init();
		log_debug("lock init %d args %s", rv, lock_args ? lock_args : "");
		goto out;
	}

	if (lock_start) {
		rv = do_lock_start();
		log_debug("lock start %d", rv);
		goto out;
	}

	if (lock_stop) {
		rv = do_lock_stop();
		log_debug("lock stop %d", rv);
		goto out;
	}

	if (lock_gl) {
		rv = do_lock_gl();
		log_debug("lock gl %d", rv);

		if (rv < 0)
			goto out;
	}

	if (lock_vg) {
		rv = do_lock_vg();
		log_debug("lock vg %d", rv);

		if (rv < 0)
			goto out;
	}

	if (lock_lv) {
		rv = do_lock_lv();
		log_debug("lock lv %d", rv);

		if (rv < 0)
			goto out;
	}

	if (sleep_sec)
		usleep(sleep_sec * 1000000);

	if (pid) {
		/* tell child to exec */
		write(cmd_pipe[1], "g", 1);
		waitpid(pid, &status, 0);
		pid = 0;
	}

	if (update && lock_gl && !strcmp(gl_mode, "ex")) {
		rv = do_update_gl();
		log_debug("update gl %d", rv);
	}

	if (update && lock_vg && !strcmp(vg_mode, "ex")) {
		rv = do_update_vg();
		log_debug("update vg %d", rv);
	}

out:
	lvmlockd_close(_lvmlockd_handle);
out_pid:
	if (pid) {
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
	}

	return rv;
}


import atexit
import grp
import logging
import os
import pwd
import resource
import signal
import stat
import sys
import traceback

from logging import handlers


__version__ = "2.4.8"


class Daemonize(object):
    """
    Daemonize object.

    Object constructor expects three arguments.

    :param app: contains the application name which will be sent to syslog.
    :param pid: path to the pidfile or None for no PID file.
    :param action: your custom function which will be executed after
                   daemonization.
    :param keep_fds: optional list of fds which should not be closed.
    :param auto_close_fds: optional parameter to not close opened fds.
    :param privileged_action: action that will be executed before drop
                              privileges if user and/or group parameter is
                              provided.
                              If you want to transfer anything from
                              privileged_action to action, such as opened
                              file descriptor, you should return it from
                              privileged_action function and catch it inside
                              action function.
    :param user: drop privileges to this user if provided.
    :param group: drop privileges to this group if provided.
    :param verbose: send debug messages to logger if provided.
    :param logger: use this logger object instead of creating new one,
                   if provided.
    :param foreground: stay in foreground; do not fork (for debugging)
    :param chdir: change working directory if provided or /
    """
    def __init__(self, app, pid, action,
                 keep_fds=None, auto_close_fds=True, privileged_action=None,
                 user=None, group=None, verbose=False, logger=None,
                 foreground=False, chdir="/"):
        self.app = app

        # Allow no pid file.
        if pid is not None:
            self.pid = os.path.abspath(pid)
        else:
            self.pid = None

        self.action = action
        self.keep_fds = keep_fds or []
        self.privileged_action = privileged_action or (lambda: ())
        self.user = user
        self.group = group
        self.logger = logger
        self.verbose = verbose
        self.auto_close_fds = auto_close_fds
        self.foreground = foreground
        self.chdir = chdir

        if self.logger is None:
            # Initialize logging.
            self.logger = logging.getLogger(self.app)
            self.logger.setLevel(logging.DEBUG)
            # Display log messages only on defined handlers.
            self.logger.propagate = False

            # Initialize syslog.
            # It will correctly work on OS X, Linux and FreeBSD.
            if sys.platform == "darwin":
                syslog_address = "/var/run/syslog"
            else:
                syslog_address = "/dev/log"

            # We will continue with syslog initialization only if actually have
            # such capabilities on the machine we are running this.
            if os.path.exists(syslog_address):
                syslog = handlers.SysLogHandler(syslog_address)
                if self.verbose:
                    syslog.setLevel(logging.DEBUG)
                else:
                    syslog.setLevel(logging.INFO)
                # Try to mimic to normal syslog messages.
                formatter = logging.Formatter(
                    "%(asctime)s %(name)s: %(message)s",
                    "%b %e %H:%M:%S"
                )
                syslog.setFormatter(formatter)

                self.logger.addHandler(syslog)

    def start(self):
        """
        Start daemonization process.
        """
        try:
            self.pidfile()
        except:
            for line in traceback.format_exc().split("\n"):
                self.logger.error(line)
            raise

        # skip fork if foreground is specified
        if not self.foreground:
            # Fork, creating a new process for the child.
            try:
                process_id = os.fork()
            except OSError as e:
                self.logger.error("Unable to fork, errno: {0}".format(e.errno))
                raise

            if process_id != 0:
                # This is the parent process. Exit without cleanup,
                # see https://github.com/thesharp/daemonize/issues/46
                os._exit(0)
            # This is the child process. Continue.

            # Stop listening for signals that the parent process receives.
            # This is done by getting a new process id.
            # setpgrp() is an alternative to setsid().
            # setsid puts the process in a new parent group and detaches its
            # controlling terminal.
            process_id = os.setsid()
            if process_id == -1:
                # Uh oh, there was a problem.
                sys.exit(1)

            # Close all file descriptors, except self.keep_fds.
            devnull = "/dev/null"
            if hasattr(os, "devnull"):
                # Python has set os.devnull on this system, use it instead as
                # it might be different than /dev/null
                devnull = os.devnull

            if self.auto_close_fds:
                for fd in range(3,
                                resource.getrlimit(resource.RLIMIT_NOFILE)[0]):
                    if fd not in self.keep_fds:
                        try:
                            os.close(fd)
                        except OSError:
                            pass

            devnull_fd = os.open(devnull, os.O_RDWR)
            os.dup2(devnull_fd, 0)
            os.dup2(devnull_fd, 1)
            os.dup2(devnull_fd, 2)
            os.close(devnull_fd)

        # Set umask to default to safe file permissions when running as a root
        # daemon. 027 octal number which we are typing as 0o27 for Python3.
        os.umask(0o27)

        # Change to a known directory. If this isn't done, starting a daemon in
        # a subdirectory that needs to be deleted results in errors.
        os.chdir(self.chdir)

        # Execute privileged action
        privileged_action_result = self.privileged_action()
        if not privileged_action_result:
            privileged_action_result = []

        self.drop_privileges()

        # Set custom action on SIGINT/SIGTERM.
        signal.signal(signal.SIGINT, self.sigreceived)
        signal.signal(signal.SIGTERM, self.sigreceived)

        atexit.register(self.exit)

        self.logger.info("Starting daemon.")

        try:
            self.action(*privileged_action_result)
        except Exception:
            for line in traceback.format_exc().split("\n"):
                self.logger.error(line)

    def sigreceived(self, signum, frame):
        """
        These actions will be done after SIGINT/SIGTERM.
        """
        self.logger.info("Caught signal %s." % signum)
        sys.exit(0)

    def exit(self):
        """
        Try to cleanup pid file at exit.
        """
        self.logger.info("Stopping daemon.")

        if self.pid:
            try:
                # Only remove if regular file (prevents device deletion)
                if stat.S_ISREG(os.stat(self.pid).st_mode):
                    os.remove(self.pid)
            except:
                self.logger.warning('Was unable to remove pid file: ' +
                                    self.pid)

    def drop_privileges(self):
        if os.getuid() != 0 or not self.user:
            return

        try:
            pw = pwd.getpwnam(self.user)
        except:
            self.logger.error(
                'Unable to drop privileges. User %s not found.' % self.user
            )
            return

        uid = pw.pw_uid

        if uid == 0:
            self.logger.warning(
                'Unable to drop privileges. User %s is a super-user.' %
                self.user
            )
            return

        if self.group:
            try:
                gid = grp.getgrnam(self.group).gr_gid
            except:
                self.logger.error(
                    'Unable to drop privileges. Group %s not found.' %
                    self.group
                )
                return
        else:
            gid = pw.pw_gid

        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)

        os.umask(0o77)
        os.environ['HOME'] = pw.pw_dir

    def pidfile(self):
        if not self.pid:
            return

        try:
            with open(self.pid, 'r') as pidfile:
                pid = int(pidfile.read().strip())
        except:
            pid = None

        if pid:
            try:
                os.kill(pid, 0)

                raise Exception('Daemon already running')
            except OSError:
                raise

        try:
            with open(self.pid, 'w') as pidfile:
                pidfile.write(str(os.getpid()) + '\n')
        except:
            raise

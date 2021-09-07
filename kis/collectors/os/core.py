# -*- coding: utf-8 -*-
"""This file contains all functionality to execute OS commands."""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2018 Lukas Reiter

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
__version__ = 0.1

import subprocess
import psutil
import queue
import os
import time
import logging
import pwd
from threading import Thread
from threading import Lock
from typing import List
from datetime import datetime

logger = logging.getLogger('process')


def demote(user_uid, user_gid):
    """
    Pass the function 'set_ids' to preexec_fn, rather than just calling
    setuid and setgid. This will change the ids for that subprocess only
    """
    def set_ids():
        os.setgid(user_gid)
        os.setuid(user_uid)
    return set_ids


class OutputReader(Thread):
    """This class is used as base class to asynchronously read data from processes' STDOUT and STDERR."""
    def __init__(self, proc):
        """
        :param proc: Process instance created by method subprocess.Popen
        """
        Thread.__init__(self, daemon=True)
        self._proc = proc
        self._list_lock = Lock()
        self._output = []

    @property
    def output(self) -> list:
        """
        :return: queue.Queue instance which holds the STDOUT or STDERR output of the process
        """
        with self._list_lock:
            return list(self._output)

    def append(self, value: str):
        """
        This method adds a new line to the output list.
        """
        with self._list_lock:
            self._output.append(value)

    def run(self):
        raise NotImplementedError("Method not implemented!")


class StdoutReader(OutputReader):
    """
    Thread to asynchronously read data from processes' STDOUT. This class is used by CommandWithReadQueue for example.
    """

    def __init__(self, proc):
        """
        :param proc: Process instance created by method subprocess.Popen
        """
        super().__init__(proc)

    def run(self):
        """
        Method reads the content of STDOUT as long as the process is active.
        :return: None
        """
        for line in iter(self._proc.stdout.readline, b''):
            self.append(line.decode().rstrip())


class StderrReader(OutputReader):
    """
    Thread to asynchronously read data from processes' STDERR. This class is used by CommandWithReadQueue for example.
    """

    def __init__(self, proc):
        """
        :param proc: Process instance created by method subprocess.Popen
        """
        super().__init__(proc)

    def run(self):
        """
        Method reads the content of STDERR as long as the process is active.
        :return: None
        """
        for line in iter(self._proc.stderr.readline, b''):
            self.append(line.decode().rstrip())


class BaseCommand(Thread):
    """
    This class represents a base class for subclasses that implement some sort of OS command execution functionality.
    """
    def __init__(self, os_command: List[str],
                 stdout: int = subprocess.STDOUT,
                 stderr: int = subprocess.STDOUT,
                 username: str = None,
                 cwd: str = None,
                 env: dict = None,
                 shell: bool = False):
        super().__init__(daemon=True)
        self._os_command = os_command
        self._stdout = stdout
        self._stderr = stderr
        self._shell = False
        self._cwd = cwd
        self._start_time = None
        self._stop_time = None
        self._lock = Lock()
        self._pwd = None
        self._env = {'PATH': os.environ["PATH"],
                     'HOME': os.environ["HOME"]}
        for key, value in self._env.items():
            self._env[key] = str(value)
        if username:
            self._pwd = pwd.getpwnam(username)
            self._demote = demote(self._pwd.pw_uid, self._pwd.pw_gid)
        else:
            self._demote = None

    @property
    def tool(self) -> str:
        return_value = None
        if len(self._os_command) > 0:
            return_value = self._os_command[0]
        return return_value

    @property
    def options(self) -> List[str]:
        return_value = None
        if len(self._os_command) > 1:
            return_value = self._os_command[1:]
        return return_value

    @property
    def os_command_str(self) -> str:
        return " ".join(self._os_command)

    @property
    def os_command(self) -> List[str]:
        return self._os_command

    @os_command.setter
    def os_command(self, value: List[str]) -> None:
        self._os_command = value

    @property
    def shell(self) -> bool:
        return self._shell

    @shell.setter
    def shell(self, value: bool) -> None:
        self._shell = value

    @property
    def cwd(self):
        return self._cwd

    @cwd.setter
    def cwd(self, value: str) -> None:
        self._cwd = value

    @property
    def start_time(self) -> datetime:
        with self._lock:
            return self._start_time

    @property
    def stop_time(self) -> datetime:
        with self._lock:
            return self._stop_time

    @stop_time.setter
    def stop_time(self, value) -> datetime:
        with self._lock:
            self._stop_time = value

    @property
    def command(self) -> List[str]:
        return self._os_command

    def __repr__(self) -> str:
        return "<{} command='{}' />".format(self.__class__.__name__, " ".join(self.command))

    def run(self) -> None:
        """This method starts the execution of the OS command."""
        raise NotImplementedError("Method not implemented!")


class PopenCommand(BaseCommand):
    """
    This class implements an interface to execute an OS command in a separate thread.

    This class executes the process using method subprocess.Popen, which allows interacting with the process (e.g., via
    method poll or wait) during execution. All process interaction (e.g., reading from STDIN, waiting for the process to
    finish) must be implemented in the actual Python script.
    """
    def __init__(self, os_command: List[str],
                 stdout: int = subprocess.PIPE,
                 stderr: int = subprocess.PIPE,
                 cwd: str = None,
                 timeout: int = None,
                 **kwargs):
        super().__init__(os_command=os_command, stdout=stdout, stderr=stderr, cwd=cwd, shell=False, **kwargs)
        self._proc = None
        self._return_code = None
        self._killed = False
        self._timeout = timeout if timeout and timeout > 0 else None
        self._stdout_reader_lock = Lock()
        self._stderr_reader_lock = Lock()
        self._stdout_reader = None
        self._stderr_reader = None

    @property
    def proc(self):
        """
        :return: Returns the Popen instance or None if the process executions has not started yet.
        """
        with self._lock:
            return self._proc

    @property
    def stdout_list(self) -> list:
        """
        :return: Returns the standard output of the executed command or None.
        """
        result = None
        with self._stdout_reader_lock:
            if self._stdout_reader:
                result = self._stdout_reader.output
        return result

    @property
    def stderr_list(self) -> list:
        """
        :return: Returns the standard output of the executed command or None.
        """
        result = None
        with self._stderr_reader_lock:
            if self._stderr_reader:
                result = self._stderr_reader.output
        return result

    @property
    def pid(self) -> int:
        """
        :return: Returns the process' PID
        """
        return self._proc.pid

    @property
    def return_code(self) -> int:
        """
        :return: Returns the return code or None if the process execution has not yet finished.
        """
        with self._lock:
            return self._return_code

    @property
    def killed(self) -> bool:
        """
        :return: Returns true, if the process was killed, else false
        """
        with self._lock:
            return self._killed

    def poll(self) -> int:
        """
        This method can be used to determine whether the process is still running.

        :return: Returns None as long as the process is still running or the process' return code.
        """
        with self._lock:
            self._return_code = self._proc.poll()
            return self._return_code

    def _kill_process(self, process_id: int, signal: int):
        try:
            os.kill(process_id, signal)
        except psutil.NoSuchProcess:
            pass
        except ProcessLookupError:
            pass

    def _kill_all(self, signal: int):
        if self._proc and self._proc.pid:
            try:
                parent = psutil.Process(self._proc.pid)
                for child in parent.children(recursive=True):
                    self._kill_process(process_id=child.pid, signal=signal)
                self._kill_process(process_id=parent.pid, signal=signal)
            except psutil.NoSuchProcess:
                pass
        self._killed = True

    def kill(self) -> None:
        """Kills the process with SIGKILL."""
        self._kill_all(signal=15)

    def terminate(self) -> None:
        """Terminates the process with SIGTERM"""
        self._kill_all(signal=9)

    def communicate(self, input=None, timeout=None):
        """
        Send input to stdin of the running process.
        """
        if self._proc:
            self._proc.communicate(input, timeout)

    def run(self) -> None:
        """This method starts the execution of the OS command."""
        with self._lock:
            try:
                env = dict(self._env)
                env['HOME'] = self._cwd
                self._start_time = datetime.utcnow()
                self._proc = subprocess.Popen(self.command,
                                              stdout=self._stdout,
                                              stderr=self._stderr,
                                              shell=False,
                                              cwd=self._cwd,
                                              env=env,
                                              preexec_fn=self._demote)
                if self._stdout == subprocess.PIPE:
                    with self._stdout_reader_lock:
                        self._stdout_reader = StdoutReader(self._proc)
                    self._stdout_reader.start()
                if self._stderr == subprocess.PIPE:
                    with self._stderr_reader_lock:
                        self._stderr_reader = StderrReader(self._proc)
                    self._stderr_reader.start()
                self._return_code = self._proc.wait(self._timeout)
            except subprocess.TimeoutExpired:
                self._killed = True
            if self._stdout == subprocess.PIPE:
                self._stdout_reader.join()
            if self._stderr == subprocess.PIPE:
                self._stderr_reader.join()

    def close(self) -> None:
        with self._lock:
            if self._proc:
                if self._proc.stdout:
                    self._proc.stdout.close()
                if self._proc.stderr:
                    self._proc.stderr.close()


class PopenCommandWithoutStderr(PopenCommand):
    """
    This class implements an interface to execute an OS command in a separate thread.

    Thereby, the output to stderr is ignored
    """

    def __init__(self, os_command: List[str],
                 stdout: int = subprocess.STDOUT,
                 stderr: int = subprocess.STDOUT,
                 **kwargs):
        super().__init__(os_command=os_command,
                         stdout=stdout,
                         stderr=subprocess.DEVNULL,
                         **kwargs)

    @property
    def stderr_list(self) -> List[str]:
        """
        :return: Returns the current content of the stderr buffer as a list of strings
        """
        return []


class PopenCommandOpenSsl(PopenCommand):
    """
    This class implements an interface to execute an OS command in a separate thread.

    Thereby, the output to stderr is ignored
    """

    def __init__(self, os_command: List[str],
                 stdout: int = subprocess.PIPE,
                 stderr: int = subprocess.PIPE,
                 **kwargs):
        super().__init__(os_command=os_command,
                         stdout=stdout,
                         stderr=stderr,
                         **kwargs)
        self._stdout_list = []
        self._stderr_list = []

    @property
    def stdout_list(self) -> List[str]:
        """
        :return: Returns the current content of the stdout buffer as a list of strings
        """
        return self._stdout_list

    @property
    def stderr_list(self) -> List[str]:
        """
        :return: Returns the current content of the stderr buffer as a list of strings
        """
        return self._stderr_list

    def run(self) -> None:
        """This method starts the execution of the OS command."""
        with self._lock:
            try:
                self._start_time = datetime.utcnow()
                self._proc = subprocess.Popen(self.command,
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE,
                                              stdin=subprocess.PIPE,
                                              shell=False,
                                              env=self._env,
                                              cwd=self._cwd,
                                              preexec_fn=self._demote)
                self._stderr_list = [item.decode("utf-8").strip() for item in iter(self._proc.stderr.readline, b'')]
                self._stdout_list = [item.decode("utf-8").strip() for item in iter(self._proc.stdout.readline, b'')]
                self._proc.communicate(b"x")
                self._proc.wait(self._timeout)
            except subprocess.TimeoutExpired:
                self._killed = True

    def close(self) -> None:
        pass


class PopenCommandWithOutputQueue(PopenCommand):
    """
    This class implements an interface to execute an OS command in a separate thread.

    This class executes the process using method subprocess.Popen, which allows interacting with the process (e.g., via
    method poll or wait) during execution. In addition, the process' STDOUT and STDERR are written in the properties
    self.stdout and self.stderr of type queue.Queue. These queues allow asynchronously reading the process' output.

    All remaining process interaction (e.g., waiting for the process to finish) must be implemented in the actual Python
    script.
    """

    def __init__(self, os_command: List[str],
                 stdout: int = subprocess.PIPE,
                 stderr: int = subprocess.PIPE,
                 cwd: str = None,
                 shell: bool = None,
                 **kwargs) -> None:
        super().__init__(os_command, stdout, stderr, cwd, shell, **kwargs)
        self._stdout_reader = None
        self._stderr_reader = None

    @property
    def stdout_queue(self):
        rvalue = None
        if self._stdout_reader:
            rvalue = self._stdout_reader.out_queue
        return rvalue

    @property
    def stderr_queue(self):
        rvalue = None
        if self._stderr_reader:
            rvalue = self._stderr_reader.out_queue
        return rvalue

    def run(self):
        """This method starts the execution of the OS command."""
        with self._lock:
            self._start_time = datetime.utcnow()
            self._proc = subprocess.Popen(self.command,
                                          stdout=self._stdout,
                                          stderr=self._stderr,
                                          shell=self._shell,
                                          cwd=self._cwd,
                                          env=self._env,
                                          preexec_fn=self._demote)
            self._stdout_reader = StdoutReader(self._proc)
            self._stderr_reader = StderrReader(self._proc)
        self._stdout_reader.start()
        self._stderr_reader.start()


class RunCommand(BaseCommand):
    """This class implements an interface to execute OS commands in a separate thread.

    This class executes the process using method subprocess.run. By using this command, you won't have control over
    the process. In other words, you cannot terminate the process for example.
    """

    def __init__(self, os_command: List[str],
                 stdout: int = subprocess.STDOUT,
                 stderr: int = subprocess.STDOUT,
                 cwd: str = None,
                 shell: bool = None,
                 check: bool = False,
                 **kwargs) -> None:
        super().__init__(os_command, stdout, stderr, cwd, shell, **kwargs)
        self._check = check
        self._completed_proc_info = None

    @property
    def check(self):
        return self._check

    @check.setter
    def check(self, value):
        self._check = value

    @property
    def completed_proc_info(self):
        return self._completed_proc_info

    def run(self):
        """This method starts the execution of the OS command."""
        self._start_time = datetime.utcnow()

        self._completed_proc_info = subprocess.run(self.command,
                                                   stdout=self._stdout,
                                                   stderr=self._stderr,
                                                   shell=False,
                                                   cwd=self._cwd,
                                                   check=self._check,
                                                   env=self._env,
                                                   preexec_fn=self._demote)


class SetupCommand:

    def __init__(self, description: str, command: List[str], return_code: int=None):
        self._description = description
        self._return_code = return_code
        self._command = command

    def _print_output(self, prefix: str, output: List[str]) -> None:
        for line in iter(output.readline, b''):
            line = line.decode("utf-8").strip()
            print("{}   {}".format(prefix, line))

    def execute(self, debug: bool=False) -> bool:
        "Executes the given command"
        rvalue = True
        print("[*] {}".format(self._description))
        print("    $ {}".format(subprocess.list2cmdline(self._command)))
        if not debug:
            p = subprocess.Popen(self._command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            Thread(target=self._print_output, args=("[*]", p.stdout, ), daemon=True).start()
            Thread(target=self._print_output, args=("[e]", p.stderr, ), daemon=True).start()
            return_code = p.wait()
            rvalue = (self._return_code == return_code if self._return_code is not None else True)
            time.sleep(1)
        return rvalue

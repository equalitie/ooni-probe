import os, signal

def do_nothing(*args):
    pass

def gdb_breakpoint():
    signal.signal(signal.SIGUSR1, do_nothing)
    PID = os.getpid()
    os.kill(PID, signal.SIGUSR1)

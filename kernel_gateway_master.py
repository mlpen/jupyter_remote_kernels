import socket
import sys
import os
import json
import subprocess
import signal
import time

conn = None

def send_json(tp, data):
    msg = {"type":tp, "value":data}
    if conn != None:
        conn.send(json.dumps(msg).encode("ascii"))

def register_signal_handler():
    def get_signal_pair():
        return [(signame, getattr(signal, signame)) for signame in dir(signal) if signame.startswith("SIG") and not signame.startswith("SIG_")]

    def get_signal_name(inp):
        for signame, signum in get_signal_pair():
            if signum == inp:
                return signame
        return None

    def signal_handler(signum, frame):
        print("Forwarding received signal: %d" %(signum))
        send_json("signal", get_signal_name(signum))

    for signame, signum in get_signal_pair():
        try:
            signal.signal(signum, signal_handler)
        except (OSError, RuntimeError) as e:
            print(e)
            print("Skipping %s" % (signame))

def create_server():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    addr, port = tcp.getsockname()
    tcp.listen(1)
    return tcp, port

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

jupyter_kernel_dir = '/.jupyter_kernel_dir'
jupyter_kernel_temp = '/.jupyter_kernel_temp'

register_signal_handler()

master_addr, master_port = get_ip_address(), sys.argv[-3]
worker_addr, worker_port = sys.argv[-2].split(":")
tcp, master_comm_port = create_server()

connection_file_path = sys.argv[-1]
connection_file_name = connection_file_path.split('/')[-1]
kernel_info = connection_file_name.replace('.json', '')
current_working_dir = os.getcwd()

with open(connection_file_path, 'r') as f:
    conn_file_json = json.load(f)

kernel_info = {"conn_file": conn_file_json,
               "current_working_dir": current_working_dir,
               "kernel_temp_folder": os.path.join(jupyter_kernel_temp, kernel_info),
               "worker_addr": worker_addr,
               "worker_port": worker_port,
               "master_addr": master_addr,
               "master_port": master_port}

try:
    cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "TCPKeepAlive=yes",
           worker_addr, "-p", worker_port,
           "python %s/kernel_gateway_worker.py %s %d" % (jupyter_kernel_dir, master_addr, master_comm_port)]

    kernel_proc = subprocess.Popen(cmd, shell = False, preexec_fn = os.setpgrp)
except Exception as e:
    print(e)
    kernel_proc.kill()
    raise e

conn, addr = tcp.accept()

send_json("kernel_info", kernel_info)

kernel_proc.wait()

import socket
import sys
import os
import json
import subprocess
import signal
import time

conn = None

def send_json(conn, tp, data):
    msg = {"type":tp, "value":data}
    if conn != None:
        conn.send(json.dumps(msg).encode("ascii"))

def receive_json(conn, tp = None):
    if conn != None:
        msg = conn.recv(2 ** 12)
        msg = msg.decode("ascii")
        if len(msg) == 0:
            raise RuntimeError
        msg = json.loads(msg)
        if tp == None or msg["type"] == tp:
            value = msg["value"]
            log("Matched message received %s" % (str(msg["type"])))
            return value
        else:
            log("Mismatched message received %s" % (str(msg["type"])))
            return None
    return None

def register_signal_handler():
    def get_signal_pair():
        return [(signame, getattr(signal, signame)) for signame in dir(signal) if signame.startswith("SIG") and not signame.startswith("SIG_")]

    def get_signal_name(inp):
        for signame, signum in get_signal_pair():
            if signum == inp:
                return signame
        return None

    def signal_handler(signum, frame):
        if signum == signal.SIGINT:
            log("Forwarding received signal: %s" %(get_signal_name(signum)))
            send_json(conn, "signal", get_signal_name(signum))
        else:
            log("Catched signal: %s" %(get_signal_name(signum)))

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

def port_forward(ssh_server_addr, ssh_server_port, port_pairs):
    def signal_handling():
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    devnull = open(os.devnull, 'w')
    procs = []
    for master_port, worker_port in port_pairs:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "TCPKeepAlive=yes",
               "-N", "-L", "%d:127.0.0.1:%d" % (master_port, worker_port), ssh_server_addr, "-p", ssh_server_port]
        local_pf = subprocess.Popen(cmd, stdout = devnull, stderr = devnull, shell = False, preexec_fn = signal_handling)
        tunnel = "127:0.0.1:%s --- %s:%s" % (worker_port, ssh_server_addr, master_port)
        log("Tunneled " + tunnel)
        procs.append((local_pf, tunnel))
    return procs

def log(msg):
    if log_f != None:
        log_f.write(msg + "\n")
        log_f.flush()

jupyter_kernel_dir = '/.jupyter_kernel_dir'
jupyter_kernel_temp = '/.jupyter_kernel_temp'

cmd = "python -m ipykernel_launcher -f {worker_connection_file}"
for argv in sys.argv:
    if argv.startswith("--cmd "):
        cmd = argv[6:]

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
               "master_port": master_port, 
               "cmd": cmd}

if not os.path.exists(kernel_info["kernel_temp_folder"]):
    os.makedirs(kernel_info["kernel_temp_folder"])
import random
log_path = os.path.join(kernel_info["kernel_temp_folder"], 'master.log')
log_f = open(log_path, 'w')

register_signal_handler()
log("Registered signals")

try:
    cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "TCPKeepAlive=yes",
           worker_addr, "-p", worker_port,
           "python %s/kernel_gateway_worker.py %s %d" % (jupyter_kernel_dir, master_addr, master_comm_port)]

    kernel_proc = subprocess.Popen(cmd, shell = False, preexec_fn = os.setpgrp)

    log("Lauched remote worker")
except Exception as e:
    print(e)
    kernel_proc.kill()
    raise e

conn, addr = tcp.accept()

free_ports = receive_json(conn, tp = "free_ports")

kernel_info["port_map"] = {}
for name, port in free_ports:
    kernel_info["port_map"][name] = (kernel_info["conn_file"][name], port)
    kernel_info["conn_file"][name] = port

try:
    procs = []
    procs = port_forward(kernel_info["worker_addr"], kernel_info["worker_port"], list(kernel_info["port_map"].values()))
except Exception as e:
    print(e)
    raise e

send_json(conn, "kernel_info", kernel_info)

log("Entering wait status")
try:
    kernel_proc.wait()
finally:
    for (local_pf, tunnel) in procs:
        try:
            local_pf.kill()
        except:
            pass
        log("Closed " + tunnel)

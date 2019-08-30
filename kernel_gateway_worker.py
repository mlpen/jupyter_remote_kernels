import socket
import json
import sys
import os
import subprocess
import signal
import time

sock = None
log_f = None

def receive_json(tp = None):
    if sock != None:
        msg = sock.recv(2 ** 12)
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

def get_signal_pair():
    return [(signame, getattr(signal, signame)) for signame in dir(signal) if signame.startswith("SIG") and not signame.startswith("SIG_")]

def get_signal_num(inp):
    for signame, signum in get_signal_pair():
        if signame == inp:
            return signum
    return None

def get_free_tcp_port(num_port):
    ports = []
    tcps = []
    for _ in range(num_port):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(('', 0))
        addr, port = tcp.getsockname()
        tcps.append(tcp)
        ports.append(port)
    for tcp in tcps:
        tcp.close()
    return ports

def port_forward(ssh_server_addr, ssh_server_port, port_pairs):
    procs = []
    for master_port, worker_port in port_pairs:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "TCPKeepAlive=yes",
               "-N", "-L", "%d:127.0.0.1:%d" % (worker_port, master_port), ssh_server_addr, "-p", ssh_server_port]
        p = subprocess.Popen(cmd, shell = False, preexec_fn = os.setpgrp)
        tunnel = "127:0.0.1:%s --- %s:%s" % (worker_port, ssh_server_addr, master_port)
        log("Tunneled " + tunnel)
        procs.append((p, tunnel))
    return procs

def log(msg):
    if log_f != None:
        log_f.write(msg + "\n")
        log_f.flush()

assert len(sys.argv) == 3

master_comm_addr, master_comm_port = sys.argv[-2], int(sys.argv[-1])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((master_comm_addr, master_comm_port))

kernel_info = receive_json(tp = "kernel_info")

if not os.path.exists(kernel_info["kernel_temp_folder"]):
    os.makedirs(kernel_info["kernel_temp_folder"])
log_path = os.path.join(kernel_info["kernel_temp_folder"], 'kernel.log')
log_f = open(log_path, 'w')

###################### lauch kernel process ######################


connection_file_path = os.path.join(kernel_info["kernel_temp_folder"], 'kernel.json')
with open(connection_file_path, 'w') as f:
    json.dump(kernel_info["conn_file"], f)
    f.flush()

log("Writed kernel connection file %s" % (connection_file_path))

os.chdir(kernel_info["current_working_dir"])

log("Changed current working directory %s" % (kernel_info["current_working_dir"]))

try:
    cmd = ['python', '-m', 'ipykernel_launcher', '-f', connection_file_path]

    kernel_proc = subprocess.Popen(cmd,
                                   stdout = subprocess.PIPE,
                                   stderr = subprocess.PIPE,
                                   stdin = subprocess.PIPE,
                                   shell = False,
                                   preexec_fn = os.setpgrp)

    log("Lauched kernel process, process pid: %d" % (kernel_proc.pid))
except Exception as e:
    print(e)
    raise e

###################### opening ssh tunnels ######################

port_names = ["shell_port", "iopub_port", "stdin_port", "control_port", "hb_port"]
free_ports = get_free_tcp_port(len(port_names))

kernel_info["port_map"] = {}
for name_idx in range(len(port_names)):
    kernel_info["port_map"][port_names[name_idx]] = (kernel_info["conn_file"][port_names[name_idx]], free_ports[name_idx])
    kernel_info["conn_file"][port_names[name_idx]] = free_ports[name_idx]

try:
    procs = []
    procs = port_forward(kernel_info["master_addr"], kernel_info["master_port"], list(kernel_info["port_map"].values()))
except Exception as e:
    print(e)
    raise e

log("Opened ssh tunnels")

##################################################################

try:
    while True:
        signal_msg = receive_json(tp = "signal")
        assert signal_msg != None
        signum = get_signal_num(signal_msg)
        assert signum != None
        log("Sending signal %s to %d" % (signal_msg, kernel_proc.pid))
        os.kill(kernel_proc.pid, signum)
except Exception as e:
    print(e)
finally:
    try:
        os.kill(kernel_proc.pid, signal.SIGQUIT)
        log("Sending signal %s to %d" % ("SIGQUIT", kernel_proc.pid))
    except Exception as e:
        print(e)

    for (p, tunnel) in procs:
        try:
            p.kill()
            log("Closed " + tunnel)
        except:
            log("Closing " + tunnel + " failed")



log_f.close()

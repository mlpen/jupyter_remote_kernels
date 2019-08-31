import socket
import json
import sys
import os
import subprocess
import signal
import time

sock = None
log_f = None

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

def log(msg):
    if log_f != None:
        log_f.write(msg + "\n")
        log_f.flush()

assert len(sys.argv) == 3

master_comm_addr, master_comm_port = sys.argv[-2], int(sys.argv[-1])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((master_comm_addr, master_comm_port))

port_names = ["shell_port", "iopub_port", "stdin_port", "control_port", "hb_port"]
free_ports = get_free_tcp_port(len(port_names))
free_ports = [(port_names[i], free_ports[i]) for i in range(len(port_names))]
send_json(sock, "free_ports", free_ports)

kernel_info = receive_json(sock, tp = "kernel_info")

if not os.path.exists(kernel_info["kernel_temp_folder"]):
    os.makedirs(kernel_info["kernel_temp_folder"])
log_path = os.path.join(kernel_info["kernel_temp_folder"], 'worker.log')
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

try:
    while True:
        signal_msg = receive_json(sock, tp = "signal")
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



log_f.close()

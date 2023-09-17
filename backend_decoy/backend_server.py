# for now, this script can only support linux environment.

import socket
import os
import subprocess
import concurrent.futures


SERVER_IP = '0.0.0.0'
SERVER_PORT = 10000
MAX_THREADS = 30
BUFFER_SIZE = 1024
CODING_SCHEME = 'gbk'


def handle_incoming_data(client_socket, client_addr, default_dir):
    try:
        print("Accepted connection from {}:{}".format(client_addr[0], client_addr[1]))
        while True:
            full_prompt = get_prompt(default_dir)
            command = receive_message(client_socket)

            if command == " ":
                send_message(client_socket, full_prompt)
            else:
                response, exit_code, error = execute_command(command)
                if len(response) != 0:
                    response += full_prompt
                    send_message(client_socket, response)
                elif len(error) != 0:
                    error += full_prompt
                    send_message(client_socket, error)
                else:
                    # it means there is no any output after executing the command 
                    if command.startswith("cd"):
                        if command == "cd" or command == "cd ~":
                            os.chdir(default_dir)
                            full_prompt = get_prompt(default_dir)
                            send_message(client_socket, full_prompt)
                        elif command.startswith("cd ~"):
                            target_dir = default_dir + command[4:]
                            os.chdir(target_dir)
                            full_prompt = get_prompt(default_dir)
                            send_message(client_socket, full_prompt)
                        else:
                            os.chdir(command[3:])
                            full_prompt = get_prompt(default_dir)
                            send_message(client_socket, full_prompt)
                    else:
                        send_message(client_socket, full_prompt)
    except:
        client.close()


def receive_message(socket):
    data = b""
    while True:
        chunk = socket.recv(BUFFER_SIZE)
        data += chunk
        if len(chunk) < BUFFER_SIZE:
            break

    return data.decode(CODING_SCHEME)


def send_message(socket, message):
    encoded_message = message.encode(CODING_SCHEME)
    total_bytes_sent = 0
    while total_bytes_sent < len(encoded_message):
        bytes_sent = socket.send(encoded_message[total_bytes_sent:])
        if bytes_sent == 0:
            raise Exception("Socket connection broken")
        total_bytes_sent += bytes_sent


def get_prompt(default_dir):
    user = os.getlogin()
    response, _, _ = execute_command("hostname")
    hostname = response.strip()
    current_dir = os.getcwd()
    displayed_dir = ""
    if current_dir.startswith(default_dir):
        displayed_dir = "~" + current_dir[len(default_dir):]
    else:
        displayed_dir = current_dir
    prompt_character = "$"
    full_prompt = f"{user}@{hostname}:{displayed_dir}{prompt_character} "
    return full_prompt


def execute_command(command):
    process = subprocess.run(command, shell=True, text=True, capture_output=True)
    response = process.stdout
    exit_code = process.returncode
    error_response = process.stderr
    return response, exit_code, error_response


def main():
    # run the script using sudo -E, or do not use sudo.
    default_dir, _, _ = execute_command("eval echo ~")
    default_dir = default_dir.strip()
    os.chdir(default_dir)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_IP, SERVER_PORT))
    server.listen(MAX_THREADS)  
    print("Server is listening on {}:{}".format(SERVER_IP, SERVER_PORT))

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        while True:
            client_socket, client_addr = server.accept()
            executor.submit(handle_incoming_data, client_socket, client_addr, default_dir)


if __name__ == '__main__':
    main()
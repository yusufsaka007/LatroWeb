# Libraries
import os
import subprocess
import argparse
import sys
from colorama import Fore, Back, Style, init
import json

init(autoreset=True)

ROOT_FOLDER = "./honeypot"
FOLDER_LIST = ['lib/x86_64-linux-gnu','lib64','usr/bin','usr/sbin','etc','home','var/www/html']
COMMAND_LIST = ['ls','cat','bash','passwd','useradd','whoami','hostname']
JSON_NAME = "meta.json"
LIB_LIST = []
metadata = {}

def run_command(command, args):
    try:
        output = subprocess.run([command] + args, check=True, text=True, capture_output=True)
        return output.stdout
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] {e}")
        return None
    
def create_folder(folder):
    try:
        os.makedirs(folder)
        print(Fore.GREEN + f"[+] Created folder {folder}")
    except FileExistsError:
        print(Fore.YELLOW + f"[!] Folder {folder.split('/')[-1]} already exists")
    # check if parent folder exists

# Create the virtual folder under honeypot/ which is exactly the scommand
def default_structure():
    for folder in FOLDER_LIST:
        create_folder(os.path.join(ROOT_FOLDER, folder))
# Copy the libraries the copied commands need
def copy_libraries(command):
    print(Style.BRIGHT + f"\nCopying libraries for {command}\n")
    command_path = run_command('which', [command])
    out = run_command('ldd', [f'{command_path.strip()}'])
    if out:
        out_split = out.split('\n')
        for line in out_split:
            if '/' in line:
                if '=>' in line:
                    lib_path = line.split('=>')[1].strip().split('(')[0].strip()
                else:
                    lib_path = line.split('(')[0].strip()
                target_path = os.path.join(ROOT_FOLDER, lib_path[1:].strip())
                if not os.path.exists(target_path):
                    print(Back.BLUE + f"Copying {lib_path}  ===>  {target_path}")
                    run_command('cp', [lib_path, target_path])
                else:
                    print(Back.YELLOW + f"[!] {lib_path} already copied to {target_path}")
# Copy the commands which will be available in the virtual environment
def copy_commands():
    for command in COMMAND_LIST:
        try:
            command_path = run_command('which', [command]).strip()
            if command_path:
                if not os.path.exists(os.path.join(ROOT_FOLDER, os.path.dirname(command_path[1:]))):
                    create_folder(os.path.join(ROOT_FOLDER, os.path.dirname(command_path[1:])))
                target_path = os.path.join(ROOT_FOLDER, command_path[1:]).strip()
                if not os.path.exists(target_path):
                    run_command('cp', [command_path, target_path])
                    print(Fore.GREEN + f"[+] Copied {command}")
                    copy_libraries(command) # Copying the libraries for the command
                else:
                    print(Fore.YELLOW + f"[!] {command_path} already copied to {target_path}")
        except Exception as e:
            print(Fore.RED + f"[-] e")

# Create a user and set the password. Define the /etc/passwd and /etc/shadow files

# Make everything read only. Avoid writing to files especially libraries

# Final security measures. Make sure attacker can't get out laterally

# Run commands using chroot (set honeypot as root folder)

# Custom command/folder handle
def custom_folders(cf_arg):
    if len(cf_arg) == 1:
        if os.path.exists(cf_arg[0]) and os.path.isfile(cf_arg[0]):
            with open(cf_arg[0], 'r') as f:
                for line in f.readlines():
                    create_folder(os.path.join(ROOT_FOLDER, line.strip()))
        elif not "." in cf_arg[0]:
            create_folder(os.path.join(ROOT_FOLDER, cf_arg[0]))
        else:
            print(Fore.RED + "[-] Invalid syntax")
    else:
        for folder in cf_arg:
            if not "." in folder:
                create_folder(os.path.join(ROOT_FOLDER, folder))
            else:
                print(Fore.RED + "[-] Invalid syntax")

def redefine_commands(cc_arg):
    global COMMAND_LIST
    if len(cc_arg) == 1 and ".txt" in cc_arg[0]:
        arg = cc_arg[0]
        if os.path.exists(arg) and os.path.isfile(arg):
            with open(arg, 'r') as f:
                COMMAND_LIST = [command_path.strip() for command_path in f.readlines()]
        else:
            print(Fore.RED + "[-] Command list file does not exist")
    else:
        COMMAND_LIST = cc_arg

# Create a dummy ssh key under ./src/key
def create_ssh_key():
    pass

# Modify the json file with the metadata
def modify_json():
    if len(metadata) == 0:
        print(Fore.RED + "[-] Use --help to see the available options")
        return
    if os.path.exists(JSON_NAME):
        with open(JSON_NAME, 'r') as f:
            data = json.load(f)
        data.update(metadata)        
    else:
        data = metadata

    with open(JSON_NAME, 'w') as f:
        json.dump(data, f, indent=4)
        print(Fore.GREEN + f"[+] Changes made on {JSON_NAME}")
        

def main():
    parser = argparse.ArgumentParser(description="Start a honeypot with the given username and password")
    parser.add_argument("--username", "-u", help="Username of the virtual environment")
    parser.add_argument("--password", "-p", help="Password of the virtual environment")
    parser.add_argument("--hostname", "-hn", help="Computer name/hostname of the virtual environment")
    parser.add_argument("--custom-folder", "-cf", help="Custom folder to create on top of the ./honeypot. -cf <folder_path> | -cf <folder_path1 folder_path2...> | -cf <folder_list.txt> | e.g -cf bin/new_virtual_folder", nargs="+", required=False)
    parser.add_argument("--custom-command", "-cc", help="Custom command to add to the virtual environment. Custom command list for this flag requires to be in .txt format. Requires the absolute path | -cc <path_to_command> | -cc <path_to_command1 path_to_command2...> | -cc <commands_list.txt> | e.g -cc /bin/bash ", nargs="+", required=False)
    parser.add_argument("--virtual", "-v", help="Enable virtual environment setup (copy commands, libraries, etc.)", action="store_true", default=False)
    parser.add_argument("--json", "-j", help="Create or modify the info container in json format", action="store_true", default=False)
    args = parser.parse_args()

    # Check root priviliges
    if os.getuid() != 0:
        print(Fore.RED + "Please run this script as root")
        sys.exit(1)
    if args.virtual:
        print(Fore.GREEN + "[+] Setting up the virtual environment")
        if args.custom_folder:
            custom_folders(args.custom_folder)
        else:
            default_structure()

        if args.custom_command:
            redefine_commands(args.custom_command) # Change the default COMMAND_LIST
        copy_commands()
    
    if args.username and args.password:
        metadata['username'] = args.username
        metadata['password'] = args.password
    if args.hostname:
        metadata['hostname'] = args.hostname
    if args.json:
        modify_json()
if __name__ == '__main__':
    main()
# Libraries
import os
import subprocess
import argparse
import sys
from colorama import Fore, Back, Style, init
import json
import bcrypt


init(autoreset=True)

ROOT_DIR = "./honeypot"
DIR_LIST = ['lib/x86_64-linux-gnu','lib64','usr/bin','usr/sbin','etc','home','var/www/html']
COMMAND_LIST = ['ls','cat','bash','passwd','useradd','whoami','hostname', 'id', 'cd']
JSON_NAME = "meta.json"
LIB_LIST = []
COMMAND_PATH_LIST = []
metadata = {}
uid = 1000
gid = 1000

def run_command(command, args):
    try:
        output = subprocess.run([command] + args, check=True, text=True, capture_output=True)
        return output.stdout
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] {e}")
        return None

def set_permissions(username):
    pid = os.fork()
    if pid == 0:
        os.chroot(ROOT_DIR)
        os.chdir('/')
        for lib in LIB_LIST:
            os.chown(lib, 0, 0)
            os.chmod(lib, 0o755)
        for command in COMMAND_PATH_LIST:
            os.chown(command, 0, 0)
            os.chmod(command, 0o755)
        os.chown(os.path.join(ROOT_DIR, f"/home/{username}"), uid, gid)
        os.chmod(os.path.join(ROOT_DIR, f"/home/{username}"), 0o700)
        os.chown(os.path.join(ROOT_DIR, 'etc', 'passwd'), 0, 0)
        os.chown(os.path.join(ROOT_DIR, 'etc', 'shadow'), 0, 0)
        os.chmod(os.path.join(ROOT_DIR, 'etc', 'passwd'), 0o644)
        os.chmod(os.path.join(ROOT_DIR, 'etc', 'shadow'), 0o600)

        os._exit(0)
    else:
        os.waitpid(pid, 0) # wait for child process to finish
        print(Fore.GREEN + "[+] Permissions set")
def create_dir(dir):
    try:
        os.makedirs(dir)
        print(Fore.GREEN + f"[+] Created dir {dir}")
    except FileExistsError:
        print(Fore.YELLOW + f"[!] Directory {dir.split('/')[-1]} already exists")
    # check if parent dir exists

# Create the virtual dir under honeypot/ which is exactly the scommand
def default_structure():
    for dir in DIR_LIST:
        create_dir(os.path.join(ROOT_DIR, dir))
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
                target_path = os.path.join(ROOT_DIR, lib_path[1:].strip())
                if not os.path.exists(target_path):
                    print(Back.BLUE + f"Copying {lib_path}  ===>  {target_path}")
                    run_command('cp', [lib_path, target_path])
                    LIB_LIST.append(lib_path)
                else:
                    print(Back.YELLOW + f"[!] {lib_path} already copied to {target_path}")
# Copy the commands which will be available in the virtual environment
def copy_commands():
    for command in COMMAND_LIST:
        try:
            command_path = run_command('which', [command]).strip()
            if command_path:
                if not os.path.exists(os.path.join(ROOT_DIR, os.path.dirname(command_path[1:]))):
                    create_dir(os.path.join(ROOT_DIR, os.path.dirname(command_path[1:])))
                target_path = os.path.join(ROOT_DIR, command_path[1:]).strip()
                if not os.path.exists(target_path):
                    run_command('cp', [command_path, target_path])
                    COMMAND_PATH_LIST.append(command_path)
                    print(Fore.GREEN + f"[+] Copied {command}")
                    copy_libraries(command) # Copying the libraries for the command
                
                else:
                    print(Fore.YELLOW + f"[!] {command_path} already copied to {target_path}")
        except Exception as e:
            print(Fore.RED + f"[-] e")

# Create a user and set the password. Define the /etc/passwd and /etc/shadow files
def create_virtual_user(username, password, uid, gid, shell):
    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Create entries for /etc/passwd and /etc/shadow
    passwd_entry = f"{username}:x:{uid}:{gid}::/home/{username}:{shell}\n"
    shadow_entry = f"{username}:{hashed_password}:18500:0:99999:7:::\n"

    if not os.path.exists(os.path.join(ROOT_DIR, 'etc')):
        create_dir(os.path.join(ROOT_DIR, 'etc'))
    
    # Add to /etc/passwd and /etc/shadow
    passwd_path = os.path.join(ROOT_DIR, 'etc', 'passwd')
    shadow_path = os.path.join(ROOT_DIR, 'etc', 'shadow')

    with open(passwd_path, 'w') as passwd:
        passwd.write(passwd_entry)
        print(Fore.GREEN + f"[+] Added {username} to {passwd_path}")
    with open(shadow_path, 'w') as shadow:
        shadow.write(shadow_entry)
        print(Fore.GREEN + f"[+] Added {username} to {shadow_path}")
    
    # Set permissions for shadow

# Set up home directory for the user
def setup_user_home(username):
    home_dir = os.path.join(ROOT_DIR, 'home', username)
    create_dir(home_dir)

    print(Fore.GREEN + f"[+] Created home directory for {username} at {home_dir}")
    
# Final security measures. Make sure attacker can't get out laterally

# Custom command/dir handle
def custom_dirs(cf_arg):
    if len(cf_arg) == 1:
        if os.path.exists(cf_arg[0]) and os.path.isfile(cf_arg[0]):
            with open(cf_arg[0], 'r') as f:
                for line in f.readlines():
                    create_dir(os.path.join(ROOT_DIR, line.strip()))
        elif not "." in cf_arg[0]:
            create_dir(os.path.join(ROOT_DIR, cf_arg[0]))
        else:
            print(Fore.RED + "[-] Invalid syntax")
    else:
        for dir in cf_arg:
            if not "." in dir:
                create_dir(os.path.join(ROOT_DIR, dir))
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
    parser = argparse.ArgumentParser(description="Start a honeypot with the given username and password. Configure the virtual system as well as the log system")
    parser.add_argument("--username", "-u", help="Username of the virtual environment")
    parser.add_argument("--password", "-p", help="Password of the virtual environment")
    parser.add_argument("--hostname", "-hn", help="Computer name/hostname of the virtual environment")
    parser.add_argument("--custom-dir", "-cd", help="Custom dir to create on top of the ./honeypot. -cf <dir_path> | -cf <dir_path1 dir_path2...> | -cf <dir_list.txt> | e.g -cf bin/new_virtual_dir", nargs="+", required=False)
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
        if args.custom_dir:
            custom_dirs(args.custom_dir)
        else:
            default_structure()

        if args.custom_command:
            redefine_commands(args.custom_command) # Change the default COMMAND_LIST
        copy_commands()
    
    if args.username and args.password:
        metadata['username'] = args.username
        metadata['password'] = args.password
        metadata['uid'] = uid
        metadata['gid'] = gid
        
        if args.virtual:
            create_virtual_user(args.username, args.password, uid, gid, '/bin/bash')
            setup_user_home(args.username)
            set_permissions(args.username)
    if args.hostname:
        metadata['hostname'] = args.hostname
    if args.json:
        modify_json()
    # Create a Logs dir which will store all of the log files for each attacker
    create_dir('Logs')
    
if __name__ == '__main__':
    main()
# Libraries
import os
import subprocess
import argparse
import sys
from colorama import Fore, Back, Style, init

init(autoreset=True)

'''
print(Fore.RED + "This is red text")
print(Fore.GREEN + "This is green text")
print(Back.YELLOW + "This has a yellow background")
print(Style.BRIGHT + "This is bright text")
'''

ROOT_FOLDER = "./honeypot"
FOLDER_STRUCTURE = ['bin','lib/x86_64-linux-gnu','lib64','usr/bin','usr/sbin','etc','home','var/www/html']
COMMAND_LIST = ['ls','cat','bash','passwd','useradd','ps','whoami','hostname']
LIB_LIST = []

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
# Copy the libraries the copied commands need
def copy_libraries(command):
    command_path = run_command('which', [command])
    out = run_command('ldd', [f'{command_path.strip()}'])
    if out:
        out_split = out.split('\n')
        for line in out_split:
            if '/' in line:
                if '=>' in line:
                    lib_path = line.split('=>')[1].strip()
                else:
                    lib_path = line.split('(')[0].strip()
                print(Back.YELLOW + lib_path)
# Copy the commands which will be available in the virtual environment
def copy_commands():
    for command in COMMAND_LIST:
        try:
            command_path = run_command('which', [command])
            if command_path:
                target_path = os.path.join(ROOT_FOLDER, command_path[1:].strip())
                if not os.path.exists(command_path):
                    out = run_command('cp', [command_path.strip(), target_path])
                    if out:
                        #copy_libraries(command)
                        print(Fore.GREEN + f"[+] Copied {command}")
                        pass
                else:
                    print(Fore.YELLOW + f"[!] {target_path} already copied")
        except Exception as e:
            print(Fore.RED + f"[-] e")

# Create a user 'yusuf' with password 'password' using chroot

# Make everything the libraries read only

# Final security measures

# Run commands using chroot (set honeypot as root folder)


def main():
    parser = argparse.ArgumentParser(description="Start a honeypot with the given username and password")
    parser.add_argument("--username", "-u", help="Username of the virtual environment", default="guest")
    parser.add_argument("--password", "-p", help="Password of the virtual environment", default="password")
    parser.add_argument("--hostname", "-hn", help="Computer name/hostname of the virtual environment", default="honeypot")
    args = parser.parse_args()

    # Check root priviliges
    if os.getuid() != 0:
        print(Fore.RED + "Please run this script as root")
        sys.exit(1)
    
    #run_command('echo', [f"{args.username}-{args.password}"])
    #create_virtual_structure()
    #copy_commands()

    copy_libraries("passwd")
if __name__ == '__main__':
    main()
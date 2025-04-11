# Latro Web

![Latro Web Banner](./img/LatroWeb%20arkaplan.png)

**Latro Web** is a hybrid honeypot written in **Python** and **C++**, designed to deceive attackers by mimicking an interactive and realistic system environment. The Python component (`start_honeypot.py`) sets up the virtual environment, simulates common directories and commands, and creates fake users—offering an authentic surface for attackers. The core honeypot logic, including logging, command handling, and client management, is implemented in C++, utilizing a parent-child process architecture for command execution.

> ⚠️ **Note:** This is a **beta version** and is currently under active development.

---

## 🚀 Usage

1. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up the virtual environment**
   ```bash
   sudo python3 start_honeypot.py -v -j -u <username> -p <password> -hn <hostname>
   ```
   - Add additional custom commands using `-cc`  
   - Add custom directories using `-cd`  
   - Use `--help` to view all available options

3. **Install nlohmann JSON for C++**  
   You can get it from: [https://github.com/nlohmann/json](https://github.com/nlohmann/json)

4. **Build the C++ binary**
   ```bash
   mkdir build && cd build
   cmake ..
   make
   ```

   The executable `LatroWeb` will be located in the `bin/` directory.

5. **Run the honeypot with root privileges**
   ```bash
   sudo ./bin/LatroWeb
   ```

6. **Connect from an attacker machine**
   ```bash
   nc <ip_address> <port>
   ```
   - Use the fake user credentials: `username:password`

7. **Logs**  
   All executed commands are saved in the `Logs/` directory.

---

## 🛠️ TODO

- [ ] Integrate GeoIP for attacker location tracking
- [ ] Integrate more logging features
- [ ] Expand command emulation and response capabilities
- [ ] Implement counter-attack strategies using custom payloads

---

## 📄 License

Latro Web is licensed under the [MIT License](LICENSE).

---
#pragma once

#include <array>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <functional>

#include <fcntl.h>
#include <cerrno>
#include <climits>
#include <spawn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../core/provider.h"

extern char **environ;

namespace fs = std::filesystem;

inline const std::string NETNS_NAME = "ar-discord-vpn";
inline const std::string WG_IF = "wg-ardc";

enum class LaunchTargetType {
  NativeExe,
  Flatpak,
  Snap,
  Command
};

struct LaunchTarget {
  LaunchTargetType type = LaunchTargetType::NativeExe;
  std::string command;
  std::string displayName;
};

inline std::string runCommand(const std::string &cmd) {
  std::array<char, 256> buffer;
  std::string result;
  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe)
    return "";
  while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
    result += buffer.data();
  pclose(pipe);
  while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
    result.pop_back();
  return result;
}

inline bool haveCommand(const std::string &binary) {
  return std::system(("command -v " + binary + " >/dev/null 2>&1").c_str()) == 0;
}

inline std::string detectLinuxDistro() {
  std::ifstream ofs("/etc/os-release");
  if (!ofs.is_open())
    return "linux";

  std::string line;
  std::string id, idLike;
  while (std::getline(ofs, line)) {
    if (line.rfind("ID=", 0) == 0) {
      id = line.substr(3);
      if (!id.empty() && id.front() == '"') id = id.substr(1, id.size() - 2);
    } else if (line.rfind("ID_LIKE=", 0) == 0) {
      idLike = line.substr(8);
      if (!idLike.empty() && idLike.front() == '"') idLike = idLike.substr(1, idLike.size() - 2);
    }
  }

  std::string combined = id + " " + idLike;
  for (char &c : combined) c = static_cast<char>(std::tolower(c));
  return combined;
}

inline bool checkPrerequisites(std::string &errorMessage) {
  bool missingIp = !haveCommand("ip");
  bool missingWg = !haveCommand("wg");
  bool missingCurl = !haveCommand("curl");
  bool missingIptables = !haveCommand("iptables");

  if (missingIp || missingWg || missingCurl || missingIptables) {
    // Tenta instalar automaticamente os pacotes ausentes via gerenciador de pacotes nativo
    std::string installCmd = "";
    if (haveCommand("pacman")) {
      installCmd = "sudo pacman -S --noconfirm --needed wireguard-tools iproute2 iptables curl";
    } else if (haveCommand("apt-get")) {
      installCmd = "sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools iproute2 iptables curl";
    } else if (haveCommand("dnf")) {
      installCmd = "sudo dnf install -y -q wireguard-tools iproute iptables curl";
    } else if (haveCommand("zypper")) {
      installCmd = "sudo zypper --non-interactive install -q wireguard-tools iproute2 iptables curl";
    }

    if (!installCmd.empty()) {
      int ret = std::system((installCmd + " >/dev/null 2>&1").c_str());
      if (ret == 0 && haveCommand("ip") && haveCommand("wg")) {
        return true;
      }
    }

    std::string distro = detectLinuxDistro();
    std::ostringstream ss;
    ss << "Dependências do sistema ausentes: ";
    if (missingIp) ss << "[iproute2 (ip)] ";
    if (missingWg) ss << "[wireguard-tools (wg)] ";
    if (missingCurl) ss << "[curl] ";
    if (missingIptables) ss << "[iptables] ";
    ss << "\nNão foi possível instalar automaticamente. Execute manualmente:\n";

    if (distro.find("arch") != std::string::npos || distro.find("manjaro") != std::string::npos || distro.find("endeavour") != std::string::npos) {
      ss << "  sudo pacman -S --needed wireguard-tools iproute2 iptables curl";
    } else if (distro.find("debian") != std::string::npos || distro.find("ubuntu") != std::string::npos || distro.find("mint") != std::string::npos || distro.find("pop") != std::string::npos) {
      ss << "  sudo apt update && sudo apt install -y wireguard-tools iproute2 iptables curl";
    } else if (distro.find("fedora") != std::string::npos || distro.find("rhel") != std::string::npos) {
      ss << "  sudo dnf install -y wireguard-tools iproute iptables curl";
    } else if (distro.find("suse") != std::string::npos) {
      ss << "  sudo zypper install -y wireguard-tools iproute2 iptables curl";
    } else {
      ss << "  Instale os pacotes 'wireguard-tools', 'iproute2', 'iptables' e 'curl'.";
    }

    errorMessage = ss.str();
    return false;
  }

  return true;
}

inline bool isDiscordRunning() {
  return std::system("pgrep -x \"(Discord|DiscordCanary|DiscordPTB|vesktop|equibop)\" >/dev/null 2>&1") == 0;
}

inline bool isDiscordRunningInNetns() {
  std::string pid = runCommand("pgrep -x \"(Discord|DiscordCanary|DiscordPTB|vesktop|equibop)\" | head -1");
  if (pid.empty())
    return false;
  std::string ns = runCommand("sudo ip netns identify " + pid + " 2>/dev/null");
  return ns == NETNS_NAME;
}

inline void killDiscord() {
  std::system("pkill -TERM -x \"Discord|DiscordCanary|DiscordPTB|vesktop|equibop\" >/dev/null 2>&1 || true");
  std::system("pkill -TERM -f \"/opt/discord\" >/dev/null 2>&1 || true");
  std::system("pkill -TERM -f \"/usr/share/discord\" >/dev/null 2>&1 || true");
  std::system("pkill -TERM -f \"/app/discord\" >/dev/null 2>&1 || true");
  for (int i = 0; i < 6; ++i) {
    if (!isDiscordRunning())
      return;
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }
  std::system("pkill -9 -x \"Discord|DiscordCanary|DiscordPTB|vesktop|equibop\" >/dev/null 2>&1 || true");
  std::system("pkill -9 -f \"/opt/discord\" >/dev/null 2>&1 || true");
  std::system("pkill -9 -f \"/usr/share/discord\" >/dev/null 2>&1 || true");
  std::system("pkill -9 -f \"/app/discord\" >/dev/null 2>&1 || true");
}

inline bool stopBypass() {
  // Encerrar quaisquer processos rodando dentro do namespace seguro
  std::system(("sudo ip netns pids " + NETNS_NAME + " 2>/dev/null | xargs -r sudo kill -9 >/dev/null 2>&1 || true").c_str());

  // Encerrar Discord e clientes alternativos
  killDiscord();

  // Deletar interfaces WireGuard e namespace de rede
  std::system(("sudo ip -n " + NETNS_NAME + " link del dev " + WG_IF + " 2>/dev/null || true").c_str());
  std::system(("sudo ip link del dev " + WG_IF + " 2>/dev/null || true").c_str());
  std::system(("sudo ip netns del " + NETNS_NAME + " 2>/dev/null || true").c_str());
  std::system(("sudo rm -rf /etc/netns/" + NETNS_NAME + " 2>/dev/null || true").c_str());

  // Limpeza de travas singleton
  const char *sudoUser = std::getenv("SUDO_USER");
  std::string user = (sudoUser && *sudoUser) ? sudoUser : runCommand("whoami");
  std::string realHome;
  if (sudoUser && *sudoUser) {
    realHome = "/home/" + std::string(sudoUser);
  } else {
    const char *h = std::getenv("HOME");
    realHome = (h && *h) ? h : ("/home/" + user);
  }

  const std::vector<std::string> configs = {"discord", "discordcanary", "discordptb", "vesktop", "equibop"};
  for (const auto &cfg : configs) {
    std::error_code ec;
    fs::remove(fs::path(realHome) / ".config" / cfg / "SingletonLock", ec);
    fs::remove(fs::path(realHome) / ".config" / cfg / "SingletonCookie", ec);
    fs::remove(fs::path(realHome) / ".config" / cfg / "SingletonSocket", ec);
  }

  return true;
}

inline std::string findDiscordExeInDir(const fs::path &dir, const std::string &binaryName = "Discord") {
  if (!fs::exists(dir))
    return "";

  fs::path latestPath;
  std::string latestVersion;
  try {
    for (const auto &entry : fs::directory_iterator(dir)) {
      if (!entry.is_directory())
        continue;
      const std::string folder = entry.path().filename().string();
      if (folder.rfind("app-", 0) != 0)
        continue;
      const fs::path exePath = entry.path() / binaryName;
      if (fs::is_regular_file(exePath) &&
          (latestVersion.empty() || folder > latestVersion)) {
        latestVersion = folder;
        latestPath = exePath;
      }
    }
  } catch (...) {}
  return latestPath.empty() ? "" : latestPath.string();
}

inline LaunchTarget locateDiscordLaunchTarget(const std::string &manualPath = "") {
  if (!manualPath.empty()) {
    if (fs::is_regular_file(manualPath)) {
      return {LaunchTargetType::NativeExe, manualPath, "Discord (Caminho Manual)"};
    }
    return {LaunchTargetType::Command, manualPath, "Discord (Comando Manual)"};
  }

  const char *home = std::getenv("HOME");
  std::string homeStr = home ? home : "";

  // 1. Procurar versões nativas oficiais na pasta do usuário ~/.config/discord*
  if (!homeStr.empty()) {
    std::string exe = findDiscordExeInDir(fs::path(homeStr) / ".config" / "discord", "Discord");
    if (!exe.empty()) return {LaunchTargetType::NativeExe, exe, "Discord Stable (Nativo)"};

    exe = findDiscordExeInDir(fs::path(homeStr) / ".config" / "discordcanary", "DiscordCanary");
    if (!exe.empty()) return {LaunchTargetType::NativeExe, exe, "Discord Canary (Nativo)"};

    exe = findDiscordExeInDir(fs::path(homeStr) / ".config" / "discordptb", "DiscordPTB");
    if (!exe.empty()) return {LaunchTargetType::NativeExe, exe, "Discord PTB (Nativo)"};
  }

  // 2. Procurar executáveis nativos no PATH do sistema
  const std::vector<std::pair<std::string, std::string>> binCandidates = {
      {"discord", "Discord Stable"},
      {"Discord", "Discord Stable"},
      {"discord-canary", "Discord Canary"},
      {"discordcanary", "Discord Canary"},
      {"discord-ptb", "Discord PTB"},
      {"discordptb", "Discord PTB"},
      {"vesktop", "Vesktop (Cliente Vencord)"},
      {"equibop", "Equibop (Cliente Equicord)"}
  };

  for (const auto &[cmd, name] : binCandidates) {
    if (haveCommand(cmd)) {
      std::string path = runCommand("command -v " + cmd + " 2>/dev/null");
      // Atalhos em /snap/bin são snaps: têm lançamento próprio (ver launchDiscord)
      if (path.rfind("/snap/bin/", 0) == 0 || path.rfind("/var/lib/snapd/snap/bin/", 0) == 0) {
        return {LaunchTargetType::Snap, "snap run " + fs::path(path).filename().string(), name + " (Snap)"};
      }
      if (!path.empty()) {
        return {LaunchTargetType::NativeExe, path, name};
      }
    }
  }

  // 3. Procurar instalações Flatpak (do usuário ou do sistema)
  if (haveCommand("flatpak")) {
    const std::vector<std::pair<std::string, std::string>> flatpakApps = {
        {"com.discordapp.Discord", "Discord (Flatpak)"},
        {"com.discordapp.DiscordCanary", "Discord Canary (Flatpak)"},
        {"com.discordapp.DiscordPTB", "Discord PTB (Flatpak)"},
        {"dev.vencord.Vesktop", "Vesktop (Flatpak)"},
        {"org.equicord.equibop", "Equibop (Flatpak)"}
    };

    for (const auto &[appId, name] : flatpakApps) {
      std::string check = runCommand("flatpak info " + appId + " 2>/dev/null");
      if (!check.empty()) {
        return {LaunchTargetType::Flatpak, "flatpak run " + appId, name};
      }
    }
  }

  // 4. Procurar instalações Snap
  if (haveCommand("snap")) {
    if (fs::is_regular_file("/snap/bin/discord") || fs::is_regular_file("/var/lib/snapd/snap/bin/discord")) {
      return {LaunchTargetType::Snap, "snap run discord", "Discord (Snap)"};
    }
  }

  // 5. Procurar diretórios de sistema padrão (/opt, /usr/share, /usr/lib)
  const std::vector<std::string> systemDirs = {
      "/opt/discord/Discord", "/opt/Discord/Discord",
      "/usr/share/discord/Discord", "/usr/lib/discord/Discord"
  };
  for (const auto &sysPath : systemDirs) {
    if (fs::is_regular_file(sysPath)) {
      return {LaunchTargetType::NativeExe, sysPath, "Discord (Sistema)"};
    }
  }

  return {};
}

#ifndef _WIN32
extern "C" const char _binary_proton_confgen_start[];
extern "C" const char _binary_proton_confgen_end[];

inline std::string extractEmbeddedProtonConfgenLinux() {
  size_t size = _binary_proton_confgen_end - _binary_proton_confgen_start;
  if (size == 0) return "";

  const char *home = std::getenv("HOME");
  std::string targetDir = home ? (std::string(home) + "/.local/share/ARDiscordBypass") : "/tmp/ARDiscordBypass";

  std::error_code ec;
  fs::create_directories(targetDir, ec);
  std::string outPath = targetDir + "/proton-confgen";

  if (fs::exists(outPath) && fs::file_size(outPath) == size) {
    ::chmod(outPath.c_str(), 0755);
    return outPath;
  }

  std::ofstream out(outPath, std::ios::binary);
  if (!out.is_open()) return "";
  out.write(_binary_proton_confgen_start, size);
  out.close();

  ::chmod(outPath.c_str(), 0755);
  return fs::exists(outPath) ? outPath : "";
}
#endif

inline std::string findProtonConfgen() {
  char exePath[PATH_MAX];
  ssize_t len = ::readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
  std::vector<std::string> paths = {
    "./bin/proton-confgen",
    "../bin/proton-confgen",
    "PC/bin/proton-confgen",
    "./proton-confgen",
    "/usr/local/bin/proton-confgen"
  };
  if (len != -1) {
    exePath[len] = '\0';
    fs::path selfDir = fs::path(exePath).parent_path();
    paths.insert(paths.begin(), (selfDir / "bin" / "proton-confgen").string());
    paths.insert(paths.begin(), (selfDir / "proton-confgen").string());
  }

  for (const auto &p : paths) {
    if (fs::is_regular_file(p)) return p;
  }

#ifndef _WIN32
  return extractEmbeddedProtonConfgenLinux();
#else
  return "";
#endif
}

extern "C" const char _binary_nord_confgen_start[];
extern "C" const char _binary_nord_confgen_end[];

// Grava em ~/.local/share/ARDiscordBypass um utilitário embutido no executável.
inline std::string extractEmbeddedHelperLinux(const std::string &name, const char *start, const char *end) {
  size_t size = end - start;
  if (size == 0) return "";

  const char *home = std::getenv("HOME");
  std::string targetDir = home ? (std::string(home) + "/.local/share/ARDiscordBypass") : "/tmp/ARDiscordBypass";

  std::error_code ec;
  fs::create_directories(targetDir, ec);
  std::string outPath = targetDir + "/" + name;

  if (fs::exists(outPath, ec) && fs::file_size(outPath, ec) == size) {
    ::chmod(outPath.c_str(), 0755);
    return outPath;
  }

  std::ofstream out(outPath, std::ios::binary);
  if (!out.is_open()) return "";
  out.write(start, size);
  out.close();

  ::chmod(outPath.c_str(), 0755);
  return fs::exists(outPath, ec) ? outPath : "";
}

inline std::string findNordConfgen() {
  char exePath[PATH_MAX];
  ssize_t len = ::readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
  std::vector<std::string> paths = {
    "./bin/nord-confgen",
    "../bin/nord-confgen",
    "PC/bin/nord-confgen",
    "./nord-confgen",
    "/usr/local/bin/nord-confgen"
  };
  if (len != -1) {
    exePath[len] = '\0';
    fs::path selfDir = fs::path(exePath).parent_path();
    paths.insert(paths.begin(), (selfDir / "bin" / "nord-confgen").string());
    paths.insert(paths.begin(), (selfDir / "nord-confgen").string());
  }

  for (const auto &p : paths) {
    if (fs::is_regular_file(p)) return p;
  }

  return extractEmbeddedHelperLinux("nord-confgen", _binary_nord_confgen_start, _binary_nord_confgen_end);
}

inline fs::path protonSessionPath() {
  const char *home = std::getenv("HOME");
  return (home && *home) ? fs::path(home) / PROTON_SESSION_FILE : fs::path();
}

inline fs::path nordSessionPath() {
  const char *home = std::getenv("HOME");
  return (home && *home) ? fs::path(home) / NORD_SESSION_FILE : fs::path();
}

inline bool hasNordSession() {
  fs::path p = nordSessionPath();
  std::error_code ec;
  return !p.empty() && fs::is_regular_file(p, ec);
}

inline VpnProvider savedSessionProvider() {
  return newestSessionProvider(protonSessionPath(), nordSessionPath());
}

inline bool defaultConfExists() {
  return fs::is_regular_file("ardc_vpn.conf");
}

// Executa um programa diretamente (sem shell; args[0] é procurado no PATH),
// entrega stdinData pela entrada padrão e captura stdout+stderr linha a linha.
// Devolve o código de saída ou -1.
inline int runHelperCapture(
    const std::vector<std::string> &args,
    const std::string &stdinData,
    std::string &fullOutput,
    const std::function<void(const std::string&)> &onLine = nullptr) {
  // O conteúdo de stdin precisa caber no buffer do pipe (64 KiB no Linux; ver abaixo).
  if (args.empty() || stdinData.size() > 60 * 1024) return -1;

  int inPipe[2] = {-1, -1};
  int outPipe[2] = {-1, -1};
  if (::pipe2(inPipe, O_CLOEXEC) != 0) return -1;
  if (::pipe2(outPipe, O_CLOEXEC) != 0) {
    ::close(inPipe[0]);
    ::close(inPipe[1]);
    return -1;
  }

  // Grava antes de criar o processo e fecha a ponta de escrita: o utilitário lê
  // até EOF e, como a ponta de leitura ainda é nossa, não há risco de SIGPIPE.
  if (!stdinData.empty()) {
    ssize_t written = ::write(inPipe[1], stdinData.data(), stdinData.size());
    (void)written;
  }
  ::close(inPipe[1]);

  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, inPipe[0], STDIN_FILENO);
  posix_spawn_file_actions_adddup2(&actions, outPipe[1], STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, outPipe[1], STDERR_FILENO);

  std::vector<char *> argv;
  for (const auto &arg : args) argv.push_back(const_cast<char *>(arg.c_str()));
  argv.push_back(nullptr);

  pid_t pid = -1;
  int rc = ::posix_spawnp(&pid, args[0].c_str(), &actions, nullptr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  ::close(inPipe[0]);
  ::close(outPipe[1]);
  if (rc != 0) {
    ::close(outPipe[0]);
    return -1;
  }

  FILE *out = ::fdopen(outPipe[0], "r");
  if (out) {
    char buffer[512];
    while (fgets(buffer, sizeof(buffer), out) != nullptr) {
      fullOutput += buffer;
      if (onLine) onLine(trimWhitespace(buffer));
    }
    fclose(out);
  } else {
    ::close(outPipe[0]);
  }

  int status = 0;
  while (::waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

inline bool setupWireGuardFromConf(const std::string &confPath, std::string *wgError = nullptr) {
  std::ifstream infile(confPath);
  if (!infile.is_open()) return false;

  std::string line;
  std::string address = "10.2.0.2/32";
  std::string dns = "10.2.0.1";
  std::vector<std::string> cleanLines;

  while (std::getline(infile, line)) {
    std::string trimmed = line;
    trimmed.erase(0, trimmed.find_first_not_of(" \t\r\n"));
    trimmed.erase(trimmed.find_last_not_of(" \t\r\n") + 1);

    std::string lower = trimmed;
    for (char &c : lower) c = static_cast<char>(std::tolower(c));

    if (lower.rfind("address", 0) == 0) {
      size_t eq = trimmed.find('=');
      if (eq != std::string::npos) {
        address = trimmed.substr(eq + 1);
        address.erase(0, address.find_first_not_of(" \t"));
        address.erase(address.find_last_not_of(" \t") + 1);
      }
    } else if (lower.rfind("dns", 0) == 0) {
      size_t eq = trimmed.find('=');
      if (eq != std::string::npos) {
        dns = trimmed.substr(eq + 1);
        dns.erase(0, dns.find_first_not_of(" \t"));
        dns.erase(dns.find_last_not_of(" \t") + 1);
      }
    } else if (lower.rfind("mtu", 0) == 0) {
      // Ignorar MTU no arquivo para wg setconf
    } else {
      cleanLines.push_back(line);
    }
  }

  // O perfil limpo chega ao wg por um pipe criado pelo shell root (mesma técnica
  // do wg-quick), nunca por arquivo em /tmp: onde o wg roda confinado por
  // AppArmor (ex.: Ubuntu 26.04) ele só pode ler arquivos em /etc/wireguard, e o
  // setconf falhava em silêncio. De quebra a chave privada não passa por disco.
  std::string cleanConf;
  for (const auto &cl : cleanLines) cleanConf += cl + "\n";

  std::string wgOutput;
  int wgRet = runHelperCapture({"sudo", "sh", "-c", "cat | wg setconf " + WG_IF + " /dev/stdin"}, cleanConf, wgOutput);
  if (wgRet != 0) {
    if (wgError) *wgError = trimWhitespace(wgOutput);
    return false;
  }

  std::system(("sudo ip link set " + WG_IF + " netns " + NETNS_NAME).c_str());
  if (address.find('/') == std::string::npos) address += "/32";
  std::system(("sudo ip -n " + NETNS_NAME + " addr add " + address + " dev " + WG_IF).c_str());
  std::system(("sudo ip -n " + NETNS_NAME + " link set " + WG_IF + " mtu 1280").c_str());
  std::system(("sudo ip -n " + NETNS_NAME + " link set " + WG_IF + " up").c_str());
  std::system(("sudo ip -n " + NETNS_NAME + " link set lo up").c_str());
  std::system(("sudo ip -n " + NETNS_NAME + " route add default dev " + WG_IF).c_str());

  // Clamping de MSS para evitar queda de pacotes TLS maiores que o MTU
  std::system(("sudo ip netns exec " + NETNS_NAME + " iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o " + WG_IF + " -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true").c_str());

  // DNS para apps em sandbox (Snap): o sandbox monta o /etc/resolv.conf do
  // sistema, que costuma apontar para um resolvedor local (127.0.0.53 do
  // systemd-resolved) que não existe dentro do namespace. As consultas DNS a
  // endereços de loopback são redirecionadas para o primeiro DNS IPv4 do perfil.
  std::string tunnelDns = "1.1.1.1";
  {
    std::stringstream dnsList(dns);
    std::string candidate;
    while (std::getline(dnsList, candidate, ',')) {
      candidate = trimWhitespace(candidate);
      if (!candidate.empty() && candidate.find_first_not_of("0123456789.") == std::string::npos) {
        tunnelDns = candidate;
        break;
      }
    }
  }
  const std::string inNetns = "sudo ip netns exec " + NETNS_NAME + " ";
  std::system((inNetns + "sysctl -qw net.ipv4.conf.all.route_localnet=1 2>/dev/null || true").c_str());
  for (const char *proto : {"udp", "tcp"}) {
    std::system((inNetns + "iptables -t nat -A OUTPUT -d 127.0.0.0/8 -p " + proto + " --dport 53 -j DNAT --to-destination " + tunnelDns + ":53 2>/dev/null || true").c_str());
  }
  std::system((inNetns + "iptables -t nat -A POSTROUTING -o " + WG_IF + " -s 127.0.0.0/8 -j MASQUERADE 2>/dev/null || true").c_str());

  // Formatação robusta de resolv.conf com múltiplos DNS
  std::system(("sudo mkdir -p /etc/netns/" + NETNS_NAME).c_str());
  std::string resolvContent = "options timeout:1 attempts:2\n";
  std::stringstream ss(dns);
  std::string item;
  while (std::getline(ss, item, ',')) {
    item.erase(0, item.find_first_not_of(" \t\r\n"));
    item.erase(item.find_last_not_of(" \t\r\n") + 1);
    if (!item.empty()) resolvContent += "nameserver " + item + "\n";
  }
  resolvContent += "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
  std::string resolvTmp = "/tmp/resolv-" + std::to_string(getpid()) + ".conf";
  std::ofstream resFile(resolvTmp);
  resFile << resolvContent;
  resFile.close();
  std::system(("sudo cp " + resolvTmp + " /etc/netns/" + NETNS_NAME + "/resolv.conf && rm -f " + resolvTmp).c_str());

  return true;
}

inline bool setupProtonConfig(
    bool interactive = false,
    const std::string &explicitUser = "",
    const std::string &explicitPass = "",
    std::string *outErr = nullptr,
    std::function<void(const std::string&)> onProgress = nullptr) {
  if (fs::is_regular_file("ardc_vpn.conf") && !interactive && explicitUser.empty()) {
    return true;
  }

  const char *home = std::getenv("HOME");
  std::string sessionPath = home ? (std::string(home) + "/.protonvpn-session.json") : "";
  bool hasSession = !sessionPath.empty() && fs::is_regular_file(sessionPath);
  std::string confgen = findProtonConfgen();

  if (hasSession && !confgen.empty() && !interactive && explicitUser.empty()) {
    std::string cmd = confgen + " --free-only --countries US,NL,JP --output ardc_vpn.conf >/dev/null 2>&1";
    int ret = std::system(cmd.c_str());
    if (ret == 0 && fs::is_regular_file("ardc_vpn.conf")) {
      return true;
    }
  }

  if (confgen.empty()) {
    std::string msg = "Utilitário proton-confgen não encontrado.";
    if (outErr) *outErr = msg;
    if (onProgress) onProgress(msg);
    std::cerr << "  \033[38;2;229;9;20m✖\033[0m Utilitário proton-confgen não encontrado e ardc_vpn.conf ausente.\n";
    std::cerr << "    Por favor, coloque seu arquivo WireGuard 'ardc_vpn.conf' nesta pasta.\n";
    return false;
  }

  std::string username = explicitUser;
  std::string password = explicitPass;

  if (username.empty() || password.empty()) {
    std::cout << "\n  \033[38;2;255;214;0m\033[1m[ Configuração do Túnel WireGuard (ProtonVPN Free / Plus) ]\033[0m\n";
    std::cout << "  Para gerar seu túnel exclusivo (sem risco de colisão de IP ou vazamento de chaves):\n";
    std::cout << "  Usuário ProtonVPN: ";
    std::cout.flush();
    std::getline(std::cin, username);
    if (username.empty()) return false;

    std::cout << "  Senha ProtonVPN: ";
    std::cout.flush();
    std::system("stty -echo");
    std::getline(std::cin, password);
    std::system("stty echo");
    std::cout << "\n";

    if (password.empty()) return false;
  }

  if (onProgress) onProgress("Iniciando handshake seguro via SRP na API Proton...");
  std::cout << "  Autenticando no Proton e gerando túnel WireGuard exclusivo..." << std::endl;

  auto escapeShellArg = [](const std::string &s) -> std::string {
    std::string out = "'";
    for (char c : s) {
      if (c == '\'') out += "'\\''";
      else out += c;
    }
    out += "'";
    return out;
  };

  std::string cmd = confgen + " --username " + escapeShellArg(username) + " --password " + escapeShellArg(password) + " --free-only --countries US,NL,JP --output ardc_vpn.conf 2>&1";

  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    if (outErr) *outErr = "Erro ao executar utilitário proton-confgen.";
    if (onProgress) onProgress("Erro ao executar utilitário proton-confgen.");
    return false;
  }

  std::string fullOutput;
  char buffer[512];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    std::string line(buffer);
    fullOutput += line;
    std::cout << line;
    std::cout.flush();

    if (onProgress) {
      if (line.find("Authentication successful") != std::string::npos) {
        onProgress("Credenciais aceitas! Consultando servidores...");
      } else if (line.find("Selected server:") != std::string::npos) {
        size_t pos = line.find("Selected server:");
        std::string s = line.substr(pos + 16);
        size_t endPos = s.find(" (");
        if (endPos != std::string::npos) s = s.substr(0, endPos);
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
        while (!s.empty() && (s.back() == ' ' || s.back() == '\r' || s.back() == '\n')) s.pop_back();
        onProgress("Servidor selecionado: " + s);
      } else if (line.find("WireGuard configuration written") != std::string::npos) {
        onProgress("Chaves criptográficas geradas com sucesso!");
      } else if (line.find("Successfully generated config") != std::string::npos) {
        onProgress("Perfil WireGuard finalizado com sucesso!");
      }
    }
  }

  int ret = pclose(pipe);

  if (ret != 0 || !fs::is_regular_file("ardc_vpn.conf")) {
    if (fullOutput.find("code 8002") != std::string::npos || fullOutput.find("password is not correct") != std::string::npos) {
      if (outErr) *outErr = "Senha incorreta. Verifique suas credenciais Proton.";
    } else if (fullOutput.find("code 9001") != std::string::npos || fullOutput.find("human verification") != std::string::npos) {
      if (outErr) *outErr = "A Proton solicitou verificação humana. Faça login pelo navegador uma vez.";
    } else if (fullOutput.find("code 2001") != std::string::npos || fullOutput.find("user does not exist") != std::string::npos) {
      if (outErr) *outErr = "Usuário ou email Proton não encontrado.";
    } else {
      std::string cleanErr;
      std::stringstream ss(fullOutput);
      std::string l;
      while (std::getline(ss, l)) {
        if (l.rfind("Error: ", 0) == 0) {
          cleanErr = l.substr(7);
        }
      }
      if (outErr) *outErr = cleanErr.empty() ? "Falha na autenticação ou timeout da API Proton." : cleanErr;
    }
    std::cerr << "  \033[38;2;229;9;20m✖\033[0m " << (outErr ? *outErr : "Falha na autenticação Proton.") << "\n";
    return false;
  }

  if (onProgress) onProgress("Perfil WireGuard ProtonVPN gerado com sucesso!");
  std::cout << "  \033[38;2;0;230;118m✔\033[0m \033[1mConfiguração ProtonVPN internacional gerada com sucesso!\033[0m\n";
  return true;
}

// Gera ardc_vpn.conf pelo nord-confgen. Com token faz o login na API NordVPN;
// com token vazio reutiliza a chave NordLynx salva na sessão. O token segue
// pela entrada padrão do utilitário e nunca aparece em argv ou em disco.
inline bool runNordConfgen(
    const std::string &token,
    std::string *outErr = nullptr,
    const std::function<void(const std::string&)> &onProgress = nullptr) {
  std::string confgen = findNordConfgen();
  if (confgen.empty()) {
    if (outErr) *outErr = "Utilitário nord-confgen não encontrado.";
    return false;
  }

  std::vector<std::string> args = {confgen, "--countries", NORD_COUNTRIES, "--output", "ardc_vpn.conf"};
  if (!token.empty()) args.push_back("--token-stdin");

  std::string output;
  int ret = runHelperCapture(args, token.empty() ? "" : token + "\n", output, [&](const std::string &line) {
    if (!onProgress) return;
    std::string step = confgenProgressMessage(line);
    if (!step.empty()) onProgress(step);
  });

  if (ret != 0 || !fs::is_regular_file("ardc_vpn.conf")) {
    if (outErr) *outErr = (ret == -1 && output.empty()) ? "Erro ao executar utilitário nord-confgen." : nordErrorMessage(output);
    return false;
  }
  return true;
}

// Fluxo de terminal (CLI) da NordVPN: reaproveita o perfil ou a sessão salva e
// só pede o token de acesso quando não há outra forma (ou quando forceLogin).
inline bool setupNordConfig(bool forceLogin = false) {
  if (!forceLogin) {
    if (fs::is_regular_file("ardc_vpn.conf")) return true;
    if (hasNordSession() && runNordConfgen("")) return true;
  }

  std::cout << "\n  \033[38;2;255;214;0m\033[1m[ Configuração do Túnel WireGuard (NordVPN) ]\033[0m\n";
  std::cout << "  Requer assinatura NordVPN ativa. Gere um token de acesso em:\n";
  std::cout << "  " << NORD_TOKEN_URL << "\n";
  std::cout << "  Token de acesso NordVPN: ";
  std::cout.flush();

  std::string token;
  std::system("stty -echo");
  std::getline(std::cin, token);
  std::system("stty echo");
  std::cout << "\n";

  token = trimWhitespace(token);
  if (token.empty()) return false;

  std::cout << "  Validando token e gerando túnel WireGuard exclusivo..." << std::endl;

  std::string err;
  bool ok = runNordConfgen(token, &err, [](const std::string &step) {
    std::cout << "  " << step << std::endl;
  });
  if (!ok) {
    std::cerr << "  \033[38;2;229;9;20m✖\033[0m " << err << "\n";
    return false;
  }

  std::cout << "  \033[38;2;0;230;118m✔\033[0m \033[1mConfiguração NordVPN internacional gerada com sucesso!\033[0m\n";
  return true;
}

// Recria ardc_vpn.conf pela sessão salva do provedor, sem nenhuma interação.
inline bool renewDefaultProfile(VpnProvider provider) {
  if (provider == VpnProvider::Nord) {
    return runNordConfgen("");
  }
  if (provider == VpnProvider::Proton) {
    std::string confgen = findProtonConfgen();
    if (confgen.empty()) return false;
    std::string cmd = confgen + " --free-only --countries US,NL,JP --output ardc_vpn.conf </dev/null >/dev/null 2>&1";
    return std::system(cmd.c_str()) == 0 && fs::is_regular_file("ardc_vpn.conf");
  }
  return false;
}

// Remove a interface recém-criada e explica por que o wg não aceitou o perfil.
inline bool abortTunnelSetup(const std::string &wgError, std::string *outDetail) {
  std::system(("sudo ip link del dev " + WG_IF + " 2>/dev/null || true").c_str());
  if (outDetail) {
    std::string reason = wgError;
    for (char &c : reason) if (c == '\n' || c == '\r') c = ' ';
    *outDetail = "wg setconf recusou o perfil" + (reason.empty() ? std::string() : ": " + reason);
  }
  return false;
}

inline bool ensureWireGuardNetns(const std::string &confPath = "ardc_vpn.conf", std::string *outDetail = nullptr) {
  std::system("sudo modprobe wireguard >/dev/null 2>&1 || true");

  // Limpeza prévia para não deixar conflito de namespace ou interface
  std::system(("sudo ip -n " + NETNS_NAME + " link del dev " + WG_IF + " 2>/dev/null || true").c_str());
  std::system(("sudo ip link del dev " + WG_IF + " 2>/dev/null || true").c_str());
  std::system(("sudo ip netns del " + NETNS_NAME + " 2>/dev/null || true").c_str());

  std::system(("sudo ip netns add " + NETNS_NAME).c_str());
  std::system(("sudo ip link add dev " + WG_IF + " type wireguard").c_str());

  if (!fs::is_regular_file(confPath)) {
    // Perfil padrão ausente: recria pela sessão salva (ProtonVPN ou NordVPN)
    if (confPath != "ardc_vpn.conf" || !renewDefaultProfile(savedSessionProvider())) {
      return false;
    }
  }

  std::string wgError;
  if (!setupWireGuardFromConf(confPath, &wgError)) {
    return abortTunnelSetup(wgError, outDetail);
  }

  // Aquecimento do túnel: envia pacote para forçar o handshake inicial do WireGuard
  std::system(("sudo ip netns exec " + NETNS_NAME + " ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 || true").c_str());

  // Aguarda confirmação ativa do handshake WireGuard (até 3 segundos)
  for (int i = 0; i < 6; ++i) {
    std::string wgHs = runCommand("sudo ip netns exec " + NETNS_NAME + " wg show " + WG_IF + " latest-handshakes 2>/dev/null");
    std::stringstream ss(wgHs);
    std::string key;
    long long ts = 0;
    if (ss >> key >> ts && ts > 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  // Validação 1: Gateway WebSocket oficial do Discord
  std::string testDiscord = runCommand("sudo ip netns exec " + NETNS_NAME + " curl -s -m 5 https://discord.com/api/v9/gateway 2>/dev/null");
  if (testDiscord.find("gateway") != std::string::npos) {
    return true;
  }

  // Validação 2: Cloudflare Trace com checagem de país internacional
  std::string testEgress = runCommand("sudo ip netns exec " + NETNS_NAME + " curl -s -m 5 https://1.1.1.1/cdn-cgi/trace 2>/dev/null");
  if (!testEgress.empty() && testEgress.find("loc=BR") == std::string::npos) {
    return true;
  }

  // Se o usuário passou um arquivo de configuração customizado, não tenta sobrescrever com Proton
  if (confPath != "ardc_vpn.conf") {
    return false;
  }

  // Auto-recuperação: se a rota expirou, renova o perfil pelo provedor que o gerou.
  // Perfis sem cabeçalho de gerador foram trazidos pelo usuário e não são sobrescritos.
  if (renewDefaultProfile(detectConfProvider("ardc_vpn.conf"))) {
    std::system(("sudo ip -n " + NETNS_NAME + " link del dev " + WG_IF + " 2>/dev/null || true").c_str());
    std::system(("sudo ip link del dev " + WG_IF + " 2>/dev/null || true").c_str());
    std::system(("sudo ip link add dev " + WG_IF + " type wireguard").c_str());
    if (!setupWireGuardFromConf("ardc_vpn.conf", &wgError)) {
      return abortTunnelSetup(wgError, outDetail);
    }
    std::system(("sudo ip netns exec " + NETNS_NAME + " ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 || true").c_str());
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    testDiscord = runCommand("sudo ip netns exec " + NETNS_NAME + " curl -s -m 5 https://discord.com/api/v9/gateway 2>/dev/null");
    return testDiscord.find("gateway") != std::string::npos;
  }

  return false;
}

inline bool launchDiscord(const LaunchTarget &target) {
  const char *sudoUser = std::getenv("SUDO_USER");
  const char *sudoUid = std::getenv("SUDO_UID");
  std::string user = (sudoUser && *sudoUser) ? sudoUser : runCommand("whoami");
  std::string uid = (sudoUid && *sudoUid) ? sudoUid : runCommand("id -u");
  if (user == "root" && sudoUser && *sudoUser) user = sudoUser;
  if (uid == "0" && sudoUid && *sudoUid) uid = sudoUid;
  if (user.empty() || user == "root") user = "alexsanderalri";
  if (uid.empty() || uid == "0") uid = "1000";

  std::string realHome;
  if (sudoUser && *sudoUser) {
    realHome = "/home/" + std::string(sudoUser);
  } else {
    const char *h = std::getenv("HOME");
    realHome = (h && *h) ? h : ("/home/" + user);
  }

  const std::vector<std::string> configs = {"discord", "discordcanary", "discordptb", "vesktop"};
  for (const auto &cfg : configs) {
    fs::remove(fs::path(realHome) / ".config" / cfg / "SingletonLock");
    fs::remove(fs::path(realHome) / ".config" / cfg / "SingletonCookie");
    fs::remove(fs::path(realHome) / ".config" / cfg / "SingletonSocket");
  }

  // Detecção dinâmica de ambiente gráfico (X11 / Wayland)
  std::ostringstream envVars;
  envVars << "HOME=" << realHome << " "
          << "USER=" << user << " "
          << "LOGNAME=" << user << " "
          << "XDG_RUNTIME_DIR=/run/user/" << uid << " ";

  const char *display = std::getenv("DISPLAY");
  if (display && *display) {
    envVars << "DISPLAY=" << display << " ";
  } else {
    envVars << "DISPLAY=:0 ";
  }

  const char *waylandDisplay = std::getenv("WAYLAND_DISPLAY");
  if (waylandDisplay && *waylandDisplay) {
    envVars << "WAYLAND_DISPLAY=" << waylandDisplay << " ";
  } else {
    // Verificar se existe socket wayland na pasta do usuário
    if (fs::exists("/run/user/" + uid + "/wayland-0")) {
      envVars << "WAYLAND_DISPLAY=wayland-0 ";
    }
  }

  const char *xauth = std::getenv("XAUTHORITY");
  if (xauth && *xauth) {
    envVars << "XAUTHORITY=" << xauth << " ";
  } else if (fs::exists(fs::path(realHome) / ".Xauthority")) {
    envVars << "XAUTHORITY=" << fs::path(realHome) / ".Xauthority" << " ";
  }

  // Audio e Sessao
  envVars << "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" << uid << "/bus "
          << "PULSE_SERVER=unix:/run/user/" << uid << "/pulse/native "
          << "ELECTRON_OZONE_PLATFORM_HINT=auto ";

  const char *desktop = std::getenv("XDG_CURRENT_DESKTOP");
  if (desktop && *desktop) {
    envVars << "XDG_CURRENT_DESKTOP=" << desktop << " ";
  }

  const char *sessionType = std::getenv("XDG_SESSION_TYPE");
  if (sessionType && *sessionType) {
    envVars << "XDG_SESSION_TYPE=" << sessionType << " ";
  }

  // Snaps não iniciam sob "ip netns exec": ele troca também o namespace de
  // montagem e esconde /sys/fs/cgroup, e o "snap run" aborta com "cannot find
  // tracking cgroup". O nsenter troca apenas o namespace de rede.
  std::string enterNetns = "ip netns exec " + NETNS_NAME;
  if (target.type == LaunchTargetType::Snap && haveCommand("nsenter")) {
    enterNetns = "nsenter --net=/run/netns/" + NETNS_NAME;
  }

  std::ostringstream cmd;
  cmd << "sudo " << enterNetns << " setsid -f sudo -u " << user << " env "
      << envVars.str()
      << target.command << " >/dev/null 2>&1";

  int ret = std::system(cmd.str().c_str());
  if (ret != 0) return false;

  // Snaps e Flatpaks montam o sandbox antes de o processo do Discord aparecer:
  // além dos 2 segundos de sempre, espera até mais 10.
  std::this_thread::sleep_for(std::chrono::seconds(2));
  for (int i = 0; i < 20 && !isDiscordRunning(); ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  return isDiscordRunning();
}

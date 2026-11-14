#pragma once

// Camada de plataforma do macOS (somente CLI por enquanto).
//
// O macOS não tem namespaces de rede. O túnel por aplicativo é montado assim:
//   1. o utilitário ardc-tunnel (tools/macos-tunnel) sobe um WireGuard em
//      userspace numa interface utun que nunca vira rota padrão;
//   2. regras do firewall pf desviam para essa interface apenas o tráfego de
//      sockets cujo dono é um grupo unix dedicado;
//   3. este executável abre o navegador sob esse grupo, com um perfil próprio,
//      direto no Discord Web. Tudo o mais na máquina segue pela rede normal.
// Abrir um processo sob outro grupo exige root, então o executável se chama de
// novo via sudo com --internal-launch (ver internalLaunchMain).

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include <dlfcn.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#include "../../core/provider.h"

extern char **environ;

namespace fs = std::filesystem;

inline const char *DISCORD_WEB_URL = "https://discord.com/app";
inline const char *DISCORD_GATEWAY_URL = "https://discord.com/api/v9/gateway";
// Páginas "trace" da Cloudflare: devolvem o IP com que a requisição chegou.
inline const char *TRACE_URL = "https://1.1.1.1/cdn-cgi/trace";
inline const char *FALLBACK_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace";

enum class LaunchTargetType {
  ChromiumBrowser, // Chrome, Brave, Edge, Chromium, Vivaldi
  Firefox,
  App              // qualquer outro executável, aberto sem argumentos extras
};

struct LaunchTarget {
  LaunchTargetType type = LaunchTargetType::ChromiumBrowser;
  std::string command;     // caminho do executável
  std::string displayName;
  std::string profileKey;  // sufixo da pasta de perfil dedicada
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

// Executa um programa diretamente (sem shell; args[0] é procurado no PATH),
// entrega stdinData pela entrada padrão e captura stdout+stderr linha a linha.
// Devolve o código de saída ou -1.
inline int runHelperCapture(
    const std::vector<std::string> &args,
    const std::string &stdinData,
    std::string &fullOutput,
    const std::function<void(const std::string&)> &onLine = nullptr) {
  // O conteúdo de stdin precisa caber no buffer do pipe (16 KiB no macOS).
  if (args.empty() || stdinData.size() > 8 * 1024) return -1;

  int inPipe[2] = {-1, -1};
  int outPipe[2] = {-1, -1};
  if (::pipe(inPipe) != 0) return -1;
  if (::pipe(outPipe) != 0) {
    ::close(inPipe[0]);
    ::close(inPipe[1]);
    return -1;
  }
  for (int fd : {inPipe[0], inPipe[1], outPipe[0], outPipe[1]}) {
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
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

// ---------------------------------------------------------------------------
// Localização do próprio executável e dos utilitários que o acompanham
// ---------------------------------------------------------------------------

inline std::string selfExecutablePath() {
  char buffer[PATH_MAX * 2];
#ifdef __APPLE__
  uint32_t size = sizeof(buffer);
  if (_NSGetExecutablePath(buffer, &size) != 0) return "";
#else
  ssize_t len = ::readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
  if (len <= 0) return "";
  buffer[len] = '\0';
#endif
  std::error_code ec;
  fs::path resolved = fs::canonical(buffer, ec);
  return ec ? std::string(buffer) : resolved.string();
}

// Pasta dos utilitários compilados para esta arquitetura de Mac.
inline const char *macHelperDirName() {
#if defined(__aarch64__) || defined(__arm64__)
  return "macos-arm64";
#else
  return "macos-amd64";
#endif
}

// Os utilitários (ardc-tunnel, nord-confgen, proton-confgen) não são embutidos
// no executável do macOS: ficam em bin/<arquitetura>/ ao lado dele.
inline std::string findMacHelper(const std::string &name) {
  const std::string archDir = macHelperDirName();
  std::vector<fs::path> dirs;
  std::string self = selfExecutablePath();
  if (!self.empty()) {
    fs::path selfDir = fs::path(self).parent_path();
    dirs.push_back(selfDir / "bin" / archDir);
    dirs.push_back(selfDir / "PC" / "bin" / archDir);
    dirs.push_back(selfDir.parent_path() / "bin" / archDir);
    dirs.push_back(selfDir);
  }
  dirs.push_back(fs::path("bin") / archDir);
  dirs.push_back(fs::path("PC") / "bin" / archDir);
  dirs.push_back(fs::path("..") / "bin" / archDir);

  std::error_code ec;
  for (const auto &dir : dirs) {
    fs::path candidate = dir / name;
    if (fs::is_regular_file(candidate, ec)) {
      fs::path absolute = fs::absolute(candidate, ec);
      return ec ? candidate.string() : absolute.string();
    }
  }
  return "";
}

inline std::string findProtonConfgen() { return findMacHelper("proton-confgen"); }
inline std::string findNordConfgen() { return findMacHelper("nord-confgen"); }
inline std::string findTunnelHelper() { return findMacHelper("ardc-tunnel"); }

// ---------------------------------------------------------------------------
// Perfil WireGuard: sessões salvas e geradores (ProtonVPN e NordVPN)
// ---------------------------------------------------------------------------

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

// Lê uma linha do terminal sem eco (senha ou token).
inline std::string promptHidden() {
  std::string value;
  int ignored = std::system("stty -echo");
  std::getline(std::cin, value);
  ignored = std::system("stty echo");
  (void)ignored;
  std::cout << "\n";
  return value;
}

inline std::string protonErrorMessage(const std::string &output) {
  auto has = [&output](const char *needle) { return output.find(needle) != std::string::npos; };
  if (has("code 8002") || has("password is not correct")) {
    return "Senha incorreta. Verifique suas credenciais Proton.";
  }
  if (has("code 9001") || has("human verification")) {
    return "A Proton solicitou verificação humana. Faça login pelo navegador uma vez.";
  }
  if (has("code 2001") || has("user does not exist")) {
    return "Usuário ou email Proton não encontrado.";
  }
  std::string cleanErr;
  std::stringstream ss(output);
  std::string line;
  while (std::getline(ss, line)) {
    if (line.rfind("Error: ", 0) == 0) cleanErr = trimWhitespace(line.substr(7));
  }
  return cleanErr.empty() ? "Falha na autenticação ou timeout da API Proton." : cleanErr;
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

  std::string confgen = findProtonConfgen();
  const std::vector<std::string> baseArgs = {confgen, "--free-only", "--countries", "US,NL,JP", "--output", "ardc_vpn.conf"};

  fs::path session = protonSessionPath();
  std::error_code ec;
  bool hasSession = !session.empty() && fs::is_regular_file(session, ec);
  if (hasSession && !confgen.empty() && !interactive && explicitUser.empty()) {
    std::string ignored;
    if (runHelperCapture(baseArgs, "", ignored) == 0 && fs::is_regular_file("ardc_vpn.conf")) {
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
    password = promptHidden();
    if (password.empty()) return false;
  }

  if (onProgress) onProgress("Iniciando handshake seguro via SRP na API Proton...");
  std::cout << "  Autenticando no Proton e gerando túnel WireGuard exclusivo..." << std::endl;

  std::vector<std::string> args = baseArgs;
  args.insert(args.begin() + 1, {"--username", username, "--password", password});

  std::string output;
  int ret = runHelperCapture(args, "", output, [&](const std::string &line) {
    std::cout << line << std::endl;
    if (!onProgress) return;
    std::string step = confgenProgressMessage(line);
    if (!step.empty()) onProgress(step);
  });

  if (ret != 0 || !fs::is_regular_file("ardc_vpn.conf")) {
    std::string err = protonErrorMessage(output);
    if (outErr) *outErr = err;
    std::cerr << "  \033[38;2;229;9;20m✖\033[0m " << err << "\n";
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

  std::string token = trimWhitespace(promptHidden());
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
    std::string ignored;
    int ret = runHelperCapture({confgen, "--free-only", "--countries", "US,NL,JP", "--output", "ardc_vpn.conf"}, "", ignored);
    return ret == 0 && fs::is_regular_file("ardc_vpn.conf");
  }
  return false;
}

// ---------------------------------------------------------------------------
// Túnel (ardc-tunnel) e processos tunelados
// ---------------------------------------------------------------------------

// Estado do túnel como o ardc-tunnel o informa ("status", sem privilégios).
inline std::map<std::string, std::string> tunnelStatus() {
  std::map<std::string, std::string> values;
  std::string helper = findTunnelHelper();
  if (helper.empty()) return values;

  std::string output;
  runHelperCapture({helper, "status"}, "", output);
  std::stringstream ss(output);
  std::string line;
  while (std::getline(ss, line)) {
    size_t eq = line.find('=');
    if (eq != std::string::npos) values[trimWhitespace(line.substr(0, eq))] = trimWhitespace(line.substr(eq + 1));
  }
  return values;
}

inline bool isTunnelRunning() {
  return tunnelStatus()["running"] == "1";
}

// Grupo unix sob o qual os processos tunelados rodam (0 se desconhecido).
inline unsigned long tunnelGroupId() {
  std::string helper = findTunnelHelper();
  if (helper.empty()) return 0;
  std::string output;
  if (runHelperCapture({helper, "gid"}, "", output) != 0) return 0;
  return std::strtoul(trimWhitespace(output).c_str(), nullptr, 10);
}

// Usuário real, mesmo quando o programa inteiro foi iniciado com sudo.
inline unsigned long realUserId() {
  uid_t uid = getuid();
  if (uid == 0) {
    const char *sudoUid = std::getenv("SUDO_UID");
    if (sudoUid && *sudoUid) return std::strtoul(sudoUid, nullptr, 10);
  }
  return uid;
}

inline bool checkPrerequisites(std::string &errorMessage) {
  std::ostringstream ss;
  if (findTunnelHelper().empty()) {
    ss << "Utilitário ardc-tunnel não encontrado. Ele deve ficar em bin/" << macHelperDirName()
       << "/ ao lado deste executável (ou em PC/bin/" << macHelperDirName() << "/).\n";
  }
  if (!haveCommand("curl")) {
    ss << "O comando curl não foi encontrado.\n";
  }
  if (realUserId() == 0) {
    ss << "Execute como seu usuário normal (não como root); o sudo é pedido quando necessário.\n";
  }
  errorMessage = trimWhitespace(ss.str());
  return errorMessage.empty();
}

// No macOS "Discord rodando" significa: há processos sob o grupo do túnel. O
// navegador e o Discord que o usuário abriu por conta própria nunca são tocados.
inline bool isDiscordRunning() {
  std::string helper = findTunnelHelper();
  if (helper.empty()) return false;
  std::string output;
  return runHelperCapture({helper, "pids"}, "", output) == 0;
}

inline bool isDiscordRunningInNetns() {
  auto status = tunnelStatus();
  return status["running"] == "1" && status["tunneled_processes"] != "0" && !status["tunneled_processes"].empty();
}

inline void killDiscord() {
  std::string helper = findTunnelHelper();
  if (helper.empty()) return;
  std::string output;
  runHelperCapture({helper, "kill"}, "", output);
}

inline bool stopBypass() {
  std::string helper = findTunnelHelper();
  if (helper.empty()) return false;
  // O "down" fecha os processos tunelados, encerra o túnel e remove as regras
  // do pf, inclusive o que tiver sobrado de uma execução interrompida.
  std::string output;
  int ret = runHelperCapture({"sudo", helper, "down"}, "", output);
  return ret == 0 && output.find("DOWN") != std::string::npos;
}

// ---------------------------------------------------------------------------
// Alvo de lançamento: navegador com perfil dedicado
// ---------------------------------------------------------------------------

struct BrowserCandidate {
  const char *bundle;
  const char *executable;
  const char *displayName;
  LaunchTargetType type;
  const char *profileKey;
};

// Safari e outros navegadores WebKit ficam de fora: a rede deles roda em
// processos do sistema que não herdam o grupo, então não podem ser tunelados.
inline const std::vector<BrowserCandidate> &browserCandidates() {
  static const std::vector<BrowserCandidate> candidates = {
      {"Google Chrome.app", "Google Chrome", "Google Chrome", LaunchTargetType::ChromiumBrowser, "chrome"},
      {"Brave Browser.app", "Brave Browser", "Brave", LaunchTargetType::ChromiumBrowser, "brave"},
      {"Microsoft Edge.app", "Microsoft Edge", "Microsoft Edge", LaunchTargetType::ChromiumBrowser, "edge"},
      {"Chromium.app", "Chromium", "Chromium", LaunchTargetType::ChromiumBrowser, "chromium"},
      {"Vivaldi.app", "Vivaldi", "Vivaldi", LaunchTargetType::ChromiumBrowser, "vivaldi"},
      {"Firefox.app", "firefox", "Firefox", LaunchTargetType::Firefox, "firefox"},
  };
  return candidates;
}

inline std::string lowerCase(std::string text) {
  for (char &c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return text;
}

// Executável principal de um pacote .app (Contents/MacOS/<CFBundleExecutable>).
inline std::string bundleExecutable(const fs::path &bundle) {
  std::error_code ec;
  fs::path macosDir = bundle / "Contents" / "MacOS";

  fs::path sameName = macosDir / bundle.stem();
  if (fs::is_regular_file(sameName, ec)) return sameName.string();

  std::string output;
  if (runHelperCapture({"/usr/bin/defaults", "read", (bundle / "Contents" / "Info").string(), "CFBundleExecutable"}, "", output) == 0) {
    fs::path named = macosDir / trimWhitespace(output);
    if (fs::is_regular_file(named, ec)) return named.string();
  }
  return "";
}

inline LaunchTarget classifyManualTarget(const std::string &executable, const std::string &label) {
  std::string lower = lowerCase(label + " " + fs::path(executable).filename().string());
  auto has = [&lower](const char *needle) { return lower.find(needle) != std::string::npos; };

  LaunchTarget target;
  target.command = executable;
  target.displayName = label + " (Caminho Manual)";
  if (has("firefox")) {
    target.type = LaunchTargetType::Firefox;
    target.profileKey = "firefox";
  } else if (has("chrom") || has("brave") || has("edge") || has("vivaldi")) {
    target.type = LaunchTargetType::ChromiumBrowser;
    target.profileKey = "custom";
  } else {
    target.type = LaunchTargetType::App;
  }
  return target;
}

inline LaunchTarget locateDiscordLaunchTarget(const std::string &manualPath = "") {
  std::error_code ec;

  if (!manualPath.empty()) {
    fs::path manual(manualPath);
    // "/Applications/Foo.app/" com barra final tem filename vazio
    if (!manual.has_filename()) manual = manual.parent_path();
    if (fs::is_directory(manual, ec) && manual.extension() == ".app") {
      std::string exe = bundleExecutable(manual);
      if (exe.empty()) return {};
      return classifyManualTarget(exe, manual.stem().string());
    }
    if (fs::is_regular_file(manual, ec)) {
      fs::path absolute = fs::absolute(manual, ec);
      return classifyManualTarget(ec ? manual.string() : absolute.string(), manual.filename().string());
    }
    return {};
  }

  std::vector<fs::path> appDirs = {"/Applications"};
  const char *home = std::getenv("HOME");
  if (home && *home) appDirs.push_back(fs::path(home) / "Applications");

  for (const auto &candidate : browserCandidates()) {
    for (const auto &dir : appDirs) {
      fs::path exe = dir / candidate.bundle / "Contents" / "MacOS" / candidate.executable;
      if (fs::is_regular_file(exe, ec)) {
        return {candidate.type, exe.string(), candidate.displayName, candidate.profileKey};
      }
    }
  }
  return {};
}

// Pasta do perfil dedicado do navegador tunelado. Um perfil à parte faz o
// navegador abrir como instância separada mesmo que o do usuário já esteja
// aberto (que continua fora do túnel), e guarda o login do Discord.
inline std::string browserProfileDir(const LaunchTarget &target) {
  const char *home = std::getenv("HOME");
  fs::path base = (home && *home) ? fs::path(home) : fs::path("/tmp");
  return (base / "Library" / "Application Support" / "ARDiscordBypass" / ("Browser-" + target.profileKey)).string();
}

inline std::vector<std::string> launchArguments(const LaunchTarget &target) {
  std::vector<std::string> args = {target.command};
  if (target.type == LaunchTargetType::ChromiumBrowser) {
    args.push_back("--user-data-dir=" + browserProfileDir(target));
    args.push_back("--no-first-run");
    args.push_back("--no-default-browser-check");
    // Sem o resolvedor DNS próprio do Chrome, que falaria direto com o servidor
    // DNS da rede: pelo túnel esse servidor costuma recusar a consulta, e cada
    // nome só resolveria depois de um timeout. Fica valendo o DNS do sistema.
    args.push_back("--disable-features=AsyncDns");
    // Janela de aplicativo, sem abas nem barra de endereço: só o Discord.
    args.push_back(std::string("--app=") + DISCORD_WEB_URL);
  } else if (target.type == LaunchTargetType::Firefox) {
    args.push_back("-profile");
    args.push_back(browserProfileDir(target));
    args.push_back("-no-remote");
    args.push_back("-new-instance");
    args.push_back(DISCORD_WEB_URL);
  }
  return args;
}

// ---------------------------------------------------------------------------
// Lançamento sob o grupo do túnel (--internal-launch)
// ---------------------------------------------------------------------------

// Substitui o processo atual pelo programa pedido. Com disclaim, o programa
// passa a responder por si mesmo perante o macOS: sem isso os pedidos de
// microfone, câmera e gravação de tela do navegador seriam atribuídos ao
// Terminal (o "processo responsável" de tudo o que ele inicia).
inline void execProgram(char *const args[], bool disclaim) {
#ifdef __APPLE__
  posix_spawnattr_t attr;
  if (posix_spawnattr_init(&attr) == 0) {
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
    if (disclaim) {
      // Exportada pela libSystem desde o macOS 10.14, mas declarada apenas em
      // cabeçalho privado; procurada em tempo de execução para o programa
      // continuar funcionando se ela deixar de existir.
      using DisclaimFn = int (*)(posix_spawnattr_t *, int);
      auto setDisclaim = reinterpret_cast<DisclaimFn>(dlsym(RTLD_DEFAULT, "responsibility_spawnattrs_setdisclaim"));
      if (setDisclaim) setDisclaim(&attr, 1);
    }
    // Com POSIX_SPAWN_SETEXEC só retorna em caso de erro.
    posix_spawn(nullptr, args[0], nullptr, &attr, args, environ);
    posix_spawnattr_destroy(&attr);
  }
#else
  (void)disclaim;
#endif
  execv(args[0], args);
}

// Ponto de entrada interno, sempre chamado via sudo por este mesmo programa:
//   <exe> --internal-launch <uid> <gid> <attach|detach> -- <programa> [args...]
// Troca o grupo do processo pelo grupo do túnel, devolve os privilégios ao
// usuário <uid> e executa o programa. "detach" é para o navegador (sessão
// própria, sem terminal); "attach" é para comandos cuja saída quem chamou lê.
inline int internalLaunchMain(int argc, char *argv[]) {
  if (argc < 7 || std::string(argv[5]) != "--") {
    std::fprintf(stderr, "uso interno incorreto de --internal-launch\n");
    return 64;
  }
  if (geteuid() != 0) {
    std::fprintf(stderr, "--internal-launch precisa de root (sudo)\n");
    return 77;
  }

  const uid_t uid = static_cast<uid_t>(std::strtoul(argv[2], nullptr, 10));
  const gid_t tunnelGid = static_cast<gid_t>(std::strtoul(argv[3], nullptr, 10));
  const std::string mode = argv[4];
  if (uid == 0 || tunnelGid == 0 || (mode != "attach" && mode != "detach")) return 64;

  struct passwd *pw = getpwuid(uid);
  if (!pw) return 67;
  const std::string userName = pw->pw_name;
  const std::string home = pw->pw_dir;
  const std::string shell = pw->pw_shell;
  const gid_t primaryGid = pw->pw_gid;

  // O grupo do túnel vai na frente: no macOS o grupo efetivo é o primeiro da
  // lista, e é ele que o pf compara. Os demais grupos do usuário são mantidos
  // até o limite do sistema (16).
#ifdef __APPLE__
  using GroupListItem = int;
#else
  using GroupListItem = gid_t;
#endif
  std::vector<gid_t> groups = {tunnelGid, primaryGid};
  {
    std::vector<GroupListItem> memberOf(64);
    int count = static_cast<int>(memberOf.size());
    if (getgrouplist(userName.c_str(), static_cast<GroupListItem>(primaryGid), memberOf.data(), &count) >= 0) {
      for (int i = 0; i < count && groups.size() < 16; ++i) {
        gid_t g = static_cast<gid_t>(memberOf[i]);
        if (std::find(groups.begin(), groups.end(), g) == groups.end()) groups.push_back(g);
      }
    }
  }
  if (setgroups(static_cast<int>(groups.size()), groups.data()) != 0) {
    groups.resize(2);
    if (setgroups(2, groups.data()) != 0) return 71;
  }
  if (setgid(tunnelGid) != 0 || setuid(uid) != 0) return 71;
  // Nada deve continuar se o grupo não pegou ou se ainda der para voltar a root.
  if (getuid() != uid || geteuid() != uid || getgid() != tunnelGid || getegid() != tunnelGid || setuid(0) == 0) {
    return 71;
  }

  setenv("HOME", home.c_str(), 1);
  setenv("USER", userName.c_str(), 1);
  setenv("LOGNAME", userName.c_str(), 1);
  if (!shell.empty()) setenv("SHELL", shell.c_str(), 1);
  // __CFBundleIdentifier e XPC_* vêm do Terminal e fariam o aplicativo aberto
  // se apresentar ao sistema com a identidade dele.
  for (const char *name : {"SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND", "MAIL",
                           "__CFBundleIdentifier", "XPC_SERVICE_NAME", "XPC_FLAGS"}) {
    unsetenv(name);
  }
  if (chdir(home.c_str()) != 0 && chdir("/") != 0) return 71;

  char **program = argv + 6;

  if (mode == "attach") {
    execProgram(program, false);
    std::fprintf(stderr, "%s: %s\n", program[0], std::strerror(errno));
    return 126;
  }

  // detach: o filho avisa por um pipe (fechado sozinho no exec) se não
  // conseguiu executar o programa; fim de arquivo significa que executou.
  int report[2];
  if (pipe(report) != 0) return 71;
  fcntl(report[0], F_SETFD, FD_CLOEXEC);
  fcntl(report[1], F_SETFD, FD_CLOEXEC);

  pid_t child = fork();
  if (child < 0) return 71;
  if (child == 0) {
    close(report[0]);
    setsid();
    int devNull = open("/dev/null", O_RDWR);
    if (devNull >= 0) {
      dup2(devNull, STDIN_FILENO);
      dup2(devNull, STDOUT_FILENO);
      dup2(devNull, STDERR_FILENO);
      if (devNull > STDERR_FILENO) close(devNull);
    }
    execProgram(program, true);
    int err = errno;
    ssize_t ignored = write(report[1], &err, sizeof(err));
    (void)ignored;
    _exit(126);
  }

  close(report[1]);
  int err = 0;
  ssize_t got;
  do {
    got = read(report[0], &err, sizeof(err));
  } while (got < 0 && errno == EINTR);
  close(report[0]);
  if (got > 0) {
    std::fprintf(stderr, "%s: %s\n", program[0], std::strerror(err));
    return 126;
  }
  return 0;
}

// Executa um comando sob o grupo do túnel e captura a saída.
inline int runInTunnel(const std::vector<std::string> &command, std::string &output, unsigned long gid) {
  std::string self = selfExecutablePath();
  if (self.empty() || gid == 0) return -1;
  std::vector<std::string> args = {"sudo", self, "--internal-launch",
                                   std::to_string(realUserId()), std::to_string(gid), "attach", "--"};
  args.insert(args.end(), command.begin(), command.end());
  return runHelperCapture(args, "", output);
}

// Valor de uma linha "chave=valor" da saída do /cdn-cgi/trace.
inline std::string traceField(const std::string &trace, const std::string &key) {
  std::stringstream ss(trace);
  std::string line;
  while (std::getline(ss, line)) {
    if (line.rfind(key + "=", 0) == 0) return trimWhitespace(line.substr(key.size() + 1));
  }
  return "";
}

// Busca uma URL pela rede normal ou, com throughTunnel, por um processo do
// grupo do túnel (o mesmo caminho que o navegador vai usar).
inline std::string fetchUrl(const char *url, bool throughTunnel, unsigned long gid) {
  const std::vector<std::string> curl = {"/usr/bin/curl", "-4", "-s", "-m", "6", url};
  std::string output;
  if (throughTunnel) {
    runInTunnel(curl, output, gid);
  } else {
    runHelperCapture(curl, "", output);
  }
  return output;
}

// Saída do /cdn-cgi/trace (IP de saída, país), pela primeira página que responder.
inline std::string fetchTrace(bool throughTunnel, unsigned long gid) {
  std::string trace = fetchUrl(TRACE_URL, throughTunnel, gid);
  if (traceField(trace, "ip").empty()) trace = fetchUrl(FALLBACK_TRACE_URL, throughTunnel, gid);
  return traceField(trace, "ip").empty() ? std::string() : trace;
}

enum class TunnelCheck {
  Ok,
  NoConnectivity, // o Discord não responde pelo túnel (servidor ou perfil com problema)
  NotTunneled     // o tráfego do grupo saiu pela rede normal: o pf não desviou
};

// Confere, com o mesmo mecanismo que o navegador vai usar, que um processo do
// grupo alcança o Discord e que sai pela VPN. Num namespace de rede não haveria
// como vazar, mas aqui uma regra do pf que não case deixaria o tráfego seguir
// pela rede normal sem nenhum erro; por isso o IP de saída é comparado com o da
// rede normal (ou, se não der para saber os dois, vale o contador de pacotes
// que o ardc-tunnel reescreveu).
inline TunnelCheck checkTunnel(unsigned long gid) {
  bool reachable = false;
  for (int attempt = 0; attempt < 2 && !reachable; ++attempt) {
    reachable = fetchUrl(DISCORD_GATEWAY_URL, true, gid).find("gateway") != std::string::npos;
  }
  if (!reachable) return TunnelCheck::NoConnectivity;

  std::string tunneled = traceField(fetchTrace(true, gid), "ip");
  std::string direct = traceField(fetchTrace(false, gid), "ip");
  if (!tunneled.empty() && !direct.empty()) {
    return tunneled == direct ? TunnelCheck::NotTunneled : TunnelCheck::Ok;
  }

  // O ardc-tunnel atualiza os contadores a cada 3 segundos.
  for (int i = 0; i < 8; ++i) {
    std::string rewritten = tunnelStatus()["nat_out"];
    if (!rewritten.empty() && rewritten != "0") return TunnelCheck::Ok;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  return TunnelCheck::NotTunneled;
}

inline std::string tunnelErrorMessage(const std::string &output) {
  auto has = [&output](const char *needle) { return output.find(needle) != std::string::npos; };

  if (has("no WireGuard handshake")) {
    return "O servidor WireGuard não respondeu (sem handshake). Verifique a internet, se a rede bloqueia UDP, ou gere um novo perfil.";
  }
  if (has("has no anchor")) {
    return "O firewall pf do macOS está com as regras substituídas por outro programa (sem a âncora com.apple/*); o túnel não teria efeito.";
  }
  if (has("pf refused the rules") || has("could not enable pf") || has("anchor is empty")) {
    return "O firewall pf do macOS não aceitou as regras do túnel. Rode com --diag e envie a saída.";
  }
  if (has("could not create the tunnel interface")) {
    return "Não foi possível criar a interface utun do túnel.";
  }
  if (has("profile has no") || has("invalid ")) {
    return "O perfil WireGuard (.conf) está incompleto ou inválido.";
  }

  std::string cleanErr;
  std::stringstream ss(output);
  std::string line;
  while (std::getline(ss, line)) {
    if (line.rfind("Error: ", 0) == 0) cleanErr = trimWhitespace(line.substr(7));
  }
  return cleanErr.empty() ? "Falha ao iniciar o utilitário ardc-tunnel." : cleanErr;
}

// Sobe o túnel com o perfil dado e confere que ele funciona de ponta a ponta.
inline bool startTunnel(const std::string &confPath, std::string *outDetail, bool *retryWithNewProfile) {
  if (retryWithNewProfile) *retryWithNewProfile = false;

  std::string helper = findTunnelHelper();
  if (helper.empty()) {
    if (outDetail) *outDetail = "Utilitário ardc-tunnel não encontrado.";
    return false;
  }

  std::error_code ec;
  fs::path absolute = fs::absolute(confPath, ec);
  std::string output;
  int ret = runHelperCapture({"sudo", helper, "up", "--conf", ec ? confPath : absolute.string()}, "", output);

  unsigned long gid = 0;
  {
    std::stringstream ss(output);
    std::string line;
    while (std::getline(ss, line)) {
      if (line.rfind("READY ", 0) != 0) continue;
      std::stringstream fields(line.substr(6));
      std::string field;
      while (fields >> field) {
        if (field.rfind("gid=", 0) == 0) gid = std::strtoul(field.c_str() + 4, nullptr, 10);
      }
    }
  }
  if (ret != 0 || gid == 0) {
    if (outDetail) *outDetail = tunnelErrorMessage(output);
    // Um servidor que não responde pode ter saído do ar: vale tentar outro.
    if (retryWithNewProfile) *retryWithNewProfile = output.find("no WireGuard handshake") != std::string::npos;
    return false;
  }

  switch (checkTunnel(gid)) {
    case TunnelCheck::Ok:
      return true;
    case TunnelCheck::NotTunneled:
      if (outDetail) {
        *outDetail = "O túnel subiu, mas o tráfego do grupo de teste saiu pela rede normal: o pf não desviou os pacotes. "
                     "Nada foi aberto. Rode com --diag e envie a saída.";
      }
      return false;
    case TunnelCheck::NoConnectivity:
      if (outDetail) *outDetail = "O túnel subiu, mas o Discord não respondeu através dele. Rode com --diag para ver os detalhes.";
      if (retryWithNewProfile) *retryWithNewProfile = true;
      return false;
  }
  return false;
}

// Mesmo papel do ensureWireGuardNetns do Linux (o nome é mantido porque o
// fluxo em main.cpp é compartilhado): deixa o túnel pronto para o lançamento.
inline bool ensureWireGuardNetns(const std::string &confPath = "ardc_vpn.conf", std::string *outDetail = nullptr) {
  const bool isDefault = confPath == "ardc_vpn.conf";

  if (!fs::is_regular_file(confPath)) {
    // Perfil padrão ausente: recria pela sessão salva (ProtonVPN ou NordVPN)
    if (!isDefault || !renewDefaultProfile(savedSessionProvider())) {
      if (outDetail) *outDetail = "Perfil WireGuard não encontrado: " + confPath;
      return false;
    }
  }

  bool retry = false;
  if (startTunnel(confPath, outDetail, &retry)) return true;

  // Auto-recuperação: se o servidor do perfil não responde, renova o perfil
  // pelo provedor que o gerou. Perfis sem cabeçalho de gerador foram trazidos
  // pelo usuário e não são sobrescritos.
  if (retry && isDefault && renewDefaultProfile(detectConfProvider("ardc_vpn.conf"))) {
    if (startTunnel("ardc_vpn.conf", outDetail, nullptr)) return true;
  }

  // Não deixa para trás um túnel que não serve para nada.
  stopBypass();
  return false;
}

inline bool launchDiscord(const LaunchTarget &target) {
  std::string self = selfExecutablePath();
  unsigned long gid = tunnelGroupId();
  if (self.empty() || gid == 0 || target.command.empty()) return false;

  if (target.type != LaunchTargetType::App) {
    std::error_code ec;
    fs::create_directories(browserProfileDir(target), ec);
  }

  std::vector<std::string> args = {"sudo", self, "--internal-launch",
                                   std::to_string(realUserId()), std::to_string(gid), "detach", "--"};
  std::vector<std::string> program = launchArguments(target);
  args.insert(args.end(), program.begin(), program.end());

  std::string output;
  if (runHelperCapture(args, "", output) != 0) return false;

  // O navegador leva alguns segundos para aparecer; espera até 12.
  for (int i = 0; i < 24; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    if (isDiscordRunning()) return true;
  }
  return false;
}

// --diag: reúne o estado do túnel para investigar uma falha.
inline int runDiagnostics() {
  std::cout << "ARDiscordBypass (macOS) - diagnóstico\n";
  std::cout << "executável: " << selfExecutablePath() << "\n";
  std::string helper = findTunnelHelper();
  std::cout << "ardc-tunnel: " << (helper.empty() ? "(não encontrado)" : helper) << "\n";
  LaunchTarget target = locateDiscordLaunchTarget();
  std::cout << "navegador: " << (target.command.empty() ? "(nenhum compatível encontrado)" : target.command) << "\n";
  if (helper.empty()) return 1;

  // Pede a senha do sudo (se preciso) antes de capturar a saída dos comandos.
  std::cout.flush();
  if (std::system("sudo true") != 0) {
    std::cout << "sudo indisponível; o diagnóstico do sistema precisa dele.\n";
    return 1;
  }

  std::string output;
  runHelperCapture({"sudo", helper, "diag"}, "", output);
  std::cout << output;

  unsigned long gid = tunnelGroupId();
  std::cout << "\n--- identidade de um processo aberto pelo lançador (grupo " << gid << ")\n";
  output.clear();
  runInTunnel({"/usr/bin/id"}, output, gid);
  std::cout << output;

  auto summary = [](const std::string &trace) {
    if (trace.empty()) return std::string("(sem resposta)");
    return "ip=" + traceField(trace, "ip") + " loc=" + traceField(trace, "loc") + " colo=" + traceField(trace, "colo");
  };
  std::cout << "\n--- saída para a internet\n";
  std::cout << "rede normal:    " << summary(fetchTrace(false, gid)) << "\n";
  std::cout << "grupo do túnel: " << summary(fetchTrace(true, gid)) << "\n";
  std::string gateway = trimWhitespace(fetchUrl(DISCORD_GATEWAY_URL, true, gid));
  std::cout << "Discord pelo grupo do túnel: " << (gateway.empty() ? "(sem resposta)" : gateway) << "\n";
  std::cout << "(com o túnel ativo os dois IPs devem ser diferentes; com ele parado o grupo sai igual à rede normal,\n"
               " ou fica sem resposta se ainda houver um aplicativo do túnel aberto)\n";
  return 0;
}

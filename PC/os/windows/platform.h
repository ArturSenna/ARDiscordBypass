#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <shellapi.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <functional>

#include "../../core/provider.h"

namespace fs = std::filesystem;

inline const std::string WG_CONFIG_NAME = "ardiscord-vpn.conf";

inline std::string runCommand(const std::string &cmd) {
  std::string result;
  FILE *pipe = _popen(cmd.c_str(), "r");
  if (!pipe)
    return "";
  char buffer[256];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    result += buffer;
  _pclose(pipe);
  while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
    result.pop_back();
  return result;
}

inline bool isDiscordRunning() {
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE)
    return false;

  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);

  bool running = false;
  if (Process32FirstW(hSnap, &pe)) {
    do {
      std::wstring name(pe.szExeFile);
      if (_wcsicmp(pe.szExeFile, L"Discord.exe") == 0 ||
          _wcsicmp(pe.szExeFile, L"DiscordCanary.exe") == 0 ||
          _wcsicmp(pe.szExeFile, L"DiscordPTB.exe") == 0 ||
          _wcsicmp(pe.szExeFile, L"Vesktop.exe") == 0) {
        running = true;
        break;
      }
    } while (Process32NextW(hSnap, &pe));
  }

  CloseHandle(hSnap);
  return running;
}

inline void killDiscord() {
  // Encerramento forçado e da árvore de processos no Windows
  _wsystem(L"taskkill /F /IM Discord.exe /T >nul 2>&1");
  _wsystem(L"taskkill /F /IM DiscordCanary.exe /T >nul 2>&1");
  _wsystem(L"taskkill /F /IM DiscordPTB.exe /T >nul 2>&1");
  _wsystem(L"taskkill /F /IM Vesktop.exe /T >nul 2>&1");

  for (int i = 0; i < 10; ++i) {
    if (!isDiscordRunning())
      return;
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

inline bool stopBypass() {
  killDiscord();

  // Encerra processo do WireSock se ativo
  _wsystem(L"taskkill /F /IM wiresock-client.exe >nul 2>&1");

  // Remove arquivo temporário de configuração com as diretivas WFP
  fs::path confPath = fs::temp_directory_path() / WG_CONFIG_NAME;
  std::error_code ec;
  fs::remove(confPath, ec);

  // Limpa travas singleton do Electron/Chromium
  wchar_t appData[MAX_PATH];
  if (GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH) != 0) {
    fs::path base(appData);
    const std::vector<std::wstring> cfgs = {L"discord", L"discordcanary", L"discordptb", L"vesktop"};
    for (const auto &cfg : cfgs) {
      fs::remove(base / cfg / L"SingletonLock", ec);
      fs::remove(base / cfg / L"SingletonCookie", ec);
      fs::remove(base / cfg / L"SingletonSocket", ec);
    }
  }

  return true;
}

inline std::wstring findDiscordExeIn(const std::wstring &basePath) {
  const std::vector<std::pair<std::wstring, std::wstring>> apps = {
      {L"\\Discord", L"Discord.exe"},
      {L"\\DiscordCanary", L"DiscordCanary.exe"},
      {L"\\DiscordPTB", L"DiscordPTB.exe"},
      {L"\\Programs\\vesktop", L"Vesktop.exe"},
      {L"\\Vesktop", L"Vesktop.exe"}
  };

  for (const auto &app : apps) {
    std::wstring root = basePath + app.first;
    if (!fs::exists(root))
      continue;

    // Se houver executável diretamente na pasta raiz
    if (fs::is_regular_file(fs::path(root) / app.second)) {
      return (fs::path(root) / app.second).wstring();
    }

    // Se estiver em subpasta versionada app-x.x.xxxx (formato Squirrel padrão)
    std::wstring latestPath;
    std::wstring latestVersion;
    try {
      for (const auto &entry : fs::directory_iterator(root)) {
        if (!entry.is_directory())
          continue;
        std::wstring folder = entry.path().filename().wstring();
        if (folder.rfind(L"app-", 0) != 0)
          continue;
        std::wstring exePath = (entry.path() / app.second).wstring();
        if (fs::exists(exePath)) {
          if (latestVersion.empty() || folder > latestVersion) {
            latestVersion = folder;
            latestPath = exePath;
          }
        }
      }
    } catch (...) {}
    if (!latestPath.empty())
      return latestPath;
  }

  return L"";
}

inline std::wstring locateDiscordExe() {
  wchar_t pathBuf[MAX_PATH];
  if (GetEnvironmentVariableW(L"LOCALAPPDATA", pathBuf, MAX_PATH) != 0) {
    std::wstring result = findDiscordExeIn(std::wstring(pathBuf));
    if (!result.empty())
      return result;
  }
  if (GetEnvironmentVariableW(L"ProgramFiles", pathBuf, MAX_PATH) != 0) {
    std::wstring result = findDiscordExeIn(std::wstring(pathBuf));
    if (!result.empty())
      return result;
  }
  if (GetEnvironmentVariableW(L"ProgramFiles(x86)", pathBuf, MAX_PATH) != 0) {
    std::wstring result = findDiscordExeIn(std::wstring(pathBuf));
    if (!result.empty())
      return result;
  }

  // Fallback: se executado como Administrador ou outro perfil, procurar nas pastas C:\Users\*\AppData\Local
  try {
    fs::path usersDir = L"C:\\Users";
    if (fs::exists(usersDir)) {
      for (const auto &entry : fs::directory_iterator(usersDir)) {
        if (!entry.is_directory())
          continue;
        fs::path localApp = entry.path() / L"AppData" / L"Local";
        if (fs::exists(localApp)) {
          std::wstring result = findDiscordExeIn(localApp.wstring());
          if (!result.empty())
            return result;
        }
      }
    }
  } catch (...) {}

  return L"";
}

inline std::wstring findWireSockExecutable() {
  // 1. Verificar pasta do próprio executável
  wchar_t modulePath[MAX_PATH];
  if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) != 0) {
    fs::path dir = fs::path(modulePath).parent_path();
    if (fs::exists(dir / L"wiresock-client.exe"))
      return (dir / L"wiresock-client.exe").wstring();
    if (fs::exists(dir / L"bin" / L"wiresock-client.exe"))
      return (dir / L"bin" / L"wiresock-client.exe").wstring();
  }

  // 2. Verificar Program Files
  const std::vector<std::wstring> candidates = {
      L"C:\\Program Files\\WireSock Secure Connect\\wiresock-client.exe",
      L"C:\\Program Files\\WireSock Secure Connect\\sdk\\wiresock-client.exe",
      L"C:\\Program Files (x86)\\WireSock Secure Connect\\wiresock-client.exe",
      L"C:\\Program Files (x86)\\WireSock Secure Connect\\sdk\\wiresock-client.exe"
  };

  for (const auto &cand : candidates) {
    if (fs::exists(cand))
      return cand;
  }

  // 3. Verificar via PATH
  std::string whereOut = runCommand("where wiresock-client.exe 2>nul");
  if (!whereOut.empty()) {
    std::wstring wWhere(whereOut.begin(), whereOut.end());
    if (fs::exists(wWhere))
      return wWhere;
  }

  return L"";
}

inline bool ensureWireSockInstalled() {
  std::wstring wsExe = findWireSockExecutable();
  if (!wsExe.empty())
    return true;

  std::cout << std::endl;
  std::cout << "\033[36m[INFO]\033[0m WireSock WFP Driver não encontrado no seu Windows." << std::endl;
  std::cout << "\033[36m[INFO]\033[0m Baixando e configurando automaticamente a dependência para o programa funcionar..." << std::endl;
  std::cout << "\033[33m[AVISO]\033[0m Caso o Windows solicite permissão de Administrador (UAC), clique em \"Sim\" para autorizar o driver de rede." << std::endl;

  // Tenta instalar via winget silenciosamente primeiro
  int wingetRet = _wsystem(L"powershell -NoProfile -ExecutionPolicy Bypass -Command "
                           L"\"Start-Process winget -ArgumentList 'install -e --id WireSock.WireSockSecureConnectSDK --silent --accept-source-agreements --accept-package-agreements' -Wait -Verb RunAs\" >nul 2>&1");

  if (wingetRet == 0 && !findWireSockExecutable().empty()) {
    std::cout << "\033[32m[ ✔ ] Dependência WireSock instalada com sucesso!\033[0m" << std::endl << std::endl;
    return true;
  }

  // Fallback: download direto do instalador oficial do WireSock SDK
  std::wstring tempInstaller = fs::temp_directory_path() / L"wiresock-sdk.exe";
  std::wstring dlCmd = L"powershell -NoProfile -ExecutionPolicy Bypass -Command \""
                       L"Invoke-WebRequest -Uri 'https://wiresock.net/_api/download-release.php?product=wiresock-secure-connect-sdk&platform=x64&version=3.4.8.1&channel=winget' -OutFile '" +
                       tempInstaller + L"'; "
                       L"Start-Process -FilePath '" + tempInstaller + L"' -ArgumentList @('/quiet','/norestart') -Wait -Verb RunAs\"";

  _wsystem(dlCmd.c_str());

  bool ok = !findWireSockExecutable().empty();
  if (ok) {
    std::cout << "\033[32m[ ✔ ] Dependência WireSock instalada e configurada com sucesso!\033[0m" << std::endl << std::endl;
  }
  return ok;
}

inline bool isWireSockRunning() {
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE)
    return false;

  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);

  bool running = false;
  if (Process32FirstW(hSnap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, L"wiresock-client.exe") == 0) {
        running = true;
        break;
      }
    } while (Process32NextW(hSnap, &pe));
  }

  CloseHandle(hSnap);
  return running;
}

#ifdef _WIN32
extern "C" const char _binary_proton_confgen_exe_start[];
extern "C" const char _binary_proton_confgen_exe_end[];

inline std::wstring extractEmbeddedProtonConfgenExe() {
  size_t size = _binary_proton_confgen_exe_end - _binary_proton_confgen_exe_start;
  if (size == 0) return L"";

  wchar_t localApp[MAX_PATH];
  std::wstring targetDir = L"";
  if (GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH) != 0) {
    targetDir = std::wstring(localApp) + L"\\ARDiscordBypass";
  } else {
    wchar_t userProfile[MAX_PATH];
    if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH) != 0) {
      targetDir = std::wstring(userProfile) + L"\\ARDiscordBypass";
    }
  }
  if (targetDir.empty()) return L"";

  std::error_code ec;
  fs::create_directories(targetDir, ec);
  std::wstring outPath = targetDir + L"\\proton-confgen.exe";

  if (fs::exists(outPath) && fs::file_size(outPath) == size) {
    return outPath;
  }

  std::ofstream out(fs::path(outPath), std::ios::binary);
  if (!out.is_open()) return L"";
  out.write(_binary_proton_confgen_exe_start, size);
  out.close();

  return fs::exists(outPath) ? outPath : L"";
}
#endif

inline std::wstring findProtonConfgenExe() {
  wchar_t modulePath[MAX_PATH];
  std::vector<std::wstring> candidates = {
      L"bin\\proton-confgen.exe",
      L"PC\\bin\\proton-confgen.exe",
      L"proton-confgen.exe"
  };
  if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) != 0) {
    fs::path dir = fs::path(modulePath).parent_path();
    candidates.insert(candidates.begin(), (dir / L"bin" / L"proton-confgen.exe").wstring());
    candidates.insert(candidates.begin(), (dir / L"proton-confgen.exe").wstring());
  }

  wchar_t userProfile[MAX_PATH];
  if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH) != 0) {
    candidates.push_back(std::wstring(userProfile) + L"\\ARDiscordBypass\\proton-confgen.exe");
    candidates.push_back(std::wstring(userProfile) + L"\\Documents\\proton-confgen.exe");
  }

  wchar_t localApp[MAX_PATH];
  if (GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH) != 0) {
    candidates.push_back(std::wstring(localApp) + L"\\ARDiscordBypass\\proton-confgen.exe");
  }

  for (const auto &cand : candidates) {
    if (fs::exists(cand) && fs::is_regular_file(cand)) return cand;
  }

#ifdef _WIN32
  return extractEmbeddedProtonConfgenExe();
#else
  return L"";
#endif
}

inline std::string getVpnConfigPath() {
  if (fs::is_regular_file("ardc_vpn.conf")) {
    return "ardc_vpn.conf";
  }
  wchar_t modulePath[MAX_PATH];
  if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) != 0) {
    fs::path appDir = fs::path(modulePath).parent_path();
    fs::path appConf = appDir / "ardc_vpn.conf";
    if (fs::is_regular_file(appConf)) return appConf.string();
  }
  wchar_t localApp[MAX_PATH];
  if (GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH) != 0) {
    fs::path localConf = fs::path(localApp) / "ARDiscordBypass" / "ardc_vpn.conf";
    if (fs::is_regular_file(localConf)) return localConf.string();
  }
  if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) != 0) {
    fs::path appDir = fs::path(modulePath).parent_path();
    try {
      fs::path testFile = appDir / ".ar_perm_test";
      std::ofstream test(testFile);
      if (test.is_open()) {
        test.close();
        fs::remove(testFile);
        return (appDir / "ardc_vpn.conf").string();
      }
    } catch (...) {}
  }
  if (GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH) != 0) {
    fs::path dir = fs::path(localApp) / "ARDiscordBypass";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return (dir / "ardc_vpn.conf").string();
  }
  return "ardc_vpn.conf";
}

inline bool setupProtonConfigWindows(
    bool interactive = false,
    const std::string &explicitUser = "",
    const std::string &explicitPass = "",
    std::string *outErr = nullptr,
    std::function<void(const std::string&)> onProgress = nullptr) {

  std::string targetConf = getVpnConfigPath();
  if (fs::is_regular_file(targetConf) && !interactive && explicitUser.empty()) {
    return true;
  }

  std::wstring confgen = findProtonConfgenExe();

  wchar_t userProfile[MAX_PATH];
  std::wstring sessionPath = L"";
  if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH) != 0) {
    sessionPath = std::wstring(userProfile) + L"\\.protonvpn-session.json";
  }

  auto escapeWinArg = [](const std::string &s) -> std::wstring {
    std::wstring out;
    for (char c : s) {
      if (c == '"') out += L"\\\"";
      else out += static_cast<wchar_t>(static_cast<unsigned char>(c));
    }
    return out;
  };

  bool hasSession = !sessionPath.empty() && fs::exists(sessionPath);
  if (hasSession && !confgen.empty() && !interactive && explicitUser.empty()) {
    std::wstring cmdLine = L"\"" + confgen + L"\" --free-only --countries US,NL,JP --output \"" + escapeWinArg(targetConf) + L"\"";
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
      WaitForSingleObject(pi.hProcess, 30000);
      DWORD code = 1;
      GetExitCodeProcess(pi.hProcess, &code);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
      if (code == 0 && fs::is_regular_file(targetConf)) {
        return true;
      }
    }
  }

  if (confgen.empty()) {
    std::string msg = "Utilitario proton-confgen.exe nao encontrado.";
    if (outErr) *outErr = msg;
    if (onProgress) onProgress(msg);
    std::wcerr << L"  \033[31m✖\033[0m " << std::wstring(msg.begin(), msg.end()) << L"\n";
    return false;
  }

  std::string username = explicitUser;
  std::string password = explicitPass;

  if (username.empty() || password.empty()) {
    std::cout << "\n  \033[33m\033[1m[ Configuracao do Tunel WireGuard (ProtonVPN Free / Plus) ]\033[0m\n";
    std::cout << "  Para gerar seu tunel exclusivo (sem risco de colisao de IP ou vazamento de chaves):\n";
    std::cout << "  Email ProtonVPN: ";
    std::cout.flush();
    std::getline(std::cin, username);
    if (username.empty()) return false;

    std::cout << "  Senha ProtonVPN: ";
    std::cout.flush();
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    std::getline(std::cin, password);
    SetConsoleMode(hStdin, mode);
    std::cout << "\n";

    if (password.empty()) return false;
  }

  if (onProgress) onProgress("Iniciando handshake seguro via SRP na API Proton...");
  std::cout << "  Autenticando no Proton e gerando tunel WireGuard exclusivo..." << std::endl;

  std::wstring cmdLine = L"\"" + confgen + L"\" --username \"" + escapeWinArg(username) +
                         L"\" --password \"" + escapeWinArg(password) +
                         L"\" --free-only --countries US,NL,JP --output \"" +
                         escapeWinArg(targetConf) + L"\"";

  SECURITY_ATTRIBUTES sa;
  ZeroMemory(&sa, sizeof(sa));
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = TRUE;

  HANDLE hStdOutRead = NULL, hStdOutWrite = NULL;
  if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
    if (outErr) *outErr = "Falha ao criar pipes de comunicacao.";
    return false;
  }
  SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.hStdOutput = hStdOutWrite;
  si.hStdError = hStdOutWrite;
  si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));

  std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
  cmdBuf.push_back(L'\0');

  BOOL created = CreateProcessW(
      nullptr,
      cmdBuf.data(),
      nullptr,
      nullptr,
      TRUE,
      CREATE_NO_WINDOW,
      nullptr,
      nullptr,
      &si,
      &pi
  );

  CloseHandle(hStdOutWrite);

  if (!created) {
    CloseHandle(hStdOutRead);
    if (outErr) *outErr = "Falha ao executar utilitario proton-confgen.exe.";
    return false;
  }

  std::string fullOutput;
  char buffer[512];
  DWORD bytesRead = 0;
  std::string currentLine;

  while (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
    buffer[bytesRead] = '\0';
    fullOutput += buffer;

    for (DWORD i = 0; i < bytesRead; ++i) {
      char ch = buffer[i];
      if (ch == '\n' || ch == '\r') {
        if (!currentLine.empty()) {
          if (onProgress) {
            if (currentLine.find("Authentication successful") != std::string::npos) {
              onProgress("Credenciais aceitas! Consultando servidores...");
            } else if (currentLine.find("Selected server:") != std::string::npos) {
              size_t pos = currentLine.find("Selected server:");
              std::string s = currentLine.substr(pos + 16);
              size_t endPos = s.find(" (");
              if (endPos != std::string::npos) s = s.substr(0, endPos);
              while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
              while (!s.empty() && (s.back() == ' ' || s.back() == '\r' || s.back() == '\n')) s.pop_back();
              onProgress("Servidor selecionado: " + s);
            } else if (currentLine.find("WireGuard configuration written") != std::string::npos) {
              onProgress("Chaves criptográficas geradas com sucesso!");
            } else if (currentLine.find("Successfully generated config") != std::string::npos) {
              onProgress("Perfil WireGuard finalizado com sucesso!");
            }
          }
          std::cout << currentLine << std::endl;
          currentLine.clear();
        }
      } else {
        currentLine += ch;
      }
    }
  }

  CloseHandle(hStdOutRead);
  WaitForSingleObject(pi.hProcess, 60000);

  DWORD exitCode = 1;
  GetExitCodeProcess(pi.hProcess, &exitCode);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  if (exitCode != 0 || !fs::is_regular_file(targetConf)) {
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
    std::cerr << "  \033[31m[ ✖ ] " << (outErr ? *outErr : "Falha na autenticacao Proton.") << "\033[0m\n";
    return false;
  }

  if (onProgress) onProgress("Perfil WireGuard ProtonVPN gerado com sucesso!");
  std::cout << "  \033[32m[ ✔ ] Configuracao ProtonVPN internacional gerada com sucesso!\033[0m\n";
  return true;
}

extern "C" const char _binary_nord_confgen_exe_start[];
extern "C" const char _binary_nord_confgen_exe_end[];

// Grava em %LOCALAPPDATA%\ARDiscordBypass um utilitário embutido no executável.
inline std::wstring extractEmbeddedHelperExe(const std::wstring &name, const char *start, const char *end) {
  size_t size = end - start;
  if (size == 0) return L"";

  wchar_t localApp[MAX_PATH];
  std::wstring targetDir = L"";
  if (GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH) != 0) {
    targetDir = std::wstring(localApp) + L"\\ARDiscordBypass";
  } else {
    wchar_t userProfile[MAX_PATH];
    if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH) != 0) {
      targetDir = std::wstring(userProfile) + L"\\ARDiscordBypass";
    }
  }
  if (targetDir.empty()) return L"";

  std::error_code ec;
  fs::create_directories(targetDir, ec);
  std::wstring outPath = targetDir + L"\\" + name;

  if (fs::exists(outPath, ec) && fs::file_size(outPath, ec) == size) {
    return outPath;
  }

  std::ofstream out(fs::path(outPath), std::ios::binary);
  if (!out.is_open()) return L"";
  out.write(start, size);
  out.close();

  return fs::exists(outPath, ec) ? outPath : L"";
}

inline std::wstring findNordConfgenExe() {
  wchar_t modulePath[MAX_PATH];
  std::vector<std::wstring> candidates = {
      L"bin\\nord-confgen.exe",
      L"PC\\bin\\nord-confgen.exe",
      L"nord-confgen.exe"
  };
  if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) != 0) {
    fs::path dir = fs::path(modulePath).parent_path();
    candidates.insert(candidates.begin(), (dir / L"bin" / L"nord-confgen.exe").wstring());
    candidates.insert(candidates.begin(), (dir / L"nord-confgen.exe").wstring());
  }

  for (const auto &cand : candidates) {
    if (fs::exists(cand) && fs::is_regular_file(cand)) return cand;
  }

  return extractEmbeddedHelperExe(L"nord-confgen.exe", _binary_nord_confgen_exe_start, _binary_nord_confgen_exe_end);
}

inline fs::path protonSessionPath() {
  wchar_t userProfile[MAX_PATH];
  if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH) == 0) return fs::path();
  return fs::path(userProfile) / PROTON_SESSION_FILE;
}

inline fs::path nordSessionPath() {
  wchar_t userProfile[MAX_PATH];
  if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH) == 0) return fs::path();
  return fs::path(userProfile) / NORD_SESSION_FILE;
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
  return fs::is_regular_file(getVpnConfigPath());
}

// Executa um utilitário via CreateProcessW (sem cmd.exe), entrega stdinData pela
// entrada padrão e captura stdout+stderr linha a linha. Devolve o código de
// saída ou -1 se o processo não pôde ser criado.
inline int runHelperCapture(
    const std::wstring &cmdLine,
    const std::string &stdinData,
    std::string &fullOutput,
    const std::function<void(const std::string&)> &onLine = nullptr) {
  // O conteúdo de stdin precisa caber no buffer do pipe (ver abaixo).
  if (stdinData.size() > 2048) return -1;

  SECURITY_ATTRIBUTES sa;
  ZeroMemory(&sa, sizeof(sa));
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = TRUE;

  HANDLE hStdOutRead = NULL, hStdOutWrite = NULL;
  HANDLE hStdInRead = NULL, hStdInWrite = NULL;
  if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) return -1;
  if (!CreatePipe(&hStdInRead, &hStdInWrite, &sa, 4096)) {
    CloseHandle(hStdOutRead);
    CloseHandle(hStdOutWrite);
    return -1;
  }
  SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0);

  // Grava antes de criar o processo e fecha a ponta de escrita: o utilitário lê
  // o conteúdo e recebe EOF em seguida, sem bloquear nenhum dos lados.
  if (!stdinData.empty()) {
    DWORD written = 0;
    WriteFile(hStdInWrite, stdinData.data(), static_cast<DWORD>(stdinData.size()), &written, nullptr);
  }
  CloseHandle(hStdInWrite);

  STARTUPINFOW si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.hStdInput = hStdInRead;
  si.hStdOutput = hStdOutWrite;
  si.hStdError = hStdOutWrite;
  si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));

  std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
  cmdBuf.push_back(L'\0');

  BOOL created = CreateProcessW(
      nullptr,
      cmdBuf.data(),
      nullptr,
      nullptr,
      TRUE,
      CREATE_NO_WINDOW,
      nullptr,
      nullptr,
      &si,
      &pi
  );

  CloseHandle(hStdOutWrite);
  CloseHandle(hStdInRead);

  if (!created) {
    CloseHandle(hStdOutRead);
    return -1;
  }

  char buffer[512];
  DWORD bytesRead = 0;
  std::string currentLine;

  while (ReadFile(hStdOutRead, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
    fullOutput.append(buffer, bytesRead);

    for (DWORD i = 0; i < bytesRead; ++i) {
      char ch = buffer[i];
      if (ch == '\n' || ch == '\r') {
        if (!currentLine.empty()) {
          if (onLine) onLine(currentLine);
          currentLine.clear();
        }
      } else {
        currentLine += ch;
      }
    }
  }
  if (!currentLine.empty() && onLine) onLine(currentLine);

  CloseHandle(hStdOutRead);
  WaitForSingleObject(pi.hProcess, 60000);

  DWORD exitCode = 1;
  GetExitCodeProcess(pi.hProcess, &exitCode);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return static_cast<int>(exitCode);
}

// Gera o perfil padrão pelo nord-confgen.exe. Com token faz o login na API
// NordVPN; com token vazio reutiliza a chave NordLynx salva na sessão. O token
// segue pela entrada padrão do utilitário e nunca aparece na linha de comando.
inline bool runNordConfgen(
    const std::string &token,
    std::string *outErr = nullptr,
    const std::function<void(const std::string&)> &onProgress = nullptr) {
  std::wstring confgen = findNordConfgenExe();
  if (confgen.empty()) {
    if (outErr) *outErr = "Utilitário nord-confgen.exe não encontrado.";
    return false;
  }

  std::string targetConf = getVpnConfigPath();
  std::string countries = NORD_COUNTRIES;

  std::wstring cmdLine = L"\"" + confgen + L"\" --countries " + std::wstring(countries.begin(), countries.end()) +
                         L" --output \"" + fs::path(targetConf).wstring() + L"\"";
  if (!token.empty()) cmdLine += L" --token-stdin";

  std::string output;
  int ret = runHelperCapture(cmdLine, token.empty() ? "" : token + "\n", output, [&](const std::string &line) {
    if (!onProgress) return;
    std::string step = confgenProgressMessage(line);
    if (!step.empty()) onProgress(step);
  });

  if (ret != 0 || !fs::is_regular_file(targetConf)) {
    if (outErr) *outErr = (ret == -1 && output.empty()) ? "Falha ao executar utilitário nord-confgen.exe." : nordErrorMessage(output);
    return false;
  }
  return true;
}

// Fluxo de terminal (CLI) da NordVPN: reaproveita o perfil ou a sessão salva e
// só pede o token de acesso quando não há outra forma (ou quando forceLogin).
inline bool setupNordConfig(bool forceLogin = false) {
  if (!forceLogin) {
    if (defaultConfExists()) return true;
    if (hasNordSession() && runNordConfgen("")) return true;
  }

  std::cout << "\n  \033[33m\033[1m[ Configuracao do Tunel WireGuard (NordVPN) ]\033[0m\n";
  std::cout << "  Requer assinatura NordVPN ativa. Gere um token de acesso em:\n";
  std::cout << "  " << NORD_TOKEN_URL << "\n";
  std::cout << "  Token de acesso NordVPN: ";
  std::cout.flush();

  std::string token;
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  GetConsoleMode(hStdin, &mode);
  SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
  std::getline(std::cin, token);
  SetConsoleMode(hStdin, mode);
  std::cout << "\n";

  token = trimWhitespace(token);
  if (token.empty()) return false;

  std::cout << "  Validando token e gerando tunel WireGuard exclusivo..." << std::endl;

  std::string err;
  bool ok = runNordConfgen(token, &err, [](const std::string &step) {
    std::cout << "  " << step << std::endl;
  });
  if (!ok) {
    std::cerr << "  \033[31m[ ✖ ] " << err << "\033[0m\n";
    return false;
  }

  std::cout << "  \033[32m[ ✔ ] Configuracao NordVPN internacional gerada com sucesso!\033[0m\n";
  return true;
}

inline bool ensureWireGuardWindows(const std::string &chosenConf = "") {
  if (!ensureWireSockInstalled()) {
    std::cerr << "[ERRO] Não foi possível encontrar ou instalar o WireSock no Windows." << std::endl;
    return false;
  }

  std::wstring wsExe = findWireSockExecutable();
  if (wsExe.empty())
    return false;

  // Se o WireSock já estiver rodando, encerra para recarregar com a configuração ativa
  if (isWireSockRunning()) {
    _wsystem(L"taskkill /F /IM wiresock-client.exe >nul 2>&1");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  std::string targetConf = chosenConf.empty() ? getVpnConfigPath() : chosenConf;

  // Se o arquivo não existir e não for customizado, recria pela sessão NordVPN
  // salva ou, nos demais casos, por setupProtonConfigWindows()
  if (!fs::is_regular_file(targetConf)) {
    if (chosenConf.empty()) {
      std::string err;
      if (savedSessionProvider() == VpnProvider::Nord) {
        runNordConfgen("", &err);
      } else {
        setupProtonConfigWindows(false, "", "", &err);
      }
    } else {
      std::cerr << "[ERRO] Arquivo de configuração customizado não encontrado: " << chosenConf << std::endl;
      return false;
    }
  }

  fs::path confPath = fs::temp_directory_path() / WG_CONFIG_NAME;

  if (fs::is_regular_file(targetConf)) {
    // Copiar e anexar diretiva de aplicativo WireSock
    std::ifstream src(targetConf);
    std::ofstream dst(confPath);
    std::string line;
    while (std::getline(src, line)) {
      dst << line << "\n";
    }
    dst << "\n#@ws:AllowedApps = Discord, Update, DiscordCanary, DiscordPTB, Vesktop\n";
    src.close();
    dst.close();
  } else {
    return false;
  }

  // Iniciar WireSock em background
  std::wstring cmd = L"\"" + wsExe + L"\" run -config \"" + confPath.wstring() + L"\" -log-level none";

  STARTUPINFOW si = {sizeof(si)};
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi = {0};

  BOOL ok = CreateProcessW(
      nullptr, const_cast<LPWSTR>(cmd.data()), nullptr, nullptr, FALSE,
      CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi);

  if (ok) {
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return isWireSockRunning();
  }

  return false;
}

inline bool launchDiscord(const std::wstring &exePath) {
  // Limpar travas Singleton no Windows
  wchar_t appData[MAX_PATH];
  if (GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH) != 0) {
    fs::path base(appData);
    const std::vector<std::wstring> cfgs = {L"discord", L"discordcanary", L"discordptb", L"vesktop"};
    for (const auto &cfg : cfgs) {
      std::error_code ec;
      fs::remove(base / cfg / L"SingletonLock", ec);
      fs::remove(base / cfg / L"SingletonCookie", ec);
      fs::remove(base / cfg / L"SingletonSocket", ec);
    }
  }

  std::wstring workDir = fs::path(exePath).parent_path().wstring();

  // 1. Tentar lançar através do Update.exe (Squirrel launcher oficial do Discord no Windows)
  // O caminho do Update.exe geralmente é o diretório pai da pasta 'app-x.x.xxxx' (ex: %LOCALAPPDATA%\Discord\Update.exe)
  fs::path parentDir = fs::path(exePath).parent_path().parent_path();
  fs::path updateExe = parentDir / L"Update.exe";

  HINSTANCE hInst = nullptr;
  if (fs::is_regular_file(updateExe)) {
    std::wstring exeName = fs::path(exePath).filename().wstring();
    std::wstring params = L"--processStart " + exeName;
    hInst = ShellExecuteW(nullptr, L"open", updateExe.c_str(), params.c_str(), parentDir.wstring().c_str(), SW_SHOWNORMAL);
  }

  // 2. Se não houver Update.exe ou se falhou, lançar diretamente o executável via ShellExecuteW
  if ((INT_PTR)hInst <= 32) {
    hInst = ShellExecuteW(nullptr, L"open", exePath.c_str(), nullptr, workDir.c_str(), SW_SHOWNORMAL);
  }

  // 3. Fallback: CreateProcessW limpo de subsistema Windows caso ShellExecute não responda
  if ((INT_PTR)hInst <= 32) {
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    std::wstring cmdLine = L"\"" + exePath + L"\"";
    BOOL ok = CreateProcessW(
        nullptr, const_cast<LPWSTR>(cmdLine.data()), nullptr, nullptr, FALSE,
        0, nullptr, workDir.c_str(), &si, &pi);
    if (ok) {
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
    }
  }

  // Aguarda até 5 segundos para o processo inicializar e aparecer no snapshot de processos
  for (int i = 0; i < 10; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    if (isDiscordRunning()) {
      return true;
    }
  }

  return isDiscordRunning();
}

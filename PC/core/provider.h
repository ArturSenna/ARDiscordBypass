#pragma once

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

// Definições compartilhadas entre Linux e Windows para os provedores que geram
// o perfil padrão ardc_vpn.conf (ProtonVPN e NordVPN). Nada aqui depende do
// sistema operacional; o que depende fica em os/<plataforma>/platform.h.

enum class VpnProvider {
  None,   // perfil ausente ou trazido pelo usuário (sem cabeçalho de gerador)
  Proton,
  Nord
};

inline const char *PROTON_SESSION_FILE = ".protonvpn-session.json";
inline const char *NORD_SESSION_FILE = ".nordvpn-session.json";

// Países de saída do túnel NordVPN, em ordem de preferência.
inline const char *NORD_COUNTRIES = "US,NL,JP";

// Página do Nord Account onde o usuário gera o token de acesso.
inline const char *NORD_TOKEN_URL = "https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/";

inline const char *providerDisplayName(VpnProvider provider) {
  switch (provider) {
    case VpnProvider::Proton: return "ProtonVPN";
    case VpnProvider::Nord: return "NordVPN";
    default: return "Personalizado";
  }
}

// Identifica o provedor de um perfil pelo cabeçalho que o gerador grava nas
// primeiras linhas de comentário.
inline VpnProvider detectConfProvider(const std::string &confPath) {
  std::ifstream in(confPath);
  std::string line;
  while (std::getline(in, line)) {
    size_t start = line.find_first_not_of(" \t\r");
    if (start == std::string::npos) continue;
    if (line[start] != '#') break;
    if (line.find("NordVPN WireGuard Configuration") != std::string::npos) return VpnProvider::Nord;
    if (line.find("ProtonVPN WireGuard Configuration") != std::string::npos) return VpnProvider::Proton;
  }
  return VpnProvider::None;
}

// Entre as sessões salvas existentes, devolve a do provedor usado por último.
inline VpnProvider newestSessionProvider(const std::filesystem::path &protonSession,
                                         const std::filesystem::path &nordSession) {
  std::error_code ec;
  bool hasProton = !protonSession.empty() && std::filesystem::is_regular_file(protonSession, ec);
  bool hasNord = !nordSession.empty() && std::filesystem::is_regular_file(nordSession, ec);
  if (hasProton && hasNord) {
    auto protonTime = std::filesystem::last_write_time(protonSession, ec);
    auto nordTime = std::filesystem::last_write_time(nordSession, ec);
    return nordTime > protonTime ? VpnProvider::Nord : VpnProvider::Proton;
  }
  if (hasNord) return VpnProvider::Nord;
  if (hasProton) return VpnProvider::Proton;
  return VpnProvider::None;
}

inline std::string trimWhitespace(const std::string &text) {
  size_t first = text.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  size_t last = text.find_last_not_of(" \t\r\n");
  return text.substr(first, last - first + 1);
}

// Converte uma linha de saída do gerador (mesmo contrato no proton-confgen e
// no nord-confgen) em etapa de progresso. Devolve "" se a linha não for etapa.
inline std::string confgenProgressMessage(const std::string &line) {
  if (line.find("Authentication successful") != std::string::npos) {
    return "Credenciais aceitas! Consultando servidores...";
  }
  size_t pos = line.find("Selected server:");
  if (pos != std::string::npos) {
    std::string name = line.substr(pos + 16);
    size_t endPos = name.find(" (");
    if (endPos != std::string::npos) name = name.substr(0, endPos);
    return "Servidor selecionado: " + trimWhitespace(name);
  }
  if (line.find("WireGuard configuration written") != std::string::npos) {
    return "Chaves criptográficas geradas com sucesso!";
  }
  if (line.find("Successfully generated config") != std::string::npos) {
    return "Perfil WireGuard finalizado com sucesso!";
  }
  return "";
}

// Converte a saída de uma execução malsucedida do nord-confgen em mensagem
// para o usuário.
inline std::string nordErrorMessage(const std::string &output) {
  auto has = [&output](const char *needle) { return output.find(needle) != std::string::npos; };

  if (has("invalid or expired access token")) {
    return "Token de acesso NordVPN inválido ou expirado. Gere um novo token no Nord Account.";
  }
  if (has("no NordLynx key")) {
    return "A conta não retornou chave NordLynx. Verifique se a assinatura NordVPN está ativa.";
  }
  if (has("could not reach the NordVPN API")) {
    return "Falha de comunicação com a API NordVPN. Verifique sua conexão com a internet.";
  }
  if (has("no saved session found") || has("saved session is corrupted")) {
    return "Sessão NordVPN ausente ou inválida. Informe um token de acesso.";
  }
  if (has("no online WireGuard server found") || has("unknown country code")) {
    return "Nenhum servidor NordVPN disponível nos países configurados.";
  }

  std::string cleanErr;
  std::stringstream ss(output);
  std::string line;
  while (std::getline(ss, line)) {
    if (line.rfind("Error: ", 0) == 0) cleanErr = trimWhitespace(line.substr(7));
  }
  return cleanErr.empty() ? "Falha ao gerar o perfil NordVPN." : cleanErr;
}

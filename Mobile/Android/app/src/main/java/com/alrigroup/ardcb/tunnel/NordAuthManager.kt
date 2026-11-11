package com.alrigroup.ardcb.tunnel

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException

/**
 * Orquestra o gerador nativo libnordconfgen.so (código-fonte em tools/nord-confgen).
 *
 * O token de acesso segue pela entrada padrão do processo: não aparece na linha
 * de comando nem é gravado em disco. O gerador salva apenas a chave NordLynx.
 */
object NordAuthManager {

    const val TOKEN_URL = "https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/"

    private const val SESSION_FILE = ".nordvpn-session.json"

    // Países de saída do túnel, em ordem de preferência.
    private const val COUNTRIES = "US,NL,JP"

    fun getNativeBinary(context: Context): File? {
        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        val bin = File(nativeDir, "libnordconfgen.so")
        return if (bin.exists() && bin.canExecute()) bin else null
    }

    fun hasSavedSession(context: Context): Boolean {
        val sessionFile = File(context.filesDir, SESSION_FILE)
        return sessionFile.exists() && sessionFile.length() > 0
    }

    fun clearSession(context: Context) {
        val sessionFile = File(context.filesDir, SESSION_FILE)
        if (sessionFile.exists()) sessionFile.delete()
    }

    suspend fun authenticateAndGenerate(
        context: Context,
        token: String,
        onProgress: (String) -> Unit
    ): Result<File> = withContext(Dispatchers.IO) {
        val bin = getNativeBinary(context)
            ?: return@withContext Result.failure(IllegalStateException("Módulo nativo libnordconfgen não encontrado."))

        val outputFile = File(context.filesDir, "ardc_vpn.conf")
        onProgress("Validando token de acesso na API NordVPN...")

        val cmd = listOf(
            bin.absolutePath,
            "--token-stdin",
            "--countries", COUNTRIES,
            "--output", outputFile.absolutePath
        )

        try {
            val pb = ProcessBuilder(cmd)
            pb.environment()["HOME"] = context.filesDir.absolutePath
            pb.redirectErrorStream(true)

            val process = pb.start()
            try {
                process.outputStream.use { stdin ->
                    stdin.write((token.trim() + "\n").toByteArray())
                }
            } catch (_: IOException) {
                // O gerador encerrou antes de ler o token; a saída abaixo explica o motivo.
            }

            val outputBuilder = StringBuilder()
            val reader = process.inputStream.bufferedReader()
            var line = reader.readLine()
            while (line != null) {
                outputBuilder.appendLine(line)
                val trimmed = line.trim()
                when {
                    trimmed.contains("Authentication successful", ignoreCase = true) ->
                        onProgress("Token aceito! Consultando servidores...")
                    trimmed.contains("Selected server:", ignoreCase = true) ->
                        onProgress("Servidor selecionado: " + trimmed.substringAfter("Selected server: ").substringBefore(" ("))
                    trimmed.contains("WireGuard configuration written", ignoreCase = true) ->
                        onProgress("Chaves criptográficas geradas com sucesso!")
                    trimmed.contains("Successfully generated config", ignoreCase = true) ->
                        onProgress("Perfil WireGuard finalizado com sucesso!")
                }
                line = reader.readLine()
            }
            val exitCode = process.waitFor()

            if (exitCode == 0 && outputFile.exists() && outputFile.length() > 0) {
                onProgress("Perfil WireGuard NordVPN gerado com sucesso!")
                Result.success(outputFile)
            } else {
                Result.failure(Exception(describeError(outputBuilder.toString(), exitCode)))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun describeError(output: String, exitCode: Int): String = when {
        output.contains("invalid or expired access token", ignoreCase = true) ->
            "Token de acesso NordVPN inválido ou expirado. Gere um novo token no Nord Account."
        output.contains("no NordLynx key", ignoreCase = true) ->
            "A conta não retornou chave NordLynx. Verifique se a assinatura NordVPN está ativa."
        output.contains("could not reach the NordVPN API", ignoreCase = true) ->
            "Falha de comunicação com a API NordVPN. Verifique sua conexão com a internet."
        output.contains("no online WireGuard server found", ignoreCase = true) ||
            output.contains("unknown country code", ignoreCase = true) ->
            "Nenhum servidor NordVPN disponível nos países configurados."
        else -> {
            val cleanError = output.lines()
                .map { it.trim() }
                .lastOrNull { it.startsWith("Error:") }
            cleanError?.removePrefix("Error: ") ?: "Falha ao gerar o perfil NordVPN (código $exitCode)"
        }
    }
}

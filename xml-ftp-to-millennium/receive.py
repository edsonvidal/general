"""
receive_one_batch_strict.py — baixa ATÉ 100 XMLs do FTP, valida e move para ENVIADO, e ENCERRA.
Modo "estrito": o lote só é considerado concluído se TODOS os arquivos forem enviados/movidos
com sucesso. Se qualquer arquivo falhar após as tentativas configuradas, o script encerra
com código de saída 2 (útil para o Agendador do Windows).

Fluxo (apenas 1 lote):
  1) Conecta via FTPS e entra em /XML/TESTE.
  2) Lista por nome e pega no máximo 100 arquivos (sem varrer tudo).
  3) Para cada arquivo (sequencial, sem paralelismo):
       - baixa p/ C:\TUDO_NICOLAS\TESTE_EXTRACAO_XML (uma vez)
       - valida tamanho local (>0)
       - tenta mover no FTP com RNFR/RNTO; se não der:
            fallback: STOR para /XML/TESTE_ENVIADO, valida SIZE remoto e DELE original
       - em caso de erro de TLS (ex.: [SSL: BAD_LENGTH]) ou reset, refaz handshakes e reconecta
         e TENTA de novo (até X tentativas)
       - só passa para o próximo após sucesso confirmado
  4) Sai com:
       - código 0: sucesso total
       - código 2: houve falha em algum arquivo do lote
"""

import os
import sys
import time
import socket
import ssl as _ssl
from ftplib import FTP, FTP_TLS, error_perm

# ==========================
# ⚙️ CONFIGURAÇÕES
# ==========================
FTP_HOST = os.getenv("FTP_HOST", "ftp-amobeleza.millenniumhosting.com.br")
FTP_USER = os.getenv("FTP_USER", "amobeleza")
FTP_PASS = os.getenv("FTP_PASS", "1wlapt22kjh5")  # use variável de ambiente em produção

PASTA_REMOTA_ORIGEM   = "/XML/CTE"
PASTA_REMOTA_ENVIADO  = "/XML/CTES_ENVIADOS"
PASTA_LOCAL_DESTINO   = r"C:\wts\download_enfe"

ARQUIVOS_POR_LOTE = 100
SOMENTE_XML       = True

# Estabilidade/performance (sem paralelismo)
BLOCKSIZE            = 65_536     # 64 KiB (mais compatível para STOR/RETR)
KEEPALIVE_INTERVAL   = 30         # NOOP a cada X s durante o lote (apenas defensivo)
RECONNECT_A_CADA     = 100        # reconectar a cada N transferências (0 = desativado)
LOG_CADA             = 10         # log detalhado a cada X arquivos (1 = loga todos)

# Modo estrito (retries por arquivo)
MAX_TENTATIVAS_POR_ARQUIVO = 5    # quantas tentativas por arquivo
BACKOFF_INICIAL_S           = 1    # 1s, depois dobra (1,2,4,8,...)

# ==========================
# 🔐 Cliente FTPS robusto
# ==========================
class FTPSClient(FTP_TLS):
    def makepasv(self):
        host, port = super().makepasv()
        if host.startswith(("10.", "192.168.", "172.", "127.")):
            return FTP_HOST, port
        return host, port

    def prot_p(self):
        super().prot_p()
        self._prot_level = "P"

    def prot_c(self):
        super().prot_c()
        self._prot_level = "C"

    def ntransfercmd(self, cmd, rest=None):
        conn, size = FTP.ntransfercmd(self, cmd, rest)
        # buffers + Nagle-off (melhora throughput em alguns servidores)
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        # reenvolve canal de dados se PROT P ativo
        if getattr(self, "_prot_level", "C") == "P":
            session = getattr(self.sock, "session", None)
            conn = self.context.wrap_socket(conn, server_hostname=self.host, session=session)
        return conn, size

def configurar_transferencia(ftp, protecao="P", modo_passivo=True):
    if protecao == "P":
        ftp.prot_p()
    else:
        ftp.prot_c()
    ftp.set_pasv(modo_passivo)

def conectar_ftp():
    print("📡 Conectando ao servidor FTPS...")
    ftp = FTPSClient(timeout=60)
    ftp.encoding = "utf-8"
    ftp.connect(FTP_HOST, 21)
    ftp.auth()
    ftp.login(FTP_USER, FTP_PASS)
    ftp.sendcmd("PBSZ 0")

    modos = [
        ("PROT P + PASV", ("P", True)),
        ("PROT P + ATIVO", ("P", False)),
        ("PROT C + PASV", ("C", True)),
        ("PROT C + ATIVO", ("C", False)),
    ]
    for nome, (prot, pasv) in modos:
        try:
            configurar_transferencia(ftp, prot, pasv)
            ftp.cwd(PASTA_REMOTA_ORIGEM)
            try:
                ftp.voidcmd("NOOP")
            except Exception:
                pass
            print(f"✅ Modo funcionando ({nome}).")
            return ftp
        except Exception as e:
            print(f"⚠️ Falha no modo {nome}: {e}")
    print("❌ Nenhum modo de conexão de dados funcionou.")
    return None

def garantir_conexao(ftp):
    """
    Garante que a sessão de controle está viva. Se não, reconecta.
    Retorna um objeto FTP válido (ou None se não conseguir).
    """
    try:
        if ftp is None:
            return conectar_ftp()
        try:
            ftp.voidcmd("NOOP")
            return ftp
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass
            return conectar_ftp()
    except (ConnectionResetError, EOFError):
        try:
            if ftp:
                ftp.close()
        except Exception:
            pass
        return conectar_ftp()

# ==========================
# 🧭 Utilidades FTP
# ==========================
def _force_type_i_and_tls(ftp):
    # Reafirma canal de dados protegido e modo binário
    try:
        ftp.prot_p()
    except Exception:
        pass
    try:
        ftp.voidcmd("TYPE I")
    except Exception:
        pass

def assegurar_diretorio_remoto(ftp, caminho_abs: str, tentativas=3, pausa=1.0):
    """
    Garante que 'caminho_abs' exista no servidor (criando recursivamente).
    Resiliente a ConnectionReset/SSL: reconecta e re-tenta.
    Retorna (ftp) que pode ter sido reestabelecido.
    """
    if not caminho_abs or caminho_abs == "/":
        return ftp

    partes = [p for p in caminho_abs.strip("/").split("/") if p]
    atual = ""
    # guarda diretório corrente para restaurar depois
    try:
        cur = ftp.pwd()
    except Exception:
        ftp = garantir_conexao(ftp)
        cur = "/"

    for p in partes:
        atual = f"{atual}/{p}"
        ok = False
        for _ in range(tentativas):
            try:
                # tenta entrar; se entrar, já existe
                ftp.cwd(atual)
                ok = True
                break
            except Exception:
                # tenta criar
                try:
                    ftp.mkd(atual)
                    ok = True
                    break
                except error_perm:
                    # pode ser "já existe" ou sem permissão; testa cwd para decidir
                    try:
                        ftp.cwd(atual)
                        ok = True
                        break
                    except Exception:
                        ok = False
                except (ConnectionResetError, EOFError, _ssl.SSLError):
                    ftp = garantir_conexao(ftp)
            time.sleep(pausa)
        if not ok:
            raise RuntimeError(f"Não foi possível assegurar diretório remoto: {atual}")

    # restaura diretório anterior se possível
    try:
        ftp.cwd(cur)
    except Exception:
        pass
    return ftp

def _cwd_and_size(ftp, caminho_abs: str):
    _force_type_i_and_tls(ftp)
    try:
        sz = ftp.size(caminho_abs)
        return int(sz) if sz is not None else None
    except Exception:
        pass
    try:
        dirpath, fname = caminho_abs.rsplit("/", 1)
        if not dirpath:
            return None
        cur = ftp.pwd()
        try:
            ftp.cwd(dirpath)
            try:
                sz = ftp.size(fname)
                return int(sz) if sz is not None else None
            except Exception:
                return None
        finally:
            try:
                ftp.cwd(cur)
            except Exception:
                pass
    except Exception:
        return None

def remoto_confere_tamanho(ftp, caminho_abs: str, tamanho_esperado: int) -> bool:
    sz = _cwd_and_size(ftp, caminho_abs)
    return (sz is not None) and (int(sz) == int(tamanho_esperado))

# ==========================
# 📋 Listar primeiros N por nome (sem varrer tudo)
# ==========================
_PREFIXES = (
    [chr(c) for c in range(ord('0'), ord('9') + 1)] +
    [chr(c) for c in range(ord('A'), ord('Z') + 1)] +
    [chr(c) for c in range(ord('a'), ord('z') + 1)] +
    ['_', '-', '.']
)

def _nlst_prefix(ftp, pattern):
    try:
        ftp.voidcmd("TYPE A")
    except Exception:
        pass
    itens = []
    def coletor(nome):
        if nome and nome not in (".", ".."):
            itens.append(nome)
    try:
        ftp.retrlines(f"NLST {pattern}", coletor)
    except Exception:
        pass
    return itens

def listar_primeiros_n_ordenados_nome(ftp, n, somente_xml=True):
    coletados, vistos = [], set()
    # 1) varre por prefixos para não trazer tudo
    for prefix in _PREFIXES:
        if len(coletados) >= n:
            break
        nomes = _nlst_prefix(ftp, f"{prefix}*")
        if not nomes:
            continue
        if somente_xml:
            nomes = [x for x in nomes if x.lower().endswith(".xml")]
        nomes = sorted(set(nomes) - vistos)
        for nome in nomes:
            coletados.append(nome)
            vistos.add(nome)
            if len(coletados) >= n:
                break

    # 2) fallback: NLST geral, se ainda faltou
    if len(coletados) < n:
        try:
            ftp.voidcmd("TYPE A")
        except Exception:
            pass
        tudo = []
        def cap(nm):
            if nm and nm not in (".", ".."):
                tudo.append(nm)
        try:
            ftp.retrlines("NLST", cap)
        except Exception:
            pass
        if SOMENTE_XML:
            tudo = [x for x in tudo if x.lower().endswith(".xml")]
        tudo = sorted(set(tudo) - vistos)
        for nm in tudo:
            coletados.append(nm)
            if len(coletados) >= n:
                break

    return coletados[:n]

# ==========================
# 🔁 Tentativa robusta por arquivo (modo estrito)
# ==========================
def tentar_processar_arquivo(ftp, nome, idx, total):
    """
    Processa UM arquivo com múltiplas tentativas:
      1) download (se ainda não tiver local válido)
      2) mover por RNFR/RNTO OU fallback STOR→SIZE→DELE
    Retorna (ftp, sucesso: bool)
    """
    os.makedirs(PASTA_LOCAL_DESTINO, exist_ok=True)

    # caminho local sem sobrescrever (anexa _1, _2, ...)
    caminho_local = os.path.join(PASTA_LOCAL_DESTINO, os.path.basename(nome))
    base, ext = os.path.splitext(caminho_local)
    i = 1
    while os.path.exists(caminho_local):
        caminho_local = f"{base}_{i}{ext}"
        i += 1

    backoff = BACKOFF_INICIAL_S
    tent = 1
    tam_local_cache = None  # cacheia tamanho após download bem-sucedido

    while tent <= MAX_TENTATIVAS_POR_ARQUIVO:
        # keepalive defensivo
        try:
            ftp.voidcmd("NOOP")
        except Exception:
            try:
                ftp.quit()
            except Exception:
                pass
            ftp = conectar_ftp()
            if not ftp:
                print("❌ Reconexão falhou.")
                return ftp, False

        # reconexão periódica por contagem (opcional)
        if RECONNECT_A_CADA and ((idx - 1) % RECONNECT_A_CADA == 0) and idx > 1 and tent == 1:
            try:
                ftp.quit()
            except Exception:
                pass
            ftp = conectar_ftp()
            if not ftp:
                print("❌ Reconexão periódica falhou.")
                return ftp, False

        # 1) download (apenas se ainda não baixou com sucesso)
        try:
            _force_type_i_and_tls(ftp)
            if tam_local_cache is None:
                with open(caminho_local, "wb") as f:
                    ftp.retrbinary(f"RETR {nome}", f.write, blocksize=BLOCKSIZE)
                tam_local = os.path.getsize(caminho_local)
                if tam_local <= 0:
                    raise RuntimeError("arquivo local vazio")
                tam_local_cache = tam_local
                if (idx % LOG_CADA) == 0 or LOG_CADA == 1:
                    print(f"⬇️  {idx}/{total} Download OK: {nome} ({tam_local_cache} bytes)")
            else:
                tam_local = tam_local_cache
        except (_ssl.SSLError,) as e:
            print(f"⚠️ Tentativa {tent}/{MAX_TENTATIVAS_POR_ARQUIVO} — TLS falhou no RETR ({e}). Rehandshake...")
            _force_type_i_and_tls(ftp)
            time.sleep(backoff); backoff *= 2; tent += 1
            continue
        except Exception as e:
            print(f"❌ Tentativa {tent} — Download falhou para {nome}: {e}")
            try:
                if os.path.exists(caminho_local):
                    os.remove(caminho_local)
            except Exception:
                pass
            time.sleep(backoff); backoff *= 2; tent += 1
            tam_local_cache = None
            continue

        # 2) mover no servidor (RNFR/RNTO) OU fallback STOR→SIZE→DELE
        destino_abs = f"{PASTA_REMOTA_ENVIADO.rstrip('/')}/{os.path.basename(nome)}"
        move_ok = False

        # 2a) RNFR/RNTO
        try:
            try:
                ftp.cwd(PASTA_REMOTA_ORIGEM)
            except Exception:
                pass
            ftp.rename(nome, destino_abs)
            if remoto_confere_tamanho(ftp, destino_abs, tam_local):
                move_ok = True
        except error_perm:
            move_ok = False
        except Exception:
            move_ok = False

        # 2b) fallback: STOR → valida SIZE → DELE original
        if not move_ok:
            try:
                # garante que ENVIADO exista apenas se necessário
                try:
                    ftp.cwd(PASTA_REMOTA_ENVIADO)
                except Exception:
                    ftp = assegurar_diretorio_remoto(ftp, PASTA_REMOTA_ENVIADO)

                _force_type_i_and_tls(ftp)
                with open(caminho_local, "rb") as f:
                    ftp.storbinary(f"STOR {destino_abs}", f, blocksize=BLOCKSIZE)

                if remoto_confere_tamanho(ftp, destino_abs, tam_local):
                    # apaga o original somente após confirmar o destino
                    try:
                        ftp.delete(f"{PASTA_REMOTA_ORIGEM.rstrip('/')}/{nome}")
                    except error_perm:
                        try:
                            ftp.delete(nome)
                        except Exception:
                            pass
                    move_ok = True
                else:
                    print(f"⚠️ Tamanho no destino não confere (fallback): {destino_abs}")
                    move_ok = False
            except (_ssl.SSLError,) as e:
                print(f"⚠️ Tentativa {tent}/{MAX_TENTATIVAS_POR_ARQUIVO} — TLS falhou no STOR ({e}). Rehandshake...")
                _force_type_i_and_tls(ftp)
                move_ok = False
            except Exception as e:
                print(f"❌ Tentativa {tent} — Fallback falhou para {nome}: {e}")
                move_ok = False

        if move_ok:
            if (idx % LOG_CADA) == 0 or LOG_CADA == 1:
                print(f"✅ {idx}/{total} Enviado para ENVIADO: {destino_abs}")
            return ftp, True

        # se chegou aqui, deu ruim — backoff e nova tentativa
        time.sleep(backoff); backoff *= 2; tent += 1

    # estourou tentativas
    print(f"⛔️ Arquivo FALHOU após {MAX_TENTATIVAS_POR_ARQUIVO} tentativas: {nome}")
    return ftp, False

# ==========================
# 🚀 Principal — 1 lote, estrito
# ==========================
def main():
    ftp = conectar_ftp()
    if not ftp:
        print("❌ Não foi possível estabelecer sessão FTPS.")
        print("🏁 Fim.")
        sys.exit(2)

    try:
        # origem
        try:
            ftp.cwd(PASTA_REMOTA_ORIGEM)
        except Exception as e:
            print(f"❌ Não foi possível mudar para {PASTA_REMOTA_ORIGEM}: {e}")
            sys.exit(2)

        # cria/garante ENVIADO uma ÚNICA vez (fora do hot-path)
        try:
            ftp = assegurar_diretorio_remoto(ftp, PASTA_REMOTA_ENVIADO)
        except Exception as e:
            print(f"❌ Falha ao assegurar {PASTA_REMOTA_ENVIADO}: {e}")
            sys.exit(2)

        # lista ATÉ 100 por nome (filtrando .xml se configurado)
        nomes = listar_primeiros_n_ordenados_nome(ftp, ARQUIVOS_POR_LOTE, SOMENTE_XML)
        if not nomes:
            print("✅ Nada a processar neste ciclo. Encerrando.")
            sys.exit(0)

        print(f"\n🚚 Iniciando lote ÚNICO (estrito) com {len(nomes)} arquivo(s)...")

        total = len(nomes)
        inicio_lote = time.time()
        for idx, nome in enumerate(nomes, start=1):
            ftp = garantir_conexao(ftp)
            if not ftp:
                print("❌ Conexão perdida e não foi possível reconectar.")
                sys.exit(2)

            ftp, ok = tentar_processar_arquivo(ftp, nome, idx, total)
            if not ok:
                print("❌ Interrompendo execução: houve falha em arquivo do lote.")
                sys.exit(2)

            # keepalive por tempo (defensivo)
            if (time.time() - inicio_lote) >= KEEPALIVE_INTERVAL:
                try:
                    ftp.voidcmd("NOOP")
                except Exception:
                    ftp = garantir_conexao(ftp)
                inicio_lote = time.time()

        print("🏁 Lote finalizado com SUCESSO (todos os arquivos enviados).")
        sys.exit(0)

    finally:
        try:
            if ftp:
                ftp.quit()
        except Exception:
            pass
        print("🔌 Conexão encerrada.")

if __name__ == "__main__":
    main()

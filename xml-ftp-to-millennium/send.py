"""
Automatiza o envio de arquivos XML via FTPS.

Resumo do fluxo:
    1. Procura arquivos ZIP em `CAMINHO_PADRAO` (pasta `files`).
    2. Extrai cada ZIP e move todos os XMLs diretamente para `CAMINHO_PADRAO_TO_SEND`.
    3. Limpa a pasta `files` quando todas as extrações terminam sem erro.
    4. Estabelece uma conexão FTPS segura e envia os XMLs em lotes de 100.
    5. Após cada envio bem-sucedido move o XML para `CAMINHO_PADRAO_SEND` para manter histórico.

O script foi comentado pensando em quem está começando e precisa entender
como as partes interagem. Consulte os docstrings das funções para detalhes.
"""

import os
import shutil
import time
import zipfile
from collections import deque, defaultdict
from datetime import datetime
from ftplib import FTP, FTP_TLS, error_perm


class FTPSClient(FTP_TLS):
    """
    Versão customizada do `FTP_TLS` que corrige um detalhe comum em servidores FTPS.

    Alguns servidores retornam um endereço IP privado quando usamos modo passivo.
    Aqui sobrescrevemos métodos da classe padrão para detectar esse cenário e
    reutilizar o host configurado, evitando erros de conexão para quem está
    trabalhando atrás de firewalls ou NAT.
    """

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
        if getattr(self, "_prot_level", "C") == "P":
            session = getattr(self.sock, "session", None)
            conn = self.context.wrap_socket(
                conn,
                server_hostname=self.host,
                session=session,
            )
        return conn, size

# ============================================================
# 🔧 CONFIGURAÇÕES PADRÃO
# ============================================================

# Dados de acesso ao servidor FTPS (modo seguro com TLS explícito)
FTP_HOST = "ftp-amobeleza.millenniumhosting.com.br"
FTP_USER = "amobeleza"
FTP_PASS = "1wlapt22kjh5"

# Caminho local onde os arquivos .zip estão armazenados
#CAMINHO_PADRAO = r"C:\Sys\PROJETOS\xml-ftp-to-millennium\files"
#CAMINHO_PADRAO_TO_SEND = r"C:\Sys\PROJETOS\xml-ftp-to-millennium\to_send"
#CAMINHO_PADRAO_SEND = r"C:\Sys\PROJETOS\xml-ftp-to-millennium\send"
CAMINHO_PADRAO = r"C:\Sys\PROJETOS\xml-ftp-to-millennium\files"
CAMINHO_PADRAO_TO_SEND = r"C:\Sys\PROJETOS\xml-ftp-to-millennium\to_send"
CAMINHO_PADRAO_SEND = r"C:\Sys\PROJETOS\xml-ftp-to-millennium\send"


# Caminho remoto (no servidor FTP) para onde os XMLs serão enviados
DESTINO_REMOTO = "/XML/CTE"

# Número total de ciclos para tentar reenviar arquivos que falharam
MAX_REPROCESSOS = 3

# Caminho do log textual de envios (com timestamp para cada execução)
RELATORIO_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
CAMINHO_LOG = os.path.join(CAMINHO_PADRAO, f"relatorio_envio_{RELATORIO_TIMESTAMP}.txt")

# Lista de combinações de proteção e modo de transferência a testar.
# Mantemos apenas PROT P (canal de dados criptografado), alternando entre
# passivo e ativo para contornar firewalls eventualmente.
MODOS_TRANSFERENCIA = [
    ("P", True),
    ("P", False),
]

# ============================================================
# 🌐 CONEXÃO FTP SEGURA (FTPS)
# ============================================================
def verificar_arquivo_remoto(ftp, nome_arquivo):
    """
    Consulta se um arquivo já existe no FTP e devolve o tamanho remoto.

    Args:
        ftp: Conexão ativa com o servidor FTPS.
        nome_arquivo: Nome do arquivo que deve existir no diretório atual do FTP.

    Returns:
        O tamanho remoto em bytes quando disponível ou `None` quando o arquivo
        não está presente ou o servidor não consegue informar o tamanho.
    """
    if ftp is None:
        return None

    try:
        tamanho = ftp.size(nome_arquivo)
        if tamanho is not None:
            return int(tamanho)
    except error_perm:
        # Servidor pode não suportar SIZE ou o arquivo não existe.
        pass
    except Exception:
        pass

    try:
        linhas = []
        ftp.retrlines("LIST", linhas.append)
        for linha in linhas:
            partes = linha.split()
            if partes and partes[-1] == nome_arquivo:
                for parte in partes:
                    if parte.isdigit():
                        return int(parte)
    except Exception:
        pass

    return None

def conectar_ftp():
    """
    Abre uma conexão FTPS pronta para enviar arquivos.

    A função cuida de configurar TLS, autenticação, modo passivo e da criação
    do diretório remoto configurado caso ainda não exista.

    Returns:
        Uma instância de `FTPSClient` pronta para uso ou `None` se não for
        possível estabelecer a conexão.
    """
    print("🌐 Tentando conectar ao servidor FTP seguro (FTPS - TLS Explícito)...")
    try:
        # Criando conexão segura
        ftp = FTPSClient(timeout=60)
        ftp.encoding = "utf-8"

        print("🔄 Iniciando conexão...")
        ftp.connect(FTP_HOST, 21)

        print("🔐 Realizando handshake TLS...")
        ftp.auth()

        print("🔐 Realizando login...")
        ftp.login(FTP_USER, FTP_PASS)
        ftp.sendcmd("PBSZ 0")

        print("🔒 Configurando conexão segura...")
        ftp.prot_p()                 # Protege o canal de dados (requerido por muitos servidores)
        ftp.set_pasv(True)           # Usa modo passivo, mais estável atrás de NAT/firewall
        ftp.voidcmd("TYPE I")        # Garante modo binário já na conexão inicial
        print("✅ Modo passivo seguro ativado")

        # Tenta acessar a pasta remota configurada
        try:
            ftp.cwd(DESTINO_REMOTO)
            print(f"📁 Diretório remoto alterado para: {DESTINO_REMOTO}")
        except error_perm:
            print(f"⚠️ Diretório {DESTINO_REMOTO} não existe. Criando...")
            criar_diretorios_remotos(ftp, DESTINO_REMOTO)
            ftp.cwd(DESTINO_REMOTO)
            print(f"✅ Diretório {DESTINO_REMOTO} criado e selecionado com sucesso!")

        print(f"✅ Conectado com segurança ao FTP: {FTP_HOST}")
        return ftp

    except Exception as e:
        print(f"❌ Erro ao conectar ao FTP seguro: {e}")
        return None


# ============================================================
# 📂 CRIAÇÃO RECURSIVA DE DIRETÓRIOS REMOTOS
# ============================================================
def criar_diretorios_remotos(ftp, caminho):
    """
    Cria cada nível do caminho remoto informado (caso não exista).

    Args:
        ftp: Conexão ativa com o servidor FTPS.
        caminho: Caminho absoluto no servidor (ex.: "/XML/CTE").
    """
    partes = caminho.strip("/").split("/")
    caminho_atual = ""
    for parte in partes:
        caminho_atual += f"/{parte}"
        try:
            ftp.mkd(caminho_atual)
            print(f"📂 Pasta criada: {caminho_atual}")
        except error_perm:
            # Pasta já existe
            pass


# ============================================================
# 📤 ENVIO DE ARQUIVOS COM RECONEXÃO AUTOMÁTICA
# ============================================================
def garantir_conexao(ftp):
    """
    Testa se a conexão FTP ainda está ativa e tenta reconectar quando necessário.

    Args:
        ftp: Conexão existente (pode estar `None`).

    Returns:
        Uma conexão válida ou `None` quando não foi possível restabelecer o link.
    """
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

def configurar_transferencia(ftp, protecao, modo_passivo):
    """
    Configura parâmetros de transferência antes de cada envio.

    Args:
        ftp: Conexão FTPS ativa.
        protecao: Caracter ("P" ou "C") indicando o nível de proteção TLS.
        modo_passivo: `True` para modo passivo, `False` para ativo.
    """
    # A maioria dos servidores FTPS exige PROT P, por isso o mantemos sempre ativo.
    if protecao == "P":
        ftp.prot_p()

    ftp.set_pasv(modo_passivo)
    ftp.voidcmd("TYPE I")

def enviar_para_ftp(ftp, caminho_arquivo, nome_remoto, max_tentativas=3):
    """
    Envia um arquivo para o FTP e valida o tamanho remoto antes de concluir.

    Se o envio não confirmar o tamanho esperado, a função tenta novamente
    alternando configurações de transferência.

    Args:
        ftp: Conexão FTPS (revalidada internamente a cada tentativa).
        caminho_arquivo: Caminho local completo do arquivo a ser enviado.
        nome_remoto: Nome do arquivo no servidor FTP.
        max_tentativas: Número máximo de tentativas; usa a lista de modos
            de transferência quando o valor é zero ou negativo.

    Returns:
        Uma tupla `(ftp, info)`:
            ftp: Conexão atual (ou `None` se houve falha irrecuperável).
            info: Dicionário com dados do envio (status, tamanhos, detalhes).
    """
    if not os.path.exists(caminho_arquivo):
        info = {
            "arquivo": nome_remoto,
            "caminho_local": caminho_arquivo,
            "tamanho_local": 0,
            "tamanho_remoto": None,
            "tentativas": 0,
            "status": "ignorado",
            "detalhe": "Arquivo local não encontrado",
        }
        print(f"⚠️ Arquivo local não encontrado, pulando: {caminho_arquivo}")
        return ftp, info

    # Obtém o tamanho do arquivo local
    tamanho_local = os.path.getsize(caminho_arquivo)
    print(f"📊 Tamanho do arquivo local: {tamanho_local} bytes")

    info = {
        "arquivo": nome_remoto,
        "caminho_local": caminho_arquivo,
        "tamanho_local": tamanho_local,
        "tamanho_remoto": None,
        "tentativas": 0,
        "status": "pendente",
        "detalhe": "",
    }

    if max_tentativas <= 0:
        max_tentativas = len(MODOS_TRANSFERENCIA)

    for tentativa in range(1, max_tentativas + 1):
        protecao, modo_passivo = MODOS_TRANSFERENCIA[(tentativa - 1) % len(MODOS_TRANSFERENCIA)]
        ftp = garantir_conexao(ftp)
        if not ftp:
            print("❌ Não foi possível obter uma conexão FTP válida.")
            info.update({
                "tentativas": tentativa,
                "status": "falha",
                "detalhe": "Conexão FTP indisponível",
            })
            return None, info

        descricao_modo = "PASSIVO" if modo_passivo else "ATIVO"
        info["tentativas"] = tentativa
        print(f"📡 Iniciando envio de {nome_remoto} (tentativa {tentativa}/{max_tentativas}) "
              f"[modo {descricao_modo} / PROT {protecao}]...")

        try:
            configurar_transferencia(ftp, protecao, modo_passivo)

            with open(caminho_arquivo, "rb") as f:
                ftp.storbinary(f"STOR {nome_remoto}", f, blocksize=65536)

            tamanho_remoto = verificar_arquivo_remoto(ftp, nome_remoto)
            print(f"📏 Tamanho remoto retornado: {tamanho_remoto}")
            if tamanho_remoto == tamanho_local:
                print("✅ Arquivo enviado com sucesso!")
                info.update({
                    "tamanho_remoto": tamanho_remoto,
                    "status": "sucesso",
                    "detalhe": f"Transferido em {tentativa} tentativa(s) usando modo {descricao_modo}",
                })
                return ftp, info

            print(f"⚠️ Tamanho remoto diferente do esperado ({tamanho_remoto} bytes). Tentando novamente...")
            info.update({
                "tamanho_remoto": tamanho_remoto,
                "detalhe": f"Tamanho remoto divergente ({tamanho_remoto} bytes)",
            })
            try:
                ftp.delete(nome_remoto)
                print("🧹 Arquivo remoto removido para nova tentativa.")
            except error_perm:
                pass

        except Exception as e:
            print(f"❌ Falha ao enviar {nome_remoto}: {e}")
            info["detalhe"] = str(e)
            try:
                ftp.close()
            except Exception:
                pass
            ftp = None

        time.sleep(0.5)

    print(f"❌ Não foi possível enviar {nome_remoto} após {max_tentativas} tentativas.")
    if info["status"] != "sucesso":
        info["status"] = "falha"
    return ftp, info


def gravar_relatorio(relatorio, caminho_log):
    """
    Salva um relatório textual com o resultado das transferências.

    Args:
        relatorio: Lista de dicionários produzidos por `enviar_para_ftp`.
        caminho_log: Caminho absoluto do arquivo de log.
    """
    try:
        os.makedirs(os.path.dirname(caminho_log), exist_ok=True)
    except OSError:
        pass

    resumo_sucesso = sum(1 for item in relatorio if item["status"] == "sucesso")
    resumo_falha = sum(1 for item in relatorio if item["status"] == "falha")
    resumo_ignorados = sum(1 for item in relatorio if item["status"] == "ignorado")

    linhas = [
        "====================================================",
        f"Relatório gerado em {datetime.now().isoformat(timespec='seconds')}",
        f"Total processado: {len(relatorio)}"
        f" | Sucesso: {resumo_sucesso}"
        f" | Falha: {resumo_falha}"
        f" | Ignorados: {resumo_ignorados}",
    ]

    for item in relatorio:
        tamanho_remoto = item["tamanho_remoto"]
        info_tamanho = f"{tamanho_remoto} bytes" if tamanho_remoto is not None else "n/d"
        linhas.append(
            f"- {item['status'].upper():8s} | tentativas: {item['tentativas']:2d} "
            f"| local: {item['tamanho_local']:6d} bytes | remoto: {info_tamanho:>8} "
            f"| {item['arquivo']} | {item['detalhe']}"
        )

    linhas.append("")  # separador final

    with open(caminho_log, "a", encoding="utf-8") as f:
        f.write("\n".join(linhas))

# ============================================================
# 📦 EXTRAÇÃO RECURSIVA DE ARQUIVOS ZIP
# ============================================================
def extrair_zip_recursivo(caminho_zip, destino):
    """
    Extrai um arquivo ZIP e trata ZIPs internos recursivamente.

    Args:
        caminho_zip: Caminho do arquivo ZIP que será aberto.
        destino: Pasta onde o conteúdo será extraído.

    Returns:
        `True` quando todas as extrações concluíram sem erro ou `False`
        caso algum ZIP falhe durante o processo.
    """
    try:
        with zipfile.ZipFile(caminho_zip, "r") as zip_ref:
            zip_ref.extractall(destino)
        print(f"📦 Arquivo extraído: {os.path.basename(caminho_zip)}")

        sucesso = True
        # Verifica se há ZIPs dentro do ZIP e os extrai
        for raiz, _, arquivos in os.walk(destino):
            for arquivo in arquivos:
                if arquivo.lower().endswith(".zip"):
                    novo_zip = os.path.join(raiz, arquivo)
                    nova_pasta = os.path.splitext(novo_zip)[0]
                    os.makedirs(nova_pasta, exist_ok=True)
                    print(f"🔁 Arquivo ZIP encontrado dentro de outro ZIP: {arquivo}")
                    if not extrair_zip_recursivo(novo_zip, nova_pasta):
                        sucesso = False

        return sucesso

    except Exception as e:
        print(f"❌ Erro ao extrair {caminho_zip}: {e}")
        return False


def limpar_conteudo_pasta(pasta):
    """
    Remove todos os itens de uma pasta, preservando apenas a pasta raiz.

    Args:
        pasta: Caminho da pasta a ser esvaziada.
    """
    if not os.path.isdir(pasta):
        return

    for nome in os.listdir(pasta):
        caminho = os.path.join(pasta, nome)
        try:
            if os.path.isdir(caminho):
                shutil.rmtree(caminho)
            else:
                os.remove(caminho)
        except Exception as e:
            print(f"⚠️ Não foi possível remover '{caminho}': {e}")


def coletar_arquivos_xml(pasta_raiz):
    """
    Procura XMLs dentro de uma pasta (incluindo subpastas).

    Args:
        pasta_raiz: Caminho a ser varrido.

    Returns:
        Lista ordenada alfabeticamente com dicionários:
            {"caminho": <caminho completo>, "nome_remoto": <apenas o nome>}
    """
    itens = []
    if not os.path.isdir(pasta_raiz):
        return itens

    for raiz, _, arquivos in os.walk(pasta_raiz):
        for arquivo in arquivos:
            if arquivo.lower().endswith(".xml"):
                caminho_arquivo = os.path.join(raiz, arquivo)
                itens.append(
                    {
                        "caminho": caminho_arquivo,
                        "nome_remoto": os.path.basename(caminho_arquivo),
                    }
                )
    itens.sort(key=lambda item: item["caminho"])
    return itens


def remover_diretorios_vazios(caminho, limite):
    """
    Exclui diretórios vazios a partir de um caminho até uma pasta limite.

    Args:
        caminho: Pasta inicial que será avaliada e, se estiver vazia, removida.
        limite: Pasta que serve de limite superior (não é removida).
    """
    caminho_atual = caminho
    limite = os.path.abspath(limite)

    while True:
        caminho_atual = os.path.abspath(caminho_atual)
        if caminho_atual == limite or not caminho_atual.startswith(limite):
            break

        if os.path.isdir(caminho_atual) and not os.listdir(caminho_atual):
            try:
                os.rmdir(caminho_atual)
            except OSError:
                break
            caminho_atual = os.path.dirname(caminho_atual)
        else:
            break


def mover_para_enviados(caminho_origem, raiz_origem, pasta_destino):
    """
    Move o arquivo enviado para a pasta de arquivos já processados.

    Args:
        caminho_origem: Caminho completo do arquivo local que foi enviado.
        raiz_origem: Pasta que representa a raiz da área de envio (usada para
            manter a estrutura relativa).
        pasta_destino: Pasta final onde os arquivos enviados são armazenados.

    Returns:
        Caminho final do arquivo já movido.
    """
    rel_path = os.path.relpath(caminho_origem, raiz_origem)
    destino_final = os.path.join(pasta_destino, rel_path)
    os.makedirs(os.path.dirname(destino_final), exist_ok=True)
    shutil.move(caminho_origem, destino_final)
    remover_diretorios_vazios(os.path.dirname(caminho_origem), raiz_origem)
    return destino_final


def gerar_destino_sem_conflito(pasta_destino, nome_arquivo):
    """
    Gera um caminho final sem sobrescrever arquivos existentes.

    Args:
        pasta_destino: Pasta onde o arquivo será salvo.
        nome_arquivo: Nome desejado para o arquivo.

    Returns:
        Caminho seguro e exclusivo dentro de `pasta_destino`.
    """
    base, ext = os.path.splitext(nome_arquivo)
    destino = os.path.join(pasta_destino, nome_arquivo)
    contador = 1
    while os.path.exists(destino):
        destino = os.path.join(pasta_destino, f"{base}_{contador}{ext}")
        contador += 1
    return destino


def mover_xmls_para_pasta_base(pasta_origem, pasta_destino):
    """
    Move todos os XMLs encontrados em `pasta_origem` (recursivamente)
    para `pasta_destino`, garantindo que fiquem diretamente dentro dela.

    Args:
        pasta_origem: Pasta onde os XMLs foram extraídos.
        pasta_destino: Pasta base `to_send` onde os XMLs devem ficar.

    Returns:
        Uma tupla `(sucesso, total_movidos)`:
            sucesso: `True` se todos os arquivos foram movidos sem erro.
            total_movidos: Quantidade de XMLs encontrados.
    """
    itens = coletar_arquivos_xml(pasta_origem)
    sucesso = True
    for item in itens:
        nome_arquivo = os.path.basename(item["caminho"])
        destino_final = gerar_destino_sem_conflito(pasta_destino, nome_arquivo)
        try:
            os.makedirs(pasta_destino, exist_ok=True)
            shutil.move(item["caminho"], destino_final)
            print(f"📄 {nome_arquivo} movido para {destino_final}")
        except Exception as e:
            sucesso = False
            print(f"⚠️ Falha ao mover {item['caminho']} para {destino_final}: {e}")

    if os.path.abspath(pasta_origem) != os.path.abspath(pasta_destino):
        try:
            shutil.rmtree(pasta_origem)
        except Exception as e:
            sucesso = False
            print(f"⚠️ Não foi possível remover a pasta temporária '{pasta_origem}': {e}")

    return sucesso, len(itens)


def achatar_pasta_xml(pasta_destino):
    """
    Garante que todos os XMLs dentro de `pasta_destino` estejam na raiz da pasta.

    Args:
        pasta_destino: Pasta `to_send` onde os arquivos devem ficar sem subpastas.

    Returns:
        `True` quando todas as subpastas foram tratadas corretamente.
    """
    sucesso_global = True
    for nome in list(os.listdir(pasta_destino)):
        caminho = os.path.join(pasta_destino, nome)
        if os.path.isdir(caminho):
            sucesso, _ = mover_xmls_para_pasta_base(caminho, pasta_destino)
            if not sucesso:
                sucesso_global = False
    return sucesso_global


# ============================================================
# 🧹 LIMPEZA DE ARQUIVOS TEMPORÁRIOS
# ============================================================
def limpar_arquivos_temporarios(pasta):
    """
    Remove por completo uma pasta temporária (caso utilizada).

    Args:
        pasta: Diretório que deve ser excluído.
    """
    try:
        import shutil
        if os.path.exists(pasta):
            shutil.rmtree(pasta)
            print(f"🧹 Pasta temporária removida: {pasta}")
    except Exception as e:
        print(f"⚠️ Erro ao limpar pasta temporária {pasta}: {e}")

# ============================================================
# 🚀 FLUXO PRINCIPAL DE EXECUÇÃO
# ============================================================
def main():
    """
    Fluxo principal do script:
      1️⃣ Prepara as pastas locais necessárias.
      2️⃣ Extrai arquivos ZIP de `CAMINHO_PADRAO` para `CAMINHO_PADRAO_TO_SEND`.
      3️⃣ Limpa `CAMINHO_PADRAO` após extração bem-sucedida.
      4️⃣ Envia os XMLs de `CAMINHO_PADRAO_TO_SEND` para o FTP em lotes de 100 arquivos.
      5️⃣ Move cada arquivo transmitido para `CAMINHO_PADRAO_SEND` e registra o resultado.

    A função também serve como orquestradora: ela decide quando repetir envios,
    monta o relatório final e garante que, caso a execução seja interrompida, os
    arquivos já processados permaneçam organizados para uma futura retomada.
    """
    print("\n🚀 Script iniciado!")
    print("====================================================")

    diretorio_principal = CAMINHO_PADRAO
    print(f"📂 Usando diretório padrão: {diretorio_principal}")

    # Garante que as pastas existam
    os.makedirs(CAMINHO_PADRAO, exist_ok=True)
    os.makedirs(CAMINHO_PADRAO_TO_SEND, exist_ok=True)
    os.makedirs(CAMINHO_PADRAO_SEND, exist_ok=True)

    # Busca os arquivos ZIP
    try:
        arquivos_zip = [
            f for f in os.listdir(diretorio_principal) if f.lower().endswith(".zip")
        ]
    except FileNotFoundError:
        arquivos_zip = []

    if arquivos_zip:
        print(f"🔍 {len(arquivos_zip)} arquivo(s) ZIP encontrado(s) em {diretorio_principal}.")
    else:
        print("ℹ️ Nenhum arquivo ZIP para processar; verificando diretório de envio existente.")

    sucesso_extracoes = True
    for arquivo_zip in arquivos_zip:
        caminho_zip = os.path.join(diretorio_principal, arquivo_zip)
        nome_pasta = os.path.splitext(arquivo_zip)[0]
        destino_extracao = os.path.join(CAMINHO_PADRAO_TO_SEND, nome_pasta)

        if os.path.isdir(destino_extracao):
            try:
                shutil.rmtree(destino_extracao)
            except Exception as e:
                print(f"⚠️ Não foi possível limpar destino '{destino_extracao}': {e}")
        os.makedirs(destino_extracao, exist_ok=True)

        print(f"\n🔹 Processando: {arquivo_zip}")
        if not extrair_zip_recursivo(caminho_zip, destino_extracao):
            sucesso_extracoes = False

        sucesso_movimento, total_movidos = mover_xmls_para_pasta_base(
            destino_extracao, CAMINHO_PADRAO_TO_SEND
        )
        if total_movidos:
            print(f"📥 {total_movidos} XML(s) preparado(s) em {CAMINHO_PADRAO_TO_SEND}.")
        if not sucesso_movimento:
            sucesso_extracoes = False

    if not achatar_pasta_xml(CAMINHO_PADRAO_TO_SEND):
        sucesso_extracoes = False

    if arquivos_zip and sucesso_extracoes:
        print(f"🧹 Limpando conteúdo da pasta de origem: {diretorio_principal}")
        limpar_conteudo_pasta(diretorio_principal)
    elif arquivos_zip and not sucesso_extracoes:
        print("⚠️ Houve falhas durante a extração; o conteúdo original foi mantido para análise manual.")

    itens_envio = coletar_arquivos_xml(CAMINHO_PADRAO_TO_SEND)
    if not itens_envio:
        print(f"⚠️ Nenhum arquivo XML disponível em {CAMINHO_PADRAO_TO_SEND}.")
        return

    print(f"📦 {len(itens_envio)} arquivo(s) preparados para envio a partir de {CAMINHO_PADRAO_TO_SEND}.")

    # Conexão inicial com o FTP
    ftp = conectar_ftp()
    if not ftp:
        print("❌ Não foi possível conectar ao FTP. Encerrando.")
        return

    fila = deque(itens_envio)
    tentativas_por_arquivo = defaultdict(int)
    relatorio_envios = []
    lote_atual = 1

    while fila:
        lote = []
        while fila and len(lote) < 100:
            lote.append(fila.popleft())

        print(f"\n🚚 Processando lote {lote_atual} com {len(lote)} arquivo(s).")

        for item in lote:
            tentativas_por_arquivo[item["caminho"]] += 1
            tentativa_atual = tentativas_por_arquivo[item["caminho"]]

        #teste de reconexão

            if ftp:
                try:
                    ftp.quit()
                except Exception:
                    pass
                ftp = None
            ftp = conectar_ftp()

        #teste de reconexão

            ftp, info_envio = enviar_para_ftp(ftp, item["caminho"], item["nome_remoto"])
            info_envio["tentativas"] = tentativa_atual

            if info_envio["status"] == "sucesso":
                try:
                    destino_movido = mover_para_enviados(
                        item["caminho"], CAMINHO_PADRAO_TO_SEND, CAMINHO_PADRAO_SEND
                    )
                    detalhe_original = info_envio.get("detalhe", "")
                    movimento = f"Movido para {destino_movido}"
                    info_envio["detalhe"] = f"{detalhe_original} | {movimento}".strip(" |")
                    info_envio["caminho_local"] = destino_movido
                    print(f"📁 {item['nome_remoto']} movido para {destino_movido}")
                except Exception as e:
                    detalhe_original = info_envio.get("detalhe", "")
                    info_envio["detalhe"] = f"{detalhe_original} | falha ao mover: {e}".strip(" |")
                    print(
                        f"⚠️ Não foi possível mover {item['caminho']} para {CAMINHO_PADRAO_SEND}: {e}")

                relatorio_envios.append(info_envio)
            elif info_envio["status"] == "ignorado":
                relatorio_envios.append(info_envio)
            else:
                if tentativa_atual < MAX_REPROCESSOS:
                    detalhe = info_envio.get("detalhe", "")
                    info_envio["detalhe"] = f"{detalhe} | reagendado para nova tentativa".strip(" |")
                    print(
                        f"🔁 Reagendando {item['nome_remoto']} para nova tentativa "
                        f"({tentativa_atual + 1}/{MAX_REPROCESSOS})."
                    )
                    fila.append(item)
                else:
                    print(f"⛔️ Tentativas esgotadas para {item['nome_remoto']}.")
                    relatorio_envios.append(info_envio)

        lote_atual += 1

#CONTADOR

#        if lote_atual % 50 == 0 and lote_atual != 0:
#                print("🔄 Reconectando ao servidor FTP para evitar timeout...")
#                if ftp:
#                    try:
#                        ftp.quit()
#                    except Exception:
#                        pass
#                    ftp = None
#                ftp = conectar_ftp()

#CONTADOR

    if ftp:
        try:
            ftp.quit()
            print("\n✅ Conexão encerrada com sucesso.")
        except Exception:
            print("\n⚠️ Não foi possível encerrar a conexão FTP normalmente.")
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    if relatorio_envios:
        gravar_relatorio(relatorio_envios, CAMINHO_LOG)
        print("\n📝 Relatório gravado em:", CAMINHO_LOG)
        sucesso = sum(1 for item in relatorio_envios if item["status"] == "sucesso")
        falha = sum(1 for item in relatorio_envios if item["status"] == "falha")
        ignorados = sum(1 for item in relatorio_envios if item["status"] == "ignorado")
        print(f"- ✅ Sucesso: {sucesso}")
        print(f"- ❌ Falha: {falha}")
        print(f"- ⚠️ Ignorados: {ignorados}")
        if falha > 0:
            print("⚠️ Reexecute o script para tentar novamente os arquivos com falha (limite atual de reprocessos atingido).")

    print("\n✅ Processo concluído com sucesso!")
    print("====================================================")

# ============================================================
# ▶️ PONTO DE ENTRADA
# ============================================================
if __name__ == "__main__":
    main()

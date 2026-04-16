#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <sys/stat.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 8192
#define TIMEOUT_MS 3000
#define MAX_RETRIES 50
#define HANDSHAKE_RETRIES 5

struct ClientConfig {
    std::string identity;
    std::string key;
};

ClientConfig g_clientConfig;

std::string trim(const std::string& value) {
    std::size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    std::size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string exeDir() {
    char path[MAX_PATH]{};
    DWORD len = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return ".";
    std::string full(path, len);
    std::size_t slash = full.find_last_of("\\/");
    return slash == std::string::npos ? "." : full.substr(0, slash);
}

bool openConfig(const char* name, std::ifstream& file) {
    file.open(name);
    if (file) return true;
    file.clear();
    file.open(exeDir() + "\\" + name);
    return (bool)file;
}

std::string envValue(const char* name) {
    char* value = nullptr;
    std::size_t len = 0;
    if (_dupenv_s(&value, &len, name) != 0 || !value) return "";
    std::string result(value);
    free(value);
    return result;
}

bool loadClientConfig() {
    std::string envIdentity = envValue("DTLS_PSK_IDENTITY");
    std::string envKey = envValue("DTLS_PSK_KEY");
    if (!envIdentity.empty() && !envKey.empty()) {
        g_clientConfig.identity = envIdentity;
        g_clientConfig.key = envKey;
        return true;
    }

    std::ifstream file;
    if (!openConfig("psk_client.txt", file)) {
        std::cerr << "Configuration PSK introuvable: psk_client.txt\n";
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        std::size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq));
        std::string value = trim(line.substr(eq + 1));
        if (key == "identity") g_clientConfig.identity = value;
        if (key == "key") g_clientConfig.key = value;
    }

    if (g_clientConfig.identity.empty() || g_clientConfig.key.empty()) {
        std::cerr << "psk_client.txt doit contenir identity=... et key=...\n";
        return false;
    }
    return true;
}

std::string baseName(const char* filename) {
    std::string path(filename ? filename : "");
    std::size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

bool isDirectory(const std::string& path) {
    struct _stat info {};
    return _stat(path.c_str(), &info) == 0 && (info.st_mode & _S_IFDIR);
}

std::string joinPath(const std::string& dir, const std::string& name) {
    if (dir.empty()) return name;
    char last = dir[dir.size() - 1];
    if (last == '\\' || last == '/') return dir + name;
    return dir + "\\" + name;
}

std::string receivePath(const char* requested, const std::string& originalName) {
    std::string path(requested ? requested : "");
    if (!path.empty() && (path[path.size() - 1] == '\\' || path[path.size() - 1] == '/')) {
        return joinPath(path, originalName.empty() ? "fichier_recu.bin" : originalName);
    }
    if (isDirectory(path)) {
        return joinPath(path, originalName.empty() ? "fichier_recu.bin" : originalName);
    }
    return path;
}

#pragma pack(push, 1)
// En-tete commun a tous les messages applicatifs envoyes dans le tunnel DTLS.
// op  : type du message ('P'=put/debut envoi, 'G'=get/demande, 'S'=taille,
//       'D'=bloc de donnees, 'A'=ack, 'E'=erreur serveur).
// seq : numero du bloc, ou taille totale selon le type de message.
// len : nombre d'octets utiles qui suivent l'en-tete.
struct MsgHeader {
    char op;
    std::uint64_t seq;
    std::uint32_t len;
};
#pragma pack(pop)

std::uint64_t swap64(std::uint64_t v) {
    return ((v & 0x00000000000000ffULL) << 56) | ((v & 0x000000000000ff00ULL) << 40) |
           ((v & 0x0000000000ff0000ULL) << 24) | ((v & 0x00000000ff000000ULL) << 8) |
           ((v & 0x000000ff00000000ULL) >> 8)  | ((v & 0x0000ff0000000000ULL) >> 24) |
           ((v & 0x00ff000000000000ULL) >> 40) | ((v & 0xff00000000000000ULL) >> 56);
}

std::uint64_t net64(std::uint64_t v) {
    static const int x = 1;
    // Les entiers envoyes sur le reseau doivent avoir le meme ordre d'octets
    // sur toutes les machines. On convertit donc les 64 bits si le PC est little-endian.
    return (*(const char*)&x) ? swap64(v) : v;
}

void dieSSL() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void printSSLError(const char* where, SSL* ssl, int ret) {
    std::cerr << where << " SSL_get_error=" << SSL_get_error(ssl, ret)
        << " WSA=" << WSAGetLastError() << "\n";
    ERR_print_errors_fp(stderr);
}

bool retrySSL(int err) {
    int wsa = WSAGetLastError();
    // UDP/DTLS peut ne rien recevoir immediatement. Ces erreurs indiquent
    // qu'on peut reessayer au lieu de considerer la connexion comme morte.
    return err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ||
        (err == SSL_ERROR_SYSCALL && (wsa == 0 || wsa == WSAETIMEDOUT || wsa == WSAEWOULDBLOCK));
}

// Callback appele par OpenSSL pendant le handshake DTLS-PSK.
// Il donne l'identite du client et la cle partagee. Le serveur compare ensuite
// ces valeurs pour verifier que le client parle bien avec un pair autorise.
unsigned int psk_client_cb(SSL*, const char*, char* identity, unsigned int max_identity_len,
    unsigned char* psk, unsigned int max_psk_len)
{
    const char* id = g_clientConfig.identity.c_str();
    const char* key = g_clientConfig.key.c_str();
    unsigned int id_len = (unsigned int)g_clientConfig.identity.size();
    unsigned int psk_len = (unsigned int)g_clientConfig.key.size();
    if (id_len + 1 > max_identity_len || psk_len > max_psk_len) return 0;
    memcpy(identity, id, id_len + 1);
    memcpy(psk, key, psk_len);
    return psk_len;
}

bool sendMsg(SSL* ssl, char op, std::uint64_t seq, const char* data = nullptr, std::uint32_t len = 0) {
    if (len > BUFFER_SIZE) return false;
    char packet[sizeof(MsgHeader) + BUFFER_SIZE];
    MsgHeader h{ op, net64(seq), htonl(len) };
    // On construit un paquet applicatif: en-tete + donnees.
    // SSL_write chiffre et authentifie ce paquet dans la session DTLS.
    memcpy(packet, &h, sizeof(h));
    if (len) memcpy(packet + sizeof(h), data, len);
    int total = (int)(sizeof(h) + len);
    int r = SSL_write(ssl, packet, total);
    return r == total;
}

int readMsg(SSL* ssl, MsgHeader& h, std::vector<char>& data) {
    char packet[sizeof(MsgHeader) + BUFFER_SIZE];
    int r = SSL_read(ssl, packet, sizeof(packet));
    if (r <= 0) {
        int e = SSL_get_error(ssl, r);
        if (retrySSL(e)) return 0;
        return -1;
    }
    if (r < (int)sizeof(MsgHeader)) return -1;
    memcpy(&h, packet, sizeof(h));
    // Conversion inverse: les champs reseau redeviennent utilisables par le CPU local.
    h.seq = net64(h.seq);
    h.len = ntohl(h.len);
    if (h.len > BUFFER_SIZE || r != (int)(sizeof(MsgHeader) + h.len)) return -1;
    data.assign(packet + sizeof(MsgHeader), packet + r);
    return 1;
}

bool waitAck(SSL* ssl, std::uint64_t seq) {
    // Chaque bloc important attend un accuse de reception portant le meme numero.
    // C'est la partie "fiabilite" ajoutee au-dessus d'UDP.
    for (;;) {
        MsgHeader h{};
        std::vector<char> data;
        int r = readMsg(ssl, h, data);
        if (r == 0) return false;
        if (r < 0) return false;
        if (h.op == 'A' && h.seq == seq) return true;
    }
}

bool sendReliable(SSL* ssl, char op, std::uint64_t seq, const char* data = nullptr, std::uint32_t len = 0) {
    // UDP ne garantit pas l'arrivee des paquets. On renvoie donc le meme bloc
    // jusqu'a recevoir son ACK ou jusqu'a atteindre la limite d'essais.
    for (int i = 0; i < MAX_RETRIES; ++i) {
        if (!sendMsg(ssl, op, seq, data, len)) return false;
        if (waitAck(ssl, seq)) return true;
        std::cout << "Nouvel essai bloc " << seq << "\n";
    }
    return false;
}

bool putFile(SSL* ssl, const char* filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) { std::cerr << "Impossible d'ouvrir le fichier\n"; return false; }
    std::uint64_t total = (std::uint64_t)file.tellg();
    file.seekg(0, std::ios::beg);

    // Mode envoi: le client annonce la taille totale et transmet le nom original.
    std::string originalName = baseName(filename);
    if (originalName.empty()) originalName = "fichier_recu.bin";
    if (originalName.size() > BUFFER_SIZE) originalName.resize(BUFFER_SIZE);
    if (!sendReliable(ssl, 'P', total, originalName.data(), (std::uint32_t)originalName.size())) return false;
    std::cout << "Nom original envoye: " << originalName << "\n";

    char buffer[BUFFER_SIZE];
    std::uint64_t seq = 0, sent = 0;
    while (file) {
        file.read(buffer, BUFFER_SIZE);
        std::streamsize n = file.gcount();
        if (n <= 0) break;
        // Ensuite il envoie le fichier par blocs numerotes.
        if (!sendReliable(ssl, 'D', seq, buffer, (std::uint32_t)n)) return false;
        sent += (std::uint64_t)n;
        if ((seq++ % 1024) == 0) std::cout << "\rEnvoye: " << sent << "/" << total << std::flush;
    }
    std::cout << "\rEnvoye: " << sent << "/" << total << "\n";
    return sent == total;
}

bool getSize(SSL* ssl, std::uint64_t& total, std::string& originalName) {
    for (int i = 0; i < MAX_RETRIES; ++i) {
        // Mode reception: le client demande au serveur d'envoyer le fichier stocke.
        if (!sendMsg(ssl, 'G', 0)) return false;
        for (;;) {
            MsgHeader h{};
            std::vector<char> data;
            int r = readMsg(ssl, h, data);
            if (r == 0) break;
            if (r < 0) return false;
            if (h.op == 'E') { std::cerr << std::string(data.begin(), data.end()) << "\n"; return false; }
            if (h.op == 'S') {
                // Le serveur repond avec la taille totale et le nom original.
                total = h.seq;
                originalName.assign(data.begin(), data.end());
                if (originalName.empty()) originalName = "fichier_recu.bin";
                return sendMsg(ssl, 'A', total);
            }
        }
    }
    return false;
}

bool getFile(SSL* ssl, const char* filename) {
    std::uint64_t total = 0;
    std::string originalName;
    if (!getSize(ssl, total, originalName)) return false;

    // Le protocole transporte maintenant le nom original. Si la destination est
    // un dossier, le client reconstruit le fichier avec ce nom et son extension.
    std::string outputPath = receivePath(filename, originalName);
    std::ofstream file(outputPath, std::ios::binary);
    if (!file) { std::cerr << "Impossible de creer le fichier\n"; return false; }
    std::cout << "Nom original recu: " << originalName << "\n";
    std::cout << "Fichier recu enregistre: " << outputPath << "\n";

    std::uint64_t seq = 0, got = 0;
    int idle = 0;
    while (got < total) {
        MsgHeader h{};
        std::vector<char> data;
        int r = readMsg(ssl, h, data);
        if (r == 0) { if (++idle > MAX_RETRIES) return false; continue; }
        if (r < 0) return false;
        idle = 0;

        if (h.op == 'S') { sendMsg(ssl, 'A', h.seq); continue; }
        if (h.op != 'D') continue;
        if (h.seq == seq && h.len <= total - got) {
            // On accepte seulement le bloc attendu. Les doublons sont accuses
            // de reception mais ne sont pas reecrits dans le fichier.
            file.write(data.data(), h.len);
            got += h.len;
            sendMsg(ssl, 'A', h.seq);
            if ((seq++ % 1024) == 0) std::cout << "\rRecu: " << got << "/" << total << std::flush;
        } else if (h.seq < seq) {
            sendMsg(ssl, 'A', h.seq);
        }
    }
    std::cout << "\rRecu: " << got << "/" << total << "\n";
    return true;
}

bool connectDTLS(SSL* ssl) {
    // Handshake DTLS: negotiation du chiffrement et verification de la cle PSK.
    // Si la cle ou l'identite ne correspondent pas, la session ne s'etablit pas.
    for (int i = 0; i < HANDSHAKE_RETRIES; ++i) {
        int r = SSL_connect(ssl);
        if (r == 1) return true;
        int e = SSL_get_error(ssl, r);
        if (!retrySSL(e)) { printSSLError("SSL_connect", ssl, r); return false; }
    }
    return false;
}

int main(int argc, char* argv[]) {
    if (argc != 4 && argc != 5) {
        std::cout << "Usage:\n  client.exe <IP> <PORT> <FILE>\n  client.exe <IP> <PORT> put <FILE>\n  client.exe <IP> <PORT> get <FILE>\n";
        return 1;
    }

    const char* server_ip = argv[1];
    int port = atoi(argv[2]);
    bool getMode = (argc == 5 && strcmp(argv[3], "get") == 0);
    bool putMode = (argc == 4 || (argc == 5 && strcmp(argv[3], "put") == 0));
    const char* filename = (argc == 4) ? argv[3] : argv[4];
    if (!getMode && !putMode) { std::cerr << "Mode invalide: utilisez put ou get\n"; return 1; }
    if (!loadClientConfig()) return 1;
    std::cout << "Identite PSK client: " << g_clientConfig.identity << "\n";

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { std::cerr << "WSAStartup failed\n"; return 1; }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) { std::cerr << "Socket failed\n"; return 1; }

    DWORD timeout = TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    // Le client sait a quel serveur parler grace a l'IP et au port entres dans l'interface.
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &serverAddr.sin_addr);
    connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));

    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX* ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) dieSSL();
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);
    // Suite unique autorisee: DTLS-PSK avec AES-256-GCM et SHA-384.
    // Si le serveur ne supporte pas exactement cette suite, le handshake echoue.
    SSL_CTX_set_cipher_list(ctx, "PSK-AES256-GCM-SHA384");
    SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);

    SSL* ssl = SSL_new(ctx);
    BIO* bio = BIO_new_dgram((int)sock, BIO_NOCLOSE);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &serverAddr);
    SSL_set_bio(ssl, bio, bio);

    if (!connectDTLS(ssl)) dieSSL();
    std::cout << "Connexion DTLS PSK etablie.\n";
    std::cout << "Suite DTLS negociee: " << SSL_get_cipher(ssl) << "\n";

    // Le meme executable sert aux deux sens: put envoie vers le serveur, get recupere
    // depuis le serveur vers un fichier local choisi par l'utilisateur.
    bool ok = getMode ? getFile(ssl, filename) : putFile(ssl, filename);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(sock);
    WSACleanup();

    std::cout << (ok ? "Transfert termine.\n" : "Transfert echoue.\n");
    return ok ? 0 : 1;
}

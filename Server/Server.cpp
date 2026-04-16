#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <ctime>
#include <direct.h>
#include <sys/stat.h>

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT 4444
#define BUFFER_SIZE 8192
#define TIMEOUT_MS 3000
#define MAX_RETRIES 50
#define HANDSHAKE_RETRIES 5

const char* STORAGE_DIR = "stored_files";
const char* LATEST_FILE = "stored_files\\latest.txt";
const char* LEGACY_STORED_FILE = "received_file.bin";

struct UserConfig {
    std::string key;
    bool canPut = true;
    bool canGet = true;
};

struct StoredFile {
    std::string path;
    std::string originalName;
    std::string owner;
};

std::map<std::string, UserConfig> g_users;
std::string g_currentIdentity;

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

bool hasPermission(const std::string& token, const char* expected) {
    return token == expected || token == "all" || token == "*";
}

bool loadServerConfig() {
    std::ifstream file;
    if (!openConfig("psk_clients.txt", file)) {
        std::cerr << "Configuration PSK introuvable: psk_clients.txt\n";
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        std::size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string identity = trim(line.substr(0, eq));
        std::string rest = trim(line.substr(eq + 1));
        std::stringstream ss(rest);
        std::string part;
        std::vector<std::string> parts;
        while (std::getline(ss, part, ',')) parts.push_back(trim(part));
        if (identity.empty() || parts.empty() || parts[0].empty()) continue;

        UserConfig user;
        user.key = parts[0];
        if (parts.size() > 1) {
            user.canPut = false;
            user.canGet = false;
            for (std::size_t i = 1; i < parts.size(); ++i) {
                if (hasPermission(parts[i], "put")) user.canPut = true;
                if (hasPermission(parts[i], "get")) user.canGet = true;
            }
        }
        g_users[identity] = user;
    }

    if (g_users.empty()) {
        std::cerr << "psk_clients.txt ne contient aucun utilisateur valide\n";
        return false;
    }
    return true;
}

const UserConfig* currentUser() {
    auto it = g_users.find(g_currentIdentity);
    return it == g_users.end() ? nullptr : &it->second;
}

bool ensureStorageDir() {
    struct _stat info {};
    if (_stat(STORAGE_DIR, &info) == 0 && (info.st_mode & _S_IFDIR)) return true;
    return _mkdir(STORAGE_DIR) == 0 || errno == EEXIST;
}

bool fileExists(const std::string& path) {
    struct _stat info {};
    return _stat(path.c_str(), &info) == 0;
}

std::string sanitizeName(const std::string& raw) {
    std::string name = raw;
    std::size_t slash = name.find_last_of("\\/");
    if (slash != std::string::npos) name = name.substr(slash + 1);
    std::string clean;
    for (char ch : name) {
        unsigned char c = (unsigned char)ch;
        if (c < 32 || ch == '<' || ch == '>' || ch == ':' || ch == '"' ||
            ch == '/' || ch == '\\' || ch == '|' || ch == '?' || ch == '*') {
            clean.push_back('_');
        } else {
            clean.push_back(ch);
        }
    }
    clean = trim(clean);
    if (clean.empty() || clean == "." || clean == "..") clean = "fichier_recu.bin";
    if (clean.size() > 120) clean.resize(120);
    return clean;
}

std::string timestamp() {
    std::time_t now = std::time(nullptr);
    std::tm tm {};
    localtime_s(&tm, &now);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y%m%d_%H%M%S");
    return out.str();
}

std::string uniqueStoredPath(const std::string& owner, const std::string& originalName) {
    std::string safeOwner = sanitizeName(owner);
    std::string safeName = sanitizeName(originalName);
    std::string prefix = std::string(STORAGE_DIR) + "\\" + timestamp() + "_" + safeOwner + "_";
    std::string path = prefix + safeName;
    for (int i = 1; fileExists(path); ++i) {
        path = prefix + std::to_string(i) + "_" + safeName;
    }
    return path;
}

void writeLatest(const StoredFile& file) {
    std::ofstream latest(LATEST_FILE, std::ios::trunc);
    latest << file.path << "\n" << file.originalName << "\n" << file.owner << "\n";
}

bool loadLatest(StoredFile& file) {
    std::ifstream latest(LATEST_FILE);
    if (latest) {
        std::getline(latest, file.path);
        std::getline(latest, file.originalName);
        std::getline(latest, file.owner);
        file.path = trim(file.path);
        file.originalName = sanitizeName(trim(file.originalName));
        file.owner = trim(file.owner);
        return !file.path.empty() && fileExists(file.path);
    }
    if (fileExists(LEGACY_STORED_FILE)) {
        file.path = LEGACY_STORED_FILE;
        file.originalName = LEGACY_STORED_FILE;
        file.owner = "legacy";
        return true;
    }
    return false;
}

#pragma pack(push, 1)
// En-tete du protocole applicatif. Il est identique cote client et cote serveur.
// op  : 'P'=un client depose un fichier, 'G'=un client demande le fichier,
//       'S'=taille du fichier, 'D'=bloc de donnees, 'A'=ack, 'E'=erreur.
// seq : numero de bloc, ou taille totale selon le type.
// len : longueur des donnees placees apres l'en-tete.
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
    // Meme representation reseau pour tous les PC, meme si leur CPU range
    // les octets dans un ordre different.
    return (*(const char*)&x) ? swap64(v) : v;
}

void printSSL() {
    ERR_print_errors_fp(stderr);
}

void printSSLError(const char* where, SSL* ssl, int ret) {
    std::cerr << where << " SSL_get_error=" << SSL_get_error(ssl, ret)
        << " WSA=" << WSAGetLastError() << "\n";
    ERR_print_errors_fp(stderr);
}

bool retrySSL(int err) {
    int wsa = WSAGetLastError();
    // Un timeout UDP n'est pas forcement fatal. DTLS peut demander de reessayer.
    return err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ||
        (err == SSL_ERROR_SYSCALL && (wsa == 0 || wsa == WSAETIMEDOUT || wsa == WSAEWOULDBLOCK));
}

// Callback serveur DTLS-PSK. Le serveur accepte seulement les identites
// declarees dans psk_clients.txt et remet a OpenSSL la cle correspondante.
unsigned int psk_server_cb(SSL*, const char* identity, unsigned char* psk, unsigned int max_psk_len) {
    if (!identity) return 0;
    auto it = g_users.find(identity);
    if (it == g_users.end()) return 0;
    unsigned int psk_len = (unsigned int)it->second.key.size();
    if (psk_len > max_psk_len) return 0;
    memcpy(psk, it->second.key.data(), psk_len);
    g_currentIdentity = identity;
    return psk_len;
}

int makeCookie(SSL*, unsigned char* cookie, unsigned int* cookie_len) {
    // Cookie DTLS: evite qu'un faux client force le serveur a allouer trop de ressources
    // avant d'avoir prouve qu'il peut recevoir les reponses a son adresse.
    const char* value = "simple-dtls-cookie";
    *cookie_len = (unsigned int)strlen(value);
    memcpy(cookie, value, *cookie_len);
    return 1;
}

int checkCookie(SSL*, const unsigned char* cookie, unsigned int cookie_len) {
    const char* value = "simple-dtls-cookie";
    return cookie_len == strlen(value) && memcmp(cookie, value, cookie_len) == 0;
}

bool sendMsg(SSL* ssl, char op, std::uint64_t seq, const char* data = nullptr, std::uint32_t len = 0) {
    if (len > BUFFER_SIZE) return false;
    char packet[sizeof(MsgHeader) + BUFFER_SIZE];
    MsgHeader h{ op, net64(seq), htonl(len) };
    // DTLS protege ensuite ce paquet: confidentialite, integrite et controle du pair PSK.
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
    // On decode l'en-tete recu avant d'utiliser le numero de bloc et la taille.
    h.seq = net64(h.seq);
    h.len = ntohl(h.len);
    if (h.len > BUFFER_SIZE || r != (int)(sizeof(MsgHeader) + h.len)) return -1;
    data.assign(packet + sizeof(MsgHeader), packet + r);
    return 1;
}

bool waitAck(SSL* ssl, std::uint64_t seq) {
    // Le serveur attend l'ACK correspondant au bloc envoye pour eviter de perdre
    // des donnees sur UDP.
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
    // Couche de fiabilite simple: repetition jusqu'a reception de l'ACK.
    for (int i = 0; i < MAX_RETRIES; ++i) {
        if (!sendMsg(ssl, op, seq, data, len)) return false;
        if (waitAck(ssl, seq)) return true;
        std::cout << "Nouvel essai bloc " << seq << "\n";
    }
    return false;
}

bool receiveFile(SSL* ssl, std::uint64_t total, const std::string& originalName, const std::string& owner) {
    // Quand un client fait "put", le serveur conserve le fichier dans stored_files
    // avec son nom original et sans ecraser les fichiers deja recus.
    if (!ensureStorageDir()) {
        std::cerr << "Impossible de creer le dossier de stockage\n";
        return false;
    }
    StoredFile stored{ uniqueStoredPath(owner, originalName), sanitizeName(originalName), owner };
    std::ofstream file(stored.path, std::ios::binary);
    if (!file) { std::cerr << "Impossible d'ecrire le fichier\n"; return false; }

    std::uint64_t seq = 0, got = 0;
    int idle = 0;
    while (got < total) {
        MsgHeader h{};
        std::vector<char> data;
        int r = readMsg(ssl, h, data);
        if (r == 0) { if (++idle > MAX_RETRIES) return false; continue; }
        if (r < 0) return false;
        idle = 0;

        if (h.op == 'P') { sendMsg(ssl, 'A', h.seq); continue; }
        if (h.op != 'D') continue;
        if (h.seq == seq && h.len <= total - got) {
            // Ecriture dans l'ordre: le bloc attendu est ajoute au fichier.
            file.write(data.data(), h.len);
            got += h.len;
            sendMsg(ssl, 'A', h.seq);
            if ((seq++ % 1024) == 0) std::cout << "\rRecu: " << got << "/" << total << std::flush;
        } else if (h.seq < seq) {
            sendMsg(ssl, 'A', h.seq);
        }
    }
    std::cout << "\rRecu: " << got << "/" << total << "\n";
    file.close();
    writeLatest(stored);
    std::cout << "Fichier stocke: " << stored.path << "\n";
    std::cout << "Nom original: " << stored.originalName << "\n";
    std::cout << "Proprietaire: " << stored.owner << "\n";
    return true;
}

bool acceptDTLS(SSL* ssl) {
    // Termine le handshake cote serveur. Sans PSK valide, la session echoue.
    for (int i = 0; i < HANDSHAKE_RETRIES; ++i) {
        int r = SSL_accept(ssl);
        if (r == 1) return true;
        int e = SSL_get_error(ssl, r);
        if (!retrySSL(e)) { printSSLError("SSL_accept", ssl, r); return false; }
    }
    return false;
}

bool sendFile(SSL* ssl) {
    // Quand un client fait "get", le serveur renvoie le dernier fichier stocke.
    StoredFile stored;
    if (!loadLatest(stored)) {
        const char* msg = "Aucun fichier sur le serveur";
        sendMsg(ssl, 'E', 0, msg, (std::uint32_t)strlen(msg));
        return false;
    }

    std::ifstream file(stored.path, std::ios::binary | std::ios::ate);
    if (!file) {
        const char* msg = "Aucun fichier sur le serveur";
        sendMsg(ssl, 'E', 0, msg, (std::uint32_t)strlen(msg));
        return false;
    }
    std::uint64_t total = (std::uint64_t)file.tellg();
    file.seekg(0, std::ios::beg);

    // Le serveur annonce d'abord la taille totale et le nom original, puis envoie les blocs.
    if (!sendReliable(ssl, 'S', total, stored.originalName.data(), (std::uint32_t)stored.originalName.size())) return false;
    std::cout << "Fichier redistribue: " << stored.path << "\n";
    std::cout << "Nom original: " << stored.originalName << "\n";

    char buffer[BUFFER_SIZE];
    std::uint64_t seq = 0, sent = 0;
    while (file) {
        file.read(buffer, BUFFER_SIZE);
        std::streamsize n = file.gcount();
        if (n <= 0) break;
        if (!sendReliable(ssl, 'D', seq, buffer, (std::uint32_t)n)) return false;
        sent += (std::uint64_t)n;
        if ((seq++ % 1024) == 0) std::cout << "\rEnvoye: " << sent << "/" << total << std::flush;
    }
    std::cout << "\rEnvoye: " << sent << "/" << total << "\n";
    return sent == total;
}

SOCKET makeServerSocket(int port) {
    // Socket UDP classique: DTLS ajoute la securite au-dessus de ce transport.
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons((u_short)port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    std::cout << "Serveur DTLS PSK en attente sur le port " << port << "...\n";
    DWORD timeout = TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    return sock;
}

bool listenDTLS(SSL* ssl, BIO* bio) {
    BIO_ADDR* client = BIO_ADDR_new();
    if (!client) return false;

    for (;;) {
        // DTLSv1_listen attend un client et gere l'echange de cookie avant
        // de connecter le socket UDP a l'adresse du client.
        int r = DTLSv1_listen(ssl, client);
        if (r > 0) {
            int fd = -1;
            BIO_get_fd(bio, &fd);
            if (fd < 0 || BIO_connect(fd, client, 0) == 0) {
                BIO_ADDR_free(client);
                return false;
            }
            BIO_ctrl_set_connected(bio, client);
            BIO_ADDR_free(client);
            return true;
        }
        if (r < 0) {
            BIO_ADDR_free(client);
            return false;
        }
    }
}

bool handleSession(SSL* ssl) {
    // Une session traite une seule operation: depot de fichier (P) ou demande (G).
    for (;;) {
        MsgHeader h{};
        std::vector<char> data;
        int r = readMsg(ssl, h, data);
        if (r == 0) continue;
        if (r < 0) return false;

        if (h.op == 'P') {
            const UserConfig* user = currentUser();
            if (!user || !user->canPut) {
                const char* msg = "Acces refuse: droit put manquant";
                sendMsg(ssl, 'E', 0, msg, (std::uint32_t)strlen(msg));
                return false;
            }
            // A veut envoyer un fichier au serveur: h.seq contient la taille totale.
            sendMsg(ssl, 'A', h.seq);
            std::string originalName(data.begin(), data.end());
            if (originalName.empty()) originalName = "fichier_recu.bin";
            std::cout << "Reception de " << h.seq << " octets.\n";
            std::cout << "Utilisateur: " << g_currentIdentity << "\n";
            return receiveFile(ssl, h.seq, originalName, g_currentIdentity);
        }
        if (h.op == 'G') {
            const UserConfig* user = currentUser();
            if (!user || !user->canGet) {
                const char* msg = "Acces refuse: droit get manquant";
                sendMsg(ssl, 'E', 0, msg, (std::uint32_t)strlen(msg));
                return false;
            }
            // B veut recevoir le dernier fichier stocke sur le serveur.
            std::cout << "Envoi du fichier stocke.\n";
            std::cout << "Utilisateur: " << g_currentIdentity << "\n";
            return sendFile(ssl);
        }
    }
}

int main(int argc, char* argv[]) {
    int port = (argc >= 2) ? atoi(argv[1]) : DEFAULT_PORT;
    if (port <= 0 || port > 65535) {
        std::cerr << "Port invalide\n";
        return 1;
    }
    if (!loadServerConfig()) return 1;
    std::cout << "Utilisateurs PSK charges: " << g_users.size() << "\n";

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { std::cerr << "WSAStartup failed\n"; return 1; }

    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX* ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) { printSSL(); return 1; }
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);
    // Suite unique autorisee: DTLS-PSK avec AES-256-GCM et SHA-384.
    // Si le client ne supporte pas exactement cette suite, le handshake echoue.
    SSL_CTX_set_cipher_list(ctx, "PSK-AES256-GCM-SHA384");
    SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE);
    SSL_CTX_set_cookie_generate_cb(ctx, makeCookie);
    SSL_CTX_set_cookie_verify_cb(ctx, checkCookie);
    SSL_CTX_set_psk_server_callback(ctx, psk_server_cb);

    for (;;) {
        // Boucle principale: apres chaque client, le serveur se remet en attente
        // pour accepter une nouvelle operation.
        SOCKET sock = makeServerSocket(port);
        if (sock == INVALID_SOCKET) { std::cerr << "Socket/bind failed\n"; break; }

        SSL* ssl = SSL_new(ctx);
        BIO* bio = BIO_new_dgram((int)sock, BIO_NOCLOSE);
        SSL_set_bio(ssl, bio, bio);
        SSL_set_accept_state(ssl);
        g_currentIdentity.clear();

        if (!listenDTLS(ssl, bio) || !acceptDTLS(ssl)) {
            printSSL();
        } else {
            std::cout << "Client connecte.\n";
            std::cout << "Suite DTLS negociee: " << SSL_get_cipher(ssl) << "\n";
            std::cout << (handleSession(ssl) ? "Session terminee.\n" : "Session echouee.\n");
            SSL_shutdown(ssl);
        }

        SSL_free(ssl);
        closesocket(sock);
    }

    SSL_CTX_free(ctx);
    WSACleanup();
    return 0;
}

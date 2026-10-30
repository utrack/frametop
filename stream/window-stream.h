// Experimental direct KWin windows. Included after Viewer in ft-stream.cpp.
// Reuses Sunshine's paired client certificate and Frametop's stored server key pin.
// Wire format: type byte + big-endian uint32 length + payload. J = JSON,
// V = one HEVC Annex-B access unit, C = an existing ft-screens input message.
// The host service is host/linux/windows/ft_window_host.py.

constexpr size_t kWindowMaxFrame = 4u << 20;
constexpr int kWindowPort = 14501;

struct WindowPacket {
    char type;
    std::vector<uint8_t> data;
};

struct WindowPeer {
    int fd = -1;
    SSL_CTX *context = nullptr;
    SSL *tls = nullptr;
    std::vector<uint8_t> incoming;
    std::deque<std::string> outgoing;
    size_t written = 0, queued = 0;
    bool readNeedsWrite = false;

    ~WindowPeer() {
        if (tls) SSL_free(tls);
        if (context) SSL_CTX_free(context);
        if (fd >= 0) close(fd);
    }

    void Connect(const Client &client) {
        std::string expected;
        std::ifstream pin(KeyDir("hosts") + "/" + g_host + ".pin");
        if (!(pin >> expected) || expected.rfind("sha256//", 0) != 0)
            throw std::runtime_error("pair this host in Remote Displays first (no server key pin)");
        context = SSL_CTX_new(TLS_client_method());
        if (!context) throw std::runtime_error("cannot create TLS context");
        SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION);
        // The self-signed server is authenticated by its existing public-key pin below.
        SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nullptr);
        if (SSL_CTX_use_certificate_file(context, (client.dir + "/client.pem").c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(context, (client.dir + "/key.pem").c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(context) != 1)
            throw std::runtime_error("cannot load this paired client's certificate");
        addrinfo hints{}, *addresses = nullptr;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(client.host.c_str(), std::to_string(kWindowPort).c_str(), &hints, &addresses))
            throw std::runtime_error("cannot resolve the window host");
        for (const addrinfo *a = addresses; a; a = a->ai_next) {
            fd = socket(a->ai_family, SOCK_STREAM | SOCK_CLOEXEC, a->ai_protocol);
            if (fd < 0) continue;
            timeval timeout{3, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
            if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
            close(fd);
            fd = -1;
        }
        freeaddrinfo(addresses);
        if (fd < 0) throw std::runtime_error("cannot connect to the window exporter on port 14501");
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        tls = SSL_new(context);
        if (!tls || SSL_set_fd(tls, fd) != 1 || SSL_connect(tls) != 1)
            throw std::runtime_error("window TLS handshake failed (is this client paired with Sunshine?)");
        X509 *certificate = SSL_get1_peer_certificate(tls);
        if (!certificate) throw std::runtime_error("window host sent no certificate");
        unsigned char *encoded = nullptr;
        const int size = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &encoded);
        unsigned char digest[EVP_MAX_MD_SIZE], base64[EVP_MAX_MD_SIZE * 2];
        unsigned digestSize = 0;
        const bool hashed = size > 0 && EVP_Digest(encoded, size_t(size), digest, &digestSize, EVP_sha256(), nullptr);
        OPENSSL_free(encoded);
        X509_free(certificate);
        if (!hashed) throw std::runtime_error("cannot check the window host's key");
        const int count = EVP_EncodeBlock(base64, digest, int(digestSize));
        const std::string actual = "sha256//" + std::string(reinterpret_cast<char *>(base64), size_t(count));
        if (actual != expected) throw std::runtime_error("window host key differs from the paired Sunshine host");
        SSL_set_mode(tls, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        SSL_set_options(tls, SSL_OP_NO_RENEGOTIATION);
        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0)
            throw std::runtime_error("cannot make window transport nonblocking");
    }

    void Send(char type, const std::string &payload) {
        if (payload.size() > 4096 || queued + payload.size() + 5 > 65536)
            throw std::runtime_error("window control queue is full");
        const uint32_t size = htonl(uint32_t(payload.size()));
        std::string message(1, type);
        message.append(reinterpret_cast<const char *>(&size), sizeof size);
        message += payload;
        queued += message.size();
        outgoing.push_back(std::move(message));
    }

    void Flush() {
        while (!outgoing.empty()) {
            const std::string &message = outgoing.front();
            const int n = SSL_write(tls, message.data() + written, int(message.size() - written));
            if (n <= 0) {
                const int error = SSL_get_error(tls, n);
                if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return;
                throw std::runtime_error("window transport write failed");
            }
            written += size_t(n);
            if (written == message.size()) {
                queued -= message.size();
                outgoing.pop_front();
                written = 0;
            }
        }
    }

    bool Parse(std::deque<WindowPacket> &packets) {
        if (incoming.size() < 5 || packets.size() >= 4) return false;
        uint32_t size;
        std::memcpy(&size, incoming.data() + 1, sizeof size);
        size = ntohl(size);
        const char type = char(incoming[0]);
        if ((type != 'J' && type != 'V') || size == 0 || size > kWindowMaxFrame ||
            (type == 'J' && size > 65536))
            throw std::runtime_error("invalid window transport frame");
        if (incoming.size() < size_t(size) + 5) return false;
        packets.push_back({type, {incoming.begin() + 5, incoming.begin() + 5 + size}});
        incoming.erase(incoming.begin(), incoming.begin() + 5 + size);
        return true;
    }

    void Read(std::deque<WindowPacket> &packets) {
        while (Parse(packets)) {}
        if (packets.size() >= 4) return;
        uint8_t bytes[32768];
        const int n = SSL_read(tls, bytes, sizeof bytes);
        readNeedsWrite = false;
        if (n <= 0) {
            const int error = SSL_get_error(tls, n);
            if (error == SSL_ERROR_WANT_WRITE) readNeedsWrite = true;
            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return;
            throw std::runtime_error("window host disconnected");
        }
        if (incoming.size() + size_t(n) > kWindowMaxFrame + sizeof bytes + 5)
            throw std::runtime_error("window receive buffer exceeded its limit");
        incoming.insert(incoming.end(), bytes, bytes + n);
        while (Parse(packets)) {}
    }
};

int StreamWindow(Client &client, const std::string &window, int fd, int width, int height, int fps, int bitrate) {
    Viewer viewer{fd};
    sigset_t none;
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, nullptr);
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    signal(SIGINT, Stop);
    signal(SIGTERM, Stop);
    signal(SIGPIPE, SIG_IGN);
    Decoder dec;
    dec.toSteamVR = false;
    Converter conv;
    conv.toSteamVR = false;
    try {
        if (!client.server.paired) throw std::runtime_error("client is not paired");
        if (width % 2 || height % 2 || fps > 120 || bitrate < 100 || bitrate > 150000)
            throw std::runtime_error("window streams need even dimensions, 1–120 fps and 100–150000 kbit/s");
        for (std::string msg; viewer.Read(&msg, true) && !msg.empty();) {
            if (msg.rfind("modifiers", 0) != 0) continue;
            std::istringstream words(msg.substr(9));
            for (std::string m; words >> m;) conv.modifiers.push_back(std::strtoull(m.c_str(), nullptr, 16));
            break;
        }
        WindowPeer peer;
        peer.Connect(client);
        viewer.Send("state connecting direct window");
        const nlohmann::json request = {{"version", 1}, {"window", window}, {"width", width}, {"height", height},
                                        {"fps", fps}, {"bitrate", bitrate}};
        peer.Send('J', request.dump());
        if (!dec.Open("/dev/video-dec0", 6) || !conv.Init())
            throw std::runtime_error("cannot open the hardware window decoder");
        bool owned[3] = {}, live = false, hidden = false;
        std::deque<WindowPacket> packets;
        uint64_t sequence = 0, bytes = 0;
        int shown = 0, received = 0;
        int64_t report = MonoNs(), cpu = CpuNs(), lastShown = 0;
        while (!g_stop) {
            peer.Flush();
            pollfd events[3] = {
                {peer.fd, short((packets.size() < 4 ? POLLIN : 0) |
                                ((!peer.outgoing.empty() || peer.readNeedsWrite) ? POLLOUT : 0)), 0},
                {dec.fd, short(POLLIN | POLLPRI | (!packets.empty() ? POLLOUT : 0)), 0},
                {viewer.fd, POLLIN, 0},
            };
            poll(events, 3, SSL_pending(peer.tls) ? 0 : 20);
            if (events[0].revents & (POLLERR | POLLHUP | POLLNVAL))
                throw std::runtime_error("window connection ended");
            if (packets.size() < 4) peer.Read(packets);
            std::string message;
            bool open = true;
            while ((open = viewer.Read(&message, false)) && !message.empty()) {
                int index;
                if (std::sscanf(message.c_str(), "release %d", &index) == 1) {
                    if (index >= 0 && index < 3) owned[index] = false;
                } else if (message == "quit") {
                    g_stop = 1;
                } else if (message.rfind("attention ", 0) == 0) {
                    hidden = message == "attention hidden";
                    peer.Send('C', message);
                } else if (message == "blur" || message.rfind("move ", 0) == 0 ||
                           message.rfind("button ", 0) == 0 || message.rfind("key ", 0) == 0 ||
                           message.rfind("scroll ", 0) == 0) {
                    peer.Send('C', message);
                }
            }
            if (!open) break;
            if (dec.Events()) {
                if (!conv.Setup(dec)) throw std::runtime_error("cannot convert decoded window buffers");
                const int fds[3] = {conv.out[0].fd, conv.out[1].fd, conv.out[2].fd};
                char text[160];
                std::snprintf(text, sizeof text, "buffers %u %u %x %llx %u %u", conv.width, conv.height,
                              DRM_FORMAT_ABGR8888, (unsigned long long)conv.out[0].modifier,
                              conv.out[0].offset, conv.out[0].stride);
                if (!viewer.Send(text, fds, 3)) break;
                for (bool &slot : owned) slot = false;
            }
            dec.Reclaim();
            while (!packets.empty()) {
                auto &p = packets.front();
                if (p.type == 'J') {
                    const auto metadata = nlohmann::json::parse(p.data.begin(), p.data.end());
                    if (metadata.contains("error")) throw std::runtime_error(metadata["error"].get<std::string>());
                    if (metadata.value("codec", "") != "hevc" || metadata.value("version", 0) != 1)
                        throw std::runtime_error("unsupported window stream");
                    std::printf("window %s: authenticated, HEVC %dx%d\n", window.c_str(), width, height);
                } else {
                    if (!dec.Feed(p.data.data(), p.data.size(), sequence)) break;
                    ++sequence;
                    ++received;
                    bytes += p.data.size();
                }
                packets.pop_front();
            }
            uint64_t frame = 0;
            bool last = false;
            int decoded;
            while ((decoded = dec.Decoded(&frame, &last)) >= 0) {
                const int64_t now = MonoNs();
                int slot = -1;
                if (!hidden || now - lastShown >= 1'000'000'000 / kHiddenFps) {
                    for (int k = 0; k < 3 && slot < 0; ++k)
                        if (!owned[(conv.next + k) % 3]) slot = (conv.next + k) % 3;
                }
                if (slot >= 0) {
                    conv.ConvertInto(decoded, slot);
                    conv.next = (slot + 1) % 3;
                    owned[slot] = true;
                    if (!viewer.Send("frame " + std::to_string(slot))) g_stop = 1;
                    lastShown = now;
                    ++shown;
                    if (!live) live = true, viewer.Send("state live direct window");
                }
                dec.Requeue(decoded);
            }
            const int64_t now = MonoNs();
            if (now - report >= 10'000'000'000) {
                const double seconds = (now - report) / 1e9;
                std::printf("window: in %.1f fps, shown %.1f fps, %.2f Mbit/s, convert %.2f ms, CPU %.1f%% of a core\n",
                            received / seconds, shown / seconds, bytes * 8 / seconds / 1e6,
                            shown ? conv.msSum / shown : 0.0, 100 * (CpuNs() - cpu) / 1e9 / seconds);
                report = now, cpu = CpuNs(), bytes = 0, received = shown = 0, conv.msSum = 0;
            }
        }
        peer.Send('C', "blur");
        peer.Flush();
        dec.Close();
        viewer.Send("state lost window disconnected");
        return 0;
    } catch (const std::exception &error) {
        std::fprintf(stderr, "window stream: %s\n", error.what());
        viewer.Send(std::string("state lost ") + error.what());
        dec.Close();
        return 1;
    }
}

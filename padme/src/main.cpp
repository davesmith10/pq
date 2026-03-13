#include <crystals/tray.hpp>
#include <crystals/tray_reader.hpp>
#include <crystals/tray_pack.hpp>
#include <crystals/yaml_io.hpp>
#include <crystals/base64.hpp>
#include "lodepng.h"
#include "bitmap_font.hpp"
#include "encaps_crypto.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

// ── Rainbow palette ───────────────────────────────────────────────────────────

static std::array<uint8_t, 3> byte_to_rgb(uint8_t v) {
    double h  = (v / 256.0) * 360.0;
    double h6 = h / 60.0;
    int    i  = static_cast<int>(h6) % 6;
    double f  = h6 - std::floor(h6);

    double r, g, b;
    switch (i) {
        case 0: r = 1.0; g = f;       b = 0.0;   break;
        case 1: r = 1-f; g = 1.0;     b = 0.0;   break;
        case 2: r = 0.0; g = 1.0;     b = f;     break;
        case 3: r = 0.0; g = 1.0-f;   b = 1.0;   break;
        case 4: r = f;   g = 0.0;     b = 1.0;   break;
        default:r = 1.0; g = 0.0;     b = 1.0-f; break;
    }

    return {
        static_cast<uint8_t>(r * 255.0 + 0.5),
        static_cast<uint8_t>(g * 255.0 + 0.5),
        static_cast<uint8_t>(b * 255.0 + 0.5)
    };
}

// Reverse lookup: RGB triple (packed as r<<16|g<<8|b) → original byte value.
static std::unordered_map<uint32_t, uint8_t> build_reverse_lut() {
    std::unordered_map<uint32_t, uint8_t> lut;
    lut.reserve(256);
    for (int v = 0; v < 256; ++v) {
        auto c = byte_to_rgb(static_cast<uint8_t>(v));
        uint32_t key = (uint32_t(c[0]) << 16) | (uint32_t(c[1]) << 8) | c[2];
        lut[key] = static_cast<uint8_t>(v);
    }
    return lut;
}

// ── Image geometry constants (render / decode) ────────────────────────────────

static const unsigned MARGIN    = 8;
static const unsigned GAP       = 8;
static const unsigned ROW_WIDTH = 32;

// ── Image geometry constants (encaps / decaps) ────────────────────────────────

static const unsigned ENCAPS_IMG_W  = 256;
static const unsigned ENCAPS_MARGIN = 12;
static const unsigned ENCAPS_GAP    = 8;
static const unsigned ENCAPS_COL_W  = (ENCAPS_IMG_W - ENCAPS_MARGIN - ENCAPS_MARGIN - ENCAPS_GAP) / 2;  // 112
static const unsigned LINE_SPACING  = 10;
static const unsigned KEM_BLOB_BYTES = 60;  // kem_nonce(12) + kem_tag(16) + data_key_enc(32)

struct ImageResult {
    std::vector<uint8_t> pixels;
    unsigned w, h;
};

static bool is_pq_slot(const std::string& alg_name) {
    return alg_name.rfind("Kyber", 0) == 0 ||
           alg_name.rfind("Dilithium", 0) == 0;
}

// row_count using ROW_WIDTH (render / decode)
static unsigned row_count(size_t nbytes) {
    return static_cast<unsigned>((nbytes + ROW_WIDTH - 1) / ROW_WIDTH);
}

// row_count for arbitrary column width
static unsigned row_count_cw(size_t nbytes, unsigned col_w) {
    if (nbytes == 0 || col_w == 0) return 0;
    return static_cast<unsigned>((nbytes + col_w - 1) / col_w);
}

// ── iTXt metadata ─────────────────────────────────────────────────────────────

static std::string make_meta_text(const Tray& tray) {
    std::ostringstream ss;
    ss << "alias="   << tray.alias    << "\n"
       << "id="      << tray.id       << "\n"
       << "profile=" << tray.type_str << "\n"
       << "created=" << tray.created  << "\n"
       << "expires=" << tray.expires  << "\n";
    return ss.str();
}

struct TrayMeta {
    std::string alias, id, profile, created, expires;
};

static TrayMeta parse_meta(const std::string& text) {
    TrayMeta m;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if      (key == "alias")   m.alias   = val;
        else if (key == "id")      m.id      = val;
        else if (key == "profile") m.profile = val;
        else if (key == "created") m.created = val;
        else if (key == "expires") m.expires = val;
    }
    if (m.alias.empty() || m.id.empty() || m.profile.empty())
        throw std::runtime_error("crystals-tray iTXt chunk is missing required fields");
    return m;
}

// ── crystals-encaps iTXt metadata ────────────────────────────────────────────

struct EncapsMeta {
    std::vector<uint8_t> salt;          // 16 bytes
    int n_log2 = 0;
    int r = 0, p = 0;
    std::vector<uint8_t> sk_nonce;      // 12 bytes
    std::vector<uint8_t> sk_tag;        // 16 bytes
};

static std::string make_encaps_text(const EncapsMeta& em) {
    std::ostringstream ss;
    ss << "salt="     << base64_encode(em.salt.data(), em.salt.size())         << "\n"
       << "n_log2="   << em.n_log2                                             << "\n"
       << "r="        << em.r                                                  << "\n"
       << "p="        << em.p                                                  << "\n"
       << "sk_nonce=" << base64_encode(em.sk_nonce.data(), em.sk_nonce.size()) << "\n"
       << "sk_tag="   << base64_encode(em.sk_tag.data(), em.sk_tag.size())     << "\n";
    return ss.str();
}

static EncapsMeta parse_encaps_meta(const std::string& text) {
    EncapsMeta em;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if      (key == "salt")     em.salt     = base64_decode(val);
        else if (key == "n_log2")   em.n_log2   = std::stoi(val);
        else if (key == "r")        em.r        = std::stoi(val);
        else if (key == "p")        em.p        = std::stoi(val);
        else if (key == "sk_nonce") em.sk_nonce = base64_decode(val);
        else if (key == "sk_tag")   em.sk_tag   = base64_decode(val);
    }
    if (em.salt.empty() || em.n_log2 == 0 || em.sk_nonce.empty() || em.sk_tag.empty())
        throw std::runtime_error("crystals-encaps iTXt chunk is missing required fields");
    return em;
}

// ── Profile slot-size table ───────────────────────────────────────────────────

struct SlotDef {
    std::string alg_name;
    size_t pk_size;
    size_t sk_size;
};

static const std::map<std::string, std::vector<SlotDef>> PROFILES = {
    {"level0", {
        {"X25519",     32,   32},
        {"Ed25519",    32,   32},
    }},
    {"level1", {
        {"Kyber512",   800,  1632},
        {"Dilithium2", 1312, 2560},
    }},
    {"level2-25519", {
        {"X25519",     32,   32},
        {"Kyber512",   800,  1632},
        {"Ed25519",    32,   32},
        {"Dilithium2", 1312, 2560},
    }},
    {"level2", {
        {"P-256",      65,   32},
        {"Kyber512",   800,  1632},
        {"ECDSA P-256", 65,  32},
        {"Dilithium2", 1312, 2560},
    }},
    {"level3", {
        {"P-384",      97,   48},
        {"Kyber768",   1184, 2400},
        {"ECDSA P-384", 97,  48},
        {"Dilithium3", 1952, 4032},
    }},
    {"level5", {
        {"P-521",      133,  66},
        {"Kyber1024",  1568, 3168},
        {"ECDSA P-521", 133, 66},
        {"Dilithium5", 2592, 4896},
    }},
};

// ── Pixel buffer helpers ──────────────────────────────────────────────────────

// fill_block: writes data bytes as rainbow pixels.
// col_width: number of pixels per row (ROW_WIDTH for render, ENCAPS_COL_W for encaps).
static void fill_block(std::vector<uint8_t>& pixels, unsigned img_w,
                        const std::vector<uint8_t>& data, unsigned nrows,
                        unsigned x_off, unsigned y_off,
                        unsigned col_width = ROW_WIDTH) {
    for (unsigned row = 0; row < nrows; ++row) {
        for (unsigned col = 0; col < col_width; ++col) {
            size_t  byte_idx = static_cast<size_t>(row) * col_width + col;
            uint8_t bval     = (byte_idx < data.size()) ? data[byte_idx] : 0;
            auto [r, g, b]   = byte_to_rgb(bval);
            size_t px = ((y_off + row) * img_w + (x_off + col)) * 4;
            pixels[px + 0] = r;
            pixels[px + 1] = g;
            pixels[px + 2] = b;
            pixels[px + 3] = 255;
        }
    }
}

// read_block: extracts nbytes from the image using the reverse palette LUT.
// col_width: number of pixels per row (ROW_WIDTH for render, ENCAPS_COL_W for encaps).
static std::vector<uint8_t> read_block(const unsigned char* pixels, unsigned img_w,
                                        const std::unordered_map<uint32_t, uint8_t>& rlut,
                                        unsigned x_off, unsigned y_off,
                                        size_t nbytes,
                                        unsigned col_width = ROW_WIDTH) {
    std::vector<uint8_t> out;
    out.reserve(nbytes);
    for (size_t i = 0; i < nbytes; ++i) {
        unsigned row = static_cast<unsigned>(i / col_width);
        unsigned col = static_cast<unsigned>(i % col_width);
        size_t px = ((y_off + row) * img_w + (x_off + col)) * 4;
        uint32_t key = (uint32_t(pixels[px])     << 16)
                     | (uint32_t(pixels[px + 1]) <<  8)
                     |  uint32_t(pixels[px + 2]);
        auto it = rlut.find(key);
        if (it == rlut.end())
            throw std::runtime_error("pixel at ("
                + std::to_string(x_off + col) + ","
                + std::to_string(y_off + row)
                + ") is not in the rainbow palette — not a padme PNG?");
        out.push_back(it->second);
    }
    return out;
}

// ── Build image (render path) ─────────────────────────────────────────────────

static ImageResult build_image_grid(const std::vector<uint8_t>& cl_pk,
                                     const std::vector<uint8_t>& cl_sk,
                                     const std::vector<uint8_t>& pq_pk,
                                     const std::vector<uint8_t>& pq_sk) {
    unsigned cl_pk_rows = row_count(cl_pk.size());
    unsigned cl_sk_rows = row_count(cl_sk.size());
    unsigned pq_pk_rows = row_count(pq_pk.size());
    unsigned pq_sk_rows = row_count(pq_sk.size());

    unsigned top_rows = std::max(cl_pk_rows, cl_sk_rows);
    unsigned bot_rows = std::max(pq_pk_rows, pq_sk_rows);
    if (top_rows == 0) top_rows = 1;
    if (bot_rows == 0) bot_rows = 1;

    unsigned img_w = MARGIN + ROW_WIDTH + GAP + ROW_WIDTH + MARGIN;
    unsigned img_h = MARGIN + top_rows + GAP + bot_rows + MARGIN;

    std::vector<uint8_t> pixels(img_w * img_h * 4, 0xFF);

    fill_block(pixels, img_w, cl_pk, cl_pk_rows, MARGIN,                  MARGIN);
    fill_block(pixels, img_w, cl_sk, cl_sk_rows, MARGIN + ROW_WIDTH + GAP, MARGIN);
    fill_block(pixels, img_w, pq_pk, pq_pk_rows, MARGIN,                  MARGIN + top_rows + GAP);
    fill_block(pixels, img_w, pq_sk, pq_sk_rows, MARGIN + ROW_WIDTH + GAP, MARGIN + top_rows + GAP);

    return {std::move(pixels), img_w, img_h};
}

static ImageResult build_image_stack(const Tray& tray) {
    struct SlotData { std::vector<uint8_t> bytes; unsigned rows; };
    std::vector<SlotData> slots;
    slots.reserve(tray.slots.size());
    for (const auto& s : tray.slots) {
        SlotData sd;
        sd.bytes = s.pk;
        sd.bytes.insert(sd.bytes.end(), s.sk.begin(), s.sk.end());
        if (sd.bytes.empty()) sd.bytes.push_back(0);
        sd.rows = row_count(sd.bytes.size());
        slots.push_back(std::move(sd));
    }
    unsigned total_rows = 0;
    for (const auto& sd : slots) total_rows += sd.rows;
    unsigned n    = static_cast<unsigned>(slots.size());
    unsigned img_w = MARGIN * 2 + ROW_WIDTH;
    unsigned img_h = MARGIN * 2 + total_rows + (n > 1 ? (n - 1) * GAP : 0);

    std::vector<uint8_t> pixels(img_w * img_h * 4, 0xFF);
    unsigned y = MARGIN;
    for (size_t si = 0; si < slots.size(); ++si) {
        fill_block(pixels, img_w, slots[si].bytes, slots[si].rows, MARGIN, y);
        y += slots[si].rows;
        if (si + 1 < slots.size()) y += GAP;
    }
    return {std::move(pixels), img_w, img_h};
}

static ImageResult build_image(const Tray& tray,
                                std::vector<uint8_t>& cl_pk_out,
                                std::vector<uint8_t>& cl_sk_out,
                                std::vector<uint8_t>& pq_pk_out,
                                std::vector<uint8_t>& pq_sk_out) {
    for (const auto& s : tray.slots) {
        if (is_pq_slot(s.alg_name)) {
            pq_pk_out.insert(pq_pk_out.end(), s.pk.begin(), s.pk.end());
            pq_sk_out.insert(pq_sk_out.end(), s.sk.begin(), s.sk.end());
        } else {
            cl_pk_out.insert(cl_pk_out.end(), s.pk.begin(), s.pk.end());
            cl_sk_out.insert(cl_sk_out.end(), s.sk.begin(), s.sk.end());
        }
    }
    if (!cl_pk_out.empty() && !pq_pk_out.empty())
        return build_image_grid(cl_pk_out, cl_sk_out, pq_pk_out, pq_sk_out);
    return build_image_stack(tray);
}

// ── Write PNG with one or two iTXt chunks ─────────────────────────────────────

static void write_png(const ImageResult& img, const std::string& out_file,
                       const std::string& meta_text,
                       const std::string& encaps_text = "") {
    LodePNGState state;
    lodepng_state_init(&state);
    state.info_raw.colortype = LCT_RGBA;
    state.info_raw.bitdepth  = 8;
    state.info_png.color.colortype = LCT_RGBA;
    state.info_png.color.bitdepth  = 8;
    state.encoder.auto_convert = 0;

    unsigned err = lodepng_add_itext(&state.info_png,
                                      "crystals-tray", "", "crystals-tray",
                                      meta_text.c_str());
    if (err) {
        lodepng_state_cleanup(&state);
        throw std::runtime_error(std::string("iTXt error: ") + lodepng_error_text(err));
    }

    if (!encaps_text.empty()) {
        err = lodepng_add_itext(&state.info_png,
                                 "crystals-encaps", "", "crystals-encaps",
                                 encaps_text.c_str());
        if (err) {
            lodepng_state_cleanup(&state);
            throw std::runtime_error(std::string("iTXt encaps error: ") + lodepng_error_text(err));
        }
    }

    unsigned char* png_buf = nullptr;
    size_t png_size = 0;
    err = lodepng_encode(&png_buf, &png_size, img.pixels.data(), img.w, img.h, &state);
    lodepng_state_cleanup(&state);
    if (err) {
        free(png_buf);
        throw std::runtime_error(std::string("PNG encode error: ") + lodepng_error_text(err));
    }

    err = lodepng_save_file(png_buf, png_size, out_file.c_str());
    free(png_buf);
    if (err)
        throw std::runtime_error(std::string("PNG write error: ") + lodepng_error_text(err));
}

// ── Encaps image builder ───────────────────────────────────────────────────────

// Build the encaps-format image (256px wide, text header+footer, 112px columns).
// cl_sk_enc and pq_sk_enc are the encrypted SK bytes for their respective sections.
// kem_blob is 60 bytes: kem_nonce(12) || kem_tag(16) || data_key_enc(32).
static ImageResult build_encaps_image(
    const Tray& tray,
    const std::vector<uint8_t>& cl_pk,
    const std::vector<uint8_t>& cl_sk_enc,
    const std::vector<uint8_t>& pq_pk,
    const std::vector<uint8_t>& pq_sk_enc,
    const std::vector<uint8_t>& kem_blob)
{
    const unsigned img_w = ENCAPS_IMG_W;

    // ── Key section heights ─────────────────────────────────────────────────
    unsigned cl_rows = std::max(row_count_cw(cl_pk.size(),     ENCAPS_COL_W),
                                 row_count_cw(cl_sk_enc.size(), ENCAPS_COL_W));
    unsigned pq_rows = std::max(row_count_cw(pq_pk.size(),     ENCAPS_COL_W),
                                 row_count_cw(pq_sk_enc.size(), ENCAPS_COL_W));

    // ── Y positions ─────────────────────────────────────────────────────────
    // Header: 2 lines of text, each LINE_SPACING apart
    unsigned y_hdr1    = ENCAPS_MARGIN;                          // line 1
    unsigned y_hdr2    = y_hdr1 + LINE_SPACING;                  // line 2
    unsigned y_keys    = y_hdr2 + FONT_H + ENCAPS_GAP;           // start of key blocks

    unsigned y_cl      = y_keys;
    unsigned y_pq      = y_cl + cl_rows + (cl_rows > 0 && pq_rows > 0 ? ENCAPS_GAP : 0);

    unsigned total_key_h = cl_rows + (cl_rows > 0 && pq_rows > 0 ? ENCAPS_GAP : 0) + pq_rows;
    if (total_key_h == 0) total_key_h = 1;

    unsigned y_kem     = y_keys + total_key_h + ENCAPS_GAP;      // KEM row
    unsigned y_cpy1    = y_kem + 1 + ENCAPS_GAP;                 // copyright line 1
    unsigned y_cpy2    = y_cpy1 + LINE_SPACING;                  // copyright line 2

    unsigned img_h     = y_cpy2 + FONT_H + ENCAPS_MARGIN;

    std::vector<uint8_t> pixels(img_w * img_h * 4, 0xFF);

    // ── Text colors ──────────────────────────────────────────────────────────
    std::array<uint8_t, 3> fg_dark  = {20,  20,  20};
    std::array<uint8_t, 3> bg_white = {255, 255, 255};

    // ── Header line 1: "PADME Tray - <level>" ───────────────────────────────
    std::string hdr1 = "PADME Tray - " + tray.type_str;
    draw_text(pixels, img_w, ENCAPS_MARGIN, y_hdr1, hdr1, fg_dark, bg_white);

    // ── Header line 2: <uuid> ────────────────────────────────────────────────
    draw_text(pixels, img_w, ENCAPS_MARGIN, y_hdr2, tray.id, fg_dark, bg_white);

    // ── Classical key block (top section) ────────────────────────────────────
    const unsigned x_pk = ENCAPS_MARGIN;
    const unsigned x_sk = ENCAPS_MARGIN + ENCAPS_COL_W + ENCAPS_GAP;

    if (cl_rows > 0) {
        fill_block(pixels, img_w, cl_pk,     cl_rows, x_pk, y_cl, ENCAPS_COL_W);
        fill_block(pixels, img_w, cl_sk_enc, cl_rows, x_sk, y_cl, ENCAPS_COL_W);
    }

    // ── PQ key block (bottom section) ────────────────────────────────────────
    if (pq_rows > 0) {
        fill_block(pixels, img_w, pq_pk,     pq_rows, x_pk, y_pq, ENCAPS_COL_W);
        fill_block(pixels, img_w, pq_sk_enc, pq_rows, x_sk, y_pq, ENCAPS_COL_W);
    }

    // ── KEM block: 60 pixels centered ────────────────────────────────────────
    // Content area: ENCAPS_MARGIN to img_w-ENCAPS_MARGIN = 232px wide
    unsigned content_w = img_w - 2 * ENCAPS_MARGIN;
    unsigned x_kem = ENCAPS_MARGIN + (content_w - KEM_BLOB_BYTES) / 2;
    fill_block(pixels, img_w, kem_blob, 1, x_kem, y_kem, KEM_BLOB_BYTES);

    // ── Copyright footer ─────────────────────────────────────────────────────
    const std::string cpy1 = "\xC2\xA9 2026 David R. Smith";  // © 2026 David R. Smith
    const std::string cpy2 = "All Rights Reserved";
    unsigned cpy1_w = text_pixel_width(cpy1);
    unsigned cpy2_w = text_pixel_width(cpy2);
    unsigned x_cpy1 = ENCAPS_MARGIN + (content_w - cpy1_w) / 2;
    unsigned x_cpy2 = ENCAPS_MARGIN + (content_w - cpy2_w) / 2;
    draw_text(pixels, img_w, x_cpy1, y_cpy1, cpy1, fg_dark, bg_white);
    draw_text(pixels, img_w, x_cpy2, y_cpy2, cpy2, fg_dark, bg_white);

    return {std::move(pixels), img_w, img_h};
}

// ── Password prompt helpers ───────────────────────────────────────────────────

static std::string read_noecho(const char* prompt) {
    std::cerr << prompt;
    struct termios old_t, new_t;
    tcgetattr(STDIN_FILENO, &old_t);
    new_t = old_t;
    new_t.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_t);
    std::string pw;
    std::getline(std::cin, pw);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
    std::cerr << "\n";
    return pw;
}

static std::string get_password_encaps(const std::string& pwfile) {
    if (!pwfile.empty()) {
        std::ifstream f(pwfile);
        if (!f) throw std::runtime_error("Cannot open pwfile: " + pwfile);
        std::string pw;
        std::getline(f, pw);
        return pw;
    }
    std::string p1 = read_noecho("password: ");
    std::string p2 = read_noecho("again: ");
    if (p1 != p2) throw std::runtime_error("Passwords do not match");
    return p1;
}

static std::string get_password_decaps(const std::string& pwfile) {
    if (!pwfile.empty()) {
        std::ifstream f(pwfile);
        if (!f) throw std::runtime_error("Cannot open pwfile: " + pwfile);
        std::string pw;
        std::getline(f, pw);
        return pw;
    }
    return read_noecho("password: ");
}

// ── Output helpers ────────────────────────────────────────────────────────────

static bool has_yaml_ext(const std::string& path) {
    auto dot = path.rfind('.');
    if (dot == std::string::npos) return false;
    std::string ext = path.substr(dot);
    return ext == ".yaml" || ext == ".yml";
}

// Write tray to file: YAML if path ends in .yaml/.yml, msgpack otherwise.
// Returns false and prints error on failure.
static bool write_tray_file(const Tray& tray, const std::string& path, const char* cmd) {
    if (has_yaml_ext(path)) {
        try {
            std::ofstream f(path);
            if (!f) { std::cerr << "Error: cannot open " << path << " for writing\n"; return false; }
            f << emit_tray_yaml(tray);
        } catch (const std::exception& e) {
            std::cerr << "Error: YAML write failed: " << e.what() << "\n"; return false;
        }
    } else {
        try { tray_mp::pack_to_file(tray, path); }
        catch (const std::exception& e) {
            std::cerr << "Error: msgpack write failed: " << e.what() << "\n"; return false;
        }
    }
    std::cout << cmd << ": tray '" << tray.alias << "' \xe2\x86\x92 " << path
              << " (" << tray.slots.size() << " slots)\n";
    return true;
}

// ── render command ────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " render  --tray <file>     [--out <file.png>]\n"
        "       " << prog << " decode  --tray <file.png> [--out <file>]\n"
        "       " << prog << " encaps  --tray <file>     [--out <file.png>] [--pwfile <file>]\n"
        "       " << prog << " decaps  --tray <file.png> [--out <file>]     [--pwfile <file>]\n"
        "\n"
        "  render  Visualize a tray as a PNG image\n"
        "  decode  Recover a tray from a padme PNG\n"
        "  encaps  Render + password-encrypt private keys into a PNG\n"
        "  decaps  Decrypt and recover a tray from an encaps PNG\n"
        "\n"
        "render/decode options:\n"
        "  --tray <file>      Source tray (YAML or msgpack) / padme PNG\n"
        "  --out  <file>      Output file (default: stdout / <alias>.png)\n"
        "\n"
        "encaps/decaps options:\n"
        "  --tray    <file>   Input (tray YAML/msgpack for encaps, PNG for decaps)\n"
        "  --out     <file>   Output (PNG for encaps, tray file for decaps)\n"
        "  --pwfile  <file>   Read password from file (newline stripped)\n"
        "\n"
        "Layout (4-slot trays):\n"
        "  top-left: classical pk  |  top-right: classical sk\n"
        "  bot-left: PQ pk         |  bot-right: PQ sk\n";
}

static int cmd_render(int argc, char* argv[]) {
    std::string tray_file, out_file;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--tray") == 0) {
            if (++i >= argc) { std::cerr << "Error: --tray requires a filename\n"; return 1; }
            tray_file = argv[i];
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a filename\n"; return 1; }
            out_file = argv[i];
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n"; return 1;
        }
    }
    if (tray_file.empty()) { std::cerr << "Error: --tray is required\n"; return 1; }

    Tray tray;
    try { tray = load_tray(tray_file); }
    catch (const std::exception& e) {
        std::cerr << "Error: failed to load tray: " << e.what() << "\n"; return 2;
    }

    if (out_file.empty()) out_file = tray.alias + ".png";

    std::vector<uint8_t> cl_pk, cl_sk, pq_pk, pq_sk;
    ImageResult img = build_image(tray, cl_pk, cl_sk, pq_pk, pq_sk);

    try { write_png(img, out_file, make_meta_text(tray)); }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 3;
    }

    std::cout << "Rendered tray '" << tray.alias << "' \xe2\x86\x92 " << out_file
              << " (" << img.w << "\xc3\x97" << img.h << " px, "
              << tray.slots.size() << " slots)\n";
    return 0;
}

// ── decode command ────────────────────────────────────────────────────────────

static int cmd_decode(int argc, char* argv[]) {
    std::string png_file, out_file;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--tray") == 0) {
            if (++i >= argc) { std::cerr << "Error: --tray requires a filename\n"; return 1; }
            png_file = argv[i];
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a filename\n"; return 1; }
            out_file = argv[i];
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n"; return 1;
        }
    }
    if (png_file.empty()) { std::cerr << "Error: --tray is required\n"; return 1; }

    // ── 1. Load PNG ───────────────────────────────────────────────────────────
    unsigned char* png_bytes = nullptr;
    size_t png_size = 0;
    if (lodepng_load_file(&png_bytes, &png_size, png_file.c_str()))
        { std::cerr << "Error: cannot read PNG file: " << png_file << "\n"; return 3; }

    LodePNGState state;
    lodepng_state_init(&state);
    state.info_raw.colortype = LCT_RGBA;
    state.info_raw.bitdepth  = 8;

    unsigned char* pixels = nullptr;
    unsigned img_w = 0, img_h = 0;
    unsigned err = lodepng_decode(&pixels, &img_w, &img_h, &state, png_bytes, png_size);
    free(png_bytes);
    if (err) {
        free(pixels);
        lodepng_state_cleanup(&state);
        std::cerr << "Error: PNG decode failed: " << lodepng_error_text(err) << "\n";
        return 3;
    }

    // ── 2. Extract iTXt metadata ──────────────────────────────────────────────
    std::string meta_text;
    bool has_encaps_chunk = false;
    for (size_t i = 0; i < state.info_png.itext_num; ++i) {
        if (std::strcmp(state.info_png.itext_keys[i], "crystals-tray") == 0)
            meta_text = state.info_png.itext_strings[i];
        if (std::strcmp(state.info_png.itext_keys[i], "crystals-encaps") == 0)
            has_encaps_chunk = true;
    }
    lodepng_state_cleanup(&state);

    if (meta_text.empty()) {
        free(pixels);
        std::cerr << "Error: no crystals-tray iTXt chunk — not a padme PNG\n";
        return 2;
    }
    if (has_encaps_chunk) {
        free(pixels);
        std::cerr << "Error: this is an encaps PNG — use 'decaps' to recover the tray\n";
        return 2;
    }

    TrayMeta meta;
    try { meta = parse_meta(meta_text); }
    catch (const std::exception& e) {
        free(pixels); std::cerr << "Error: " << e.what() << "\n"; return 2;
    }

    // ── 3. Look up slot definitions ───────────────────────────────────────────
    auto pit = PROFILES.find(meta.profile);
    if (pit == PROFILES.end()) {
        free(pixels);
        std::cerr << "Error: unknown profile '" << meta.profile << "' in iTXt chunk\n";
        return 2;
    }
    const auto& slot_defs = pit->second;

    // ── 4. Compute byte stream sizes and image geometry ───────────────────────
    size_t cl_pk_bytes = 0, cl_sk_bytes = 0, pq_pk_bytes = 0, pq_sk_bytes = 0;
    for (const auto& sd : slot_defs) {
        if (sd.alg_name.rfind("Kyber", 0) == 0 || sd.alg_name.rfind("Dilithium", 0) == 0) {
            pq_pk_bytes += sd.pk_size;
            pq_sk_bytes += sd.sk_size;
        } else {
            cl_pk_bytes += sd.pk_size;
            cl_sk_bytes += sd.sk_size;
        }
    }

    bool is_grid = (cl_pk_bytes > 0 && pq_pk_bytes > 0);

    unsigned x_cl_pk, x_cl_sk, y_cl, x_pq_pk, x_pq_sk, y_pq;
    if (is_grid) {
        unsigned top_rows = std::max(row_count(cl_pk_bytes), row_count(cl_sk_bytes));
        if (top_rows == 0) top_rows = 1;
        x_cl_pk = MARGIN;
        x_cl_sk = MARGIN + ROW_WIDTH + GAP;
        y_cl    = MARGIN;
        x_pq_pk = MARGIN;
        x_pq_sk = MARGIN + ROW_WIDTH + GAP;
        y_pq    = MARGIN + top_rows + GAP;
    } else {
        x_cl_pk = x_pq_pk = MARGIN;
        x_cl_sk = x_pq_sk = MARGIN;
        y_cl = y_pq = MARGIN;
    }

    // ── 5. Extract byte streams ───────────────────────────────────────────────
    auto rlut = build_reverse_lut();
    std::vector<uint8_t> cl_pk_data, cl_sk_data, pq_pk_data, pq_sk_data;
    try {
        if (is_grid) {
            cl_pk_data = read_block(pixels, img_w, rlut, x_cl_pk, y_cl,  cl_pk_bytes);
            cl_sk_data = read_block(pixels, img_w, rlut, x_cl_sk, y_cl,  cl_sk_bytes);
            pq_pk_data = read_block(pixels, img_w, rlut, x_pq_pk, y_pq,  pq_pk_bytes);
            pq_sk_data = read_block(pixels, img_w, rlut, x_pq_sk, y_pq,  pq_sk_bytes);
        } else {
            std::vector<uint8_t> combined_data;
            size_t total = 0;
            for (const auto& sd : slot_defs) total += sd.pk_size + sd.sk_size;
            combined_data = read_block(pixels, img_w, rlut, MARGIN, MARGIN, total);

            size_t off = 0;
            for (const auto& sd : slot_defs) {
                auto pk = std::vector<uint8_t>(combined_data.begin() + off,
                                               combined_data.begin() + off + sd.pk_size);
                off += sd.pk_size;
                auto sk = std::vector<uint8_t>(combined_data.begin() + off,
                                               combined_data.begin() + off + sd.sk_size);
                off += sd.sk_size;
                if (is_pq_slot(sd.alg_name)) {
                    pq_pk_data.insert(pq_pk_data.end(), pk.begin(), pk.end());
                    pq_sk_data.insert(pq_sk_data.end(), sk.begin(), sk.end());
                } else {
                    cl_pk_data.insert(cl_pk_data.end(), pk.begin(), pk.end());
                    cl_sk_data.insert(cl_sk_data.end(), sk.begin(), sk.end());
                }
            }
        }
    } catch (const std::exception& e) {
        free(pixels); std::cerr << "Error: " << e.what() << "\n"; return 2;
    }
    free(pixels);

    // ── 6. Reconstruct Tray slots from byte streams ───────────────────────────
    Tray tray;
    tray.version       = 1;
    tray.alias         = meta.alias;
    tray.id            = meta.id;
    tray.type_str      = meta.profile;
    tray.profile_group = "crystals";
    tray.created       = meta.created;
    tray.expires       = meta.expires;

    if      (meta.profile == "level0")       tray.tray_type = TrayType::Level0;
    else if (meta.profile == "level1")       tray.tray_type = TrayType::Level1;
    else if (meta.profile == "level2-25519") tray.tray_type = TrayType::Level2_25519;
    else if (meta.profile == "level2")       tray.tray_type = TrayType::Level2;
    else if (meta.profile == "level3")       tray.tray_type = TrayType::Level3;
    else if (meta.profile == "level5")       tray.tray_type = TrayType::Level5;

    size_t cl_pk_off = 0, cl_sk_off = 0, pq_pk_off = 0, pq_sk_off = 0;
    for (const auto& sd : slot_defs) {
        Slot s;
        s.alg_name = sd.alg_name;
        if (is_pq_slot(sd.alg_name)) {
            s.pk = std::vector<uint8_t>(pq_pk_data.begin() + pq_pk_off,
                                         pq_pk_data.begin() + pq_pk_off + sd.pk_size);
            pq_pk_off += sd.pk_size;
            if (pq_sk_off + sd.sk_size <= pq_sk_data.size()) {
                s.sk = std::vector<uint8_t>(pq_sk_data.begin() + pq_sk_off,
                                             pq_sk_data.begin() + pq_sk_off + sd.sk_size);
                pq_sk_off += sd.sk_size;
            }
        } else {
            s.pk = std::vector<uint8_t>(cl_pk_data.begin() + cl_pk_off,
                                         cl_pk_data.begin() + cl_pk_off + sd.pk_size);
            cl_pk_off += sd.pk_size;
            if (cl_sk_off + sd.sk_size <= cl_sk_data.size()) {
                s.sk = std::vector<uint8_t>(cl_sk_data.begin() + cl_sk_off,
                                             cl_sk_data.begin() + cl_sk_off + sd.sk_size);
                cl_sk_off += sd.sk_size;
            }
        }
        tray.slots.push_back(std::move(s));
    }

    // ── 7. Output ─────────────────────────────────────────────────────────────
    if (!out_file.empty()) {
        if (!write_tray_file(tray, out_file, "Decoded")) return 3;
    } else {
        try { std::cout << emit_tray_yaml(tray); }
        catch (const std::exception& e) {
            std::cerr << "Error: YAML output failed: " << e.what() << "\n"; return 3;
        }
    }
    return 0;
}

// ── encaps command ────────────────────────────────────────────────────────────

static int cmd_encaps(int argc, char* argv[]) {
    std::string tray_file, out_file, pwfile;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--tray") == 0) {
            if (++i >= argc) { std::cerr << "Error: --tray requires a filename\n"; return 1; }
            tray_file = argv[i];
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a filename\n"; return 1; }
            out_file = argv[i];
        } else if (std::strcmp(argv[i], "--pwfile") == 0) {
            if (++i >= argc) { std::cerr << "Error: --pwfile requires a filename\n"; return 1; }
            pwfile = argv[i];
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n"; return 1;
        }
    }
    if (tray_file.empty()) { std::cerr << "Error: --tray is required\n"; return 1; }

    // ── 1. Load tray ──────────────────────────────────────────────────────────
    Tray tray;
    try { tray = load_tray(tray_file); }
    catch (const std::exception& e) {
        std::cerr << "Error: failed to load tray: " << e.what() << "\n"; return 2;
    }
    if (out_file.empty()) out_file = tray.alias + "_enc.png";

    // ── 2. Get password ───────────────────────────────────────────────────────
    std::string password;
    try { password = get_password_encaps(pwfile); }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 1;
    }

    try {
        // ── 3. Key derivation ─────────────────────────────────────────────────
        auto salt     = encaps_rand(ENCAPS_SALT_LEN);           // 16 bytes
        auto wrap_key = encaps_derive_key(password, salt);       // 32 bytes (scrypt)
        auto data_key = encaps_rand(ENCAPS_KEY_LEN);             // 32 bytes

        // ── 4. Encrypt data_key → KEM blob ───────────────────────────────────
        // aes_enc returns nonce(12)||tag(16)||ct(32) = 60 bytes
        auto kem_blob = encaps_aes_enc(wrap_key, data_key);
        if (kem_blob.size() != KEM_BLOB_BYTES) {
            std::cerr << "Error: unexpected KEM blob size\n"; return 2;
        }

        // ── 5. Concatenate all sk in slot order ───────────────────────────────
        std::vector<uint8_t> all_sk;
        for (const auto& s : tray.slots)
            all_sk.insert(all_sk.end(), s.sk.begin(), s.sk.end());

        // ── 6. Encrypt all_sk → sk_blob ──────────────────────────────────────
        // aes_enc returns nonce(12)||tag(16)||ct(N)
        auto sk_blob = encaps_aes_enc(data_key, all_sk);
        // nonce=sk_blob[0..11], tag=sk_blob[12..27], ct=sk_blob[28..]
        std::vector<uint8_t> sk_nonce(sk_blob.begin(),      sk_blob.begin() + 12);
        std::vector<uint8_t> sk_tag  (sk_blob.begin() + 12, sk_blob.begin() + 28);
        // sk_enc_raw: ciphertext only, same length as all_sk
        std::vector<uint8_t> sk_enc_raw(sk_blob.begin() + 28, sk_blob.end());

        // ── 7. Split sk_enc_raw into cl and pq portions ───────────────────────
        // Walk slots in order, dispatch to cl or pq by alg type
        std::vector<uint8_t> cl_pk, cl_sk_enc, pq_pk, pq_sk_enc;
        size_t sk_off = 0;
        for (const auto& s : tray.slots) {
            if (is_pq_slot(s.alg_name)) {
                pq_pk.insert(pq_pk.end(), s.pk.begin(), s.pk.end());
                pq_sk_enc.insert(pq_sk_enc.end(),
                                  sk_enc_raw.begin() + (std::ptrdiff_t)sk_off,
                                  sk_enc_raw.begin() + (std::ptrdiff_t)(sk_off + s.sk.size()));
            } else {
                cl_pk.insert(cl_pk.end(), s.pk.begin(), s.pk.end());
                cl_sk_enc.insert(cl_sk_enc.end(),
                                  sk_enc_raw.begin() + (std::ptrdiff_t)sk_off,
                                  sk_enc_raw.begin() + (std::ptrdiff_t)(sk_off + s.sk.size()));
            }
            sk_off += s.sk.size();
        }

        // ── 8. Build encaps image ─────────────────────────────────────────────
        ImageResult img = build_encaps_image(tray, cl_pk, cl_sk_enc, pq_pk, pq_sk_enc, kem_blob);

        // ── 9. Build iTXt chunks ──────────────────────────────────────────────
        EncapsMeta em;
        em.salt     = salt;
        em.n_log2   = ENCAPS_N_LOG2;
        em.r        = ENCAPS_R;
        em.p        = ENCAPS_P;
        em.sk_nonce = sk_nonce;
        em.sk_tag   = sk_tag;

        write_png(img, out_file, make_meta_text(tray), make_encaps_text(em));

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 2;
    }

    std::cout << "Encaps: tray '" << tray.alias << "' \xe2\x86\x92 " << out_file
              << " (scrypt N=2^" << ENCAPS_N_LOG2 << ", AES-256-GCM)\n";
    return 0;
}

// ── decaps command ────────────────────────────────────────────────────────────

static int cmd_decaps(int argc, char* argv[]) {
    std::string png_file, out_file, pwfile;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--tray") == 0) {
            if (++i >= argc) { std::cerr << "Error: --tray requires a filename\n"; return 1; }
            png_file = argv[i];
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a filename\n"; return 1; }
            out_file = argv[i];
        } else if (std::strcmp(argv[i], "--pwfile") == 0) {
            if (++i >= argc) { std::cerr << "Error: --pwfile requires a filename\n"; return 1; }
            pwfile = argv[i];
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n"; return 1;
        }
    }
    if (png_file.empty()) { std::cerr << "Error: --tray is required\n"; return 1; }

    // ── 1. Load PNG ───────────────────────────────────────────────────────────
    unsigned char* png_bytes = nullptr;
    size_t png_size = 0;
    if (lodepng_load_file(&png_bytes, &png_size, png_file.c_str()))
        { std::cerr << "Error: cannot read PNG file: " << png_file << "\n"; return 3; }

    LodePNGState state;
    lodepng_state_init(&state);
    state.info_raw.colortype = LCT_RGBA;
    state.info_raw.bitdepth  = 8;

    unsigned char* pixels = nullptr;
    unsigned img_w = 0, img_h = 0;
    unsigned err = lodepng_decode(&pixels, &img_w, &img_h, &state, png_bytes, png_size);
    free(png_bytes);
    if (err) {
        free(pixels);
        lodepng_state_cleanup(&state);
        std::cerr << "Error: PNG decode failed: " << lodepng_error_text(err) << "\n";
        return 3;
    }

    // ── 2. Extract both iTXt chunks ───────────────────────────────────────────
    std::string meta_text, encaps_text;
    for (size_t i = 0; i < state.info_png.itext_num; ++i) {
        if (std::strcmp(state.info_png.itext_keys[i], "crystals-tray") == 0)
            meta_text   = state.info_png.itext_strings[i];
        if (std::strcmp(state.info_png.itext_keys[i], "crystals-encaps") == 0)
            encaps_text = state.info_png.itext_strings[i];
    }
    lodepng_state_cleanup(&state);

    if (meta_text.empty()) {
        free(pixels);
        std::cerr << "Error: no crystals-tray iTXt chunk — not a padme PNG\n";
        return 2;
    }
    if (encaps_text.empty()) {
        free(pixels);
        std::cerr << "Error: no crystals-encaps chunk — not an encaps PNG; use 'decode'\n";
        return 2;
    }

    TrayMeta meta;
    EncapsMeta em;
    try {
        meta = parse_meta(meta_text);
        em   = parse_encaps_meta(encaps_text);
    } catch (const std::exception& e) {
        free(pixels); std::cerr << "Error: " << e.what() << "\n"; return 2;
    }

    // ── 3. Look up profile ────────────────────────────────────────────────────
    auto pit = PROFILES.find(meta.profile);
    if (pit == PROFILES.end()) {
        free(pixels);
        std::cerr << "Error: unknown profile '" << meta.profile << "'\n";
        return 2;
    }
    const auto& slot_defs = pit->second;

    // ── 4. Compute byte counts ────────────────────────────────────────────────
    size_t cl_pk_bytes = 0, cl_sk_bytes = 0, pq_pk_bytes = 0, pq_sk_bytes = 0;
    for (const auto& sd : slot_defs) {
        if (is_pq_slot(sd.alg_name)) {
            pq_pk_bytes += sd.pk_size;
            pq_sk_bytes += sd.sk_size;
        } else {
            cl_pk_bytes += sd.pk_size;
            cl_sk_bytes += sd.sk_size;
        }
    }

    // ── 5. Reconstruct encaps image geometry ──────────────────────────────────
    unsigned cl_rows = std::max(row_count_cw(cl_pk_bytes, ENCAPS_COL_W),
                                 row_count_cw(cl_sk_bytes, ENCAPS_COL_W));
    unsigned pq_rows = std::max(row_count_cw(pq_pk_bytes, ENCAPS_COL_W),
                                 row_count_cw(pq_sk_bytes, ENCAPS_COL_W));

    unsigned y_keys = ENCAPS_MARGIN + LINE_SPACING + FONT_H + ENCAPS_GAP;  // = 38
    unsigned y_cl   = y_keys;
    unsigned y_pq   = y_cl + cl_rows + (cl_rows > 0 && pq_rows > 0 ? ENCAPS_GAP : 0);

    unsigned total_key_h = cl_rows + (cl_rows > 0 && pq_rows > 0 ? ENCAPS_GAP : 0) + pq_rows;
    if (total_key_h == 0) total_key_h = 1;
    unsigned y_kem = y_keys + total_key_h + ENCAPS_GAP;

    unsigned content_w = ENCAPS_IMG_W - 2 * ENCAPS_MARGIN;
    unsigned x_pk  = ENCAPS_MARGIN;
    unsigned x_sk  = ENCAPS_MARGIN + ENCAPS_COL_W + ENCAPS_GAP;
    unsigned x_kem = ENCAPS_MARGIN + (content_w - KEM_BLOB_BYTES) / 2;

    // ── 6. Read pixel blocks ──────────────────────────────────────────────────
    auto rlut = build_reverse_lut();
    std::vector<uint8_t> cl_pk_data, cl_sk_enc, pq_pk_data, pq_sk_enc, kem_raw;
    try {
        if (cl_rows > 0) {
            cl_pk_data = read_block(pixels, img_w, rlut, x_pk, y_cl, cl_pk_bytes, ENCAPS_COL_W);
            cl_sk_enc  = read_block(pixels, img_w, rlut, x_sk, y_cl, cl_sk_bytes, ENCAPS_COL_W);
        }
        if (pq_rows > 0) {
            pq_pk_data = read_block(pixels, img_w, rlut, x_pk, y_pq, pq_pk_bytes, ENCAPS_COL_W);
            pq_sk_enc  = read_block(pixels, img_w, rlut, x_sk, y_pq, pq_sk_bytes, ENCAPS_COL_W);
        }
        kem_raw = read_block(pixels, img_w, rlut, x_kem, y_kem, KEM_BLOB_BYTES, KEM_BLOB_BYTES);
    } catch (const std::exception& e) {
        free(pixels); std::cerr << "Error: " << e.what() << "\n"; return 2;
    }
    free(pixels);

    // ── 7. Get password and derive wrap_key ───────────────────────────────────
    std::string password;
    try { password = get_password_decaps(pwfile); }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 1;
    }

    std::vector<uint8_t> wrap_key;
    try { wrap_key = encaps_derive_key(password, em.salt, em.n_log2); }
    catch (const std::exception& e) {
        std::cerr << "Error: key derivation failed: " << e.what() << "\n"; return 2;
    }
    OPENSSL_cleanse((void*)password.data(), password.size());

    // ── 8. Decrypt data_key from KEM block ────────────────────────────────────
    // kem_raw = nonce(12)||tag(16)||ct(32) — same format as aes_enc output
    std::vector<uint8_t> data_key;
    try {
        data_key = encaps_aes_dec(wrap_key, kem_raw);
    } catch (const std::exception&) {
        OPENSSL_cleanse(wrap_key.data(), wrap_key.size());
        std::cerr << "Error: decryption failed — wrong password or corrupted image\n";
        return 2;
    }
    OPENSSL_cleanse(wrap_key.data(), wrap_key.size());

    // ── 9. Reconstruct all_sk_enc in slot order ───────────────────────────────
    std::vector<uint8_t> all_sk_enc;
    size_t cl_sk_off = 0, pq_sk_off = 0;
    for (const auto& sd : slot_defs) {
        if (is_pq_slot(sd.alg_name)) {
            all_sk_enc.insert(all_sk_enc.end(),
                               pq_sk_enc.begin() + (std::ptrdiff_t)pq_sk_off,
                               pq_sk_enc.begin() + (std::ptrdiff_t)(pq_sk_off + sd.sk_size));
            pq_sk_off += sd.sk_size;
        } else {
            all_sk_enc.insert(all_sk_enc.end(),
                               cl_sk_enc.begin() + (std::ptrdiff_t)cl_sk_off,
                               cl_sk_enc.begin() + (std::ptrdiff_t)(cl_sk_off + sd.sk_size));
            cl_sk_off += sd.sk_size;
        }
    }

    // ── 10. Decrypt all_sk ────────────────────────────────────────────────────
    // Reassemble nonce(12)||tag(16)||ct for AES-GCM
    std::vector<uint8_t> sk_blob;
    sk_blob.insert(sk_blob.end(), em.sk_nonce.begin(), em.sk_nonce.end());
    sk_blob.insert(sk_blob.end(), em.sk_tag.begin(),   em.sk_tag.end());
    sk_blob.insert(sk_blob.end(), all_sk_enc.begin(),  all_sk_enc.end());

    std::vector<uint8_t> all_sk;
    try {
        all_sk = encaps_aes_dec(data_key, sk_blob);
    } catch (const std::exception&) {
        OPENSSL_cleanse(data_key.data(), data_key.size());
        std::cerr << "Error: SK decryption failed — corrupted image or metadata\n";
        return 2;
    }
    OPENSSL_cleanse(data_key.data(), data_key.size());

    // ── 11. Split all_sk into per-slot sk ─────────────────────────────────────
    std::vector<uint8_t> cl_pk_data_dec, cl_sk_data, pq_pk_data_dec, pq_sk_data;
    // pk data for reconstruction (same as from image)
    cl_pk_data_dec = cl_pk_data;
    pq_pk_data_dec = pq_pk_data;

    size_t all_sk_off = 0;
    for (const auto& sd : slot_defs) {
        auto sk = std::vector<uint8_t>(all_sk.begin() + (std::ptrdiff_t)all_sk_off,
                                        all_sk.begin() + (std::ptrdiff_t)(all_sk_off + sd.sk_size));
        all_sk_off += sd.sk_size;
        if (is_pq_slot(sd.alg_name))
            pq_sk_data.insert(pq_sk_data.end(), sk.begin(), sk.end());
        else
            cl_sk_data.insert(cl_sk_data.end(), sk.begin(), sk.end());
    }
    OPENSSL_cleanse(all_sk.data(), all_sk.size());

    // ── 12. Reconstruct Tray ──────────────────────────────────────────────────
    Tray tray;
    tray.version       = 1;
    tray.alias         = meta.alias;
    tray.id            = meta.id;
    tray.type_str      = meta.profile;
    tray.profile_group = "crystals";
    tray.created       = meta.created;
    tray.expires       = meta.expires;

    if      (meta.profile == "level0")       tray.tray_type = TrayType::Level0;
    else if (meta.profile == "level1")       tray.tray_type = TrayType::Level1;
    else if (meta.profile == "level2-25519") tray.tray_type = TrayType::Level2_25519;
    else if (meta.profile == "level2")       tray.tray_type = TrayType::Level2;
    else if (meta.profile == "level3")       tray.tray_type = TrayType::Level3;
    else if (meta.profile == "level5")       tray.tray_type = TrayType::Level5;

    size_t cl_pk_off = 0, cl_sk_off2 = 0, pq_pk_off = 0, pq_sk_off2 = 0;
    for (const auto& sd : slot_defs) {
        Slot s;
        s.alg_name = sd.alg_name;
        if (is_pq_slot(sd.alg_name)) {
            s.pk = std::vector<uint8_t>(pq_pk_data_dec.begin() + (std::ptrdiff_t)pq_pk_off,
                                         pq_pk_data_dec.begin() + (std::ptrdiff_t)(pq_pk_off + sd.pk_size));
            pq_pk_off += sd.pk_size;
            s.sk = std::vector<uint8_t>(pq_sk_data.begin() + (std::ptrdiff_t)pq_sk_off2,
                                         pq_sk_data.begin() + (std::ptrdiff_t)(pq_sk_off2 + sd.sk_size));
            pq_sk_off2 += sd.sk_size;
        } else {
            s.pk = std::vector<uint8_t>(cl_pk_data_dec.begin() + (std::ptrdiff_t)cl_pk_off,
                                         cl_pk_data_dec.begin() + (std::ptrdiff_t)(cl_pk_off + sd.pk_size));
            cl_pk_off += sd.pk_size;
            s.sk = std::vector<uint8_t>(cl_sk_data.begin() + (std::ptrdiff_t)cl_sk_off2,
                                         cl_sk_data.begin() + (std::ptrdiff_t)(cl_sk_off2 + sd.sk_size));
            cl_sk_off2 += sd.sk_size;
        }
        tray.slots.push_back(std::move(s));
    }

    // ── 13. Output ────────────────────────────────────────────────────────────
    if (!out_file.empty()) {
        if (!write_tray_file(tray, out_file, "Decaps")) return 3;
    } else {
        try { std::cout << emit_tray_yaml(tray); }
        catch (const std::exception& e) {
            std::cerr << "Error: YAML output failed: " << e.what() << "\n"; return 3;
        }
    }
    return 0;
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    const std::string cmd = argv[1];
    if (cmd == "render") return cmd_render(argc - 1, argv + 1);
    if (cmd == "decode") return cmd_decode(argc - 1, argv + 1);
    if (cmd == "encaps") return cmd_encaps(argc - 1, argv + 1);
    if (cmd == "decaps") return cmd_decaps(argc - 1, argv + 1);
    if (cmd == "--help" || cmd == "-h") { print_usage(argv[0]); return 0; }

    std::cerr << "Error: unknown command '" << cmd << "'\n";
    print_usage(argv[0]);
    return 1;
}

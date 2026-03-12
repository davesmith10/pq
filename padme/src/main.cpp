#include <crystals/tray.hpp>
#include <crystals/tray_reader.hpp>
#include "lodepng.h"

#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// ── Rainbow palette ───────────────────────────────────────────────────────────
// Maps byte value 0–255 to HSV color with hue 0°–360°, S=1, V=1.

static std::array<uint8_t, 3> byte_to_rgb(uint8_t v) {
    double h  = (v / 255.0) * 360.0;
    double h6 = h / 60.0;
    int    i  = static_cast<int>(h6) % 6;
    double f  = h6 - std::floor(h6);

    // p=0, q=1-f, t=f  (S=1, V=1)
    double r, g, b;
    switch (i) {
        case 0: r = 1.0; g = f;       b = 0.0; break;
        case 1: r = 1-f; g = 1.0;     b = 0.0; break;
        case 2: r = 0.0; g = 1.0;     b = f;   break;
        case 3: r = 0.0; g = 1.0-f;   b = 1.0; break;
        case 4: r = f;   g = 0.0;     b = 1.0; break;
        default:r = 1.0; g = 0.0;     b = 1.0-f; break;
    }

    return {
        static_cast<uint8_t>(r * 255.0 + 0.5),
        static_cast<uint8_t>(g * 255.0 + 0.5),
        static_cast<uint8_t>(b * 255.0 + 0.5)
    };
}

// ── Image builder ─────────────────────────────────────────────────────────────

static const unsigned MARGIN    = 8;
static const unsigned GAP       = 8;
static const unsigned ROW_WIDTH = 32;

struct ImageResult {
    std::vector<uint8_t> pixels;
    unsigned w, h;
};

static ImageResult build_image(const Tray& tray) {
    struct SlotData {
        std::vector<uint8_t> bytes;
        unsigned rows;
    };

    std::vector<SlotData> slots;
    slots.reserve(tray.slots.size());
    for (const auto& s : tray.slots) {
        SlotData sd;
        sd.bytes = s.pk;
        sd.bytes.insert(sd.bytes.end(), s.sk.begin(), s.sk.end());
        if (sd.bytes.empty())
            sd.bytes.push_back(0);  // ensure at least 1 pixel
        sd.rows = static_cast<unsigned>((sd.bytes.size() + ROW_WIDTH - 1) / ROW_WIDTH);
        slots.push_back(std::move(sd));
    }

    unsigned total_slot_rows = 0;
    for (const auto& sd : slots)
        total_slot_rows += sd.rows;

    unsigned n    = static_cast<unsigned>(slots.size());
    unsigned gaps = (n > 1) ? (n - 1) * GAP : 0;
    unsigned img_w = MARGIN * 2 + ROW_WIDTH;
    unsigned img_h = MARGIN * 2 + total_slot_rows + gaps;

    // Allocate white RGBA buffer (255 in every channel)
    std::vector<uint8_t> pixels(img_w * img_h * 4, 0xFF);

    // Fill slot rectangles row by row
    unsigned y = MARGIN;
    for (size_t si = 0; si < slots.size(); ++si) {
        const auto& sd = slots[si];
        for (unsigned row = 0; row < sd.rows; ++row) {
            for (unsigned col = 0; col < ROW_WIDTH; ++col) {
                size_t  byte_idx = static_cast<size_t>(row) * ROW_WIDTH + col;
                uint8_t bval     = (byte_idx < sd.bytes.size()) ? sd.bytes[byte_idx] : 0;
                auto [r, g, b]   = byte_to_rgb(bval);
                size_t px = ((y + row) * img_w + (MARGIN + col)) * 4;
                pixels[px + 0] = r;
                pixels[px + 1] = g;
                pixels[px + 2] = b;
                pixels[px + 3] = 255;
            }
        }
        y += sd.rows;
        if (si + 1 < slots.size())
            y += GAP;
    }

    return {std::move(pixels), img_w, img_h};
}

// ── render command ────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " render\n"
        "              --tray <file>\n"
        "              [--out <file.png>]\n"
        "\n"
        "  --tray <file>      Tray file to visualize (YAML or msgpack)\n"
        "  --out  <file.png>  Output PNG path (default: <alias>.png)\n"
        "\n"
        "Renders each tray slot's key bytes as rainbow-colored pixels.\n"
        "pk+sk bytes are concatenated per slot; slots are stacked vertically.\n";
}

static int cmd_render(int argc, char* argv[]) {
    std::string tray_file;
    std::string out_file;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--tray") == 0) {
            if (++i >= argc) { std::cerr << "Error: --tray requires a filename\n"; return 1; }
            tray_file = argv[i];
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a filename\n"; return 1; }
            out_file = argv[i];
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n";
            return 1;
        }
    }

    if (tray_file.empty()) {
        std::cerr << "Error: --tray is required\n";
        return 1;
    }

    Tray tray;
    try {
        tray = load_tray(tray_file);
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to load tray: " << e.what() << "\n";
        return 2;
    }

    if (out_file.empty())
        out_file = tray.alias + ".png";

    ImageResult img;
    try {
        img = build_image(tray);
    } catch (const std::exception& e) {
        std::cerr << "Error: image build failed: " << e.what() << "\n";
        return 2;
    }

    unsigned err = lodepng::encode(out_file, img.pixels, img.w, img.h);
    if (err) {
        std::cerr << "Error: PNG write failed: " << lodepng_error_text(err) << "\n";
        return 3;
    }

    std::cout << "Rendered tray '" << tray.alias << "' \xe2\x86\x92 " << out_file
              << " (" << img.w << "\xc3\x97" << img.h << " px, "
              << tray.slots.size() << " slots)\n";
    return 0;
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string cmd = argv[1];

    if (cmd == "render") {
        return cmd_render(argc - 1, argv + 1);
    }

    if (cmd == "--help" || cmd == "-h") {
        print_usage(argv[0]);
        return 0;
    }

    std::cerr << "Error: unknown command '" << cmd << "'\n";
    print_usage(argv[0]);
    return 1;
}

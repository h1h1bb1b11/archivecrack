#pragma once
// Minimal raw DEFLATE decoder (MIT-style, derived from the logq project).
#include <string>
#include <cstddef>

namespace zinflate {

struct BitReader {
    const unsigned char* data = nullptr;
    size_t size = 0;
    size_t pos = 0;
    unsigned long buf = 0;
    int cnt = 0;
    bool error = false;

    int bits(int need) {
        unsigned long val = buf;
        while (cnt < need) {
            if (pos >= size) {
                error = true;
                return -1;
            }
            val |= static_cast<unsigned long>(data[pos++]) << cnt;
            cnt += 8;
        }
        buf = val >> need;
        cnt -= need;
        return static_cast<int>(val & ((1UL << need) - 1));
    }

    // 丢弃当前字节剩余的比特（stored 块前需要对齐）
    void alignByte() {
        buf = 0;
        cnt = 0;
    }
};

struct Huffman {
    short count[16] = {0};
    short symbol[288] = {0};
};

// 构造规范 Huffman 表；返回剩余码数，0 表示完整，负数表示码长非法
int construct(Huffman* h, const short* length, int n) {
    for (int len = 0; len <= 15; ++len) h->count[len] = 0;
    for (int sym = 0; sym < n; ++sym) h->count[length[sym]]++;
    if (h->count[0] == n) return 0;

    int left = 1;
    for (int len = 1; len <= 15; ++len) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0) return left;
    }

    short offs[16] = {0};
    for (int len = 1; len < 15; ++len) offs[len + 1] = offs[len] + h->count[len];
    for (int sym = 0; sym < n; ++sym)
        if (length[sym] != 0) h->symbol[offs[length[sym]]++] = static_cast<short>(sym);
    return left;
}

int decodeSym(BitReader& s, const Huffman& h) {
    int len = 1, code = 0, first = 0, index = 0;
    for (; len <= 15; ++len) {
        int b = s.bits(1);
        if (b < 0) return -1;
        code |= b;
        int count = h.count[len];
        if (code - count < first) return h.symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

const short LEN_BASE[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                            35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const short LEN_EXTRA[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                             2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const short DIST_BASE[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
                             193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
                             6145, 8193, 12289, 16385, 24577};
const short DIST_EXTRA[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
                              6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

bool inflateCodes(BitReader& s, const Huffman& lencode, const Huffman& distcode,
                  std::string& out) {
    for (;;) {
        int sym = decodeSym(s, lencode);
        if (sym < 0) return false;
        if (sym < 256) {
            out.push_back(static_cast<char>(sym));
        } else if (sym == 256) {
            return true;
        } else {
            sym -= 257;
            if (sym >= 29) return false;
            int extra = LEN_EXTRA[sym];
            int e = extra ? s.bits(extra) : 0;
            if (e < 0) return false;
            int len = LEN_BASE[sym] + e;

            int dsym = decodeSym(s, distcode);
            if (dsym < 0 || dsym >= 30) return false;
            int dextra = DIST_EXTRA[dsym];
            int d = dextra ? s.bits(dextra) : 0;
            if (d < 0) return false;
            size_t dist = static_cast<size_t>(DIST_BASE[dsym] + d);
            if (dist == 0 || dist > out.size()) return false;

            size_t from = out.size() - dist;
            for (int i = 0; i < len; ++i) out.push_back(out[from + i]);
        }
    }
}

bool inflateRaw(const unsigned char* data, size_t size, std::string& out) {
    BitReader s;
    s.data = data;
    s.size = size;

    int last = 0;
    do {
        last = s.bits(1);
        int type = s.bits(2);
        if (last < 0 || type < 0) return false;

        if (type == 0) {
            s.alignByte();
            if (s.pos + 4 > s.size) return false;
            unsigned len = s.data[s.pos] | (static_cast<unsigned>(s.data[s.pos + 1]) << 8);
            unsigned nlen = s.data[s.pos + 2] | (static_cast<unsigned>(s.data[s.pos + 3]) << 8);
            s.pos += 4;
            if ((len ^ 0xFFFFu) != nlen) return false;
            if (s.pos + len > s.size) return false;
            out.append(reinterpret_cast<const char*>(s.data + s.pos), len);
            s.pos += len;
        } else if (type == 1) {
            static Huffman lencode, distcode;
            static bool built = false;
            if (!built) {
                short lengths[288];
                int sym = 0;
                for (; sym < 144; ++sym) lengths[sym] = 8;
                for (; sym < 256; ++sym) lengths[sym] = 9;
                for (; sym < 280; ++sym) lengths[sym] = 7;
                for (; sym < 288; ++sym) lengths[sym] = 8;
                construct(&lencode, lengths, 288);
                short dl[30];
                for (int i = 0; i < 30; ++i) dl[i] = 5;
                construct(&distcode, dl, 30);
                built = true;
            }
            if (!inflateCodes(s, lencode, distcode, out)) return false;
        } else if (type == 2) {
            int hlit = s.bits(5);
            int hdist = s.bits(5);
            int hclen = s.bits(4);
            if (hlit < 0 || hdist < 0 || hclen < 0) return false;
            hlit += 257;
            hdist += 1;
            hclen += 4;
            if (hlit > 286 || hdist > 30) return false;

            static const int order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5,
                                          11, 4, 12, 3, 13, 2, 14, 1, 15};
            short lengths[320] = {0};
            for (int i = 0; i < hclen; ++i) {
                int v = s.bits(3);
                if (v < 0) return false;
                lengths[order[i]] = static_cast<short>(v);
            }
            Huffman clcode;
            if (construct(&clcode, lengths, 19) != 0) return false;

            int idx = 0;
            int total = hlit + hdist;
            while (idx < total) {
                int sym = decodeSym(s, clcode);
                if (sym < 0) return false;
                if (sym < 16) {
                    lengths[idx++] = static_cast<short>(sym);
                } else {
                    int rep;
                    short value = 0;
                    if (sym == 16) {
                        if (idx == 0) return false;
                        value = lengths[idx - 1];
                        int v = s.bits(2);
                        if (v < 0) return false;
                        rep = 3 + v;
                    } else if (sym == 17) {
                        int v = s.bits(3);
                        if (v < 0) return false;
                        rep = 3 + v;
                    } else {
                        int v = s.bits(7);
                        if (v < 0) return false;
                        rep = 11 + v;
                    }
                    if (idx + rep > total) return false;
                    while (rep-- > 0) lengths[idx++] = value;
                }
            }

            Huffman lencode, distcode;
            if (construct(&lencode, lengths, hlit) != 0) return false;
            if (construct(&distcode, lengths + hlit, hdist) != 0) return false;
            if (!inflateCodes(s, lencode, distcode, out)) return false;
        } else {
            return false;
        }
    } while (!last);

    return true;
}

// 解析 gzip 容器并解压到 out（只处理单 member）
bool gunzip(const std::string& raw, std::string& out) {
    const unsigned char* data = reinterpret_cast<const unsigned char*>(raw.data());
    size_t size = raw.size();
    if (size < 18) return false;
    if (data[0] != 0x1F || data[1] != 0x8B || data[2] != 8) return false;

    unsigned flg = data[3];
    size_t pos = 10;
    if (flg & 4) {  // FEXTRA
        if (pos + 2 > size) return false;
        size_t xlen = data[pos] | (static_cast<size_t>(data[pos + 1]) << 8);
        pos += 2 + xlen;
    }
    if (flg & 8) {  // FNAME
        while (pos < size && data[pos] != 0) ++pos;
        ++pos;
    }
    if (flg & 16) {  // FCOMMENT
        while (pos < size && data[pos] != 0) ++pos;
        ++pos;
    }
    if (flg & 2) pos += 2;  // FHCRC
    if (pos >= size) return false;

    out.clear();
    return inflateRaw(data + pos, size - pos, out);
}

}  // namespace zinflate

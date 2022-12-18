// SPDX-FileCopyrightText: Copyright 2018 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <array>
#include <bitset>
#include <cctype>
#include <fstream>
#include <locale>
#include <map>
#include <sstream>
#include <tuple>
#include <vector>
#include <mbedtls/bignum.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <mbedtls/sha256.h>
#include "common/fs/file.h"
#include "common/fs/fs.h"
#include "common/fs/path_util.h"
#include "common/hex_util.h"
#include "common/logging/log.h"
#include "common/settings.h"
#include "common/string_util.h"
#include "core/crypto/aes_util.h"
#include "core/crypto/key_manager.h"
#include "core/crypto/partition_data_manager.h"
#include "core/file_sys/content_archive.h"
#include "core/file_sys/nca_metadata.h"
#include "core/file_sys/registered_cache.h"
#include "core/hle/service/filesystem/filesystem.h"
#include "core/loader/loader.h"

namespace Core::Crypto {
namespace {

constexpr u64 CURRENT_CRYPTO_REVISION = 0x5;
constexpr u64 FULL_TICKET_SIZE = 0x400;

using Common::AsArray;

// clang-format off
constexpr std::array eticket_source_hashes{
    AsArray("B71DB271DC338DF380AA2C4335EF8873B1AFD408E80B3582D8719FC81C5E511C"), // eticket_rsa_kek_source
    AsArray("E8965A187D30E57869F562D04383C996DE487BBA5761363D2D4D32391866A85C"), // eticket_rsa_kekek_source
};
// clang-format on

constexpr std::array<std::pair<std::string_view, KeyIndex<S128KeyType>>, 30> s128_file_id{{
    {"eticket_rsa_kek", {S128KeyType::ETicketRSAKek, 0, 0}},
    {"eticket_rsa_kek_source",
     {S128KeyType::Source, static_cast<u64>(SourceKeyType::ETicketKek), 0}},
    {"eticket_rsa_kekek_source",
     {S128KeyType::Source, static_cast<u64>(SourceKeyType::ETicketKekek), 0}},
    {"rsa_kek_mask_0", {S128KeyType::RSAKek, static_cast<u64>(RSAKekType::Mask0), 0}},
    {"rsa_kek_seed_3", {S128KeyType::RSAKek, static_cast<u64>(RSAKekType::Seed3), 0}},
    {"rsa_oaep_kek_generation_source",
     {S128KeyType::Source, static_cast<u64>(SourceKeyType::RSAOaepKekGeneration), 0}},
    {"sd_card_kek_source", {S128KeyType::Source, static_cast<u64>(SourceKeyType::SDKek), 0}},
    {"aes_kek_generation_source",
     {S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKekGeneration), 0}},
    {"aes_key_generation_source",
     {S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKeyGeneration), 0}},
    {"package2_key_source", {S128KeyType::Source, static_cast<u64>(SourceKeyType::Package2), 0}},
    {"master_key_source", {S128KeyType::Source, static_cast<u64>(SourceKeyType::Master), 0}},
    {"header_kek_source", {S128KeyType::Source, static_cast<u64>(SourceKeyType::HeaderKek), 0}},
    {"key_area_key_application_source",
     {S128KeyType::Source, static_cast<u64>(SourceKeyType::KeyAreaKey),
      static_cast<u64>(KeyAreaKeyType::Application)}},
    {"key_area_key_ocean_source",
     {S128KeyType::Source, static_cast<u64>(SourceKeyType::KeyAreaKey),
      static_cast<u64>(KeyAreaKeyType::Ocean)}},
    {"key_area_key_system_source",
     {S128KeyType::Source, static_cast<u64>(SourceKeyType::KeyAreaKey),
      static_cast<u64>(KeyAreaKeyType::System)}},
    {"titlekek_source", {S128KeyType::Source, static_cast<u64>(SourceKeyType::Titlekek), 0}},
    {"keyblob_mac_key_source",
     {S128KeyType::Source, static_cast<u64>(SourceKeyType::KeyblobMAC), 0}},
    {"tsec_key", {S128KeyType::TSEC, 0, 0}},
    {"secure_boot_key", {S128KeyType::SecureBoot, 0, 0}},
    {"sd_seed", {S128KeyType::SDSeed, 0, 0}},
    {"bis_key_0_crypt", {S128KeyType::BIS, 0, static_cast<u64>(BISKeyType::Crypto)}},
    {"bis_key_0_tweak", {S128KeyType::BIS, 0, static_cast<u64>(BISKeyType::Tweak)}},
    {"bis_key_1_crypt", {S128KeyType::BIS, 1, static_cast<u64>(BISKeyType::Crypto)}},
    {"bis_key_1_tweak", {S128KeyType::BIS, 1, static_cast<u64>(BISKeyType::Tweak)}},
    {"bis_key_2_crypt", {S128KeyType::BIS, 2, static_cast<u64>(BISKeyType::Crypto)}},
    {"bis_key_2_tweak", {S128KeyType::BIS, 2, static_cast<u64>(BISKeyType::Tweak)}},
    {"bis_key_3_crypt", {S128KeyType::BIS, 3, static_cast<u64>(BISKeyType::Crypto)}},
    {"bis_key_3_tweak", {S128KeyType::BIS, 3, static_cast<u64>(BISKeyType::Tweak)}},
    {"header_kek", {S128KeyType::HeaderKek, 0, 0}},
    {"sd_card_kek", {S128KeyType::SDKek, 0, 0}},
}};

auto Find128ByName(std::string_view name) {
    return std::find_if(s128_file_id.begin(), s128_file_id.end(),
                        [&name](const auto& pair) { return pair.first == name; });
}

constexpr std::array<std::pair<std::string_view, KeyIndex<S256KeyType>>, 6> s256_file_id{{
    {"header_key", {S256KeyType::Header, 0, 0}},
    {"sd_card_save_key_source", {S256KeyType::SDKeySource, static_cast<u64>(SDKeyType::Save), 0}},
    {"sd_card_nca_key_source", {S256KeyType::SDKeySource, static_cast<u64>(SDKeyType::NCA), 0}},
    {"header_key_source", {S256KeyType::HeaderSource, 0, 0}},
    {"sd_card_save_key", {S256KeyType::SDKey, static_cast<u64>(SDKeyType::Save), 0}},
    {"sd_card_nca_key", {S256KeyType::SDKey, static_cast<u64>(SDKeyType::NCA), 0}},
}};

auto Find256ByName(std::string_view name) {
    return std::find_if(s256_file_id.begin(), s256_file_id.end(),
                        [&name](const auto& pair) { return pair.first == name; });
}

using KeyArray = std::array<std::pair<std::pair<S128KeyType, u64>, std::string_view>, 7>;
constexpr KeyArray KEYS_VARIABLE_LENGTH{{
    {{S128KeyType::Master, 0}, "master_key_"},
    {{S128KeyType::Package1, 0}, "package1_key_"},
    {{S128KeyType::Package2, 0}, "package2_key_"},
    {{S128KeyType::Titlekek, 0}, "titlekek_"},
    {{S128KeyType::Source, static_cast<u64>(SourceKeyType::Keyblob)}, "keyblob_key_source_"},
    {{S128KeyType::Keyblob, 0}, "keyblob_key_"},
    {{S128KeyType::KeyblobMAC, 0}, "keyblob_mac_key_"},
}};

template <std::size_t Size>
bool IsAllZeroArray(const std::array<u8, Size>& array) {
    return std::all_of(array.begin(), array.end(), [](const auto& elem) { return elem == 0; });
}
} // Anonymous namespace

u64 GetSignatureTypeDataSize(SignatureType type) {
    switch (type) {
    case SignatureType::RSA_4096_SHA1:
    case SignatureType::RSA_4096_SHA256:
        return 0x200;
    case SignatureType::RSA_2048_SHA1:
    case SignatureType::RSA_2048_SHA256:
        return 0x100;
    case SignatureType::ECDSA_SHA1:
    case SignatureType::ECDSA_SHA256:
        return 0x3C;
    }
    UNREACHABLE();
}

u64 GetSignatureTypePaddingSize(SignatureType type) {
    switch (type) {
    case SignatureType::RSA_4096_SHA1:
    case SignatureType::RSA_4096_SHA256:
    case SignatureType::RSA_2048_SHA1:
    case SignatureType::RSA_2048_SHA256:
        return 0x3C;
    case SignatureType::ECDSA_SHA1:
    case SignatureType::ECDSA_SHA256:
        return 0x40;
    }
    UNREACHABLE();
}

SignatureType Ticket::GetSignatureType() const {
    if (const auto* ticket = std::get_if<RSA4096Ticket>(&data)) {
        return ticket->sig_type;
    }
    if (const auto* ticket = std::get_if<RSA2048Ticket>(&data)) {
        return ticket->sig_type;
    }
    if (const auto* ticket = std::get_if<ECDSATicket>(&data)) {
        return ticket->sig_type;
    }
    throw std::bad_variant_access{};
}

TicketData& Ticket::GetData() {
    if (auto* ticket = std::get_if<RSA4096Ticket>(&data)) {
        return ticket->data;
    }
    if (auto* ticket = std::get_if<RSA2048Ticket>(&data)) {
        return ticket->data;
    }
    if (auto* ticket = std::get_if<ECDSATicket>(&data)) {
        return ticket->data;
    }
    throw std::bad_variant_access{};
}

const TicketData& Ticket::GetData() const {
    if (const auto* ticket = std::get_if<RSA4096Ticket>(&data)) {
        return ticket->data;
    }
    if (const auto* ticket = std::get_if<RSA2048Ticket>(&data)) {
        return ticket->data;
    }
    if (const auto* ticket = std::get_if<ECDSATicket>(&data)) {
        return ticket->data;
    }
    throw std::bad_variant_access{};
}

u64 Ticket::GetSize() const {
    const auto sig_type = GetSignatureType();

    return sizeof(SignatureType) + GetSignatureTypeDataSize(sig_type) +
           GetSignatureTypePaddingSize(sig_type) + sizeof(TicketData);
}

Ticket Ticket::SynthesizeCommon(Key128 title_key, const std::array<u8, 16>& rights_id) {
    RSA2048Ticket out{};
    out.sig_type = SignatureType::RSA_2048_SHA256;
    out.data.rights_id = rights_id;
    out.data.title_key_common = title_key;
    return Ticket{out};
}

Key128 GenerateKeyEncryptionKey(Key128 source, Key128 master, Key128 kek_seed, Key128 key_seed) {
    Key128 out{};

    AESCipher<Key128> cipher1(master, Mode::ECB);
    cipher1.Transcode(kek_seed.data(), kek_seed.size(), out.data(), Op::Decrypt);
    AESCipher<Key128> cipher2(out, Mode::ECB);
    cipher2.Transcode(source.data(), source.size(), out.data(), Op::Decrypt);

    if (key_seed != Key128{}) {
        AESCipher<Key128> cipher3(out, Mode::ECB);
        cipher3.Transcode(key_seed.data(), key_seed.size(), out.data(), Op::Decrypt);
    }

    return out;
}

Key128 DeriveKeyblobKey(const Key128& sbk, const Key128& tsec, Key128 source) {
    AESCipher<Key128> sbk_cipher(sbk, Mode::ECB);
    AESCipher<Key128> tsec_cipher(tsec, Mode::ECB);
    tsec_cipher.Transcode(source.data(), source.size(), source.data(), Op::Decrypt);
    sbk_cipher.Transcode(source.data(), source.size(), source.data(), Op::Decrypt);
    return source;
}

Key128 DeriveMasterKey(const std::array<u8, 0x90>& keyblob, const Key128& master_source) {
    Key128 master_root;
    std::memcpy(master_root.data(), keyblob.data(), sizeof(Key128));

    AESCipher<Key128> master_cipher(master_root, Mode::ECB);

    Key128 master{};
    master_cipher.Transcode(master_source.data(), master_source.size(), master.data(), Op::Decrypt);
    return master;
}

std::array<u8, 144> DecryptKeyblob(const std::array<u8, 176>& encrypted_keyblob,
                                   const Key128& key) {
    std::array<u8, 0x90> keyblob;
    AESCipher<Key128> cipher(key, Mode::CTR);
    cipher.SetIV(std::vector<u8>(encrypted_keyblob.data() + 0x10, encrypted_keyblob.data() + 0x20));
    cipher.Transcode(encrypted_keyblob.data() + 0x20, keyblob.size(), keyblob.data(), Op::Decrypt);
    return keyblob;
}

void KeyManager::DeriveGeneralPurposeKeys(std::size_t crypto_revision) {
    const auto kek_generation_source =
        GetKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKekGeneration));
    const auto key_generation_source =
        GetKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKeyGeneration));

    if (HasKey(S128KeyType::Master, crypto_revision)) {
        for (auto kak_type :
             {KeyAreaKeyType::Application, KeyAreaKeyType::Ocean, KeyAreaKeyType::System}) {
            if (HasKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::KeyAreaKey),
                       static_cast<u64>(kak_type))) {
                const auto source =
                    GetKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::KeyAreaKey),
                           static_cast<u64>(kak_type));
                const auto kek =
                    GenerateKeyEncryptionKey(source, GetKey(S128KeyType::Master, crypto_revision),
                                             kek_generation_source, key_generation_source);
                SetKey(S128KeyType::KeyArea, kek, crypto_revision, static_cast<u64>(kak_type));
            }
        }

        AESCipher<Key128> master_cipher(GetKey(S128KeyType::Master, crypto_revision), Mode::ECB);
        for (auto key_type : {SourceKeyType::Titlekek, SourceKeyType::Package2}) {
            if (HasKey(S128KeyType::Source, static_cast<u64>(key_type))) {
                Key128 key{};
                master_cipher.Transcode(
                    GetKey(S128KeyType::Source, static_cast<u64>(key_type)).data(), key.size(),
                    key.data(), Op::Decrypt);
                SetKey(key_type == SourceKeyType::Titlekek ? S128KeyType::Titlekek
                                                           : S128KeyType::Package2,
                       key, crypto_revision);
            }
        }
    }
}

RSAKeyPair<2048> KeyManager::GetETicketRSAKey() const {
    if (IsAllZeroArray(eticket_extended_kek) || !HasKey(S128KeyType::ETicketRSAKek)) {
        return {};
    }

    const auto eticket_final = GetKey(S128KeyType::ETicketRSAKek);

    std::vector<u8> extended_iv(eticket_extended_kek.begin(), eticket_extended_kek.begin() + 0x10);
    std::array<u8, 0x230> extended_dec{};
    AESCipher<Key128> rsa_1(eticket_final, Mode::CTR);
    rsa_1.SetIV(extended_iv);
    rsa_1.Transcode(eticket_extended_kek.data() + 0x10, eticket_extended_kek.size() - 0x10,
                    extended_dec.data(), Op::Decrypt);

    RSAKeyPair<2048> rsa_key{};
    std::memcpy(rsa_key.decryption_key.data(), extended_dec.data(), rsa_key.decryption_key.size());
    std::memcpy(rsa_key.modulus.data(), extended_dec.data() + 0x100, rsa_key.modulus.size());
    std::memcpy(rsa_key.exponent.data(), extended_dec.data() + 0x200, rsa_key.exponent.size());

    return rsa_key;
}

Key128 DeriveKeyblobMACKey(const Key128& keyblob_key, const Key128& mac_source) {
    AESCipher<Key128> mac_cipher(keyblob_key, Mode::ECB);
    Key128 mac_key{};
    mac_cipher.Transcode(mac_source.data(), mac_key.size(), mac_key.data(), Op::Decrypt);
    return mac_key;
}

std::optional<Key128> DeriveSDSeed() {
    const auto system_save_43_path =
        Common::FS::GetYuzuPath(Common::FS::YuzuPath::NANDDir) / "system/save/8000000000000043";
    const Common::FS::IOFile save_43{system_save_43_path, Common::FS::FileAccessMode::Read,
                                     Common::FS::FileType::BinaryFile};

    if (!save_43.IsOpen()) {
        return std::nullopt;
    }

    const auto sd_private_path =
        Common::FS::GetYuzuPath(Common::FS::YuzuPath::SDMCDir) / "Nintendo/Contents/private";

    const Common::FS::IOFile sd_private{sd_private_path, Common::FS::FileAccessMode::Read,
                                        Common::FS::FileType::BinaryFile};

    if (!sd_private.IsOpen()) {
        return std::nullopt;
    }

    std::array<u8, 0x10> private_seed{};
    if (sd_private.Read(private_seed) != private_seed.size()) {
        return std::nullopt;
    }

    std::array<u8, 0x10> buffer{};
    s64 offset = 0;
    for (; offset + 0x10 < static_cast<s64>(save_43.GetSize()); ++offset) {
        if (!save_43.Seek(offset)) {
            return std::nullopt;
        }

        if (save_43.Read(buffer) != buffer.size()) {
            return std::nullopt;
        }

        if (buffer == private_seed) {
            break;
        }
    }

    if (!save_43.Seek(offset + 0x10)) {
        return std::nullopt;
    }

    Key128 seed{};
    if (save_43.Read(seed) != seed.size()) {
        return std::nullopt;
    }

    return seed;
}

Loader::ResultStatus DeriveSDKeys(std::array<Key256, 2>& sd_keys, KeyManager& keys) {
    if (!keys.HasKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::SDKek))) {
        return Loader::ResultStatus::ErrorMissingSDKEKSource;
    }
    if (!keys.HasKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKekGeneration))) {
        return Loader::ResultStatus::ErrorMissingAESKEKGenerationSource;
    }
    if (!keys.HasKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKeyGeneration))) {
        return Loader::ResultStatus::ErrorMissingAESKeyGenerationSource;
    }

    const auto sd_kek_source =
        keys.GetKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::SDKek));
    const auto aes_kek_gen =
        keys.GetKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKekGeneration));
    const auto aes_key_gen =
        keys.GetKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKeyGeneration));
    const auto master_00 = keys.GetKey(S128KeyType::Master);
    const auto sd_kek =
        GenerateKeyEncryptionKey(sd_kek_source, master_00, aes_kek_gen, aes_key_gen);
    keys.SetKey(S128KeyType::SDKek, sd_kek);

    if (!keys.HasKey(S128KeyType::SDSeed)) {
        return Loader::ResultStatus::ErrorMissingSDSeed;
    }
    const auto sd_seed = keys.GetKey(S128KeyType::SDSeed);

    if (!keys.HasKey(S256KeyType::SDKeySource, static_cast<u64>(SDKeyType::Save))) {
        return Loader::ResultStatus::ErrorMissingSDSaveKeySource;
    }
    if (!keys.HasKey(S256KeyType::SDKeySource, static_cast<u64>(SDKeyType::NCA))) {
        return Loader::ResultStatus::ErrorMissingSDNCAKeySource;
    }

    std::array<Key256, 2> sd_key_sources{
        keys.GetKey(S256KeyType::SDKeySource, static_cast<u64>(SDKeyType::Save)),
        keys.GetKey(S256KeyType::SDKeySource, static_cast<u64>(SDKeyType::NCA)),
    };

    // Combine sources and seed
    for (auto& source : sd_key_sources) {
        for (std::size_t i = 0; i < source.size(); ++i) {
            source[i] = static_cast<u8>(source[i] ^ sd_seed[i & 0xF]);
        }
    }

    AESCipher<Key128> cipher(sd_kek, Mode::ECB);
    // The transform manipulates sd_keys as part of the Transcode, so the return/output is
    // unnecessary. This does not alter sd_keys_sources.
    std::transform(sd_key_sources.begin(), sd_key_sources.end(), sd_keys.begin(),
                   sd_key_sources.begin(), [&cipher](const Key256& source, Key256& out) {
                       cipher.Transcode(source.data(), source.size(), out.data(), Op::Decrypt);
                       return source; ///< Return unaltered source to satisfy output requirement.
                   });

    keys.SetKey(S256KeyType::SDKey, sd_keys[0], static_cast<u64>(SDKeyType::Save));
    keys.SetKey(S256KeyType::SDKey, sd_keys[1], static_cast<u64>(SDKeyType::NCA));

    return Loader::ResultStatus::Success;
}

std::vector<Ticket> GetTicketblob(const Common::FS::IOFile& ticket_save) {
    if (!ticket_save.IsOpen()) {
        return {};
    }

    std::vector<u8> buffer(ticket_save.GetSize());
    if (ticket_save.Read(buffer) != buffer.size()) {
        return {};
    }

    std::vector<Ticket> out;
    for (std::size_t offset = 0; offset + 0x4 < buffer.size(); ++offset) {
        if (buffer[offset] == 0x4 && buffer[offset + 1] == 0x0 && buffer[offset + 2] == 0x1 &&
            buffer[offset + 3] == 0x0) {
            out.emplace_back();
            auto& next = out.back();
            std::memcpy(&next, buffer.data() + offset, sizeof(Ticket));
            offset += FULL_TICKET_SIZE;
        }
    }

    return out;
}

template <size_t size>
static std::array<u8, size> operator^(const std::array<u8, size>& lhs,
                                      const std::array<u8, size>& rhs) {
    std::array<u8, size> out;
    std::transform(lhs.begin(), lhs.end(), rhs.begin(), out.begin(),
                   [](u8 lhs_elem, u8 rhs_elem) { return u8(lhs_elem ^ rhs_elem); });
    return out;
}

template <size_t target_size, size_t in_size>
static std::array<u8, target_size> MGF1(const std::array<u8, in_size>& seed) {
    // Avoids truncation overflow within the loop below.
    static_assert(target_size <= 0xFF);

    std::array<u8, in_size + 4> seed_exp{};
    std::memcpy(seed_exp.data(), seed.data(), in_size);

    std::vector<u8> out;
    size_t i = 0;
    while (out.size() < target_size) {
        out.resize(out.size() + 0x20);
        seed_exp[in_size + 3] = static_cast<u8>(i);
        mbedtls_sha256_ret(seed_exp.data(), seed_exp.size(), out.data() + out.size() - 0x20, 0);
        ++i;
    }

    std::array<u8, target_size> target;
    std::memcpy(target.data(), out.data(), target_size);
    return target;
}

template <size_t size>
static std::optional<u64> FindTicketOffset(const std::array<u8, size>& data) {
    u64 offset = 0;
    for (size_t i = 0x20; i < data.size() - 0x10; ++i) {
        if (data[i] == 0x1) {
            offset = i + 1;
            break;
        } else if (data[i] != 0x0) {
            return std::nullopt;
        }
    }

    return offset;
}

std::optional<std::pair<Key128, Key128>> ParseTicket(const Ticket& ticket,
                                                     const RSAKeyPair<2048>& key) {
    const auto issuer = ticket.GetData().issuer;
    if (IsAllZeroArray(issuer)) {
        return std::nullopt;
    }
    if (issuer[0] != 'R' || issuer[1] != 'o' || issuer[2] != 'o' || issuer[3] != 't') {
        LOG_INFO(Crypto, "Attempting to parse ticket with non-standard certificate authority.");
    }

    Key128 rights_id = ticket.GetData().rights_id;

    if (rights_id == Key128{}) {
        return std::nullopt;
    }

    if (!std::any_of(ticket.GetData().title_key_common_pad.begin(),
                     ticket.GetData().title_key_common_pad.end(), [](u8 b) { return b != 0; })) {
        return std::make_pair(rights_id, ticket.GetData().title_key_common);
    }

    mbedtls_mpi D; // RSA Private Exponent
    mbedtls_mpi N; // RSA Modulus
    mbedtls_mpi S; // Input
    mbedtls_mpi M; // Output

    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&M);

    mbedtls_mpi_read_binary(&D, key.decryption_key.data(), key.decryption_key.size());
    mbedtls_mpi_read_binary(&N, key.modulus.data(), key.modulus.size());
    mbedtls_mpi_read_binary(&S, ticket.GetData().title_key_block.data(), 0x100);

    mbedtls_mpi_exp_mod(&M, &S, &D, &N, nullptr);

    std::array<u8, 0x100> rsa_step;
    mbedtls_mpi_write_binary(&M, rsa_step.data(), rsa_step.size());

    u8 m_0 = rsa_step[0];
    std::array<u8, 0x20> m_1;
    std::memcpy(m_1.data(), rsa_step.data() + 0x01, m_1.size());
    std::array<u8, 0xDF> m_2;
    std::memcpy(m_2.data(), rsa_step.data() + 0x21, m_2.size());

    if (m_0 != 0) {
        return std::nullopt;
    }

    m_1 = m_1 ^ MGF1<0x20>(m_2);
    m_2 = m_2 ^ MGF1<0xDF>(m_1);

    const auto offset = FindTicketOffset(m_2);
    if (!offset) {
        return std::nullopt;
    }
    ASSERT(*offset > 0);

    Key128 key_temp{};
    std::memcpy(key_temp.data(), m_2.data() + *offset, key_temp.size());

    return std::make_pair(rights_id, key_temp);
}

KeyManager::KeyManager() {
    // Initialize keys
    const auto yuzu_keys_dir = Common::FS::GetYuzuPath(Common::FS::YuzuPath::KeysDir);

    if (!Common::FS::CreateDir(yuzu_keys_dir)) {
        LOG_ERROR(Core, "Failed to create the keys directory.");
    }

    auto prod_keys = (yuzu_keys_dir / "prod.keys").u8string();
    auto title_keys = (yuzu_keys_dir / "title.keys").u8string();
    if (!Common::FS::Exists(prod_keys)) {
        std::ofstream fout((const char*)prod_keys.c_str());
        fout << R"(aes_kek_generation_source = 4d870986c45d20722fba1053da92e8a9
aes_key_generation_source = 89615ee05c31b6805fe58f3da24f7aa8
bis_kek_source = 34c1a0c48258f8b4fa9e5e6adafc7e4f
bis_key_00 = 374e0e2ab275141f811badcb0fefd881b71d6af540de58895901aa0c01663bc8
bis_key_01 = 0b08f19a42ac5ae590b3373ad9698344a571f35165663536dae0842b5221b31c
bis_key_02 = 38f0936f33bacedc0c0a159ffbbeee0f40bb08386915bdd0c6730349b99081ec
bis_key_03 = 38f0936f33bacedc0c0a159ffbbeee0f40bb08386915bdd0c6730349b99081ec
bis_key_source_00 = f83f386e2cd2ca32a89ab9aa29bfc7487d92b03aa8bfdee1a74c3b6e35cb7106
bis_key_source_01 = 41003049ddccc065647a7eb41eed9c5f44424edab49dfcd98777249adc9f7ca4
bis_key_source_02 = 52c2e9eb09e3ee2932a10c1fb6a0926c4d12e14b2a474c1c09cb0359f015f4e4
device_key = bd16c45b2647d842c5ee3c869e3a9607
device_key_4x = 2078900c6bb36fff1fdad57a7dd1b66e
eticket_rsa_kek = 19c8b441d318802bad63a5beda283a84
eticket_rsa_kek_source = dba451124ca0a9836814f5ed95e3125b
eticket_rsa_kekek_source = 466e57b74a447f02f321cde58f2f5535
header_kek_source = 1f12913a4acbf00d4cde3af6d523882a
header_key = aeaab1ca08adf9bef12991f369e3c567d6881e4e4a6a47a51f6e4877062d542d
header_key_source = 5a3ed84fdec0d82631f7e25d197bf5d01c9b7bfaf628183d71f64d73f150b9d2
key_area_key_application_00 = ef979e289a132c23d39c4ec5a0bba969
key_area_key_application_01 = cdedbab97b69729073dfb2440bff2c13
key_area_key_application_02 = 75716ed3b524a01dfe21456ce26c7270
key_area_key_application_03 = f428306544cf5707c25eaa8bc0583fd1
key_area_key_application_04 = 798844ec099eb6a04b26c7c728a35a4d
key_area_key_application_05 = a57c6eecc5410ada22712eb3ccbf45f1
key_area_key_application_06 = 2a60f6c4275df1770651d5891b8e73ec
key_area_key_application_07 = 32221bd6ed19b938bec06b9d36ed9e51
key_area_key_application_08 = fb20aa9e3dbf67350e86479eb431a0b3
key_area_key_application_09 = ce8d5fa79e220d5f48470e9f21be018b
key_area_key_application_0a = 38b865725adcf568a81d2db3ceaa5bcc
key_area_key_application_0b = bbddfd40a59d0ff555c0954239972213
key_area_key_application_0c = 3fee7204e21c6b0ff1373226c0c3e055
key_area_key_application_0d = 7b05d214fa554bc3e91b044fb412fc0d
key_area_key_application_source = 7f59971e629f36a13098066f2144c30d
key_area_key_ocean_00 = b33813e4c9c4399c75fabc673ab4947b
key_area_key_ocean_01 = c54166efa8c9c0f6511fa8b580191677
key_area_key_ocean_02 = 3061ce73461e0b0409d6a33da85843c8
key_area_key_ocean_03 = 06f170025a64921c849df168e74d37f2
key_area_key_ocean_04 = dc857fd6dc1c6213076ec7b902ec5bb6
key_area_key_ocean_05 = 131d76b70bd8a60036d8218c15cb610f
key_area_key_ocean_06 = 17d565492ba819b0c19bed1b4297b659
key_area_key_ocean_07 = 37255186f7678324bf2b2d773ea2c412
key_area_key_ocean_08 = 4115c119b7bd8522ad63c831b6c816a6
key_area_key_ocean_09 = 792bfc652870cca7491d1685384be147
key_area_key_ocean_0a = dfcc9e87e61c9fba54a9b1c262d41e4d
key_area_key_ocean_0b = 66fe3107f5a6a8d8eda2459d920b07a1
key_area_key_ocean_0c = b79b6bf3d6cdc5ec10277fc07a4fec93
key_area_key_ocean_0d = 9a20ffbdcb03cfc5b8e88b058d27ae6c
key_area_key_ocean_source = 327d36085ad1758dab4e6fbaa555d882
key_area_key_system_00 = 6dd02aa15b440d6231236b6677de86bc
key_area_key_system_01 = 4ab155e7f29a292037fd147592770b12
key_area_key_system_02 = b7a74adeaf89c2a198c327bdff322d7d
key_area_key_system_03 = d5aab1acd23a8aec284a316df859d377
key_area_key_system_04 = 9b44b45b37de9d14754b1d22c2ca742c
key_area_key_system_05 = 0012e957530d3dc7af34fbbe6fd44559
key_area_key_system_06 = 01744e3b0818445cd54ee9f89da43192
key_area_key_system_07 = d0d30e46f5695b875f11522c375c5a80
key_area_key_system_08 = bd06cb1b86bd5c433667470a09eb63de
key_area_key_system_09 = e19f788f658eda8bbf34a1dd2a9503a9
key_area_key_system_0a = 7070e7ff5cfe448630143a9874903c38
key_area_key_system_0b = 3fa471d4483e58b8f7756fcb64f63890
key_area_key_system_0c = 7bfd381df3369407ab1c6bdd9fabf522
key_area_key_system_0d = 53ed531cd657edf443b551a964f44ecc
key_area_key_system_source = 8745f1bba6be79647d048ba67b5fda4a
keyblob_00 = f759024f8199101dddc1ef91e6eecf37e24b95ac9272f7ae441d5d8060c843a48322d21cdd06d4fc958c68d3800eb4db939ffbec930177f77d136144ff615aa8835e811bb958deda218f8486b5a10f531b30cb9d269645ac9fc25c53fc80525e56bd3602988a9fcf06bbf99ca910ad6530791d512c9d57e17abf49220de6419bf4eca1685c1e4df77f19db7b44a985ca
keyblob_01 = bd27264ae07e979756411d0c66e679e3c50851f3e902d9c2cd1a438b948159a517ec1566c10570326ea2697ee62da46f14bb5d581bfc06fd0c9387ea33d2d4dc63e7809ba90f03dd2c7112ffbfa548951b9b8c688b5e4f2951d24a73da29c668154a5d4838dba71ee068ace83fe720e8c2a495c596f73525dc3c05994b40ad27f8c60322f75cd548b821af9162e16f76
keyblob_02 = a3d4a8e153b8e6ae6e6aef3e8f219cb4b7790f47856accc76268f9afa99a1ff8b1a72f63d1f99f480a3c1532078bb59abdd25203cfb12a38b33e9ba6a09afb6f24283b3ba76a0161230a73669ddf5493c2b7919d094fd795b484794854f71e4f4c672245d7770e29397722444d111b4229cdbf35707b70634ea8f140766e884cc580cb1e2d9aa9866ffef920010fc409
keyblob_03 = 1558f525ae8c5be9243fb6d8a8b0a8ee0e886a59035668740a936619b7a5c83e821198b171d18e51445054df68688e45703b936818a827d8e540dd6bef2e11ec9ddc6cfe5fc736dd769b9f6e0a23a62e2e5f49e86143646a04ec3a23f828373a336a5c224a91f8a0c6c6a7b5844dd6415804209f83c943aeca9cfd856db6bd4ec32009c8cb268ed053052c9237dfd8bc
keyblob_04 = 9fbeb1957fc1629e08b753a9086d6e01ffb4f11466b7417e3fa7f5f1efb754406704fd75afaf91a408a0b524c1fc80d36c2046fa4757412efe4c11e382f72e8a10d90ed580017d9deb87af2549b6b02661af48ff94f6072c0fef7fc2833b8bdae503898e2e927ac0663e8b6391dd4f1d685313935e2c48ece7d177c88bc9c883ede36c3677495784b838d7265c6ba7a1
keyblob_05 = 94a92da1d73c2b3e165c891ced5607fc6628ca2a0654f3fbc05711c063377c6e9c96a9d0192e530dd510e4fd41aa62ef4213c5f6e059e7e21db098a9b22d1e6c29bee148aaef15c52549d9165de96e85b0d029ecdc5843e2f32cb18be707eec61909cf3385d45bc2a4c8d76e9bfad5a40c4b92dcb982aa50d474897ac9ebb5351a7015dcc277a08f1214ad41384d7941
keyblob_key_00 = 839944c8a38df6791020b38147e906b0
keyblob_key_01 = b9e6fbde828b5f42c897ade8fd14c625
keyblob_key_02 = b6988a0795d294ef522908692d5db7ca
keyblob_key_03 = 0e57d7777171d125d3fe3af5b397d009
keyblob_key_04 = b55a282d698fabeb4e03c67ff2026bc5
keyblob_key_05 = fdb542c1f1bdf134ec20b1fda02bc9e1
keyblob_key_source_00 = df206f594454efdc7074483b0ded9fd3
keyblob_key_source_01 = 0c25615d684ceb421c2379ea822512ac
keyblob_key_source_02 = 337685ee884aae0ac28afd7d63c0433b
keyblob_key_source_03 = 2d1f4880edeced3e3cf248b5657df7be
keyblob_key_source_04 = bb5a01f988aff5fc6cff079e133c3980
keyblob_key_source_05 = d8cce1266a353fcc20f32d3b517de9c0
keyblob_mac_key_00 = 604422526723e541a849fa4c18660e0b
keyblob_mac_key_01 = 279481456b1dc259d35599e6392e01e5
keyblob_mac_key_02 = dbbfb8096b676c2a54b5d9c61b423a94
keyblob_mac_key_03 = 48b7aef6d9b1edb132b8901a245a7750
keyblob_mac_key_04 = 544c082e9f8602c736dc0732d4319f88
keyblob_mac_key_05 = a540ec8ba84bd31eaaa9ce9f95226875
keyblob_mac_key_source = 59c7fb6fbe9bbe87656b15c0537336a5
mariko_master_kek_source_05 = 77605ad2ee6ef83c3f72e2599dac5e56
mariko_master_kek_source_06 = 1e80b8173ec060aa11be1a4aa66fe4ae
mariko_master_kek_source_07 = 940867bd0a00388411d31adbdd8df18a
mariko_master_kek_source_08 = 5c24e3b8b4f700c23cfd0ace13c3dc23
mariko_master_kek_source_09 = 8669f00987c805aeb57b4874de62a613
mariko_master_kek_source_0a = 0e440cedb436c03faa1daebf62b10982
mariko_master_kek_source_0b = e541acecd1a7d1abed0377f127caf8f1
mariko_master_kek_source_0c = 52719bdfa78b61d8d58511e48e4f74c6
mariko_master_kek_source_0d = d268c6539d94f9a8a5a8a7c88f534b7a
master_kek_00 = f759024f8199101dddc1ef91e6eecf37
master_kek_01 = bd27264ae07e979756411d0c66e679e3
master_kek_02 = a3d4a8e153b8e6ae6e6aef3e8f219cb4
master_kek_03 = 1558f525ae8c5be9243fb6d8a8b0a8ee
master_kek_04 = 9fbeb1957fc1629e08b753a9086d6e01
master_kek_05 = 94a92da1d73c2b3e165c891ced5607fc
master_kek_08 = e42f1ec8002043d746575ae6dd9f283f
master_kek_09 = cec2885fbeef5f6a989db84a4cc4b393
master_kek_0a = dd1a730232522b5cb4590cd43869ab6a
master_kek_0b = fc6f0c891d42710180724ed9e112e72a
master_kek_0c = 43f7fc20fcec22a5b2a744790371b094
master_kek_0d = 8dc9a8223671daa73ccd8b93cdaaed9f
master_kek_source_06 = 374b772959b4043081f6e58c6d36179a
master_kek_source_07 = 9a3ea9abfd56461c9bf6487f5cfa095c
master_kek_source_08 = dedce339308816f8ae97adec642d4141
master_kek_source_09 = 1aec11822b32387a2bedba01477e3b67
master_kek_source_0a = 303f027ed838ecd7932534b530ebca7a
master_kek_source_0b = 8467b67f1311aee6589b19af136c807a
master_kek_source_0c = 683bca54b86f9248c305768788707923
master_kek_source_0d = f013379ad56351c3b49635bc9ce87681
master_key_00 = c2caaff089b9aed55694876055271c7d
master_key_01 = 54e1b8e999c2fd16cd07b66109acaaa6
master_key_02 = 4f6b10d33072af2f250562bff06b6da3
master_key_03 = 84e04ec20b9373818c540829cf147f3d
master_key_04 = cfa2176790a53ff74974bff2af180921
master_key_05 = c1dbedcebf0dd6956079e506cfa1af6e
master_key_06 = 0aa90e6330cdc12d819b3254d11a4e1e
master_key_07 = 929f86fbfe4ef7732892bf3462511b0e
master_key_08 = 23cfb792c3cb50cd715da0f84880c877
master_key_09 = 75c93b716255319b8e03e14c19dea64e
master_key_0a = 73767484c73088f629b0eeb605f64aa6
master_key_0b = 8500b14bf4766b855a26ffc614097a8f
master_key_0c = b3c503709135d4b35de31be4b0b9c0f7
master_key_0d = 6d2b26416ab030dc504cbfd6bb2977b7
master_key_source = d8a2410ac6c59001c61d6a267c513f3c
package1_key_00 = f4eca1685c1e4df77f19db7b44a985ca
package1_key_01 = f8c60322f75cd548b821af9162e16f76
package1_key_02 = c580cb1e2d9aa9866ffef920010fc409
package1_key_03 = c32009c8cb268ed053052c9237dfd8bc
package1_key_04 = ede36c3677495784b838d7265c6ba7a1
package1_key_05 = 1a7015dcc277a08f1214ad41384d7941
package2_key_00 = a35a19cb14404b2f4460d343d178638d
package2_key_01 = a0dd1eacd438610c85a191f02c1db8a8
package2_key_02 = 7e5ba2aafd57d47a85fd4a57f2076679
package2_key_03 = bf03e9889fa18f0d7a55e8e9f684323d
package2_key_04 = 09df6e361e28eb9c96c9fa0bfc897179
package2_key_05 = 444b1a4f9035178b9b1fe262462acb8e
package2_key_06 = 442cd9c21cfb8914587dc12e8e7ed608
package2_key_07 = 70c821e7d6716feb124acbac09f7b863
package2_key_08 = 8accebcc3d15a328a48365503f8369b6
package2_key_09 = f562a7c6c42e3d4d3d13ffd504d77346
package2_key_0a = 0803167ec7fc0bc753d8330e5592a289
package2_key_0b = 341db6796aa7bdb8092f7aae6554900a
package2_key_0c = 4e97dc4225d00c6ae33d49bddd17637d
package2_key_0d = db13c2de2c313540b18a32b4f106d4a1
package2_key_source = fb8b6a9c7900c849efd24d854d30a0c7
per_console_key_source = 4f025f0eb66d110edc327d4186c2f478
retail_specific_aes_key_source = e2d6b87a119cb880e822888a46fba195
rsa_oaep_kek_generation_source = a8ca938434127fda82cc1aa5e807b112
rsa_private_kek_generation_source = ef2cb61a56729b9157c38b9316784ddd
save_mac_kek_source = d89c236ec9124e43c82b038743f9cf1b
save_mac_key = 71a917f1bac8f4f04d732e734c90e2ec
save_mac_key_source = e4cd3d4ad50f742845a487e5a063ea1f
save_mac_sd_card_kek_source = 0489ef5d326e1a59c4b7ab8c367aab17
save_mac_sd_card_key_source = 6f645947c56146f9ffa045d595332918
sd_card_custom_storage_key_source = 370c345e12e4cefe21b58e64db52af354f2ca5a3fc999a47c03ee004485b2fd0
sd_card_kek_source = 88358d9c629ba1a00147dbe0621b5432
sd_card_nca_key_source = 5841a284935b56278b8e1fc518e99f2b67c793f0f24fded075495dca006d99c2
sd_card_save_key_source = 2449b722726703a81965e6e3ea582fdd9a951517b16e8f7f1f68263152ea296a
sd_seed = fdb479221c43741a118fb5475374d2f7
secure_boot_key = 208de9b9de94ff698d00657a6a82a973
ssl_rsa_kek = b011100660d1dccbad1b1b733afa9f95
ssl_rsa_kek_source_x = 7f5bb0847b25aa67fac84be23d7b6903
ssl_rsa_kek_source_y = 9a383bf431d0bd8132534ba964397de3
titlekek_00 = 62a24d6e6d0d0e0abf3554d259be3dc9
titlekek_01 = 8821f642176969b1a18021d2665c0111
titlekek_02 = 5d15b9b95a5739a0ac9b20f600283962
titlekek_03 = 1b3f63bcb67d4b06da5badc7d89acce1
titlekek_04 = e45c1789a69c7afbbf1a1e61f2499459
titlekek_05 = ddc67f7189f4527a37b519cb051eee21
titlekek_06 = b1532b9d38ab036068f074c0d78706ac
titlekek_07 = 81dc1b1783df268789a6a0edbf058343
titlekek_08 = 47dfe4bf0eeda88b17136b8005ab08ea
titlekek_09 = adaa785d90e1a9c182ac07bc276bf600
titlekek_0a = 42daa957c128f75bb1fda56a8387e17b
titlekek_0b = d08903363f2c8655d3de3ccf85d79406
titlekek_0c = be2682599db34caa9bc7ebb2cc7c654c
titlekek_0d = 41071f95beddc4114a03e0072e6ccab7
titlekek_source = 1edc7b3b60e6b4d878b81715985e629b
tsec_key = 53ec4ac7c6c32ff2abff3eeff4f84f36
tsec_root_key_02 = 4b4fbcf58e23cf4902d478b76c8048ec)";
    }
    if (!Common::FS::Exists(title_keys)) {
        std::ofstream fout((const char*)title_keys.c_str());
        fout << R"(0100bf00112c0800000000000000000b = 96e050457df8312dcd8c5d6aff435b39
0100e950040380000000000000000003 = 49c2c307708a1ba9efa7dcd25b8d1bc4
0100e950040388000000000000000004 = 5635ddb840695f66c4b4fca67a4b6c73
0100e950040390010000000000000000 = dfc0d972d2ec07d9ef641962f3eb4d5f
0100e950040390020000000000000000 = ea88a4a648ac2d73da1df1c03bea222c
0100e950040390030000000000000000 = 6d0b9b690974c4c99996d45a0d37cd82
0100e950040390040000000000000000 = 0e00242529897c9c2f2b2ade309cf75b
0100e950040390050000000000000003 = e58b4f36369c78c3712718b7a8c6208f
0100e950040390060000000000000005 = df66fa55ffa9ce4045f0b1e404364f8e
0100e950040390630000000000000003 = 79da8a4e2ca36773bb42c8ecb0317acc
01007ef00011e0000000000000000000 = 17f3acad0780b72844fc13d363ee66ae
01007ef00011e8000000000000000003 = 2566d59be1cb9bfcc2c1b8c648b8ed0d
01001520000220000000000000000000 = a5e87b09e1700ffa6dc41ed868f3fca9
01001520000228000000000000000004 = 5ac982f853e174d8bb8b1f67e022af02
0100abf008969002000000000000000a = f3181bd3af3bc5dfcee5baae64462e5b
0100abf008969001000000000000000a = a6c1f52f7f47e126a6595ca810837be5
0100abf008968800000000000000000a = 2d7a13c17e67c70be4f1d0537141d99f
01002b00111a3001000000000000000b = 225ac97a7f910dc182ac4150173704c0
01008dd013200800000000000000000b = 63e4d9ffab703d9c6d18f76360df652d
010049900f546800000000000000000b = 9c3bb2b747d3804791492c37a706e8ec
01002b00111a2800000000000000000b = 15063e3dd537d44147d26a3279926f29
0100c1f0051b60000000000000000004 = 9114e42212871da591dfc3b2ef3e01fd
0100b7d0022ee0000000000000000000 = 6ed491d587d3e17afc2a76739b60e5bd
0100b7d0022ee8000000000000000003 = 44075fa3248310e27ff4aaf57a23f436
0100b0c013912000000000000000000b = 4e3ede13474e1e02cd603daf8945ced7
010031200b94c0000000000000000008 = 1f97a9a8ff124cc522405e83e7941eec
010031200b94c8000000000000000008 = 827e153a51977128499e4352a5f955d6
0100d870045b60000000000000000005 = f2341846b61e84dd920edfb3efc1b131
0100d870045b68000000000000000007 = 5a4541fccfc2ee91981509c98bbc9535
0100f4c009322000000000000000000b = fc0677fd7a988b14310b6f5b87f24c42
0100f4c009322800000000000000000b = 9f11546e735b567bf158d2ddd740d79f
010038e011940000000000000000000b = bebe70116fa6be3e41186a4ce3c69cd5
010038e011940800000000000000000b = 4e9e390d05908c4d9e841f0c68603bca
0100ea80032ea0000000000000000004 = 1280bf34472afb46f801aae071077633
010028600ebda800000000000000000b = 3f4414625871839bcce541fbbaafd61a
0100e460067080000000000000000008 = 08b0a36329aa240e5280f5a0f128434e
0100e460067088000000000000000008 = 13f3797ee1e8cfe5e9e4a4bcf37a46d8
01007ef00011f0010000000000000000 = 8732f3b1d4de5fe7b0092f9cdddfa308
01007ef00011f0020000000000000000 = 701c86c4804fa16167e508880c2825f5
010073401175e000000000000000000b = 9cfec133c274156e336fe15adeae1884
010073401175e800000000000000000b = 9ef9155dd3c59add02da18b792763bd3
010073401175f001000000000000000b = d3bf8e06a838af3056d53bc3e1f6dc47
010073401175f002000000000000000b = dfc73debc6a4dedde2a9882403f83bf9
01002b30028f60000000000000000004 = dc64a5fa3bf0c8b162d11ca252cdb2f2
01002b30028f68000000000000000004 = 94c9ca9fafb742714ef86df34fd5d8a6
01000520043840000000000000000000 = f2c835470ef50a0b49d307903410278d
01000520043848000000000000000003 = afeb446213d63ee64bbedbe72fbfea2f
0100ff500e34a800000000000000000b = b0952e87f6c473f9d49344f2874e31d7
010028600ebda000000000000000000b = 8465f077a1aa9eb9227bec768390630c
01006f8002326000000000000000000a = 102e6b24584754fe9d6ca6177e7d59af
01006f800232712c000000000000000b = 7b3674eca5d153f8bf2f096adc43826b
01006f800232712d000000000000000b = 5cb9f3e047c9e2926e74faaf70954629
01006f8002326800000000000000000b = 44fdfc7d7f789693c24e5aa64112658e
01003a400c3da8000000000000000007 = 596547716f0a47a2717544ce31ced0f8
01003b0012dc2800000000000000000b = 4f33fe3d2d2c0af2f4c9c0b6d6ed8b2c
010003f003a348000000000000000007 = 4a824fd653e606c341c423e709f39832
0100f8f0000a28000000000000000003 = 28735d334cbe49b5433141f6fd37e2fe
0100f8f0000a30010000000000000000 = f8d5c77ba303fd69b1a988f4d05cf6a1
0100f8f0000a30020000000000000000 = ee9788821ab63f54b92efe8d27cfe427
0100f8f0000a30050000000000000005 = a8772f9a650acdec3f1c0a9ddcfea7be
0100f8f0000a30640000000000000004 = 23b1937b304bae695c42093ba38dcc5f
0100f8f0000a30650000000000000004 = ae95d2c66b6b6c32db859e74d42434c1
01003bc0000a08000000000000000003 = fb159a42519acf1331ff465232b103f0
01003bc0000a10650000000000000004 = 809148b724a07f2e7a2a7f4b1be0b6b2
01003bc0000a00000000000000000000 = aac824f4f13139f75a6d9ac4deeda6ce
01003bc0000a10640000000000000004 = 554b72ef3cb9d024f2ab41d61698c0f3
01003b0012dc300b000000000000000b = 409404afbbb3479ba8f1abfbbe2808cb
01003b0012dc300a000000000000000b = 8546bfb4752aecb371280cee6183ce3c
01003b0012dc3002000000000000000b = c128118ca910677984891f2e17afcd4b
01003b0012dc3001000000000000000b = 9ddb35edfa02fc622365c5f5b1825596
0100c9c00e25c800000000000000000b = 53d7857ba4e8064e4dfe0b0043a2592c
01007e3006dda0000000000000000004 = 61cc2028f25a446c888afc8841ac92a3
0100abf0089680000000000000000008 = 222d5ea06bf0553f3e72a08b5637a873
0100cc00102b4000000000000000000b = 9af8f716b1834133b6e28e180929683e
0100cc00102b4800000000000000000b = 00541f55831ac05b9c974d4b5e51ebf7
010014c011146000000000000000000b = 4e20daa40d74d8cfbc07385bb4bb1355
010014c011146800000000000000000b = df0ec9ea2e7b5e67a61b3cfd17065237
0100430013120000000000000000000b = 0d2ddbb48bbf7938333f0cfdf87841cf
0100eb901040a000000000000000000b = e0ca33cd5417091908922da780dc2549
0100eb901040a800000000000000000b = e91b91de5e9a807d6f8da68a37be474a
01006bb00c6f0800000000000000000a = 3ccca97ec302cc992bd3b8602754790f
0100535012974000000000000000000b = 375f78719cc5a6f89cffdb78f231fd8e
0100535012974800000000000000000b = 5888cc89a865a57dd88ce1a8676898b5
01009bf0072d40000000000000000004 = a5ed44bbf03a01c8b887d5044e324e29
01009bf0072d48000000000000000007 = 1646cbb22cac96d5382200ef0c167e73
01009bf0072d50020000000000000007 = 77acdfa8075fa0c15ff763c1c3fe1004
01009bf0072d50010000000000000007 = e8fe74fa404a87390a62a4d74cd35e9e
01007e3006dda8000000000000000004 = 36762b88e3725a8101837ac6f1020303
010049900f546000000000000000000b = a6a5141d9a1fc44f57bd6138e5d18163
0100430013120800000000000000000b = c77c424a33b1ea4f77fcbd3f0b888a77
0100394011c30800000000000000000b = 1581c0335ca192144f0e2a7065df131a
01008d300c50c0000000000000000008 = e3f6907997b50296ea8c9037632cf424
01008d300c50c800000000000000000a = d194203efa0f7e5d37ff55fc8ea0cbe5
0100a3900c3e2000000000000000000b = 7a202b475faadcc73814dc09b0c5123c
0100a3900c3e2800000000000000000b = e33933922314900e2016cfb6fb32a39d
01000b900d8b00000000000000000008 = 907b4b2a55c683dd16cd26a360c450bf
01000b900d8b08000000000000000008 = 1dff20e9bbecd669f07c628a2307a454
01000b900d8b1001000000000000000b = a65dc4024184a37b007fb367fbc0e4e2
01000b900d8b1002000000000000000b = 4ec24f0121482aa161af3a1f70f36085
01000b900d8b1003000000000000000b = dfd012694ecde20008ffb858a64b04a3
01000b900d8b1004000000000000000b = 26cecdf7755506db5e4ad929108d76d4
010025d01221a800000000000000000b = abae9980d77c334d7920ac156e882b02
0100c5700e11a8000000000000000008 = fbdec8a6c964df9c32a303b09f5cf9a1
0100b2a00e1e0800000000000000000a = 497f08c21189d7f4e9ff453af89b17f5
0100e21011446800000000000000000b = af8805a2bb5d3b27769b101c6707b8f2
010040e0116b8000000000000000000b = 50b981adc54477f9616048c9edc0f580
010040e0116b8800000000000000000b = 4054790a73a1b98146fc548ce3cbf161
010040e0116b9001000000000000000b = b0543bbcb57cbca8ad7009ff2772bb90
010040e0116b90040000000000000000 = 00000000000000000000000000000000
010040e0116b9007000000000000000b = 6a35e6a75059c7434c832356b05aa2fb
010040e0116b9005000000000000000b = 5501dc141ed3f8b872972e9ec854eac7
010040e0116b9006000000000000000b = 807b8f435a664d2e154a3778aefca5e6
01002da013484800000000000000000b = dee25a3eb72159fd85e8bee5a27bccd7
01005e100a4f0000000000000000000b = 92e57831798e9e01166fc800f6791814
01005e100a4f0800000000000000000b = ff859f5d49949a0d5ee886500a672500
01000000000100000000000000000003 = e2d1f7b4c0e0122fedebe67b1c04802e
01000000000108000000000000000004 = c70bcdadab565d2f256c8d3fda52f16d
0100b33014710000000000000000000b = 5f07364744fc047fd41ef09f3736536b
01007c600eb42800000000000000000b = 91deb8f534cb5b5ed024aad7c7bcb185
01007c600eb43006000000000000000b = 1c01477c3bae9107208b99cfd05b2af6
0100c9a00ece6000000000000000000b = 061e18dbba726469bf603e6f571822b9
0100beb015604000000000000000000b = 59ab899d546768b0f9dfd8f5e4de7361
0100000011d90800000000000000000d = 930afadb33d1dbdd46d8bae69ba72c43
0100beb015605004000000000000000b = c4d9f4df55b00661a06ddb889b44c50d
0100beb015605003000000000000000b = 0a228caf851e754e14de6e4d16847bd9
01006f80023273e8000000000000000d = 40636911fd35e185e6a1905a68add79f
010063b012dc7001000000000000000b = c76b15d44758ebb4f3564a1a42bb41e3
010063b012dc6800000000000000000b = 3627ef925496cacbea5106b978e09523
010063b012dc7002000000000000000b = 496254e4f399f0aabb965274af828277
010063b012dc7003000000000000000b = 034a79c59d7a160960cfe2c789d2468f
010063b012dc7004000000000000000b = 4b528a01628ad3f339102d2c583a96e6
010063b012dc7005000000000000000b = 606f475adccd06bd1b3faae4f698ede9
010063b012dc7006000000000000000b = 9ce62b4ab7b299e282ab663f49ca9d20
010063b012dc7007000000000000000b = 0342ef92f635f83e6340abb1a136ad7f
010063b012dc7008000000000000000b = 9ba540953e4d1b932cbd54e84bfd732a
010063b012dc7064000000000000000b = 8cdd6889a1da1a0077f75f5cdbe1a6fa
0100000011d90000000000000000000b = 679c15346bc91245890bec995c8770c0
010063b012dc6000000000000000000b = eb7fca6052ac3aadbb4918099c921ec9
010083800e43e800000000000000000b = 5d97adbe11aec8760d02a0f7c9336db1
010083800e43e000000000000000000a = 464dfc31409c1cbc6a9f16e2e26a75e7
01004eb00e43a8000000000000000008 = 63dbe3b21750dcac9ebfbe9358b09f2e
01004eb00e43a0000000000000000008 = e1c4e521f184537923db7c3c8699b3c1
0100e21011447001000000000000000b = f6f62b26c054f380d21b9982d8479f90
0100e21011447003000000000000000b = a93244958a3357b48b5a3402eda66897
0100e21011447004000000000000000b = f9f8f3b43beebb97dfd22bc90442e4de
0100e21011447005000000000000000b = edc3f96def2738d1c762368da295a876
0100e21011447006000000000000000b = 8df0a9db66879fba716c7daf00bed390
0100e21011447007000000000000000b = 9168fae908dc966fb85cbcf454accc89
0100e2101144700a000000000000000b = dcb1a61fb00325d8b0c52aaa9d697cdc
0100e2101144700b000000000000000b = 7ba3aefdaa3438e8137d3f2e07b18dc8
0100e21011447011000000000000000b = 29a04f38f1a1acaa70811013ff8333ec
0100e21011447012000000000000000b = d1cc8e162e2405105bd81df795adeb85
0100e21011447013000000000000000b = 030f2bc32ce5d00eb3a3ea378f9a75c9
0100e21011447014000000000000000b = 40ba8048e217020768b73cddb740d471
0100e21011447016000000000000000b = 3d56a9a3f43b4cc2d29001e730c230a3
0100e21011447017000000000000000b = 239ed2f8e28a8130a34f39038a806e06
0100e2101144701b000000000000000b = 9a5219aa1cb7374c859f61cde820ad99
0100e21011447019000000000000000b = 4aee454de173ec7d1216283387407984
0100e2101144701c000000000000000b = 3962eccc7c76d403d868b3efce5cbbe7
0100e2101144701d000000000000000b = 5e50669320107e27a974a387db665bf7
0100e2101144701e000000000000000b = c2876c7635822dd06a88c3fc5ce6786b
0100e21011447022000000000000000b = 60e018e30fcd9930a7abdb4f73f1c492
0100e21011447023000000000000000b = 3bd4f40ffe2670fcbdeceeb717870da1
0100e21011447024000000000000000b = af3cfc0a25c9a4010853531157ff409c
0100c9a00ece6800000000000000000d = 770a84d2e0aea0288494587bc1f9a1cd
0100beb015604800000000000000000b = aac139619865fcd96362a79863f30399
0100beb015605002000000000000000b = 2610822de66ff380fffa304e7cab6269
0100beb015605001000000000000000b = 7b21dd57e12fd71a21f63a967a3b86d7
01006fe013472800000000000000000d = f9428cc940e59f73f108df3542a1b727
01006fe013472000000000000000000b = 677e1a60cc4074a3796cb0db35dfc963
0100a5c00d1628000000000000000008 = d7199488fe229821fbed9af9e80cf347
01001f5010dfa800000000000000000d = bb55e2f8295835d0866c0e0d336b2eff
0100a5c00d1620000000000000000007 = 0cc0a84d81a723fb36eee3c95cde6736
0100152000023001000000000000000d = 43f99b785e9e203ee4d253897f3f32d1)";
    }

    if (Settings::values.use_dev_keys) {
        dev_mode = true;
        LoadFromFile(yuzu_keys_dir / "dev.keys", false);
        LoadFromFile(yuzu_keys_dir / "dev.keys_autogenerated", false);
    } else {
        dev_mode = false;
        LoadFromFile(yuzu_keys_dir / "prod.keys", false);
        LoadFromFile(yuzu_keys_dir / "prod.keys_autogenerated", false);
    }

    LoadFromFile(yuzu_keys_dir / "title.keys", true);
    LoadFromFile(yuzu_keys_dir / "title.keys_autogenerated", true);
    LoadFromFile(yuzu_keys_dir / "console.keys", false);
    LoadFromFile(yuzu_keys_dir / "console.keys_autogenerated", false);
}

static bool ValidCryptoRevisionString(std::string_view base, size_t begin, size_t length) {
    if (base.size() < begin + length) {
        return false;
    }
    return std::all_of(base.begin() + begin, base.begin() + begin + length,
                       [](u8 c) { return std::isxdigit(c); });
}

void KeyManager::LoadFromFile(const std::filesystem::path& file_path, bool is_title_keys) {
    if (!Common::FS::Exists(file_path)) {
        return;
    }

    std::ifstream file;
    Common::FS::OpenFileStream(file, file_path, std::ios_base::in);

    if (!file.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        std::vector<std::string> out;
        std::stringstream stream(line);
        std::string item;
        while (std::getline(stream, item, '=')) {
            out.push_back(std::move(item));
        }

        if (out.size() != 2) {
            continue;
        }

        out[0].erase(std::remove(out[0].begin(), out[0].end(), ' '), out[0].end());
        out[1].erase(std::remove(out[1].begin(), out[1].end(), ' '), out[1].end());

        if (out[0].compare(0, 1, "#") == 0) {
            continue;
        }

        if (is_title_keys) {
            auto rights_id_raw = Common::HexStringToArray<16>(out[0]);
            u128 rights_id{};
            std::memcpy(rights_id.data(), rights_id_raw.data(), rights_id_raw.size());
            Key128 key = Common::HexStringToArray<16>(out[1]);
            s128_keys[{S128KeyType::Titlekey, rights_id[1], rights_id[0]}] = key;
        } else {
            out[0] = Common::ToLower(out[0]);
            if (const auto iter128 = Find128ByName(out[0]); iter128 != s128_file_id.end()) {
                const auto& index = iter128->second;
                const Key128 key = Common::HexStringToArray<16>(out[1]);
                s128_keys[{index.type, index.field1, index.field2}] = key;
            } else if (const auto iter256 = Find256ByName(out[0]); iter256 != s256_file_id.end()) {
                const auto& index = iter256->second;
                const Key256 key = Common::HexStringToArray<32>(out[1]);
                s256_keys[{index.type, index.field1, index.field2}] = key;
            } else if (out[0].compare(0, 8, "keyblob_") == 0 &&
                       out[0].compare(0, 9, "keyblob_k") != 0) {
                if (!ValidCryptoRevisionString(out[0], 8, 2)) {
                    continue;
                }

                const auto index = std::stoul(out[0].substr(8, 2), nullptr, 16);
                keyblobs[index] = Common::HexStringToArray<0x90>(out[1]);
            } else if (out[0].compare(0, 18, "encrypted_keyblob_") == 0) {
                if (!ValidCryptoRevisionString(out[0], 18, 2)) {
                    continue;
                }

                const auto index = std::stoul(out[0].substr(18, 2), nullptr, 16);
                encrypted_keyblobs[index] = Common::HexStringToArray<0xB0>(out[1]);
            } else if (out[0].compare(0, 20, "eticket_extended_kek") == 0) {
                eticket_extended_kek = Common::HexStringToArray<576>(out[1]);
            } else {
                for (const auto& kv : KEYS_VARIABLE_LENGTH) {
                    if (!ValidCryptoRevisionString(out[0], kv.second.size(), 2)) {
                        continue;
                    }
                    if (out[0].compare(0, kv.second.size(), kv.second) == 0) {
                        const auto index =
                            std::stoul(out[0].substr(kv.second.size(), 2), nullptr, 16);
                        const auto sub = kv.first.second;
                        if (sub == 0) {
                            s128_keys[{kv.first.first, index, 0}] =
                                Common::HexStringToArray<16>(out[1]);
                        } else {
                            s128_keys[{kv.first.first, kv.first.second, index}] =
                                Common::HexStringToArray<16>(out[1]);
                        }

                        break;
                    }
                }

                static constexpr std::array<const char*, 3> kak_names = {
                    "key_area_key_application_", "key_area_key_ocean_", "key_area_key_system_"};
                for (size_t j = 0; j < kak_names.size(); ++j) {
                    const auto& match = kak_names[j];
                    if (out[0].compare(0, std::strlen(match), match) == 0) {
                        const auto index =
                            std::stoul(out[0].substr(std::strlen(match), 2), nullptr, 16);
                        s128_keys[{S128KeyType::KeyArea, index, j}] =
                            Common::HexStringToArray<16>(out[1]);
                    }
                }
            }
        }
    }
}

bool KeyManager::BaseDeriveNecessary() const {
    const auto check_key_existence = [this](auto key_type, u64 index1 = 0, u64 index2 = 0) {
        return !HasKey(key_type, index1, index2);
    };

    if (check_key_existence(S256KeyType::Header)) {
        return true;
    }

    for (size_t i = 0; i < CURRENT_CRYPTO_REVISION; ++i) {
        if (check_key_existence(S128KeyType::Master, i) ||
            check_key_existence(S128KeyType::KeyArea, i,
                                static_cast<u64>(KeyAreaKeyType::Application)) ||
            check_key_existence(S128KeyType::KeyArea, i, static_cast<u64>(KeyAreaKeyType::Ocean)) ||
            check_key_existence(S128KeyType::KeyArea, i,
                                static_cast<u64>(KeyAreaKeyType::System)) ||
            check_key_existence(S128KeyType::Titlekek, i))
            return true;
    }

    return false;
}

bool KeyManager::HasKey(S128KeyType id, u64 field1, u64 field2) const {
    return s128_keys.find({id, field1, field2}) != s128_keys.end();
}

bool KeyManager::HasKey(S256KeyType id, u64 field1, u64 field2) const {
    return s256_keys.find({id, field1, field2}) != s256_keys.end();
}

Key128 KeyManager::GetKey(S128KeyType id, u64 field1, u64 field2) const {
    if (!HasKey(id, field1, field2)) {
        return {};
    }
    return s128_keys.at({id, field1, field2});
}

Key256 KeyManager::GetKey(S256KeyType id, u64 field1, u64 field2) const {
    if (!HasKey(id, field1, field2)) {
        return {};
    }
    return s256_keys.at({id, field1, field2});
}

Key256 KeyManager::GetBISKey(u8 partition_id) const {
    Key256 out{};

    for (const auto& bis_type : {BISKeyType::Crypto, BISKeyType::Tweak}) {
        if (HasKey(S128KeyType::BIS, partition_id, static_cast<u64>(bis_type))) {
            std::memcpy(
                out.data() + sizeof(Key128) * static_cast<u64>(bis_type),
                s128_keys.at({S128KeyType::BIS, partition_id, static_cast<u64>(bis_type)}).data(),
                sizeof(Key128));
        }
    }

    return out;
}

template <size_t Size>
void KeyManager::WriteKeyToFile(KeyCategory category, std::string_view keyname,
                                const std::array<u8, Size>& key) {
    const auto yuzu_keys_dir = Common::FS::GetYuzuPath(Common::FS::YuzuPath::KeysDir);

    std::string filename = "title.keys_autogenerated";

    if (category == KeyCategory::Standard) {
        filename = dev_mode ? "dev.keys_autogenerated" : "prod.keys_autogenerated";
    } else if (category == KeyCategory::Console) {
        filename = "console.keys_autogenerated";
    }

    const auto path = yuzu_keys_dir / filename;
    const auto add_info_text = !Common::FS::Exists(path);

    Common::FS::IOFile file{path, Common::FS::FileAccessMode::Append,
                            Common::FS::FileType::TextFile};

    if (!file.IsOpen()) {
        return;
    }

    if (add_info_text) {
        void(file.WriteString(
            "# This file is autogenerated by Yuzu\n"
            "# It serves to store keys that were automatically generated from the normal keys\n"
            "# If you are experiencing issues involving keys, it may help to delete this file\n"));
    }

    void(file.WriteString(fmt::format("\n{} = {}", keyname, Common::HexToString(key))));
    LoadFromFile(path, category == KeyCategory::Title);
}

void KeyManager::SetKey(S128KeyType id, Key128 key, u64 field1, u64 field2) {
    if (s128_keys.find({id, field1, field2}) != s128_keys.end() || key == Key128{}) {
        return;
    }
    if (id == S128KeyType::Titlekey) {
        Key128 rights_id;
        std::memcpy(rights_id.data(), &field2, sizeof(u64));
        std::memcpy(rights_id.data() + sizeof(u64), &field1, sizeof(u64));
        WriteKeyToFile(KeyCategory::Title, Common::HexToString(rights_id), key);
    }

    auto category = KeyCategory::Standard;
    if (id == S128KeyType::Keyblob || id == S128KeyType::KeyblobMAC || id == S128KeyType::TSEC ||
        id == S128KeyType::SecureBoot || id == S128KeyType::SDSeed || id == S128KeyType::BIS) {
        category = KeyCategory::Console;
    }

    const auto iter2 = std::find_if(
        s128_file_id.begin(), s128_file_id.end(), [&id, &field1, &field2](const auto& elem) {
            return std::tie(elem.second.type, elem.second.field1, elem.second.field2) ==
                   std::tie(id, field1, field2);
        });
    if (iter2 != s128_file_id.end()) {
        WriteKeyToFile(category, iter2->first, key);
    }

    // Variable cases
    if (id == S128KeyType::KeyArea) {
        static constexpr std::array<const char*, 3> kak_names = {
            "key_area_key_application_{:02X}",
            "key_area_key_ocean_{:02X}",
            "key_area_key_system_{:02X}",
        };
        WriteKeyToFile(category, fmt::format(fmt::runtime(kak_names.at(field2)), field1), key);
    } else if (id == S128KeyType::Master) {
        WriteKeyToFile(category, fmt::format("master_key_{:02X}", field1), key);
    } else if (id == S128KeyType::Package1) {
        WriteKeyToFile(category, fmt::format("package1_key_{:02X}", field1), key);
    } else if (id == S128KeyType::Package2) {
        WriteKeyToFile(category, fmt::format("package2_key_{:02X}", field1), key);
    } else if (id == S128KeyType::Titlekek) {
        WriteKeyToFile(category, fmt::format("titlekek_{:02X}", field1), key);
    } else if (id == S128KeyType::Keyblob) {
        WriteKeyToFile(category, fmt::format("keyblob_key_{:02X}", field1), key);
    } else if (id == S128KeyType::KeyblobMAC) {
        WriteKeyToFile(category, fmt::format("keyblob_mac_key_{:02X}", field1), key);
    } else if (id == S128KeyType::Source && field1 == static_cast<u64>(SourceKeyType::Keyblob)) {
        WriteKeyToFile(category, fmt::format("keyblob_key_source_{:02X}", field2), key);
    }

    s128_keys[{id, field1, field2}] = key;
}

void KeyManager::SetKey(S256KeyType id, Key256 key, u64 field1, u64 field2) {
    if (s256_keys.find({id, field1, field2}) != s256_keys.end() || key == Key256{}) {
        return;
    }
    const auto iter = std::find_if(
        s256_file_id.begin(), s256_file_id.end(), [&id, &field1, &field2](const auto& elem) {
            return std::tie(elem.second.type, elem.second.field1, elem.second.field2) ==
                   std::tie(id, field1, field2);
        });
    if (iter != s256_file_id.end()) {
        WriteKeyToFile(KeyCategory::Standard, iter->first, key);
    }
    s256_keys[{id, field1, field2}] = key;
}

bool KeyManager::KeyFileExists(bool title) {
    const auto yuzu_keys_dir = Common::FS::GetYuzuPath(Common::FS::YuzuPath::KeysDir);

    if (title) {
        return Common::FS::Exists(yuzu_keys_dir / "title.keys");
    }

    if (Settings::values.use_dev_keys) {
        return Common::FS::Exists(yuzu_keys_dir / "dev.keys");
    }

    return Common::FS::Exists(yuzu_keys_dir / "prod.keys");
}

void KeyManager::DeriveSDSeedLazy() {
    if (HasKey(S128KeyType::SDSeed)) {
        return;
    }

    const auto res = DeriveSDSeed();
    if (res) {
        SetKey(S128KeyType::SDSeed, *res);
    }
}

static Key128 CalculateCMAC(const u8* source, size_t size, const Key128& key) {
    Key128 out{};

    mbedtls_cipher_cmac(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB), key.data(),
                        key.size() * 8, source, size, out.data());
    return out;
}

void KeyManager::DeriveBase() {
    if (!BaseDeriveNecessary()) {
        return;
    }

    if (!HasKey(S128KeyType::SecureBoot) || !HasKey(S128KeyType::TSEC)) {
        return;
    }

    const auto has_bis = [this](u64 id) {
        return HasKey(S128KeyType::BIS, id, static_cast<u64>(BISKeyType::Crypto)) &&
               HasKey(S128KeyType::BIS, id, static_cast<u64>(BISKeyType::Tweak));
    };

    const auto copy_bis = [this](u64 id_from, u64 id_to) {
        SetKey(S128KeyType::BIS,
               GetKey(S128KeyType::BIS, id_from, static_cast<u64>(BISKeyType::Crypto)), id_to,
               static_cast<u64>(BISKeyType::Crypto));

        SetKey(S128KeyType::BIS,
               GetKey(S128KeyType::BIS, id_from, static_cast<u64>(BISKeyType::Tweak)), id_to,
               static_cast<u64>(BISKeyType::Tweak));
    };

    if (has_bis(2) && !has_bis(3)) {
        copy_bis(2, 3);
    } else if (has_bis(3) && !has_bis(2)) {
        copy_bis(3, 2);
    }

    std::bitset<32> revisions(0xFFFFFFFF);
    for (size_t i = 0; i < revisions.size(); ++i) {
        if (!HasKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::Keyblob), i) ||
            encrypted_keyblobs[i] == std::array<u8, 0xB0>{}) {
            revisions.reset(i);
        }
    }

    if (!revisions.any()) {
        return;
    }

    const auto sbk = GetKey(S128KeyType::SecureBoot);
    const auto tsec = GetKey(S128KeyType::TSEC);

    for (size_t i = 0; i < revisions.size(); ++i) {
        if (!revisions[i]) {
            continue;
        }

        // Derive keyblob key
        const auto key = DeriveKeyblobKey(
            sbk, tsec, GetKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::Keyblob), i));

        SetKey(S128KeyType::Keyblob, key, i);

        // Derive keyblob MAC key
        if (!HasKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::KeyblobMAC))) {
            continue;
        }

        const auto mac_key = DeriveKeyblobMACKey(
            key, GetKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::KeyblobMAC)));
        SetKey(S128KeyType::KeyblobMAC, mac_key, i);

        Key128 cmac = CalculateCMAC(encrypted_keyblobs[i].data() + 0x10, 0xA0, mac_key);
        if (std::memcmp(cmac.data(), encrypted_keyblobs[i].data(), cmac.size()) != 0) {
            continue;
        }

        // Decrypt keyblob
        if (keyblobs[i] == std::array<u8, 0x90>{}) {
            keyblobs[i] = DecryptKeyblob(encrypted_keyblobs[i], key);
            WriteKeyToFile<0x90>(KeyCategory::Console, fmt::format("keyblob_{:02X}", i),
                                 keyblobs[i]);
        }

        Key128 package1;
        std::memcpy(package1.data(), keyblobs[i].data() + 0x80, sizeof(Key128));
        SetKey(S128KeyType::Package1, package1, i);

        // Derive master key
        if (HasKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::Master))) {
            SetKey(S128KeyType::Master,
                   DeriveMasterKey(keyblobs[i], GetKey(S128KeyType::Source,
                                                       static_cast<u64>(SourceKeyType::Master))),
                   i);
        }
    }

    revisions.set();
    for (size_t i = 0; i < revisions.size(); ++i) {
        if (!HasKey(S128KeyType::Master, i)) {
            revisions.reset(i);
        }
    }

    if (!revisions.any()) {
        return;
    }

    for (size_t i = 0; i < revisions.size(); ++i) {
        if (!revisions[i]) {
            continue;
        }

        // Derive general purpose keys
        DeriveGeneralPurposeKeys(i);
    }

    if (HasKey(S128KeyType::Master, 0) &&
        HasKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKeyGeneration)) &&
        HasKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKekGeneration)) &&
        HasKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::HeaderKek)) &&
        HasKey(S256KeyType::HeaderSource)) {
        const auto header_kek = GenerateKeyEncryptionKey(
            GetKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::HeaderKek)),
            GetKey(S128KeyType::Master, 0),
            GetKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKekGeneration)),
            GetKey(S128KeyType::Source, static_cast<u64>(SourceKeyType::AESKeyGeneration)));
        SetKey(S128KeyType::HeaderKek, header_kek);

        AESCipher<Key128> header_cipher(header_kek, Mode::ECB);
        Key256 out = GetKey(S256KeyType::HeaderSource);
        header_cipher.Transcode(out.data(), out.size(), out.data(), Op::Decrypt);
        SetKey(S256KeyType::Header, out);
    }
}

void KeyManager::DeriveETicket(PartitionDataManager& data,
                               const FileSys::ContentProvider& provider) {
    // ETicket keys
    const auto es = provider.GetEntry(0x0100000000000033, FileSys::ContentRecordType::Program);

    if (es == nullptr) {
        return;
    }

    const auto exefs = es->GetExeFS();
    if (exefs == nullptr) {
        return;
    }

    const auto main = exefs->GetFile("main");
    if (main == nullptr) {
        return;
    }

    const auto bytes = main->ReadAllBytes();

    const auto eticket_kek = FindKeyFromHex16(bytes, eticket_source_hashes[0]);
    const auto eticket_kekek = FindKeyFromHex16(bytes, eticket_source_hashes[1]);

    const auto seed3 = data.GetRSAKekSeed3();
    const auto mask0 = data.GetRSAKekMask0();

    if (eticket_kek != Key128{}) {
        SetKey(S128KeyType::Source, eticket_kek, static_cast<size_t>(SourceKeyType::ETicketKek));
    }
    if (eticket_kekek != Key128{}) {
        SetKey(S128KeyType::Source, eticket_kekek,
               static_cast<size_t>(SourceKeyType::ETicketKekek));
    }
    if (seed3 != Key128{}) {
        SetKey(S128KeyType::RSAKek, seed3, static_cast<size_t>(RSAKekType::Seed3));
    }
    if (mask0 != Key128{}) {
        SetKey(S128KeyType::RSAKek, mask0, static_cast<size_t>(RSAKekType::Mask0));
    }
    if (eticket_kek == Key128{} || eticket_kekek == Key128{} || seed3 == Key128{} ||
        mask0 == Key128{}) {
        return;
    }

    const Key128 rsa_oaep_kek = seed3 ^ mask0;
    if (rsa_oaep_kek == Key128{}) {
        return;
    }

    SetKey(S128KeyType::Source, rsa_oaep_kek,
           static_cast<u64>(SourceKeyType::RSAOaepKekGeneration));

    Key128 temp_kek{};
    Key128 temp_kekek{};
    Key128 eticket_final{};

    // Derive ETicket RSA Kek
    AESCipher<Key128> es_master(GetKey(S128KeyType::Master), Mode::ECB);
    es_master.Transcode(rsa_oaep_kek.data(), rsa_oaep_kek.size(), temp_kek.data(), Op::Decrypt);
    AESCipher<Key128> es_kekek(temp_kek, Mode::ECB);
    es_kekek.Transcode(eticket_kekek.data(), eticket_kekek.size(), temp_kekek.data(), Op::Decrypt);
    AESCipher<Key128> es_kek(temp_kekek, Mode::ECB);
    es_kek.Transcode(eticket_kek.data(), eticket_kek.size(), eticket_final.data(), Op::Decrypt);

    if (eticket_final == Key128{}) {
        return;
    }

    SetKey(S128KeyType::ETicketRSAKek, eticket_final);

    // Titlekeys
    data.DecryptProdInfo(GetBISKey(0));

    eticket_extended_kek = data.GetETicketExtendedKek();
    WriteKeyToFile(KeyCategory::Console, "eticket_extended_kek", eticket_extended_kek);
    PopulateTickets();
}

void KeyManager::PopulateTickets() {
    const auto rsa_key = GetETicketRSAKey();

    if (rsa_key == RSAKeyPair<2048>{}) {
        return;
    }

    if (!common_tickets.empty() && !personal_tickets.empty()) {
        return;
    }

    const auto system_save_e1_path =
        Common::FS::GetYuzuPath(Common::FS::YuzuPath::NANDDir) / "system/save/80000000000000e1";

    const Common::FS::IOFile save_e1{system_save_e1_path, Common::FS::FileAccessMode::Read,
                                     Common::FS::FileType::BinaryFile};

    const auto system_save_e2_path =
        Common::FS::GetYuzuPath(Common::FS::YuzuPath::NANDDir) / "system/save/80000000000000e2";

    const Common::FS::IOFile save_e2{system_save_e2_path, Common::FS::FileAccessMode::Read,
                                     Common::FS::FileType::BinaryFile};

    const auto blob2 = GetTicketblob(save_e2);
    auto res = GetTicketblob(save_e1);

    const auto idx = res.size();
    res.insert(res.end(), blob2.begin(), blob2.end());

    for (std::size_t i = 0; i < res.size(); ++i) {
        const auto common = i < idx;
        const auto pair = ParseTicket(res[i], rsa_key);
        if (!pair) {
            continue;
        }

        const auto& [rid, key] = *pair;
        u128 rights_id;
        std::memcpy(rights_id.data(), rid.data(), rid.size());

        if (common) {
            common_tickets[rights_id] = res[i];
        } else {
            personal_tickets[rights_id] = res[i];
        }

        SetKey(S128KeyType::Titlekey, key, rights_id[1], rights_id[0]);
    }
}

void KeyManager::SynthesizeTickets() {
    for (const auto& key : s128_keys) {
        if (key.first.type != S128KeyType::Titlekey) {
            continue;
        }
        u128 rights_id{key.first.field1, key.first.field2};
        Key128 rights_id_2;
        std::memcpy(rights_id_2.data(), rights_id.data(), rights_id_2.size());
        const auto ticket = Ticket::SynthesizeCommon(key.second, rights_id_2);
        common_tickets.insert_or_assign(rights_id, ticket);
    }
}

void KeyManager::SetKeyWrapped(S128KeyType id, Key128 key, u64 field1, u64 field2) {
    if (key == Key128{}) {
        return;
    }
    SetKey(id, key, field1, field2);
}

void KeyManager::SetKeyWrapped(S256KeyType id, Key256 key, u64 field1, u64 field2) {
    if (key == Key256{}) {
        return;
    }

    SetKey(id, key, field1, field2);
}

void KeyManager::PopulateFromPartitionData(PartitionDataManager& data) {
    if (!BaseDeriveNecessary()) {
        return;
    }

    if (!data.HasBoot0()) {
        return;
    }

    for (size_t i = 0; i < encrypted_keyblobs.size(); ++i) {
        if (encrypted_keyblobs[i] != std::array<u8, 0xB0>{}) {
            continue;
        }
        encrypted_keyblobs[i] = data.GetEncryptedKeyblob(i);
        WriteKeyToFile<0xB0>(KeyCategory::Console, fmt::format("encrypted_keyblob_{:02X}", i),
                             encrypted_keyblobs[i]);
    }

    SetKeyWrapped(S128KeyType::Source, data.GetPackage2KeySource(),
                  static_cast<u64>(SourceKeyType::Package2));
    SetKeyWrapped(S128KeyType::Source, data.GetAESKekGenerationSource(),
                  static_cast<u64>(SourceKeyType::AESKekGeneration));
    SetKeyWrapped(S128KeyType::Source, data.GetTitlekekSource(),
                  static_cast<u64>(SourceKeyType::Titlekek));
    SetKeyWrapped(S128KeyType::Source, data.GetMasterKeySource(),
                  static_cast<u64>(SourceKeyType::Master));
    SetKeyWrapped(S128KeyType::Source, data.GetKeyblobMACKeySource(),
                  static_cast<u64>(SourceKeyType::KeyblobMAC));

    for (size_t i = 0; i < PartitionDataManager::MAX_KEYBLOB_SOURCE_HASH; ++i) {
        SetKeyWrapped(S128KeyType::Source, data.GetKeyblobKeySource(i),
                      static_cast<u64>(SourceKeyType::Keyblob), i);
    }

    if (data.HasFuses()) {
        SetKeyWrapped(S128KeyType::SecureBoot, data.GetSecureBootKey());
    }

    DeriveBase();

    Key128 latest_master{};
    for (s8 i = 0x1F; i >= 0; --i) {
        if (GetKey(S128KeyType::Master, static_cast<u8>(i)) != Key128{}) {
            latest_master = GetKey(S128KeyType::Master, static_cast<u8>(i));
            break;
        }
    }

    const auto masters = data.GetTZMasterKeys(latest_master);
    for (size_t i = 0; i < masters.size(); ++i) {
        if (masters[i] != Key128{} && !HasKey(S128KeyType::Master, i)) {
            SetKey(S128KeyType::Master, masters[i], i);
        }
    }

    DeriveBase();

    if (!data.HasPackage2())
        return;

    std::array<Key128, 0x20> package2_keys{};
    for (size_t i = 0; i < package2_keys.size(); ++i) {
        if (HasKey(S128KeyType::Package2, i)) {
            package2_keys[i] = GetKey(S128KeyType::Package2, i);
        }
    }
    data.DecryptPackage2(package2_keys, Package2Type::NormalMain);

    SetKeyWrapped(S128KeyType::Source, data.GetKeyAreaKeyApplicationSource(),
                  static_cast<u64>(SourceKeyType::KeyAreaKey),
                  static_cast<u64>(KeyAreaKeyType::Application));
    SetKeyWrapped(S128KeyType::Source, data.GetKeyAreaKeyOceanSource(),
                  static_cast<u64>(SourceKeyType::KeyAreaKey),
                  static_cast<u64>(KeyAreaKeyType::Ocean));
    SetKeyWrapped(S128KeyType::Source, data.GetKeyAreaKeySystemSource(),
                  static_cast<u64>(SourceKeyType::KeyAreaKey),
                  static_cast<u64>(KeyAreaKeyType::System));
    SetKeyWrapped(S128KeyType::Source, data.GetSDKekSource(),
                  static_cast<u64>(SourceKeyType::SDKek));
    SetKeyWrapped(S256KeyType::SDKeySource, data.GetSDSaveKeySource(),
                  static_cast<u64>(SDKeyType::Save));
    SetKeyWrapped(S256KeyType::SDKeySource, data.GetSDNCAKeySource(),
                  static_cast<u64>(SDKeyType::NCA));
    SetKeyWrapped(S128KeyType::Source, data.GetHeaderKekSource(),
                  static_cast<u64>(SourceKeyType::HeaderKek));
    SetKeyWrapped(S256KeyType::HeaderSource, data.GetHeaderKeySource());
    SetKeyWrapped(S128KeyType::Source, data.GetAESKeyGenerationSource(),
                  static_cast<u64>(SourceKeyType::AESKeyGeneration));

    DeriveBase();
}

const std::map<u128, Ticket>& KeyManager::GetCommonTickets() const {
    return common_tickets;
}

const std::map<u128, Ticket>& KeyManager::GetPersonalizedTickets() const {
    return personal_tickets;
}

bool KeyManager::AddTicketCommon(Ticket raw) {
    const auto rsa_key = GetETicketRSAKey();
    if (rsa_key == RSAKeyPair<2048>{}) {
        return false;
    }

    const auto pair = ParseTicket(raw, rsa_key);
    if (!pair) {
        return false;
    }

    const auto& [rid, key] = *pair;
    u128 rights_id;
    std::memcpy(rights_id.data(), rid.data(), rid.size());
    common_tickets[rights_id] = raw;
    SetKey(S128KeyType::Titlekey, key, rights_id[1], rights_id[0]);
    return true;
}

bool KeyManager::AddTicketPersonalized(Ticket raw) {
    const auto rsa_key = GetETicketRSAKey();
    if (rsa_key == RSAKeyPair<2048>{}) {
        return false;
    }

    const auto pair = ParseTicket(raw, rsa_key);
    if (!pair) {
        return false;
    }

    const auto& [rid, key] = *pair;
    u128 rights_id;
    std::memcpy(rights_id.data(), rid.data(), rid.size());
    common_tickets[rights_id] = raw;
    SetKey(S128KeyType::Titlekey, key, rights_id[1], rights_id[0]);
    return true;
}
} // namespace Core::Crypto

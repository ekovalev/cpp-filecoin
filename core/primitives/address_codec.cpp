/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "primitives/address_codec.hpp"

#include <cppcodec/base32_default_rfc4648.hpp>
#include "codec/leb128/leb128.hpp"
#include "common/visitor.hpp"
#include "crypto/blake2/blake2b.h"

namespace fc::primitives {

  const size_t kBlake2b160HashSize{20};
  const size_t kBLSHashSize{48};
  using common::Blob;

  std::vector<uint8_t> encode(const Address &address) {
    std::vector<uint8_t> res{};
    res.push_back(address.network_);
    res.push_back(address.GetProtocol());
    std::vector<uint8_t> payload = visit_in_place(
        address.data_,
        [](uint64_t v) { return codec::leb128::encode(v); },
        [](const Secp256k1PublicKeyHash &v) { return std::vector<uint8_t>(v.begin(), v.end()); },
        [](const ActorExecHash &v) { return std::vector<uint8_t>(v.begin(), v.end()); },
        [](const BLSPublicKeyHash &v) { return std::vector<uint8_t>(v.begin(), v.end()); });
    res.insert(res.end(), payload.begin(), payload.end());
    return res;
  }

  outcome::result<Address> decode(const std::vector<uint8_t> &v) {
    if (v.size() < 4) return outcome::failure(AddressError::INVALID_PAYLOAD);
    auto pos = v.begin();

    auto net = static_cast<Network>(*(pos++));
    if (!(net == Network::testnet || net == Network::mainnet)) {
      return outcome::failure(AddressError::UNKNOWN_NETWORK);
    }

    auto p = static_cast<Protocol>(*(pos++));
    std::vector<uint8_t> payload(pos, v.end());
    switch (p) {
      case Protocol::ID: {
        auto decoded = codec::leb128::decode<uint64_t>(payload);
        if (!decoded) {
          return outcome::failure(AddressError::INVALID_PAYLOAD);
        }
        return outcome::success(Address(net, decoded.value()));
      }
      case Protocol::SECP256K1: {
        if (payload.size() != kBlake2b160HashSize) {
          return outcome::failure(AddressError::INVALID_PAYLOAD);
        }
        Secp256k1PublicKeyHash hash{};
        std::copy_n(payload.begin(), kBlake2b160HashSize, hash.begin());
        return outcome::success(Address(net, hash));
      }
      case Protocol::Actor: {
        if (payload.size() != kBlake2b160HashSize) {
          return outcome::failure(AddressError::INVALID_PAYLOAD);
        }
        ActorExecHash hash{};
        std::copy_n(payload.begin(), kBlake2b160HashSize, hash.begin());
        return outcome::success(Address(net, hash));
      }
      case Protocol::BLS: {
        if (payload.size() != kBLSHashSize) {
          return outcome::failure(AddressError::INVALID_PAYLOAD);
        }
        BLSPublicKeyHash hash{};
        std::copy_n(payload.begin(), kBLSHashSize, hash.begin());
        return outcome::success(Address(net, hash));
      }
      default:
        return outcome::failure(AddressError::UNKNOWN_PROTOCOL);
    }
  }

  std::string encodeToString(const Address &address) {
    using base32 = cppcodec::base32_rfc4648;

    std::string res{};

    char networkPrefix = 'f';
    if (address.network_ == Network::testnet) networkPrefix = 't';
    res.push_back(networkPrefix);

    Protocol p = address.GetProtocol();
    res.append(std::to_string(p));

    if (p == Protocol::ID) {
      const uint64_t *data_ptr = boost::get<uint64_t>(&address.data_);
      if (data_ptr != nullptr) res.append(std::to_string(*data_ptr));
      return res;
    }

    std::vector<uint8_t> payload = visit_in_place(
        address.data_,
        [](uint64_t v) { return codec::leb128::encode(v); },
        [](const Secp256k1PublicKeyHash &v) { return std::vector<uint8_t>(v.begin(), v.end()); },
        [](const ActorExecHash &v) { return std::vector<uint8_t>(v.begin(), v.end()); },
        [](const BLSPublicKeyHash &v) { return std::vector<uint8_t>(v.begin(), v.end()); });

    std::vector chksum = checksum(address);

    payload.insert(payload.end(), chksum.begin(), chksum.end());
    auto encoded = base32::encode(payload);

    // Convert to lower case, as the spec requires: https://filecoin-project.github.io/specs/#payload
    std::transform(
        encoded.begin(), encoded.end(), encoded.begin(), [](unsigned char c) { return std::tolower(c); });
    res.append(encoded);
    // Remove padding '=' symbols
    res.erase(std::remove_if(res.begin(), res.end(), [](unsigned char x) { return x == '='; }), res.end());
    return res;
  }

  std::vector<uint8_t> checksum(const Address &address) {
    std::vector<uint8_t> res{};

    Protocol p = address.GetProtocol();
    if (p == Protocol::ID) {
      // Checksum is not defined for an ID Address
      return res;
    }

    res.resize(4);

    std::vector<uint8_t> ingest{};

    ingest.push_back(p);

    ingest = visit_in_place(address.data_,
                            [&ingest](uint64_t v) { return ingest; },
                            [&ingest](const Secp256k1PublicKeyHash &v) {
                              ingest.insert(ingest.end(), v.begin(), v.end());
                              return ingest;
                            },
                            [&ingest](const ActorExecHash &v) {
                              ingest.insert(ingest.end(), v.begin(), v.end());
                              return ingest;
                            },
                            [&ingest](const BLSPublicKeyHash &v) {
                              ingest.insert(ingest.end(), v.begin(), v.end());
                              return ingest;
                            });

    size_t outlen = 4;
    blake2b(res.data(), outlen, nullptr, 0, ingest.data(), ingest.size());
    return res;
  }

  bool validateChecksum(const Address &address, const std::vector<uint8_t> &expect) {
    std::vector<uint8_t> digest = checksum(address);
    return digest == expect;
  }

};  // namespace fc::primitives

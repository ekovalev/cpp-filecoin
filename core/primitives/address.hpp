/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CPP_FILECOIN_CORE_PRIMITIVES_ADDRESS_HPP
#define CPP_FILECOIN_CORE_PRIMITIVES_ADDRESS_HPP

#include <cstdint>

#include <boost/variant.hpp>
#include "common/blob.hpp"
#include "common/outcome.hpp"

namespace fc::primitives {

  /**
   * @brief Potential errors creating and handling Filecoin addresses
   */
  enum class AddressError {
    UNKNOWN_PROTOCOL = 1, /**< Unknown Address protocol/type */
    INVALID_PAYLOAD,      /**< Invalid data for a given protocol */
    UNKNOWN_NETWORK       /**< Unknown network: neither testnet nor mainnet */
  };

  /**
   * @brief Supported networks inside which addresses make sense
   */
  enum Network : uint8_t { mainnet = 0x0, testnet = 0x1 };

  /**
   * @brief Known Address protocols
   */
  enum Protocol : uint8_t { ID = 0x0, SECP256K1 = 0x1, Actor = 0x2, BLS = 0x3 };

  struct Secp256k1PublicKeyHash : public common::Blob<20> {
    using Blob::Blob;
  };

  struct ActorExecHash : public common::Blob<20> {
    using Blob::Blob;
  };

  using BLSPublicKeyHash = common::Blob<48>;

  using Payload = boost::variant<uint64_t, Secp256k1PublicKeyHash, ActorExecHash, BLSPublicKeyHash>;

  /**
   * @brief Address refers to an actor in the Filecoin state
   */
  struct Address {
    Address();

    /**
     * @brief ID Addresses constructor
     * @param net  Network id
     * @param id  Numeric id of an Actor to be referred by the address being created
     */
    Address(Network net, uint64_t id);

    /**
     * @brief Secp256k1 public key Address constructor
     * @param net  Network id
     * @param payload  20 bytes long byte array containing the blake2b-160 hash of a public key
     */
    Address(Network net, Secp256k1PublicKeyHash &&payload) noexcept;
    Address(Network net, const Secp256k1PublicKeyHash &payload);

    /**
     * @brief Actor Address constructor
     * @param net  Network id: testnet or mainnet
     * @param payload  20 bytes long byte array containing the blake2b-160 hash of an actor data
     */
    Address(Network net, ActorExecHash &&payload) noexcept;
    Address(Network net, const ActorExecHash &payload);

    /**
     * @brief BLS public key constructor
     * @param net  Network id: testnet or mainnet
     * @param payload  48 bytes long BLS public key
     */
    Address(Network net, BLSPublicKeyHash &&payload) noexcept;
    Address(Network net, const BLSPublicKeyHash &payload);

    /**
     * @brief Returns the address protocol: ID, Secp256k1, Actor or BLS
     */
    Protocol GetProtocol() const;

    /**
     * @brief Public API method as in
     * https://filecoin-project.github.io/specs/#systems__filecoin_vm__actor__address
     * @return true if the address represents a public key
     */
    bool IsKeyType() const;

    Network network_;
    Payload data_;
  };

  /**
   * @brief Addresses equality operator
   */
  bool operator==(const Address &lhs, const Address &rhs);

  /**
   * @brief Addresses "less than" operator
   */
  bool operator<(const Address &lhs, const Address &rhs);

};  // namespace fc::primitives

/**
 * @brief Outcome errors declaration
 */
OUTCOME_HPP_DECLARE_ERROR(fc::primitives, AddressError);

#endif //CMAKE_HUNTER_SEED_CORE_ADDRESS_ADDRESS_HPP

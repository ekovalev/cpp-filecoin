/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CRYPTO_BLS_PROVIDER_IMPL_HPP
#define CRYPTO_BLS_PROVIDER_IMPL_HPP

#include "crypto/bls_provider/bls_provider.hpp"

namespace fc::crypto::bls::impl {
  class BlsProviderImpl : public BlsProvider {
   public:
    outcome::result<KeyPair> generateKeyPair() const override;

    outcome::result<PublicKey> derivePublicKey(
        const PrivateKey &key) const override;

    outcome::result<Signature> sign(gsl::span<uint8_t> message,
                                    const PrivateKey &key) const override;

    outcome::result<bool> verifySignature(gsl::span<uint8_t> message,
                                          const Signature &signature,
                                          const PublicKey &key) const override;

   private:
    /**
     * @brief Generate BLS message digest
     * @param message - data for hashing
     * @return BLS digest or error code
     */
    static outcome::result<Digest> generateHash(
        gsl::span<const uint8_t> message);
  };
}  // namespace fc::crypto::bls

#endif

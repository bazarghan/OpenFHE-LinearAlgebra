#include "EncryptedMatrix.hpp"
#include "openfhe.h"
#include <complex>
#include <gtest/gtest.h>
#include <vector>

using namespace lbcrypto;

// A test for encryption and decryption of a 2x2 matrix.
TEST(EncryptedMatrixTest, EncryptionDecryption) {
  // Define a simple 2x2 plaintext matrix using complex numbers.
  std::vector<std::vector<std::complex<double>>> plaintext = {
      {{1.0, 0.0}, {2.0, 0.0}}, {{3.0, 0.0}, {4.0, 0.0}}};

  CCParams<CryptoContextCKKSRNS> parameters;

  parameters.SetSecretKeyDist(UNIFORM_TERNARY);
  parameters.SetSecurityLevel(HEStd_NotSet);
  parameters.SetRingDim(1 << 10);
  parameters.SetScalingModSize(59);
  parameters.SetScalingTechnique(FLEXIBLEAUTO);
  parameters.SetFirstModSize(60);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

  cc->Enable(PKE);

  // Generate a key pair.
  auto keyPair = cc->KeyGen();
  ASSERT_TRUE(keyPair.publicKey);
  ASSERT_TRUE(keyPair.secretKey);

  // Create an EncryptedMatrix using the crypto context, plaintext matrix, and
  // public key.
  EncryptedMatrix encMat(cc, plaintext, keyPair.publicKey);

  // Decrypt the matrix using the secret key.
  auto decryptedMatrix = encMat.Decrypt(keyPair.secretKey);

  // Verify the dimensions are the same.
  ASSERT_EQ(decryptedMatrix.size(), plaintext.size());
  ASSERT_EQ(decryptedMatrix[0].size(), plaintext[0].size());

  // Check that each element is approximately equal.
  // Use a tolerance value since CKKS encryption is approximate.
  double tol = 1e-3;
  for (size_t i = 0; i < plaintext.size(); ++i) {
    for (size_t j = 0; j < plaintext[0].size(); ++j) {
      EXPECT_NEAR(decryptedMatrix[i][j].real(), plaintext[i][j].real(), tol);
      EXPECT_NEAR(decryptedMatrix[i][j].imag(), plaintext[i][j].imag(), tol);
    }
  }
}

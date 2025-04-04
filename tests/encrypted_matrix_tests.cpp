#include "EncryptedMatrix.hpp"
#include <gtest/gtest.h>

using namespace lbcrypto;

// Test fixture for EncryptedMatrix tests.
class EncryptedMatrixTest : public ::testing::Test {
protected:
  // Define a 4x4 matrix size constant.
  static constexpr int matrixSize = 4;

  // Tolerance for approximate comparisons (CKKS is approximate).
  const double tolerance = 1e-3;

  // Plaintext matrix that will be used for tests.
  std::vector<std::vector<double>> plaintext;

  // Crypto context.
  CryptoContext<DCRTPoly> cc;

  // Key pair.
  KeyPair<DCRTPoly> keyPair;

  // Set up the plaintext matrix and crypto context.
  void SetUp() override {
    // Initialize the 4x4 plaintext matrix.
    plaintext.resize(matrixSize, std::vector<double>(matrixSize));
    for (int i = 0; i < matrixSize; i++) {
      for (int j = 0; j < matrixSize; j++) {
        plaintext[i][j] = i * matrixSize + j;
      }
    }

    // Set up crypto parameters for CKKS scheme.
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(UNIFORM_TERNARY);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 10);
    parameters.SetScalingModSize(59);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetFirstModSize(60);
    parameters.SetBatchSize(matrixSize); // Must match the matrix dimension.

    // Generate crypto context.
    cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // Key generation.
    keyPair = cc->KeyGen();
    ASSERT_TRUE(keyPair.publicKey);
    ASSERT_TRUE(keyPair.secretKey);

    // Generate rotation keys for evaluation (the list should be tailored to
    // your use-case).
    cc->EvalRotateKeyGen(keyPair.secretKey, {-1, -2, -3, -4, 0, 1, 2, 3, 4});
  }
};

TEST_F(EncryptedMatrixTest, EncryptionDecryptionAndTranspose) {
  // Create an EncryptedMatrix from the plaintext using the crypto context and
  // public key.
  EncryptedMatrix encMat(cc, plaintext, keyPair.publicKey);

  // Decrypt the encrypted matrix.
  auto decryptedMatrix = encMat.Decrypt(keyPair.secretKey);

  // Verify dimensions match.
  ASSERT_EQ(decryptedMatrix.size(), plaintext.size());
  ASSERT_EQ(decryptedMatrix[0].size(), plaintext[0].size());

  // Verify that each element is approximately equal.
  for (size_t i = 0; i < plaintext.size(); ++i) {
    for (size_t j = 0; j < plaintext[i].size(); ++j) {
      EXPECT_NEAR(decryptedMatrix[i][j], plaintext[i][j], tolerance);
    }
  }

  // Test the transpose functionality.
  auto encMatTranspose = encMat.T();
  auto decryptedMatrixTranspose = encMatTranspose.Decrypt(keyPair.secretKey);

  // Check that the transposed matrix has been correctly computed:
  // element (i, j) of the transposed matrix should equal element (j, i) of the
  // original plaintext.
  for (size_t i = 0; i < plaintext.size(); ++i) {
    for (size_t j = 0; j < plaintext[i].size(); ++j) {
      EXPECT_NEAR(decryptedMatrixTranspose[i][j], plaintext[j][i], tolerance);
    }
  }

  // Ensure that the original EncryptedMatrix remains unchanged after the
  // transpose operation.
  auto newDecryptedMatrix = encMat.Decrypt(keyPair.secretKey);
  for (size_t i = 0; i < plaintext.size(); ++i) {
    for (size_t j = 0; j < plaintext[i].size(); ++j) {
      EXPECT_NEAR(newDecryptedMatrix[i][j], plaintext[i][j], tolerance);
    }
  }
}

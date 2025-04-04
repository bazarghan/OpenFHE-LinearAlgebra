#ifndef ENCRYPTEDMATRIX_HPP
#define ENCRYPTEDMATRIX_HPP

#include "openfhe.h"
#include <complex>
#include <vector>

// This only Support Square matrix
class EncryptedMatrix {
public:
  // construct and encrypt Matrix from Cleartext Matrix
  EncryptedMatrix(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,
                  const std::vector<std::vector<double>> &matrix,
                  lbcrypto::PublicKey<lbcrypto::DCRTPoly> &pk);

  // this method Decrypt and Decode the Matrix and return as clearMatrix
  std::vector<std::vector<double>>
  Decrypt(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> &sk);

  // this method return the Trasnpose of matirx A.T()-> A^T
  EncryptedMatrix T() const;

private:
  int m_rows;
  int m_cols;
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>
      encryptedData; // here the encrypted Matrix is stored
  lbcrypto::CryptoContext<lbcrypto::DCRTPoly> *cc;
};

#endif

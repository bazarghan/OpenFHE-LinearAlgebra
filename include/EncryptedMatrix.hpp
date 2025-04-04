#ifndef ENCRYPTEDMATRIX_HPP
#define ENCRYPTEDMATRIX_HPP

#include "openfhe.h"
#include <complex>
#include <vector>

class EncryptedMatrix {
public:
  // construct and encrypt Matrix from Cleartext Matrix
  EncryptedMatrix(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,
                  const std::vector<std::vector<std::complex<double>>> &matrix,
                  lbcrypto::PublicKey<lbcrypto::DCRTPoly> &pk);

  // this method Decrypt and Decode the Matrix and return as clearMatrix
  std::vector<std::vector<std::complex<double>>>
  Decrypt(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> &sk);

private:
  int m_rows;
  int m_cols;
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>
      encryptedData; // here the encrypted Matrix is stored
  lbcrypto::CryptoContext<lbcrypto::DCRTPoly> *cc;
};

#endif

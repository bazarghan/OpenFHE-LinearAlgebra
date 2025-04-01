#include "EncryptedMatrix.hpp"

EncryptedMatrix::EncryptedMatrix(
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptoCtx,
    const std::vector<std::vector<std::complex<double>>> &matrix,
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> &pk)
    : m_rows(matrix.size()), m_cols(matrix[0].size()),
      cc(&cryptoCtx) // Store the address of cryptoCtx
{
  std::vector<std::vector<std::complex<double>>> encoded_matrix(
      m_rows, std::vector<std::complex<double>>(m_cols));

  // This is Halevi-Shoup Diagonal Matrix Packing for square Matrix
  // For more information check the link: https://eprint.iacr.org/2020/1481
  for (int i = 0; i < m_rows; i++) {
    for (int j = 0; j < m_cols; j++) {
      encoded_matrix[i][j] = matrix[j][(i + j) % m_cols];
    }
  }

  // The packed matrix should be encrypted.
  for (const auto &row : encoded_matrix) {
    auto ptxt = (*cc)->MakeCKKSPackedPlaintext(row);
    auto ctxt = (*cc)->Encrypt(pk, ptxt);
    encryptedData.push_back(ctxt);
  }
}

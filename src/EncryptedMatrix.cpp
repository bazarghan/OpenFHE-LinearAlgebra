#include "EncryptedMatrix.hpp"

EncryptedMatrix::EncryptedMatrix(
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptoCtx,
    const std::vector<std::vector<double>> &matrix,
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> &pk)
    : m_rows(matrix.size()), m_cols(matrix[0].size()),
      cc(&cryptoCtx) // Store the address of cryptoCtx
{
  std::vector<std::vector<double>> encoded_matrix(m_rows,
                                                  std::vector<double>(m_cols));

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
    ptxt->SetLength(m_cols);
    auto ctxt = (*cc)->Encrypt(pk, ptxt);
    encryptedData.push_back(ctxt);
  }
}

std::vector<std::vector<double>>
EncryptedMatrix::Decrypt(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> &sk) {

  // Decrypt the Matrix
  std::vector<std::vector<double>> encoded_matrix;
  for (auto &cRow : encryptedData) {
    lbcrypto::Plaintext pRow;
    (*cc)->Decrypt(sk, cRow, &pRow);
    pRow->SetLength(m_cols);
    encoded_matrix.push_back(pRow->GetRealPackedValue());
  }

  // Unpack the matrix

  std::vector<std::vector<double>> decoded_matrix(m_rows,
                                                  std::vector<double>(m_cols));

  // This is Halevi-Shoup Diagonal Matrix UnPacking for square Matrix
  // For more information check the link: https://eprint.iacr.org/2020/1481
  for (int i = 0; i < m_rows; i++) {
    for (int j = 0; j < m_cols; j++) {
      decoded_matrix[i][j] = encoded_matrix[(j - i + m_rows) % m_rows][i];
    }
  }

  return decoded_matrix;
}

// Returns the Transpose of the matrix
EncryptedMatrix EncryptedMatrix::T() const {
  EncryptedMatrix matrixT(*this);
  for (int i = 0; i < matrixT.m_rows; i++) {
    matrixT.encryptedData[i] =
        (*cc)->EvalRotate(this->encryptedData[(m_rows - i) % m_rows], i);
  }
  return matrixT;
}

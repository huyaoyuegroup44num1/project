#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <openssl/sha.h>

using namespace std;

string sha256(const string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    string hashedString;
    hashedString.reserve(SHA256_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashedString.append(to_string(hash[i]));
    }

    return hashedString;
}

string computeMerkleRoot(const vector<string>& transactions) {
    if (transactions.empty()) {
        return "";
    }
    if (transactions.size() == 1) {
        return sha256(transactions[0]);
    }

    vector<string> merkleTree = transactions;
    if (merkleTree.size() % 2 != 0) {
        merkleTree.push_back(merkleTree.back());
    }

    while (merkleTree.size() > 1) {
        vector<string> nextLevel;
        for (size_t i = 0; i < merkleTree.size(); i += 2) {
            string concatenatedHashes = merkleTree[i] + merkleTree[i + 1];
            string combinedHash = sha256(concatenatedHashes);
            nextLevel.push_back(combinedHash);
        }

        merkleTree = nextLevel;
    }

    return merkleTree[0];
}

int main() {
    vector<string> transactions = { "Transaction1", "Transaction2", "Transaction3", "Transaction4" };

    auto start = chrono::high_resolution_clock::now();  // 记录开始时间

    string merkleRoot = computeMerkleRoot(transactions);

    auto end = chrono::high_resolution_clock::now();  // 记录结束时间
    chrono::duration<double, milli> duration = end - start;  // 计算运行时间

    cout << "Merkle Root: " << merkleRoot << endl;
    cout << "运行时间: " << fixed << setprecision(2) << duration.count() << " 毫秒" << endl;

    return 0;
}

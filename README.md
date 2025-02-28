# SSS-C++ - Shamir's Secret Sharing in C++
A very simple, header only, implementation of SSS in C++. Based on https://github.com/onbit-uchenik/shamir_secret_share

## Simple Usage:
```
#include "sss.h"

// Initialize secrets
const std::string secret = "This is a secret";
constexpr const size_t members = 10; // Split into 10 parts
constexpr const size_t threshold = 7; // Require at least 7 parts to decrypt
SSS::Shares s = SSS::CreateShares(10, 7, secret.c_str());

// Access individual parts of the share with std::vector access:
const SSS::Share& sharePart0 = s[0];
const SSS::Share& sharePart1 = s[1];

// Save to file
const char* filePath = "/tmp/sss-cpp-test";
SSS::SaveShares(s, filePath);

// Load from file
SSS::Shares s2 = SSS::LoadShares(filePath);
const std::string retrievedSecret = SSS::GetSecret(s2);
```

#pragma once

#include <cassert>
#include <random>
#include <string>
#include <vector>

/// Implementation originally taken from: https://github.com/onbit-uchenik/shamir_secret_share

namespace SSS
{

#define SECRET_CANARY_PADDING 0
constexpr const char CanaryPaddingByte = 0x01;

namespace GF256
{

constexpr const size_t FieldSize = 256;
constexpr const uint8_t FieldMax = 255;

/*
 this function should be called so that a*b can be calculated O(1), also if this function is not
 called a*b will output always 0.
 the function precalculate exponents of 3 ^ rs where 0<=rs<=255, 3 is chosen becuase 3 is generator
 in field GF(256) when irreducible polynomial is :- x^8 + x^4 + x^3 + x + 1
 the function also precalculate logarithms to the base 3.
*/

/*
 slow multiplication of bytes, a * b,Time Complexity : O(log a)
*/

/*Byte slowMul(Byte& a, Byte& b)
{
	unsigned int aa = a.num, bb = b.num, r = 0, t;
	while (aa != 0)
	{
		if ((aa & 1) != 0)
		{
			r = (r ^ bb);
		}
		t = (bb & 128);
		bb = (bb << 1);
		if (t != 0)
		{
			bb = bb ^ 283;
		}
		aa = aa >> 1;
	}
	Byte ans = r;
	return ans;
}*/

/*void gen_multipletable()
{
	Byte generator = 3;
	Exponents[0] = 1;;
	for (int i = 1; i < 256; i++)
	{
		Exponents[i] = slowMul(generator, Exponents[i - 1]);
	}

	for (int i = 0; i < 256; i++)
	{
		Logs[Exponents[i].num] = i;
	}
	Logs[1] = 0;
}*/

static unsigned char Exponents[FieldSize] =
{
	0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35
	, 0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa
	, 0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31
	, 0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd
	, 0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88
	, 0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a
	, 0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3
	, 0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0
	, 0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41
	, 0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75
	, 0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80
	, 0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54
	, 0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca
	, 0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e
	, 0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17
	, 0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01
};

static unsigned char Logs[FieldSize] =
{
	0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03
	, 0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1
	, 0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78
	, 0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e
	, 0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38
	, 0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10
	, 0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba
	, 0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57
	, 0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8
	, 0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0
	, 0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7
	, 0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d
	, 0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1
	, 0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab
	, 0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5
	, 0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07
};

class Byte
{
public:
	unsigned char num;

	Byte() : num(0)
	{
	}

	Byte(unsigned char n) : num(n)
	{
	}

	Byte operator+(Byte b) const
	{
		return ((*this) ^ b);
	}

	Byte operator-(Byte b) const
	{
		return ((*this) ^ b);
	}

	Byte operator^(Byte b) const
	{
		return num ^ (b.num);
	}

	void operator=(int n)
	{
		num = n;
	}

	Byte operator*(Byte b) const
	{
		int t = 0;
		if (num == 0 || b.num == 0)
		{
			return 0;
		}

		t = Logs[num] + Logs[b.num];
		if (t > FieldMax)
		{
			t = t - FieldMax;
		}
		return Exponents[t];
	}

	bool operator!=(Byte b) const
	{
		return num != b.num;
	}

	Byte operator~() const
	{
		unsigned char y = Logs[num];
		unsigned char x = FieldMax - y;
		x = FieldMax - y;
		return Exponents[x];
	}

	Byte operator/(Byte b) const
	{
		Byte c = ~b;
		return (*this) * c;
	}
};

struct Point
{
	Byte x;
	Byte y;
};

bool operator<(const Byte& lhs, const Byte& rhs)
{
	return lhs.num < rhs.num;
}

/*
  calculating a ^ b, time Complexity : O(log b)
*/
Byte Power(Byte a, int b)
{
	if (b == 0) return 1;
	else
	{
		Byte ans = Power(a, b / 2);
		if (b % 2 != 0)
		{
			return (ans * (ans * a));
		}
		else
		{
			return (ans * ans);
		}
	}
}

/*
  lagrange interpolation algorithm.
  rather than calculating the complete ploynomial p(x) only value of p(0) is calculated as this is
  secret.
*/
unsigned char Interpolate(const std::vector<Point>& share)
{
	Byte secret = 0;
	int n = share.size();

	for (int i = 0; i < n; i++)
	{
		Byte term = 1;

		for (int j = 0; j < n; j++)
		{
			if (i == j)
			{
				continue;
			}
			term = term * (share[j].x / (share[j].x - share[i].x));
		}
		term = term * share[i].y;
		secret = secret + term;
	}
	return secret.num;
}

};

using Share = std::vector<GF256::Point>;

size_t SerializeShare(const Share& s, char* buffer, size_t sz)
{
	char* bufferStart = buffer;
	const size_t size = s.size();

	sz -= sizeof(size);
	assert(sz >= 0);
	std::memcpy(buffer, &size, sizeof(size));
	buffer += sizeof(size);

	for (size_t i = 0; i < s.size(); ++i)
	{
		sz -= sizeof(size);
		assert(sz >= 0);
		buffer[0] = reinterpret_cast<unsigned char>(s[i].x.num);
		buffer += sizeof(s[i].x.num);

		sz -= sizeof(size);
		assert(sz >= 0);
		buffer[0] = reinterpret_cast<unsigned char>(s[i].y.num);
		buffer += sizeof(s[i].y.num);
	}

	return buffer - bufferStart;
}

size_t DeserializeShare(Share& s, const char* buffer)
{
	const char* bufferStart = buffer;
	size_t size = 0;
	std::memcpy(&size, buffer, sizeof(size));
	buffer += sizeof(size);
	s.resize(size);

	for (size_t i = 0; i < s.size(); ++i)
	{
		s[i].x = buffer[0];
		buffer += sizeof(s[i].x);
		s[i].y = buffer[0];
		buffer += sizeof(s[i].y);
	}

	return buffer - bufferStart;
}

class Shares : public std::vector<Share>
{
public:
	void InitShares(size_t members, size_t threshold)
	{
		_members = members;
		_threshold = threshold;
		resize(members);
	}

	inline bool HasThreshold() const
	{
		return size() >= _threshold;
	}

	inline bool CanDecrypt() const
	{
		return HasThreshold();
	}

	inline size_t Members() const
	{
		return _members;
	}

	inline size_t Threshold() const
	{
		return _threshold;
	}

	size_t SerializeSize() const
	{
		size_t retval = 0;
		retval += sizeof(_members);
		retval += sizeof(_threshold);
		retval += sizeof(size_t);
		for (const SSS::Share& share : *this)
		{
			retval += sizeof(size_t);
			for (const SSS::GF256::Point& p : share)
			{
				retval += sizeof(p);
			}
		}
		return retval;
	}

	size_t Serialize(char* buffer, size_t bufsz) const
	{
		const char* bufferStart = buffer;
		const size_t sz = size();

		bufsz -= sizeof(sz);
		assert(bufsz >= 0);
		std::memcpy(buffer, &_members, sizeof(_members));
		buffer += sizeof(sz);

		bufsz -= sizeof(sz);
		assert(bufsz >= 0);
		std::memcpy(buffer, &_threshold, sizeof(_threshold));
		buffer += sizeof(sz);

		bufsz -= sizeof(sz);
		assert(bufsz >= 0);
		std::memcpy(buffer, &sz, sizeof(sz));
		buffer += sizeof(sz);

		for (size_t i = 0; i < size(); ++i)
		{
			const size_t bytes = SerializeShare(at(i), buffer, bufsz);
			buffer += bytes;
			bufsz -= bytes;
		}

		return buffer - bufferStart;
	}

	void Deserialize(const char* buffer, size_t bufsz)
	{
		std::memcpy(&_members, buffer, sizeof(_members));
		buffer += sizeof(_members);

		std::memcpy(&_threshold, buffer, sizeof(_threshold));
		buffer += sizeof(_threshold);

		size_t sz = 0;
		std::memcpy(&sz, buffer, sizeof(sz));
		buffer += sizeof(sz);

		for (size_t i = 0; i < sz; ++i)
		{
			Share s;
			buffer += DeserializeShare(s, buffer);
			push_back(s);
		}
	}

private:
	size_t _members = 0;
	size_t _threshold = 0;
};

size_t SaveShares(const Shares& shares, FILE* f)
{
	char* buffer = new char[shares.SerializeSize()];
	const size_t retval = shares.Serialize(buffer, shares.SerializeSize());
	fwrite(buffer, retval, 1, f);
	delete[] buffer;
	return retval;
}

size_t SaveShares(const Shares& shares, const char* path)
{
	FILE* f = fopen(path, "wb");
	const size_t retval = SaveShares(shares, f);
	fclose(f);
	return retval;
}

Shares LoadShares(FILE* f)
{
	fseek(f, 0, SEEK_END);
	long filesz = ftell(f);
	fseek(f, 0, SEEK_SET);
	char* buffer = new char[filesz];
	fread(buffer, filesz, 1, f);
	Shares shares;
	shares.Deserialize(buffer, filesz);
	delete[] buffer;
	return shares;
}

Shares LoadShares(const char* path)
{
	FILE* f = fopen(path, "rb");
	const Shares& shares = LoadShares(f);
	fclose(f);
	return shares;
}

Shares CreateShares(size_t members, size_t threshold, const char* secret, size_t size)
{
	Shares retval;
	retval.InitShares(members, threshold);

	std::random_device device;
	std::default_random_engine generator(device());
	std::uniform_int_distribution<int> distribution(0, SSS::GF256::FieldMax);

	GF256::Byte* coeff = new GF256::Byte[threshold];
	for (size_t i = 0; i < size; ++i)
	{
		char data = 0;
#if SECRET_CANARY_PADDING == 1
		if (i == 0 || i == 1)
		{
			data = CanaryPaddingByte;
		}
		else
#endif
		{
			data = secret[i];
		}

		coeff[0] = data;
		for (size_t j = 1; j < threshold; j++)
		{
			coeff[j] = distribution(generator);
		}

		GF256::Point temp;
		GF256::Byte x;
		GF256::Byte y;

		for (size_t j = 0; j < members; j++)
		{
			x = static_cast<int>(j + 1);
			y = 0;
			for (size_t j = 0; j < threshold; j++)
			{
				y = y + (coeff[j] * Power(x, j));
			}
			temp.x = x;
			temp.y = y;
			retval[j].push_back(temp);
		}
	}
	delete[] coeff;

	return retval;
}

Shares CreateShares(size_t members, size_t threshold, const std::string& secret)
{
	return CreateShares(members, threshold, secret.c_str(), secret.size());
}

bool GetSecret(const Shares& shares, std::string& out)
{
	out = "";
	bool retval = true;
	if (!shares.HasThreshold())
	{
		// fprintf(stderr, "Not enough shares to decrypt\n");
		retval = false;
	}

	size_t pos = 0;

	// Try to decrypt anyway, keeping the function at fixed time
	const size_t shareCount = shares.size();
	const int secretSize = shares[0].size();
	out.reserve(secretSize);
	std::vector<GF256::Point> currentShares(shares.size());
	for (int di = 0; di < secretSize; di++)
	{
		for (size_t i = 0; i < shareCount; i++)
		{
			currentShares[i] = shares[i][di];
		}
		const char c = Interpolate(currentShares);

#if SECRET_CANARY_PADDING == 1
		if (pos == 0 || pos == 1)
		{
			if (c != CanaryPaddingByte)
			{
				//assert(c == CanaryPaddingByte);
				fprintf(stderr, "CanaryByteError\n");
				retval = false;
			}
		}
		else
#endif
		{
			out += c;
		}

		++pos;
	}

	return retval;
}

bool GetSecret(const Shares& shares, char* secret, size_t size)
{
	const size_t shareCount = shares.size();
	const size_t secretSize = shares[0].size();

	bool retval = true;

	if (!shares.HasThreshold())
	{
		// fprintf(stderr, "Not enough shares to decrypt\n");
		retval = false;
	}

	if (secretSize > size)
	{
		// fprintf(stderr, "Not enough space given to decrypt secret. Secret size: %zu, size allowed: %zu\n", secretSize, size);
		return false;
	}

	// Try to decrypt anyway, keeping the function at fixed time
	std::vector<GF256::Point> currentShares(shares.size());
	size_t pos = 0;
	for (size_t di = 0; di < secretSize; di++)
	{
		for (size_t i = 0; i < shareCount; i++)
		{
			currentShares[i] = shares[i][di];
		}

		const char c = Interpolate(currentShares);
#if SECRET_CANARY_PADDING == 1
		if (pos == 0 || pos == 1)
		{
			if (c != CanaryPaddingByte)
			{
				//assert(c == CanaryPaddingByte);
				fprintf(stderr, "CanaryByteError\n");
				retval = false;
			}
			++pos;
		}
		else
#endif
		{
			secret[pos++] = Interpolate(currentShares);
		}
	}

	return retval;
}

char* GetSecret(const Shares& shares)
{
	const size_t secretSize = shares[0].size();

	char* retval = new char[secretSize + 1];
	retval[secretSize] = '\0';
	assert(retval != nullptr);

	if (!GetSecret(shares, retval, secretSize))
	{
		delete[] retval;
		retval = nullptr;
	}

	return retval;
}

}; // namespace SSS

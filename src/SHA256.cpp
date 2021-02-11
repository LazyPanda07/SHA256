#include "SHA256.h"

#include <unordered_map>
#include <bitset>
#include <algorithm>

#define CHAR_BIT 8

#pragma warning(disable: 4146) // unary - on unsigned rightRotate
#pragma warning(disable: 6260)
#pragma warning(disable: 6290) // unary ! on unsigned

using namespace std;

enum class appendType
{
	zero,
	one
};

template<typename T>
string toBinary(const T& value);

string rightRotate(const string& binaryString, uint32_t count);

uint32_t rightRotate(uint32_t value, uint32_t count);

string rightShift(const string& binaryString, uint32_t count);

void appendBit(string& binaryData, appendType type);

namespace encoding
{
	string SHA256::hexConversion(const string& binaryString)
	{
		static const unordered_map<string_view, char> alphabet =
		{
			{ "0000", '0' },
			{ "0001", '1' },
			{ "0010", '2' },
			{ "0011", '3' },
			{ "0100", '4' },
			{ "0101", '5' },
			{ "0110", '6' },
			{ "0111", '7' },
			{ "1000", '8' },
			{ "1001", '9' },
			{ "1010", 'A' },
			{ "1011", 'B' },
			{ "1100", 'C' },
			{ "1101", 'D' },
			{ "1110", 'E' },
			{ "1111", 'F' },
		};
		string result;

		result.reserve(SHA256::sha256InBytesSize);

		for (size_t i = 0; i < binaryString.size(); i += 4)
		{
			result += alphabet.at(string_view(binaryString.data() + i, 4));
		}

		return result;
	}

	SHA256::SHA256(outputType type) :
		type(type)
	{

	}

	SHA256::SHA256(const string& data, outputType type) :
		data(data),
		type(type)
	{

	}

	SHA256::SHA256(const SHA256& other) :
		data(other.data),
		type(other.type)
	{

	}

	SHA256::SHA256(SHA256&& other) noexcept :
		data(move(other.data)),
		type(other.type)
	{

	}

	SHA256& SHA256::operator = (const SHA256& other)
	{
		data = other.data;
		type = other.type;

		return *this;
	}

	SHA256 & SHA256::operator = (SHA256&& other) noexcept
	{
		data = move(other.data);
		type = other.type;

		return *this;
	}

	string SHA256::encode() const
	{
		string binaryData;
		array<string, 64> w;
		string tem;
		size_t zeroIndex = 0;
		string result;

		result.reserve(sha256InBitsSize);

		binaryData.reserve(data.size() * CHAR_BIT);

		for (const auto& i : data)
		{
			binaryData += toBinary(i);
		}

		appendBit(binaryData, appendType::one);

		while (binaryData.size() % 512 != 448)
		{
			appendBit(binaryData, appendType::zero);
		}

		binaryData += toBinary
		(
			[this]() -> uint64_t
			{
				string tem;

				tem.reserve(data.size() * CHAR_BIT);

				for (const auto& i : data)
				{
					tem += toBinary(i);
				}

				return tem.size();
			}()
				);


		for (size_t i = 0, j = 0; i < binaryData.size(); i++)
		{
			if (i && !(i % 32))	// 32 bits words in w array
			{
				w[j++] = move(tem);
			}

			tem += binaryData[i];
		}

		w[15] = move(tem);

		for_each(w.begin() + 16, w.end(), [](string& value) { value = string(32, '0'); });

		for (size_t i = 16; i < w.size(); i++)
		{
			uint32_t s0 = stoul(rightRotate(w[i - 15], 7), &zeroIndex, 2) ^ stoul(rightRotate(w[i - 15], 18), &zeroIndex, 2) ^ stoul(rightShift(w[i - 15], 3), &zeroIndex, 2);
			uint32_t s1 = stoul(rightRotate(w[i - 2], 17), &zeroIndex, 2) ^ stoul(rightRotate(w[i - 2], 19), &zeroIndex, 2) ^ stoul(rightShift(w[i - 2], 10), &zeroIndex, 2);

			w[i] = toBinary((stoul(w[i - 16], &zeroIndex, 2) + s0 + stoul(w[i - 7], &zeroIndex, 2) + s1) % additionModulo);
		}

		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;
		uint32_t f = h5;
		uint32_t g = h6;
		uint32_t h = h7;

		for (size_t i = 0; i < w.size(); i++)
		{
			uint32_t s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
			uint32_t ch = (e & f) ^ (~e & g);
			uint32_t temp1 = (h + s1 + ch + k[i] + stoul(w[i], &zeroIndex, 2)) % additionModulo;
			uint32_t s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
			uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint32_t temp2 = (s0 + maj) % additionModulo;

			h = g;
			g = f;
			f = e;
			e = (d + temp1) % additionModulo;
			d = c;
			c = b;
			b = a;
			a = (temp1 + temp2) % additionModulo;
		}

		result = 
			toBinary((h0 + a) % additionModulo) +
			toBinary((h1 + b) % additionModulo) +
			toBinary((h2 + c) % additionModulo) +
			toBinary((h3 + d) % additionModulo) +
			toBinary((h4 + e) % additionModulo) +
			toBinary((h5 + f) % additionModulo) +
			toBinary((h6 + g) % additionModulo) +
			toBinary((h7 + h) % additionModulo);

		switch (type)
		{
		case encoding::SHA256::outputType::binary:
			return result;

		case encoding::SHA256::outputType::hexadecimal:
			return hexConversion(result);

		default:
			throw runtime_error("Unknown error");
		}
	}

	const string& SHA256::operator * () const
	{
		return data;
	}

	void SHA256::setOutputType(outputType type)
	{
		this->type = type;
	}

	SHA256::outputType SHA256::getOutputType() const
	{
		return type;
	}

	ostream& operator << (ostream& stream, const SHA256& sha)
	{
		return stream << sha.encode();
	}
}

template<typename T>
string toBinary(const T& value)
{
	return (stringstream() << bitset<sizeof(T) * CHAR_BIT>(value)).str();
}

string rightRotate(const string& binaryString, uint32_t count)
{
	count = binaryString.size() - count;
	string tem = binaryString;

	reverse(tem.begin(), tem.begin() + count);
	reverse(tem.begin() + count, tem.end());
	reverse(tem.begin(), tem.end());

	return tem;
}

uint32_t rightRotate(uint32_t value, uint32_t count)
{
	const unsigned int mask = (CHAR_BIT * sizeof(value) - 1);

	count &= mask;
	return (value >> count) | (value << ((-count) & mask));
}

string rightShift(const string& binaryString, uint32_t count)
{
	string tem = binaryString;

	for (uint32_t i = tem.size() - 1; i >= count; i--)
	{
		tem[i] = tem[i - count];
	}

	replace_if(tem.begin(), tem.begin() + count, [](const auto& value) { return true; }, '0');

	return tem;
}

void appendBit(string& binaryData, appendType type)
{
	switch (type)
	{
	case appendType::zero:
		binaryData += '0';

		break;

	case appendType::one:
		binaryData += '1';

		break;
	}
}

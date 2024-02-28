#include "SHA256.h"

#include <unordered_map>
#include <bitset>
#include <algorithm>
#include <numeric>
#include <cstring>

constexpr uint8_t bitsInByte = 8;
constexpr uint8_t hexAlphabetValuesSize = 4;

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

uint32_t rightRotate(uint32_t value, uint32_t count);

uint32_t rightShift(uint32_t value, uint32_t count);

void appendBit(string& binaryData, appendType type);

string accumulateResultString(const string& currentString, uint32_t nextValue);

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

		result.reserve(SHA256::sha256StringSize);

		for (size_t i = 0; i < binaryString.size(); i += hexAlphabetValuesSize)
		{
			result += alphabet.at(string_view(binaryString.data() + i, hexAlphabetValuesSize));
		}

		return result;
	}

	void SHA256::mainLoop(string_view nextBlock, vector<uint32_t>& currentValues)
	{
		array<uint32_t, sha256StringSize> w = {};

		for (size_t i = 0, j = 0; i < nextBlock.size(); i += hexAlphabetValuesSize, j++)
		{
			uint32_t value = 0;
			char* ptr = reinterpret_cast<char*>(&value) + sizeof(value) - 1;
			char* currentPtr = const_cast<char*>(nextBlock.data()) + i;

			for (size_t k = 0; k < sizeof(uint32_t); k++)
			{
				*ptr-- = *currentPtr++;
			}

			w[j] = value;
		}

		for (size_t i = 16; i < w.size(); i++)
		{
			uint32_t s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ rightShift(w[i - 15], 3);
			uint32_t s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ rightShift(w[i - 2], 10);

			w[i] = (w[i - 16] + s0 + w[i - 7] + s1);
		}

		uint32_t a = currentValues[0];
		uint32_t b = currentValues[1];
		uint32_t c = currentValues[2];
		uint32_t d = currentValues[3];
		uint32_t e = currentValues[4];
		uint32_t f = currentValues[5];
		uint32_t g = currentValues[6];
		uint32_t h = currentValues[7];

		for (size_t i = 0; i < w.size(); i++)
		{
			uint32_t s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
			uint32_t ch = (e & f) ^ (~e & g);
			uint32_t temp1 = h + s1 + ch + k[i] + w[i];
			uint32_t s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
			uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint32_t temp2 = s0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		currentValues[0] += a;
		currentValues[1] += b;
		currentValues[2] += c;
		currentValues[3] += d;
		currentValues[4] += e;
		currentValues[5] += f;
		currentValues[6] += g;
		currentValues[7] += h;
	}

	string SHA256::getVersion()
	{
		string version = "1.5.0";

		return version;
	}

	string SHA256::getHash(const string& data, outputType type)
	{
		string binaryData = data;
		string result;

		result.reserve(sha256InBitsSize);

		appendBit(binaryData, appendType::one);

		while (binaryData.size() % sha256StringSize != sha256StringSize - sizeof(uint64_t))
		{
			appendBit(binaryData, appendType::zero);
		}

		binaryData += [&data]() -> string
		{
			string tem;
			uint64_t size = 0;
			char* ptr = reinterpret_cast<char*>(&size) + sizeof(size) - 1;	// big-endian

			tem.reserve(data.size() * bitsInByte);

			for (const auto& i : data)
			{
				tem += toBinary(i);
			}

			size = tem.size();
			tem.clear();

			for (size_t i = 0; i < sizeof(size); i++)
			{
				tem += *ptr--;
			}

			return tem;
		}();

		vector<uint32_t> values =
		{
			SHA256::h0,
			SHA256::h1,
			SHA256::h2,
			SHA256::h3,
			SHA256::h4,
			SHA256::h5,
			SHA256::h6,
			SHA256::h7
		};

		for (size_t i = 0; i < binaryData.size(); i += sha256StringSize)
		{
			mainLoop(string_view(binaryData.data() + i, sha256StringSize), values);
		}

		result = accumulate(values.begin(), values.end(), ""s, accumulateResultString);

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

	SHA256::SHA256(outputType type)
	{
		data.reserve(sha256StringSize);

		this->clear(type);
	}

	SHA256::SHA256(const string& data, outputType type)
	{
		this->data.reserve(sha256StringSize);

		this->clear(type);

		this->update(data);
	}

	SHA256::SHA256(const SHA256& other) :
		data(other.data),
		type(other.type),
		currentSize(other.currentSize),
		currentValues(other.currentValues)
	{

	}

	SHA256::SHA256(SHA256&& other) noexcept :
		data(move(other.data)),
		type(other.type),
		currentSize(other.currentSize),
		currentValues(move(other.currentValues))
	{

	}

	SHA256& SHA256::operator = (const SHA256& other)
	{
		data = other.data;
		type = other.type;
		currentSize = other.currentSize;
		currentValues = other.currentValues;

		return *this;
	}

	SHA256& SHA256::operator = (SHA256&& other) noexcept
	{
		data = move(other.data);
		type = other.type;
		currentSize = other.currentSize;
		currentValues = move(other.currentValues);

		return *this;
	}

	void SHA256::update(const string& data)
	{
		for (const auto& i : data)
		{
			this->data += i;
			currentSize++;

			if (this->data.size() == sha256StringSize)
			{
				mainLoop(string_view(this->data.data(), sha256StringSize), currentValues);

				this->data.clear();
			}
		}
	}

	string SHA256::getHash()
	{
		string binaryData = data;
		string result;
		vector<uint32_t> savedValues = currentValues;

		result.reserve(sha256InBitsSize);

		if (binaryData.size() >= sha256StringSize - sizeof(uint64_t))
		{
			uint64_t size = currentSize * 8;
			char* ptr = reinterpret_cast<char*>(&size) + sizeof(size) - 1; // big-endian

			appendBit(binaryData, appendType::one);

			while (binaryData.size() != sha256StringSize)
			{
				appendBit(binaryData, appendType::zero);
			}

			mainLoop(string_view(binaryData.data(), sha256StringSize), currentValues);

			memset(binaryData.data(), NULL, sha256StringSize - sizeof(size));

			for (size_t i = sha256StringSize - sizeof(size); i < binaryData.size(); i++)
			{
				binaryData[i] = *ptr--;
			}
		}
		else
		{
			appendBit(binaryData, appendType::one);

			while (binaryData.size() != sha256StringSize - sizeof(uint64_t))
			{
				appendBit(binaryData, appendType::zero);
			}

			binaryData += [this]() -> string
			{
				string tem;
				uint64_t size = 0;
				char* ptr = reinterpret_cast<char*>(&size) + sizeof(size) - 1; // big-endian

				size = currentSize * 8;
				tem.clear();

				for (size_t i = 0; i < sizeof(size); i++)
				{
					tem += *ptr--;
				}

				return tem;
			}();
		}

		mainLoop(string_view(binaryData.data(), sha256StringSize), currentValues);

		result = accumulate(currentValues.begin(), currentValues.end(), ""s, accumulateResultString);

		currentValues = savedValues;

		switch (type)
		{
		case outputType::binary:
			return result;

		case outputType::hexadecimal:
			return hexConversion(result);

		default:
			throw runtime_error("Unknown outputType value");
		}
	}

	void SHA256::setOutputType(outputType type)
	{
		this->type = type;
	}

	SHA256::outputType SHA256::getOutputType() const
	{
		return type;
	}

	void SHA256::clear(outputType type) noexcept
	{
		currentSize = 0;
		currentValues = { h0, h1, h2, h3, h4, h5, h6, h7 };
		this->type = type;
		data.clear();
	}

	ostream& operator << (ostream& stream, SHA256& sha)
	{
		return stream << sha.getHash();
	}
}

template<typename T>
string toBinary(const T& value)
{
	return (ostringstream() << bitset<sizeof(T) * bitsInByte>(value)).str();
}

string rightRotate(const string& binaryString, uint32_t count)
{
	count = static_cast<uint32_t>(binaryString.size()) - count;
	string tem = binaryString;

	reverse(tem.begin(), tem.begin() + count);
	reverse(tem.begin() + count, tem.end());
	reverse(tem.begin(), tem.end());

	return tem;
}

uint32_t rightRotate(uint32_t value, uint32_t count)
{
	uint32_t mask = (bitsInByte * sizeof(value) - 1);

	count &= mask;
	return (value >> count) | (value << ((-count) & mask));
}

uint32_t rightShift(uint32_t value, uint32_t count)
{
	return value >> count;
}

void appendBit(string& binaryData, appendType type)
{
	switch (type)
	{
	case appendType::zero:
		binaryData += static_cast<char>(NULL);

		break;

	case appendType::one:
		binaryData += static_cast<char>(128);

		break;
	}
}

string accumulateResultString(const string& currentString, uint32_t nextValue)
{
	return currentString + toBinary(nextValue);
}

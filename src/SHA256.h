#pragma once

#include <string>
#include <unordered_map>
#include <array>
#include <sstream>
#include <bitset>
#include <algorithm>

#pragma warning (push)

#pragma warning(disable: 4146) // unary - on unsigned rightRotate
#pragma warning(disable: 6260)
#pragma warning(disable: 6290) // unary ! on unsigned

using namespace std;

namespace encoding
{
	class SHA256
	{
	private:
		enum class appendType
		{
			zero,
			one
		};

	public:
		template<typename T>
		static string toBinary(const T& value)
		{
			return (stringstream() << bitset<sizeof(T) * sizeof(char)>(value)).str();
		}

		static string rightRotate(const string& binaryString, uint32_t count)
		{
			count = binaryString.size() - count;
			string tem = binaryString;

			reverse(tem.begin(), tem.begin() + count);
			reverse(tem.begin() + count, tem.end());
			reverse(tem.begin(), tem.end());

			return tem;
		}

		static uint32_t rightRotate(uint32_t value, uint32_t count)
		{
			const unsigned int mask = (sizeof(char) * sizeof(value) - 1);

			count &= mask;
			return (value >> count) | (value << ((-count) & mask));
		}

		static string rightShift(const string& binaryString, uint32_t count)
		{
			string tem = binaryString;

			for (int i = tem.size() - 1; i >= count; i--)
			{
				tem[i] = tem[i - count];
			}

			replace_if(tem.begin(), tem.begin() + count, [](const auto& value) { return true; }, '0');

			return tem;
		}

	private:
		static constexpr uint32_t h0 = 0x6a09e667;
		static constexpr uint32_t h1 = 0xbb67ae85;
		static constexpr uint32_t h2 = 0x3c6ef372;
		static constexpr uint32_t h3 = 0xa54ff53a;
		static constexpr uint32_t h4 = 0x510e527f;
		static constexpr uint32_t h5 = 0x9b05688c;
		static constexpr uint32_t h6 = 0x1f83d9ab;
		static constexpr uint32_t h7 = 0x5be0cd19;
		static constexpr array<uint32_t, 64> k =
		{
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		};
		static constexpr uint32_t additionModulo = static_cast<uint64_t>(numeric_limits<uint32_t>::max());

	private:
		void appendBit(appendType type)
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

	private:
		string data;
		string binaryData;

	public:
		SHA256() = default;

		SHA256(const string& data) :
			data(data)
		{
			binaryData.reserve(data.size() * sizeof(char));

			for (const auto& i : data)
			{
				binaryData += toBinary(i);
			}
		}

		string calculate()
		{
			array<string, 64> w;
			string tem;
			size_t zeroIndex = 0;

			this->appendBit(appendType::one);

			while (binaryData.size() % 512 != 448)
			{
				this->appendBit(appendType::zero);
			}

			binaryData += toBinary
			(
				[this]() -> uint64_t
				{
					string tem;

					tem.reserve(data.size() * sizeof(char));

					for (const auto& i : data)
					{
						tem += toBinary(i);
					}

					return tem.size();
				}()
					);


			for (size_t i = 0, j = 0; i < binaryData.size(); i++)
			{
				if (i && !(i % 32))
				{
					w[j++] = move(tem);
				}

				tem += binaryData[i];
			}

			w[15] = move(tem);

			for (size_t i = 16; i < w.size(); i++)
			{
				w[i] = string(32, '0');
			}

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

#define RESULT(first, second) toBinary((first + second) % additionModulo)

			return RESULT(h0, a) + RESULT(h1, b) + RESULT(h2, c) + RESULT(h3, d) + RESULT(h4, e) + RESULT(h5, f) + RESULT(h6, g) + RESULT(h7, h);
		}

		const string& getBinaryData() const
		{
			return binaryData;
		}

		friend ostream& operator << (ostream& stream, SHA256& sha)
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

			string tem = sha.calculate();
			string result;

			result.reserve(64);

			for (size_t i = 0; i < tem.size(); i += 4)
			{
				result += alphabet.at(string_view(tem.data() + i, 4));
			}

			return stream << result;
		}

		~SHA256() = default;
	};
}

#pragma warning (pop)

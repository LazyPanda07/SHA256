#pragma once

#ifdef SHA256_DLL
#define SHA256_API __declspec(dllexport)
#else
#define SHA256_API
#endif // SHA256_DLL

#include <array>
#include <vector>
#include <string>
#include <sstream>

namespace encoding
{
	class SHA256_API SHA256
	{
	public:
		static constexpr uint32_t sha256InBitsSize = 256;
		static constexpr uint32_t sha256InBytesSize = 32;
		static constexpr uint32_t sha256StringSize = 64;

	public:
		enum class outputType
		{
			binary,
			hexadecimal
		};

	private:
		static std::string hexConversion(const std::string& binaryString);

		static void mainLoop(std::string_view nextBlock, std::vector<uint32_t>& currentValues);

	private:
		static constexpr uint32_t h0 = 0x6a09e667;
		static constexpr uint32_t h1 = 0xbb67ae85;
		static constexpr uint32_t h2 = 0x3c6ef372;
		static constexpr uint32_t h3 = 0xa54ff53a;
		static constexpr uint32_t h4 = 0x510e527f;
		static constexpr uint32_t h5 = 0x9b05688c;
		static constexpr uint32_t h6 = 0x1f83d9ab;
		static constexpr uint32_t h7 = 0x5be0cd19;
		static constexpr std::array<uint32_t, 64> k =
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

	private:
		std::string data;
		outputType type;
		std::vector<uint32_t> currentValues;
		uint64_t currentSize;

	public:
		/// <summary>
		/// Encode data with SHA256 algorithm
		/// </summary>
		/// <returns>SHA256 encoded string</returns>
		static std::string getHash(const std::string& data, outputType type = outputType::hexadecimal);

	public:
		SHA256(outputType type = outputType::hexadecimal);

		SHA256(const std::string& data, outputType type = outputType::hexadecimal);

		SHA256(const SHA256& other);

		SHA256(SHA256&& other) noexcept;

		SHA256& operator = (const SHA256& other);

		SHA256& operator = (SHA256&& other) noexcept;

		/// <summary>
		/// Update current hash with data
		/// </summary>
		/// <param name="data">is for updating current hash</param>
		void update(const std::string& data);

		/// <summary>
		/// Update current hash with data
		/// </summary>
		/// <param name="data">is for updating current hash</param>
		void update(std::string_view data);

		/// <summary>
		/// Get current calculated hash
		/// </summary>
		/// <returns>SHA256 hash</returns>
		/// <exception cref="std::runtime_error">wrong outputType value</exception>
		std::string getHash();

		/// <summary>
		/// Setter for type
		/// </summary>
		/// <param name="type">new type</param>
		void setOutputType(outputType type);

		/// <summary>
		/// Getter for type
		/// </summary>
		/// <returns>current type</returns>
		outputType getOutputType() const;

		/// <summary>
		/// Set all members to default state
		/// </summary>
		/// <param name="type">outputType enum class value</param>
		void clear(outputType type = outputType::hexadecimal) noexcept;

		/// <summary>
		/// <para>Set to output stream SHA256 encoded data</para>
		/// <para>Modify current instance</para>
		/// </summary>
		/// <param name="stream">std::ostream subclass</param>
		/// <param name="sha">instance of SHA256</param>
		/// <returns>stream</returns>
		/// <exception cref="std::runtime_error">wrong outputType value</exception>
		friend SHA256_API std::ostream& operator << (std::ostream& stream, SHA256& sha);

		~SHA256() = default;
	};

	/// <summary>
	/// <para>_sha256 literals</para>
	/// <para>Shortcut access to SHA256 hash</para>
	/// </summary>
	inline namespace literals
	{
		/// <summary>
		/// SHA256 hash for C type string
		/// </summary>
		/// <param name="data">C type string</param>
		/// <param name="size">size in bytes of data</param>
		/// <returns>SHA256 hash</returns>
		SHA256_API std::string operator ""_sha256(const char* data, size_t size);

		/// <summary>
		/// SHA256 hash for unsigned integers
		/// </summary>
		/// <param name="data">unsigned integer</param>
		/// <returns>SHA256 hash</returns>
		SHA256_API std::string operator ""_sha256(unsigned long long int data);

		/// <summary>
		/// SHA256 hash for doubles
		/// </summary>
		/// <param name="data">double</param>
		/// <returns>SHA256 hash</returns>
		SHA256_API std::string operator ""_sha256(long double data);

		/// <summary>
		/// SHA256 hash for single chars
		/// </summary>
		/// <param name="data">single char</param>
		/// <returns>SHA256 hash</returns>
		SHA256_API std::string operator ""_sha256(char data);
	}
}

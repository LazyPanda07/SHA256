#include <string>
#include <sstream>
#include <unordered_map>

#include "gtest/gtest.h"

#include "SHA256.h"

std::unordered_map<std::string, std::string> hashes =
{
	{ "qwe", "489CD5DBC708C7E541DE4D7CD91CE6D0F1613573B7FC5B40D3942CCB9555CF35" },
	{ "some string here", "962AFC13263E6B264969A5F7D006A11029745EB4138D354FD8E81F0926CFE62A" },
	{ "test string", "D5579C46DFCC7F18207013E65B44E4CB4E2C2298F4AC457BA8F82743F31E930B" },
	{ "check hash", "1725681422832D04C8424C43665A7F1E67C7B770CB1EC1984BB12FAB6AA65051" },
	{ "very long string with many different characters!", "4333DDC7B044E14AE479151C2A4917174090304CA58FFC5A3D4C74B6C78A9BF1" }
};

TEST(SHA256, GenerateHash)
{
	for (const auto& [key, value] : hashes)
	{
		encoding::SHA256 sha(key);

		ASSERT_EQ(sha.getHash(), value);
	}
}

TEST(SHA256, Output)
{
	encoding::SHA256 sha(hashes.begin()->first);
	
	for (size_t i = 0; i < 10; i++)
	{
		std::ostringstream os;

		os << sha;

		ASSERT_EQ(sha.getHash(), os.str());
	}
}

TEST(SHA256, Literals)
{
	using namespace encoding::literals;

	ASSERT_EQ("qwe"_sha256, encoding::SHA256("qwe").getHash());

	ASSERT_EQ(5_sha256, encoding::SHA256(std::to_string(5)).getHash());

	ASSERT_EQ(5.32_sha256, encoding::SHA256(std::to_string(5.32)).getHash());

	ASSERT_EQ('c'_sha256, encoding::SHA256(std::string() += 'c').getHash());
}

int main(int argc, char** argv)
{
	testing::InitGoogleTest(&argc, argv);

	return RUN_ALL_TESTS();
}

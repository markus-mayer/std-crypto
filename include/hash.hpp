/*
The MIT License (MIT)

Copyright (c) 2014 Markus Mayer

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * This files contains various implementations of hash functions.
 * 
 * In this file a hash function is defied as (http://en.wikipedia.org/wiki/Hash_function):
 * A hash function is any algorithm that maps data of arbitrary length to data 
 * of a fixed length.
 * 
 * A hash function must be deterministic: when it is invoked twice on identical 
 * data (e.g. two strings containing exactly the same characters), the function must produce the same value.
 */
#include<array>
#include<iterator>
#include<algorithm>
#include<gcrypt.h>

namespace std
{

namespace detail
{

template<std::size_t VALUE_TYPE_BYTE_COUNT, int ALGO_ID>
class hash_function
{
public:
	typedef std::array<unsigned char, VALUE_TYPE_BYTE_COUNT> value_type;
	
	hash_function()
	{
		gcry_md_open(&_hd, ALGO_ID, 0);
	}

	hash_function(const hash_function& other)
	{
		gcry_md_copy(&_hd, other._hd);
	}

	hash_function& operator=(const hash_function& other)
	{
		gcry_md_close(_hd);
		gcry_md_copy(&_hd, other._hd);
		return *this;
	}	

	~hash_function()
	{
		gcry_md_close(_hd);
	}

	hash_function& process_bytes(const void* buffer, std::size_t byte_count)
	{
		gcry_md_write(_hd, buffer, byte_count);
		return *this;
	}

	template<class IterType>
	hash_function& process_bytes(IterType bytes_begin, IterType bytes_end)
	{
		static_assert(sizeof(typename std::iterator_traits<IterType>::value_type) == 1, "only char iterators allowed!");
		for (; bytes_begin != bytes_end; bytes_begin++ )
		{
			unsigned char byte = static_cast<unsigned char>(*bytes_begin);
			gcry_md_putc(_hd, byte);
		}
		return *this;
	}

	hash_function& operator()(const void* buffer, std::size_t byte_count)
	{
		return process_bytes(buffer, byte_count);
	}

	template<class IterType>
	hash_function& operator()(IterType bytes_begin, IterType bytes_end)
	{
		return process_bytes(bytes_begin, bytes_end);
	}

	void reset()
	{
		gcry_md_reset(_hd);
	}
	
	value_type hash_value() const
	{

		gcry_md_hd_t tmp_handle;
		gcry_md_copy(&tmp_handle, _hd);
		unsigned char* result_begin = gcry_md_read(tmp_handle, ALGO_ID);
		value_type result;
		std::copy_n(result_begin, VALUE_TYPE_BYTE_COUNT, result.begin());
		gcry_md_close(tmp_handle);
		return result;
	}
	
private:
	gcry_md_hd_t _hd;
};

template<std::size_t BYTE_COUNT>
struct sha_helper;

template<>
struct sha_helper<224>
{
	typedef hash_function<28, GCRY_MD_SHA224> hash_t;
};

template<>
struct sha_helper<256>
{
	typedef hash_function<32, GCRY_MD_SHA256> hash_t;
};

template<>
struct sha_helper<384>
{
	typedef hash_function<48, GCRY_MD_SHA384> hash_t;
};

template<>
struct sha_helper<512>
{
	typedef hash_function<64, GCRY_MD_SHA512> hash_t;
};

}

template<std::size_t BYTE_COUNT>
using sha2 = typename detail::sha_helper<BYTE_COUNT>::hash_t;

typedef detail::hash_function<16, GCRY_MD_MD4> md4;
typedef detail::hash_function<16, GCRY_MD_MD5> md5;
typedef detail::hash_function<20, GCRY_MD_SHA1> sha1;
typedef detail::hash_function<28, GCRY_MD_SHA224> sha224;
typedef detail::hash_function<32, GCRY_MD_SHA256> sha256;
typedef detail::hash_function<48, GCRY_MD_SHA384> sha384;
typedef detail::hash_function<64, GCRY_MD_SHA512> sha512;
typedef detail::hash_function<20, GCRY_MD_RMD160> ripemd160;


}

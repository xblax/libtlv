
#include <cstdio>
#include <cstdarg>
#include <stack>
#include <functional>
#include <tlv.hpp>


std::vector<unsigned char> unhexify( const std::string &str )
{
	static unsigned char nibble[] = {
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,10,0,0,0,0,0,0,
		0,11,12,13,14,15,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,11,12,13,14,15,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	std::vector<unsigned char> ret( ( str.size() + 1 ) / 2, 0 );
	if ( !str.empty() )
	{
		bool flip_flap = str.size() % 2;
		int offset = flip_flap;
		for( size_t i = 0; i < str.size(); i++ )
		{
			unsigned char ch = nibble[static_cast<uint8_t>( str[i] )];
			if ( !ch )
			{
				ret.clear();
				break;
			}
			ch--;
			flip_flap = !flip_flap;
			ret[( i + offset ) / 2] |= ch << ( flip_flap * 4 );
		}
	}
	return ret;
}

std::string hexify( const std::vector<unsigned char> &data, bool lower_case )
{
	static char nibble_lc[] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};
	static char nibble_uc[] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
	};
	char *nibble = lower_case ? nibble_lc : nibble_uc;
	std::string ret;
	ret.resize( data.size() * 2 );
	int i = 0;
	for( const auto &b : data )
	{
		ret[i++] = nibble[b >> 4];
		ret[i++] = nibble[b & 0x0F];
	}
	return ret;
}

static uint32_t msb( uint32_t value )
{
	return value >> ( 8 * ( sizeof(value) - __builtin_clz( value ) / 8 - 1 ) );
}

/*
 * TlvTag
 */

Tlv::Tag Tlv::Tag::build( Tlv::Tag::Class cls, bool constructed, uint32_t tag )
{
	// See X.690 BER tar encoding
	static const unsigned char next_byte = 0x80;
	static const unsigned char first_byte_bits = 0x1F;
	static const unsigned char paytload_bits = 0x7F;
	static const unsigned char constructed_tag = 0x20;
	static const unsigned char primitive_tag = 0x00;
	Tlv::Tag ret; // invalid tag
	if( tag <= max_tag_number ) // must fit in 4 bytes
	{
		if ( tag < 31 )
		{
			// Short form
			ret.value = (uint32_t)cls | ( constructed ? constructed_tag : primitive_tag ) | tag;
		} else {
			// Long form
			// First byte
			ret.value = (uint32_t)cls | ( constructed ? constructed_tag : primitive_tag ) | first_byte_bits;
			// Next bytes
			size_t effective_bits = sizeof( tag ) * 8 - __builtin_clz( tag );
			for( int i = ( effective_bits / 7 ) + ( ( effective_bits % 7 ) ? 1 : 0 ); i > 0; i-- )
			{
				ret.value <<= 8;
				ret.value |= next_byte | ( ( tag >> ( 7 * ( i - 1 ) ) ) & paytload_bits );
			}
			ret.value ^= next_byte; // Unset last byte "next byte" indicator
		}
	}
	return ret;
}

Tlv::Tag Tlv::Tag::build( UniversalTagType type, bool constructed )
{
	return build( Class::Universal, constructed, (uint32_t)type );
}

Tlv::Tag::Tag() :
		value( empty_tag_value )
{}

Tlv::Tag::Tag( uint32_t value ) :
		value( value )
{}

Tlv::Tag::Tag( const Tag &rhs )
{
	value = rhs.value;
}

Tlv::Tag::Tag( const Tag &&rhs )
{
	value = rhs.value;
}

Tlv::Tag& Tlv::Tag::operator=( const Tag &rhs )
{
	value = rhs.value;
	return *this;
}

Tlv::Tag& Tlv::Tag::operator=( const Tag &&rhs )
{
	value = rhs.value;
	return *this;
}

bool Tlv::Tag::operator==( const Tag &rhs )
{
	return value == rhs.value;
}

Tlv::Tag::operator bool() const
{
	return value == 0;
}

bool Tlv::Tag::empty() const
{
	return value == empty_tag_value;
}

size_t Tlv::Tag::size() const
{
	if ( value == empty_tag_value )
	{
		return 0;
	}
	else
	{
		return 4 - __builtin_clz( value ) / 8;
	}
}

Tlv::Tag::Class Tlv::Tag::tag_class() const
{
	return (Class)( msb( value ) & 0xC0 );
}

bool Tlv::Tag::constructed() const
{
	return msb( value ) & 0x20;
}

uint32_t Tlv::Tag::tag_number() const
{
	int i = ( sizeof(value) - __builtin_clz( value ) / 8 );
	uint32_t tag = ( i > 1 ) ? 0 : ( value & 0x1F );
	for( i--; i > 0; i-- )
	{
		tag <<= 7;
		tag |= ( 0x7F & ( value >> ( ( i - 1 ) * 8 ) ) );
	}
	return tag;
}

/*
 * Tlv::Data
 */
struct Tlv::Data
{
	Tag tag;
	Data* parent;
	// Leaf
	Value value;
	// Branch
	std::list<std::shared_ptr<Data>> children;

	Data() :
		parent( nullptr )
	{}

	Data( const Data &rhs ) = delete;
	Data operator=( const Data &rhs ) = delete;

	~Data()
	{
		// make sure that parent ptr of children is unset, when parent is destroyed
		for( auto& child : children )
		{
			child->parent = nullptr;
		}
	}
	bool operator==( const Data &rhs ) const
	{
		return tag == rhs.tag && parent == rhs.parent && value == rhs.value && children == rhs.children;
	}
	bool operator!=( const Data &rhs ) const
	{
		return !operator==( rhs );
	}
	operator bool() const
	{
		return !tag.empty();
	}
};

/*
 * Error
 */
Tlv::Status::Status() :
	code_( Code::None )
{}

Tlv::Status::Status( const Code code ) :
	code_( code )
{}

Tlv::Status::Status( Code code, const char *fmt, ... ) :
	code_( code )
{
	va_list vl, vl2;
	va_start( vl, fmt );
	va_copy( vl2, vl );
	unsigned len = vsnprintf( nullptr, 0, fmt, vl ) + 1;
	va_end( vl );
	if ( len > 0 )
	{
		description_.resize( len );
		vsnprintf( (char*)description_.c_str(), len, fmt, vl2 );
	}
	va_end( vl2 );
}

Tlv::Status::operator bool() const
{
	return code_ == Code::None;
}

Tlv::Status::Code Tlv::Status::code() const
{
	return code_;
}

const std::string& Tlv::Status::description() const
{
	return description_;
}

bool Tlv::Status::empty() const
{
	return code_ == Code::None;
}

void Tlv::Status::clear()
{
	code_ = Code::None;
	description_.clear();
}

std::string Tlv::Status::to_string() const
{
	if ( empty() )
	{
		return "OK";
	}
	return std::to_string( code_ ) + ':' + description_;

}

/*
 * Parser
 */

class Tlv::Parser
{
	enum State
	{
		Start = 0,
		TagStart,
		Tag,
		LenStart,
		Len,
		Data,
		End
	};
	static constexpr const unsigned char multi_octet_tag_mask_ = 0x1F;
	static constexpr const unsigned char more_octet_mask_ = 0x80;
	unsigned const char * const data_;
	size_t size_;
	std::list<Tlv::Tag> &path_;
	size_t offset_;
	size_t pos_;

	Parser( const unsigned char *data, const size_t size, std::list<Tlv::Tag> &path, size_t &offset ) :
		data_( data ),
		size_( size ),
		path_( path ),
		offset_( offset ),
		pos_( 0u )
	{}

	size_t offset() const
	{
		return offset_ + pos_;
	}

	std::string path() const
	{
		char buf[11]; // max unsigned characters
		std::string ret;
		for( const auto &i : path_ )
		{
			if ( !ret.empty() )
			{
				ret += "/";
			}
			snprintf( buf, sizeof( buf ), "%u", i.value );
			ret += buf;
		}
		return ret;
	}

	inline bool next_byte( unsigned char &buf )
	{
		if ( size_ <= pos_ )
		{
			return false;
		}
		buf = data_[pos_];
		pos_++;
		return true;
	}

	std::shared_ptr<Tlv::Data> next( Tlv::Status &s )
	{
		auto ret = std::make_shared<Tlv::Data>();
		size_t tag_len = 1;
		size_t size = 0;
		size_t size_len = 0;
		Tlv::Value data;
		State state = Start;
		unsigned char b = 0;

		while( state != End )
		{
			bool has_byte = next_byte( b );
			if ( !has_byte && state != Start )
			{
				s = Tlv::Status( Tlv::Status::UnexpectedEnd, "Unexpected end at [%s] offset %lu", path().c_str(), offset() );
				return nullptr;
			}
			if ( state == Start )
			{
				if ( has_byte && b == 0x00 )
				{
					continue;
				}
				state = TagStart;
			}
			switch( state )
			{
			case TagStart:
				if ( !has_byte )
				{
					return nullptr;
				}
				ret->tag = b;
				state = ( ( b & multi_octet_tag_mask_ ) == multi_octet_tag_mask_ ) ? Tag : LenStart;
				break;
			case Tag:
				if ( tag_len >= 4 )
				{
					s = Tlv::Status( Tlv::Status::BadTag, "Tag is too long at [%s] offset %lu", path().c_str(), offset() );
					return nullptr;
				}
				tag_len += 1;
				ret->tag = ( ret->tag.value << 8 ) | b;
				state = ( ( b & more_octet_mask_ ) == more_octet_mask_ ) ? Tag : LenStart;
				break;
			case LenStart:
				if ( ( b & more_octet_mask_ ) == more_octet_mask_ )
				{
					size_len = ( b ^ more_octet_mask_ );
					if ( size_len > 4 )
					{
						s = Tlv::Status( Tlv::Status::BadLength, "Tag length is too large at [%s] offset %lu", path().c_str(), offset() );
						return nullptr;
					}
					state = Len;
				} else {
					size = b;
					if ( size > 0 )
					{
						ret->value.resize( size );
						state = Data;
						size_len = 0;
					} else {
						state = End;
					}
				}
				break;
			case Len:
				size = ( size << 8 ) | b;
				size_len--;
				if ( size_len == 0 )
				{
					if ( size > 0 )
					{
						ret->value.resize( size );
						state = Data;
						size_len = 0;
					} else {
						state = End;
					}
				}
				break;
			case Data:
				ret->value[size_len] = b;
				size_len++;
				if ( size_len >= size )
				{
					state = End;
				}
				break;
			default:
				break;
			}
		}
		return ret;
	}

public:
	static std::shared_ptr<Tlv::Data> get_one( const unsigned char *data, const size_t size,
			std::list<Tlv::Tag> &path, size_t &offset, Tlv::Status &s )
	{
		Parser p( data, size, path, offset );
		auto t = p.next( s );
		if ( s.empty() )
		{
			offset = p.offset();
		}

		offset = p.offset();
		return t;
	}

	static std::list<std::shared_ptr<Tlv::Data>> get_all( const unsigned char *data, const size_t size,
			std::list<Tlv::Tag> &path, size_t &offset, Tlv::Status &s )
	{
		std::list<std::shared_ptr<Tlv::Data>> items;
		Parser p( data, size, path, offset );
		while( s.empty() )
		{
			auto t = p.next( s );
			if ( !t )
			{
				break;
			}
			items.push_back( t );
		}

		if ( s.empty() )
		{
			offset = p.offset();
		} else {
			items.clear();
		}
		return items;
	}
};

/**
 * Tlv
 */

Tlv::Tlv() :
	data_( std::make_shared<Data>() )
{}

Tlv::Tlv( const Tag tag ) :
	Tlv()
{
	data_->tag = tag;
}

Tlv::Tlv( const Tag tag, const Value &data ) :
	Tlv( tag )
{
	data_->value = data;
}

Tlv::Tlv( const Tag tag, const Value &&data ) :
	Tlv( tag )
{
	data_->value = std::move( data );
}

Tlv::Tlv( const Tag tag, const unsigned char *data, size_t size ) :
	Tlv( tag )
{
	data_->value = Value( data, data + size );
}

Tlv::Tlv( const Tag tag, const char *s ) :
	Tlv( tag, std::string( s ) )
{}

Tlv::Tlv( const Tag tag, const std::string &s ) :
	Tlv( tag )
{
	data_->value = Value( s.data(), s.data() + s.size() );
}

template<typename T>
void build_int_value( Tlv::Value &buf, T value )
{
	if ( value == 0 )
	{
		buf.push_back( 0x00 );
	} else {
		for( int i = sizeof( T ) - 1; i >= 0; i-- )
		{
			unsigned char b = ( value >> ( i * 8 ) ) & 0xFF;
			if ( b == 0 )
			{
				continue;
			}
			buf.push_back( b );
		}
	}
}

Tlv::Tlv( const Tag tag, bool b ) :
	Tlv( tag )
{
	data_->value.push_back( (unsigned char)b );
}

Tlv::Tlv( const Tag tag, int8_t i ) :
	Tlv( tag )
{
	data_->value.push_back( i );
}

Tlv::Tlv( const Tag tag, int16_t i ) :
	Tlv( tag )
{
	build_int_value<int16_t>( data_->value, i );
}

Tlv::Tlv( const Tag tag, int32_t i ) :
	Tlv( tag )
{
	build_int_value<int32_t>( data_->value, i );
}

Tlv::Tlv( const Tag tag, int64_t i ) :
	Tlv( tag )
{
	build_int_value<int64_t>( data_->value, i );
}

Tlv::Tlv( const Tag tag, uint8_t i ) :
	Tlv( tag )
{
	data_->value.push_back( i );
}

Tlv::Tlv( const Tag tag, uint16_t i ) :
	Tlv( tag )
{
	build_int_value<int16_t>( data_->value, i );
}

Tlv::Tlv( const Tag tag, uint32_t i ) :
	Tlv( tag )
{
	build_int_value<int32_t>( data_->value, i );
}

Tlv::Tlv( const Tag tag, uint64_t i ) :
	Tlv( tag )
{
	build_int_value<int64_t>( data_->value, i );
}

Tlv::Tlv( const Tag tag, const Tlv &child ) :
	Tlv( tag )
{
	push_back( child );
}

Tlv::Tlv( const Tlv &rhs ) :
	data_( rhs.data_ )
{}

Tlv::Tlv( Tlv &&rhs ) :
	data_( std::move(rhs.data_) )
{}

Tlv::Tlv( const std::shared_ptr<Data> &data ) :
	data_( data )
{}

Tlv::Tlv( std::shared_ptr<Data> &&data ) :
	data_( std::move(data) )
{}

Tlv::~Tlv()
{}

Tlv& Tlv::operator=( const Tlv &rhs )
{
	data_ = rhs.data_;
	return *this;
}

Tlv& Tlv::operator=( Tlv &&rhs )
{
	data_ = std::move( rhs.data_ );
	return *this;
}

bool Tlv::operator==( const Tlv &rhs ) const
{
	return *data_ == *rhs.data_;
}

bool Tlv::operator!=( const Tlv &rhs ) const
{
	return *data_ != *rhs.data_;
}

bool Tlv::identical(const Tlv& other) const
{
	return data_ == other.data_;
}

Tlv::operator bool() const
{
	return data_ && data_->operator bool();
}

Tlv Tlv::parse( const unsigned char *data, const size_t size, Status &s, size_t *len, unsigned depth )
{
	Tlv tlv;
	s = tlv.parse( data, size, len, depth );
	return tlv;
}

std::list<Tlv> Tlv::parse_all( const unsigned char *data, const size_t size, Status &s, size_t *len, unsigned depth )
{
	std::list<Tlv> ret;
	if ( depth == 0 )
	{
		// Depth must be >= 1
		s = Status( Status::BadArgument, "Invalid argument" );
	} else {
		// Get list of tags on current level (without going deeper)
		std::list<Tlv::Tag> path;
		size_t offset = 0;
		auto items = Parser::get_all( data, size, path, offset, s );
		if ( s.empty() )
		{
			if ( depth > 1 )
			{
				// Go deeper up to specified depth
				std::stack<std::shared_ptr<Tlv::Data>> backlog;
				for( auto &i : items )
				{
					if ( i->tag.constructed() && i->value.size() > 2 )
					{
						backlog.push( i );
					}
				}
				backlog.push( nullptr );
				while( !backlog.empty() )
				{
					// Get stack top
					auto top = backlog.top();
					backlog.pop();
					if ( !top )
					{
						depth--;
						continue;
					}
					// Try to get all subitems
					size_t sub_offset = 0;
					Status sub_status;
					auto subitems = Parser::get_all( top->value.data(), top->value.size(), path, sub_offset, sub_status );
					if ( !sub_status.empty() || subitems.empty() )
					{
						continue;
					}
					// Set children
					top->value.clear();
					for( auto &si : subitems )
					{
						top->children.push_back( si );
						si->parent = top.get();
						if ( depth > 1 && si->tag.constructed() && si->value.size() > 2 )
						{
							backlog.push( si );
						}
					}
					backlog.push( nullptr );
				}
			}
			// Build parsed root objects
			for( auto &i : items )
			{
				ret.push_back( std::move( Tlv( i ) ) );
			}
			// Pass parsed length to the caller
			if ( len )
			{
				*len = offset;
			}
		}
	}
	return ret;
}

Tlv::Status Tlv::parse( const unsigned char *data, const size_t size, size_t *len, unsigned depth )
{
	Status s;
	if ( depth == 0 )
	{
		// Depth must be >= 1
		s = Status( Status::BadArgument, "Invalid argument" );
	} else {
		// Get list of tags on current level (without going deeper)
		std::list<Tlv::Tag> path;
		size_t offset = 0;
		data_ = Parser::get_one( data, size, path, offset, s );
		if ( s.empty() )
		{
			if ( depth > 1 )
			{
				// Go deeper up to specified depth
				std::stack<std::shared_ptr<Tlv::Data>> backlog;
				if ( data_->tag.constructed() && data_->value.size() > 2 )
				{
					backlog.push( data_ );
				}
				backlog.push( nullptr );
				while( !backlog.empty() )
				{
					// Get stack top
					auto top = backlog.top();
					backlog.pop();
					if ( !top )
					{
						depth--;
						continue;
					}
					// Try to get all subitems
					size_t sub_offset = 0;
					Status sub_status;
					auto subitems = Parser::get_all( top->value.data(), top->value.size(), path, sub_offset, sub_status );
					if ( !sub_status.empty() || subitems.empty() )
					{
						continue;
					}
					// Set children
					top->value.clear();
					for( auto &si : subitems )
					{
						top->children.push_back( si );
						si->parent = top.get();
						if ( depth > 1 && si->tag.constructed() && si->value.size() > 2 )
						{
							backlog.push( si );
						}
					}
					backlog.push( nullptr );
				}
			}
			// Pass parsed length to the caller
			if ( len )
			{
				*len = offset;
			}
		}
	}
	return s;
}

std::vector<unsigned char> Tlv::dump() const
{
	// Sort elements in build order
	std::list<std::pair<unsigned, std::shared_ptr<Data>>> build_items;
	{
		std::stack<std::pair<unsigned, std::shared_ptr<Data>>> items;
		items.push( std::make_pair( 0, data_ ) );
		while( !items.empty() )
		{
			const auto i = items.top();
			items.pop();
			if ( !i.second )
			{
				continue;
			}
			if ( i.second->children.empty() )
			{
				build_items.push_back( std::make_pair( i.first, i.second ) );
			} else {
				build_items.push_back( std::make_pair( i.first, i.second ) );
				for( auto it = i.second->children.rbegin(); it != i.second->children.rend(); ++it )
				{
					items.push( std::make_pair( i.first + 1, *it ) );
				}
			}
		}
	}
	static auto build_tag = []( std::vector<unsigned char> &out, Data &element, std::vector<unsigned char> *data = nullptr ) {
		if( !element.tag.empty() )
		{
			// Build tag
			for( int i = ( sizeof( element.tag.value ) - __builtin_clz( element.tag.value ) / 8 ) - 1; i >= 0; i-- )
			{
				out.push_back( ( element.tag.value >> ( i * 8 ) ) & 0xFF );
			}
			// Build length
			size_t len = element.value.size();
			if ( data )
			{
				len = data->size();
			}
			if ( len <= 127 )
			{
				// Definite short form
				out.push_back( len & 0x7F );
			} else {
				// Definite long form
				int len_bytes = 4 - __builtin_clz( len ) / 8;
				out.push_back( (unsigned char)( 0x80 | len_bytes ) );
				for( int i = len_bytes - 1; i >= 0; i-- )
				{
					out.push_back( ( len >> ( i * 8 ) ) & 0xFF );
				}
			}
		}
		// Append data
		if ( data )
		{
			out.insert( out.end(), data->begin(), data->end() );
		} else {
			out.insert( out.end(), element.value.begin(), element.value.end() );
		}
	};
	std::stack<std::pair<std::shared_ptr<Data>, std::vector<unsigned char>>> build_stack;
	auto it = build_items.begin();
	build_stack.push( std::make_pair( it->second, std::vector<unsigned char>() ) );
	for( ++it; it != build_items.end(); ++it )
	{
		while( it->first < build_stack.size() )
		{
			auto top = build_stack.top();
			build_stack.pop();
			build_tag( build_stack.top().second, *top.first, &top.second );
		}

		if ( it->second->children.empty() )
		{
			build_tag( build_stack.top().second, *it->second );
		}
		else
		{
			build_stack.push( std::make_pair( it->second, std::vector<unsigned char>() ) );
		}
	}
	while( build_stack.size() > 1 )
	{
		auto top = build_stack.top();
		build_stack.pop();
		build_tag( build_stack.top().second, *top.first, &top.second );
	}
	std::vector<unsigned char> ret;
	if ( build_stack.top().first->value.empty() )
	{
		build_tag( ret, *build_stack.top().first, &build_stack.top().second );
	} else {
		build_tag( ret, *build_stack.top().first, &build_stack.top().first->value );
	}
	return ret;
}

std::vector<unsigned char> Tlv::dump( const std::list<Tlv> &tags )
{
	std::vector<unsigned char> ret;
	for( const auto &t : tags )
	{
		const auto branch = t.dump();
		ret.insert( ret.end(), branch.begin(), branch.end() );
	}
	return ret;
}

// Capacity

bool Tlv::empty() const
{
	return !data_ || !data_->operator bool();
}

bool Tlv::has_tag() const
{
	return data_->operator bool();
}

bool Tlv::has_value() const
{
	return !data_->value.empty();
}

size_t Tlv::value_size() const
{
	return data_->value.size();
}

bool Tlv::has_parent() const
{
	return data_->parent != nullptr;
}

bool Tlv::has_children() const
{
	return !data_->children.empty();
}

size_t Tlv::count() const
{
	return data_->children.size();
}

// Element access

Tlv::Tag Tlv::tag() const
{
	return data_->tag;
}

const Tlv::Value& Tlv::value() const
{
	return data_->value;
}

Tlv::Value& Tlv::value()
{
	return data_->value;
}

std::string Tlv::string() const
{
	return std::string( (const char*)data_->value.data(), data_->value.size() );
}

bool Tlv::boolean() const
{
	return (bool)data_->value.front();
}

int8_t Tlv::int8() const
{
	return (int8_t)data_->value.front();
}

int16_t Tlv::int16() const
{
	return (int16_t)uint64();
}

int32_t Tlv::int32() const
{
	return (int32_t)uint64();
}

int64_t Tlv::int64() const
{
	return uint64();
}

uint8_t Tlv::uint8() const
{
	return data_->value.front();
}

uint16_t Tlv::uint16() const
{
	return (uint16_t)uint64();
}

uint32_t Tlv::uint32() const
{
	return (uint32_t)uint64();
}

uint64_t Tlv::uint64() const
{
	uint64_t ret = 0;
	int n = ( data_->value.size() > 7 ) ? 8 : data_->value.size();
	for( int i = 0; i < n; i++ )
	{
		ret <<= 8;
		ret |= data_->value.at( i );
	}
	return ret;
}

std::list<Tlv> Tlv::children() const
{
	std::list<Tlv> ret;
	for( const auto &c : data_->children )
	{
		ret.push_back( Tlv( c ) );
	}
	return ret;
}

Tlv Tlv::front() const
{
	return ( data_ && !data_->children.empty() ) ? Tlv( data_->children.front() ) : Tlv();
}

Tlv Tlv::back() const
{
	return ( data_ && !data_->children.empty() ) ? Tlv( data_->children.back() ) : Tlv();
}

Tlv& Tlv::value( const Value &v )
{
	data_->value = v;
	data_->children.clear();
	return *this;
}

Tlv& Tlv::operator=( const Value &v )
{
	data_->value = v;
	data_->children.clear();
	return *this;
}

Tlv& Tlv::operator=( const Value &&v )
{
	data_->value = std::move( v );
	data_->children.clear();
	return *this;
}

bool Tlv::dfs( std::function<bool(Tlv&)> cb ) const
{
	if ( !cb )
	{
		return false;
	}
	std::stack<std::pair<bool, std::shared_ptr<Data>>> backlog;
	backlog.push( std::make_pair( false, data_ ) );
	while( !backlog.empty() )
	{
		auto &top = backlog.top();
		if ( !top.first )
		{
			if ( !top.second->children.empty() )
			{
				for( auto it = top.second->children.rbegin(); it != top.second->children.rend(); ++it )
				{
					backlog.push( std::make_pair( false, *it ) );
				}
			}
			top.first = true;
		} else {
			Tlv node( top.second );
			backlog.pop();
			if ( !cb( node ) )
			{
				return false;
			}
		}
	}
	return true;
}

bool Tlv::dfs( const std::list<Tlv> &tree, std::function<bool(Tlv&)> cb )
{
	for( const auto &t : tree )
	{
		if ( !t.dfs( cb ) )
		{
			return false;
		}
	}
	return true;
}

bool Tlv::bfs( std::function<bool(Tlv&)> cb ) const
{
	if ( !cb )
	{
		return false;
	}
	std::list<std::shared_ptr<Data>> backlog;
	if ( data_->children.empty() )
	{
		Tlv node( data_ );
		return cb( node );
	}
	for( auto &c : data_->children )
	{
		backlog.push_back( c );
	}
	Tlv node( data_ );
	if ( !cb( node ) )
	{
		return false;
	}
	while( !backlog.empty() )
	{
		auto front = backlog.front();
		Tlv node( front );
		backlog.pop_front();
		if ( !cb( node ) )
		{
			return false;
		}
		for( auto &c : front->children )
		{
			backlog.push_back( c );
		}
	}
	return true;
}

bool Tlv::bfs( const std::list<Tlv> &tree, std::function<bool(Tlv&)> cb )
{
	if ( !cb )
	{
		return false;
	}
	std::list<std::shared_ptr<Data>> backlog;
	for( auto &t : tree )
	{
		Tlv node( t.data_ );
		if ( !cb( node ) )
		{
			return false;
		}
		for( auto &c : t.data_->children )
		{
			backlog.push_back( c );
		}
	}
	while( !backlog.empty() )
	{
		auto front = backlog.front();
		Tlv node( front );
		backlog.pop_front();
		if ( !cb( node ) )
		{
			return false;
		}
		for( auto &c : front->children )
		{
			backlog.push_back( c );
		}
	}
	return true;
}

// Modifiers

Tlv& Tlv::parent( const Tlv &p )
{
	data_->parent = p.data_.get();
	if ( data_->parent )
	{
		data_->parent->value.clear();
		bool found = false;
		for( auto it = data_->parent->children.begin(); it != data_->parent->children.end(); ++it )
		{
			if ( it->get() == data_.get() )
			{
				found = true;
				break;
			}
		}
		if ( !found )
		{
			data_->parent->children.push_back( data_ );
		}
	}
	return *this;
}

Tlv& Tlv::push_front( const Tlv &node )
{
	data_->value.clear();
	data_->children.push_front( node.data_ );
	node.data_->parent = data_.get();
	return *this;
}

Tlv& Tlv::push_back( const Tlv &node )
{
	data_->value.clear();
	data_->children.push_back( node.data_ );
	node.data_->parent = data_.get();
	return *this;
}

Tlv& Tlv::pop_front()
{
	if ( !data_->children.empty() )
	{
		data_->children.pop_front();
	}
	return *this;
}

Tlv& Tlv::pop_back()
{
	if ( !data_->children.empty() )
	{
		data_->children.pop_back();
	}
	return *this;
}

Tlv& Tlv::detach()
{
	if ( data_->parent )
	{
		for( auto it = data_->parent->children.begin(); it != data_->parent->children.end(); ++it )
		{
			if ( it->get() == data_.get() )
			{
				data_->parent->children.erase( it );
				break;
			}
		}
	}
	data_->parent = nullptr;
	return *this;
}

Tlv& Tlv::erase( const Tag tag )
{
	for( auto it = data_->children.begin(); it != data_->children.end(); ++it )
	{
		if ( (*it)->tag == tag )
		{
			it = (*it)->children.erase( it );
		}
	}
	return *this;
}

void Tlv::swap( Tlv &rhs )
{
	std::shared_ptr<Data> tmp = data_;
	data_ = rhs.data_;
	rhs.data_ = tmp;
}

void Tlv::clear()
{
	data_ = std::make_shared<Data>();
}

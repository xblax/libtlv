
#include <cstdio>
#include <cstdarg>
#include <stack>
#include <functional>
#include <algorithm>
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
	return empty() || msb( value ) & 0x20;
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
	ChildContainer children;

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
			child.data_->parent = nullptr;
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
	static constexpr const uint8_t multi_octet_tag_mask_ = 0x1F;
	static constexpr const uint8_t more_octet_mask_ = 0x80;

	const uint8_t* _pos;
	const uint8_t* _end;

	inline bool next_byte( uint8_t &byte )
	{
		if ( _pos < _end )
		{
			byte = *_pos;
			_pos++;
			return true;
		} else {
			return false;
		}
	}

	void skip_zero_bytes()
	{
		while( _pos < _end && *_pos == 0 ) _pos++;
	}

public:

	struct ShallowNode  // for detected nodes during parser run
	{
		Tlv::Tag tag;
		const uint8_t* begin;
		const uint8_t* end;

		ShallowNode() :
			tag(),
			begin( nullptr ),
			end( nullptr )
		{}
	};

	Parser( const uint8_t* begin, const uint8_t* end ) :
		_pos( begin ),
		_end( end )
	{}

	bool has_next_tag()
	{
		skip_zero_bytes();
		return _pos < _end;
	}

	const uint8_t* get_pos()
	{
		return _pos;
	}

	Tlv::Status next( ShallowNode &node )
	{
		uint32_t tag = 0;
		uint32_t length = 0;
		uint8_t  byte;

		/* Step 1: Read Tag */

		// Read tag first byte
		if( !next_byte( byte ) )
			return Tlv::Status( Tlv::Status::BadArgument, "Unexpected error: no next tag available in current data segment" );

		tag = byte;

		// Read tag other bytes
		if( ( byte & multi_octet_tag_mask_ ) == multi_octet_tag_mask_ )
		{
			bool hasNext = true;
			for(size_t i = 1; i < sizeof(uint32_t) && hasNext; i++ )
			{
				if( !next_byte(byte) )
					return Tlv::Status( Tlv::Status::UnexpectedEnd, "Unexpected end of input while reading tag %X..", tag );

				tag = ( tag << 8 ) + byte;
				hasNext = (byte & more_octet_mask_);
			}

			if( hasNext )
			{
				return Tlv::Status( Tlv::Status::BadLength, "Tag too long while reading tag %X..", tag );
			}
		}

		node.tag = tag;

		/* Step 2: Read Length */

		// Read tag length first byte
		if( !next_byte( byte ) )
			return Tlv::Status( Tlv::Status::UnexpectedEnd, "Unexpected end of input while reading length of tag %X", tag );

		// Reag tag length other bytes
		if( byte & more_octet_mask_ )
		{
			size_t num_bytes = byte ^ more_octet_mask_;
			if( num_bytes > sizeof( length ) )
				return Tlv::Status( Tlv::Status::BadLength, "Tag length of tag %X too large.", tag );

			for(size_t i = 0; i < num_bytes; i++ )
			{
				if( !next_byte( byte ) )
					return Tlv::Status( Tlv::Status::UnexpectedEnd, "Unexpected end of input while reading length of tag %X", tag );

				length = ( length << 8 ) + byte;
			}
		}
		else
		{
			length = byte;
		}

		// Verify data bounds, advance parser _pos
		node.begin = _pos;
		const uint8_t* valueEnd = _pos + length;

		if( valueEnd > _end )
		{
			node.end = _end;
			_pos = _end;
			return Tlv::Status( Tlv::Status::UnexpectedEnd , "Unexpected end of input while reading data of tag %X", tag );
		} else {
			node.end = valueEnd;
			_pos = valueEnd;
			return Tlv::Status(); // Status ok
		}
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

Tlv Tlv::parse_all( const unsigned char *data, const size_t size, Status &s, size_t *len, unsigned depth )
{
	Tlv root;
	s = root.parse_all( data, size, len, depth );
	return root;
}

Tlv::Status Tlv::parse( const unsigned char *data, const size_t size, size_t *len, unsigned depth )
{
	clear();
	Status s = _parse_one( *this, data, data + size, depth );

	// TODO provide actual len?
	if( s && len )
	{
		*len = size;
	}

	return s;
}

Tlv::Status Tlv::parse_all(const unsigned char* data, const size_t size, size_t* len, unsigned depth)
{
	clear();
	Status s = _parse( *this, data, data + size, depth );

	// TODO provide actual len?
	if( s && len )
	{
		*len = size;
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
					items.push( std::make_pair( i.first + 1, it->data_ ) );
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

size_t Tlv::num_children() const
{
	return data_->children.size();
}

Tlv::ChildIterator Tlv::begin()
{
	return data_->children.begin();
}

Tlv::ChildIterator Tlv::end()
{
	return data_->children.begin();
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

const Tlv::ChildContainer& Tlv::children() const
{
	return data_->children;
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

	std::vector<Tlv> stack;
	stack.reserve( 4 );	 // start with a reasonable default size
	stack.push_back( *this );

	while( !stack.empty() )
	{
		Tlv currentNode( std::move( stack.back() ) );
		stack.pop_back();

		// visit node
		if( !cb( currentNode ) )
		{
			return false;
		}

		// add children of current node to stack - first child must be on top of stack
		stack.insert( stack.end(), currentNode.data_->children.rbegin(), currentNode.data_->children.rend() );
	}

	return true;
}

bool Tlv::bfs( std::function<bool(Tlv&)> cb ) const
{
	if ( !cb )
	{
		return false;
	}

	std::deque<Tlv> queue;
	queue.push_back( *this );

	while( !queue.empty() )
	{
		Tlv currentNode( std::move( queue.front() ) );
		queue.pop_front();

		// visit node
		if( !cb( currentNode ) )
		{
			return false;
		}

		// add children of current node to queue
		queue.insert( queue.end(), currentNode.data_->children.begin(), currentNode.data_->children.end() );
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
			if ( it->data_.get() == data_.get() )
			{
				found = true;
				break;
			}
		}
		if ( !found )
		{
			data_->parent->children.push_back( *this );
		}
	}
	return *this;
}

Tlv& Tlv::push_front( const Tlv &node )
{
	data_->value.clear();
	data_->children.insert( data_->children.begin(), node );
	node.data_->parent = data_.get();
	return *this;
}

Tlv& Tlv::push_back( const Tlv &node )
{
	data_->value.clear();
	data_->children.push_back( node );
	node.data_->parent = data_.get();
	return *this;
}

Tlv& Tlv::pop_front()
{
	if ( !data_->children.empty() )
	{
		data_->children.erase( data_->children.begin() );
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
			if ( it->data_.get() == data_.get() )
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
		if ( it->data_->tag == tag )
		{
			it = it->data_->children.erase( it );
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

template< typename T >
inline void Tlv::_dfs_unsafe( T callback ) const
{
	std::vector<const Tlv*> stack;
	stack.reserve( 4 );				// start with a reasonable default size
	stack.push_back( this );

	while( !stack.empty() )
	{
		const Tlv* currentNode = stack.back();
		stack.pop_back();

		auto ret = callback( *currentNode );

		switch( ret )
		{
			case Break: return;		// stop here
			case Prune: continue;   // continue, but skip subtree of current node
			case Continue: ;		// continue traversal
		}

		// add children of current node to stack - first child must be on top of stack
		auto &children = currentNode->data_->children;
		for( int r = children.size() - 1; r >= 0; r-- )
		{
			stack.push_back(&children[r]);
		}
	}
}

const Tlv::Status Tlv::_parse(Tlv& root, const uint8_t* begin, const uint8_t* end, int maxDepth)
{
	if( maxDepth <= 0 )
	{
		return Status( Status::BadArgument, "Minimum parse depth is 1" );
	}

	struct BacklogNode			// for incomplete nodes in backlog
	{
		Data* data;
		const uint8_t* begin;
		const uint8_t* end;
		int depth;
	};

	Status status;
	std::vector<BacklogNode> backlogStack;
	backlogStack.reserve(4); // start with reasonable default size
	std::vector<Parser::ShallowNode> nodeCache;
	nodeCache.reserve(4);    // start with a reasonable default size

	backlogStack.push_back( BacklogNode{ root.data_.get(), begin, end, 0 } );

	while( !backlogStack.empty() )
	{
		BacklogNode curNode = backlogStack.back();
		backlogStack.pop_back();
		int curChildDepth = curNode.depth + 1;

		Parser parser(curNode.begin, curNode.end);
		nodeCache.clear();

		while( parser.has_next_tag() )
		{
			nodeCache.emplace_back();
			status = parser.next( nodeCache.back() );

			if( !status )
			{
				return status;
			}
		}

		curNode.data->children.reserve( nodeCache.size() );
		for( auto &cacheNode : nodeCache )
		{
			curNode.data->children.push_back( Tlv() );
			Data* childDataPtr = curNode.data->children.back().data_.get();
			childDataPtr->tag = cacheNode.tag;
			childDataPtr->parent = curNode.data;

			// Constructed nodes must be revisted for parsing of child nodes, unless max depth was reached
			if ( cacheNode.tag.constructed() && curChildDepth < maxDepth )
			{
				backlogStack.push_back( BacklogNode{childDataPtr, cacheNode.begin, cacheNode.end, curChildDepth} );
			}
			// Otherwise assign data
			else
			{
				childDataPtr->value.assign(cacheNode.begin, cacheNode.end);
			}
		}

		// Abort on parse errors
		if( !status )
		{
			break;
		}
	}

	return status;
}

const Tlv::Status Tlv::_parse_one(Tlv& root, const uint8_t* begin, const uint8_t* end, int maxDepth)
{
	if( maxDepth <= 0 )
	{
		return Status( Status::BadArgument, "Minimum parse depth is 1" );
	}

	Status s;
	Parser parser(begin, end);
	if( parser.has_next_tag() )
	{
		Parser::ShallowNode shallowNode;
		s = parser.next( shallowNode );

		if( s )
		{
			root.data_->tag = shallowNode.tag;
			// Do we neet to continue parsing children?
			if( root.tag().constructed() && maxDepth -1 > 0 )
			{
				s = _parse( root, shallowNode.begin, shallowNode.end, maxDepth -1 );
			}
			else
			{
				root.data_->value.assign( shallowNode.begin, shallowNode.end );
			}

		}
	}

	return s;
}

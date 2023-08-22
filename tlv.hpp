
#include <cstdint>
#include <string>
#include <vector>
#include <list>
#include <memory>
#include <functional>
#include <limits>
#include <iterator>

std::vector<unsigned char> unhexify( const std::string &str );
std::string hexify( const std::vector<unsigned char> &data, bool lower_case = false );


class Tlv
{
public:
	class Status
	{
	public:

		enum Code
		{
			OK,
			UnexpectedEnd,
			BadTag,
			BadLength,
			BadArgument
		};

		Status()  :
			code_( Code::OK ),
			length_( 0 )
		{}

		Status( const Status& ) = default;
		Status( Status&& ) = default;
		Status& operator=( const Status& ) = default;
		Status& operator=( Status&& ) = default;

		bool ok() const { return code_ == Code::OK; }
		operator bool() const { return ok(); }
		Code code() const { return code_; }
		const std::string& message() { return message_; }

		void reset()
		{
			code_ = Code::OK;
			length_ = 0;
			message_.clear();
		}

		/**
		 * Length of the parsed data. On errors, length indicates the position at which the parser stopped.
		 */
		size_t parsed_len() { return length_; }

	private:
		friend class Tlv;

		Status( const Code, const size_t length );
		Status( const Code, const size_t length, const char*, ... )
			__attribute__((format (printf, 4, 5)));

		void set_parsed_len( size_t length ){ length_ = length; }

		Code code_;
		size_t length_;
		std::string message_;
	};

	class Tag
	{
	public:
		enum Class
		{
			Universal = 0x00,
			Application = 0x40,
			ContextSpecific = 0x80,
			Private = 0xC0
		};
		enum UniversalTagType
		{
			EndOfContent = 0,
			Boolean,
			Integer,
			BitString,
			OctetString,
			Null,
			ObjectIdentifier,
			ObjectDescriptor,
			External,
			Real,
			Enumerated,
			EmbeddedPdv,
			Utf8String,
			RelativeOid,
			Time,
			Reserved,
			Sequence,
			Set,
			NumericString,
			PrintableString,
			T61String,
			VideotexString,
			IA5String,
			UtcTime,
			GeneralizedTime,
			GraphicString,
			VisibleString,
			GeneralString,
			UniversalString,
			CharacterString,
			BmpString,
			Date,
			TimeOfDay,
			DateTime,
			Duration,
			OidIri,
			RelativeOidIri
		};

		// max tag number fitting into 4 byte constructed tag
		static const uint32_t max_tag_number = 0x1FFFFF;
		// empty tag value (0xFF is invalid because it indicates another byte follows)
		static const uint32_t empty_tag_value = 0;

		static Tlv::Tag build( Class cls, bool constructed, uint32_t tag_number );
		static Tlv::Tag build( UniversalTagType type, bool constructed );

		Tag() : _value( empty_tag_value ) {}
		Tag( uint32_t value ) : _value ( value ) {}
		Tag( const Tag& ) = default;

		Tag& operator=( const Tag& ) = default;
		bool operator==( const Tag& other ) const { return _value == other._value; }

		/**
		 * The tag is empty if no tag was set.
		 */
		bool empty() const { return _value == empty_tag_value; }

		/**
		 * True if tag was set (i.e., tag is not empty)
		 */
		operator bool() const { return _value != empty_tag_value; }

		/**
		 * Number of bytes required to encode the tag.
		 */
		size_t size() const;

		/**
		 * True if the constructed flag of the tag is set.
		 */
		bool constructed() const;

		/**
		 * Returns the tag class of the tag.
		 */
		Class tag_class() const;

		/**
		 * Returns the tag number of the tag.
		 */
		uint32_t tag_number() const;

		/**
		 * Returns the value of the tag.
		 */
		uint32_t value() const { return _value; }

	private:
		friend class Tlv;
		uint32_t _value;
	};

	typedef std::vector<uint8_t> Value;
	typedef std::vector<Tlv> ChildContainer;
	typedef std::vector<Tlv>::iterator ChildIterator;

	explicit Tlv();
	explicit Tlv( const Tag );
	explicit Tlv( const Tag, const Value& );
	explicit Tlv( const Tag, const Value&& );
	explicit Tlv( const Tag, const unsigned char*, const size_t );
	explicit Tlv( const Tag, const char* );
	explicit Tlv( const Tag, const std::string& );
	explicit Tlv( const Tag, bool );
	explicit Tlv( const Tag, int8_t );
	explicit Tlv( const Tag, int16_t );
	explicit Tlv( const Tag, int32_t );
	explicit Tlv( const Tag, int64_t );
	explicit Tlv( const Tag, uint8_t );
	explicit Tlv( const Tag, uint16_t );
	explicit Tlv( const Tag, uint32_t );
	explicit Tlv( const Tag, uint64_t );
	explicit Tlv( const Tag, const Tlv& );
	Tlv( const Tlv& );
	Tlv( Tlv&& );
	~Tlv();

	Tlv& operator=( const Tlv& );
	Tlv& operator=( Tlv&& );
	bool operator==( const Tlv& ) const;
	bool operator!=( const Tlv& ) const;

	/**
	 * Parse raw data into TLV
	 * @param[in] data  - input buffer
	 * @param[in] size  - input size
	 * @param[out] s    - operation status
	 * @param[out] len  - parsed data length
	 * @param[in] depth - parse sub-items recursively up to specified depth
	 * @return Parsed TLV tree
	 */
	static Tlv parse( const unsigned char *data, const size_t size, Status &s, unsigned depth = 1 );

	/**
	 * Parse raw data into set of TLV nodes (if tags come one after another)
	 * @param[in] data  - input buffer
	 * @param[in] size  - input size
	 * @param[out] s    - operation status
	 * @param[out] len  - parsed data length
	 * @param[in] depth - parse sub-items recursively up to specified depth
	 * @return Parsed TLV tree
	 */
	static Tlv parse_all( const unsigned char *data, const size_t size, Status &s, unsigned depth = 1 );

	/**
	 * Parse raw data into current TLV object
	 * @param[in] data  - input buffer
	 * @param[in] size  - input size
	 * @param[out] len  - parsed data length
	 * @param[in] depth - parse sub-items recursively up to specified depth
	 * @return operation status
	 */
	Status parse( const unsigned char *data, const size_t size, unsigned depth = 1 );

	/**
	 * Parse raw data into set of TLV nodes (if tags come one after another)
	 * @param[in] data  - input buffer
	 * @param[in] size  - input size
	 * @param[out] len  - parsed data length
	 * @param[in] depth - parse sub-items recursively up to specified depth
	 * @return opreation status
	 */
	Status parse_all( const unsigned char *data, const size_t size, unsigned depth = 1 );

	/**
	 * Build tree into byte sequence
	 */
	std::vector<unsigned char> dump() const;

	/***********
	 * Capacity
	 ***********/

	/**
	 * A node is considered empty if has no tag, no value and no children.
	 */
	bool empty() const;

	/**
	 * True if Tlv node is not empty.
	 */
	operator bool() const;

	/**
	 * Is tag set
	 */
	bool has_tag() const;

	/**
	 * Has value
	 */
	bool has_value() const;

	/**
	 * Data size in bytes
	 */
	size_t value_size() const;

	/**
	 * Has parent node
	 */
	bool has_parent() const;

	/**
	 * Has children nodes
	 */
	bool has_children() const;

	/**
	 * Number of direct child nodes
	 */
	size_t num_children() const;

	/**
	 * Size of tree including this node
	 */
	size_t tree_size() const;

	/****************
	 * Element access
	 ****************/

	/**
	 *  Begin iterator to child nodes
	 */
	ChildIterator begin();

	/**
	 * End iterator to child nodes
	 */
	ChildIterator end();

	/**
	 * First node
	 */
	Tlv front() const;

	/**
	 * Last node
	 */
	Tlv back() const;

	/**
	 * Node tag
	 */
	Tag tag() const;

	/**
	 * Children nodes
	 */
	const ChildContainer& children() const;

	/**
	 * Node value
	 */
	const Value& value() const;
	Value& value();

	/**
	 * Build string from node value
	 */
	std::string string() const;

	/**
	 * Value as boolean
	 */
	bool boolean() const;

	/**
	 * Value as signed integer
	 */
	int8_t int8() const;
	int16_t int16() const;
	int32_t int32() const;
	int64_t int64() const;

	/**
	 * Value as unsigned integer
	 */
	uint8_t uint8() const;
	uint16_t uint16() const;
	uint32_t uint32() const;
	uint64_t uint64() const;

	/**************
	 * Data setters
	 **************/
	void set_value( const Value& value );
	void set_value( Value&& value );
	void set_tag( const Tag& tag );

	/***********
	 * Traversal
	 ***********/

	enum TraversalAction
	{
		Continue,
		Prune,
		Break
	};

	/**
	 * Depth first search tree traversal.
	 * Callback must return one of defined TraversalActions.
	 */
	void dfs( std::function<TraversalAction(Tlv&)> ) const;

	/**
	 * Breadth first search tree traversal.
	 * Callback must return one of defined TraversalActions.
	 */
	void bfs( std::function<TraversalAction(Tlv&)> ) const;

	/***********
	 * Data Modifiers
	 ***********/

	/**
	 * Set parent
	 */
	void set_parent( const Tlv& parent );

	/**
	 * Add new item to the beginning of children list
	 */
	void push_front( const Tlv& child );

	/**
	 * Add new item to the end of children list
	 */
	void push_back( const Tlv& child );

	/**
	 * Remove first child node
	 */
	void pop_front();

	/**
	 * Remove last child node
	 */
	void pop_back();

	/**
	 * Detach node from parent
	 */
	void detach();

	/**
	 * Remove all child nodes with specified tag
	 */
	void erase( const Tag tag );

	/***********
	 * Tlv Pointer Management
	 ***********/

	/**
	 * Swap internally referenced tree nodes.
	 */
	void swap( Tlv& other );

	/**
	 * True if other Tlv object internally references the same tree node.
	 */
	bool identical( const Tlv &other ) const;

	/**
	 * Replace internally referenced node with empty node.
	 */
	void reset();

private:
	struct Data;
	std::shared_ptr<Data> data_;
	class Parser;

	explicit Tlv( const std::shared_ptr<Data> &data );
	explicit Tlv( std::shared_ptr<Data> &&data );

	template< typename T >
	inline void _dfs_unsafe( T callback ) const;

	static const Status _parse( Tlv& root, const uint8_t* begin, const uint8_t* end, const uint8_t* tree_begin, int maxDepth = std::numeric_limits<int>::max() );
	static const Status _parse_one( Tlv& root, const uint8_t* begin, const uint8_t* end, const uint8_t* tree_begin, int maxDepth = std::numeric_limits<int>::max() );
};

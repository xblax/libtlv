
#include <cstdint>
#include <string>
#include <vector>
#include <list>
#include <memory>
#include <functional>


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
			None = 0xFFFFFFFF,
			UnexpectedEnd = 1,
			BadTag,
			BadLength,
			BadArgument
		};

		Status();
		Status( const Code );
		Status( const Code, const char*, ... )
			__attribute__((format (printf, 3, 4)));

		Status& operator=( const Status& );
		operator bool() const;
		Code code() const;
		const std::string& description() const;
		bool empty() const;
		void clear();
		std::string to_string() const;

	protected:
		Code code_;
		std::string description_;
	};

	struct Tag
	{
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

		uint32_t value;

		static Tlv::Tag build( Class cls, bool constructed, uint32_t tag );
		static Tlv::Tag build( UniversalTagType type, bool constructed );
		Tag();
		Tag( uint32_t );
		Tag( const Tag& );
		Tag( const Tag&& );
		Tag& operator=( const Tag& );
		Tag& operator=( const Tag&& );
		bool operator==( const Tag& );
		operator bool() const;
		bool empty() const;
		size_t size() const;
		Class tag_class() const;
		bool constructed() const;
		uint32_t tag_number() const;
	};
	typedef std::vector<unsigned char> Value;

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
	operator bool() const;

	/**
	 * Parse raw data into TLV
	 * @param[in] data  - input buffer
	 * @param[in] size  - input size
	 * @param[out] s    - operation status
	 * @param[out] len  - parsed data length
	 * @param[in] depth - parse sub-items recursively up to specified depth
	 * @return Parsed TLV tree
	 */
	static Tlv parse( const unsigned char *data, const size_t size, Status &s,
			size_t *len = nullptr, unsigned depth = 1 );

	/**
	 * Parse raw data into TLV series (if tags come one after another)
	 * @param[in] data  - input buffer
	 * @param[in] size  - input size
	 * @param[out] s    - operation status
	 * @param[out] len  - parsed data length
	 * @param[in] depth - parse sub-items recursively up to specified depth
	 * @return Parsed TLV tree
	 */
	static std::list<Tlv> parse_all( const unsigned char *data, const size_t size, Status &s,
			size_t *len = nullptr, unsigned depth = 1 );

	/**
	 * Parse raw data into current TLV object
	 * @param[in] data  - input buffer
	 * @param[in] size  - input size
	 * @param[out] len  - parsed data length
	 * @param[in] depth - parse sub-items recursively up to specified depth
	 * @return operation status
	 */
	Status parse( const unsigned char *data, const size_t size, size_t *len = nullptr, unsigned depth = 1 );

	/**
	 * Build tree into byte sequence
	 */
	std::vector<unsigned char> dump() const;
	static std::vector<unsigned char> dump( const std::list<Tlv>& );

	/***********
	 * Capacity
	 ***********/

	/**
	 * Is node empty
	 */
	bool empty() const;

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
	size_t size() const;

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
	size_t count() const;

	/****************
	 * Element access
	 ****************/

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
	std::list<Tlv> children() const;

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
	Tlv& value( const Value& );
	Tlv& operator=( const Value& );
	Tlv& operator=( const Value&& );

	/***********
	 * Traversal
	 ***********/

	/**
	 * Depth first search tree traversal
	 * Callback shall return false to stop
	 */
	bool dfs( std::function<bool(Tlv&)> ) const;
	static bool dfs( const std::list<Tlv>&, std::function<bool(Tlv&)> );

	/**
	 * Breadth first search tree traversal
	 * Callback shall return false to stop
	 */
	bool bfs( std::function<bool(Tlv&)> ) const;
	static bool bfs( const std::list<Tlv>&, std::function<bool(Tlv&)> );

	/***********
	 * Modifiers
	 ***********/

	/**
	 * Set parent
	 */
	Tlv& parent( const Tlv& );

	/**
	 * Add new item to the beginning of children list
	 */
	Tlv& push_front( const Tlv& );

	/**
	 * Add new item to the end of children list
	 */
	Tlv& push_back( const Tlv& );

	/**
	 * Remove first child node
	 */
	Tlv& pop_front();

	/**
	 * Remove last child node
	 */
	Tlv& pop_back();

	/**
	 * Detach node from parent
	 */
	Tlv& detach();

	/**
	 * Remove all child nodes with specified tag
	 */
	Tlv& erase( const Tag );

	/**
	 * Exchange nodes
	 */
	void swap( Tlv& );

	/**
	 * Unset node tag and data
	 */
	void clear();

private:
	struct Data;
	std::shared_ptr<Data> data_;
	class Parser;

	explicit Tlv( const std::shared_ptr<Data> &data );
	explicit Tlv( std::shared_ptr<Data> &&data );
};

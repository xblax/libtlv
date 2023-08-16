
#include "tlv.hpp"
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>


int main( int argc, char** argv)
{
	return CommandLineTestRunner::RunAllTests( argc, argv );
}

TEST_GROUP(TlvMisc)
{};

TEST(TlvMisc, Unhexify)
{
	auto v = unhexify( "1234Ab" );
	CHECK( v.size() == 3 );
	CHECK_EQUAL( 0x12, v[0] );
	CHECK_EQUAL( 0x34, v[1] );
	CHECK_EQUAL( 0xAB, v[2] );

	v = unhexify( "1234A" );
	CHECK( v.size() == 3 );
	CHECK_EQUAL( 0x01, v[0] );
	CHECK_EQUAL( 0x23, v[1] );
	CHECK_EQUAL( 0x4A, v[2] );

	v = unhexify( "f" );
	CHECK( v.size() == 1 );
	CHECK_EQUAL( 0x0F, v[0] );

	v = unhexify( "0" );
	CHECK( v.size() == 1 );
	CHECK_EQUAL( 0x00, v[0] );

	v = unhexify( "0A\xff" );
	CHECK( v.empty() );

	v = unhexify( "" );
	CHECK( v.empty() );

	v = unhexify( "test" );
	CHECK( v.empty() );
}

TEST(TlvMisc, Hexify)
{
	auto s = hexify( { 0x01 } );
	CHECK_EQUAL( 2, s.size() );
	STRCMP_EQUAL( "01", s.c_str() );

	s = hexify( { 0x01, 0x23, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xa2, 0x97 } );
	CHECK_EQUAL( 18, s.size() );
	STRCMP_EQUAL( "0123FFEEDDCCBBA297", s.c_str() );

	s = hexify( { 0x01, 0x23, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xa2, 0x97 }, true );
	CHECK_EQUAL( 18, s.size() );
	STRCMP_EQUAL( "0123ffeeddccbba297", s.c_str() );
}

/*
 * TlvTag
 */

TEST_GROUP(TlvTag)
{};

TEST(TlvTag, TagClass)
{
	// 1 byte
	CHECK_EQUAL( (int)Tlv::Tag::Class::Universal, (int)Tlv::Tag( 0x05 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::Application, (int)Tlv::Tag( 0x45 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::ContextSpecific, (int)Tlv::Tag( 0x85 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::Private, (int)Tlv::Tag( 0xC5 ).tag_class() );

	// 2 bytes
	CHECK_EQUAL( (int)Tlv::Tag::Class::Universal, (int)Tlv::Tag( 0x1F81 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::Application, (int)Tlv::Tag( 0x5F81 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::ContextSpecific, (int)Tlv::Tag( 0x9F81 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::Private, (int)Tlv::Tag( 0xDF81 ).tag_class() );

	// 3 bytes
	CHECK_EQUAL( (int)Tlv::Tag::Class::Universal, (int)Tlv::Tag( 0x1F8001 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::Application, (int)Tlv::Tag( 0x5F8001 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::ContextSpecific, (int)Tlv::Tag( 0x9F8001 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::Private, (int)Tlv::Tag( 0xDF8001 ).tag_class() );

	// 4 bytes
	CHECK_EQUAL( (int)Tlv::Tag::Class::Universal, (int)Tlv::Tag( 0x1F800001 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::Application, (int)Tlv::Tag( 0x5F800001 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::ContextSpecific, (int)Tlv::Tag( 0x9F800001 ).tag_class() );
	CHECK_EQUAL( (int)Tlv::Tag::Class::Private, (int)Tlv::Tag( 0xDF800001 ).tag_class() );
}

TEST(TlvTag, TagConstructed)
{
	// 1 byte
	CHECK_EQUAL( false, (int)Tlv::Tag( 0x05 ).constructed() );
	CHECK_EQUAL( true, (int)Tlv::Tag( 0x65 ).constructed() );
	CHECK_EQUAL( false, (int)Tlv::Tag( 0x85 ).constructed() );
	CHECK_EQUAL( true, (int)Tlv::Tag( 0xE5 ).constructed() );

	// 2 bytes
	CHECK_EQUAL( false, (int)Tlv::Tag( 0x1F81 ).constructed() );
	CHECK_EQUAL( true, (int)Tlv::Tag( 0x7F81 ).constructed() );
	CHECK_EQUAL( false, (int)Tlv::Tag( 0x9F81 ).constructed() );
	CHECK_EQUAL( true, (int)Tlv::Tag( 0xFF81 ).constructed() );

	// 3 bytes
	CHECK_EQUAL( false, (int)Tlv::Tag( 0x1F8001 ).constructed() );
	CHECK_EQUAL( true, (int)Tlv::Tag( 0x7F8001 ).constructed() );
	CHECK_EQUAL( false, (int)Tlv::Tag( 0x9F8001 ).constructed() );
	CHECK_EQUAL( true, (int)Tlv::Tag( 0xFF8001 ).constructed() );

	// 4 bytes
	CHECK_EQUAL( true, (int)Tlv::Tag( 0x3F800001 ).constructed() );
	CHECK_EQUAL( false, (int)Tlv::Tag( 0x5F800001 ).constructed() );
	CHECK_EQUAL( true, (int)Tlv::Tag( 0xBF800001 ).constructed() );
	CHECK_EQUAL( false, (int)Tlv::Tag( 0xDF800001 ).constructed() );
}

TEST(TlvTag, TagNumber)
{
	// 1 byte
	CHECK_EQUAL( 5, Tlv::Tag( 0x05 ).tag_number() );
	CHECK_EQUAL( 5, Tlv::Tag( 0x65 ).tag_number() );
	CHECK_EQUAL( 5, Tlv::Tag( 0x85 ).tag_number() );
	CHECK_EQUAL( 5, Tlv::Tag( 0xC5 ).tag_number() );

	// 2 bytes
	CHECK_EQUAL( 65, Tlv::Tag( 0x1F41 ).tag_number() );
	CHECK_EQUAL( 65, Tlv::Tag( 0x7F41 ).tag_number() );
	CHECK_EQUAL( 65, Tlv::Tag( 0x9F41 ).tag_number() );
	CHECK_EQUAL( 65, Tlv::Tag( 0xFF41 ).tag_number() );

	// 3 bytes
	CHECK_EQUAL( 8193, Tlv::Tag( 0x1FC001 ).tag_number() );
	CHECK_EQUAL( 8193, Tlv::Tag( 0x7FC001 ).tag_number() );
	CHECK_EQUAL( 8193, Tlv::Tag( 0x9FC001 ).tag_number() );
	CHECK_EQUAL( 8193, Tlv::Tag( 0xFFC001 ).tag_number() );

	// 4 bytes
	CHECK_EQUAL( 1048577, Tlv::Tag( 0x3FC08001 ).tag_number() );
	CHECK_EQUAL( 1048577, Tlv::Tag( 0x5FC08001 ).tag_number() );
	CHECK_EQUAL( 1048577, Tlv::Tag( 0xBFC08001 ).tag_number() );
	CHECK_EQUAL( 1048577, Tlv::Tag( 0xDFC08001 ).tag_number() );
}

TEST(TlvTag, TagBuild)
{
	// 1 byte (short form)
	auto tag = Tlv::Tag::build( Tlv::Tag::Class::Application, false, 5 );
	CHECK_EQUAL( 0x45, tag.value );
	CHECK_EQUAL( 1, tag.size() );
	CHECK_FALSE( tag.empty() );
	tag = Tlv::Tag::build( Tlv::Tag::Class::ContextSpecific, true, 30 );
	CHECK_EQUAL( 0xBE, tag.value );
	CHECK_EQUAL( 1, tag.size() );

	// 2 bytes
	tag = Tlv::Tag::build( Tlv::Tag::Class::Application, false, 31 );
	CHECK_EQUAL( 0x5F1F, tag.value );
	CHECK_EQUAL( 2, tag.size() );
	tag = Tlv::Tag::build( Tlv::Tag::Class::Private, false, 65 );
	CHECK_EQUAL( 0xDF41, tag.value );
	CHECK_EQUAL( 2, tag.size() );

	// 3 bytes
	tag = Tlv::Tag::build( Tlv::Tag::Class::Application, false, 193 );
	CHECK_EQUAL( 0x5F8141, tag.value );
	CHECK_EQUAL( 3, tag.size() );
	tag = Tlv::Tag::build( Tlv::Tag::Class::Application, false, 8385 );
	CHECK_EQUAL( 0x5FC141, tag.value );
	CHECK_EQUAL( 3, tag.size() );

	// 4 bytes
	tag = Tlv::Tag::build( Tlv::Tag::Class::Application, false, 24769 );
	CHECK_EQUAL( 0x5F81C141, tag.value );
	CHECK_EQUAL( 4, tag.size() );
	tag = Tlv::Tag::build( Tlv::Tag::Class::Private, true, Tlv::Tag::max_tag_number );
	CHECK_EQUAL( 0xFFFFFF7F, tag.value );
	CHECK_EQUAL( 4, tag.size() );

	// Overflow
	tag = Tlv::Tag::build( Tlv::Tag::Class::Application, false, Tlv::Tag::max_tag_number + 1 );
	CHECK_EQUAL( Tlv::Tag::empty_tag_value, tag.value );
	CHECK_EQUAL( 0, tag.size() );
	CHECK( tag.empty() );
}

TEST(TlvTag, UniversalTagBuild)
{
	auto tag = Tlv::Tag::build( Tlv::Tag::UniversalTagType::EndOfContent, false );
	CHECK_EQUAL( 0, tag.value );
	CHECK_EQUAL( 0, tag.size() );
	CHECK( tag.empty() );

	tag = Tlv::Tag::build( Tlv::Tag::UniversalTagType::Boolean, false );
	CHECK_EQUAL( 0x01, tag.value );
	CHECK_EQUAL( 1, tag.size() );
	CHECK_FALSE( tag.empty() );
}

/*
 * TlvBuild
 */

TEST_GROUP(TlvBuild)
{};

TEST(TlvBuild, DefaultCtor)
{
	Tlv t;
	CHECK( t.empty() );
}

TEST(TlvBuild, NoValueCtor)
{
	Tlv t( 0x1F81 );
	CHECK_FALSE( t.empty() );
	CHECK( t.has_tag() );
	CHECK_FALSE( t.has_value() );
	CHECK_FALSE( t.has_children() );
}

TEST(TlvBuild, TagValueCtor)
{
	unsigned char *data = (unsigned char*)"test";
	Tlv t( 0x1F81, Tlv::Value( data, data + 5 ) );
	CHECK_FALSE( t.empty() );
	CHECK( t.has_tag() );
	CHECK_EQUAL( 0x1F81, t.tag().value );
	CHECK( t.has_value() );
	std::string s( t.value().begin(), t.value().end() );
	STRCMP_EQUAL( "test", s.c_str() );
	CHECK_FALSE( t.has_children() );
}

TEST(TlvBuild, TagBufCtor)
{
	Tlv t( 0x1F81, (const unsigned char*)"test", 5 );
	CHECK_FALSE( t.empty() );
	CHECK( t.has_tag() );
	CHECK_EQUAL( 0x1F81, t.tag().value );
	CHECK( t.has_value() );
	std::string s( t.value().begin(), t.value().end() );
	STRCMP_EQUAL( "test", s.c_str() );
	CHECK_FALSE( t.has_children() );
}

TEST(TlvBuild, BuildTree1)
{
	/*
	 * 9F8501
	 * 		92	123
	 * 		AA
	 * 			8A	test
	 * 		93	ABBCCDD
	 */
	Tlv root( 0x9F8501 );
	CHECK_EQUAL( 0x9F8501, root.tag().value );
	root.push_back( Tlv( 0x92, 0x123 ) );
	CHECK_EQUAL( 0x92, root.back().tag().value );
	root.push_back( Tlv( 0xAA ) );
	CHECK_EQUAL( 0xAA, root.back().tag().value );
	root.back().push_back( Tlv( 0x8A, (const unsigned char*)"test", 4 ) );
	CHECK_EQUAL( 0x8A, root.back().back().tag().value );
	root.push_back( Tlv( 0x93, 0xABBCCDD ) );
	CHECK_EQUAL( 0x93, root.back().tag().value );
	STRCMP_EQUAL( "9F85011292020123AA068A047465737493040ABBCCDD", hexify( root.dump() ).c_str() );
}

TEST(TlvBuild, BuildTree2)
{
	/*
	 * 9F8501
	 * 		92
	 * 			AA
	 * 				8A	test
	 */
	Tlv _8a( 0x8A, (const unsigned char*)"test", 4 );
	Tlv _aa( 0xAA, std::move( _8a ) );
	Tlv _92( 0x92, std::move( _aa ) );
	Tlv root( 0x9F8501, std::move( _92 ) );
	STRCMP_EQUAL( "9F85010A9208AA068A0474657374", hexify( root.dump() ).c_str() );
}

TEST(TlvBuild, BuildTree3)
{
	/*
	 * BF800001
	 * 		92	123
	 * 		93
	 * 		8A	test
	 */
	Tlv _92( 0x92, 0x123 );
	Tlv _8a( 0x8A, (const unsigned char*)"test", 4 );
	Tlv root( 0xBF800001 );
	root.push_back( _92 );
	root.push_back( Tlv( 0x93 ) );
	root.push_back( _8a );
	STRCMP_EQUAL( "BF8000010C9202012393008A0474657374", hexify( root.dump() ).c_str() );
}

TEST(TlvBuild, BuildTree4)
{
	/*
	 * 9F8501	test
	 */
	Tlv root( 0x9F8501, (const unsigned char*)"test", 4 );
	STRCMP_EQUAL( "9F85010474657374", hexify( root.dump() ).c_str() );
}

TEST(TlvBuild, BuildTreeList)
{
	/*
	 * 45	1
	 * 9F8501
	 * 		AA
	 * 			8A	test
	 * 		93	ABBCCDD
	 * 5F41 345
	 */
	Tlv tree;
	tree.push_back( Tlv( 0x45, 1 ) );
	tree.push_back( Tlv( 0x9F8501 ) );
	tree.back().push_back( Tlv( 0xAA ) );
	tree.back().back().push_back( Tlv( 0x8A, (const unsigned char*)"test", 4 ) );
	tree.back().push_back( Tlv( 0x93, 0xABBCCDD ) );
	tree.push_back( Tlv( 0x5F41, 0x345 ) );
	STRCMP_EQUAL( "4501019F85010EAA068A047465737493040ABBCCDD5F41020345", hexify( tree.dump() ).c_str() );
}

TEST(TlvBuild, Graft1)
{
	/*
	 * 45	1
	 * 9F8501
	 * 		AA
	 * 			8A	test
	 * 		93	ABBCCDD
	 * 5F41 345
	 */
	Tlv tree;
	{
		tree.push_back( Tlv( 0x45, 1 ) );
		tree.push_back( Tlv( 0x9F8501 ) );
		tree.back().push_back( Tlv( 0x93, 0xABBCCDD ) );

		Tlv branch( 0xAA );
		branch.push_back( Tlv( 0x8A, (const unsigned char*)"test", 4 ) );

		tree.back().push_front( branch );
		tree.push_back( Tlv( 0x5F41, 0x345 ) );
	}
	STRCMP_EQUAL( "4501019F85010EAA068A047465737493040ABBCCDD5F41020345", hexify( tree.dump() ).c_str() );

	// Check parent is set properly
	auto it = tree.begin();
	CHECK_FALSE( tree.has_parent() );	// root has no parent
	// 45
	CHECK_EQUAL( 0x45, it->tag().value );
	CHECK( it->has_parent() );			// parent is node without tag
	CHECK_FALSE( it->has_children() );
	CHECK_EQUAL( 1, it->value().at( 0 ) );
	// 9F8501
	it++;
	CHECK_EQUAL( 0x9F8501, it->tag().value );
	CHECK( it->has_parent() );			// parent is node without tag
	CHECK( it->has_children() );
	auto _9F8501 = it->children();
	auto _9F8501_it = _9F8501.begin();
	// AA
	CHECK_EQUAL( 0xAA, _9F8501_it->tag().value );
	CHECK( _9F8501_it->has_parent() );
	CHECK( _9F8501_it->has_children() );
	auto _AA = _9F8501_it->children();
	auto _AA_it = _AA.begin();
	// 8A
	CHECK_EQUAL( 0x8A, _AA_it->tag().value );
	CHECK( _AA_it->has_parent() );
	CHECK_FALSE( _AA_it->has_children() );
	STRCMP_EQUAL( "test", _AA_it->string().c_str() );
	// 93
	_9F8501_it++;
	CHECK_EQUAL( 0x93, _9F8501_it->tag().value );
	CHECK( _9F8501_it->has_parent() );
	CHECK_FALSE( _9F8501_it->has_children() );
	CHECK_EQUAL( 0x0A, _9F8501_it->value().at( 0 ) );
	// 5F41
	it++;
	CHECK_EQUAL( 0x5F41, it->tag().value );
	CHECK_TRUE( it->has_parent() );		// parent is node without tag
	CHECK_FALSE( it->has_children() );
}

TEST(TlvBuild, Graft2)
{
	/*
	 * 45	1
	 * 9F8501
	 * 		93	ABBCCDD
	 * 		AA
	 * 			8A	test
	 * 5F41 345
	 */
	Tlv tree;
	{
		tree.push_back( Tlv( 0x45, 1 ) );
		tree.push_back( Tlv( 0x9F8501 ) );
		tree.back().push_back( Tlv( 0x93, 0xABBCCDD ) );

		Tlv branch( 0xAA );
		branch.push_back( Tlv( 0x8A, (const unsigned char*)"test", 4 ) );

		tree.back().push_back( branch );
		tree.push_back( Tlv( 0x5F41, 0x345 ) );
	}
	STRCMP_EQUAL( "4501019F85010E93040ABBCCDDAA068A04746573745F41020345", hexify( tree.dump() ).c_str() );
}

TEST(TlvBuild, AsString)
{
	Tlv t( 0x8A, "test" );
	STRCMP_EQUAL( "8A0474657374", hexify( t.dump() ).c_str() );
	STRCMP_EQUAL( "test", t.string().c_str() );
}

TEST(TlvBuild, AsBool)
{
	Tlv t( 0x8A, true );
	STRCMP_EQUAL( "8A0101", hexify( t.dump() ).c_str() );
	CHECK_EQUAL( true, t.boolean() );
}

TEST(TlvBuild, AsInt8)
{
	int8_t i = 5;
	Tlv t( 0x8A, i );
	STRCMP_EQUAL( "8A0105", hexify( t.dump() ).c_str() );
	CHECK_EQUAL( 5, t.int8() );

	i = -5;
	Tlv t2( 0x8A, i );
	t.swap( t2 );
	STRCMP_EQUAL( "8A01FB", hexify( t.dump() ).c_str() );
	CHECK_EQUAL( -5, t.int8() );
}

TEST(TlvBuild, AsInt16)
{
	int16_t i = 0x555;
	Tlv t( 0x8A, i );
	STRCMP_EQUAL( "8A020555", hexify( t.dump() ).c_str() );
	CHECK_EQUAL( (int16_t)0x555, t.int16() );

	i = -1365;
	Tlv t2( 0x8A, i );
	t.swap( t2 );
	STRCMP_EQUAL( "8A02FAAB", hexify( t.dump() ).c_str() );
	CHECK_EQUAL( -1365, t.int16() );
}

TEST(TlvBuild, AsInt32)
{
	int32_t i = 0x5555555;
	Tlv t( 0x8A, i );
	STRCMP_EQUAL( "8A0405555555", hexify( t.dump() ).c_str() );
	CHECK_EQUAL( (int32_t)0x5555555, t.int32() );

	i = -89478485;
	Tlv t2( 0x8A, i );
	t.swap( t2 );
	STRCMP_EQUAL( "8A04FAAAAAAB", hexify( t.dump() ).c_str() );
	CHECK_EQUAL( -89478485, t.int32() );
}

TEST(TlvBuild, AsInt64)
{
	int64_t i = 0x555555555555555;
	Tlv t( 0x8A, i );
	STRCMP_EQUAL( "8A080555555555555555", hexify( t.dump() ).c_str() );
	CHECK_EQUAL( (int64_t)0x555555555555555, t.int64() );

	i = -384307168202282325;
	Tlv t2( 0x8A, i );
	t.swap( t2 );
	STRCMP_EQUAL( "8A08FAAAAAAAAAAAAAAB", hexify( t.dump() ).c_str() );
	CHECK_EQUAL( -384307168202282325, t.int64() );

	i = 0x123;
	t = Tlv( 0x8A, i );
	STRCMP_EQUAL( "8A020123", hexify( t.dump() ).c_str() );
	CHECK_EQUAL( 0x123, t.int16() );
	CHECK_EQUAL( 0x123, t.int32() );
	CHECK_EQUAL( 0x123, t.int64() );
}

TEST(TlvBuild, DuplicateTags)
{
	/*
	 * BF01
	 * 		8A	1
	 * 		8B	ABC
	 * 		8A	2
	 * 		8B	DEF
	 * 		30
	 * 			31	100
	 * 11	FF
	 */
	Tlv tree;
	{
		tree.push_back( Tlv( 0xBF01 ) );
		tree.back().push_back( Tlv( 0x8A, 1 ) );
		tree.back().push_back( Tlv( 0x8B, "ABC" ) );
		tree.back().push_back( Tlv( 0x8A, 2 ) );
		tree.back().push_back( Tlv( 0x8B, "DEF" ) );
		tree.back().push_back( Tlv( 0x30 ) );
		tree.back().back().push_back( Tlv( 0x31, 100 ) );
		tree.push_back( Tlv( 0x11, 0xFF ) );
	}
	STRCMP_EQUAL( "BF01158A01018B034142438A01028B0344454630033101641101FF", hexify( tree.dump() ).c_str() );
}

TEST(TlvBuild, TagWithTrailingZero)
{
	Tlv tlv( 0xDFA300, "app123" );
	STRCMP_EQUAL( "DFA30006617070313233", hexify( tlv.dump() ).c_str() );
}

TEST(TlvBuild, TraverseDfsFull)
{
	/*
	 * 81	1
	 * A2
	 * 		83	2
	 * 		A4
	 * 			85	3
	 * 		86	4
	 * A7
	 * 		88 5
	 */
	Tlv tree;
	{
		tree.push_back( Tlv( 0x81, 1 ) );
		tree.push_back( Tlv( 0xA2 ) );
		tree.back().push_back( Tlv( 0x83, 2 ) );
		tree.back().push_back( Tlv( 0xA4 ) );
		tree.back().back().push_back( Tlv( 0x85, 3 ) );
		tree.back().push_back( Tlv( 0x86, 4 ) );
		tree.push_back( Tlv( 0xA7 ) );
		tree.back().push_back( Tlv( 0x88, 5 ) );
	}
	CHECK_FALSE( tree.dfs( nullptr ) );
	int n = 0;
	// TODO: testcase is broken, this is not DFS ordering!
	bool ret = tree.dfs( [&n]( Tlv &node ) -> bool {
		switch( n )
		{
		case 0:
			CHECK_EQUAL( 0x81, node.tag().value );
			CHECK_EQUAL( 1, node.int32() );
			break;
		case 1:
			CHECK_EQUAL( 0x83, node.tag().value );
			CHECK_EQUAL( 2, node.int32() );
			break;
		case 2:
			CHECK_EQUAL( 0x85, node.tag().value );
			CHECK_EQUAL( 3, node.int32() );
			break;
		case 3:
			CHECK_EQUAL( 0xA4, node.tag().value );
			break;
		case 4:
			CHECK_EQUAL( 0x86, node.tag().value );
			CHECK_EQUAL( 4, node.int32() );
			break;
		case 5:
			CHECK_EQUAL( 0xA2, node.tag().value );
			break;
		case 6:
			CHECK_EQUAL( 0x88, node.tag().value );
			CHECK_EQUAL( 5, node.int32() );
			break;
		case 7:
			CHECK_EQUAL( 0xA7, node.tag().value );
			break;
		default:
			FAIL( "Unexpected call" );
		}
		n++;
		return true;
	} );
	CHECK_EQUAL( true, ret );
	CHECK_EQUAL( 8, n );
}

TEST(TlvBuild, TraverseDfsPartial)
{
	/*
	 * 81
	 * 		82	1
	 * 		83
	 * 			84	2
	 * 		85	3
	 */
	Tlv tree( 0x81 );
	{
		tree.push_back( Tlv( 0x82, 1 ) );
		tree.push_back( Tlv( 0x83 ) );
		tree.back().push_back( Tlv( 0x84, 2 ) );
		tree.push_back( Tlv( 0x85, 3 ) );
	}
	int n = 0;
	// TODO: testcase is broken, this is not DFS ordering!
	bool ret = tree.dfs( [&n]( Tlv &node ) -> bool {
		bool ret = true;
		switch( n )
		{
		case 0:
			CHECK_EQUAL( 0x82, node.tag().value );
			CHECK_EQUAL( 1, node.int32() );
			break;
		case 1:
			CHECK_EQUAL( 0x84, node.tag().value );
			CHECK_EQUAL( 2, node.int32() );
			ret = false;
			break;
		default:
			FAIL( "Unexpected call" );
		}
		n++;
		return ret;
	} );
	CHECK_EQUAL( false, ret );
	CHECK_EQUAL( 2, n );
}

TEST(TlvBuild, TraverseBfsFull)
{
	/*
	 * A2
	 * 		83	2
	 * 		A4
	 * 			85	3
	 * 		86	4
	 */
	Tlv tree( 0xA2 );
	{
		tree.push_back( Tlv( 0x83, 2 ) );
		tree.push_back( Tlv( 0xA4 ) );
		tree.back().push_back( Tlv( 0x85, 3 ) );
		tree.push_back( Tlv( 0x86, 4 ) );
	}
	CHECK_FALSE( tree.bfs( nullptr ) );
	int n = 0;
	bool ret = tree.bfs( [&n]( Tlv &node ) -> bool {
		switch( n )
		{
		case 0:
			CHECK_EQUAL( 0xA2, node.tag().value );
			break;
		case 1:
			CHECK_EQUAL( 0x83, node.tag().value );
			CHECK_EQUAL( 2, node.int32() );
			break;
		case 2:
			CHECK_EQUAL( 0xA4, node.tag().value );
			break;
		case 3:
			CHECK_EQUAL( 0x86, node.tag().value );
			CHECK_EQUAL( 4, node.int32() );
			break;
		case 4:
			CHECK_EQUAL( 0x85, node.tag().value );
			CHECK_EQUAL( 3, node.int32() );
			break;
		default:
			FAIL( "Unexpected call" );
		}
		n++;
		return true;
	} );
	CHECK_EQUAL( true, ret );
	CHECK_EQUAL( 5, n );
}

TEST(TlvBuild, TraverseBfsFullList)
{
	/*
	 * 81	1
	 * A2
	 * 		83	2
	 * 		A4
	 * 			85	3
	 * 		86	4
	 * A7
	 * 		88 5
	 */
	Tlv tree;
	{
		tree.push_back( Tlv( 0x81, 1 ) );
		tree.push_back( Tlv( 0xA2 ) );
		tree.back().push_back( Tlv( 0x83, 2 ) );
		tree.back().push_back( Tlv( 0xA4 ) );
		tree.back().back().push_back( Tlv( 0x85, 3 ) );
		tree.back().push_back( Tlv( 0x86, 4 ) );
		tree.push_back( Tlv( 0xA7 ) );
		tree.back().push_back( Tlv( 0x88, 5 ) );
	}
	CHECK_FALSE( tree.bfs( nullptr ) );
	int n = 0;
	bool ret = tree.bfs( [&n]( Tlv &node ) -> bool {
		switch( n )
		{
		case 0:
			CHECK( node.tag().empty() );	// "virtual" root with empty tag
			break;
		case 1:
			CHECK_EQUAL( 0x81, node.tag().value );
			CHECK_EQUAL( 1, node.int32() );
			break;
		case 2:
			CHECK_EQUAL( 0xA2, node.tag().value );
			break;
		case 3:
			CHECK_EQUAL( 0xA7, node.tag().value );
			break;
		case 4:
			CHECK_EQUAL( 0x83, node.tag().value );
			CHECK_EQUAL( 2, node.int32() );
			break;
		case 5:
			CHECK_EQUAL( 0xA4, node.tag().value );
			break;
		case 6:
			CHECK_EQUAL( 0x86, node.tag().value );
			CHECK_EQUAL( 4, node.int32() );
			break;
		case 7:
			CHECK_EQUAL( 0x88, node.tag().value );
			CHECK_EQUAL( 5, node.int32() );
			break;
		case 8:
			CHECK_EQUAL( 0x85, node.tag().value );
			CHECK_EQUAL( 3, node.int32() );
			break;
		default:
			FAIL( "Unexpected call" );
		}
		n++;
		return true;
	} );
	CHECK_EQUAL( true, ret );
	CHECK_EQUAL( 9, n );
}

TEST(TlvBuild, TraverseBfsPartial)
{
	/*
	 * 81	1
	 * A2
	 * 		83	2
	 * 		A4
	 * 			85	3
	 * 		86	4
	 * A7
	 * 		88 5
	 */
	Tlv tree;
	{
		tree.push_back( Tlv( 0x81, 1 ) );
		tree.push_back( Tlv( 0xA2 ) );
		tree.back().push_back( Tlv( 0x83, 2 ) );
		tree.back().push_back( Tlv( 0xA4 ) );
		tree.back().back().push_back( Tlv( 0x85, 3 ) );
		tree.back().push_back( Tlv( 0x86, 4 ) );
		tree.push_back( Tlv( 0xA7 ) );
		tree.back().push_back( Tlv( 0x88, 5 ) );
	}
	CHECK_FALSE( tree.bfs( nullptr ) );
	int n = 0;
	bool ret = tree.bfs( [&n]( Tlv &node ) -> bool {
		switch( n )
		{
		case 0:
			CHECK( node.tag().empty() );	// "virtual" root with empty tag
			break;
		case 1:
			CHECK_EQUAL( 0x81, node.tag().value );
			CHECK_EQUAL( 1, node.int32() );
			break;
		case 2:
			CHECK_EQUAL( 0xA2, node.tag().value );
			break;
		case 3:
			CHECK_EQUAL( 0xA7, node.tag().value );
			break;
		case 4:
			CHECK_EQUAL( 0x83, node.tag().value );
			CHECK_EQUAL( 2, node.int32() );
			break;
		case 5:
			CHECK_EQUAL( 0xA4, node.tag().value );
			return false;
		default:
			FAIL( "Unexpected call" );
		}
		n++;
		return true;
	} );
	CHECK_EQUAL( false, ret );
	CHECK_EQUAL( 5, n );
}

TEST(TlvBuild, SetParent)
{
	Tlv root( 0xAA, 10 );
	Tlv node( 0xA1, "test" );
	node.parent( root );
	STRCMP_EQUAL( "AA06A10474657374", hexify( root.dump() ).c_str() );
}

TEST(TlvBuild, TraverseDetach)
{
	Tlv root( 0xAA );
	root.push_back( Tlv( 0x88, 1 ) );
	root.push_back( Tlv( 0x89, 2 ) );

	root.front().detach();
	STRCMP_EQUAL( "AA03890102", hexify( root.dump() ).c_str() );
}

TEST( TlvBuild, LongLengthEncoding )
{
    std::vector<uint8_t> data( 0xFF /*size*/, 0xF );
    std::vector<uint8_t> data2( 0x101 /*size*/, 0xF );
    Tlv root( 0xFE, data );
    root.push_back( Tlv( 0xDE, data ) );
    root.push_back( Tlv( 0xDE, data2 ) );
    auto tlvData = root.dump();

    // FE 82 02 01   DE 81 FF 0F ... DE 82 01 01 0F ...
    CHECK_EQUAL( 0xFE, tlvData[0] );
    CHECK_EQUAL( 0x82, tlvData[1] );
    CHECK_EQUAL( 0x02, tlvData[2] );
    CHECK_EQUAL( 0x07, tlvData[3] ); // 0x200 + 3 + 4

    CHECK_EQUAL( 0xDE, tlvData[4] );
    CHECK_EQUAL( 0x81, tlvData[5] );
    CHECK_EQUAL( 0xFF, tlvData[6] );
    CHECK_EQUAL( 0x0F, tlvData[7] );

    CHECK_EQUAL( 0xDE, tlvData[262] );
    CHECK_EQUAL( 0x82, tlvData[263] );
    CHECK_EQUAL( 0x01, tlvData[264] );
    CHECK_EQUAL( 0x01, tlvData[265] );
    CHECK_EQUAL( 0x0F, tlvData[266] );
    CHECK_EQUAL( 0x20B, tlvData.size() );

    Tlv parsedData;
    auto status = parsedData.parse( tlvData.data(), tlvData.size(), nullptr, 2 );

    CHECK_TRUE( status );
    CHECK_TRUE( parsedData.has_tag() );
    CHECK_EQUAL( 0xFE, parsedData.tag().value );
    CHECK_TRUE( parsedData.tag().constructed() );
    CHECK_EQUAL( 2, parsedData.children().size() );
    CHECK_TRUE( parsedData.children().front().has_tag() );
    CHECK_TRUE(  parsedData.children().back().has_tag() );
    CHECK_EQUAL( 0xDE, parsedData.children().front().tag().value );
    CHECK_EQUAL( 0xDE, parsedData.children().back().tag().value );
    CHECK_FALSE( parsedData.children().front().tag().constructed() );
    CHECK_FALSE( parsedData.children().back().tag().constructed() );
    CHECK_TRUE( parsedData.children().front().value() == data );
    CHECK_TRUE( parsedData.children().back().value() == data2 );
}

TEST(TlvBuild, DeepBranches)
{
    /*
     * F1
     *    F2
     *       F3
     *          D4 01
     *    F2
     *       F3
     *          D4 01
     */
    Tlv root( 0xF1 );
    for( int i = 0; i < 2; i++ )
    {
        Tlv f2( 0xF2 );
        root.push_back( f2 );
        Tlv f3( 0xF3 );
        f2.push_back( f3 );
        Tlv d4( 0xD4, 1 );
        f3.push_back( d4 );
    }

    STRCMP_EQUAL( "F10EF205F303D40101F205F303D40101", hexify( root.dump() ).c_str() );
}

TEST(TlvBuild, ParentDestroyed)
{
	Tlv child( 0xD1, 1 );
	{
		Tlv root( 0xF1 );
		root.push_back( child );
		CHECK_TRUE( child.has_parent() );
	}
	// Root is destroyed when out of scope, since not referenced by any other node
	CHECK_FALSE( child.has_parent() );
}

TEST(TlvBuild, ChildNotDestroyed)
{
	Tlv root( 0xF1 );
	{
		Tlv child( 0xD1, 1 );
		root.push_back( child );
		CHECK_TRUE( child.has_parent() );
	}
	// Child is not destroyed when out of scope, since still referenced by root
	CHECK_TRUE( root.has_children() );
	CHECK_EQUAL( 0xD1, root.front().tag().value );
	CHECK_TRUE( root.front().has_parent() );
}

TEST(TlvBuild, EmptyTree)
{
	Tlv root;
	CHECK_TRUE( root.empty() );
	CHECK_EQUAL( 0, root.dump().size() );
}

TEST(TlvBuild, EmptyRoot)
{
	Tlv root; // has no tag
	root.push_back( Tlv( 0xD1, 0xFF ) );
	root.push_back( Tlv( 0xD2, 0xFF ) );
	CHECK_TRUE( root.tag().empty() );
	// TODO CHECK_FALSE( root.empty() ); - root should not be empty when having children
	CHECK_EQUAL( "D101FFD201FF", hexify( root.dump()) );
}

TEST(TlvBuild, CopyConstructor)
{
	Tlv node( 0xF1 );
	Tlv other( node );
	Tlv third( 0xF1 );

	// all three nodes are equal
	CHECK( node == other );
	CHECK( other == node );
	CHECK( node == third );
	CHECK( third == node );
	CHECK( other == third );
	CHECK( third == other );

	// node and other share identiy, other is unrelated
	CHECK( node.identical( other ));
	CHECK( other.identical( node ));
	CHECK_FALSE( node.identical( third ) );
	CHECK_FALSE( third.identical( node ) );
	CHECK_FALSE( other.identical( third ) );
	CHECK_FALSE( third.identical( other ) );

	node.push_back( Tlv( 0xD1, 0xFF ));
	other.push_back( Tlv( 0xD2, 0xFF ));

	// since node and other share identiy, all changes to node affect other and vice versa
	CHECK( node.has_children() );
	CHECK( other.has_children() );
	CHECK( node.back().identical( other.back() ));
	CHECK( node.front().identical( other.front() ));
	CHECK_EQUAL( node.children().size(), other.children().size() );

	// move other to new
	Tlv moved( std::move(other) );
	CHECK( node.identical( moved ) );
	CHECK_FALSE( node.identical( other ) );
	CHECK( node == moved );
}

TEST(TlvBuild, AssignmentOperator)
{
	Tlv node( 0xF1 );
	Tlv other = node;
	Tlv third( 0xF1 );

	// all three nodes are equal
	CHECK( node == other );
	CHECK( other == node );
	CHECK( node == third );
	CHECK( third == node );
	CHECK( other == third );
	CHECK( third == other );

	// node and other share identiy, other is unrelated
	CHECK( node.identical( other ));
	CHECK( other.identical( node ));
	CHECK_FALSE( node.identical( third ) );
	CHECK_FALSE( third.identical( node ) );
	CHECK_FALSE( other.identical( third ) );
	CHECK_FALSE( third.identical( other ) );

	node.push_back( Tlv( 0xD1, 0xFF ));
	other.push_back( Tlv( 0xD2, 0xFF ));

	// since node and other share identiy, all changes to node affect other and vice versa
	CHECK( node.has_children() );
	CHECK( other.has_children() );
	CHECK( node.back().identical( other.back() ));
	CHECK( node.front().identical( other.front() ));
	CHECK_EQUAL( node.children().size(), other.children().size() );

	// move assign other to thrid
	third = std::move(other);
	CHECK( node.identical( third ) );
	CHECK_FALSE( node.identical( other ) );
	CHECK( node == third );
}

/*
 * TlvParse
 */

TEST_GROUP(TlvParse)
{};

TEST(TlvParse, OneByteTag)
{
	auto v = unhexify( "100100" );
	Tlv::Status s;
	size_t len;
	auto t = Tlv::parse( v.data(), v.size(), s, &len );
	CHECK( s.empty() );
	CHECK_EQUAL( 3, len );
	CHECK_EQUAL( 0x10, t.tag().value );
	CHECK_EQUAL( 1, t.value().size() );
	CHECK_EQUAL( 0, t.value().at( 0 ) );
}

TEST(TlvParse, TwoByteTag)
{
	auto v = unhexify( "9F01021234" );
	Tlv::Status s;
	size_t len;
	auto t = Tlv::parse( v.data(), v.size(), s, &len );
	CHECK( s.empty() );
	CHECK_EQUAL( 5, len );
	CHECK_EQUAL( 0x9F01, t.tag().value );
	CHECK_EQUAL( 2, t.value().size() );
	CHECK_EQUAL( 0x12, t.value().at( 0 ) );
	CHECK_EQUAL( 0x34, t.value().at( 1 ) );
}

TEST(TlvParse, ThreeByteTag)
{
	auto v = unhexify( "BF8101021234" );
	Tlv::Status s;
	size_t len;
	auto t = Tlv::parse( v.data(), v.size(), s, &len );
	CHECK( s.empty() );
	CHECK_EQUAL( 6, len );
	CHECK_EQUAL( 0xBF8101, t.tag().value );
	CHECK_EQUAL( 2, t.value().size() );
	CHECK_EQUAL( 0x12, t.value().at( 0 ) );
	CHECK_EQUAL( 0x34, t.value().at( 1 ) );
}

TEST(TlvParse, FourByteTag)
{
	auto v = unhexify( "BF81FF01021234" );
	Tlv::Status s;
	size_t len;
	auto t = Tlv::parse( v.data(), v.size(), s, &len );
	CHECK( s.empty() );
	CHECK_EQUAL( 7, len );
	CHECK_EQUAL( 0xBF81FF01, t.tag().value );
	CHECK_EQUAL( 2, t.value().size() );
	CHECK_EQUAL( 0x12, t.value().at( 0 ) );
	CHECK_EQUAL( 0x34, t.value().at( 1 ) );
}

TEST(TlvParse, FiveByteTag)
{
	auto v = unhexify( "BF81FF8301021234" );
	Tlv::Status s;
	size_t len;
	auto t = Tlv::parse( v.data(), v.size(), s, &len );
	CHECK_FALSE( s.empty() );
}

TEST(TlvParse, EmptyData)
{
	auto v = unhexify( "1000" );
	Tlv::Status s;
	size_t len;
	auto t = Tlv::parse( v.data(), v.size(), s, &len );
	CHECK( s.empty() );
	CHECK_EQUAL( 2, len );
	CHECK_EQUAL( 0x10, t.tag().value );
	CHECK( t.value().empty() );
}

TEST(TlvParse, TwoByteLength)
{
	auto v = unhexify( "12820101" );
	for( int i = 0; i < 257; i++ )
	{
		v.push_back( 0x00 );
	}
	Tlv::Status s;
	size_t len;
	auto t = Tlv::parse( v.data(), v.size(), s, &len );
	CHECK( s.empty() );
	CHECK_EQUAL( 261, len );
	CHECK_EQUAL( 0x12, t.tag().value );
	CHECK_EQUAL( 257, t.value().size() );
}

TEST(TlvParse, BadLength)
{
	auto v = unhexify( "1285" );
	Tlv::Status s;
	size_t len;
	auto t = Tlv::parse( v.data(), v.size(), s, &len );
	CHECK_FALSE( s.empty() );
	CHECK( t.empty() );
}

TEST(TlvParse, IncompleteData)
{
	auto v = unhexify( "9F010212" );
	Tlv::Status s;
	size_t len;
	auto t = Tlv::parse( v.data(), v.size(), s, &len );
	CHECK_FALSE( s.empty() );
	CHECK( t.empty() );
}

TEST(TlvParse, MultipleTags)
{
	auto v = unhexify( "9F1001318A03414243" );
	Tlv::Status s;
	size_t len;
	auto t = Tlv::parse_all( v.data(), v.size(), s, &len );
	CHECK( s.empty() );
	CHECK_EQUAL( 9, len );
	CHECK_EQUAL( 2, t.num_children() );
	auto it = t.begin();
	CHECK_EQUAL( 0x9F10, it->tag().value );
	CHECK_EQUAL( 1, it->value().size() );
	CHECK_EQUAL( 0x31, it->value().at( 0 ) );
	it++;
	CHECK_EQUAL( 0x8A, it->tag().value );
	CHECK_EQUAL( 3, it->value().size() );
	CHECK_EQUAL( 0x41, it->value().at( 0 ) );
	CHECK_EQUAL( 0x42, it->value().at( 1 ) );
	CHECK_EQUAL( 0x43, it->value().at( 2 ) );
}

TEST(TlvParse, NestedTags)
{
	/*
	 * BF10
	 *   AA
	 *     8B 414243
	 *   10 00
	 * 8C FF
	 */
	auto v = unhexify( "BF100AAA058B034142431001008C01FF" );
	Tlv::Status s;
	size_t len;

	// depth = 0
	auto tags = Tlv::parse_all( v.data(), v.size(), s, &len, 0 );
	CHECK_FALSE( s.empty() );
	CHECK( s.code() == Tlv::Status::BadArgument );
	s.clear();

	// depth = 1
	tags = Tlv::parse_all( v.data(), v.size(), s, &len );
	CHECK( s.empty() );
	CHECK_EQUAL( 16, len );
	CHECK_EQUAL( 2, tags.num_children() );
	auto it = tags.begin();
	CHECK_EQUAL( 0xBF10, it->tag().value );
	CHECK_EQUAL( 10, it->value().size() );
	CHECK_EQUAL( 0xAA, it->value().at( 0 ) );
	CHECK( it->children().empty() );
	it++;
	CHECK_EQUAL( 0x8C, it->tag().value );
	CHECK_EQUAL( 1, it->value().size() );
	CHECK_EQUAL( 0xFF, it->value().at( 0 ) );
	CHECK( it->children().empty() );

	// depth = 2
	tags = Tlv::parse_all( v.data(), v.size(), s, &len, 2 );
	CHECK( s.empty() );
	CHECK_EQUAL( 16, len );
	CHECK_EQUAL( 2, tags.num_children() );
	it = tags.begin();
	// 9F10
	CHECK_EQUAL( 0xBF10, it->tag().value );
	CHECK( it->value().empty() );
	auto subitems = it->children();
	CHECK_EQUAL( 2, subitems.size() );
	auto s_it = subitems.begin();
	// AA
	CHECK_EQUAL( 0xAA, s_it->tag().value );
	CHECK_EQUAL( 5, s_it->value().size() );
	CHECK_EQUAL( 0x8B, s_it->value().at( 0 ) );
	// 10
	s_it++;
	CHECK_EQUAL( 0x10, s_it->tag().value );
	CHECK_EQUAL( 1, s_it->value().size() );
	CHECK_EQUAL( 0x00, s_it->value().at( 0 ) );
	// 8C
	it++;
	CHECK_EQUAL( 0x8C, it->tag().value );
	CHECK_EQUAL( 1, it->value().size() );
	CHECK_EQUAL( 0xFF, it->value().at( 0 ) );
	CHECK( it->children().empty() );

	// depth = 3
	tags = Tlv::parse_all( v.data(), v.size(), s, &len, 3 );
	CHECK( s.empty() );
	CHECK_EQUAL( 16, len );
	CHECK_EQUAL( 2, tags.num_children() );
	it = tags.begin();
	// 9F10
	CHECK_EQUAL( 0xBF10, it->tag().value );
	CHECK( it->value().empty() );
	subitems = it->children();
	CHECK_EQUAL( 2, subitems.size() );
	s_it = subitems.begin();
	// AA
	CHECK_EQUAL( 0xAA, s_it->tag().value );
	CHECK( s_it->value().empty() );
	auto subitems2 = s_it->children();
	CHECK_EQUAL( 1, subitems2.size() );
	auto s2_it = subitems2.begin();
	CHECK_EQUAL( 0x8B, s2_it->tag().value );
	CHECK_EQUAL( 3, s2_it->value().size() );
	CHECK_EQUAL( 0x41, s2_it->value().at( 0 ) );
	// 10
	s_it++;
	CHECK_EQUAL( 0x10, s_it->tag().value );
	CHECK_EQUAL( 1, s_it->value().size() );
	CHECK_EQUAL( 0x00, s_it->value().at( 0 ) );
	// 8C
	it++;
	CHECK_EQUAL( 0x8C, it->tag().value );
	CHECK_EQUAL( 1, it->value().size() );
	CHECK_EQUAL( 0xFF, it->value().at( 0 ) );
	CHECK( it->children().empty() );
}

TEST(TlvParse, NestedNotConstructedTags)
{
	/*
	 * BF10
	 *   8A		<= not constructed
	 *     8B 414243
	 *   10 00
	 * 8C FF
	 */
	auto v = unhexify( "BF100A8A058B034142431001008C01FF" );
	Tlv::Status s;
	size_t len;

	auto tags = Tlv::parse_all( v.data(), v.size(), s, &len, 3 );
	CHECK( s.empty() );
	CHECK_EQUAL( 16, len );
	CHECK_EQUAL( 2, tags.num_children() );
	auto it = tags.begin();
	// 9F10
	CHECK_EQUAL( 0xBF10, it->tag().value );
	CHECK( it->value().empty() );
	auto subitems = it->children();
	CHECK_EQUAL( 2, subitems.size() );
	auto s_it = subitems.begin();
	// 8A
	CHECK_EQUAL( 0x8A, s_it->tag().value );
	CHECK_EQUAL( 5, s_it->value().size() );
	CHECK_EQUAL( 0x8B, s_it->value().at( 0 ) );
	// 10
	s_it++;
	CHECK_EQUAL( 0x10, s_it->tag().value );
	CHECK_EQUAL( 1, s_it->value().size() );
	CHECK_EQUAL( 0x00, s_it->value().at( 0 ) );
	// 8C
	it++;
	CHECK_EQUAL( 0x8C, it->tag().value );
	CHECK_EQUAL( 1, it->value().size() );
	CHECK_EQUAL( 0xFF, it->value().at( 0 ) );
	CHECK( it->children().empty() );
}

TEST(TlvParse, NestedTags2)
{
	/*
	 * 45	1
	 * BF8501
	 * 		AA
	 * 			8A	test
	 * 		93	ABBCCDD
	 * 5F41 345
	 */
	const auto buf = unhexify( "450101BF85010EAA068A047465737493040ABBCCDD5F41020345" );
	Tlv::Status s;
	size_t len;
	auto tlv = Tlv::parse_all( buf.data(), buf.size(), s, &len, 3 );
	CHECK( s.empty() );
	CHECK_EQUAL( 26, len );
	CHECK_EQUAL( 3, tlv.num_children() );

	// 45
	auto it = tlv.begin();
	CHECK_EQUAL( 0x45, it->tag().value );
	CHECK_EQUAL( 1, it->value().size() );
	CHECK_EQUAL( 0x01, it->value().at( 0 ) );

	// BF8501
	it++;
	CHECK_EQUAL( 0xBF8501, it->tag().value );
	CHECK( it->value().empty() );
	CHECK_EQUAL( 2, it->num_children() );

	auto _9F8501 = it->children();
	auto _9F8501_it = _9F8501.begin();

	// AA
	CHECK_EQUAL( 0xAA, _9F8501_it->tag().value );
	CHECK( _9F8501_it->value().empty() );
	CHECK_EQUAL( 1, _9F8501_it->num_children() );

	auto _aa = _9F8501_it->children();
	auto _aa_it = _aa.begin();

	// 8A
	CHECK_EQUAL( 0x8A, _aa_it->tag().value );
	CHECK_EQUAL( 4, _aa_it->value().size() );
	STRCMP_EQUAL( "test", _aa_it->string().c_str() );

	// 93
	_9F8501_it++;
	CHECK_EQUAL( 0x93, _9F8501_it->tag().value );
	CHECK_EQUAL( 4, _9F8501_it->value().size() );
	CHECK_EQUAL( 0x0A, _9F8501_it->value().at( 0 ) );
	CHECK_EQUAL( 0xBB, _9F8501_it->value().at( 1 ) );
	CHECK_EQUAL( 0xCC, _9F8501_it->value().at( 2 ) );
	CHECK_EQUAL( 0xDD, _9F8501_it->value().at( 3 ) );

	// 5F41
	it++;
	CHECK_EQUAL( 0x5F41, it->tag().value );
	CHECK_EQUAL( 2, it->value().size() );
	CHECK_EQUAL( 0x03, it->value().at( 0 ) );
	CHECK_EQUAL( 0x45, it->value().at( 1 ) );
}

TEST(TlvParse, Empty)
{
	Tlv::Status s;
	std::vector<unsigned char> buf;
	auto tlv = Tlv::parse_all( buf.data(), buf.size(), s );
	CHECK( s.empty() );
	CHECK( tlv.empty() );

	buf.push_back( 0x00 );
	tlv = Tlv::parse_all( buf.data(), buf.size(), s );
	CHECK( s.empty() );
	CHECK( tlv.empty() );
}

TEST(TlvParse, NoData)
{
	const auto buf = unhexify( "1000" );
	Tlv::Status s;
	auto tlv = Tlv::parse_all( buf.data(), buf.size(), s );
	CHECK( s.empty() );
	CHECK_EQUAL( 1, tlv.num_children() );
	CHECK_EQUAL( 0x10, tlv.back().tag().value );
	CHECK_EQUAL( 0, tlv.back().value_size() );
}

TEST(TlvParse, TwoByteLen)
{
	auto buf = unhexify( "12820101" );
	for( int i = 0; i < 257; i++ )
	{
		buf.push_back( 0x00 );
	}
	Tlv::Status s;
	auto tlv = Tlv::parse( buf.data(), buf.size(), s );
	CHECK( s.empty() );
	CHECK_EQUAL( 0x12, tlv.tag().value );
	CHECK_EQUAL( 257, tlv.value_size() );
}

TEST(TlvParse, LenMoreThanFour)
{
	const auto buf = unhexify( "1285" );
	Tlv::Status s;
	auto tlv = Tlv::parse( buf.data(), buf.size(), s );
	CHECK_FALSE( s.empty() );
	CHECK_EQUAL( Tlv::Status::BadLength, s.code() );
}

TEST(TlvParse, LeadingZeroes)
{
	const auto buf = unhexify( "00009F1001318A03414243" );
	Tlv::Status s;
	size_t len;
	auto tlv = Tlv::parse_all( buf.data(), buf.size(), s, &len );
	CHECK( s.empty() );
	CHECK_EQUAL( 11, len );
	CHECK_EQUAL( 2, tlv.num_children() );

	// 9F10
	auto it = tlv.begin();
	CHECK_EQUAL( 0x9F10, it->tag().value );
	CHECK_EQUAL( 1, it->value().size() );
	CHECK_EQUAL( 0x31, it->value().at( 0 ) );

	// 8A
	it++;
	CHECK_EQUAL( 0x8A, it->tag().value );
	CHECK_EQUAL( 3, it->value().size() );
	STRCMP_EQUAL( "ABC", it->string().c_str() );
}

TEST(TlvParse, InterElementPadding)
{
	const auto buf = unhexify( "9F10013100008A03414243" );
	Tlv::Status s;
	size_t len;
	auto tlv = Tlv::parse_all( buf.data(), buf.size(), s, &len );
	CHECK( s.empty() );
	CHECK_EQUAL( 11, len );
	CHECK_EQUAL( 2, tlv.num_children() );

	// 9F10
	auto it = tlv.begin();
	CHECK_EQUAL( 0x9F10, it->tag().value );
	CHECK_EQUAL( 1, it->value().size() );
	CHECK_EQUAL( 0x31, it->value().at( 0 ) );

	// 8A
	it++;
	CHECK_EQUAL( 0x8A, it->tag().value );
	CHECK_EQUAL( 3, it->value().size() );
	STRCMP_EQUAL( "ABC", it->string().c_str() );
}

TEST(TlvParse, TrailingZeroes)
{
	const auto buf = unhexify( "9F1001318A034142430000" );
	Tlv::Status s;
	size_t len;
	auto tlv = Tlv::parse_all( buf.data(), buf.size(), s, &len );
	CHECK( s.empty() );
	CHECK_EQUAL( 11, len );
	CHECK_EQUAL( 2, tlv.num_children() );

	// 9F10
	auto it = tlv.begin();
	CHECK_EQUAL( 0x9F10, it->tag().value );
	CHECK_EQUAL( 1, it->value().size() );
	CHECK_EQUAL( 0x31, it->value().at( 0 ) );

	// 8A
	it++;
	CHECK_EQUAL( 0x8A, it->tag().value );
	CHECK_EQUAL( 3, it->value().size() );
	STRCMP_EQUAL( "ABC", it->string().c_str() );
}

TEST(TlvParse, NestedPadding)
{
	const auto buf = unhexify( "00BF100B008A034142430010010000" );
	Tlv::Status s;
	size_t len;
	auto tlv = Tlv::parse_all( buf.data(), buf.size(), s, &len, 2 );
	CHECK( s.empty() );
	CHECK_EQUAL( 15, len );
	CHECK_EQUAL( 1, tlv.num_children() );

	// BF10
	auto it = tlv.begin();
	CHECK_EQUAL( 0xBF10, it->tag().value );

	auto _BF10 = it->children();
	auto _BF10_it = _BF10.begin();

	// 8A
	CHECK_EQUAL( 0x8A, _BF10_it->tag().value );
	CHECK_EQUAL( 3, _BF10_it->value().size() );
	STRCMP_EQUAL( "ABC", _BF10_it->string().c_str() );

	// 10
	_BF10_it++;
	CHECK_EQUAL( 0x10, _BF10_it->tag().value );
	CHECK_EQUAL( 1, _BF10_it->value().size() );
	CHECK_EQUAL( 0x00, _BF10_it->value().at( 0 ) );
}

TEST(TlvParse, NestedUnexpectedEnd)
{
	const auto buf = unhexify( "100101AA079F1002414210019F110131" ); // Tag 9F has 0x10 byte length, but only five byte available
	Tlv::Status s;
	size_t len;
	auto tlv = Tlv::parse_all( buf.data(), buf.size(), s, &len, 2 );
	CHECK_FALSE( s.empty() );
	CHECK_EQUAL( Tlv::Status::UnexpectedEnd, s.code() );
}

TEST(TlvParse, DuplicateTags)
{
	const auto buf = unhexify( "BF0110DA03414243DA03444546AA04100201021101FF" );
	Tlv::Status s;
	size_t len;
	auto tlv = Tlv::parse_all( buf.data(), buf.size(), s, &len, 3 );
	CHECK( s.empty() );
	CHECK_EQUAL( 22, len );
	CHECK_EQUAL( 2, tlv.num_children() );

	// BF01
	auto it = tlv.begin();
	CHECK_EQUAL( 0xBF01, it->tag().value );

	// DA
	auto _BF10 = it->children();
	auto _BF10_it = _BF10.begin();
	CHECK_EQUAL( 0xDA, _BF10_it->tag().value );
	CHECK_EQUAL( 3, _BF10_it->value().size() );
	STRCMP_EQUAL( "ABC", _BF10_it->string().c_str() );

	// DA
	_BF10_it++;
	CHECK_EQUAL( 0xDA, _BF10_it->tag().value );
	CHECK_EQUAL( 3, _BF10_it->value().size() );
	STRCMP_EQUAL( "DEF", _BF10_it->string().c_str() );

	// AA
	_BF10_it++;
	CHECK_EQUAL( 0xAA, _BF10_it->tag().value );

	// 10
	auto _10 = _BF10_it->children();
	auto _10_it = _10.begin();
	CHECK_EQUAL( 0x10, _10_it->tag().value );
	CHECK_EQUAL( 2, _10_it->value().size() );
	CHECK_EQUAL( 0x01, _10_it->value().at( 0 ) );
	CHECK_EQUAL( 0x02, _10_it->value().at( 1 ) );

	// 11
	it++;
	CHECK_EQUAL( 0x11, it->tag().value );
	CHECK_EQUAL( 1, it->value().size() );
	CHECK_EQUAL( 0xFF, it->value().at( 0 ) );
}

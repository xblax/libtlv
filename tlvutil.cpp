#include <libtlv/tlv.hpp>
#include <CLI/CLI.hpp>
#include <fstream>
#include <iterator>
#include <iostream>

class TlvUtil
{

public:
    enum class TlvFormat : int {
        Hex,
        Binary,
        Formatted
    };

private:
    CLI::App cliApp;

    std::string inPath;
    std::string outPath;
    TlvFormat inFormat;
    TlvFormat outFormat;

    Tlv tree;

    void validate_format( TlvFormat& target, const std::string& val )
    {
        if( CLI::detail::to_lower(val) == "hex" )
            target = TlvFormat::Hex;
        else if( CLI::detail::to_lower(val) == "bin")
            target = TlvFormat::Binary;
        else if( CLI::detail::to_lower(val) == "formatted")
            target = TlvFormat::Formatted;
        else
            throw CLI::ValidationError( "Invalid TLV format: \"" + val + "\"" );
    }

public:

    TlvUtil() :
        cliApp( "Command line utility for operations on tlv encoded data", "tlvutil" ),
        outPath("-"),
        inFormat(TlvFormat::Hex),
        outFormat(TlvFormat::Formatted)
    {
        cliApp.add_option("--in", inPath, "Path to tlv input data or - for stdin")->required(true);
        cliApp.add_option("--out", outPath, "Path to tlv output data or - for stdout (default)");
        cliApp.add_option("--inform", "Input format [hex, bin, formatted]")->each([&]( const std::string& val ){ validate_format( inFormat, val ); });
        cliApp.add_option("--outform", "Output format [hex, bin, formatted]")->each([&]( const std::string& val ){ validate_format( outFormat, val ); });
    }

    void read_tlv()
    {
        try
        {
            if( inPath == "-" )
            {
                read_tlv_istream( std::cin );
            }
            else
            {
                std::ifstream inStream( inPath, std::ios::binary );
                inStream.exceptions( std::ios::failbit | std::ios::badbit );
                read_tlv_istream( inStream );
            }
        }
        catch( std::ios::failure& )
        {
            std::cerr << "Error reading input data:" << std::endl << strerror(errno) << std::endl;
            std::exit( -1 );
        }
        catch ( std::exception& e )
        {
            std::cerr << "Error parsing input data:" << std::endl << e.what() << std::endl;
            std::exit( -1 );
        }
    }

    void read_tlv_istream( std::istream& in )
    {
        std::vector<char> inBuffer( (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>() );

        if( inFormat == TlvFormat::Binary )
        {
            auto status = tree.parse_all( reinterpret_cast<uint8_t*>(inBuffer.data()), inBuffer.size() );
            if( !status.ok() )
            {
                throw std::runtime_error( status.message() );
            }
        }
        else if ( inFormat == TlvFormat::Hex )
        {
            std::string_view hexStr( inBuffer.data(), inBuffer.size() );
            auto binData = LibtlvUtil::unhexify( hexStr, true );
            auto status = tree.parse_all( binData.data(), binData.size() );
            if( !status.ok() )
            {
                throw std::runtime_error( status.message() );
            }
        }
        else if ( inFormat == TlvFormat::Formatted )
        {
            throw std::runtime_error( "not supported" );
        }
    }

    void write_tlv()
    {
        try
        {
            if( outPath == "-" )
            {
                write_tlv_ostream( std::cout );
            }
            else
            {
                std::ofstream outStream( outPath, std::ios::binary );
                outStream.exceptions( std::ios::failbit | std::ios::badbit );
                write_tlv_ostream( outStream );
            }

        }
        catch ( std::ios::failure& )
        {
            std::cerr << "Error writing output data:" << std::endl << strerror(errno) << std::endl;
            std::exit( -1 );
        }
    }

    void write_tlv_ostream( std::ostream& out )
    {
        std::vector<uint8_t> outBuffer;
        if( outFormat == TlvFormat::Binary )
        {
            outBuffer = tree.dump();
        }
        else if( outFormat == TlvFormat::Hex )
        {
            auto hexStr = LibtlvUtil::hexify( tree.dump() );
            outBuffer.assign( hexStr.data(), hexStr.data() + hexStr.size() );
        }
        else if( outFormat == TlvFormat::Formatted )
        {
            auto formattedStr = tree.dump_formatted();
            outBuffer.assign( formattedStr.data(), formattedStr.data() + formattedStr.size() );
        }

        out.write( reinterpret_cast<const char*>(outBuffer.data()), outBuffer.size() );
    }

    int run( int argc, char** argv )
    {
        CLI11_PARSE(cliApp, argc, argv);

        // read TLV input
        read_tlv();
        // write TLV output
        write_tlv();

        // Maybe in the future implement optional transformations like tag search
        return 0;
    };

};

int main( int argc, char** argv )
{
    TlvUtil util;
    util.run( argc, argv );
}

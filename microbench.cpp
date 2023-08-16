#include <iostream>
#include <memory>
#include <chrono>
#include <vector>
#include <list>
#include <tlv.hpp>
#include <fstream>

void bench_list_ptr()
{
    // Prepare Data
    int n = 100000;
    std::vector<std::shared_ptr<int64_t>> vectorElements;
    for( int i = 0; i < n; i++ )
    {
	vectorElements.push_back(std::make_shared<int64_t>(n));
    }

    std::list<std::shared_ptr<int64_t>> listElements;
    for (int i = 0; i < n; i++ )
    {
	listElements.push_back(std::make_shared<int64_t>(n));
    }

    // Run benchmark on data
    {
        auto timeStart = std::chrono::steady_clock::now();
        std::vector<std::shared_ptr<int64_t>> vectorReferences;
        vectorReferences.reserve(vectorElements.size());
        for( auto& el : vectorElements )
        {
	    vectorReferences.push_back(el);
        }
	uint64_t count = 0;
        auto duration = std::chrono::steady_clock::now() - timeStart;
        std::cout << "Vector of shared_ptr took " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(duration).count()
                  << "ms " << count << std::endl;
    }

    {
        auto timeStart = std::chrono::steady_clock::now();
        std::vector<std::shared_ptr<int64_t>*> listReferences;
	listReferences.reserve(listElements.size());
        for( auto& el : listElements )
        {
	    listReferences.push_back(&el);
        }
	uint64_t count = 0;
        auto duration = std::chrono::steady_clock::now() - timeStart;
        std::cout << "Vector of raw pointer took " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(duration).count()
                  << "ms " << count << std::endl;
    }
}

// Bench TLV parse and dump
void bench_parse_dump()
{
    std::ifstream tlvFile( "./tlv.txt", std::ios::in | std::ios::binary );
    if( !tlvFile.is_open() )
    {
        return;
    }
    std::string tlvDataHex( (std::istreambuf_iterator<char>(tlvFile)), 
                             std::istreambuf_iterator<char>());
    std::vector<uint8_t> tlvData = unhexify( tlvDataHex );
    std::cout << "Input TLV size: " << tlvData.size() << std::endl;
    //std::vector<uint8_t> tlvDataHex;

    Tlv t;

    // Parse
    {
        auto timeStart = std::chrono::steady_clock::now();
        int n = 100000;
        for( int i = 0; i < n; i++ )
        {
           t.parse( tlvData.data(), tlvData.size(), 1024 );
        }        
        auto duration = std::chrono::steady_clock::now() - timeStart;
        std::cout << "TLV parse took " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(duration).count()
                  << "ms for " << n  << std::endl;
    }

    // Dump
    {
        auto timeStart = std::chrono::steady_clock::now();
        int n = 100000;
        for( int i = 0; i < n; i++ )
        {
           auto dump = t.dump();
        }        
        auto duration = std::chrono::steady_clock::now() - timeStart;
        std::cout << "TLV dump took " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(duration).count()
                  << "ms for " << n << std::endl;
    }

}

int main(int argc, const char** argv)
{
    bench_parse_dump();
    bench_list_ptr();
    return 0;
}

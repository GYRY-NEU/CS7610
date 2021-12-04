#pragma once
#ifndef FUNCSTORAGE_HPP__
#define FUNCSTORAGE_HPP__

#include "basic.hpp"

namespace storage
{

class kvstorage : public tbb::concurrent_unordered_map<std::string, boost::json::value>
{};

class bucketstorage : public tbb::concurrent_unordered_multimap<std::string, boost::json::value>
{};

struct pack
{
    kvstorage kv;
    bucketstorage bucket;
};

class storage : public tbb::concurrent_unordered_map<std::string, pack>
{};

struct cache
{
    std::string response;
    std::chrono::time_point<std::chrono::system_clock> timestamp;
};

class expire_storage : public tbb::concurrent_unordered_map<std::string, cache>
{};

} // storage

#endif // FUNCSTORAGE_HPP__

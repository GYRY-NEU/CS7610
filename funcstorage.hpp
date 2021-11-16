#pragma once
#ifndef FUNCSTORAGE_HPP__
#define FUNCSTORAGE_HPP__

#include "basic.hpp"

namespace storage
{

class storage
{
    tbb::concurrent_unordered_map<std::string, std::string> data_;
public:
    storage()

};

} // launch

#endif // FUNCSTORAGE_HPP__

#pragma once
#ifndef FUNCSTORAGE_HPP__
#define FUNCSTORAGE_HPP__

#include "basic.hpp"

namespace storage
{

class storage : public tbb::concurrent_unordered_map<std::string, boost::json::value>
{
public:
};

} // storage

#endif // FUNCSTORAGE_HPP__

// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_VECTOR_H
#define BITCOIN_UTIL_VECTOR_H

#include <initializer_list>
#include <type_traits>
#include <vector>

/** Construct a vector with the specified elements.
 *
 * This is preferable over the list initializing constructor of std::vector:
 * - It automatically infers the element type from its arguments.
 * - If any arguments are rvalue references, they will be moved into the vector
 *   (list initialization always copies).
 */
template<typename... Args>
inline std::vector<typename std::common_type<Args...>::type> Vector(Args&&... args)
{
    std::vector<typename std::common_type<Args...>::type> ret;
    ret.reserve(sizeof...(args));
    // The line below uses the trick from https://www.experts-exchange.com/articles/32502/None-recursive-variadic-templates-with-std-initializer-list.html
    (void)std::initializer_list<int>{(ret.emplace_back(std::forward<Args>(args)), 0)...};
    return ret;
}

/** Concatenate two vectors, moving elements. */
template<typename V>
inline V Cat(V v1, V&& v2)
{
    v1.reserve(v1.size() + v2.size());
    for (auto& arg : v2) {
        v1.push_back(std::move(arg));
    }
    return v1;
}

/** Concatenate two vectors. */
template<typename V>
inline V Cat(V v1, const V& v2)
{
    v1.reserve(v1.size() + v2.size());
    for (const auto& arg : v2) {
        v1.push_back(arg);
    }
    return v1;
}

/** Concatenate any number of vectors into the first one, moving elements. */
template<typename V, typename... Vs>
inline V CatMany(V v, const Vs&&... vs)
{
    v.reserve(v.size() + (vs.size() + ...));
    (v.insert(v.end(), std::make_move_iterator(vs.begin()), std::make_move_iterator(vs.end())), ...);
    return v;
}

/** Concatenate any number of vectors into the first one. */
template<typename V, typename... Vs>
inline V CatMany(V v, const Vs&... vs)
{
    v.reserve(v.size() + (vs.size() + ...));
    (v.insert(v.end(), vs.begin(), vs.end()), ...);
    return v;
}

#endif // BITCOIN_UTIL_VECTOR_H

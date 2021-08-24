// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_MINISCRIPT_H
#define BITCOIN_SCRIPT_MINISCRIPT_H

#include <algorithm>
#include <numeric>
#include <memory>
#include <string>
#include <vector>

#include <stdlib.h>
#include <assert.h>

#include <script/script.h>
#include <span.h>
#include <util/spanparsing.h>
#include <util/strencodings.h>
#include <util/vector.h>
#include <primitives/transaction.h>

namespace miniscript {

/** This type encapsulates the miniscript type system properties.
 *
 * Every miniscript expression is one of 4 basic types, and additionally has
 * a number of boolean type properties.
 *
 * The basic types are:
 * - "B" Base:
 *   - Takes its inputs from the top of the stack.
 *   - When satisfied, pushes a nonzero value of up to 4 bytes onto the stack.
 *   - When dissatisfied, pushes a 0 onto the stack.
 *   - This is used for most expressions, and required for the top level one.
 *   - For example: older(n) = <n> OP_CHECKSEQUENCEVERIFY.
 * - "V" Verify:
 *   - Takes its inputs from the top of the stack.
 *   - When satisfactied, pushes nothing.
 *   - Cannot be dissatisfied.
 *   - This is obtained by adding an OP_VERIFY to a B, modifying the last opcode
 *     of a B to its -VERIFY version (only for OP_CHECKSIG, OP_CHECKSIGVERIFY
 *     and OP_EQUAL), or using IFs where both branches are also Vs.
 *   - For example vc:pk_k(key) = <key> OP_CHECKSIGVERIFY
 * - "K" Key:
 *   - Takes its inputs from the top of the stack.
 *   - Becomes a B when followed by OP_CHECKSIG.
 *   - Always pushes a public key onto the stack, for which a signature is to be
 *     provided to satisfy the expression.
 *   - For example pk_h(key) = OP_DUP OP_HASH160 <Hash160(key)> OP_EQUALVERIFY
 * - "W" Wrapped:
 *   - Takes its input from one below the top of the stack.
 *   - When satisfied, pushes a nonzero value (like B) on top of the stack, or one below.
 *   - When dissatisfied, pushes 0 op top of the stack or one below.
 *   - Is always "OP_SWAP [B]" or "OP_TOALTSTACK [B] OP_FROMALTSTACK".
 *   - For example sc:pk_k(key) = OP_SWAP <key> OP_CHECKSIG
 *
 * There a type properties that help reasoning about correctness:
 * - "z" Zero-arg:
 *   - Is known to always consume exactly 0 stack elements.
 *   - For example after(n) = <n> OP_CHECKLOCKTIMEVERIFY
 * - "o" One-arg:
 *   - Is known to always consume exactly 1 stack element.
 *   - Conflicts with property 'z'
 *   - For example sha256(hash) = OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL
 * - "n" Nonzero:
 *   - For every way this expression can be satisfied, a satisfaction exists that never needs
 *     a zero top stack element.
 *   - Conflicts with property 'z' and with type 'W'.
 * - "d" Dissatisfiable:
 *   - There is an easy way to construct a dissatisfaction for this expression.
 *   - Conflicts with type 'V'.
 * - "u" Unit:
 *   - In case of satisfaction, an exact 1 is put on the stack (rather than just nonzero).
 *   - Conflicts with type 'V'.
 *
 * Additional type properties help reasoning about nonmalleability:
 * - "e" Expression:
 *   - This implies property 'd', but the dissatisfaction is nonmalleable.
 *   - This generally requires 'e' for all subexpressions which are invoked for that
 *     dissatifsaction, and property 'f' for the unexecuted subexpressions in that case.
 *   - Conflicts with type 'V'.
 * - "f" Forced:
 *   - Dissatisfactions (if any) for this expression always involve at least one signature.
 *   - Is always true for type 'V'.
 * - "s" Safe:
 *   - Satisfactions for this expression always involve at least one signature.
 * - "m" Nonmalleable:
 *   - For every way this expression can be satisfied (which may be none),
 *     a nonmalleable satisfaction exists.
 *   - This generally requires 'm' for all subexpressions, and 'e' for all subexpressions
 *     which are dissatisfied when satisfying the parent.
 *
 * One type property is an implementation detail:
 * - "x" Expensive verify:
 *   - Expressions with this property have a script whose last opcode is not EQUAL, CHECKSIG, or CHECKMULTISIG.
 *   - Not having this property means that it can be converted to a V at no cost (by switching to the
 *     -VERIFY version of the last opcode).
 *
 * Five more type properties for representing timelock information. Spend paths
 * in miniscripts containing conflicting timelocks and heightlocks cannot be spent together.
 * This helps users detect if miniscript does not match the semantic behaviour the
 * user expects.
 * - "g" Whether the branch contains a relative time timelock
 * - "h" Whether the branch contains a relative height timelock
 * - "i" Whether the branch contains a absolute time timelock
 * - "j" Whether the branch contains a absolute time heightlock
 * - "k"
 *   - Whether all satisfactions of this expression don't contain a mix of heightlock and timelock
 *     of the same type.
 *   - If the miniscript does not have the "k" property, the miniscript template will not match
 *     the user expectation of the corresponding spending policy.
 * For each of these properties the subset rule holds: an expression with properties X, Y, and Z, is also
 * valid in places where an X, a Y, a Z, an XY, ... is expected.
*/
class Type {
    //! Internal bitmap of properties (see ""_mst operator for details).
    uint32_t m_flags;

    //! Internal constructed used by the ""_mst operator.
    explicit constexpr Type(uint32_t flags) : m_flags(flags) {}

public:
    //! The only way to publicly construct a Type is using this literal operator.
    friend constexpr Type operator"" _mst(const char* c, size_t l);

    //! Compute the type with the union of properties.
    constexpr Type operator|(Type x) const { return Type(m_flags | x.m_flags); }

    //! Compute the type with the intersection of properties.
    constexpr Type operator&(Type x) const { return Type(m_flags & x.m_flags); }

    //! Check whether the left hand's properties are superset of the right's (= left is a subtype of right).
    constexpr bool operator<<(Type x) const { return (x.m_flags & ~m_flags) == 0; }

    //! Comparison operator to enable use in sets/maps (total ordering incompatible with <<).
    constexpr bool operator<(Type x) const { return m_flags < x.m_flags; }

    //! Equality operator.
    constexpr bool operator==(Type x) const { return m_flags == x.m_flags; }

    //! The empty type if x is false, itself otherwise.
    constexpr Type If(bool x) const { return Type(x ? m_flags : 0); }
};

//! Literal operator to construct Type objects.
inline constexpr Type operator"" _mst(const char* c, size_t l) {
    return l == 0 ? Type(0) : operator"" _mst(c + 1, l - 1) | Type(
        *c == 'B' ? 1 << 0 : // Base type
        *c == 'V' ? 1 << 1 : // Verify type
        *c == 'K' ? 1 << 2 : // Key type
        *c == 'W' ? 1 << 3 : // Wrapped type
        *c == 'z' ? 1 << 4 : // Zero-arg property
        *c == 'o' ? 1 << 5 : // One-arg property
        *c == 'n' ? 1 << 6 : // Nonzero arg property
        *c == 'd' ? 1 << 7 : // Dissatisfiable property
        *c == 'u' ? 1 << 8 : // Unit property
        *c == 'e' ? 1 << 9 : // Expression property
        *c == 'f' ? 1 << 10 : // Forced property
        *c == 's' ? 1 << 11 : // Safe property
        *c == 'm' ? 1 << 12 : // Nonmalleable property
        *c == 'x' ? 1 << 13 : // Expensive verify
        *c == 'g' ? 1 << 14 : // older: contains relative time timelock   (csv_time)
        *c == 'h' ? 1 << 15 : // older: contains relative height timelock (csv_height)
        *c == 'i' ? 1 << 16 : // after: contains time timelock   (cltv_time)
        *c == 'j' ? 1 << 17 : // after: contains height timelock   (cltv_height)
        *c == 'k' ? 1 << 18 : // does not contain a combination of height and time locks
        (throw std::logic_error("Unknown character in _mst literal"), 0)
    );
}

template<typename Key> struct Node;
template<typename Key> using NodeRef = std::shared_ptr<const Node<Key>>;

//! Construct a miniscript node as a shared_ptr.
template<typename Key, typename... Args>
NodeRef<Key> MakeNodeRef(Args&&... args) { return std::make_shared<const Node<Key>>(std::forward<Args>(args)...); }

//! The different node types in miniscript.
enum class NodeType {
    JUST_0,    //!< OP_0
    JUST_1,    //!< OP_1
    PK_K,      //!< [key]
    PK_H,      //!< OP_DUP OP_HASH160 [keyhash] OP_EQUALVERIFY
    OLDER,     //!< [n] OP_CHECKSEQUENCEVERIFY
    AFTER,     //!< [n] OP_CHECKLOCKTIMEVERIFY
    SHA256,    //!< OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 [hash] OP_EQUAL
    HASH256,   //!< OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 [hash] OP_EQUAL
    RIPEMD160, //!< OP_SIZE 32 OP_EQUALVERIFY OP_RIPEMD160 [hash] OP_EQUAL
    HASH160,   //!< OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 [hash] OP_EQUAL
    WRAP_A,    //!< OP_TOALTSTACK [X] OP_FROMALTSTACK
    WRAP_S,    //!< OP_SWAP [X]
    WRAP_C,    //!< [X] OP_CHECKSIG
    WRAP_D,    //!< OP_DUP OP_IF [X] OP_ENDIF
    WRAP_V,    //!< [X] OP_VERIFY (or -VERIFY version of last opcode in X)
    WRAP_J,    //!< OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
    WRAP_N,    //!< [X] OP_0NOTEQUAL
    AND_V,     //!< [X] [Y]
    AND_B,     //!< [X] [Y] OP_BOOLAND
    OR_B,      //!< [X] [Y] OP_BOOLOR
    OR_C,      //!< [X] OP_NOTIF [Y] OP_ENDIF
    OR_D,      //!< [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
    OR_I,      //!< OP_IF [X] OP_ELSE [Y] OP_ENDIF
    ANDOR,     //!< [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
    THRESH,    //!< [X1] ([Xn] OP_ADD)* [k] OP_EQUAL
    MULTI,     //!< [k] [key_n]* [n] OP_CHECKMULTISIG
    // AND_N(X,Y) is represented as ANDOR(X,Y,0)
    // WRAP_T(X) is represented as AND_V(X,1)
    // WRAP_L(X) is represented as OR_I(0,X)
    // WRAP_U(X) is represented as OR_I(X,0)
};

namespace internal {

//! Helper function for Node::CalcType.
Type ComputeType(NodeType nodetype, Type x, Type y, Type z, const std::vector<Type>& sub_types, uint32_t k, size_t data_size, size_t n_subs, size_t n_keys);

//! Helper function for Node::CalcScriptLen.
size_t ComputeScriptLen(NodeType nodetype, Type sub0typ, size_t subsize, uint32_t k, size_t n_subs, size_t n_keys);

//! A helper sanitizer/checker for the output of CalcType.
Type SanitizeType(Type x);

} // namespace internal

//! A node in a miniscript expression.
template<typename Key>
struct Node {
    //! What node type this node is.
    const NodeType nodetype;
    //! The k parameter (time for OLDER/AFTER, threshold for THRESH(_M))
    const uint32_t k = 0;
    //! The keys used by this expression (only for PK_K/PK_H/MULTI)
    const std::vector<Key> keys;
    //! The data bytes in this expression (only for HASH160/HASH256/SHA256/RIPEMD10).
    const std::vector<unsigned char> data;
    //! Subexpressions (for WRAP_*/AND_*/OR_*/ANDOR/THRESH)
    const std::vector<NodeRef<Key>> subs;

private:
    //! Cached expression type (computed by CalcType and fed through SanitizeType).
    const Type typ;
    //! Cached script length (computed by CalcScriptLen).
    const size_t scriptlen;

    //! Compute the length of the script for this miniscript (including children).
    size_t CalcScriptLen() const {
        size_t subsize = 0;
        for (const auto& sub : subs) {
            subsize += sub->GetScriptSize();
        }
        Type sub0type = subs.size() > 0 ? subs[0]->GetType() : ""_mst;
        return internal::ComputeScriptLen(nodetype, sub0type, subsize, k, subs.size(), keys.size());
    }

    //! Compute the type for this miniscript.
    Type CalcType() const {
        using namespace internal;

        // THRESH has a variable number of subexpression
        std::vector<Type> sub_types;
        if (nodetype == NodeType::THRESH) {
            for (const auto& sub : subs) sub_types.push_back(sub->GetType());
        }
        // All other nodes than THRESH can be computed just from the types of the 0-3 subexpexpressions.
        Type x = subs.size() > 0 ? subs[0]->GetType() : ""_mst;
        Type y = subs.size() > 1 ? subs[1]->GetType() : ""_mst;
        Type z = subs.size() > 2 ? subs[2]->GetType() : ""_mst;

        return SanitizeType(ComputeType(nodetype, x, y, z, sub_types, k, data.size(), subs.size(), keys.size()));
    }

    //! Internal code for ToScript.
    template<typename Ctx>
    CScript MakeScript(const Ctx& ctx, bool verify = false) const {
        std::vector<unsigned char> bytes;
        switch (nodetype) {
            case NodeType::PK_K: return CScript() << ctx.ToPKBytes(keys[0]);
            case NodeType::PK_H: return CScript() << OP_DUP << OP_HASH160 << ctx.ToPKHBytes(keys[0]) << OP_EQUALVERIFY;
            case NodeType::OLDER: return CScript() << k << OP_CHECKSEQUENCEVERIFY;
            case NodeType::AFTER: return CScript() << k << OP_CHECKLOCKTIMEVERIFY;
            case NodeType::SHA256: return CScript() << OP_SIZE << 32 << OP_EQUALVERIFY << OP_SHA256 << data << (verify ? OP_EQUALVERIFY : OP_EQUAL);
            case NodeType::RIPEMD160: return CScript() << OP_SIZE << 32 << OP_EQUALVERIFY << OP_RIPEMD160 << data << (verify ? OP_EQUALVERIFY : OP_EQUAL);
            case NodeType::HASH256: return CScript() << OP_SIZE << 32 << OP_EQUALVERIFY << OP_HASH256 << data << (verify ? OP_EQUALVERIFY : OP_EQUAL);
            case NodeType::HASH160: return CScript() << OP_SIZE << 32 << OP_EQUALVERIFY << OP_HASH160 << data << (verify ? OP_EQUALVERIFY : OP_EQUAL);
            case NodeType::WRAP_A: return (CScript() << OP_TOALTSTACK) + subs[0]->MakeScript(ctx) + (CScript() << OP_FROMALTSTACK);
            case NodeType::WRAP_S: return (CScript() << OP_SWAP) + subs[0]->MakeScript(ctx, verify);
            case NodeType::WRAP_C: return subs[0]->MakeScript(ctx) + CScript() << (verify ? OP_CHECKSIGVERIFY : OP_CHECKSIG);
            case NodeType::WRAP_D: return (CScript() << OP_DUP << OP_IF) + subs[0]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::WRAP_V: return subs[0]->MakeScript(ctx, true) + (subs[0]->GetType() << "x"_mst ? (CScript() << OP_VERIFY) : CScript());
            case NodeType::WRAP_J: return (CScript() << OP_SIZE << OP_0NOTEQUAL << OP_IF) + subs[0]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::WRAP_N: return subs[0]->MakeScript(ctx) + CScript() << OP_0NOTEQUAL;
            case NodeType::JUST_1: return CScript() << OP_1;
            case NodeType::JUST_0: return CScript() << OP_0;
            case NodeType::AND_V: return subs[0]->MakeScript(ctx) + subs[1]->MakeScript(ctx, verify);
            case NodeType::AND_B: return subs[0]->MakeScript(ctx) + subs[1]->MakeScript(ctx) + (CScript() << OP_BOOLAND);
            case NodeType::OR_B: return subs[0]->MakeScript(ctx) + subs[1]->MakeScript(ctx) + (CScript() << OP_BOOLOR);
            case NodeType::OR_D: return subs[0]->MakeScript(ctx) + (CScript() << OP_IFDUP << OP_NOTIF) + subs[1]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::OR_C: return subs[0]->MakeScript(ctx) + (CScript() << OP_NOTIF) + subs[1]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::OR_I: return (CScript() << OP_IF) + subs[0]->MakeScript(ctx) + (CScript() << OP_ELSE) + subs[1]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::ANDOR: return subs[0]->MakeScript(ctx) + (CScript() << OP_NOTIF) + subs[2]->MakeScript(ctx) + (CScript() << OP_ELSE) + subs[1]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::MULTI: {
                CScript script = CScript() << k;
                for (const auto& key : keys) {
                    script << ctx.ToPKBytes(key);
                }
                return script << keys.size() << (verify ? OP_CHECKMULTISIGVERIFY : OP_CHECKMULTISIG);
            }
            case NodeType::THRESH: {
                CScript script = subs[0]->MakeScript(ctx);
                for (size_t i = 1; i < subs.size(); ++i) {
                    script = (script + subs[i]->MakeScript(ctx)) << OP_ADD;
                }
                return script << k << (verify ? OP_EQUALVERIFY : OP_EQUAL);
            }
        }
        assert(false);
        return {};
    }

    //! Internal code for ToString.
    template<typename Ctx>
    std::string MakeString(const Ctx& ctx, bool& success, bool wrapped = false) const {
        std::string ret = wrapped ? ":" : "";

        switch (nodetype) {
            case NodeType::WRAP_A: return "a" + subs[0]->MakeString(ctx, success, true);
            case NodeType::WRAP_S: return "s" + subs[0]->MakeString(ctx, success, true);
            case NodeType::WRAP_C:
                if (subs[0]->nodetype == NodeType::PK_K) {
                    // pk(K) is syntactic sugar for c:pk_k(K)
                    std::string key_str;
                    success = ctx.ToString(subs[0]->keys[0], key_str);
                    return std::move(ret) + "pk(" + std::move(key_str) + ")";
                }
                if (subs[0]->nodetype == NodeType::PK_H) {
                    // pkh(K) is syntactic sugar for c:pk_h(K)
                    std::string key_str;
                    success = ctx.ToString(subs[0]->keys[0], key_str);
                    return std::move(ret) + "pkh(" + std::move(key_str) + ")";
                }
                return "c" + subs[0]->MakeString(ctx, success, true);
            case NodeType::WRAP_D: return "d" + subs[0]->MakeString(ctx, success, true);
            case NodeType::WRAP_V: return "v" + subs[0]->MakeString(ctx, success, true);
            case NodeType::WRAP_J: return "j" + subs[0]->MakeString(ctx, success, true);
            case NodeType::WRAP_N: return "n" + subs[0]->MakeString(ctx, success, true);
            case NodeType::AND_V:
                // t:X is syntactic sugar for and_v(X,1).
                if (subs[1]->nodetype == NodeType::JUST_1) return "t" + subs[0]->MakeString(ctx, success, true);
                break;
            case NodeType::OR_I:
                if (subs[0]->nodetype == NodeType::JUST_0) return "l" + subs[1]->MakeString(ctx, success, true);
                if (subs[1]->nodetype == NodeType::JUST_0) return "u" + subs[0]->MakeString(ctx, success, true);
                break;
            default:
                break;
        }

        switch (nodetype) {
            case NodeType::PK_K: {
                std::string key_str;
                success = ctx.ToString(keys[0], key_str);
                return std::move(ret) + "pk_k(" + std::move(key_str) + ")";
            }
            case NodeType::PK_H: {
                std::string key_str;
                success = ctx.ToString(keys[0], key_str);
                return std::move(ret) + "pk_h(" + std::move(key_str) + ")";
            }
            case NodeType::AFTER: return std::move(ret) + "after(" + std::to_string(k) + ")";
            case NodeType::OLDER: return std::move(ret) + "older(" + std::to_string(k) + ")";
            case NodeType::HASH256: return std::move(ret) + "hash256(" + HexStr(data) + ")";
            case NodeType::HASH160: return std::move(ret) + "hash160(" + HexStr(data) + ")";
            case NodeType::SHA256: return std::move(ret) + "sha256(" + HexStr(data) + ")";
            case NodeType::RIPEMD160: return std::move(ret) + "ripemd160(" + HexStr(data) + ")";
            case NodeType::JUST_1: return std::move(ret) + "1";
            case NodeType::JUST_0: return std::move(ret) + "0";
            case NodeType::AND_V: return std::move(ret) + "and_v(" + subs[0]->MakeString(ctx, success) + "," + subs[1]->MakeString(ctx, success) + ")";
            case NodeType::AND_B: return std::move(ret) + "and_b(" + subs[0]->MakeString(ctx, success) + "," + subs[1]->MakeString(ctx, success) + ")";
            case NodeType::OR_B: return std::move(ret) + "or_b(" + subs[0]->MakeString(ctx, success) + "," + subs[1]->MakeString(ctx, success) + ")";
            case NodeType::OR_D: return std::move(ret) + "or_d(" + subs[0]->MakeString(ctx, success) + "," + subs[1]->MakeString(ctx, success) + ")";
            case NodeType::OR_C: return std::move(ret) + "or_c(" + subs[0]->MakeString(ctx, success) + "," + subs[1]->MakeString(ctx, success) + ")";
            case NodeType::OR_I: return std::move(ret) + "or_i(" + subs[0]->MakeString(ctx, success) + "," + subs[1]->MakeString(ctx, success) + ")";
            case NodeType::ANDOR:
                // and_n(X,Y) is syntactic sugar for andor(X,Y,0).
                if (subs[2]->nodetype == NodeType::JUST_0) return std::move(ret) + "and_n(" + subs[0]->MakeString(ctx, success) + "," + subs[1]->MakeString(ctx, success) + ")";
                return std::move(ret) + "andor(" + subs[0]->MakeString(ctx, success) + "," + subs[1]->MakeString(ctx, success) + "," + subs[2]->MakeString(ctx, success) + ")";
            case NodeType::MULTI: {
                auto str = std::move(ret) + "multi(" + std::to_string(k);
                for (const auto& key : keys) {
                    std::string key_str;
                    success &= ctx.ToString(key, key_str);
                    str += "," + std::move(key_str);
                }
                return std::move(str) + ")";
            }
            case NodeType::THRESH: {
                auto str = std::move(ret) + "thresh(" + std::to_string(k);
                for (const auto& sub : subs) {
                    str += "," + sub->MakeString(ctx, success);
                }
                return std::move(str) + ")";
            }
            default: assert(false); // Wrappers should have been handled above
        }
        return "";
    }

public:
    //! Return the size of the script for this expression (faster than ToString().size()).
    size_t GetScriptSize() const { return scriptlen; }

    //! Return the expression type.
    Type GetType() const { return typ; }

    //! Check whether this node is valid at all.
    bool IsValid() const { return !(GetType() == ""_mst); }

    //! Check whether this node is valid as a script on its own.
    bool IsValidTopLevel() const { return GetType() << "B"_mst; }

    //! Check whether this script can always be satisfied in a non-malleable way.
    bool IsNonMalleable() const { return GetType() << "m"_mst; }

    //! Check whether this script always needs a signature.
    bool NeedsSignature() const { return GetType() << "s"_mst; }

    //! Check whether there is no satisfaction path that contains both timelocks and heightlocks
    bool CheckTimeLocksMix() const { return GetType() << "k"_mst; }

    //! Do all sanity checks.
    bool IsSafeTopLevel() const { return GetType() << "Bms"_mst; }

    //! Construct the script for this miniscript (including subexpressions).
    template<typename Ctx>
    CScript ToScript(const Ctx& ctx) const { return MakeScript(ctx); }

    //! Convert this miniscript to its textual descriptor notation.
    template<typename Ctx>
    bool ToString(const Ctx& ctx, std::string& out) const {
        bool ret = true;
        out = MakeString(ctx, ret);
        if (!ret) out = "";
        return ret;
    }

    //! Equality testing.
    bool operator==(const Node<Key>& arg) const
    {
        if (nodetype != arg.nodetype) return false;
        if (k != arg.k) return false;
        if (data != arg.data) return false;
        if (keys != arg.keys) return false;
        if (subs.size() != arg.subs.size()) return false;
        for (size_t i = 0; i < subs.size(); ++i) {
            if (!(*subs[i] == *arg.subs[i])) return false;
        }
        assert(scriptlen == arg.scriptlen);
        assert(typ == arg.typ);
        return true;
    }

    // Constructors with various argument combinations.
    Node(NodeType nt, std::vector<NodeRef<Key>> sub, std::vector<unsigned char> arg, uint32_t val = 0) : nodetype(nt), k(val), data(std::move(arg)), subs(std::move(sub)), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, std::vector<unsigned char> arg, uint32_t val = 0) : nodetype(nt), k(val), data(std::move(arg)), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, std::vector<NodeRef<Key>> sub, std::vector<Key> key, uint32_t val = 0) : nodetype(nt), k(val), keys(std::move(key)), subs(std::move(sub)), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, std::vector<Key> key, uint32_t val = 0) : nodetype(nt), k(val), keys(std::move(key)), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, std::vector<NodeRef<Key>> sub, uint32_t val = 0) : nodetype(nt), k(val), subs(std::move(sub)), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, uint32_t val = 0) : nodetype(nt), k(val), typ(CalcType()), scriptlen(CalcScriptLen()) {}
};

namespace internal {

// Parse(...) is recursive. Recursion depth is limited to MAX_PARSE_RECURSION to avoid
// running out of stack space at run-time. It is impossible to create a valid Miniscript
// with a nesting depth higher than 402 (any such script will trivially exceed the ops
// limit of 201). Those 402 consist of 201 v: wrappers and 201 other nodes. The Parse
// functions don't use recursion for wrappers, so the recursion limit can be 201.
static constexpr int MAX_PARSE_RECURSION = 201;

//! Parse a miniscript from its textual descriptor form.
template<typename Key, typename Ctx>
inline NodeRef<Key> Parse(Span<const char>& in, const Ctx& ctx, int recursion_depth, bool wrappers_parsed = false) {
    using namespace spanparsing;
    if (recursion_depth >= MAX_PARSE_RECURSION) {
        return {};
    }
    auto expr = Expr(in);
    // Parse wrappers
    if (!wrappers_parsed) {
        // colon cannot be the first character
        //`:pk()` is invalid miniscript
        for (unsigned int i = 1; i < expr.size(); ++i) {
            if (expr[i] == ':') {
                auto in2 = expr.subspan(i + 1);
                // pass wrappers_parsed = true to avoid multi-colons
                auto sub = Parse<Key>(in2, ctx, recursion_depth + 1, true);
                if (!sub || in2.size()) return {};
                for (int j = i; j-- > 0; ) {
                    if (expr[j] == 'a') {
                        sub = MakeNodeRef<Key>(NodeType::WRAP_A, Vector(std::move(sub)));
                    } else if (expr[j] == 's') {
                        sub = MakeNodeRef<Key>(NodeType::WRAP_S, Vector(std::move(sub)));
                    } else if (expr[j] == 'c') {
                        sub = MakeNodeRef<Key>(NodeType::WRAP_C, Vector(std::move(sub)));
                    } else if (expr[j] == 'd') {
                        sub = MakeNodeRef<Key>(NodeType::WRAP_D, Vector(std::move(sub)));
                    } else if (expr[j] == 'j') {
                        sub = MakeNodeRef<Key>(NodeType::WRAP_J, Vector(std::move(sub)));
                    } else if (expr[j] == 'n') {
                        sub = MakeNodeRef<Key>(NodeType::WRAP_N, Vector(std::move(sub)));
                    } else if (expr[j] == 'v') {
                        sub = MakeNodeRef<Key>(NodeType::WRAP_V, Vector(std::move(sub)));
                    } else if (expr[j] == 't') {
                        sub = MakeNodeRef<Key>(NodeType::AND_V, Vector(std::move(sub), MakeNodeRef<Key>(NodeType::JUST_1)));
                    } else if (expr[j] == 'u') {
                        sub = MakeNodeRef<Key>(NodeType::OR_I, Vector(std::move(sub), MakeNodeRef<Key>(NodeType::JUST_0)));
                    } else if (expr[j] == 'l') {
                        sub = MakeNodeRef<Key>(NodeType::OR_I, Vector(MakeNodeRef<Key>(NodeType::JUST_0), std::move(sub)));
                    } else {
                        return {};
                    }
                }
                return sub;
            }
            if (expr[i] < 'a' || expr[i] > 'z') break;
        }
    }
    // Parse the other node types
    NodeType nodetype;
    if (expr == Span<const char>("0", 1)) {
        return MakeNodeRef<Key>(NodeType::JUST_0);
    } else if (expr == Span<const char>("1", 1)) {
        return MakeNodeRef<Key>(NodeType::JUST_1);
    } else if (Func("pk", expr)) {
        Key key;
        if (ctx.FromString(expr.begin(), expr.end(), key)) {
            return MakeNodeRef<Key>(NodeType::WRAP_C, Vector(MakeNodeRef<Key>(NodeType::PK_K, Vector(std::move(key)))));
        }
        return {};
    } else if (Func("pkh", expr)) {
        Key key;
        if (ctx.FromString(expr.begin(), expr.end(), key)) {
            return MakeNodeRef<Key>(NodeType::WRAP_C, Vector(MakeNodeRef<Key>(NodeType::PK_H, Vector(std::move(key)))));
        }
        return {};
    } else if (Func("pk_k", expr)) {
        Key key;
        if (ctx.FromString(expr.begin(), expr.end(), key)) {
            return MakeNodeRef<Key>(NodeType::PK_K, Vector(std::move(key)));
        }
        return {};
    } else if (Func("pk_h", expr)) {
        Key key;
        if (ctx.FromString(expr.begin(), expr.end(), key)) {
            return MakeNodeRef<Key>(NodeType::PK_H, Vector(std::move(key)));
        }
        return {};
    } else if (Func("sha256", expr)) {
        std::string val = std::string(expr.begin(), expr.end());
        if (!IsHex(val)) return {};
        auto hash = ParseHex(val);
        if (hash.size() != 32) return {};
        return MakeNodeRef<Key>(NodeType::SHA256, std::move(hash));
    } else if (Func("ripemd160", expr)) {
        std::string val = std::string(expr.begin(), expr.end());
        if (!IsHex(val)) return {};
        auto hash = ParseHex(val);
        if (hash.size() != 20) return {};
        return MakeNodeRef<Key>(NodeType::RIPEMD160, std::move(hash));
    } else if (Func("hash256", expr)) {
        std::string val = std::string(expr.begin(), expr.end());
        if (!IsHex(val)) return {};
        auto hash = ParseHex(val);
        if (hash.size() != 32) return {};
        return MakeNodeRef<Key>(NodeType::HASH256, std::move(hash));
    } else if (Func("hash160", expr)) {
        std::string val = std::string(expr.begin(), expr.end());
        if (!IsHex(val)) return {};
        auto hash = ParseHex(val);
        if (hash.size() != 20) return {};
        return MakeNodeRef<Key>(NodeType::HASH160, std::move(hash));
    } else if (Func("after", expr)) {
        int64_t num;
        if (!ParseInt64(std::string(expr.begin(), expr.end()), &num)) return {};
        if (num < 1 || num >= 0x80000000L) return {};
        return MakeNodeRef<Key>(NodeType::AFTER, num);
    } else if (Func("older", expr)) {
        int64_t num;
        if (!ParseInt64(std::string(expr.begin(), expr.end()), &num)) return {};
        if (num < 1 || num >= 0x80000000L) return {};
        return MakeNodeRef<Key>(NodeType::OLDER, num);
    } else if (Func("and_n", expr)) {
        auto left = Parse<Key>(expr, ctx, recursion_depth + 1);
        if (!left || !Const(",", expr)) return {};
        auto right = Parse<Key>(expr, ctx, recursion_depth + 1);
        if (!right || expr.size()) return {};
        return MakeNodeRef<Key>(NodeType::ANDOR, Vector(std::move(left), std::move(right), MakeNodeRef<Key>(NodeType::JUST_0)));
    } else if (Func("andor", expr)) {
        auto left = Parse<Key>(expr, ctx, recursion_depth + 1);
        if (!left || !Const(",", expr)) return {};
        auto mid = Parse<Key>(expr, ctx, recursion_depth + 1);
        if (!mid || !Const(",", expr)) return {};
        auto right = Parse<Key>(expr, ctx, recursion_depth + 1);
        if (!right || expr.size()) return {};
        return MakeNodeRef<Key>(NodeType::ANDOR, Vector(std::move(left), std::move(mid), std::move(right)));
    } else if (Func("multi", expr)) {
        auto arg = Expr(expr);
        int64_t count;
        if (!ParseInt64(std::string(arg.begin(), arg.end()), &count)) return {};
        std::vector<Key> keys;
        while (expr.size()) {
            if (!Const(",", expr)) return {};
            auto keyarg = Expr(expr);
            Key key;
            if (!ctx.FromString(keyarg.begin(), keyarg.end(), key)) return {};
            keys.push_back(std::move(key));
        }
        if (keys.size() < 1 || keys.size() > 20) return {};
        if (count < 1 || count > (int64_t)keys.size()) return {};
        return MakeNodeRef<Key>(NodeType::MULTI, std::move(keys), count);
    } else if (Func("thresh", expr)) {
        auto arg = Expr(expr);
        int64_t count;
        if (!ParseInt64(std::string(arg.begin(), arg.end()), &count)) return {};
        std::vector<NodeRef<Key>> subs;
        while (expr.size()) {
            if (!Const(",", expr)) return {};
            auto sub = Parse<Key>(expr, ctx, recursion_depth + 1);
            if (!sub) return {};
            subs.push_back(std::move(sub));
        }
        if (count < 1 || count > (int64_t)subs.size()) return {};
        return MakeNodeRef<Key>(NodeType::THRESH, std::move(subs), count);
    } else if (Func("and_v", expr)) {
        nodetype = NodeType::AND_V;
    } else if (Func("and_b", expr)) {
        nodetype = NodeType::AND_B;
    } else if (Func("or_c", expr)) {
        nodetype = NodeType::OR_C;
    } else if (Func("or_b", expr)) {
        nodetype = NodeType::OR_B;
    } else if (Func("or_d", expr)) {
        nodetype = NodeType::OR_D;
    } else if (Func("or_i", expr)) {
        nodetype = NodeType::OR_I;
    } else {
        return {};
    }
    auto left = Parse<Key>(expr, ctx, recursion_depth + 1);
    if (!left || !Const(",", expr)) return {};
    auto right = Parse<Key>(expr, ctx, recursion_depth + 1);
    if (!right || expr.size()) return {};
    return MakeNodeRef<Key>(nodetype, Vector(std::move(left), std::move(right)));
}

} // namespace internal

template<typename Ctx>
inline NodeRef<typename Ctx::Key> FromString(const std::string& str, const Ctx& ctx) {
    using namespace internal;
    Span<const char> span = MakeSpan(str);
    auto ret = Parse<typename Ctx::Key>(span, ctx, 0);
    if (!ret || span.size()) return {};
    return ret;
}

} // namespace miniscript

#endif // BITCOIN_SCRIPT_MINISCRIPT_H

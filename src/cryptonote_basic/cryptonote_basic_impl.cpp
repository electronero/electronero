// Copyright (c) 2014-2018, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "include_base_utils.h"
using namespace epee;

#include "cryptonote_basic_impl.h"
#include "string_tools.h"
#include "serialization/binary_utils.h"
#include "serialization/container.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "misc_language.h"
#include "common/base58.h"
#include "crypto/hash.h"
#include "common/int-util.h"
#include "common/dns_utils.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"


#define ELECTRONERO_HARDFORK ((uint64_t)(310787)) 
#define MAINNET_HARDFORK_V1_HEIGHT ((uint64_t)(1)) // MAINNET v1 
#define MAINNET_HARDFORK_V7_HEIGHT ((uint64_t)(307003)) // MAINNET v7 hard fork 
#define MAINNET_HARDFORK_V8_HEIGHT ((uint64_t)(307054)) // MAINNET v8 hard fork 
#define MAINNET_HARDFORK_V9_HEIGHT ((uint64_t)(308110)) // MAINNET v9 hard fork 
#define MAINNET_HARDFORK_V10_HEIGHT ((uint64_t)(310790)) // MAINNET v10 hard fork 
#define MAINNET_HARDFORK_V11_HEIGHT ((uint64_t)(310860)) // MAINNET v11 hard fork -- 70 blocks difference from 10
#define MAINNET_HARDFORK_V12_HEIGHT ((uint64_t)(333690)) // MAINNET 72289156 hard fork 
#define MAINNET_HARDFORK_V13_HEIGHT ((uint64_t)(337496)) // MAINNET v13 hard fork  
#define MAINNET_HARDFORK_V14_HEIGHT ((uint64_t)(337816)) // MAINNET v14 hard fork
#define MAINNET_HARDFORK_V15_HEIGHT ((uint64_t)(337838)) // MAINNET v15 hard fork 
#define MAINNET_HARDFORK_V16_HEIGHT ((uint64_t)(500060)) // MAINNET v16 hard fork
#define MAINNET_HARDFORK_V17_HEIGHT ((uint64_t)(570000)) // MAINNET v17 hard fork
#define MAINNET_HARDFORK_V18_HEIGHT ((uint64_t)(659000)) // MAINNET v18 hard fork
#define MAINNET_HARDFORK_V19_HEIGHT ((uint64_t)(739800)) // MAINNET v19 hard fork
#define MAINNET_HARDFORK_V20_HEIGHT ((uint64_t)(1132596)) // MAINNET v20 hard fork -- skipped
#define MAINNET_HARDFORK_V20_B_HEIGHT ((uint64_t)(1132597)) // MAINNET v20 hard fork -- used for emissions -- skipped fork
#define MAINNET_HARDFORK_V21_HEIGHT ((uint64_t)(1132900)) // MAINNET v21 hard fork
#define MAINNET_HARDFORK_V22_HEIGHT ((uint64_t)(1132935)) // MAINNET v22 hard fork
#define MAINNET_HARDFORK_V23_HEIGHT ((uint64_t)(1183409)) // MAINNET v23 hard fork
#define MAINNET_HARDFORK_V23_B_HEIGHT ((uint64_t)(1183485)) // MAINNET v23_b soft fork

#define TESTNET_ELECTRONERO_HARDFORK ((uint64_t)(12746)) // Electronero TESTNET fork height
#define TESTNET_HARDFORK_V1_HEIGHT ((uint64_t)(1)) // TESTNET v1 
#define TESTNET_HARDFORK_V7_HEIGHT ((uint64_t)(307003)) // TESTNET v7 hard fork 
#define TESTNET_HARDFORK_V8_HEIGHT ((uint64_t)(307054)) // TESTNET v8 hard fork 
#define TESTNET_HARDFORK_V9_HEIGHT ((uint64_t)(308110)) // TESTNET v9 hard fork
#define TESTNET_HARDFORK_V10_HEIGHT ((uint64_t)(310790)) // TESTNET v10 hard fork
#define TESTNET_HARDFORK_V11_HEIGHT ((uint64_t)(310860)) // TESTNET v11 hard fork
#define TESTNET_HARDFORK_V12_HEIGHT ((uint64_t)(333690)) // TESTNET v12 hard fork
#define TESTNET_HARDFORK_V13_HEIGHT ((uint64_t)(337496)) // TESTNET v13 hard fork
#define TESTNET_HARDFORK_V14_HEIGHT ((uint64_t)(337816)) // TESTNET v14 hard fork
#define TESTNET_HARDFORK_V15_HEIGHT ((uint64_t)(337838)) // TESTNET v15 hard fork
#define TESTNET_HARDFORK_V16_HEIGHT ((uint64_t)(492500)) // TESTNET v16 hard fork

#define STAGENET_HARDFORK_V1_HEIGHT ((uint64_t)(1)) // STAGENET v1 
#define STAGENET_HARDFORK_V7_HEIGHT ((uint64_t)(307003)) // STAGENET v7 hard fork 
#define STAGENET_HARDFORK_V8_HEIGHT ((uint64_t)(307054)) // STAGENET v8 hard fork 
#define STAGENET_HARDFORK_V9_HEIGHT ((uint64_t)(308110)) // STAGENET v9 hard fork 
#define STAGENET_HARDFORK_V10_HEIGHT ((uint64_t)(310790)) // STAGENET v10 hard fork 
#define STAGENET_HARDFORK_V11_HEIGHT ((uint64_t)(310860)) // STAGENET v11 hard fork -- 70 blocks difference from 10
#define STAGENET_HARDFORK_V12_HEIGHT ((uint64_t)(333690)) // STAGENET 72289156 hard fork 
#define STAGENET_HARDFORK_V13_HEIGHT ((uint64_t)(337496)) // STAGENET v13 hard fork  
#define STAGENET_HARDFORK_V14_HEIGHT ((uint64_t)(337816)) // STAGENET v14 hard fork
#define STAGENET_HARDFORK_V15_HEIGHT ((uint64_t)(337838)) // STAGENET v15 hard fork
#define STAGENET_HARDFORK_V16_HEIGHT ((uint64_t)(492500)) // STAGENET v16 hard fork
#define STAGENET_HARDFORK_V17_HEIGHT ((uint64_t)(492530)) // STAGENET v17 hard fork
#define STAGENET_HARDFORK_V18_HEIGHT ((uint64_t)(492540)) // TESTNET v18 hard fork

namespace cryptonote {

  struct integrated_address {
    account_public_address adr;
    crypto::hash8 payment_id;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(adr)
      FIELD(payment_id)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(adr)
      KV_SERIALIZE(payment_id)
    END_KV_SERIALIZE_MAP()
  };

  /************************************************************************/
  /* Cryptonote helper functions                                          */
  /************************************************************************/
  //-----------------------------------------------------------------------------------------------
  size_t get_min_block_size(uint8_t version)
  {
    if (version < 2)
      return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
    if (version < 5)
      return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2;
    return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  }
  //-----------------------------------------------------------------------------------------------
  size_t get_max_block_size()
  {
    return CRYPTONOTE_MAX_BLOCK_SIZE;
  }
  //-----------------------------------------------------------------------------------------------
  size_t get_max_tx_size()
  {
    return CRYPTONOTE_MAX_TX_SIZE;
  }
  //-----------------------------------------------------------------------------------------------
  bool get_block_reward(size_t median_size, size_t current_block_size, uint64_t already_generated_coins, uint64_t &reward, uint8_t version, uint64_t height) {
    static_assert(DIFFICULTY_TARGET_V2%60==0&&DIFFICULTY_TARGET_V1%60==0,"difficulty targets must be a multiple of 60");
    uint64_t versionHeight = height; // alias used for emissions
    uint64_t COIN_SUPPLY_V1 = version < 7 ? MONEY_SUPPLY_ETN : version < 10 ? MONEY_SUPPLY : version <  16 ? TOKENS : ELECTRONERO_TOKENS;
    uint64_t COIN_SUPPLY_V2 = ELECTRONERO_PULSE;
    uint64_t COIN_SUPPLY_V3 = ELECTRONERO_COINS;
    uint64_t COIN_SUPPLY = (uint64_t)versionHeight < MAINNET_HARDFORK_V20_HEIGHT ? COIN_SUPPLY_V1 : (uint64_t)versionHeight < MAINNET_HARDFORK_V23_B_HEIGHT ? COIN_SUPPLY_V2 : COIN_SUPPLY_V3;

    const int target = (uint64_t)versionHeight < MAINNET_HARDFORK_V7_HEIGHT ? DIFFICULTY_TARGET_V1 : (uint64_t)versionHeight >= MAINNET_HARDFORK_V14_HEIGHT ? DIFFICULTY_TARGET_V1 : DIFFICULTY_TARGET_V2;
    const int target_minutes = target / 60;
    const int emission_speed_factor = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes-1); // 20 emf
    const int emission_speed_factor_v2 = EMISSION_SPEED_FACTOR_PER_MINUTE + (target_minutes-1); // 20 emf
    const int emission_speed_factor_v3 = EMISSION_SPEED_FACTOR_PER_MINUTE + (target_minutes-2); // v10 - 19 emf
    const int emission_speed_factor_v4 = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes-1); // v16 - 20 emf 
    const int emission_speed_factor_v5 = EMISSION_SPEED_FACTOR_PER_MINUTE + (target_minutes); //  21 emf 
    const int emission_speed_factor_v6 = EMISSION_SPEED_FACTOR_PER_MINUTE + (target_minutes+1); // v17 - 22 emf 
    const int emission_speed_factor_v7 = EMISSION_SPEED_FACTOR_PER_MINUTE + (target_minutes+9); // v18 - 30 emf 
    const int emission_speed_factor_v8 = EMISSION_SPEED_FACTOR_PER_MINUTE + (target_minutes+6); // v19 - 27 emf 
    const int emission_speed_factor_v9 = EMISSION_SPEED_FACTOR_PER_MINUTE + (target_minutes+9); // v20 - 30 emf 
    const int emission_speed_factor_v10 = EMISSION_SPEED_FACTOR_PER_MINUTE + (target_minutes+7); // v21 - 28 emf 
    const int emission_speed_factor_v11 = EMISSION_SPEED_FACTOR_PER_MINUTE + (target_minutes+9); // v22 - 30 emf
    const int emission_speed_factor_v12 = EMISSION_SPEED_FACTOR_PER_MINUTE + (target_minutes+8); // v23 - 29 emf
    const int emission_speed_factor_v13 = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes-3); // v23_b - 18 emf
    uint64_t emission_speed = (uint64_t)versionHeight < MAINNET_HARDFORK_V7_HEIGHT ? emission_speed_factor : (uint64_t)versionHeight < MAINNET_HARDFORK_V10_HEIGHT ? emission_speed_factor_v2 : (uint64_t)versionHeight < MAINNET_HARDFORK_V16_HEIGHT ? emission_speed_factor_v3 : (uint64_t)versionHeight < MAINNET_HARDFORK_V17_HEIGHT ? emission_speed_factor_v4 : (uint64_t)versionHeight < MAINNET_HARDFORK_V18_HEIGHT ? emission_speed_factor_v6 : (uint64_t)versionHeight < MAINNET_HARDFORK_V19_HEIGHT ? emission_speed_factor_v7 : (uint64_t)versionHeight < MAINNET_HARDFORK_V20_HEIGHT ? emission_speed_factor_v8 : (uint64_t)versionHeight < MAINNET_HARDFORK_V21_HEIGHT ? emission_speed_factor_v9 : (uint64_t)versionHeight < MAINNET_HARDFORK_V22_HEIGHT ? emission_speed_factor_v10 : (uint64_t)versionHeight < MAINNET_HARDFORK_V23_HEIGHT ? emission_speed_factor_v11 : (uint64_t)versionHeight < MAINNET_HARDFORK_V23_B_HEIGHT ? emission_speed_factor_v12 : emission_speed_factor_v13;
    uint64_t base_reward = (COIN_SUPPLY - already_generated_coins) >> emission_speed_factor;
    
    const uint64_t electroneum_genesis_byte_size = 1260000000000U;
    if ((uint64_t)height == 1) {
      reward = electroneum_genesis_byte_size;
      return true;
    }
    const uint64_t community_airdrop_byte_size = electroneum_genesis_byte_size;
    if ((uint64_t)height == 307003 || (uint64_t)height == 310790) {
      reward = community_airdrop_byte_size;
      return true;
    }
    const uint64_t electronero_genesis_byte_size = 613090000000000U;
    if ((uint64_t)height == 500060 || (uint64_t)height == 1183410 || (uint64_t)height == 1183411 || (uint64_t)height == 1183412 || (uint64_t)height == 1183413) {
      reward = electronero_genesis_byte_size;
      return true;
    }
    const uint64_t electronero_parking_genesis_byte_size = 3333333333310301990U;
    if ((uint64_t)height == 1132597) {
      reward = electronero_parking_genesis_byte_size;
      return true;
    }
    
    uint64_t round_factor = 10; // 1 * pow(10, 1)
    if ((uint64_t)height > 307003 && version >= 7)
    {
      if (height < (PEAK_COIN_EMISSION_HEIGHT + COIN_EMISSION_HEIGHT_INTERVAL)) {
        uint64_t interval_num = height / COIN_EMISSION_HEIGHT_INTERVAL;
        double money_supply_pct = 0.1888 + interval_num*(0.023 + interval_num*0.0032);
        base_reward = ((uint64_t)(COIN_SUPPLY * money_supply_pct)) >> emission_speed;
      }
      else{
        base_reward = ((uint64_t)(COIN_SUPPLY - already_generated_coins)) >> emission_speed;
      }
    }
    else
    {
      // do something
      base_reward = (COIN_SUPPLY - already_generated_coins) >> emission_speed;
    }

    // rounding (floor) base reward
    if (version > 7)
    {
    base_reward = base_reward / round_factor * round_factor;
    }
    if (version < 2) 
    {
     base_reward = (MONEY_SUPPLY_ETN - already_generated_coins) >> emission_speed;
    }
    
   // maybe work on better final subsidy later
   const uint64_t FINAL_SUBSIDY_ACTIVATOR = 666U;
    if (base_reward < FINAL_SUBSIDY_ACTIVATOR){
     if (already_generated_coins >= COIN_SUPPLY){
       base_reward = FINAL_SUBSIDY_PER_MINUTE;
     }
    }
    
    uint64_t full_reward_zone = get_min_block_size(version);

    //make it soft
    if (median_size < full_reward_zone) {
      median_size = full_reward_zone;
    }

    if (current_block_size <= median_size) {
      reward = base_reward;
      return true;
    }

    if(current_block_size > 2 * median_size) {
      MERROR("Block cumulative size is too big: " << current_block_size << ", expected less than " << 2 * median_size);
      return false;
    }

    assert(median_size < std::numeric_limits<uint32_t>::max());
    assert(current_block_size < std::numeric_limits<uint32_t>::max());

    uint64_t product_hi;
    // BUGFIX: 32-bit saturation bug (e.g. ARM7), the result was being
    // treated as 32-bit by default.
    uint64_t multiplicand = 2 * median_size - current_block_size;
    multiplicand *= current_block_size;
    uint64_t product_lo = mul128(base_reward, multiplicand, &product_hi);

    uint64_t reward_hi;
    uint64_t reward_lo;
    div128_32(product_hi, product_lo, static_cast<uint32_t>(median_size), &reward_hi, &reward_lo);
    div128_32(reward_hi, reward_lo, static_cast<uint32_t>(median_size), &reward_hi, &reward_lo);
    assert(0 == reward_hi);
    assert(reward_lo < base_reward);

    reward = reward_lo;
    return true;
  }
  //------------------------------------------------------------------------------------
  uint8_t get_account_address_checksum(const public_address_outer_blob& bl)
  {
    const unsigned char* pbuf = reinterpret_cast<const unsigned char*>(&bl);
    uint8_t summ = 0;
    for(size_t i = 0; i!= sizeof(public_address_outer_blob)-1; i++)
      summ += pbuf[i];

    return summ;
  }
  //------------------------------------------------------------------------------------
  uint8_t get_account_integrated_address_checksum(const public_integrated_address_outer_blob& bl)
  {
    const unsigned char* pbuf = reinterpret_cast<const unsigned char*>(&bl);
    uint8_t summ = 0;
    for(size_t i = 0; i!= sizeof(public_integrated_address_outer_blob)-1; i++)
      summ += pbuf[i];

    return summ;
  }
  //-----------------------------------------------------------------------
  std::string get_account_address_as_str(
      network_type nettype
    , bool subaddress
    , account_public_address const & adr
    )
  {
    uint64_t address_prefix = nettype == TESTNET ?
      (subaddress ? config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX) : nettype == STAGENET ?
      (subaddress ? config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX) :
      (subaddress ? config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);

    return tools::base58::encode_addr(address_prefix, t_serializable_object_to_blob(adr));
  }
  //-----------------------------------------------------------------------
  std::string get_account_integrated_address_as_str(
      network_type nettype
    , account_public_address const & adr
    , crypto::hash8 const & payment_id
    )
  {
    uint64_t integrated_address_prefix = nettype == TESTNET ? config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX : nettype == STAGENET ? config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX : config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;

    integrated_address iadr = {
      adr, payment_id
    };
    return tools::base58::encode_addr(integrated_address_prefix, t_serializable_object_to_blob(iadr));
  }
  //-----------------------------------------------------------------------
  bool is_coinbase(const transaction& tx)
  {
    if(tx.vin.size() != 1)
      return false;

    if(tx.vin[0].type() != typeid(txin_gen))
      return false;

    return true;
  }
  //-----------------------------------------------------------------------
  bool get_account_address_from_str(
      address_parse_info& info
    , network_type nettype
    , std::string const & str
    )
  {
    uint64_t address_prefix = nettype == TESTNET ?
      config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX : nettype == STAGENET ?
      config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX : config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t integrated_address_prefix = nettype == TESTNET ?
      config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX : nettype == STAGENET ?
      config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX : config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t subaddress_prefix = nettype == TESTNET ?
      config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : nettype == STAGENET ?
      config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;

    if (2 * sizeof(public_address_outer_blob) != str.size())
    {
      blobdata data;
      uint64_t prefix;
      if (!tools::base58::decode_addr(str, prefix, data))
      {
        LOG_PRINT_L2("Invalid address format");
        return false;
      }

      if (integrated_address_prefix == prefix)
      {
        info.is_subaddress = false;
        info.has_payment_id = true;
      }
      else if (address_prefix == prefix)
      {
        info.is_subaddress = false;
        info.has_payment_id = false;
      }
      else if (subaddress_prefix == prefix)
      {
        info.is_subaddress = true;
        info.has_payment_id = false;
      }
      else {
        LOG_PRINT_L1("Wrong address prefix: " << prefix << ", expected " << address_prefix 
          << " or " << integrated_address_prefix
          << " or " << subaddress_prefix);
        return false;
      }

      if (info.has_payment_id)
      {
        integrated_address iadr;
        if (!::serialization::parse_binary(data, iadr))
        {
          LOG_PRINT_L1("Account public address keys can't be parsed");
          return false;
        }
        info.address = iadr.adr;
        info.payment_id = iadr.payment_id;
      }
      else
      {
        if (!::serialization::parse_binary(data, info.address))
        {
          LOG_PRINT_L1("Account public address keys can't be parsed");
          return false;
        }
      }

      if (!crypto::check_key(info.address.m_spend_public_key) || !crypto::check_key(info.address.m_view_public_key))
      {
        LOG_PRINT_L1("Failed to validate address keys");
        return false;
      }
    }
    else
    {
      // Old address format
      std::string buff;
      if(!string_tools::parse_hexstr_to_binbuff(str, buff))
        return false;

      if(buff.size()!=sizeof(public_address_outer_blob))
      {
        LOG_PRINT_L1("Wrong public address size: " << buff.size() << ", expected size: " << sizeof(public_address_outer_blob));
        return false;
      }

      public_address_outer_blob blob = *reinterpret_cast<const public_address_outer_blob*>(buff.data());


      if(blob.m_ver > CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER)
      {
        LOG_PRINT_L1("Unknown version of public address: " << blob.m_ver << ", expected " << CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER);
        return false;
      }

      if(blob.check_sum != get_account_address_checksum(blob))
      {
        LOG_PRINT_L1("Wrong public address checksum");
        return false;
      }

      //we success
      info.address = blob.m_address;
      info.is_subaddress = false;
      info.has_payment_id = false;
    }

    return true;
  }
  //--------------------------------------------------------------------------------
  bool get_account_address_from_str_or_url(
      address_parse_info& info
    , network_type nettype
    , const std::string& str_or_url
    , std::function<std::string(const std::string&, const std::vector<std::string>&, bool)> dns_confirm
    )
  {
    if (get_account_address_from_str(info, nettype, str_or_url))
      return true;
    bool dnssec_valid;
    std::string address_str = tools::dns_utils::get_account_address_as_str_from_url(str_or_url, dnssec_valid, dns_confirm);
    return !address_str.empty() &&
      get_account_address_from_str(info, nettype, address_str);
  }
  //--------------------------------------------------------------------------------
  bool operator ==(const cryptonote::transaction& a, const cryptonote::transaction& b) {
    return cryptonote::get_transaction_hash(a) == cryptonote::get_transaction_hash(b);
  }

  bool operator ==(const cryptonote::block& a, const cryptonote::block& b) {
    return cryptonote::get_block_hash(a) == cryptonote::get_block_hash(b);
  }
}

//--------------------------------------------------------------------------------
bool parse_hash256(const std::string str_hash, crypto::hash& hash)
{
  std::string buf;
  bool res = epee::string_tools::parse_hexstr_to_binbuff(str_hash, buf);
  if (!res || buf.size() != sizeof(crypto::hash))
  {
    std::cout << "invalid hash format: <" << str_hash << '>' << std::endl;
    return false;
  }
  else
  {
    buf.copy(reinterpret_cast<char *>(&hash), sizeof(crypto::hash));
    return true;
  }
}

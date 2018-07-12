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

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "include_base_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r = epee::string_tools::parse_tpod_from_hex_string(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------
  //FIXME: is this the desired behavior?
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    // Is blockchain_height before the first checkpoint?
    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    std::map< uint64_t, crypto::hash >::const_iterator highest = 
        std::max_element( m_points.begin(), m_points.end(),
                         ( boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _1) < 
                           boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _2 ) ) );
    return highest->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }

  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

  bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    if (nettype == TESTNET)
    {
      ADD_CHECKPOINT(0,     "48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b");
      ADD_CHECKPOINT(1000000, "46b690b710a07ea051bc4a6b6842ac37be691089c0f7758cfeec4d5fc0b4a258");
      return true;
    }
    if (nettype == STAGENET)
    {
      ADD_CHECKPOINT(0,       "76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb");
      ADD_CHECKPOINT(10000,   "1f8b0ce313f8b9ba9a46108bfd285c45ad7c2176871fd41c3a690d4830ce2fd5");
      return true;
    }
    ADD_CHECKPOINT(1, "4536e1e23ff7179a126a7e61cd9e89ded0e258176f2bc879c999caa155f68cc3");
    ADD_CHECKPOINT(10, "e5aefcb1d575a788ecfb65bb7be3bdd135eb76ccefb38a60d7800e86d25d408e");
    ADD_CHECKPOINT(100, "e3548600cc0e2991af4f36bbf44addd95051748fc09e8cac5f8237fd841132c0");
    ADD_CHECKPOINT(1000, "d7ec8a6329948fee02cdc95b13f286bd69fe9540863a80dfff7fe14940756293");
    ADD_CHECKPOINT(10000, "95dad4575ba43eb0d4ba9b6081d5d52e6a74fc8fe3391d9628f78ddd3b71c965");
    ADD_CHECKPOINT(25000, "7c4062b935413c84e5de8e6c27917f5158ec4e39dd322798dcf4772eb4634772");
    ADD_CHECKPOINT(50000, "1e85615e78d31168a1e7a1c0bf64a607d0adff70d78d3baa7c954adff3cc8c2a");
    ADD_CHECKPOINT(100000, "a7b51ca66b2525903efbd4a32604a7ad5000df4b9da8bdd9cb3062cb014b0cad");
    ADD_CHECKPOINT(150000, "e9b66d3f12f9cedece7d9925721b15f1ec6cb2f6b438b3ddd288237c27ffe20e");
    ADD_CHECKPOINT(179839, "f8631f50ef79b840cba9fe3484764d0c7515ff2884e1f5be2f7298a4d08e88ee");
    ADD_CHECKPOINT(179840, "74958c1b19505ab49babc91dfd14251146256873ae875ac97c26fb2000490e70");
    ADD_CHECKPOINT(179841, "8a793f1aef368e83fa72ac3a236309c06ae7726958120514e0f6d33ff3b24548");
    ADD_CHECKPOINT(180000, "65193d028c4264dc679ee384d654eff59085976231f93b990ad16a5370961803");
    ADD_CHECKPOINT(200000, "9a7853584fbe0d88746d3d7bb6a3efd02ecaa3f0158808fde9f3c8339b3d5d8f");
    ADD_CHECKPOINT(225000, "26b00fd2638340dae0b2a479598dd82c6af489b876e85cdc203f41ad90d83233");
    ADD_CHECKPOINT(230000, "b01bdcc2effb4ccfd9cf41c4412b866b2f13058e759a900cf5d24a308b9a3fcd");
    ADD_CHECKPOINT(307003, "b79cb23dafca9fb36400bc15180b48cfa43d8839c16a4938a99fb11ab024dcdf");
    ADD_CHECKPOINT(307165, "507c9d28562a311833d03970db160ae2b875eefae6e4e5acbe128b8d1d4222ac");
    ADD_CHECKPOINT(307166, "b2723276aa1ffcfbd1058547cb6d0b01307a0560ee15c3c3ca786025d7dad88b");
    ADD_CHECKPOINT(307167, "49d4e1c57eddde66786c12de22efc047f66618fcb7e85b1fcd993f5b5727554e");
    ADD_CHECKPOINT(307168, "ab767ef1d8fcb902b3fc01e63e18f9782865eb3d867df7e8cf619041de4f9aef");
    ADD_CHECKPOINT(307169, "a7719a0532f834a289e6881f04f1666c9e82948f794edc4dd0c8efdcd56e98eb");
    ADD_CHECKPOINT(307170, "55490ffe0a65f5be663307970c9ade18a0f5449cfaa83a97b1912e49f43a3345");
    ADD_CHECKPOINT(307171, "526f407f6e5e8793a3a4bdf4f603d7f2827f58c7d86ae60544dd4e9005ea2c96");
    ADD_CHECKPOINT(307172, "ba1bb40c2834cab4bfdb8d0ff19247724e1cd4204d96df2b82fd713ff48aa27d");
    ADD_CHECKPOINT(307173, "da9f28679928fed5e51644a0f2663233208140e7da30eef9a14d2227fb0dc023");
    ADD_CHECKPOINT(307174, "9b75434375e4fbabc0be2c8d69b37404bd7739417e0c151bdae258b0c2d382dc");
    ADD_CHECKPOINT(307175, "d23037889c2e97f8eec4d9ad0fa26a7bf72f89ed45c04e340c65656f675c3821");
    ADD_CHECKPOINT(308112, "0a8ff6a620824c65a796b75d1bdbeccf8150012e2d4fdc5d6f86ce8b8e8d73fe"); 
    ADD_CHECKPOINT(309231, "372cdcb2c5b89afb3cd6fa28a6f3b86d4e23c0451cf21f048fbe5305d3dca977");
    ADD_CHECKPOINT(310790, "dc74427bc33b9cb9414986ee6455f3548bf52e7a43091c7cd0be5beeda453571");
    ADD_CHECKPOINT(310791, "798da7aede00a28a6d9a5b924fd31e39ce764b8b3f591386ce8e95965fd8e31c"); 
    ADD_CHECKPOINT(319000, "d544e7cc7b2ed85703f36eb572b79c0d50a2d8f94baa5246577d28f6a3811bc6");
    ADD_CHECKPOINT(319062, "99436c56256fcd6812b49100c05f78684723f6d8cde16970308ab5db86fdf870");
    ADD_CHECKPOINT(320023, "566cabc0a6745085da3a13e38e5d8b9f87997db9600d0df34168fe33d0d621fd");
    ADD_CHECKPOINT(333685, "59ad2423d2bba213e3939e044acdabed74f654350c4309b104d2c9444b9707e2");
    ADD_CHECKPOINT(333690, "037c51d236cf33d2a58d45b30d8a6f0f59792693bd783be3593984313a4e5a68");
    ADD_CHECKPOINT(333691, "7cec4b3b4ea14ae386264654c29d30ab9718fb999af4d43f41e3cd989ba39dca");
    ADD_CHECKPOINT(333692, "671d71b2083014c9c6e2b1f09551bec417cd001417b1b685705c4e6ec0d6a9d6");
    ADD_CHECKPOINT(333693, "c2c8018a9005e0919e2a2872bca8ea278ef1def8ba865be21365d96ac6a8fc9c");
    ADD_CHECKPOINT(333694, "d719281ca62a65899eda0808a6d87b7406bd1bcd9e2045fbdfc2e4726d9493b5");
    ADD_CHECKPOINT(333695, "c937db6319b8fb86406089773e292ac2423896538e7f4df4bc4be02f60d2d937");
    ADD_CHECKPOINT(333696, "44d1d38dbfd07a1fc41a194baa1952218324ba535b221c02dff1d4b25df9e32c");
    ADD_CHECKPOINT(333697, "f5bf2b1edb09776a81089f36d40cf791d2444d50f47fa7a38035994ecfa7247b");
    ADD_CHECKPOINT(333698, "ad54c31db02630379d29dee36dbc7f4e25c41e1c9e1019350380ff696a2e74a8");
    ADD_CHECKPOINT(333699, "c2577b259a5951a2b4803be7ca1af29a4eb66187d056ba563faec494e30260d8");
    ADD_CHECKPOINT(337235, "ad63ea7d3fb97598612016d73dba7befe5badb4b5ed6aba2cff9f89392674eb8");
    ADD_CHECKPOINT(337239, "8f54ba081eff7b42e0815434ba46155033dead3b4a01fb345b8580e291bc0512");
    ADD_CHECKPOINT(337240, "b64b2e579420d5e3fcc481d401bdf6bc174bbdedb461ac5793c5401ac9f63f61");
    ADD_CHECKPOINT(337282, "67312bc96c5f1bbe68f096af30d221cf0917e945c5afa8344d59983a1568a5e4");
    ADD_CHECKPOINT(337314, "1a6a757ab93b5c18ab489796db602d94f77357cb5eb20c046362b9c96fd93a70");
    ADD_CHECKPOINT(337341, "0bc854f4db94240ae05f390b255dfb6f112b4fd0322297cccd74dcc0f79bd4ac");
    ADD_CHECKPOINT(337344, "1b0829521c151235a930fc425e6684a105c86391d07b621bd262ee4687c11b3a");  
    ADD_CHECKPOINT(337364, "615447441bfb46c880eee9a913aec5e257e8b9a07555e32562097ce51afae23e");
    ADD_CHECKPOINT(337385, "0832b54ad07789271f31fedbdb5f9636c4f6083185f7124b541a506dcf7b126e");  
    ADD_CHECKPOINT(337397, "919a7fc0191013fba630313f32f51e6049b0f9c789ef0c4c646811889ac6050f");     
    ADD_CHECKPOINT(337807, "a901b1ab60c0a9fdb78ae7761d0b40ab5ebd58c95ea5f124f2d3cab3a33fea70");
    ADD_CHECKPOINT(337808, "9207f4095a3b02389cf279871adf897a95f8718a5d967f9c38cd07dc0c4e84da");
    ADD_CHECKPOINT(337809, "5193a1a97f762bdaf0680773d86e19a45d72ccb1a57e5c037adc191696c8b455");
    ADD_CHECKPOINT(337810, "ae7b15ab2edcb9219398d4e9722060b9215cc6fc200f6654c3aba003ca0f27e1");
    ADD_CHECKPOINT(337811, "382edc23e7333b83e17b0672c713d6a7f016c074f4783957eb23f7ca50d4d15e");
    ADD_CHECKPOINT(337812, "3b5c97e6107368b6f519c06647dc0b767be6adfea602c5b782151376382faa27");
    ADD_CHECKPOINT(337813, "026a68d5512df448f0b3ce7cccf7d240bfacff0f6427bcaf5ecd3828a1cfd8a9");
    ADD_CHECKPOINT(337814, "008394ffa0cec8a14e1e61e4fb270fad3e939f8a5e1422da4868ec55132b82e4");
    ADD_CHECKPOINT(337815, "0a53b0661858eee6865de4e22c5a3ba7cbcd0e897bf8b94104a0eeab0a120403");
    ADD_CHECKPOINT(337911, "9b32bb69d76da8f39e82a6f3f0efd9efa2409089c98c6381ccb3caa2f00f076c");
    ADD_CHECKPOINT(337837, "c554c42e87daefab96a67e01693c8a8555fcf8f448cbd391e2ee2f36c7cb9efa");
    ADD_CHECKPOINT(337838, "efd2eb0e38e8160b3f1de9828e94abb6c88d5f4e57c8691656614307b773a5cf");
    ADD_CHECKPOINT(337839, "e8637efe7c3a14236705415355c6208e0bbd12cb5bbab38fa8191905c561c8a7");
    ADD_CHECKPOINT(337840, "0a73fd810b5236492b96d73fba17752dea20865e3a4fe6d4bc0cc85e7f3ccaeb");
    ADD_CHECKPOINT(338120, "460f07a66c0a7d6fd2379d546a3ce4617dc36dbaf288691383f83034f69365a8");
    ADD_CHECKPOINT(338131, "0e5e436c64987b8d3d4b75b6962cb7cc19afed7e41d71b4f7750683bd6e8e89a");

    return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    std::vector<std::string> records;

    // All four MoneroPulse domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = { "checkpoints.electroneropulse.com"
						     , "checkpoints.electroneropulse.org"
						     , "checkpoints.electroneropulse.net"
						     , "checkpoints.electroneropulse.info"
    };

    static const std::vector<std::string> testnet_dns_urls = { "testpoints.electroneropulse.com"
							     , "testpoints.electroneropulse.org"
							     , "testpoints.electroneropulse.net"
							     , "testpoints.electroneropulse.info"
    };

    static const std::vector<std::string> stagenet_dns_urls = { "stagenetpoints.electroneropulse.com"
                   , "stagenetpoints.electroneropulse.org"
                   , "stagenetpoints.electroneropulse.net"
                   , "stagenetpoints.electroneropulse.info"
    };

    if (!tools::dns_utils::load_txt_records_from_dns(records, nettype == TESTNET ? testnet_dns_urls : nettype == STAGENET ? stagenet_dns_urls : dns_urls))
      return true; // why true ?

    for (const auto& record : records)
    {
      auto pos = record.find(":");
      if (pos != std::string::npos)
      {
        uint64_t height;
        crypto::hash hash;

        // parse the first part as uint64_t,
        // if this fails move on to the next record
        std::stringstream ss(record.substr(0, pos));
        if (!(ss >> height))
        {
    continue;
        }

        // parse the second part as crypto::hash,
        // if this fails move on to the next record
        std::string hashStr = record.substr(pos + 1);
        if (!epee::string_tools::parse_tpod_from_hex_string(hashStr, hash))
        {
    continue;
        }

        ADD_CHECKPOINT(height, hashStr);
      }
    }
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}

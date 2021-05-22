// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <util/moneystr.h>
#include <versionbitsinfo.h>

#include <pow.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

int64_t CChainParams::GetProofOfStakeReward(const CBlockIndex *pindexPrev, int64_t nFees) const
{
    // 25 rhom per block, block reward
    int64_t nSubsidy = 25 * COIN;
    return nSubsidy + nFees;
};

int64_t CChainParams::GetMaxSmsgFeeRateDelta(int64_t smsg_fee_prev) const
{
    return (smsg_fee_prev * consensus.smsg_fee_max_delta_percent) / 1000000;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn) const
{
    for (auto &hrp : bech32Prefixes)  {
        if (vchPrefixIn == hrp) {
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k) {
        auto &hrp = bech32Prefixes[k];
        if (vchPrefixIn == hrp) {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const char *ps, size_t slen, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k) {
        const auto &hrp = bech32Prefixes[k];
        size_t hrplen = hrp.size();
        if (hrplen > 0
            && slen > hrplen
            && strncmp(ps, (const char*)&hrp[0], hrplen) == 0) {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        }
    }

    return false;
};

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

const std::pair<const char*, CAmount> regTestOutputs[] = {
};
const size_t nGenesisOutputsRegtest = sizeof(regTestOutputs) / sizeof(regTestOutputs[0]);

static CBlock CreateGenesisBlockRegTest(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";

    CMutableTransaction txNew;
    txNew.nVersion = RHOMBUS_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = RHOMBUS_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockTestNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "000000000000000000070f733a7938515c60e693fb07c46538a9fcff5d1c6830";

    CMutableTransaction txNew;
    txNew.nVersion = RHOMBUS_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    for (size_t k = 0; k < 20; ++k) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = (200000000/20) *  COIN;
        out->scriptPubKey =  CScript() << OP_DUP << OP_HASH160 << ParseHex("4d2a2e22250047cf4544d5870931ad3b9bbbf161") << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout.push_back(out);
    }

    for (size_t l = 0; l < 100; ++l) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = (800000000/100) *  COIN;
        out->scriptPubKey =  CScript() << OP_DUP << OP_HASH160 << ParseHex("5807ef094ad50c0e408d6845aa19cde409b1f132") << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout.push_back(out);
    }

    for (size_t m = 0; m < 15; ++m) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = (6000000000/15) *  COIN;
        out->scriptPubKey =  CScript() << OP_DUP << OP_HASH160 << ParseHex("4f953fbe777219b4da2cb852c49cd89cf6394b52") << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout.push_back(out);
    }


    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = RHOMBUS_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockMainNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "000000000000000000070f733a7938515c60e693fb07c46538a9fcff5d1c6830";

    CMutableTransaction txNew;
    txNew.nVersion = RHOMBUS_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);

    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    for (size_t k = 0; k < 20; ++k) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = (200000000/20) *  COIN;
        out->scriptPubKey =  CScript() << OP_DUP << OP_HASH160 << ParseHex("df7b11f656c53fd31486ee1e48f814814853445d") << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout.push_back(out);
    }

    for (size_t l = 0; l < 100; ++l) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = (800000000/100) *  COIN;
        out->scriptPubKey =  CScript() << OP_DUP << OP_HASH160 << ParseHex("a4e543ecac59d9caa218f7b1236153a2c764fa72") << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout.push_back(out);
    }

    for (size_t m = 0; m < 15; ++m) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = (6000000000/15) *  COIN;
        out->scriptPubKey =  CScript() << OP_DUP << OP_HASH160 << ParseHex("1aae93aba1c771c6d5edf44fc94dfecdda3ad0f5") << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout.push_back(out);
    }


    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = RHOMBUS_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}


/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;

        consensus.OpIsCoinstakeTime = 0x5F98A5A3;       // 2020-10-27 00:00:00 UTC
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0x5F98A5A3;           // 2020-10-27 12:00:00
        consensus.smsg_fee_time = 0x5F98A5A3;           // 2020-10-27 12:00:00
        consensus.bulletproof_time = 0x5F98A5A3;        // 2020-10-27 12:00:00
        consensus.rct_time = 0x5F98A5A3;                // 2020-10-27 12:00:00
        consensus.smsg_difficulty_time = 0x5F98A5A3;    // 2020-10-27 12:00:00
        consensus.exploit_fix_1_time = 1621872000;      // 2021-05-24 12:00:00
        consensus.exploit_fix_2_time = 1621958400;      // 2021-05-25 12:00:00

        consensus.smsg_fee_period = 5040;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 43;
        consensus.smsg_min_difficulty = 0x1effffff;
        consensus.smsg_difficulty_max_delta = 0xffff;

        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000000000000000010001");

        // By default assume that the signatures in ancestors of this block are valid.
        //consensus.defaultAssumeValid = uint256S("0xc330a61e218b06d3d567c459b54e83ab682a366fc00b77d69dd78c6ed9655a2e"); // 634566

        consensus.nMinRCTOutputDepth = 12;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xef;
        pchMessageStart[3] = 0xb5;
        nDefaultPort = 41738;
        nBIP44ID = 0x8000002C;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 180;   // 225 * 2 minutes
        nTargetSpacing = 150;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

	    genesis = CreateGenesisBlockMainNet(1607567863, 167674, 0x1f00ffff);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock ==  uint256S("0x00006c324b2f2fd4d570106fa8ff35bb2cb5e18c26ffcd16585d85dab252e897"));   //uint256S("0x00000b739648f3aa338b845b8495e2fda3a6a1c4cd30a84327b1395ed01329a3"));
        assert(genesis.hashMerkleRoot == uint256S("0x5bd3e9405a97b3949363d2966f078128c1d9b00de5894fc6433910e799ba188d"));   //uint256S("0x54130f73358f72fc1028bc1d5cb7abc23960679fa7cc1c4a7674fe1882ac99d6"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x6f49f663f75e32a5cfefebffad47080ac2067ec4d3031e0d57462dabfd324e60"));   //uint256S("0x619e94a7f9f04c8a1d018eb8bcd9c42d3c23171ebed8f351872256e36959d66c"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("dnsseed.clamino.com");
        vSeeds.emplace_back("dnsseed.rhom.com");

        base58Prefixes[PUBKEY_ADDRESS]     = {0x3c}; // R
        base58Prefixes[SCRIPT_ADDRESS]     = {0x3F}; // S
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x39};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x40};
        base58Prefixes[SECRET_KEY]         = {0x6c};

        base58Prefixes[EXT_PUBLIC_KEY]      = {0x04, 0x0b, 0xf2, 0xa6};
        base58Prefixes[EXT_SECRET_KEY]      = {0x04, 0x0b, 0xee, 0x6c};
        base58Prefixes[STEALTH_ADDRESS]    = {0x14};
        base58Prefixes[EXT_KEY_HASH]       = {0x4b}; // X
        base58Prefixes[EXT_ACC_HASH]       = {0x17}; // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("rh",(const char*)"rh"+2);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("rr",(const char*)"rr"+2);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("rl",(const char*)"rl"+2);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("rj",(const char*)"rj"+2);
        bech32Prefixes[SECRET_KEY].assign           ("rx",(const char*)"rx"+2);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("rep",(const char*)"rep"+3);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("rex",(const char*)"rex"+3);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("rs",(const char*)"rs"+2);
        bech32Prefixes[EXT_KEY_HASH].assign         ("rek",(const char*)"rek"+3);
        bech32Prefixes[EXT_ACC_HASH].assign         ("rea",(const char*)"rea"+3);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("rcs",(const char*)"rcs"+3);

        bech32_hrp = "rw";
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;

        checkpointData = {
            {
                {0, uint256S("00006c324b2f2fd4d570106fa8ff35bb2cb5e18c26ffcd16585d85dab252e897")},
            }
        };

        chainTxData = ChainTxData {
            // Data from rpc: getchaintxstats 4096 c330a61e218b06d3d567c459b54e83ab682a366fc00b77d69dd78c6ed9655a2e
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0.000
        };
    }

    void SetOld()
    {
        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.CSVHeight = 419328; // 000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5
        consensus.SegwitHeight = 481824; // 0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
        consensus.MinBIP9WarningHeight = consensus.SegwitHeight + consensus.nMinerConfirmationWindow;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;

        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = true; // TODO: clear for next testnet
        consensus.nPaidSmsgTime = 0;
        consensus.smsg_fee_time = 0x5F98A5A3;           // 2020-10-27 12:00:00
        consensus.bulletproof_time = 0x5F98A5A3;           // 2020-10-27 12:00:00
        consensus.rct_time = 0;
        consensus.smsg_difficulty_time = 0x5F98A5A3;           // 2020-10-27 12:00:00
        consensus.exploit_fix_1_time = 1621872000;      // 2021-05-24 12:00:00
        consensus.exploit_fix_2_time = 1621958400;      // 2021-05-25 12:00:00

        consensus.smsg_fee_period = 5040;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 43;
        consensus.smsg_min_difficulty = 0x1effffff;
        consensus.smsg_difficulty_max_delta = 0xffff;

        consensus.powLimit = uint256S("000000000005ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000899ad150e4ba9f730");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x1d9a63069ed2b88c9a1752ade780d39f783118a4d6f7b4a04b398c3d77d4cd1f"); // 585754

        consensus.nMinRCTOutputDepth = 12;

        pchMessageStart[0] = 0x08;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x05;
        pchMessageStart[3] = 0x0b;
        nDefaultPort = 51938;
        nBIP44ID = 0x80000001;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 225;   // 225 * 2 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlockTestNet(1607567863, 194729, 0x1f00ffff);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0000795feac87a1d474b6e0d4fa4f72f5732664910609a44fe002e779f1f2dfc"));
        assert(genesis.hashMerkleRoot == uint256S("0xae56a287a8d4f9a989a80a8dd1a3f9c5cbfa7b322fe02424158e0e81fdde1e86"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0xf2a4d32af3b653d5c6343a5c10a3357d7761829643226e1978b4a7420add744e"));
        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet.clamino.com");

        base58Prefixes[PUBKEY_ADDRESS]     = {0x7A}; // r
        base58Prefixes[SCRIPT_ADDRESS]     = {0x76};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0x2e};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x01, 0xfb, 0xe1, 0xa6}; // RRoM
        base58Prefixes[EXT_SECRET_KEY]     = {0x02, 0x78, 0xa1, 0x1d}; // XRom
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph",(const char*)"tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr",(const char*)"tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl",(const char*)"tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj",(const char*)"tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx",(const char*)"tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep",(const char*)"tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex",(const char*)"tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps",(const char*)"tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek",(const char*)"tpek"+4);
        bech32Prefixes[EXT_ACC_HASH].assign         ("tpea",(const char*)"tpea"+4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("tpcs",(const char*)"tpcs"+4);

        bech32_hrp = "trw";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;

        checkpointData = {
            {
                //{0, uint256S("0000795feac87a1d474b6e0d4fa4f72f5732664910609a44fe002e779f1f2dfc")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 1d9a63069ed2b88c9a1752ade780d39f783118a4d6f7b4a04b398c3d77d4cd1f
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0.000
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.CSVHeight = 432; // CSV activated on regtest (Used in rpc activation tests)
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 0;

        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shTime = 0;
        consensus.smsg_fee_time = 0;
        consensus.bulletproof_time = 0;
        consensus.rct_time = 0;
        consensus.smsg_difficulty_time = 0;

        consensus.smsg_fee_period = 50;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 4300;
        consensus.smsg_min_difficulty = 0x1f0fffff;
        consensus.smsg_difficulty_max_delta = 0xffff;

        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nMinRCTOutputDepth = 2;

        pchMessageStart[0] = 0x09;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0x06;
        pchMessageStart[3] = 0x0c;
        nDefaultPort = 11938;
        nBIP44ID = 0x80000001;


        nModifierInterval = 2 * 60;     // 2 minutes
        nStakeMinConfirmations = 12;
        nTargetSpacing = 5;             // 5 seconds
        nTargetTimespan = 16 * 60;      // 16 mins
        nStakeTimestampMask = 0;

        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlockRegTest(1487714923, 0, 0x207fffff);

        consensus.hashGenesisBlock = genesis.GetHash();
       
        assert(consensus.hashGenesisBlock == uint256S("0x397d22ca18c7ab6066c9181fafb23b4131ec086f00529ac2042902282325e92f"));
        assert(genesis.hashMerkleRoot == uint256S("0x25db6490540d17d08ae242c30d37e4223bae42a0d7ddca3895d6dc33ac9b9e68"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0xb9808b35e74ac10cd74f8aa9aaf99f424c90165a73a85e502729061b326e9514"));


        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;

        checkpointData = {
            {
                //{0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };

        base58Prefixes[PUBKEY_ADDRESS]     = {0x7A}; // r
        base58Prefixes[SCRIPT_ADDRESS]     = {0x76};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0x2e};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x01, 0xfb, 0xe1, 0xa6}; // RRoM
        base58Prefixes[EXT_SECRET_KEY]     = {0x02, 0x78, 0xa1, 0x1d}; // XRom
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph",(const char*)"tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr",(const char*)"tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl",(const char*)"tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj",(const char*)"tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx",(const char*)"tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep",(const char*)"tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex",(const char*)"tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps",(const char*)"tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek",(const char*)"tpek"+4);
        bech32Prefixes[EXT_ACC_HASH].assign         ("tpea",(const char*)"tpea"+4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("tpcs",(const char*)"tpcs"+4);

        bech32_hrp = "rtpw";

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
    }

    void SetOld()
    {
        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        /*
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        */

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (gArgs.IsArgSet("-segwitheight")) {
        int64_t height = gArgs.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams *pParams() {
    return globalChainParams.get();
};

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}


void SetOldParams(std::unique_ptr<CChainParams> &params)
{
    if (params->NetworkID() == CBaseChainParams::MAIN) {
        return ((CMainParams*)params.get())->SetOld();
    }
    if (params->NetworkID() == CBaseChainParams::REGTEST) {
        return ((CRegTestParams*)params.get())->SetOld();
    }
};

void ResetParams(std::string sNetworkId, bool fRhombusModeIn)
{
    // Hack to pass old unit tests
    globalChainParams = CreateChainParams(sNetworkId);
    if (!fRhombusModeIn) {
        SetOldParams(globalChainParams);
    }
};

/**
 * Mutable handle to regtest params
 */
CChainParams &RegtestParams()
{
    return *globalChainParams.get();
};

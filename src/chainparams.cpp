// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xdf;
        pchMessageStart[1] = 0x87;
        pchMessageStart[2] = 0x92;
        pchMessageStart[3] = 0xca;
        vAlertPubKey = ParseHex("04c0a58ccbf7fbe847e706167b16ea2784e2b775abac67edee9dbfb419966e9a7ead452e22b283b41074a01547b1fd210a0df2c24f00584d2c3191d8db1866f6bf");
        nDefaultPort = 56094;
        nRPCPort = 56095;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);
        bnProofOfStakeLimit = CBigNum(~uint256(0) >> 20);

        const char* pszTimestamp = "China LOSES patience with USA after Trump punishes Kim Jong-un’s henchmen"; // Friday, 27-Oct-17
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
        CTransaction txNew(1, 1509129817, vin, vout, 0); // Friday, 27-Oct-17
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1509129817; // Friday, 27-Oct-17
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 2981901;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x00000efde27cc17eef13d982c503b640d42c88ed46fbe459aec2c3c08efb34f2"));
        assert(genesis.hashMerkleRoot == uint256("0x44f16e2dc8601c44ee005a5cce3b68aa1ee41e4426f004db2956dc1d00d8239d"));

        //hashGenesisBlock = uint256("0x01");
        // uncomment to log genesis block info
                            //start
        if (false && genesis.GetHash() != hashGenesisBlock)
           {
               LogPrintf("Searching for Mainet genesis block...\n");
               uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
               uint256 thash;

               while (true)
               {
                   thash = genesis.GetHash();
                   if (thash <= hashTarget)
                       break;
                   if ((genesis.nNonce & 0xFFF) == 0)
                   {
                       LogPrintf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                   }
                   ++genesis.nNonce;
                   if (genesis.nNonce == 0)
                   {
                       LogPrintf("NONCE WRAPPED, incrementing time\n");
                       ++genesis.nTime;
                   }
               }
               LogPrintf("Mainet genesis.nTime = %u \n", genesis.nTime);
               LogPrintf("Mainet genesis.nNonce = %u \n", genesis.nNonce);
               LogPrintf("Mainet genesis.nVersion = %u \n", genesis.nVersion);
               LogPrintf("Mainet genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str()); //first this, then comment this line out and uncomment the one under.
               LogPrintf("Mainet genesis.hashMerkleRoot = %s \n", genesis.hashMerkleRoot.ToString().c_str()); //improvised. worked for me, to find merkle root
           }
        //
        //        //end

//        vSeeds.push_back(CDNSSeedData("emb_00.0xify.com", "emb_00.0xify.com")); // Underscore FreeBSD Server
//        vSeeds.push_back(CDNSSeedData("emb_01.0xify.com", "emb_01.0xify.com")); // Underscore Debian Server
//        vSeeds.push_back(CDNSSeedData("emb_02.0xify.com", "emb_02.0xify.com")); // konez2k VPS
        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,23);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,83);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,78);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        nTargetSpacing = 180; // Initially ~180 Sec during PoW
        if(nBestHeight > nLastPoWBlock) // Scaled down for PoS only phase
        {
          nTargetSpacing = 180;
        }
        if(nBestHeight > nStartPoSBlock) // Scaled up for PoW/PoS twin phase
        {
          if(nBestHeight <= nLastPoWBlock)
          {
            nTargetSpacing = 400;
          }
        }
        nTargetTimespan = 10 * nTargetSpacing;
        nLastPoWBlock = 380005;
        nStartPoSBlock = 50;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xd5;
        pchMessageStart[1] = 0x6d;
        pchMessageStart[2] = 0x64;
        pchMessageStart[3] = 0xbb;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        bnProofOfStakeLimit = CBigNum(~uint256(0) >> 16);

        vAlertPubKey = ParseHex("0464665119d358166c4e114f5c863ae7c00c5f2efd83799482726d490d02056cd83e5e719c078003447e6a2d7d5f7565dfd08954c3185736db3bff30dd90f28f28");
        nDefaultPort = 55094;
        nRPCPort = 55095;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 220749;


        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000839de4631dcec831d32751b0ebcb77df983adb73c092afc62e1ac34679c4"));

        hashGenesisBlock = uint256("0x01");
        if (false && genesis.GetHash() != hashGenesisBlock)
           {
               LogPrintf("Searching for Testnet genesis block...\n");
               uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
               uint256 thash;

               while (true)
               {
                   thash = genesis.GetHash();
                   if (thash <= hashTarget)
                       break;
                   if ((genesis.nNonce & 0xFFF) == 0)
                   {
                       LogPrintf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                   }
                   ++genesis.nNonce;
                   if (genesis.nNonce == 0)
                   {
                       LogPrintf("NONCE WRAPPED, incrementing time\n");
                       ++genesis.nTime;
                   }
               }
               LogPrintf("Testnet genesis.nTime = %u \n", genesis.nTime);
               LogPrintf("Testnet genesis.nNonce = %u \n", genesis.nNonce);
               LogPrintf("Testnet genesis.nVersion = %u \n", genesis.nVersion);
               LogPrintf("Testnet genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str()); //first this, then comment this line out and uncomment the one under.
               LogPrintf("Testnet genesis.hashMerkleRoot = %s \n", genesis.hashMerkleRoot.ToString().c_str()); //improvised. worked for me, to find merkle root
           }

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,23);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,83);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,78);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        nTargetSpacing = 200;
        nLastPoWBlock = 0x7fffffff;
        nStartPoSBlock = 0;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0x21;
        pchMessageStart[1] = 0xaf;
        pchMessageStart[2] = 0x56;
        pchMessageStart[3] = 0xbc;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1476533000;
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 8;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 30095;
        strDataDir = "regtest";
       // assert(hashGenesisBlock == uint256("0x523dda6d336047722cbaf1c5dce622298af791bac21b33bf6e2d5048b2a13e3d"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}

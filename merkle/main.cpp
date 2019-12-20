#define CURVE_ALT_BN128

#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <boost/optional.hpp>
#include "../circuit/merklecircuit.h"

using namespace libsnark;


template<typename ppzksnark_ppT, typename FieldT, typename HashT>
r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> generate_read_keypair(const size_t tree_depth)
{
    protoboard<FieldT> pb;

    sample::MerkleCircuit<FieldT, HashT> mc(pb, tree_depth);
    mc.generate_r1cs_constraints();
    r1cs_constraint_system<FieldT> cs = pb.get_constraint_system();

    std::cout << "Number of R1CS constraints: " << cs.num_constraints() << std::endl;

    return r1cs_gg_ppzksnark_generator<ppzksnark_ppT>(cs);
}

template<typename ppzksnark_ppT, typename FieldT, typename HashT>
boost::optional<r1cs_gg_ppzksnark_proof<ppzksnark_ppT>> generate_read_proof(r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    const size_t tree_depth, libff::bit_vector& leaf,
                                                                    libff::bit_vector& root, merkle_authentication_path& path,
                                                                    const size_t address, libff::bit_vector& address_bits)
{
    protoboard<FieldT> pb;

    sample::MerkleCircuit<FieldT, HashT> mc(pb, tree_depth);
    mc.generate_r1cs_constraints();
    mc.generate_r1cs_witness(pb, leaf, root, path, address, address_bits);
    if (!pb.is_satisfied()) {
        std::cout << "pb is not satisfied" << std::endl;
        return boost::none;
    }

    return r1cs_gg_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppzksnark_ppT, typename FieldT>
bool verify_read_proof(r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof, libff::bit_vector& root)
{
    r1cs_primary_input<FieldT> input;
    for (auto item : root) {
        input.push_back(FieldT(item));
    }
    return r1cs_gg_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

template<typename HashT>
boost::optional<std::string> binToHex(libff::bit_vector& bin) {
    if (bin.size() != HashT::get_digest_len() && bin.size() != HashT::get_digest_len() * 2) {
        std::cout << "The input binary input is not " << HashT::get_digest_len();
        return boost::none;
    }
    std::string res;
    for (int i = 0; i < bin.size(); i += 4) {
        std::string tmp;
        for (int j = i; j < i + 4; j++) {
            tmp.push_back(bin[j] == true ? '1' : '0');
        }
        if (tmp == "0000")
            res.push_back('0');
        else if (tmp == "0001")
            res.push_back('1');
        else if (tmp == "0010")
            res.push_back('2');
        else if (tmp == "0011")
            res.push_back('3');
        else if (tmp == "0100")
            res.push_back('4');
        else if (tmp == "0101")
            res.push_back('5');
        else if (tmp == "0110")
            res.push_back('6');
        else if (tmp == "0111")
            res.push_back('7');
        else if (tmp == "1000")
            res.push_back('8');
        else if (tmp == "1001")
            res.push_back('9');
        else if (tmp == "1010")
            res.push_back('a');
        else if (tmp == "1011")
            res.push_back('b');
        else if (tmp == "1100")
            res.push_back('c');
        else if (tmp == "1101")
            res.push_back('d');
        else if (tmp == "1110")
            res.push_back('e');
        else if (tmp == "1111")
            res.push_back('f');
    }
    return res;
}

std::string hexToChar(const char c) {
    switch(tolower(c))
    {
        case '0': return "0000";
        case '1': return "0001";
        case '2': return "0010";
        case '3': return "0011";
        case '4': return "0100";
        case '5': return "0101";
        case '6': return "0110";
        case '7': return "0111";
        case '8': return "1000";
        case '9': return "1001";
        case 'a': return "1010";
        case 'b': return "1011";
        case 'c': return "1100";
        case 'd': return "1101";
        case 'e': return "1110";
        case 'f': return "1111";
    }
}

libff::bit_vector hexToBin(std::string& str) {
    libff::bit_vector res;
    for (auto item : str) {
        std::string hexItem = hexToChar(item);
        res.push_back(hexItem[0] == '1' ? true : false);
        res.push_back(hexItem[1] == '1' ? true : false);
        res.push_back(hexItem[2] == '1' ? true : false);
        res.push_back(hexItem[3] == '1' ? true : false);
    }
    return res;
}

std::vector<std::string> split(std::string& str, std::string delim) {
    std::vector<std::string> res;
    auto start = 0U;
    auto end = str.find(delim);
    while (end != std::string::npos)
    {
        std::cout << str.substr(start, end - start) << std::endl;
        res.push_back(str.substr(start, end - start));
        start = end + delim.length();
        end = str.find(delim, start);
    }
    return res;
}

template<typename HashT>
libff::bit_vector hash256(std::string str) {
    libff::bit_vector operand;
    for (int i = 0; i < str.size(); i++) {
        char tmpc[5];
        sprintf(tmpc, "%x", str[i]);
        std::string tmps(tmpc);
        libff::bit_vector s = hexToBin(tmps);
        operand.insert(operand.end(), s.begin(), s.end());
    }
    //padding input
    size_t size = operand.size();
    char tmpc[20];
    sprintf(tmpc, "%x", size);
    std::string tmps(tmpc);
    libff::bit_vector s = hexToBin(tmps);
    operand.push_back(1);
    for (int i = size + 1; i < HashT::get_block_len() - s.size(); i++) {
        operand.push_back(0);
    }
    operand.insert(operand.end(), s.begin(), s.end());
    libff::bit_vector res = HashT::get_hash(operand);
    return res;
}

template<typename HashT>
void calcAllLevels(std::vector<std::vector<libff::bit_vector>>& levels, size_t level) {
    //level 1 upper layer
    for (int i = level; i > 0; i--) {
        for (int j = 0; j < levels[i].size(); j += 2) {
            libff::bit_vector input = levels[i][j];
            input.insert(input.end(), levels[i][j+1].begin(), levels[i][j+1].end());
            levels[i-1].push_back(HashT::get_hash(input));
        }
    }
}

int main(int argc, char* argv[]) {
    libff::default_ec_pp::init_public_params();
    typedef libff::default_ec_pp ppzksnark_ppT;
    typedef libff::Fr<ppzksnark_ppT> FieldT;
    typedef sha256_two_to_one_hash_gadget<FieldT> HashT;

    const size_t tree_depth = 3;
    if (std::string(argv[1]) == "generate") {
        const size_t digest_len = HashT::get_digest_len();
        std::vector<merkle_authentication_node> path(tree_depth);

        libff::bit_vector prev_hash(digest_len);
        std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
        libff::bit_vector leaf = prev_hash;

        libff::bit_vector address_bits;

        size_t address = 0;
        for (long level = tree_depth-1; level >= 0; --level)
        {
            const bool computed_is_right = (std::rand() % 2);
            address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
            address_bits.push_back(computed_is_right);
            libff::bit_vector other(digest_len);
            std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });

            libff::bit_vector block = prev_hash;
            block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
            libff::bit_vector h = HashT::get_hash(block);

            std::cout << *(binToHex<HashT>(block)) << std::endl;
            std::cout  << "h: " << *(binToHex<HashT>(h)) << std::endl;
            path[level] = other;

            prev_hash = h;
        }
        libff::bit_vector root = prev_hash;

        auto hexLeaf = binToHex<HashT>(leaf);
        std::fstream mk("merkle.txt", std::ios_base::out);
        mk << "leaf: " << *hexLeaf << std::endl; //Write out leaf
        mk << "index: " << address << std::endl; //Write out index
        mk << "path: ";                          //Write out path
        for (int i = 0; i < path.size(); i++)
            mk << *(binToHex<HashT>(path[i])) << " ";
        mk << std::endl;
        mk << "root: " << *(binToHex<HashT>(root));      //Write out root
    } else if (std::string(argv[1]) == std::string("setup")) {
        auto keypair = generate_read_keypair<ppzksnark_ppT, FieldT, HashT>(tree_depth);
        std::fstream pk("merkle_pk.raw", std::ios_base::out);
        pk << keypair.pk;
        pk.close();
        std::fstream vk("merkle_vk.raw", std::ios_base::out);
        vk << keypair.vk;
        vk.close();
    } else if (std::string(argv[1]) == std::string("prove")) {
        //load pk
        std::fstream f_pk("merkle_pk.raw", std::ios_base::in);
        r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> pk;
        f_pk >> pk;
        f_pk.close();

        libff::bit_vector leaf, root, address_bits(tree_depth);
        size_t address;
        std::vector<merkle_authentication_node> path(tree_depth);

        //generate witness
        std::vector<std::vector<libff::bit_vector>> levels(tree_depth);
        //level 2 leaves left most --> right most
	int leaf_count = std::pow(2, tree_depth);
        for (int i = 0; i < leaf_count; i++) {
            libff::bit_vector tmp = hash256<HashT>(argv[i+2]);
            //std::cout << *binToHex<HashT>(tmp) << std::endl;
            levels[tree_depth - 1].push_back(tmp);
        }

	calcAllLevels<HashT>(levels, tree_depth-1);
        libff::bit_vector input = levels[0][0];
        input.insert(input.end(), levels[0][1].begin(), levels[0][1].end());
        root = HashT::get_hash(input);

        address = std::stoi(argv[10]);
        leaf = levels[tree_depth-1][address];
        std::cout << address << std::endl;
        int addr = address;
        for (int i = 0; i < tree_depth; i++) {
            int tmp = (addr & 0x01);
            address_bits[i] = tmp;
            addr = addr / 2;
            std::cout << address_bits[tree_depth-1-i] << std::endl;
        }

        //Fill in the path
        size_t index = address;
        for (int i = tree_depth - 1; i >= 0; i--) {
            path[i] = address_bits[tree_depth-1-i] == 0 ? levels[i][index+1] : levels[i][index-1];
            index = index / 2;
        }
        std::cout << "root is " << *binToHex<HashT>(root) << std::endl;

	//generate proof
        auto proof = generate_read_proof<ppzksnark_ppT, FieldT, HashT>(
                pk, tree_depth, leaf, root, path, address, address_bits);
        if (proof != boost::none) {
            std::cout << "Proof generated!" << std::endl;
        }

	//save the proof
        std::fstream pr("proof.raw", std::ios_base::out);
        pr << (*proof);
        pr.close();

    } else if (std::string(argv[1]) == std::string("verify")) {
	//load proof
        std::fstream pr("proof.raw", std::ios_base::in);
        r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof;
        pr >> proof;
        pr.close();
	//load vk
        std::fstream vkf("merkle_vk.raw", std::ios_base::in);
        r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> vk;
        vkf >> vk;
        vkf.close();

	//load root
        std::string r(argv[2]);
        libff::bit_vector root = hexToBin(r);
	//verify the proof
        bool ret = verify_read_proof<ppzksnark_ppT, FieldT>(vk, proof, root);
        if (ret) {
            std::cout << "Verification pass!" << std::endl;
        } else {
            std::cout << "Verification failed!" << std::endl;
        }
    }

    return 0;
}

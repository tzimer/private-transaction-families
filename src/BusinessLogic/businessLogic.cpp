/*
* Copyright 2018 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <stdio.h>
#include <stdexcept>
#include <algorithm>
#include "businessLogic.h"
#include "bl_internal.h"
#include "bl_access_txns.h"
#include "access_control.h"
#include "acl_read_write.h"
#include "config.h"
#include "crypto.h"
#include "enclave_log.h"
#include "secure_allocator.h"


// add secure string support to json parser
namespace nlohmann
{
template <>
struct adl_serializer<secure::string>
{
    static void to_json(json &j, const secure::string &value)
    {
        j = std::string(value.c_str()); // calls to_json with std string
    }

    static void from_json(const json &j, secure::string &value)
    {
        value = secure::string(j.get<std::string>().c_str());
    }
};
} // namespace nlohmann

namespace business_logic
{

/*lass Transaction {

    protected:
     config::Actions m_action;
     SignerPubKey m_signerPubKey;
     uint16_t m_svn;
     secure::string m_nonce;
     StlAddress m_addr;

    public:
    std::pair<bool, nlohmann::json> readAddress(const StlAddress &addr, const SignerPubKey &signerPubKey, const uint16_t &svn);
    bool WriteJsonToAddress(const nlohmann::json &json, const StlAddress &addr, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce );
    secure::string getNonce(){return m_nonce};
    uint16_t getSyslogEquivalent(){return m_svn};
    SignerPubKey getSignerPubKey() {return m_signerPubKey}; 
    std::pair<bool, StlAddress> getAddress(const secure::string &prefix, const secure::string &subprefix, const SignerPubKey &signerPubKey);
    Transaction(const config::Actions &action, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
    {
        m_action = action;
        m_svn = svn;
        m_nonce = nonce;
        m_addr = addr;
    }
    
};

// Derived class
class AddUser: public Transaction {
    
    protected:
    secure::string m_name;
    secure::string m_timestamp;
    secure::string m_uid;
    secure::string m_email;
    secure::string m_url;


   public:
      AddUser(const secure::string &name, const secure::string &timestamp, const secure::string &uid, const secure::string &email, const secure::string &url)
      {
          m_name = name;
          m_timestamp = timestamp;
          m_uid = uid;
          m_email = email;
          m_url = url;
      }


};*/

secure::string getSubAddress(SubAddress addr)
{
  switch (addr)
  {
    case USER: return secure::string("00");
    case BALANCE: return secure::string("01");
    case BUNNIES: return secure::string("02");
    case COUPLES: return secure::string("03");
  }
}

config::Actions get_action(const secure::string &action)
{
    {
        if (action == config::add_user.c_str())
            return config::Actions::ADD_USER;
        if (action == config::remove_user.c_str())
            return config::Actions::REMOVE_USER;
        if (action == config::set_balance.c_str())
            return config::Actions::SET_BALANCE;
        if (action == config::change_balance.c_str())
            return config::Actions::CHANGE_BALANCE;
        if (action == config::add_bunny.c_str())
           return config::Actions::ADD_BUNNY;
        if (action == config::change_bunny_state.c_str())
            return config::Actions::CHANGE_BUNNY_STATE;
        if (action == config::add_couple.c_str())
            return config::Actions::ADD_COUPLE;
        if (action == config::remove_couple.c_str())
            return config::Actions::REMOVE_COUPLE;

        //if (action == config::change_carrots_balance.c_str())
            //return config::Actions::CHANGE_CARROTS_BALANCE;

        return config::Actions::INVALID_ACCTION;
    }
}

bool payloadToParams(const secure::string &payload, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
{
    config::Actions action;

    try
    {
        PRINT(INFO, LOGIC, "paylaod is %s\n", payload.c_str());
        auto json = nlohmann::json::parse(payload);
        action = get_action(json.at(config::action_str).get<secure::string>());
        if (action == config::Actions::INVALID_ACCTION)
        {
            PRINT(ERROR, LOGIC, "invalid action type %s\n", json.at(config::action_str).get<secure::string>().c_str());
            return false;
        }

       

        switch (action)
        {

        case config::Actions::ADD_USER:
        {

            secure::string name, timestamp, uid, email, url;
          
            json.at("UID").get_to(uid);
            json.at("Name").get_to(name);
            json.at("Timestamp").get_to(timestamp);
            json.at("Email").get_to(email);
            json.at("Url").get_to(url);

            return AddUser(name, timestamp, uid, email, url, signerPubKey, svn, nonce);
        }
        case config::Actions::SET_BALANCE:
        {
            secure::string uid; 
            json.at("UID").get_to(uid);
            int money_balance, carrots_balance;

            carrots_balance = json["Carrots"].get<int>();
            money_balance = json["Money"].get<int>();
            
            return SetBalance(uid, money_balance, carrots_balance,signerPubKey, svn, nonce);
        }
        case config::Actions::CHANGE_BALANCE:
        {
            secure::string uid; 
            json.at("UID").get_to(uid);
            bool res = false; 
            int change_in_money, change_in_carrots;

            secure::string money =  secure::string("Money");
            secure::string carrots =  secure::string("Carrots");
                      
            
            if ((json.find(money.c_str()) != json.end()) )
            {
                change_in_money = json[money.c_str()].get<int>();
                res =  ChangeBalance(uid, money, change_in_money, signerPubKey, svn, nonce);

            }

            if ((json.find(carrots.c_str()) != json.end()) )
            {
                change_in_carrots = json[carrots.c_str()].get<int>();
                res =  ChangeBalance(uid, carrots, change_in_carrots, signerPubKey, svn, nonce);

            }
            return res;
            
        }
        case config::Actions::CHANGE_BUNNY_STATE:
        {
            secure::string bunny, state, uid;

            json.at("UID").get_to(uid);
            json.at("Bunny").get_to(bunny);
                   
            if ((json.find("State") == json.end()) )
            {
                PRINT(ERROR, LOGIC, " Action was change state, but state wasnt found\n");
                return false;            
            }
                
            json.at("State").get_to(state);
            return ChangeBunnyState(uid, bunny, state, signerPubKey, svn, nonce);
                          
        }
        case config::Actions::ADD_BUNNY:
        {
            secure::string uid, bunny, state;
            bool isNew;
            uint16_t generation;

            json.at("UID").get_to(uid);
            json.at("Bunny").get_to(bunny);
            json.at("State").get_to(state);
            if((json.find("Generation") == json.end()) || (json.find("IsNew") == json.end()))
            {
                PRINT(ERROR, LOGIC, " Too few arguments for add_bunny transaction\n");
                return false;
            }
            generation = json["Generation"].get<int>();
            isNew = json["IsNew"].get<bool>();

            return AddBunny(uid, bunny, generation, isNew, state, signerPubKey, svn, nonce);
        }
        case config::Actions::ADD_COUPLE:
        {
            secure::string uid, bunny, inLoveWith, timeStr;
            uint16_t sonGeneration, loveTime;
            uint64_t timestamp;

            json.at("UID").get_to(uid);
            json.at("Bunny").get_to(bunny);
            sonGeneration = json["SonGeneration"].get<int>();
            loveTime = json["LoveTime"].get<int>();
            timestamp = json["Timestamp"].get<int>();
            json.at("InLoveWith").get_to(inLoveWith);
            json.at("TimeStr").get_to(timeStr);

            return AddCouple(uid, bunny, inLoveWith, loveTime, sonGeneration, timeStr, timestamp,signerPubKey, svn, nonce);
        

        }
        case config::Actions::REMOVE_COUPLE:
        {
            secure::string uid, bunny;
            json.at("UID").get_to(uid);
            json.at("Bunny").get_to(bunny);

            return RemoveCouple(uid, bunny,signerPubKey, svn);
        }
       
        default:
        {
            PRINT(ERROR, LOGIC, "do_acl_action error\n");
            return false;
        }
          
            
        }
    }
    catch (const std::exception &e)
    {
        PRINT(ERROR, LOGIC, "exception when trying to parse txn payload as json\n");
        PRINT(INFO, LOGIC, "%s\n", e.what());
        return false;
    }
}

std::pair<bool, StlAddress> getAddress(const secure::string &prefix, const secure::string &subprefix, const SignerPubKey &signerPubKey)
{
    sha512_data_t shaRes = {};
    StlAddress addr = {};
    auto prefix_len = prefix.size();
    if (prefix.empty())
    {
        config::get_prefix().copy(addr.address_32_32.family.data(), addr.address_32_32.family.size());

        if (!sha512_msg((const uint8_t *)signerPubKey.data(), PUB_KEY_LENGTH, &shaRes))
        {
            PRINT(ERROR, LOGIC, "failed to calculate signer key hash!!\n")
            return std::make_pair(false, addr);
        }
        secure::string str = ToHexString(shaRes.data, addr.address_32_32.member_id.size() / 2);
        str.copy(addr.address_32_32.member_id.data(), addr.address_32_32.member_id.size());
        prefix_len = addr.address_32_32.family.size() + addr.address_32_32.member_id.size();
    }
    else
    {
        prefix.copy(addr.val.data(), prefix_len);
    }

    secure::string str = subprefix;
    int pad = addr.val.size() - prefix_len - subprefix.size();
    while( pad > 0)
    {
        str += "0";
        pad --;
    }
    str.copy(addr.val.data() + prefix_len, addr.val.size() - 1 - prefix_len);
    addr.properties.null_terminator[0] = '\0';
    
    //PRINT(INFO, LOGIC, "got address : %s !!!\n", addr.val.data());
    return std::make_pair(true, addr);
}

bool IsUserExists(const secure::string &uid, const SignerPubKey &signerPubKey, const uint16_t &svn)//, secure::string* out_value, bool is_client_reader)
{
    
    StlAddress addr;
    bool status;
    std::tie(status, addr) = getAddress(uid, getSubAddress(USER), signerPubKey);

    if(!status){return false;}

    nlohmann::json json;
    std::tie(status, json) = readAddress(addr, signerPubKey, svn);
    
    if(!status){return false;}

    if (json.empty())
    {
        return false;
    }

    return true;
}


std::pair<bool, nlohmann::json> readAddress(const StlAddress &addr, const SignerPubKey &signerPubKey, const uint16_t &svn)
{
    nlohmann::json json;

    secure::vector<uint8_t> state_value;
    if (!acl::acl_read(addr, signerPubKey, state_value, svn))
    {
        PRINT(ERROR, LOGIC, "acl read returened failure\n");
        return std::make_pair(false, json);
    }

    try
    {
        if(!state_value.empty())
        {
            json = nlohmann::json::from_cbor(state_value);       
        }
        return std::make_pair(true, json);
    }
    catch (const std::exception &e)
    {
        PRINT(ERROR, LOGIC, "failed to parse state data as json\n");
        PRINT(INFO, LOGIC, "%s\n", e.what());
        return std::make_pair(false, json);
    }
}

bool AddBunny(const secure::string  &uid, const secure::string  &bunny, const uint16_t &generation, const bool &isNew, const secure::string &state, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
{
   
    StlAddress addr;
    bool status;

    if(!IsUserExists(uid, signerPubKey, svn))
    {
        PRINT(ERROR, LOGIC, "Cannot assosiate the rquested transaction (add_bunny) as the user %s does not exists! \n", uid.c_str());
        return false;
    }

    secure::string sub_address = secure::string(getSubAddress(BUNNIES)+bunny);
    
    std::tie(status, addr) = getAddress(uid, sub_address, signerPubKey);

    if(!status){return false;}
    
    nlohmann::json json;
    std::tie(status, json) = readAddress(addr, signerPubKey, svn);
    
    if(!status){return false;}

    if (!json.empty())
    {
       
        if (json.find("Bunny") != json.end())
        {
            PRINT(INFO, LOGIC, " Action was 'add_bunny', but bunny %s is already exists\n", bunny.c_str());
            return false;
        }
        
    }

    //write to address
    json["uid"] = uid.c_str();
    json["Bunny"] = bunny.c_str();
    json["State"] = state.c_str();
    json["Generation"] = generation;
    json["IsNew"] = isNew;
   
    
    return WriteJsonToAddress(json, addr, signerPubKey, svn, nonce);
}

bool RemoveCouple(const secure::string &uid, const secure::string &bunny, const SignerPubKey &signerPubKey, const uint16_t &svn)
{

    StlAddress addr;
    bool status;

    secure::string sub_address = secure::string(getSubAddress(COUPLES)+bunny);
    std::tie(status, addr) = getAddress(uid, sub_address, signerPubKey);

    if(!status){return false;}

    nlohmann::json json;
    std::tie(status, json) = readAddress(addr, signerPubKey, svn);
    
    if(!status){return false;}

    
    if (json.empty())
    {
        PRINT(ERROR, LOGIC, "Address %s is empty\n", addr.val.data());
        return false;
    }

    secure::vector<StlAddress> addressesToRemove;
    addressesToRemove.push_back(addr);

    if (!(acl::acl_delete(addressesToRemove, signerPubKey, svn)))
    {
        PRINT(ERROR, LOGIC, "Delete addr %s failed\n", addr.val.data());
        return false;
    }

    return true;
}

bool WriteJsonToAddress(const nlohmann::json &json, const StlAddress &addr, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce )
{
    auto cbor = nlohmann::json::to_cbor(json);
    secure::vector<uint8_t> secure_cbor(std::begin(cbor), std::end(cbor));
    
    if (FAILED(acl::acl_write(addr, signerPubKey, secure_cbor, svn, nonce)))
    {
        PRINT(INFO, LOGIC, "Write to addr %s failed\n", addr.val.data());
        return false;
    }

    return true;
}

bool AddCouple(const secure::string &uid, const secure::string &bunny, const secure::string &inLoveWith, const uint16_t &loveTime, const uint16_t &sonGeneration, const secure::string timeStr, uint64_t &timestamp, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string nonce)
{

 if(!IsUserExists(uid, signerPubKey, svn))
    {
        PRINT(ERROR, LOGIC, "Cannot assosiate the rquested transaction (add_couple) as the user %s does not exists! \n", uid.c_str());
        return false;
    }

    StlAddress bunny1_addr, bunny2_addr, addr;
    bool status, status1, status2;
    
    secure::string bunny1_sub_addr = secure::string(getSubAddress(BUNNIES)+bunny);
    secure::string bunny2_sub_addr = secure::string(getSubAddress(BUNNIES)+inLoveWith);

    std::tie(status1, bunny1_addr) = getAddress(uid, bunny1_sub_addr, signerPubKey);
    std::tie(status2, bunny2_addr) = getAddress(uid, bunny2_sub_addr, signerPubKey);

    if(!status1 || !status2){return false;}

    nlohmann::json json, json1, json2;
    std::tie(status1, json1) = readAddress(bunny1_addr, signerPubKey, svn);
    std::tie(status2, json2) = readAddress(bunny2_addr, signerPubKey, svn);
    
    if(!status1 || !status2){return false;}


    secure::string sub_address = secure::string(getSubAddress(COUPLES)+bunny);
    std::tie(status, addr) = getAddress(uid, sub_address, signerPubKey);
    
    if(!status){return false;}

    std::tie(status, json) = readAddress(addr, signerPubKey, svn);

    if(!status){return false;}


    if (!json.empty())
    { // not empty address
        if ( json.find("uid") != json.end())
        {
            PRINT(INFO, LOGIC, " Action was 'add_couple', but couple %s, %s is already exists\n", bunny.c_str(), inLoveWith.c_str());
            return false;
        }
    }

    //write to address
    json["uid"] = uid.c_str();
    json["Bunny"] = bunny.c_str();
    json["InLoveWith"] = inLoveWith.c_str();
    json["SonGeneration"] = sonGeneration;
    json["LoveTime"] = loveTime;
    json["TimeStr"] = timeStr.c_str();
    json["Timestamp"] = timestamp;

    return WriteJsonToAddress(json, addr, signerPubKey, svn, nonce);
  
} 

// Handle an IntKey 'set' verb action. This sets a IntKey value to
// the given value.
bool AddUser(const secure::string &name, const secure::string &timestamp, const secure::string &uid, const secure::string &email, const secure::string &url, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
{
    StlAddress addr;
    bool status;
       
    secure::string sub_address = getSubAddress(USER);
    std::tie(status, addr) = getAddress(uid, sub_address, signerPubKey);
    if(!status){return false;}

    nlohmann::json json; 
    std::tie(status, json) = readAddress(addr, signerPubKey, svn);

    if(!status){return false;}


    if (!json.empty())
    { // not empty address
        if (json.find("uid") != json.end())
        {
            PRINT(INFO, LOGIC, " Action was 'add_user', but uid %s is already exists\n", uid.c_str());
            return false;
        }       
    }

    //add access
    secure::vector<secure::string> addresses;
    secure::vector<SignerPubKey> keys;

    addresses.push_back(addr.val.data());
    keys.push_back(signerPubKey);

    if (!acl::add_access_to_members(addresses, keys, svn, nonce))
    {
        PRINT(ERROR, LOGIC, "acl add_access_to_members failure\n");
        return false;
    }

    //write to address
    json["uid"] = uid.c_str();
    json["timestamp"] = timestamp.c_str();
    json["name"] = name.c_str();
    json["email"] = email.c_str();
    json["photo_url"] = url.c_str();
    
    return WriteJsonToAddress(json, addr, signerPubKey, svn, nonce);
}

bool ChangeBunnyState(const secure::string &uid, const secure::string &bunny,  const secure::string newState, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
{
    if(!IsUserExists(uid, signerPubKey, svn))
    {
        PRINT(ERROR, LOGIC, "Cannot assosiate the rquested transaction (change_bunny_state) as the user %s does not exists! \n", uid.c_str());
        return false;
    }

    StlAddress addr;
    bool status;
    secure::string sub_address = getSubAddress(BUNNIES) + bunny.c_str();
    std::tie(status, addr) = getAddress(uid, sub_address, signerPubKey);
    
    if(!status){return false;}
    
    nlohmann::json json; 
    std::tie(status, json) = readAddress(addr, signerPubKey, svn);

    if(!status){return false;}

    //empty address
    if (json.empty()) 
    {
        PRINT(ERROR, LOGIC, " Action was 'change_bunny_state', but address not found, please submit add_bunny transaction first\n");
        return false;
    }

    // not empty address
    //check if the required field exists in the address
    if (json.find("State") == json.end())
    {
        PRINT(ERROR, LOGIC, "Action was 'change_bunny_state', but the field does not exists in the address\n");
        return false;
    }
    //change balance
    auto val = json["State"];
    val = newState;
    json["State"] = val;
   
    return WriteJsonToAddress(json, addr, signerPubKey, svn, nonce);
   
}


bool ChangeBalance(const secure::string &uid, const secure::string &fieldToChange,  const int &value, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
{
    if(!IsUserExists(uid, signerPubKey, svn))
    {
        PRINT(ERROR, LOGIC, "Cannot assosiate the rquested transaction (change_balance) as the user %s does not exists! \n", uid.c_str());
        return false;
    }

    StlAddress addr;
    bool status;
    secure::string sub_address = getSubAddress(BALANCE);
    std::tie(status, addr) = getAddress(uid, sub_address, signerPubKey);
    
    if(!status){return false;}
    
    nlohmann::json json; 
    std::tie(status, json) = readAddress(addr, signerPubKey, svn);

    if(!status){return false;}

    
    //empty address
    if (json.empty()) 
    {
        PRINT(INFO, LOGIC, " Action was 'change_balance', but address not found, please submit set_balance transaction first\n");
        return false;
    }

    //check if the required field exists in the address
    if (json.find(fieldToChange.c_str()) == json.end())
    {
        PRINT(INFO, LOGIC, "Action was 'change_%s', but the field does not exists in the address\n",fieldToChange.c_str());
        return false;
    }
    //change balance
    auto val = json[fieldToChange.c_str()].get<int>();
    val += value;
    json[fieldToChange.c_str()] = val;
   
    return WriteJsonToAddress(json, addr, signerPubKey, svn, nonce);

}


bool SetBalance(const secure::string &uid, const int &money_balance, const int &carrots_balance, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
{

    if(!IsUserExists(uid, signerPubKey, svn))
    {
         PRINT(ERROR, LOGIC, "Cannot assosiate the rquested transaction (add_bunny) as the user %s does not exists! \n", uid.c_str());
       
        return false;
    }

    StlAddress addr;
    bool status;
    secure::string sub_address = getSubAddress(BALANCE);   
    std::tie(status, addr) = getAddress(uid, sub_address, signerPubKey);
    
    if(!status){return false;}
    
    nlohmann::json json; 
    std::tie(status, json) = readAddress(addr, signerPubKey, svn);

    if(!status){return false;}

    if (!json.empty())
    { // not empty address    
            if (json.find(uid.c_str()) != json.end())
            {
                PRINT(INFO, LOGIC, " Action was 'set_balance', but balance for uid %s is already exists\n", uid.c_str());
                return false;
            }
    }

    json["uid"] = uid.c_str();
    json["Carrots"] = carrots_balance;
    json["Money"] = money_balance;
   
    return WriteJsonToAddress(json, addr, signerPubKey, svn, nonce);
}


bool execute_transaction(const secure::string &payload, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
{
    if (business_logic::is_acl_txn(payload))
    {
        return do_acl_action(payload, signerPubKey, svn, nonce).first;
    }

    int addr_len;
    if (!payloadToParams(payload, signerPubKey, svn, nonce))
        return false;
    return true;
}

bool bl_read(const StlAddress &addr, const SignerPubKey &key, secure::string *out_value, const uint16_t &svn)
{
    secure::vector<uint8_t> data_vec;
    if (!acl::acl_read(addr, key, data_vec, svn, true))
        return false;
    if (data_vec.empty())
    {
        *out_value = "";
        return true;
    }
    try
    {
        auto json = nlohmann::json::from_cbor(data_vec);
        *out_value = json.dump().c_str();
        return true;
    }
    catch (const std::exception &e)
    {
        PRINT(ERROR, LOGIC, "failed to parse state data as json, showing as hex string\n");
        PRINT(INFO, LOGIC, "%s\n", e.what());
        *out_value = ToHexString(data_vec.data(), data_vec.size());
        return true;
    }
}
} // namespace business_logic

                //auto it = json.value("uid", "");
               // PRINT(INFO, LOGIC, " Value is %s \n", it.c_str());

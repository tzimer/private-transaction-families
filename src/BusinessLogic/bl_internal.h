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

#pragma once
#include "secure_allocator.h"
#include "PrivateLedger.h"
#include "config.h"
#include "json.hpp"

namespace business_logic
{
enum SubAddress {USER, BALANCE, BUNNIES, COUPLES};
bool payloadToParams(const secure::string &payload,const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce);
std::pair<bool, StlAddress> getAddress(const secure::string &prefix, const secure::string &subprefix , const SignerPubKey &signerPubKey);
// Handle an IntKey 'set' verb action. This sets a IntKey value to
// the given value.
secure::string getSubAddress(SubAddress e);
config::Actions get_action(const secure::string &payload);
bool AddUser(const secure::string &name, const secure::string &timestamp, const secure::string &uid, const secure::string &email, const secure::string &photoUrl, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string& nonce);
bool AddCouple(const secure::string &uid, const secure::string &bunny, const secure::string &inLoveWith, const uint16_t &loveTime, const uint16_t &sonGeneration, const secure::string timeStr, uint64_t &timestamp, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string nonce);
bool RemoveCouple(const secure::string &uid, const secure::string &bunny, const SignerPubKey &signerPubKey, const uint16_t &svn);
bool WriteJsonToAddress(const nlohmann::json &json, const StlAddress &addr, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce );

//bool IsAddressExists(const StlAddress &addr, const SignerPubKey &signerPubKey, const uint16_t &svn);
// Handle an IntKey 'inc' and 'dec' verb action. This increments an IntKey value
// stored in global state by a given value.

bool IsUserExists(const secure::string &uid, const SignerPubKey &signerPubKey, const uint16_t &svn);
std::pair<bool, nlohmann::json> readAddress(const StlAddress &addr, const SignerPubKey &signerPubKey, const uint16_t &svn);

bool AddBunny(const secure::string  &uid, const secure::string  &bunny, const uint16_t &generation, const bool &isNew, const secure::string &state, const SignerPubKey &SignerPubKey, const uint16_t &svn, const secure::string &nonce);
bool ChangeBalance(const secure::string &uid, const secure::string &field_to_change ,const int &change, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce);

bool ChangeBunnyState(const secure::string &uid, const secure::string &bunny,  const secure::string newState, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce);
bool SetBalance(const secure::string &uid, const int &money_balance, const int &carrots_balance, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce);
bool DoIncDec(const secure::string &name, const int value, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string& nonce);
}
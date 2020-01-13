/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <utility>

#include "base/base64.h"
#include "base/json/json_writer.h"
#include "base/values.h"
#include "bat/ledger/internal/bat_util.h"
#include "bat/ledger/internal/ledger_impl.h"
#include "bat/ledger/internal/contribution/contribution_unblinded.h"
#include "bat/ledger/internal/request/promotion_requests.h"
#include "brave_base/random.h"
#include "net/http/http_status_code.h"

#include "wrapper.hpp"  // NOLINT

using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;

using challenge_bypass_ristretto::UnblindedToken;
using challenge_bypass_ristretto::VerificationKey;
using challenge_bypass_ristretto::VerificationSignature;

namespace {

std::string ConvertTypeToString(const ledger::RewardsType type) {
  switch (static_cast<int>(type)) {
    case static_cast<int>(ledger::RewardsType::AUTO_CONTRIBUTE): {
      return "auto-contribute";
    }
    case static_cast<int>(ledger::RewardsType::ONE_TIME_TIP): {
      return "oneoff-tip";
    }
    case static_cast<int>(ledger::RewardsType::RECURRING_TIP): {
      return "recurring-tip";
    }
    default: {
      // missing conversion, returning dummy value.
      NOTREACHED();
      return "oneoff-tip";
    }
  }
}

void GenerateSuggestionMock(
    ledger::UnblindedTokenPtr token,
    const std::string& suggestion_encoded,
    base::Value* result) {
  if (!token) {
    return;
  }

  result->SetStringKey("t", token->token_value);
  result->SetStringKey("publicKey", token->public_key);
  result->SetStringKey("signature", token->token_value);
}

void GenerateSuggestion(
    ledger::UnblindedTokenPtr token,
    const std::string& suggestion_encoded,
    base::Value* result) {
  if (!token) {
    return;
  }

  UnblindedToken unblinded = UnblindedToken::decode_base64(token->token_value);
  VerificationKey verification_key = unblinded.derive_verification_key();
  VerificationSignature signature = verification_key.sign(suggestion_encoded);
  const std::string pre_image = unblinded.preimage().encode_base64();

  if (challenge_bypass_ristretto::exception_occurred()) {
    challenge_bypass_ristretto::TokenException e =
        challenge_bypass_ristretto::get_last_exception();
    return;
  }

  result->SetStringKey("t", pre_image);
  result->SetStringKey("publicKey", token->public_key);
  result->SetStringKey("signature", signature.encode_base64());
}

bool HasTokenExpired(ledger::UnblindedTokenPtr token) {
  if (!token) {
    return true;
  }

  const uint64_t now = static_cast<uint64_t>(base::Time::Now().ToDoubleT());

  return token->expires_at > 0 && token->expires_at < now;
}

std::string GenerateTokenPayload(
    const std::string& publisher_key,
    const ledger::RewardsType type,
    ledger::UnblindedTokenList list) {
  base::Value suggestion(base::Value::Type::DICTIONARY);
  suggestion.SetStringKey("type", ConvertTypeToString(type));
  suggestion.SetStringKey("channel", publisher_key);

  std::string suggestion_json;
  base::JSONWriter::Write(suggestion, &suggestion_json);
  std::string suggestion_encoded;
  base::Base64Encode(suggestion_json, &suggestion_encoded);

  base::Value credentials(base::Value::Type::LIST);
  for (auto & item : list) {
    base::Value token(base::Value::Type::DICTIONARY);
    if (ledger::is_testing) {
      GenerateSuggestionMock(std::move(item), suggestion_encoded, &token);
    } else {
      GenerateSuggestion(std::move(item), suggestion_encoded, &token);
    }
    credentials.GetList().push_back(std::move(token));
  }

  base::Value payload(base::Value::Type::DICTIONARY);
  payload.SetStringKey("suggestion", suggestion_encoded);
  payload.SetKey("credentials", std::move(credentials));

  std::string json;
  base::JSONWriter::Write(payload, &json);
  return json;
}

}  // namespace

namespace braveledger_contribution {

Unblinded::Unblinded(bat_ledger::LedgerImpl* ledger) : ledger_(ledger) {
}

Unblinded::~Unblinded() = default;

void Unblinded::Initialize() {
  auto callback = std::bind(&Unblinded::OnGetNotCompletedContributions,
      this,
      _1);
  ledger_->GetNotCompletedContributions(callback);
}

void Unblinded::OnGetNotCompletedContributions(
    ledger::ContributionInfoList list) {
  if (list.size() == 0) {
    return;
  }
}

void Unblinded::Start(const std::string& contribution_id) {
    ledger_->GetAllUnblindedTokens(
      std::bind(&Unblinded::OnUnblindedTokens,
                this,
                contribution_id,
                _1));
}

void Unblinded::OnUnblindedTokens(
    const std::string& contribution_id,
    ledger::UnblindedTokenList list) {
  if (list.empty()) {
    ContributionCompleted(ledger::Result::NOT_ENOUGH_FUNDS, contribution_id);
    return;
  }

  ledger_->GetContributionInfo(contribution_id,
      std::bind(&Unblinded::OnUnblindedTokens,
                this,
                _1,
                std::move(list)));
}

void Unblinded::OnUnblindedTokens(
    ledger::ContributionInfoPtr contribution,
    ledger::UnblindedTokenList list) {
    if (!contribution) {
    ContributionCompleted(ledger::Result::LEDGER_ERROR, contribution_id);
    return;
  }

  double current_amount = 0.0;
  ledger::UnblindedTokenList token_list;
  std::vector<std::string> delete_list;
  for (auto & item : list) {
    if (HasTokenExpired(item->Clone())) {
      delete_list.push_back(std::to_string(item->id));
      continue;
    }

    if (current_amount >= contribution->amount) {
      break;
    }

    current_amount += item->value;
    token_list.push_back(std::move(item));
  }

  if (delete_list.size() > 0) {
    ledger_->DeleteUnblindedTokens(delete_list, [](const ledger::Result _){});
  }

  if (current_amount < contribution->amount) {
    ContributionCompleted(ledger::Result::NOT_ENOUGH_FUNDS, contribution_id);
    return;
  }

  MakeContribution(
      contribution_id,
      std::move(token_list),
      std::move(contribution));
}

void Unblinded::MakeContribution(
    const std::string& contribution_id,
    ledger::UnblindedTokenList list,
    ledger::ContributionInfoPtr contribution) {
  if (contribution->type == ledger::RewardsType::ONE_TIME_TIP ||
      contribution->type == ledger::RewardsType::RECURRING_TIP) {
    const auto callback = std::bind(&Unblinded::TipContributionCompleted,
        this,
        _1,
        contribution_id);
    SendTokens(
        contribution->publishers.front().publisher_key,
        contribution->type,
        std::move(list),
        callback);

  ledger_->UpdateContributionInfoStepAndCount(
      contribution_id,
      ledger::ContributionStep::STEP_SUGGESTIONS,
      0);
    return;
  }

  if (contribution->type == ledger::RewardsType::AUTO_CONTRIBUTE) {
    PrepareAutoContribution(
        contribution_id,
        std::move(list),
        std::move(contribution));
  }
}

void Unblinded::TipContributionCompleted(
    const ledger::Result result,
    const std::string& contribution_id) {
  if (result != ledger::Result::LEDGER_OK) {
    return;
  }
  ContributionCompleted(ledger::Result::LEDGER_OK, contribution_id);
}

bool Unblinded::GetStatisticalVotingWinner(
    double dart,
    const double amount,
    ledger::ContributionPublisherList* list,
    Winners* winners) const {
  if (!winners) {
    return false;
  }

  double upper = 0.0;
  for (const auto item : *list) {
    upper +=  / 100.0;
    if (upper < dart) {
      continue;
    }

    auto iter = winners->find(item.publisher_key);

    uint32_t current_value = 0;
    if (iter != winners->end()) {
      current_value = winners->at(item.publisher_key);
      winners->at(item.publisher_key) = current_value + 1;
    } else {
      winners->emplace(item.publisher_key, 1);
    }

    return true;
  }

  return false;
}

void Unblinded::GetStatisticalVotingWinners(
    uint32_t total_votes,
    const double amount,
    ledger::ContributionPublisherList list,
    Winners* winners) const {
  while (total_votes > 0) {
    double dart = brave_base::random::Uniform_01();
    if (GetStatisticalVotingWinner(dart, amount, list.get(), winners)) {
      --total_votes;
    }
  }
}

void Unblinded::PrepareAutoContribution(
    const std::string& contribution_id,
    ledger::UnblindedTokenList list,
    ledger::ContributionInfoPtr contribution) {
  if (list.size() == 0) {
    ContributionCompleted(ledger::Result::AC_TABLE_EMPTY, contribution_id);
    return;
  }

  const double total_votes = static_cast<double>(list.size());
  Winners winners;
  GetStatisticalVotingWinners(
      total_votes,
      contribution->amount,
      contribution->publishers,
      &winners);

  ledger::ContributionPublisherList publisher_list;
  uint32_t current_position = 0;
  for (auto & winner : winners) {
    if (winner.second == 0) {
      continue;
    }

    const std::string publisher_key = winner.first
    auto publisher = ledger::ContributionPublisher::New();
    publisher.publisher_key = publisher_key;
    direction.total_amount =
        (winner.second / total_votes) * contribution->amount;
    direction.contributed_amount = 0;
    publisher_list.push_back(std::move(publisher));

    const uint32_t new_position = current_position + winner.second;
    ledger::UnblindedTokenList token_list;
    for (size_t i = current_position; i < new_position; i++) {
      token_list.push_back(std::move(list[i]));
    }
    current_position = new_position;

    SendTokens(
        publisher_key,
        ledger::RewardsType::AUTO_CONTRIBUTE,
        std::move(token_list),
        [](const ledger::Result _){});
  }

  contribution.publishers = std::move(publisher_list);
  ledger_->SaveContributionInfo(
      std::move(contribution),
      [](const ledger::Result _){});
}

void Unblinded::SendTokens(
    const std::string& publisher_key,
    const ledger::RewardsType type,
    ledger::UnblindedTokenList list,
    SendTokensCallback callback) {
  if (publisher_key.empty() || list.empty()) {
    return callback(ledger::Result::LEDGER_ERROR);
  }

  std::vector<std::string> token_id_list;
  for (auto & item : list) {
    token_id_list.push_back(std::to_string(item->id));
  }

  auto url_callback = std::bind(&Unblinded::OnSendTokens,
      this,
      _1,
      _2,
      _3,
      token_id_list,
      callback);

  const std::string payload = GenerateTokenPayload(
      publisher_key,
      type,
      std::move(list));

  const std::string url =
      braveledger_request_util::GetReedemSuggestionsUrl();

  ledger_->LoadURL(
      url,
      std::vector<std::string>(),
      payload,
      "application/json; charset=utf-8",
      ledger::UrlMethod::POST,
      url_callback);
}

void Unblinded::OnSendTokens(
    const int response_status_code,
    const std::string& response,
    const std::map<std::string, std::string>& headers,
    const std::vector<std::string>& token_id_list,
    SendTokensCallback callback) {
  ledger_->LogResponse(__func__, response_status_code, response, headers);
  if (response_status_code != net::HTTP_OK) {
    callback(ledger::Result::LEDGER_ERROR);
    return;
  }

  // TODO we need to update publisher value in contribution_info_publishers

  ledger_->DeleteUnblindedTokens(token_id_list, [](const ledger::Result _){});
  callback(ledger::Result::LEDGER_OK);
}

void Unblinded::ContributionCompleted(
    const ledger::Result result,
    const std::string& contribution_id) {

  // fetch contribution info
  ledger_->ContributionCompleted(
      result,
      amount,
      contribution_id,
      type);
}

bool Unblinded::DoRetry(ledger::ContributionInfoPtr info) {
  if (!info) {
    return false;
  }

  if (info->step == ledger::ContributionStep::STEP_SUGGESTIONS) {
    // TODO go through all publisher
    // if all publishers contributed
    ContributionCompleted(
        ledger::ContributionStep::STEP_STEP_COMPLETED,
        info->amount,
        contribution_id);
  }

  return true;
}

}  // namespace braveledger_contribution

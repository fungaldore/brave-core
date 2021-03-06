/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_COMPONENTS_BRAVE_REWARDS_BROWSER_PROMOTION_H_
#define BRAVE_COMPONENTS_BRAVE_REWARDS_BROWSER_PROMOTION_H_

#include <stdint.h>
#include <string>

namespace brave_rewards {

struct Promotion {
  Promotion();
  ~Promotion();
  Promotion(const Promotion& properties);

  double amount;
  std::string promotion_id;
  uint64_t expires_at;
  uint32_t type;
  uint32_t status;
};

}  // namespace brave_rewards

#endif  // BRAVE_COMPONENTS_BRAVE_REWARDS_BROWSER_PROMOTION_H_

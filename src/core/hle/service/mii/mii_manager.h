// SPDX-FileCopyrightText: Copyright 2020 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <vector>

#include "core/hle/result.h"
#include "core/hle/service/mii/types.h"

namespace Service::Mii {

// The Mii manager is responsible for loading and storing the Miis to the database in NAND along
// with providing an easy interface for HLE emulation of the mii service.
class MiiManager {
public:
    MiiManager();

    bool CheckAndResetUpdateCounter(SourceFlag source_flag, u64& current_update_counter);
    bool IsFullDatabase() const;
    u32 GetCount(SourceFlag source_flag) const;
    ResultVal<MiiInfo> UpdateLatest(const MiiInfo& info, SourceFlag source_flag);
    MiiInfo BuildRandom(Age age, Gender gender, Race race);
    MiiInfo BuildDefault(std::size_t index);
    ResultVal<std::vector<MiiInfoElement>> GetDefault(SourceFlag source_flag);
    ResultCode GetIndex(const MiiInfo& info, u32& index);

private:
    const Common::UUID user_id{};
    u64 update_counter{};
};

}; // namespace Service::Mii

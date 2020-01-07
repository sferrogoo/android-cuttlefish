#pragma once

#include "Packetizer.h"

#include <https/RunLoop.h>

#include <memory>

#include <media/stagefright/foundation/ABuffer.h>
#include <source/StreamingSource.h>

struct OpusPacketizer
    : public Packetizer, public std::enable_shared_from_this<OpusPacketizer> {

    using StreamingSource = android::StreamingSource;

    explicit OpusPacketizer(
            std::shared_ptr<RunLoop> runLoop,
            std::shared_ptr<StreamingSource> audioSource);

    void run() override;
    uint32_t rtpNow() const override;
    android::status_t requestIDRFrame() override;

private:
    template<class T> using sp = android::sp<T>;
    using ABuffer = android::ABuffer;

    std::shared_ptr<RunLoop> mRunLoop;

    std::shared_ptr<StreamingSource> mAudioSource;

    size_t mNumSamplesRead;

    std::chrono::time_point<std::chrono::steady_clock> mStartTimeReal;
    int64_t mStartTimeMedia;
    bool mFirstInTalkspurt;

    void onFrame(const sp<ABuffer> &accessUnit);

    void packetize(const sp<ABuffer> &accessUnit, int64_t timeUs);
};



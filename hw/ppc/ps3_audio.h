/*
 * The PS3's sound output: the audio DMA ring the guest fills, played on the
 * host's audio backend.
 *
 * On hardware lv2's sys_rsxaudio owns a shared page of ring buffers and the
 * RSX's audio block pulls blocks of PCM from them.  This driver is that pull
 * side: rs6000-ps3 hands it each block the guest published and it goes out
 * through QEMU's audiodev, so cellAudio is audible under LLE.
 *
 * This work is licensed under the GNU GPL, version 2 or later.
 */

#ifndef HW_PPC_PS3_AUDIO_H
#define HW_PPC_PS3_AUDIO_H

#include "qemu/error-report.h"

typedef struct PS3Audio PS3Audio;

/*
 * Open the host backend named by an -audiodev id ("none" is silence).  A
 * machine without an audiodev gets the default backend when one exists.
 */
PS3Audio *ps3_audio_new(const char *audiodev_id, Error **errp);

/* True when a host backend is attached; the ring is drained either way. */
bool ps3_audio_active(const PS3Audio *a);

/*
 * Play one block of 32 stereo frames, each a big-endian IEEE float in
 * [-1, 1], which is the format sys_rsxaudio's serial rings carry.
 */
void ps3_audio_play_f32be(PS3Audio *a, const uint8_t *block);

/*
 * Capture: the console's microphone.
 *
 * cellMic sees a USB audio class device; on this machine the samples are the
 * host's capture input.  The voice is opened at the rate the guest asked for
 * when the backend accepts it and at the closest rate it does accept
 * otherwise - ps3_audio_mic_rate() is what cellMicGetFormat then reports, so
 * the guest is never told a rate it is not being fed.
 */
bool ps3_audio_mic_open(PS3Audio *a, unsigned rate, unsigned channels,
                        Error **errp);
void ps3_audio_mic_close(PS3Audio *a);
void ps3_audio_mic_start(PS3Audio *a, bool on);
bool ps3_audio_mic_active(const PS3Audio *a);
unsigned ps3_audio_mic_rate(const PS3Audio *a);
unsigned ps3_audio_mic_channels(const PS3Audio *a);

/*
 * Pull what the host captured since the last call: interleaved signed 16-bit
 * samples in host byte order, ps3_audio_mic_channels() of them per frame.  A
 * short read - 0 included - only means the input has not produced a full
 * block yet; the caller asks again on the next tick.
 */
size_t ps3_audio_mic_read(PS3Audio *a, void *buf, size_t max_bytes);

#endif /* HW_PPC_PS3_AUDIO_H */

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

#endif /* HW_PPC_PS3_AUDIO_H */

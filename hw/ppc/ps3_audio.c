/*
 * PS3 sound output through QEMU's audio subsystem.
 *
 * The guest side is sys_rsxaudio: lv2 hands the audio module a shared page
 * holding three ring buffers (serial/HDMI, and the two S/PDIF rings).  Each
 * entry names a 256-byte block of 32 stereo frames, stored as big-endian
 * floats.  This file turns those blocks into the host backend's format and
 * writes them out; the machine drains the ring and calls here.
 *
 * This work is licensed under the GNU GPL, version 2 or later.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/audio.h"
#include "qemu/module.h"

#include "ps3_audio.h"

#define PS3_AUDIO_FREQ      48000
#define PS3_AUDIO_CHANNELS  2
#define PS3_AUDIO_FRAMES    32

struct PS3Audio {
    AudioBackend *be;
    SWVoiceOut *voice;
    int16_t *pcm;           /* one block, converted for the backend */
    SWVoiceIn *in;          /* the microphone's capture voice */
    unsigned in_rate;       /* what the backend actually opened */
    unsigned in_channels;
};

static int16_t ps3_audio_sample(const uint8_t *p)
{
    union {
        uint32_t u;
        float f;
    } v;
    float f;

    v.u = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
          ((uint32_t)p[2] << 8) | p[3];
    f = v.f;

    if (!(f == f)) {
        return 0;           /* NaN: silence */
    }
    if (f >= 1.0f) {
        return INT16_MAX;
    }
    if (f <= -1.0f) {
        return INT16_MIN;
    }

    return (int16_t)(f * 32767.0f);
}

/* The backend only asks for more when its buffer drains; the ring timer
 * supplies the guest's blocks, so there is nothing to do here. */
static void ps3_audio_cb(void *opaque, int avail)
{
}

PS3Audio *ps3_audio_new(const char *audiodev_id, Error **errp)
{
    PS3Audio *a = g_new0(PS3Audio, 1);
    struct audsettings as = {
        .freq = PS3_AUDIO_FREQ,
        .nchannels = PS3_AUDIO_CHANNELS,
        .fmt = AUDIO_FORMAT_S16,
        .big_endian = HOST_BIG_ENDIAN,
    };

    if (audiodev_id && *audiodev_id) {
        a->be = audio_be_by_name(audiodev_id, errp);
        if (!a->be) {
            g_free(a);
            return NULL;
        }
    } else {
        a->be = audio_get_default_audio_be(errp);
        if (!a->be) {
            g_free(a);
            return NULL;
        }
    }

    a->voice = audio_be_open_out(a->be, NULL, "ps3", a, ps3_audio_cb, &as);
    if (!a->voice) {
        error_setg(errp, "ps3-audio: the backend refused a 48 kHz stereo "
                   "voice");
        g_free(a);
        return NULL;
    }

    a->pcm = g_new0(int16_t, PS3_AUDIO_FRAMES * PS3_AUDIO_CHANNELS);
    audio_be_set_active_out(a->be, a->voice, true);

    info_report("ps3-audio: 48 kHz stereo out on \"%s\"", audio_be_get_id(a->be));
    return a;
}

bool ps3_audio_active(const PS3Audio *a)
{
    return a && a->be && a->voice;
}

void ps3_audio_play_f32be(PS3Audio *a, const uint8_t *block)
{
    unsigned i;

    if (!ps3_audio_active(a)) {
        return;
    }

    for (i = 0; i < PS3_AUDIO_FRAMES * PS3_AUDIO_CHANNELS; i++) {
        a->pcm[i] = ps3_audio_sample(block + i * 4);
    }

    audio_be_write(a->be, a->voice, a->pcm, sizeof(int16_t) *
                   PS3_AUDIO_FRAMES * PS3_AUDIO_CHANNELS);
}

/*
 * Microphone capture.
 *
 * The backend raises this when it has delivered samples; the guest pulls them
 * with ps3_audio_mic_read, so there is nothing to do here either.
 */
static void ps3_audio_mic_cb(void *opaque, int avail)
{
}

bool ps3_audio_mic_open(PS3Audio *a, unsigned rate, unsigned channels,
                        Error **errp)
{
    /*
     * QEMU's audio core resamples between the device and the voice, but it
     * only knows these rates.  The guest's own rate comes first so a 48 kHz
     * capture is not needlessly resampled; the rest are the fallbacks RPCS3
     * tries for the same reason (a host input often refuses 32 kHz).
     */
    static const unsigned candidates[] = {
        48000, 44100, 32000, 16000, 8000,
    };
    struct audsettings as = {
        .fmt = AUDIO_FORMAT_S16,
        .big_endian = HOST_BIG_ENDIAN,
    };
    unsigned i;

    if (!a || !a->be) {
        error_setg(errp, "ps3-audio: no host audio backend for the "
                   "microphone");
        return false;
    }

    if (channels < 1) {
        channels = 1;
    }
    if (channels > 2) {
        channels = 2;
    }

    ps3_audio_mic_close(a);

    for (i = 0; i <= ARRAY_SIZE(candidates); i++) {
        unsigned cand = i == 0 ? rate : candidates[i - 1];

        if (!cand || (i && cand == rate)) {
            continue;               /* nothing to ask for, or already tried */
        }
        as.freq = cand;
        as.nchannels = channels;

        a->in = audio_be_open_in(a->be, NULL, "ps3-mic", a,
                                 ps3_audio_mic_cb, &as);
        if (!a->in) {
            continue;
        }

        a->in_rate = cand;
        a->in_channels = channels;
        audio_be_set_active_in(a->be, a->in, true);

        info_report("ps3-audio: microphone capture at %u Hz, %u channel(s) "
                    "on \"%s\"%s", cand, channels, audio_be_get_id(a->be),
                    cand == rate ? "" : " (the guest's rate was resampled)");
        return true;
    }

    error_setg(errp, "ps3-audio: the backend opened no capture voice (is "
               "there an input device?)");
    return false;
}

void ps3_audio_mic_close(PS3Audio *a)
{
    if (!a || !a->in) {
        return;
    }

    audio_be_set_active_in(a->be, a->in, false);
    audio_be_close_in(a->be, a->in);
    a->in = NULL;
    a->in_rate = 0;
    a->in_channels = 0;
}

void ps3_audio_mic_start(PS3Audio *a, bool on)
{
    if (!a || !a->in) {
        return;
    }

    audio_be_set_active_in(a->be, a->in, on);
}

bool ps3_audio_mic_active(const PS3Audio *a)
{
    return a && a->be && a->in;
}

unsigned ps3_audio_mic_rate(const PS3Audio *a)
{
    return a && a->in ? a->in_rate : 0;
}

unsigned ps3_audio_mic_channels(const PS3Audio *a)
{
    return a && a->in ? a->in_channels : 0;
}

size_t ps3_audio_mic_read(PS3Audio *a, void *buf, size_t max_bytes)
{
    if (!ps3_audio_mic_active(a)) {
        return 0;
    }

    return audio_be_read(a->be, a->in, buf, max_bytes);
}

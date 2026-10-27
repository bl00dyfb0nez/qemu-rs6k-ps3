/*
 * PS3 framebuffer display ("ps3-vga")
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The RSX is not modelled, so the machine needs somewhere to show a picture.
 * This is deliberately the smallest useful scanout: a register block that
 * names a surface in guest RAM (the XDR region lv2 hands out), and a display
 * refreshed from it at 60 Hz.  It is not a VGA card and does not pretend to
 * be one - it is the "display for now" until the RSX exists.
 *
 * Registers (big-endian, as the console is):
 *
 *   0x00  ID        read-only, 'PS3V'
 *   0x04  width     pixels, 16..1920
 *   0x08  height    pixels, 16..1080
 *   0x0C  stride    bytes per line, 0 means width * 4
 *   0x10  base      guest physical address of the top-left pixel
 *   0x14  enable    1 starts scanning out, 0 blanks
 *   0x18  vblank    read-only, 60 Hz counter the guest can poll
 *
 * The pixel format is XRGB8888 (a little-endian 32-bit word on the guest
 * side), which is what a linear framebuffer is when nothing has configured
 * an RSX surface yet.
 */

#include "qemu/osdep.h"
#include <math.h>
#include <time.h>
#ifdef CONFIG_OPENGL
#include <epoxy/gl.h>
#endif
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "system/kvm.h"
#ifdef CONFIG_HVF
#include "system/hvf.h"
#endif
#ifdef CONFIG_WHPX
#include "system/whpx.h"
#endif
#include "qapi/error.h"
#include "ps3_vga.h"
#include "ps3_vga_edid.h"
#include "ui/vgafont.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/sysbus.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "qom/object.h"
#include "ui/console.h"
#include "system/physmem.h"

#define TYPE_PS3_VGA "ps3-vga"
OBJECT_DECLARE_SIMPLE_TYPE(PS3VGAState, PS3_VGA)

#define PS3_VGA_REG_ID      0x00
#define PS3_VGA_REG_WIDTH   0x04
#define PS3_VGA_REG_HEIGHT  0x08
#define PS3_VGA_REG_STRIDE  0x0C
#define PS3_VGA_REG_BASE    0x10
#define PS3_VGA_REG_ENABLE  0x14
#define PS3_VGA_REG_VBLANK  0x18
#define PS3_VGA_REG_SINK    0x1C   /* 1 = HDMI sink */
#define PS3_VGA_REG_MAX_W   0x20
#define PS3_VGA_REG_MAX_H   0x24
#define PS3_VGA_REG_EDID    0x40   /* 256 bytes, base block + CEA */
#define PS3_VGA_REG_SIZE    (PS3_VGA_REG_EDID + 256)

#define PS3_VGA_ID          0x50533356  /* 'PS3V' */
#define PS3_VGA_MAX_WIDTH   1920
#define PS3_VGA_MAX_HEIGHT  1080
#define PS3_VGA_REFRESH_NS  (1000000000ULL / 60)

/* The boot screen: 1024x768, 8x16 glyphs, so 128 columns by 48 rows. */
#define PS3_VGA_BOOT_W      1024
#define PS3_VGA_BOOT_H      768
#define PS3_VGA_TEXT_COLS   (PS3_VGA_BOOT_W / 8)
#define PS3_VGA_TEXT_ROWS   (PS3_VGA_BOOT_H / 16)
#define PS3_VGA_FG          0x00E6E6E6
#define PS3_VGA_BG          0x00101418

struct PS3VGAState {
    SysBusDevice parent_obj;

    MemoryRegion regs;
    QemuConsole *con;
    QEMUTimer *refresh;

    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t base;
    uint32_t enable;
    uint32_t vblank;

    bool reported;

    /* The scanout: boot text, then the guest's frame with text over it. */
    uint32_t *boot_fb;
    DisplaySurface *boot_surface;
    char text[PS3_VGA_TEXT_ROWS][PS3_VGA_TEXT_COLS + 1];
    unsigned lines;
    bool guest_mode;
    uint32_t guest_base, guest_w, guest_h, guest_stride;
    char *dump;                 /* write the boot screen here after a line */
    bool demo;                  /* take the scanout at reset, to test it */
    bool allow_highres;         /* kept for old command lines; no gate now */
    bool bench;                 /* measure the 720p/1080p compose paths */
    bool av_test;               /* read the EDID, take the scanout, log it */

    /*
     * -vga rsx: the scanout leaves through a GL texture instead of the
     * surface path.  The context belongs to the display frontend (SDL or GTK
     * with gl=on), so the window composites the same pixels the guest sees.
     */
    bool gl;                    /* use GL when the display has it */
    bool gl_required;           /* gl=on: fail without a GL backend */
    bool gl_checked;
    bool gl_attempt;
    bool gl_active;
    bool gl_presented;
    QEMUGLContext gl_ctx;
    unsigned gl_tex;
    unsigned gl_fbo;
    /*
     * The host GPU the scanout runs on.  Both desktop drivers are used: a 3.2
     * core context is asked for first and 3.0 is the fallback, and the vendor
     * is reported so the driver in use is visible in the log.
     */
    char gl_vendor[64];
    char gl_renderer[128];
    bool gl_nvidia, gl_amd;
};

#define PS3_VGA_OVERLAY_ROWS 6

/*
 * Which host accelerator is running the machine.  This is reported with the
 * benchmarks; it no longer gates the scanout, because composing the overlay
 * measured about 0.07 ms a frame at 1080p under TCG, well inside the budget.
 */
static bool ps3_vga_accel(void)
{
    if (kvm_enabled()) {
        return true;
    }
#ifdef CONFIG_HVF
    if (hvf_enabled()) {
        return true;
    }
#endif
#ifdef CONFIG_WHPX
    if (whpx_enabled()) {
        return true;
    }
#endif
    return false;
}

/*
 * Only one PS3 board exists in a machine, and the boot code that prints here
 * is the device's own peer, so a singleton is enough - and it keeps the board
 * code free of display plumbing.
 */
static PS3VGAState *ps3_vga_current;

static void ps3_vga_present(PS3VGAState *s);

static void ps3_vga_row_at(PS3VGAState *s, unsigned row, unsigned y0)
{
    unsigned x, y, col;

    if (!s->text[row][0] || y0 + 16 > PS3_VGA_BOOT_H) {
        return;
    }

    for (y = 0; y < 16; y++) {
        for (x = 0; x < PS3_VGA_BOOT_W; x++) {
            s->boot_fb[(y0 + y) * PS3_VGA_BOOT_W + x] = PS3_VGA_BG;
        }
    }

    for (col = 0; col < PS3_VGA_TEXT_COLS && s->text[row][col]; col++) {
        const uint8_t *glyph = vgafont16 +
                               (unsigned char)s->text[row][col] * 16;

        for (y = 0; y < 16; y++) {
            for (x = 0; x < 8; x++) {
                uint32_t v = (glyph[y] & (0x80 >> x)) ?
                             PS3_VGA_FG : PS3_VGA_BG;

                s->boot_fb[(y0 + y) * PS3_VGA_BOOT_W + col * 8 + x] = v;
            }
        }
    }
}

static void ps3_vga_text_top(PS3VGAState *s)
{
    unsigned row;

    for (row = 0; row < s->lines; row++) {
        ps3_vga_row_at(s, row, row * 16);
    }
}

/*
 * After the guest owns the scanout the console still has to be readable, so
 * the last few lines are drawn over the bottom of its frame on a solid bar.
 */
static void ps3_vga_text_overlay(PS3VGAState *s)
{
    unsigned first = s->lines > PS3_VGA_OVERLAY_ROWS ?
                     s->lines - PS3_VGA_OVERLAY_ROWS : 0;
    unsigned y0 = PS3_VGA_BOOT_H - PS3_VGA_OVERLAY_ROWS * 16;
    unsigned i;

    for (i = 0; i < PS3_VGA_BOOT_H - y0; i++) {
        memset(&s->boot_fb[(y0 + i) * PS3_VGA_BOOT_W],
               PS3_VGA_BG, PS3_VGA_BOOT_W * 4);
    }

    for (i = 0; first + i < s->lines; i++) {
        ps3_vga_row_at(s, first + i, y0 + i * 16);
    }
}

/*
 * The boot splash: the console's wordmark over the boot background, centred in
 * the part of the screen the status lines have not used.  The glyphs are the
 * VGA font scaled up - this is the model's rendition of the screen the console
 * shows before vsh.self takes the scanout, not Sony's artwork (emer_init's own
 * splash is in the console's firmware and is not redistributable).
 */
static void ps3_vga_scaled_char(PS3VGAState *s, char c, unsigned x0,
                                unsigned y0, unsigned scale, uint32_t colour)
{
    const uint8_t *glyph = vgafont16 + (unsigned char)c * 16;
    unsigned x, y, sx, sy;

    for (y = 0; y < 16; y++) {
        for (x = 0; x < 8; x++) {
            if (!(glyph[y] & (0x80 >> x))) {
                continue;
            }
            for (sy = 0; sy < scale; sy++) {
                for (sx = 0; sx < scale; sx++) {
                    unsigned px = x0 + x * scale + sx;
                    unsigned py = y0 + y * scale + sy;

                    if (px < PS3_VGA_BOOT_W && py < PS3_VGA_BOOT_H) {
                        s->boot_fb[py * PS3_VGA_BOOT_W + px] = colour;
                    }
                }
            }
        }
    }
}

static void ps3_vga_scaled_text(PS3VGAState *s, const char *text, unsigned y0,
                                unsigned scale, uint32_t colour)
{
    unsigned len = strlen(text) * 8 * scale;
    unsigned x0 = len < PS3_VGA_BOOT_W ? (PS3_VGA_BOOT_W - len) / 2 : 0;
    unsigned i;

    for (i = 0; text[i]; i++) {
        ps3_vga_scaled_char(s, text[i], x0 + i * 8 * scale, y0, scale, colour);
    }
}

void ps3_vga_boot_logo(const char *title, const char *caption)
{
    PS3VGAState *s = ps3_vga_current;
    unsigned y0, y, x;

    if (!s || !s->boot_fb || s->guest_mode) {
        return;
    }

    /*
     * Start below the last status line, so the chain's own messages stay
     * readable above the wordmark.
     */
    y0 = s->lines * 16 + 24;
    if (y0 + 16 * 10 + 60 > PS3_VGA_BOOT_H) {
        y0 = PS3_VGA_BOOT_H / 3;
    }

    for (y = y0; y < PS3_VGA_BOOT_H; y++) {
        for (x = 0; x < PS3_VGA_BOOT_W; x++) {
            s->boot_fb[y * PS3_VGA_BOOT_W + x] = PS3_VGA_BG;
        }
    }

    ps3_vga_scaled_text(s, title, y0 + 24, 10, PS3_VGA_FG);

    if (caption) {
        ps3_vga_scaled_text(s, caption, y0 + 24 + 16 * 10 + 24, 2,
                            PS3_VGA_FG);
    }

    /* A thin rule under the wordmark, in the console's boot-screen style. */
    y = y0 + 24 + 16 * 10 + 12;
    for (x = PS3_VGA_BOOT_W / 4; x < PS3_VGA_BOOT_W * 3 / 4 &&
         y < PS3_VGA_BOOT_H; x++) {
        s->boot_fb[y * PS3_VGA_BOOT_W + x] = PS3_VGA_FG;
    }

    ps3_vga_present(s);
}

static void ps3_vga_dump_screen(PS3VGAState *s)
{
    FILE *f;
    size_t i;

    if (!s->dump) {
        return;
    }

    f = fopen(s->dump, "wb");
    if (!f) {
        return;
    }

    fprintf(f, "P6\n%d %d\n255\n", PS3_VGA_BOOT_W, PS3_VGA_BOOT_H);
    for (i = 0; i < PS3_VGA_BOOT_W * PS3_VGA_BOOT_H; i++) {
        uint8_t rgb[3] = { s->boot_fb[i] >> 16, s->boot_fb[i] >> 8,
                           s->boot_fb[i] };

        fwrite(rgb, 1, 3, f);
    }
    fclose(f);
}

/* Copy the guest's surface into our own buffer, so the text can sit on top. */
static void ps3_vga_compose(PS3VGAState *s)
{
    hwaddr linesize, size, mapsize;
    void *map;
    const uint8_t *p;
    unsigned rows, cols, x, y;

    if (s->guest_w < 16 || s->guest_w > PS3_VGA_MAX_WIDTH ||
        s->guest_h < 16 || s->guest_h > PS3_VGA_MAX_HEIGHT ||
        !s->guest_base) {
        return;
    }

    linesize = (hwaddr)s->guest_w * 4;
    if (!s->guest_stride) {
        s->guest_stride = linesize;
    }
    if (s->guest_stride < linesize) {
        return;
    }

    size = (hwaddr)s->guest_stride * (s->guest_h - 1) + linesize;
    mapsize = size;
    map = physical_memory_map(s->guest_base, &mapsize, false);
    if (!map || mapsize != size) {
        if (map) {
            physical_memory_unmap(map, mapsize, 0, 0);
        }
        return;
    }

    p = map;

    if (s->guest_w <= PS3_VGA_BOOT_W && s->guest_h <= PS3_VGA_BOOT_H) {
        rows = s->guest_h;
        cols = s->guest_w;
        for (y = 0; y < rows; y++) {
            memcpy(&s->boot_fb[y * PS3_VGA_BOOT_W],
                   p + (size_t)y * s->guest_stride, cols * 4);
        }
    } else {
        /*
         * The VSH renders at 720p or 1080p and this surface is 1024x768, so
         * the whole guest frame is scaled down instead of being cropped.  The
         * text overlay is drawn on top of the result, at this surface's rows.
         */
        double sc = MAX((double)s->guest_w / PS3_VGA_BOOT_W,
                        (double)s->guest_h / PS3_VGA_BOOT_H);
        unsigned dw = MIN((unsigned)(s->guest_w / sc), PS3_VGA_BOOT_W);
        unsigned dh = MIN((unsigned)(s->guest_h / sc), PS3_VGA_BOOT_H);
        unsigned x0 = (PS3_VGA_BOOT_W - dw) / 2;
        unsigned y0 = (PS3_VGA_BOOT_H - dh) / 2;

        memset(s->boot_fb, 0, PS3_VGA_BOOT_W * PS3_VGA_BOOT_H * 4);
        for (y = 0; y < dh; y++) {
            const uint32_t *row = (const uint32_t *)
                (p + (size_t)(y * sc) * s->guest_stride);

            for (x = 0; x < dw; x++) {
                s->boot_fb[(y0 + y) * PS3_VGA_BOOT_W + x0 + x] =
                    row[(unsigned)(x * sc)];
            }
        }
    }

    physical_memory_unmap(map, mapsize, 0, 0);
}

void ps3_vga_puts(const char *line)
{
    PS3VGAState *s = ps3_vga_current;

    if (!s || !s->boot_fb) {
        return;
    }

    if (s->lines == PS3_VGA_TEXT_ROWS) {
        memmove(s->text, s->text + 1,
                sizeof(s->text) - sizeof(s->text[0]));
        s->lines--;
    }

    pstrcpy(s->text[s->lines], sizeof(s->text[0]), line);
    s->lines++;

    if (s->guest_mode) {
        ps3_vga_compose(s);
        ps3_vga_text_overlay(s);
    } else {
        ps3_vga_row_at(s, s->lines - 1, (s->lines - 1) * 16);
    }

    if (s->dump) {
        FILE *f = fopen(s->dump, "wb");

        if (f) {
            size_t i;

            fprintf(f, "P6\n%d %d\n255\n", PS3_VGA_BOOT_W, PS3_VGA_BOOT_H);
            for (i = 0; i < PS3_VGA_BOOT_W * PS3_VGA_BOOT_H; i++) {
                uint8_t rgb[3] = { s->boot_fb[i] >> 16, s->boot_fb[i] >> 8,
                                   s->boot_fb[i] };

                fwrite(rgb, 1, 3, f);
            }
            fclose(f);
        }
    }

    ps3_vga_present(s);
}

void ps3_vga_printf(const char *fmt, ...)
{
    char line[PS3_VGA_TEXT_COLS + 1];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    ps3_vga_puts(line);
}

/*
 * The surface points straight at guest memory, so a scanout sees whatever the
 * guest wrote without a copy.  The unmap runs when the console frees the
 * surface, which is why it is attached to the pixman image rather than done
 * on the next register write.
 */
static void ps3_vga_unmap_surface(pixman_image_t *image, void *unused)
{
    void *data = pixman_image_get_data(image);
    size_t size = pixman_image_get_stride(image) *
                  pixman_image_get_height(image);

    physical_memory_unmap(data, size, 0, 0);
}

static DisplaySurface *ps3_vga_surface(PS3VGAState *s)
{
    hwaddr linesize, size, mapsize;
    void *data;
    DisplaySurface *surface;

    if (s->width < 16 || s->width > PS3_VGA_MAX_WIDTH ||
        s->height < 16 || s->height > PS3_VGA_MAX_HEIGHT) {
        return NULL;
    }

    linesize = (hwaddr)s->width * 4;
    if (!s->stride) {
        s->stride = linesize;
    }
    if (s->stride < linesize) {
        return NULL;
    }

    size = (hwaddr)s->stride * (s->height - 1) + linesize;
    mapsize = size;
    data = physical_memory_map(s->base, &mapsize, false);
    if (!data || mapsize != size) {
        if (data) {
            physical_memory_unmap(data, mapsize, 0, 0);
        }
        return NULL;
    }

    surface = qemu_create_displaysurface_from(s->width, s->height,
                                              PIXMAN_x8r8g8b8,
                                              s->stride, data);
    pixman_image_set_destroy_function(surface->image,
                                      ps3_vga_unmap_surface, NULL);
    return surface;
}

static void ps3_vga_frame(PS3VGAState *s)
{
    s->vblank++;

    if (!s->guest_mode) {
        /*
         * The boot screen has to reach the GL scanout once it is up.  The
         * first tick is also where the context is created, so present even
         * before gl_active is set.
         */
        if (s->gl_active || (s->gl && !s->gl_checked)) {
            ps3_vga_present(s);
        }
        return;
    }

    ps3_vga_compose(s);
    ps3_vga_text_overlay(s);
    ps3_vga_present(s);
}

static bool ps3_vga_gfx_update(void *opaque)
{
    ps3_vga_frame(opaque);
    return true;
}

static void ps3_vga_tick(void *opaque)
{
    PS3VGAState *s = opaque;

    /* The display frontend is up by the first tick; the GL context can be
     * created now (machine init runs before the display). */
    s->gl_attempt = true;
    ps3_vga_frame(s);
    timer_mod(s->refresh, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                          PS3_VGA_REFRESH_NS);
}

static const GraphicHwOps ps3_vga_ops = {
    .gfx_update = ps3_vga_gfx_update,
};

/*
 * The GL scanout.
 *
 * `-vga rsx,gl=on' takes the same pixels the CPU composed, uploads them to a
 * texture in a context shared with the display frontend, and hands that
 * texture to the console's GL scanout.  The frontend then composites it with
 * the GPU instead of blitting a pixman surface in software: on SDL that is
 * `-display sdl,gl=on', whose window context and this one share textures.
 * The context is created only once the frontend has attached (the first
 * frame), because machine init runs before the display is up.
 *
 * The texture and framebuffer are also the target the RSX draw path renders
 * into; keeping the upload path here means the boot screen and guest frames
 * go through the same object the FIFO will draw to.
 */
static void ps3_vga_gl_init(PS3VGAState *s)
{
    s->gl_checked = true;

    if (!s->gl) {
        return;
    }

#ifdef CONFIG_OPENGL
    if (!qemu_console_has_gl(s->con)) {
        if (s->gl_required) {
            error_report("ps3-vga: -vga rsx,gl=on needs a GL display backend "
                         "(run with -display sdl,gl=on)");
            exit(1);
        }
        warn_report("ps3-vga: no GL display backend, keeping the CPU scanout");
        return;
    }

    {
        QEMUGLParams params = { .major_ver = 3, .minor_ver = 2 };
        GLuint tex = 0, fbo = 0;

        s->gl_ctx = qemu_console_gl_ctx_create(s->con, &params);
        if (!s->gl_ctx) {
            /* A 3.0 core context is enough for everything used here, and is
             * what a driver that refuses 3.2 accepts. */
            params.major_ver = 3;
            params.minor_ver = 0;
            s->gl_ctx = qemu_console_gl_ctx_create(s->con, &params);
        }
        if (!s->gl_ctx) {
            if (s->gl_required) {
                error_report("ps3-vga: the display could not create a GL "
                             "context");
                exit(1);
            }
            warn_report("ps3-vga: no GL context, keeping the CPU scanout");
            return;
        }

        qemu_console_gl_ctx_make_current(s->con, s->gl_ctx);

        /*
         * Which driver the scanout runs on.  NVIDIA and AMD both take the
         * BGRA upload and the RGBA8 framebuffer, but their context handling
         * differs - the fallback above is the part that matters, since an AMD
         * driver can refuse a 3.2 core request on an older runtime - and a
         * vendor string in the log makes the path in use diagnosable.
         */
        {
            const char *vendor = (const char *)glGetString(GL_VENDOR);
            const char *renderer = (const char *)glGetString(GL_RENDERER);
            const char *version = (const char *)glGetString(GL_VERSION);

            snprintf(s->gl_vendor, sizeof(s->gl_vendor), "%s",
                     vendor ? vendor : "unknown");
            snprintf(s->gl_renderer, sizeof(s->gl_renderer), "%s",
                     renderer ? renderer : "unknown");
            s->gl_nvidia = vendor && strstr(vendor, "NVIDIA");
            s->gl_amd = vendor && (strstr(vendor, "AMD") ||
                                   strstr(vendor, "ATI") ||
                                   strstr(vendor, "Advanced Micro Devices"));
            info_report("ps3-vga: GL %s on %s (%s)",
                        version ? version : "?", s->gl_renderer,
                        s->gl_nvidia ? "NVIDIA" :
                        s->gl_amd ? "AMD" : s->gl_vendor);
        }

        glGenTextures(1, &tex);
        glBindTexture(GL_TEXTURE_2D, tex);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, PS3_VGA_BOOT_W,
                     PS3_VGA_BOOT_H, 0, GL_BGRA, GL_UNSIGNED_BYTE, NULL);

        glGenFramebuffers(1, &fbo);
        glBindFramebuffer(GL_FRAMEBUFFER, fbo);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                               GL_TEXTURE_2D, tex, 0);
        if (glCheckFramebufferStatus(GL_FRAMEBUFFER) !=
            GL_FRAMEBUFFER_COMPLETE) {
            warn_report("ps3-vga: GL framebuffer is incomplete; the scanout "
                        "still uses the texture upload");
        }
        glBindFramebuffer(GL_FRAMEBUFFER, 0);
        glBindTexture(GL_TEXTURE_2D, 0);

        s->gl_tex = tex;
        s->gl_fbo = fbo;
        s->gl_active = true;
    }

    info_report("ps3-vga: OpenGL scanout active (%ux%u texture, %s)",
                PS3_VGA_BOOT_W, PS3_VGA_BOOT_H,
                ps3_vga_accel() ? "hardware accel" : "TCG");
#else
    if (s->gl_required) {
        error_report("ps3-vga: -vga rsx,gl=on needs OpenGL support, which "
                     "this build does not have");
        exit(1);
    }
    warn_report("ps3-vga: OpenGL support is not built in, keeping the CPU "
                "scanout");
#endif
}

static void ps3_vga_gl_upload(PS3VGAState *s)
{
#ifdef CONFIG_OPENGL
    if (!s->gl_active || !qemu_console_has_gl(s->con)) {
        return;
    }
    if (qemu_console_gl_ctx_make_current(s->con, s->gl_ctx) != 0) {
        return;
    }

    glBindTexture(GL_TEXTURE_2D, s->gl_tex);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, PS3_VGA_BOOT_W,
                    PS3_VGA_BOOT_H, GL_BGRA, GL_UNSIGNED_BYTE, s->boot_fb);
    glBindTexture(GL_TEXTURE_2D, 0);

    if (!s->gl_presented) {
        qemu_console_gl_scanout_texture(s->con, s->gl_tex, false,
                                        PS3_VGA_BOOT_W, PS3_VGA_BOOT_H,
                                        0, 0, PS3_VGA_BOOT_W,
                                        PS3_VGA_BOOT_H, NULL);
        s->gl_presented = true;
    }

    qemu_console_gl_update(s->con, 0, 0, PS3_VGA_BOOT_W, PS3_VGA_BOOT_H);
#endif
}

static void ps3_vga_present(PS3VGAState *s)
{
    if (!s->gl_checked && s->gl_attempt) {
        ps3_vga_gl_init(s);
    }

    if (s->gl_active && qemu_console_has_gl(s->con)) {
        ps3_vga_gl_upload(s);
        return;
    }

    qemu_console_update_full(s->con);
}

static uint64_t ps3_vga_read(void *opaque, hwaddr offset, unsigned size)
{
    PS3VGAState *s = opaque;

    if (offset >= PS3_VGA_REG_EDID && offset < PS3_VGA_REG_EDID + 256) {
        return ps3_vga_edid[offset - PS3_VGA_REG_EDID];
    }

    switch (offset) {
    case PS3_VGA_REG_ID:
        return PS3_VGA_ID;
    case PS3_VGA_REG_SINK:
        return 1;                       /* the console's HDMI sink */
    case PS3_VGA_REG_MAX_W:
        return PS3_VGA_MAX_WIDTH;
    case PS3_VGA_REG_MAX_H:
        return PS3_VGA_MAX_HEIGHT;
    case PS3_VGA_REG_WIDTH:
        return s->width;
    case PS3_VGA_REG_HEIGHT:
        return s->height;
    case PS3_VGA_REG_STRIDE:
        return s->stride;
    case PS3_VGA_REG_BASE:
        return s->base;
    case PS3_VGA_REG_ENABLE:
        return s->enable;
    case PS3_VGA_REG_VBLANK:
        return s->vblank;
    default:
        return 0;
    }
}

static void ps3_vga_write(void *opaque, hwaddr offset, uint64_t value,
                          unsigned size)
{
    PS3VGAState *s = opaque;

    switch (offset) {
    case PS3_VGA_REG_WIDTH:
        s->width = value;
        s->stride = 0;
        break;
    case PS3_VGA_REG_HEIGHT:
        s->height = value;
        break;
    case PS3_VGA_REG_STRIDE:
        s->stride = value;
        break;
    case PS3_VGA_REG_BASE:
        s->base = value;
        break;
    case PS3_VGA_REG_ENABLE:
        s->enable = !!value;
        s->guest_mode = s->enable;
        s->guest_base = s->base;
        s->guest_w = s->width;
        s->guest_h = s->height;
        s->guest_stride = s->stride;
        break;
    default:
        return;
    }

    if (!s->guest_mode) {
        /* Back to the boot screen when the guest disables the scanout. */
        memset(s->boot_fb, 0, sizeof(uint32_t) * PS3_VGA_BOOT_W *
               PS3_VGA_BOOT_H);
        {
            size_t i;

            for (i = 0; i < PS3_VGA_BOOT_W * PS3_VGA_BOOT_H; i++) {
                s->boot_fb[i] = PS3_VGA_BG;
            }
        }
        ps3_vga_text_top(s);
        ps3_vga_present(s);
        return;
    }

    if (!s->reported) {
        s->reported = true;
        info_report("ps3-vga: guest scanout %ux%u from 0x%X, stride %u; "
                    "console text stays on top",
                    s->width, s->height, s->base, s->stride);
    }

    ps3_vga_compose(s);
    ps3_vga_text_overlay(s);
    ps3_vga_present(s);
}

static const MemoryRegionOps ps3_vga_regs_ops = {
    .read = ps3_vga_read,
    .write = ps3_vga_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
};

static void ps3_vga_realize(DeviceState *dev, Error **errp)
{
    PS3VGAState *s = PS3_VGA(dev);

    s->con = qemu_graphic_console_create(dev, 0, &ps3_vga_ops, s);

    /*
     * The boot screen comes up before the guest has a scanout, so the chain's
     * progress is visible from the first instruction of the mask ROM.
     */
    s->boot_fb = g_new(uint32_t, PS3_VGA_BOOT_W * PS3_VGA_BOOT_H);
    memset(s->boot_fb, 0, sizeof(uint32_t) * PS3_VGA_BOOT_W *
           PS3_VGA_BOOT_H);
    {
        size_t i;

        for (i = 0; i < PS3_VGA_BOOT_W * PS3_VGA_BOOT_H; i++) {
            s->boot_fb[i] = PS3_VGA_BG;
        }
    }
    s->boot_surface = qemu_create_displaysurface_from(PS3_VGA_BOOT_W,
                                                      PS3_VGA_BOOT_H,
                                                      PIXMAN_x8r8g8b8,
                                                      PS3_VGA_BOOT_W * 4,
                                                      (uint8_t *)s->boot_fb);
    qemu_console_set_surface(s->con, s->boot_surface);
    s->boot_surface = NULL;     /* the console owns it now */

    ps3_vga_current = s;
    ps3_vga_printf("PS3 BOOT");

    if (s->bench) {
        static const uint32_t modes[2][2] = { { 1280, 720 },
                                              { 1920, 1080 } };
        unsigned m;

        s->guest_base = 0x100000;
        s->guest_mode = true;

        for (m = 0; m < 2; m++) {
            int64_t t0, t1;
            unsigned i;

            s->guest_w = modes[m][0];
            s->guest_h = modes[m][1];
            s->guest_stride = modes[m][0] * 4;

            t0 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
            for (i = 0; i < 300; i++) {
                ps3_vga_compose(s);
                ps3_vga_text_overlay(s);
            }
            t1 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

            info_report("ps3-vga: %ux%u compose benchmark: %" PRIu64
                        " ns/frame (%.1f fps), %s", modes[m][0], modes[m][1],
                        (uint64_t)((t1 - t0) / 300), 300.0e9 / (double)(t1 - t0),
                        ps3_vga_accel() ? "hardware accel" : "TCG");
        }
    }

    if (s->demo) {
        s->guest_base = 0x100000;
        s->guest_w = 640;
        s->guest_h = 480;
        s->guest_stride = 640 * 4;
        s->guest_mode = true;
        ps3_vga_compose(s);
        ps3_vga_text_overlay(s);
        ps3_vga_present(s);
        ps3_vga_dump_screen(s);
    }

    s->refresh = timer_new_ns(QEMU_CLOCK_VIRTUAL, ps3_vga_tick, s);
    timer_mod(s->refresh, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                          PS3_VGA_REFRESH_NS);

    memory_region_init_io(&s->regs, OBJECT(dev), &ps3_vga_regs_ops, s,
                          TYPE_PS3_VGA ".regs", PS3_VGA_REG_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regs);

    s->width = 640;
    s->height = 480;

    if (s->av_test) {
        uint8_t edid[256];
        unsigned n, i;
        uint8_t base = 0, ext = 0;

        const char *name = "?";
        unsigned oui = 0;

        n = ps3_vga_hdmi_edid(edid, sizeof(edid));
        for (i = 0; i < 128; i++) {
            base += edid[i];
        }
        for (i = 128; i < 256; i++) {
            ext += edid[i];
        }
        for (i = 54; i + 17 < 126; i += 18) {
            if (!edid[i] && !edid[i + 1] && !edid[i + 2] &&
                edid[i + 3] == 0xFC) {
                name = (const char *)&edid[i + 5];
            }
        }
        for (i = 132; i + 2 < 256; i++) {
            if (edid[i] == 0x03 && edid[i + 1] == 0x0C &&
                edid[i + 2] == 0x00) {
                oui = 0x000C03;
            }
        }
        info_report("ps3-vga: av selftest: EDID %u bytes, header "
                    "%02x%02x%02x%02x, base checksum 0x%02x, extension "
                    "checksum 0x%02x, HDMI OUI %s, name '%.13s'",
                    n, edid[0], edid[1], edid[2], edid[3], base, ext,
                    oui ? "000C03" : "missing", name);

        /* What lv2's av calls do: read the EDID, then own the scanout. */
        ps3_vga_guest_scanout(0x100000, 1280, 720, 1280 * 4);
        ps3_vga_guest_scanout(0x100000, 1920, 1080, 1920 * 4);
        ps3_vga_puts("AV: HDMI EDID 256 BYTES, 1080P OFFERED");
        ps3_vga_puts("AV: GUEST OWNS THE SCANOUT, 1920X1080");
        ps3_vga_dump_screen(s);
    }

    info_report("ps3-vga: display ready (XRGB8888 linear framebuffer, "
                "%ux%u until the guest sets a mode)", s->width, s->height);
}

/* The AV path the guest uses to own the scanout and read the sink's EDID. */
void ps3_vga_guest_scanout(uint32_t base, uint32_t w, uint32_t h,
                           uint32_t stride)
{
    PS3VGAState *s = ps3_vga_current;

    if (!s || w < 16 || w > PS3_VGA_MAX_WIDTH ||
        h < 16 || h > PS3_VGA_MAX_HEIGHT) {
        return;
    }

    s->guest_base = base;
    s->guest_w = w;
    s->guest_h = h;
    s->guest_stride = stride;
    s->guest_mode = true;

    ps3_vga_compose(s);
    ps3_vga_text_overlay(s);
    ps3_vga_present(s);
    ps3_vga_dump_screen(s);

    info_report("ps3-vga: guest owns the scanout: %ux%u from 0x%X", w, h,
                base);
}

/* cellVideoOutConfigure's result: the guest picked a mode for the sink. */
void ps3_vga_set_mode(uint32_t w, uint32_t h)
{
    PS3VGAState *s = ps3_vga_current;

    if (!s || w < 16 || w > PS3_VGA_MAX_WIDTH ||
        h < 16 || h > PS3_VGA_MAX_HEIGHT) {
        return;
    }

    s->width = w;
    s->height = h;
    s->stride = 0;

    info_report("ps3-vga: av selects %ux%u (EDID offers 720p/1080p)", w, h);

    if (s->guest_mode && s->guest_base) {
        ps3_vga_guest_scanout(s->guest_base, w, h, 0);
    }
}

/* What the display is showing, so the AV service can report a native mode. */
void ps3_vga_mode(uint32_t *w, uint32_t *h)
{
    PS3VGAState *s = ps3_vga_current;

    if (w) {
        *w = s ? s->width : 0;
    }
    if (h) {
        *h = s ? s->height : 0;
    }
}

unsigned ps3_vga_hdmi_edid(uint8_t *out, unsigned cap)
{
    unsigned n = MIN(cap, (unsigned)sizeof(ps3_vga_edid));

    if (out && n) {
        memcpy(out, ps3_vga_edid, n);
    }
    return n;
}

static const Property ps3_vga_properties[] = {
    DEFINE_PROP_STRING("dump", PS3VGAState, dump),
    DEFINE_PROP_BOOL("demo", PS3VGAState, demo, false),
    DEFINE_PROP_BOOL("allow-highres", PS3VGAState, allow_highres, false),
    DEFINE_PROP_BOOL("av-test", PS3VGAState, av_test, false),
    DEFINE_PROP_BOOL("bench", PS3VGAState, bench, false),
    DEFINE_PROP_BOOL("gl", PS3VGAState, gl, false),
    DEFINE_PROP_BOOL("gl-required", PS3VGAState, gl_required, false),
};

static void ps3_vga_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = ps3_vga_realize;
    dc->desc = "PS3 linear framebuffer display";
    device_class_set_props(dc, ps3_vga_properties);
    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
}

static const TypeInfo ps3_vga_info = {
    .name = TYPE_PS3_VGA,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(PS3VGAState),
    .class_init = ps3_vga_class_init,
};

static void ps3_vga_register_types(void)
{
    type_register_static(&ps3_vga_info);
}

type_init(ps3_vga_register_types)

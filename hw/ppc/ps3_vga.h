/*
 * PS3 boot display
 *
 * The board prints its boot progress to this text screen as well as to the
 * monitor, so the chain is visible in the window: the container being opened,
 * the SPU payload running, the PPU stage and then the VSH.  It is the display
 * output of the machine until the guest programs the scanout itself.
 */

#ifndef PS3_VGA_H
#define PS3_VGA_H

#include <stdint.h>

/* Append one line to the boot screen (scrolling when it is full). */
void ps3_vga_puts(const char *line);
void ps3_vga_printf(const char *fmt, ...);

/*
 * The console's boot screen once the chain is done: `title' as the wordmark,
 * `caption' under it.  The glyphs are the console font scaled up, so this is
 * the model's rendition of the splash, not Sony's artwork.
 */
void ps3_vga_boot_logo(const char *title, const char *caption);

/*
 * The AV path: the guest hands the device the framebuffer it rendered into,
 * and reads the sink's EDID (an HDMI identity with 720p/1080p modes) before
 * it picks a mode.  Both are what lv2's display calls do for the VSH here.
 */
void ps3_vga_guest_scanout(uint32_t base, uint32_t w, uint32_t h,
                           uint32_t stride);
unsigned ps3_vga_hdmi_edid(uint8_t *out, unsigned cap);

/* The mode the guest selected through cellVideoOutConfigure. */
void ps3_vga_set_mode(uint32_t w, uint32_t h);

#endif /* PS3_VGA_H */

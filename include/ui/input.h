#ifndef INPUT_H
#define INPUT_H

#include "qapi/qapi-types-ui.h"
#include "qemu/notify.h"
#include <stdbool.h>
#include <stdint.h>

#define INPUT_EVENT_MASK_KEY   (1<<INPUT_EVENT_KIND_KEY)
#define INPUT_EVENT_MASK_BTN   (1<<INPUT_EVENT_KIND_BTN)
#define INPUT_EVENT_MASK_REL   (1<<INPUT_EVENT_KIND_REL)
#define INPUT_EVENT_MASK_ABS   (1<<INPUT_EVENT_KIND_ABS)
#define INPUT_EVENT_MASK_MTT   (1<<INPUT_EVENT_KIND_MTT)

#define INPUT_EVENT_ABS_MIN    0x0000
#define INPUT_EVENT_ABS_MAX    0x7FFF
#define INPUT_EVENT_SLOTS_MIN  0x0
#define INPUT_EVENT_SLOTS_MAX  0xa

typedef struct QemuInputHandler QemuInputHandler;
typedef struct QemuInputHandlerState QemuInputHandlerState;

typedef struct QemuInputKeyEvent {
    unsigned int key;
    bool down;
} QemuInputKeyEvent;

typedef struct QemuInputEvent {
    InputEventKind type;
    union {
        QemuInputKeyEvent key;
        InputBtnEvent btn;
        InputMoveEvent rel;
        InputMoveEvent abs;
        InputMultiTouchEvent mtt;
    };
} QemuInputEvent;

/*
 * Gamepads.
 *
 * QEMU's console input is keys, buttons and pointer motion; a controller has a
 * shape of its own and no console to send it to.  A display that can read one
 * publishes the whole state here and a machine with pad ports maps it: the
 * bits are the sixteen inputs a libpad port can report, and the axes are
 * -0x7FFF..0x7FFF with up and left negative (SDL's convention), so a display
 * does not have to know what a guest calls them.
 */
#define QEMU_GAMEPAD_SOUTH      (1u << 0)    /* cross / A */
#define QEMU_GAMEPAD_EAST       (1u << 1)    /* circle / B */
#define QEMU_GAMEPAD_NORTH      (1u << 2)    /* triangle / Y */
#define QEMU_GAMEPAD_WEST       (1u << 3)    /* square / X */
#define QEMU_GAMEPAD_TL         (1u << 4)
#define QEMU_GAMEPAD_TR         (1u << 5)
#define QEMU_GAMEPAD_TL2        (1u << 6)    /* L2, also set from its axis */
#define QEMU_GAMEPAD_TR2        (1u << 7)
#define QEMU_GAMEPAD_SELECT     (1u << 8)
#define QEMU_GAMEPAD_START      (1u << 9)
#define QEMU_GAMEPAD_MODE       (1u << 10)   /* PS */
#define QEMU_GAMEPAD_THUMBL     (1u << 11)
#define QEMU_GAMEPAD_THUMBR     (1u << 12)
#define QEMU_GAMEPAD_DPAD_UP    (1u << 13)
#define QEMU_GAMEPAD_DPAD_DOWN  (1u << 14)
#define QEMU_GAMEPAD_DPAD_LEFT  (1u << 15)
#define QEMU_GAMEPAD_DPAD_RIGHT (1u << 16)

typedef struct QemuGamepadState {
    uint32_t buttons;
    int lx, ly;                 /* -0x7FFF..0x7FFF, up and left negative */
    int rx, ry;
} QemuGamepadState;

typedef void (*QemuGamepadHandler)(void *opaque,
                                   const QemuGamepadState *state);

/* One machine has pads; a second registration replaces the first. */
void qemu_gamepad_set_handler(QemuGamepadHandler handler, void *opaque);

/* Called by the display on the thread that owns its events. */
void qemu_gamepad_update(const QemuGamepadState *state);

/* True while a display has a controller open, for a guest's attach report. */
bool qemu_gamepad_connected(void);

/* Announced by the display when it opens or loses the controller. */
void qemu_gamepad_set_connected(bool connected);

typedef void (*QemuInputHandlerEvent)(DeviceState *dev, QemuConsole *src,
                                      QemuInputEvent *evt);
typedef void (*QemuInputHandlerSync)(DeviceState *dev);

struct QemuInputHandler {
    const char             *name;
    uint32_t               mask;
    QemuInputHandlerEvent  event;
    QemuInputHandlerSync   sync;
};

G_GNUC_WARN_UNUSED_RESULT
QemuInputHandlerState *qemu_input_handler_register(DeviceState *dev,
                                            const QemuInputHandler *handler);
void qemu_input_handler_activate(QemuInputHandlerState *s);
void qemu_input_handler_deactivate(QemuInputHandlerState *s);
void qemu_input_handler_unregister(QemuInputHandlerState *s);
void qemu_input_handler_bind(QemuInputHandlerState *s,
                             const char *device_id, int head,
                             Error **errp);
void qemu_input_event_send(QemuConsole *src, QemuInputEvent *evt);
void qemu_input_event_send_impl(QemuConsole *src, QemuInputEvent *evt);
void qemu_input_event_sync(void);
void qemu_input_event_sync_impl(void);

void qemu_input_event_send_key_linux(QemuConsole *src, unsigned int lnx,
                                     bool down);
void qemu_input_event_send_key_number(QemuConsole *src, int num, bool down);
void qemu_input_event_send_key_delay(uint32_t delay_ms);
int qemu_input_key_number_to_qcode(unsigned int nr);
unsigned int qemu_input_key_number_to_linux(unsigned int nr);
unsigned int qemu_input_key_value_to_linux(const KeyValue *value);
int qemu_input_linux_to_scancode(unsigned int lnx, bool down, int *codes);
int qemu_input_linux_to_qcode(unsigned int lnx);

void qemu_input_queue_btn(QemuConsole *src, InputButton btn, bool down);
void qemu_input_update_buttons(QemuConsole *src, uint32_t *button_map,
                               uint32_t button_old, uint32_t button_new);

bool qemu_input_is_absolute(const QemuConsole *con);
int qemu_input_scale_axis(int value,
                          int min_in, int max_in,
                          int min_out, int max_out);
void qemu_input_queue_rel(QemuConsole *src, InputAxis axis, int value);
void qemu_input_queue_abs(QemuConsole *src, InputAxis axis, int value,
                          int min_in, int max_in);
void qemu_input_queue_mtt(QemuConsole *src, InputMultiTouchType type, int slot,
                          int tracking_id);
void qemu_input_queue_mtt_abs(QemuConsole *src, InputAxis axis, int value,
                              int min_in, int max_in,
                              int slot, int tracking_id);

/* Touch devices */
typedef struct touch_slot {
    int x;
    int y;
    int tracking_id;
} touch_slot;

void qemu_input_touch_event(QemuConsole *con,
                            struct touch_slot touch_slots[INPUT_EVENT_SLOTS_MAX],
                            uint64_t num_slot,
                            int width, int height,
                            double x, double y,
                            InputMultiTouchType type,
                            Error **errp);

void qemu_add_mouse_mode_change_notifier(Notifier *notify);
void qemu_remove_mouse_mode_change_notifier(Notifier *notify);

extern const guint qemu_input_map_atset1_to_linux_len;
extern const guint16 qemu_input_map_atset1_to_linux[];

extern const guint qemu_input_map_linux_to_qcode_len;
extern const guint16 qemu_input_map_linux_to_qcode[];

extern const guint qemu_input_map_linux_to_atset1_len;
extern const guint16 qemu_input_map_linux_to_atset1[];

extern const guint qemu_input_map_linux_to_atset2_len;
extern const guint16 qemu_input_map_linux_to_atset2[];

extern const guint qemu_input_map_linux_to_atset3_len;
extern const guint16 qemu_input_map_linux_to_atset3[];

extern const guint qemu_input_map_qcode_to_linux_len;
extern const guint16 qemu_input_map_qcode_to_linux[];

extern const guint qemu_input_map_linux_to_qnum_len;
extern const guint16 qemu_input_map_linux_to_qnum[];

extern const guint qemu_input_map_linux_to_sun_len;
extern const guint16 qemu_input_map_linux_to_sun[];

extern const guint qemu_input_map_qnum_to_linux_len;
extern const guint16 qemu_input_map_qnum_to_linux[];

extern const guint qemu_input_map_usb_to_linux_len;
extern const guint16 qemu_input_map_usb_to_linux[];

extern const guint qemu_input_map_win32_to_linux_len;
extern const guint16 qemu_input_map_win32_to_linux[];

extern const guint qemu_input_map_x11_to_linux_len;
extern const guint16 qemu_input_map_x11_to_linux[];

extern const guint qemu_input_map_xorgkbd_to_linux_len;
extern const guint16 qemu_input_map_xorgkbd_to_linux[];

extern const guint qemu_input_map_xorgxquartz_to_linux_len;
extern const guint16 qemu_input_map_xorgxquartz_to_linux[];

extern const guint qemu_input_map_xorgxwin_to_linux_len;
extern const guint16 qemu_input_map_xorgxwin_to_linux[];

extern const guint qemu_input_map_osx_to_linux_len;
extern const guint16 qemu_input_map_osx_to_linux[];

/**
 * qemu_input_get_leds_mask() - get the LED mask for the given console
 * @con: a QemuConsole or NULL
 *
 * If @con is NULL, returns the LED state mask for the default console.
 */
uint32_t qemu_input_get_leds_mask(const QemuConsole *con);
void qemu_input_handler_set_leds_mask(QemuInputHandlerState *s, uint32_t leds_mask);
void qemu_input_led_notifier_add(Notifier *n);
void qemu_input_led_notifier_remove(Notifier *n);

#endif /* INPUT_H */

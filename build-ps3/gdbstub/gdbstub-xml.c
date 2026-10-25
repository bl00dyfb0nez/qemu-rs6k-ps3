#include "qemu/osdep.h"
#include "exec/gdbstub.h"

const GDBFeature gdb_static_features[] = {
    {
        .xmlname = "power64-core.xml",
        .xml = 
            "<?xml version=\"1.0\"?>\015\n"
            "<!-- Copyright (C) 2007, 2008 Free Software Foundation, Inc.\015\n"
            "\015\n"
            "     Copying and distribution of this file, with or without modification,\015\n"
            "     are permitted in any medium without royalty provided the copyright\015\n"
            "     notice and this notice are preserved.  -->\015\n"
            "\015\n"
            "<!DOCTYPE feature SYSTEM \"gdb-target.dtd\">\015\n"
            "<feature name=\"org.gnu.gdb.power.core\">\015\n"
            "  <reg name=\"r0\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r1\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r2\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r3\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r4\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r5\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r6\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r7\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r8\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r9\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r10\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r11\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r12\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r13\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r14\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r15\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r16\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r17\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r18\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r19\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r20\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r21\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r22\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r23\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r24\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r25\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r26\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r27\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r28\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r29\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r30\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"r31\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "\015\n"
            "  <reg name=\"pc\" bitsize=\"64\" type=\"code_ptr\" regnum=\"64\"/>\015\n"
            "  <reg name=\"msr\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"cr\" bitsize=\"32\" type=\"uint32\"/>\015\n"
            "  <reg name=\"lr\" bitsize=\"64\" type=\"code_ptr\"/>\015\n"
            "  <reg name=\"ctr\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"xer\" bitsize=\"32\" type=\"uint32\"/>\015\n"
            "</feature>\015\n",
        .name = "org.gnu.gdb.power.core",
        .regs = (const char * const [70]) {
            [0] =
                "r0",
            [1] =
                "r1",
            [2] =
                "r2",
            [3] =
                "r3",
            [4] =
                "r4",
            [5] =
                "r5",
            [6] =
                "r6",
            [7] =
                "r7",
            [8] =
                "r8",
            [9] =
                "r9",
            [10] =
                "r10",
            [11] =
                "r11",
            [12] =
                "r12",
            [13] =
                "r13",
            [14] =
                "r14",
            [15] =
                "r15",
            [16] =
                "r16",
            [17] =
                "r17",
            [18] =
                "r18",
            [19] =
                "r19",
            [20] =
                "r20",
            [21] =
                "r21",
            [22] =
                "r22",
            [23] =
                "r23",
            [24] =
                "r24",
            [25] =
                "r25",
            [26] =
                "r26",
            [27] =
                "r27",
            [28] =
                "r28",
            [29] =
                "r29",
            [30] =
                "r30",
            [31] =
                "r31",
            [64] =
                "pc",
            [65] =
                "msr",
            [66] =
                "cr",
            [67] =
                "lr",
            [68] =
                "ctr",
            [69] =
                "xer",
        },
        .base_reg = 0,
        .num_regs = 70,
    },
    {
        .xmlname = "power-fpu.xml",
        .xml = 
            "<?xml version=\"1.0\"?>\015\n"
            "<!-- Copyright (C) 2007, 2008 Free Software Foundation, Inc.\015\n"
            "\015\n"
            "     Copying and distribution of this file, with or without modification,\015\n"
            "     are permitted in any medium without royalty provided the copyright\015\n"
            "     notice and this notice are preserved.  -->\015\n"
            "\015\n"
            "<!DOCTYPE feature SYSTEM \"gdb-target.dtd\">\015\n"
            "<feature name=\"org.gnu.gdb.power.fpu\">\015\n"
            "  <reg name=\"f0\" bitsize=\"64\" type=\"ieee_double\" regnum=\"71\"/>\015\n"
            "  <reg name=\"f1\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f2\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f3\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f4\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f5\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f6\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f7\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f8\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f9\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f10\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f11\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f12\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f13\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f14\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f15\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f16\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f17\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f18\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f19\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f20\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f21\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f22\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f23\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f24\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f25\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f26\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f27\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f28\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f29\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f30\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "  <reg name=\"f31\" bitsize=\"64\" type=\"ieee_double\"/>\015\n"
            "\015\n"
            "  <reg name=\"fpscr\" bitsize=\"32\" group=\"float\"/>\015\n"
            "</feature>\015\n",
        .name = "org.gnu.gdb.power.fpu",
        .regs = (const char * const [33]) {
            [0] =
                "f0",
            [1] =
                "f1",
            [2] =
                "f2",
            [3] =
                "f3",
            [4] =
                "f4",
            [5] =
                "f5",
            [6] =
                "f6",
            [7] =
                "f7",
            [8] =
                "f8",
            [9] =
                "f9",
            [10] =
                "f10",
            [11] =
                "f11",
            [12] =
                "f12",
            [13] =
                "f13",
            [14] =
                "f14",
            [15] =
                "f15",
            [16] =
                "f16",
            [17] =
                "f17",
            [18] =
                "f18",
            [19] =
                "f19",
            [20] =
                "f20",
            [21] =
                "f21",
            [22] =
                "f22",
            [23] =
                "f23",
            [24] =
                "f24",
            [25] =
                "f25",
            [26] =
                "f26",
            [27] =
                "f27",
            [28] =
                "f28",
            [29] =
                "f29",
            [30] =
                "f30",
            [31] =
                "f31",
            [32] =
                "fpscr",
        },
        .base_reg = 71,
        .num_regs = 33,
    },
    {
        .xmlname = "power-altivec.xml",
        .xml = 
            "<?xml version=\"1.0\"?>\015\n"
            "<!-- Copyright (C) 2007, 2008 Free Software Foundation, Inc.\015\n"
            "\015\n"
            "     Copying and distribution of this file, with or without modification,\015\n"
            "     are permitted in any medium without royalty provided the copyright\015\n"
            "     notice and this notice are preserved.  -->\015\n"
            "\015\n"
            "<!DOCTYPE feature SYSTEM \"gdb-target.dtd\">\015\n"
            "<feature name=\"org.gnu.gdb.power.altivec\">\015\n"
            "  <vector id=\"v4f\" type=\"ieee_single\" count=\"4\"/>\015\n"
            "  <vector id=\"v4i32\" type=\"int32\" count=\"4\"/>\015\n"
            "  <vector id=\"v8i16\" type=\"int16\" count=\"8\"/>\015\n"
            "  <vector id=\"v16i8\" type=\"int8\" count=\"16\"/>\015\n"
            "  <union id=\"vec128\">\015\n"
            "    <field name=\"uint128\" type=\"uint128\"/>\015\n"
            "    <field name=\"v4_float\" type=\"v4f\"/>\015\n"
            "    <field name=\"v4_int32\" type=\"v4i32\"/>\015\n"
            "    <field name=\"v8_int16\" type=\"v8i16\"/>\015\n"
            "    <field name=\"v16_int8\" type=\"v16i8\"/>\015\n"
            "  </union>\015\n"
            "\015\n"
            "  <reg name=\"vr0\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr1\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr2\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr3\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr4\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr5\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr6\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr7\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr8\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr9\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr10\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr11\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr12\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr13\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr14\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr15\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr16\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr17\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr18\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr19\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr20\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr21\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr22\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr23\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr24\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr25\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr26\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr27\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr28\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr29\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr30\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "  <reg name=\"vr31\" bitsize=\"128\" type=\"vec128\"/>\015\n"
            "\015\n"
            "  <reg name=\"vscr\" bitsize=\"32\" group=\"vector\"/>\015\n"
            "  <reg name=\"vrsave\" bitsize=\"32\" group=\"vector\"/>\015\n"
            "</feature>\015\n",
        .name = "org.gnu.gdb.power.altivec",
        .regs = (const char * const [34]) {
            [0] =
                "vr0",
            [1] =
                "vr1",
            [2] =
                "vr2",
            [3] =
                "vr3",
            [4] =
                "vr4",
            [5] =
                "vr5",
            [6] =
                "vr6",
            [7] =
                "vr7",
            [8] =
                "vr8",
            [9] =
                "vr9",
            [10] =
                "vr10",
            [11] =
                "vr11",
            [12] =
                "vr12",
            [13] =
                "vr13",
            [14] =
                "vr14",
            [15] =
                "vr15",
            [16] =
                "vr16",
            [17] =
                "vr17",
            [18] =
                "vr18",
            [19] =
                "vr19",
            [20] =
                "vr20",
            [21] =
                "vr21",
            [22] =
                "vr22",
            [23] =
                "vr23",
            [24] =
                "vr24",
            [25] =
                "vr25",
            [26] =
                "vr26",
            [27] =
                "vr27",
            [28] =
                "vr28",
            [29] =
                "vr29",
            [30] =
                "vr30",
            [31] =
                "vr31",
            [32] =
                "vscr",
            [33] =
                "vrsave",
        },
        .base_reg = 0,
        .num_regs = 34,
    },
    {
        .xmlname = "power-spe.xml",
        .xml = 
            "<?xml version=\"1.0\"?>\015\n"
            "<!-- Copyright (C) 2007, 2008 Free Software Foundation, Inc.\015\n"
            "\015\n"
            "     Copying and distribution of this file, with or without modification,\015\n"
            "     are permitted in any medium without royalty provided the copyright\015\n"
            "     notice and this notice are preserved.  -->\015\n"
            "\015\n"
            "<!DOCTYPE feature SYSTEM \"gdb-target.dtd\">\015\n"
            "<feature name=\"org.gnu.gdb.power.spe\">\015\n"
            "  <reg name=\"ev0h\" bitsize=\"32\" regnum=\"71\"/>\015\n"
            "  <reg name=\"ev1h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev2h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev3h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev4h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev5h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev6h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev7h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev8h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev9h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev10h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev11h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev12h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev13h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev14h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev15h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev16h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev17h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev18h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev19h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev20h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev21h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev22h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev23h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev24h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev25h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev26h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev27h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev28h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev29h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev30h\" bitsize=\"32\"/>\015\n"
            "  <reg name=\"ev31h\" bitsize=\"32\"/>\015\n"
            "\015\n"
            "  <reg name=\"acc\" bitsize=\"64\"/>\015\n"
            "  <reg name=\"spefscr\" bitsize=\"32\"/>\015\n"
            "</feature>\015\n",
        .name = "org.gnu.gdb.power.spe",
        .regs = (const char * const [34]) {
            [0] =
                "ev0h",
            [1] =
                "ev1h",
            [2] =
                "ev2h",
            [3] =
                "ev3h",
            [4] =
                "ev4h",
            [5] =
                "ev5h",
            [6] =
                "ev6h",
            [7] =
                "ev7h",
            [8] =
                "ev8h",
            [9] =
                "ev9h",
            [10] =
                "ev10h",
            [11] =
                "ev11h",
            [12] =
                "ev12h",
            [13] =
                "ev13h",
            [14] =
                "ev14h",
            [15] =
                "ev15h",
            [16] =
                "ev16h",
            [17] =
                "ev17h",
            [18] =
                "ev18h",
            [19] =
                "ev19h",
            [20] =
                "ev20h",
            [21] =
                "ev21h",
            [22] =
                "ev22h",
            [23] =
                "ev23h",
            [24] =
                "ev24h",
            [25] =
                "ev25h",
            [26] =
                "ev26h",
            [27] =
                "ev27h",
            [28] =
                "ev28h",
            [29] =
                "ev29h",
            [30] =
                "ev30h",
            [31] =
                "ev31h",
            [32] =
                "acc",
            [33] =
                "spefscr",
        },
        .base_reg = 71,
        .num_regs = 34,
    },
    {
        .xmlname = "power-vsx.xml",
        .xml = 
            "<?xml version=\"1.0\"?>\015\n"
            "<!-- Copyright (C) 2008-2015 Free Software Foundation, Inc.\015\n"
            "\015\n"
            "     Copying and distribution of this file, with or without modification,\015\n"
            "     are permitted in any medium without royalty provided the copyright\015\n"
            "     notice and this notice are preserved.  -->\015\n"
            "\015\n"
            "<!-- POWER7 VSX registers that do not overlap existing FP and VMX\015\n"
            "     registers.  -->\015\n"
            "<!DOCTYPE feature SYSTEM \"gdb-target.dtd\">\015\n"
            "<feature name=\"org.gnu.gdb.power.vsx\">\015\n"
            "  <reg name=\"vs0h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs1h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs2h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs3h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs4h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs5h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs6h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs7h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs8h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs9h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs10h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs11h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs12h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs13h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs14h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs15h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs16h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs17h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs18h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs19h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs20h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs21h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs22h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs23h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs24h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs25h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs26h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs27h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs28h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs29h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs30h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "  <reg name=\"vs31h\" bitsize=\"64\" type=\"uint64\"/>\015\n"
            "</feature>\015\n",
        .name = "org.gnu.gdb.power.vsx",
        .regs = (const char * const [32]) {
            [0] =
                "vs0h",
            [1] =
                "vs1h",
            [2] =
                "vs2h",
            [3] =
                "vs3h",
            [4] =
                "vs4h",
            [5] =
                "vs5h",
            [6] =
                "vs6h",
            [7] =
                "vs7h",
            [8] =
                "vs8h",
            [9] =
                "vs9h",
            [10] =
                "vs10h",
            [11] =
                "vs11h",
            [12] =
                "vs12h",
            [13] =
                "vs13h",
            [14] =
                "vs14h",
            [15] =
                "vs15h",
            [16] =
                "vs16h",
            [17] =
                "vs17h",
            [18] =
                "vs18h",
            [19] =
                "vs19h",
            [20] =
                "vs20h",
            [21] =
                "vs21h",
            [22] =
                "vs22h",
            [23] =
                "vs23h",
            [24] =
                "vs24h",
            [25] =
                "vs25h",
            [26] =
                "vs26h",
            [27] =
                "vs27h",
            [28] =
                "vs28h",
            [29] =
                "vs29h",
            [30] =
                "vs30h",
            [31] =
                "vs31h",
        },
        .base_reg = 0,
        .num_regs = 32,
    },
    { NULL }
};

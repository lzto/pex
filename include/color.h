/*
 * Color Library - Fancy your terminal
 * 2014-2018 Tong Zhang <ztong@vt.edu>
 * 2018 Tong Zhang <t.zhang2@partner.samsung.com>
 */
#ifndef _COLOR_H_
#define _COLOR_H_

#define ANSI_COLOR_SUFFIX "m"

#define BG_PREFIX "\e[48;5;"
#define FG_PREFIX "\e[38;5;"

#define BG_COL(C) BG_PREFIX C ANSI_COLOR_SUFFIX
#define FG_COL(C) FG_PREFIX C ANSI_COLOR_SUFFIX

#define BG_BLACK BG_COL("232")
#define BG_RED BG_COL("160")
#define BG_GREEN BG_COL("076")
#define BG_YELLOW BG_COL("226")
#define BG_BLUE BG_COL("021")
#define BG_MAGENTA BG_COL("129")
#define BG_CYAN BG_COL("039")
#define BG_WHITE BG_COL("255")

#define FG_BLACK FG_COL("232")
#define FG_RED FG_COL("160")
#define FG_GREEN FG_COL("076")
#define FG_YELLOW FG_COL("226")
#define FG_BLUE FG_COL("021")
#define FG_MAGENTA FG_COL("129")
#define FG_CYAN FG_COL("039")
#define FG_WHITE FG_COL("255")

#define ANSI_COLOR(BG, FG) BG FG

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

#endif

#ifndef PKTLENS_WINDOW_H
#define PKTLENS_WINDOW_H

#include <ncurses.h>
#include <string>

namespace pktlens
{

    // A rectangular region on the terminal.
    // Thin RAII wrapper around WINDOW*.
    // All ncurses calls go through this — zero raw ncurses in business logic.
    class Window
    {
    public:
        // Use stdscr dimensions directly
        Window();

        // Explicit position and size
        Window(int height, int width, int y, int x);

        ~Window();

        Window(const Window &) = delete;
        Window &operator=(const Window &) = delete;

        void clear() { werase(win_); }
        void refresh() { wrefresh(win_); }

        // Print at (row, col) within this window, with optional attributes
        void print(int row, int col, const std::string &s, int attrs = 0);
        void print(int row, int col, const char *s, int attrs = 0);

        // Print a single character
        void print_char(int row, int col, chtype ch);

        // Fill an entire row with a character (e.g. horizontal rule)
        void draw_hline(int row, int col, chtype ch, int count);

        // Draw a box border around the window
        void box();

        // Move cursor (needed for some ncurses operations)
        void move(int row, int col) { wmove(win_, row, col); }

        int height() const { return height_; }
        int width() const { return width_; }

        WINDOW *raw() { return win_; } // escape hatch for ncurses calls we don't wrap

        // Resize and reposition (called on SIGWINCH)
        void resize(int height, int width, int y, int x);

    private:
        WINDOW *win_;
        int height_;
        int width_;
    };

}

#endif
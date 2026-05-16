#include "pktlens/ui/Window.h"
#include <ncurses.h>
#include <cstring>

namespace pktlens {

    Window::Window()
        : win_(stdscr)
        , height_(0)
        , width_(0)
    {
        getmaxyx(stdscr, height_, width_);
    }

    Window::Window(int height, int width, int y, int x)
        : win_(nullptr)
        , height_(height)
        , width_(width)
    {
        win_ = newwin(height, width, y, x);
    }

    Window::~Window() {
        // Don't delete stdscr — ncurses owns it
        if (win_ && win_ != stdscr) {
            delwin(win_);
        }
    }

    void Window::print(int row, int col, const std::string& s, int attrs) {
        if (attrs) wattron(win_, attrs);
        mvwaddstr(win_, row, col, s.c_str());
        if (attrs) wattroff(win_, attrs);
    }

    void Window::print(int row, int col, const char* s, int attrs) {
        if (attrs) wattron(win_, attrs);
        mvwaddstr(win_, row, col, s);
        if (attrs) wattroff(win_, attrs);
    }

    void Window::print_char(int row, int col, chtype ch) {
        mvwaddch(win_, row, col, ch);
    }

    void Window::draw_hline(int row, int col, chtype ch, int count) {
        mvwhline(win_, row, col, ch, count);
    }

    void Window::box() {
        ::box(win_, 0, 0);
    }

    void Window::resize(int height, int width, int y, int x) {
        height_ = height;
        width_  = width;
        wresize(win_, height, width);
        mvwin(win_, y, x);
    }

}
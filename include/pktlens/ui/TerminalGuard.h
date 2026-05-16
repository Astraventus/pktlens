#ifndef PKTLENS_TERMINALGUARD_H
#define PKTLENS_TERMINALGUARD_H

namespace pktlens
{

    // RAII wrapper around ncurses init/teardown.
    // Construct once in main(). Destructor always calls endwin(),
    class TerminalGuard
    {
    public:
        TerminalGuard();
        ~TerminalGuard();

        // Non-copyable — there is exactly one terminal
        TerminalGuard(const TerminalGuard &) = delete;
        TerminalGuard &operator=(const TerminalGuard &) = delete;

        // True if the terminal supports colors
        bool has_colors() const { return has_colors_; }

        // Call after SIGWINCH to get new dimensions
        static void get_dimensions(int &rows, int &cols);

    private:
        bool has_colors_;

        static void setup_signals();
        static void setup_colors();
    };

}

#endif
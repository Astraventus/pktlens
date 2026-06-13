#ifndef PKTLENS_CAPTURETHREAD_H
#define PKTLENS_CAPTURETHREAD_H

#include "pktlens/capture/LiveCaptureProvider.h"
#include "pktlens/dissectors/DissectorContext.h"
#include "pktlens/session/SessionModel.h"
#include <thread>
#include <atomic>
#include <functional>

namespace pktlens {

    // RAII wrapper around the background capture thread.
    //
    // Owns a std::thread that runs the packet-capture loop:
    //   1. pulls packets from a LiveCaptureProvider
    //   2. dissects each one
    //   3. appends to SessionModel under its mutex
    //
    // Usage:
    //   CaptureThread ct(provider, model);
    //   ct.start();
    //   // … UI event loop runs here on the main thread …
    //   provider.stop();   // signal the capture thread to exit
    //   ct.join();         // wait (destructor also joins if not done yet)
    //
    // The thread is joined in the destructor so it is always safe to let
    // CaptureThread go out of scope even if join() was never called explicitly.
    //
    class CaptureThread {
    public:
        // provider and model must outlive this object.
        CaptureThread(LiveCaptureProvider& provider,
                      SessionModel&        model);

        // Joins the thread if still running.
        ~CaptureThread();

        // Non-copyable, non-movable — owns a running thread
        CaptureThread(const CaptureThread&)            = delete;
        CaptureThread& operator=(const CaptureThread&) = delete;

        // Launch the capture loop on a new thread.
        // Must be called exactly once.
        void start();

        // Block until the capture thread exits.
        // Safe to call even if the thread was never started.
        void join();

        // True if the thread threw an unhandled exception.
        // The error is retrievable via error_message().
        bool has_error()          const { return has_error_.load(); }
        std::string error_message() const { return error_; }

    private:
        void run();   // the body executed on the background thread

        LiveCaptureProvider& provider_;
        SessionModel&        model_;
        DissectorContext     ctx_;    // private to the capture thread

        std::thread          thread_;
        std::atomic<bool>    has_error_;
        std::string          error_;
    };

}  // namespace pktlens

#endif  // PKTLENS_CAPTURETHREAD_H